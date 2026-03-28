#!/usr/bin/env python3
"""
Build a work graph for BLAKE3 hashing of files stored in ternfs.

Reads a CSV from stdin with columns: path, size, inode, shard
Queries the registry for block service locations, then queries each shard
for file span/block mappings.

Outputs a JSON graph to stdout with:
- All files, their sizes, and which block services hold their data blocks
- All block services with their physical host (failure domain) and address
- A suggested execution order that minimizes per-disk contention
"""

import argparse
import csv
import io
import json
import socket
import struct
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ternfs wire protocol constants
REGISTRY_REQ_PROTOCOL = 0x554853
REGISTRY_RESP_PROTOCOL = 0x1554853
SHARD_REQ_PROTOCOL = 0x414853
SHARD_RESP_PROTOCOL = 0x1414853

# Registry message kinds
LOCAL_SHARDS = 0x03
ALL_BLOCK_SERVICES = 0x28

# Shard message kinds
LOCAL_FILE_SPANS = 0x0B

# Storage classes
EMPTY_STORAGE = 0
INLINE_STORAGE = 1
HDD_STORAGE = 2
FLASH_STORAGE = 3

# Block service flags
BLOCK_SERVICE_NO_READ = 0x2
BLOCK_SERVICE_DECOMMISSIONED = 0x8


# --------------------------------------------------------------------------
# bincode helpers (little-endian, matching ternfs go/core/bincode)
# --------------------------------------------------------------------------

class BincodeReader:
    def __init__(self, data, offset=0):
        self.data = data
        self.pos = offset

    def u8(self):
        v = self.data[self.pos]
        self.pos += 1
        return v

    def bool(self):
        return self.u8() != 0

    def u16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64(self):
        v = struct.unpack_from('<Q', self.data, self.pos)[0]
        self.pos += 8
        return v

    def fixed_bytes(self, n):
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def length(self):
        """Array/slice length prefix: uint16."""
        return self.u16()

    def bytes_field(self):
        """Length-prefixed bytes (uint8 length)."""
        n = self.u8()
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def string(self):
        return self.bytes_field().decode('utf-8', errors='replace')

    def remaining(self):
        return len(self.data) - self.pos


class BincodeWriter:
    def __init__(self):
        self.buf = bytearray()

    def u8(self, v):
        self.buf.append(v & 0xFF)

    def u16(self, v):
        self.buf.extend(struct.pack('<H', v))

    def u32(self, v):
        self.buf.extend(struct.pack('<I', v))

    def u64(self, v):
        self.buf.extend(struct.pack('<Q', v))

    def bytes(self):
        return bytes(self.buf)


# --------------------------------------------------------------------------
# IpPort / AddrsInfo parsing
# --------------------------------------------------------------------------

def read_ipport(r):
    ip = r.fixed_bytes(4)
    port = r.u16()
    return f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}:{port}"


def read_addrs_info(r):
    addr1 = read_ipport(r)
    addr2 = read_ipport(r)
    return addr1, addr2


# --------------------------------------------------------------------------
# Registry TCP protocol
# --------------------------------------------------------------------------

def registry_request(address, kind, body=b''):
    """Send a registry request over TCP and return the response body."""
    host, port = address.rsplit(':', 1)
    sock = socket.create_connection((host, int(port)), timeout=30)
    try:
        # Header: protocol(u32) + length(u32) + kind(u8) + body
        msg_len = 1 + len(body)
        header = struct.pack('<II', REGISTRY_REQ_PROTOCOL, msg_len)
        sock.sendall(header + bytes([kind]) + body)

        # Read response
        resp_header = _recv_exact(sock, 8)
        protocol, resp_len = struct.unpack('<II', resp_header)
        if protocol != REGISTRY_RESP_PROTOCOL:
            raise RuntimeError(f"Bad registry response protocol: {protocol:#x}")
        resp_data = _recv_exact(sock, resp_len)
        resp_kind = resp_data[0]
        if resp_kind == 0:  # ERROR
            if len(resp_data) >= 3:
                err_code = struct.unpack_from('<H', resp_data, 1)[0]
                raise RuntimeError(f"Registry error: {err_code}")
            raise RuntimeError("Registry error (unknown)")
        if resp_kind != kind:
            raise RuntimeError(f"Unexpected response kind {resp_kind}, expected {kind}")
        return resp_data[1:]
    finally:
        sock.close()


def _recv_exact(sock, n):
    """Read exactly n bytes from a socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed, expected {n} bytes, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


# --------------------------------------------------------------------------
# Shard UDP protocol
# --------------------------------------------------------------------------

class ShardClient:
    """Sends LocalFileSpansReq over UDP to shard leaders."""

    def __init__(self, shard_addrs, timeout=5.0, max_retries=3):
        self.shard_addrs = shard_addrs  # shard_id -> (ip, port)
        self.timeout = timeout
        self.max_retries = max_retries
        self._request_id = 0

    def _next_request_id(self):
        self._request_id += 1
        return self._request_id

    def get_file_spans(self, shard_id, inode_id):
        """Query a shard for all spans of a file. Returns (block_services, spans)."""
        addr = self.shard_addrs.get(shard_id)
        if not addr:
            raise RuntimeError(f"No address for shard {shard_id}")

        all_block_services = []
        all_spans = []
        byte_offset = 0

        while True:
            # Build LocalFileSpansReq: FileId(u64) + ByteOffset(u64) + Limit(u32) + Mtu(u16)
            w = BincodeWriter()
            w.u64(inode_id)
            w.u64(byte_offset)
            w.u32(0)     # no limit
            w.u16(8972)  # MAX_UDP_MTU
            body = w.bytes()

            resp_body = self._udp_request(addr, LOCAL_FILE_SPANS, body)
            r = BincodeReader(resp_body)

            next_offset = r.u64()
            bs_in_page, spans_in_page = _parse_local_file_spans_resp_body(r)

            # Block service indices in this page's spans are relative to
            # bs_in_page. Remap them to be relative to all_block_services.
            ix_remap = {}
            for i, bs in enumerate(bs_in_page):
                # Deduplicate by block service id
                found = None
                for j, existing in enumerate(all_block_services):
                    if existing['id'] == bs['id']:
                        found = j
                        break
                if found is not None:
                    ix_remap[i] = found
                else:
                    ix_remap[i] = len(all_block_services)
                    all_block_services.append(bs)

            for span in spans_in_page:
                for block in span.get('blocks', []):
                    block['block_service_ix'] = ix_remap[block['block_service_ix']]
                all_spans.append(span)

            if next_offset == 0:
                break
            byte_offset = next_offset

        return all_block_services, all_spans

    def _udp_request(self, addr, kind, body):
        """Send a UDP request and wait for the response."""
        request_id = self._next_request_id()

        # Build packet: protocol(u32) + request_id(u64) + kind(u8) + body
        packet = struct.pack('<QIB', request_id, SHARD_REQ_PROTOCOL, kind)
        # Wait -- the Go code writes: protocol(u32), request_id(u64), kind(u8)
        # Let me re-read: binary.Write(buf, LE, protocol) then binary.Write(buf, LE, req.requestId) then kind
        packet = struct.pack('<IQB', SHARD_REQ_PROTOCOL, request_id, kind) + body

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            for attempt in range(self.max_retries):
                sock.sendto(packet, addr)
                try:
                    data, _ = sock.recvfrom(9000)
                except socket.timeout:
                    if attempt == self.max_retries - 1:
                        raise RuntimeError(
                            f"Shard request timed out after {self.max_retries} attempts "
                            f"(shard addr {addr})"
                        )
                    continue

                # Parse response: protocol(u32) + request_id(u64) + kind(u8) + body
                if len(data) < 13:
                    continue
                resp_protocol = struct.unpack_from('<I', data, 0)[0]
                resp_req_id = struct.unpack_from('<Q', data, 4)[0]
                resp_kind = data[12]

                if resp_protocol != SHARD_RESP_PROTOCOL:
                    continue
                if resp_req_id != request_id:
                    continue
                if resp_kind == 0:  # ERROR
                    if len(data) >= 15:
                        err_code = struct.unpack_from('<H', data, 13)[0]
                        raise RuntimeError(f"Shard error: {err_code}")
                    raise RuntimeError("Shard error (unknown)")
                if resp_kind != kind:
                    continue

                return data[13:]

            raise RuntimeError(f"No valid response from shard at {addr}")
        finally:
            sock.close()


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------

def _parse_local_file_spans_resp_body(r):
    """Parse the body of a LocalFileSpansResp (after NextOffset is already read)."""
    # BlockServices array
    bs_count = r.length()
    block_services = []
    for _ in range(bs_count):
        addr1, addr2 = read_addrs_info(r)
        bs_id = r.u64()
        flags = r.u8()
        block_services.append({
            'id': bs_id,
            'addr1': addr1,
            'addr2': addr2,
            'flags': flags,
        })

    # Spans array
    span_count = r.length()
    spans = []
    for _ in range(span_count):
        # FetchedSpanHeader
        byte_offset = r.u64()
        size = r.u32()
        crc = r.u32()
        storage_class = r.u8()

        span = {
            'byte_offset': byte_offset,
            'size': size,
            'storage_class': storage_class,
        }

        if storage_class == INLINE_STORAGE:
            # FetchedInlineSpan: bytes_field (uint8 length prefix)
            inline_body = r.bytes_field()
            span['inline'] = True
        elif storage_class in (HDD_STORAGE, FLASH_STORAGE):
            # FetchedBlocksSpan
            parity = r.u8()
            stripes = r.u8()
            cell_size = r.u32()
            data_blocks = parity & 0x0F
            parity_blocks = (parity >> 4) & 0x0F
            total_blocks = data_blocks + parity_blocks

            blocks_count = r.length()
            blocks = []
            for _ in range(blocks_count):
                bs_ix = r.u8()
                block_id = r.u64()
                block_crc = r.u32()
                blocks.append({
                    'block_service_ix': bs_ix,
                    'block_id': block_id,
                })

            stripes_crc_count = r.length()
            for _ in range(stripes_crc_count):
                r.u32()  # skip stripe CRCs

            span['data_blocks'] = data_blocks
            span['parity_blocks'] = parity_blocks
            span['stripes'] = stripes
            span['cell_size'] = cell_size
            # Blocks array is flat: first D are data, next P are parity.
            # Each block service stores all stripes for its block index.
            # We only need the data blocks (first D entries).
            span['blocks'] = blocks[:data_blocks]
        elif storage_class == EMPTY_STORAGE:
            span['empty'] = True
        else:
            raise RuntimeError(f"Unknown storage class {storage_class}")

        spans.append(span)

    return block_services, spans


# --------------------------------------------------------------------------
# Discovery: get shard addresses and block service info from registry
# --------------------------------------------------------------------------

def discover_shards(registry_addr):
    """Query registry for shard leader addresses. Returns dict shard_id -> (ip, port)."""
    resp = registry_request(registry_addr, LOCAL_SHARDS)
    r = BincodeReader(resp)
    count = r.length()
    shards = {}
    for i in range(count):
        addr1, addr2 = read_addrs_info(r)
        last_seen = r.u64()
        # Parse addr1 to get (ip, port)
        if addr1 != "0.0.0.0:0":
            host, port = addr1.rsplit(':', 1)
            shards[i] = (host, int(port))
    return shards


def discover_block_services(registry_addr):
    """Query registry for all block services. Returns dict bs_id -> info."""
    resp = registry_request(registry_addr, ALL_BLOCK_SERVICES)
    r = BincodeReader(resp)
    count = r.length()
    result = {}
    for _ in range(count):
        bs_id = r.u64()
        location_id = r.u8()
        addr1, addr2 = read_addrs_info(r)
        storage_class = r.u8()

        # FailureDomain: fixed 16 bytes
        fd_bytes = r.fixed_bytes(16)
        failure_domain = fd_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

        secret_key = r.fixed_bytes(16)  # skip
        flags = r.u8()
        capacity = r.u64()
        available = r.u64()
        blocks = r.u64()
        first_seen = r.u64()
        last_seen = r.u64()
        last_info_change = r.u64()
        has_files = r.bool()
        path = r.string()

        can_read = not (flags & (BLOCK_SERVICE_NO_READ | BLOCK_SERVICE_DECOMMISSIONED))

        result[bs_id] = {
            'id': bs_id,
            'addr1': addr1,
            'addr2': addr2,
            'storage_class': storage_class,
            'failure_domain': failure_domain,
            'path': path,
            'flags': flags,
            'can_read': bool(can_read),
        }
    return result


# --------------------------------------------------------------------------
# Main: build the graph
# --------------------------------------------------------------------------

def build_graph(registry_addr, files, concurrency):
    print(f"Discovering shard addresses...", file=sys.stderr)
    shard_addrs = discover_shards(registry_addr)
    print(f"  Found {len(shard_addrs)} shards", file=sys.stderr)

    print(f"Discovering block services...", file=sys.stderr)
    all_bs = discover_block_services(registry_addr)
    print(f"  Found {len(all_bs)} block services", file=sys.stderr)

    shard_client = ShardClient(shard_addrs)

    # Group files by shard for batching
    by_shard = defaultdict(list)
    for f in files:
        by_shard[f['shard']].append(f)

    print(f"Querying spans for {len(files)} files across {len(by_shard)} shards...",
          file=sys.stderr)

    # Result: per-file info
    file_entries = []
    # Track which block services are actually used
    used_bs_ids = set()
    # Track which (failure_domain, path) combos = physical disks are used by which files
    errors = []

    def process_file(f):
        shard_id = f['shard']
        inode_id = f['inode']
        try:
            block_services, spans = shard_client.get_file_spans(shard_id, inode_id)
        except Exception as e:
            return f, None, str(e)

        # Collect the set of block service IDs that hold data for this file
        # Map from per-response bs index to global bs_id
        bs_id_map = {}
        for i, bs in enumerate(block_services):
            bs_id_map[i] = bs['id']

        file_bs_ids = set()
        for span in spans:
            for block in span.get('blocks', []):
                ix = block['block_service_ix']
                bs_id = bs_id_map.get(ix)
                if bs_id is not None:
                    file_bs_ids.add(bs_id)

        return f, file_bs_ids, None

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(process_file, f): f for f in files}
        for future in as_completed(futures):
            f, file_bs_ids, err = future.result()
            completed += 1
            if completed % 10000 == 0:
                print(f"  {completed}/{len(files)} files processed...", file=sys.stderr)

            if err:
                errors.append({'path': f['path'], 'error': err})
                continue

            # Resolve bs_ids to (failure_domain, path) = physical disk
            disks = []
            for bs_id in file_bs_ids:
                info = all_bs.get(bs_id)
                if info:
                    disks.append({
                        'bs_id': bs_id,
                        'failure_domain': info['failure_domain'],
                        'disk_path': info['path'],
                    })
                    used_bs_ids.add(bs_id)

            file_entries.append({
                'path': f['path'],
                'size': f['size'],
                'inode': f['inode'],
                'shard': f['shard'],
                'disks': disks,
            })

    print(f"  Done. {len(file_entries)} files mapped, {len(errors)} errors.", file=sys.stderr)

    # Build the output graph
    # Disk key = (failure_domain, disk_path) uniquely identifies a physical drive
    disk_index = {}  # (fd, path) -> int
    disk_list = []
    for bs_id in used_bs_ids:
        info = all_bs[bs_id]
        key = (info['failure_domain'], info['path'])
        if key not in disk_index:
            disk_index[key] = len(disk_list)
            disk_list.append({
                'disk_id': len(disk_list),
                'failure_domain': info['failure_domain'],
                'path': info['path'],
                'bs_ids': [],
            })
        disk_list[disk_index[key]]['bs_ids'].append(bs_id)

    # Replace per-file disk info with disk_id references
    for fe in file_entries:
        disk_ids = set()
        for d in fe['disks']:
            info = all_bs[d['bs_id']]
            key = (info['failure_domain'], info['path'])
            disk_ids.add(disk_index[key])
        fe['disk_ids'] = sorted(disk_ids)
        del fe['disks']

    # Sort files largest first for scheduling
    file_entries.sort(key=lambda f: -f['size'])

    # Build schedule: greedy assignment to minimize per-disk concurrency
    # Each file gets a "priority group" number. Workers should process files
    # in group order. Within a group, files can be processed concurrently.
    print(f"Building schedule...", file=sys.stderr)
    disk_load = defaultdict(int)  # disk_id -> current load
    groups = []
    current_group = []
    max_disk_load = 2  # max concurrent reads per physical disk

    for fe in file_entries:
        # Check if any of this file's disks are at max load
        can_schedule = all(disk_load[d] < max_disk_load for d in fe['disk_ids'])
        if not can_schedule:
            # Flush current group, reset loads
            if current_group:
                groups.append(current_group)
                current_group = []
                disk_load.clear()
        # Add to current group
        current_group.append(fe['path'])
        for d in fe['disk_ids']:
            disk_load[d] += 1

    if current_group:
        groups.append(current_group)

    # Assign group number to each file
    path_to_group = {}
    for gi, group in enumerate(groups):
        for p in group:
            path_to_group[p] = gi
    for fe in file_entries:
        fe['group'] = path_to_group[fe['path']]

    graph = {
        'total_files': len(file_entries),
        'total_size': sum(f['size'] for f in file_entries),
        'total_disks': len(disk_list),
        'total_groups': len(groups),
        'disks': disk_list,
        'block_services': {
            str(bs_id): {
                'addr1': info['addr1'],
                'failure_domain': info['failure_domain'],
                'path': info['path'],
                'storage_class': info['storage_class'],
            }
            for bs_id, info in all_bs.items()
            if bs_id in used_bs_ids
        },
        'files': file_entries,
        'errors': errors,
    }

    return graph


def main():
    parser = argparse.ArgumentParser(
        description='Build a work graph for BLAKE3 hashing of ternfs files')
    parser.add_argument('--registry', required=True,
                        help='Registry address (host:port)')
    parser.add_argument('--concurrency', type=int, default=256,
                        help='Number of concurrent shard queries (default: 256)')
    parser.add_argument('--output', '-o', default='-',
                        help='Output file (default: stdout)')
    args = parser.parse_args()

    # Read CSV from stdin
    files = []
    reader = csv.DictReader(sys.stdin)
    for row in reader:
        inode = int(row['inode'])
        # Shard is the low 8 bits of inode, but use the provided value if present
        shard = int(row['shard']) if 'shard' in row and row['shard'] else (inode & 0xFF)
        files.append({
            'path': row['path'],
            'size': int(row['size']),
            'inode': inode,
            'shard': shard,
        })

    if not files:
        print("No files to process", file=sys.stderr)
        sys.exit(1)

    print(f"Read {len(files)} files from stdin", file=sys.stderr)

    graph = build_graph(args.registry, files, args.concurrency)

    if args.output == '-':
        json.dump(graph, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        with open(args.output, 'w') as f:
            json.dump(graph, f, indent=2)
            f.write('\n')
        print(f"Graph written to {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
