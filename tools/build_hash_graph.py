#!/usr/bin/env python3
"""
Build a work graph for BLAKE3 hashing of files stored in ternfs.

Reads a CSV from stdin with columns: path, size, inode, shard
Queries ternweb's HTTP API for block service locations and file span mappings.

Outputs a JSON graph to stdout with:
- All files, their sizes, and which block services hold their data blocks
- All block services with their physical host (failure domain) and address
- A suggested execution order that minimizes per-disk contention
"""

import argparse
import csv
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# --------------------------------------------------------------------------
# ternweb HTTP API helpers
# --------------------------------------------------------------------------

def api_request(base_url, path, body=None, timeout=30):
    """POST JSON to ternweb API, return parsed response."""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode() if body is not None else b'{}'
    req = urllib.request.Request(url, data=data, method='POST',
                                headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req, timeout=timeout)
    result = json.loads(resp.read())
    if 'err' in result:
        raise RuntimeError(f"API error: {result['err']}")
    return result.get('resp', result)


def get_all_block_services(base_url):
    """Query registry for all block services via ternweb."""
    resp = api_request(base_url, '/api/registry/ALL_BLOCK_SERVICES')
    result = {}
    for bs in resp['BlockServices']:
        bs_id = bs['Id']
        flags = bs['Flags']
        can_read = not (flags & 0xA)  # NO_READ=0x2 | DECOMMISSIONED=0x8
        result[bs_id] = {
            'id': bs_id,
            'addr': str(bs['Addrs']['Addr1']),
            'storage_class': bs['StorageClass'],
            'failure_domain': bs['FailureDomain'],
            'path': bs['Path'],
            'flags': flags,
            'can_read': can_read,
        }
    return result


def get_file_spans(base_url, shard_id, inode_id, timeout=10):
    """Query a shard for all spans of a file. Returns list of (bs_id, ...) per data block."""
    # InodeId serializes as hex string "0x..."
    inode_hex = f"0x{inode_id:016x}"
    byte_offset = 0
    all_bs = []
    all_data_bs_ids = set()

    while True:
        resp = api_request(
            base_url,
            f'/api/shard/{shard_id}/LOCAL_FILE_SPANS',
            {'FileId': inode_hex, 'ByteOffset': byte_offset, 'Limit': 0, 'Mtu': 0},
            timeout=timeout,
        )

        # Block services for this page of results
        page_bs = resp.get('BlockServices', [])
        # Build index: position in page_bs -> bs_id
        bs_id_by_ix = {}
        for i, bs in enumerate(page_bs):
            bs_id_by_ix[i] = bs['Id']
            # Also keep full info
            found = False
            for existing in all_bs:
                if existing['Id'] == bs['Id']:
                    found = True
                    break
            if not found:
                all_bs.append(bs)

        for span in resp.get('Spans', []):
            header = span['Header']
            sc = header['StorageClass']
            if sc <= 1:  # EMPTY or INLINE
                continue
            body = span['Body']
            parity = body['Parity']  # [D, P]
            data_blocks = parity[0]
            blocks = body.get('Blocks', [])
            # First D blocks are data, rest are parity
            for block in blocks[:data_blocks]:
                ix = block['BlockServiceIx']
                bs_id = bs_id_by_ix.get(ix)
                if bs_id is not None:
                    all_data_bs_ids.add(bs_id)

        next_offset = resp.get('NextOffset', 0)
        if next_offset == 0:
            break
        byte_offset = next_offset

    return all_data_bs_ids


# --------------------------------------------------------------------------
# Main: build the graph
# --------------------------------------------------------------------------

def build_graph(base_url, files, concurrency):
    print(f"Discovering block services...", file=sys.stderr)
    all_bs = get_all_block_services(base_url)
    print(f"  Found {len(all_bs)} block services", file=sys.stderr)

    by_shard = defaultdict(list)
    for f in files:
        by_shard[f['shard']].append(f)

    print(f"Querying spans for {len(files)} files across {len(by_shard)} shards...",
          file=sys.stderr)

    file_entries = []
    used_bs_ids = set()
    errors = []

    def process_file(f):
        try:
            data_bs_ids = get_file_spans(base_url, f['shard'], f['inode'])
            return f, data_bs_ids, None
        except Exception as e:
            return f, None, str(e)

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

    # Build disk index: (failure_domain, path) uniquely identifies a physical drive
    disk_index = {}
    disk_list = []
    for bs_id in sorted(used_bs_ids, key=str):
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

    # Build schedule: greedy assignment to minimize per-disk concurrency.
    # Each file gets a "group" number. Files in the same group can run
    # concurrently without any single disk being hit by more than
    # max_disk_load concurrent reads.
    print(f"Building schedule...", file=sys.stderr)
    disk_load = defaultdict(int)
    groups = []
    current_group = []
    max_disk_load = 2

    for fe in file_entries:
        can_schedule = all(disk_load[d] < max_disk_load for d in fe['disk_ids'])
        if not can_schedule:
            if current_group:
                groups.append(current_group)
                current_group = []
                disk_load.clear()
        current_group.append(fe['path'])
        for d in fe['disk_ids']:
            disk_load[d] += 1

    if current_group:
        groups.append(current_group)

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
                'addr': info['addr'],
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
    parser.add_argument('--ternweb', required=True,
                        help='ternweb base URL (e.g. http://ternweb:8080)')
    parser.add_argument('--concurrency', type=int, default=256,
                        help='Number of concurrent shard queries (default: 256)')
    parser.add_argument('--output', '-o', default='-',
                        help='Output file (default: stdout)')
    args = parser.parse_args()

    base_url = args.ternweb.rstrip('/')

    # Read CSV from stdin
    files = []
    reader = csv.DictReader(sys.stdin)
    for row in reader:
        inode = int(row['inode'])
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

    graph = build_graph(base_url, files, args.concurrency)

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
