"""Extract exefs and romfs from Tears of the Kingdom NSPs, automating the nsp_extract + hactoolnet pipeline.

Usage: nsp_setup.py <base nsp> <update nsp> [--keys <prod.keys>] [--hactoolnet <path>] [--out <dir>]

Steps:
  1. Unpacks both NSPs (PFS0) into individual NCAs and tickets (tools/nsp_extract.py's logic)
  2. Extracts title keys from the tickets
  3. Finds the program NCA in each by content type (hactoolnet -t nca --titlekeys ... -y)
  4. Runs hactoolnet to decrypt and extract exefs/ and romfs.bin into <out>/Dump/0100F2C0115B6000/
     with the update NCA applied on top of the base via --basenca

Requires hactoolnet on PATH (or --hactoolnet), and a prod.keys at ~/.switch/prod.keys (or --keys).
"""
import os
import shutil
import struct
import subprocess
import sys

TITLE_ID = '0100F2C0115B6000'


def pfs0_entries(f):
    head = f.read(16)
    if head[:4] != b'PFS0':
        sys.exit('not an NSP (PFS0)')
    n, strsize = struct.unpack_from('<II', head, 4)
    table = f.read(n * 24)
    strings = f.read(strsize)
    data = 16 + n * 24 + strsize
    for i in range(n):
        off, size, name_off = struct.unpack_from('<QQI', table, i * 24)
        name = strings[name_off:strings.index(b'\0', name_off)].decode()
        yield name, data + off, size


def extract_nsp(nsp_path, tmp_dir, label):
    ncas = []
    keys = []
    print(f'\nunpacking {label} NSP...')
    with open(nsp_path, 'rb') as f:
        for name, off, size in pfs0_entries(f):
            path = os.path.join(tmp_dir, name)
            if os.path.exists(path) and os.path.getsize(path) == size:
                print(f'  {name}: already there')
            else:
                f.seek(off)
                with open(path + '.part', 'wb') as o:
                    left = size
                    while left:
                        chunk = f.read(min(left, 64 << 20))
                        if not chunk:
                            sys.exit(f'{name}: the NSP ends early')
                        o.write(chunk)
                        left -= len(chunk)
                os.replace(path + '.part', path)
                print(f'  {name}: {size:,} bytes')
            if name.endswith('.nca'):
                ncas.append((name, path, size))
            if name.endswith('.tik'):
                t = open(path, 'rb').read()
                if struct.unpack_from('<I', t, 0)[0] == 0x10004 and len(t) >= 0x2B0:
                    keys.append(f'{t[0x2A0:0x2B0].hex()} = {t[0x180:0x190].hex()}')
    print(f'{len(keys)} title key(s)')
    return ncas, keys


def find_hactoolnet(hint):
    if hint:
        if os.path.isfile(hint):
            return hint
        sys.exit(f'hactoolnet not found at {hint}')
    for name in ('hactoolnet', 'hactoolnet.exe'):
        path = shutil.which(name)
        if path:
            return path
    sys.exit('hactoolnet not found on PATH (install it or use --hactoolnet <path>)')


def find_keys(hint):
    if hint:
        if os.path.isfile(hint):
            return hint
        sys.exit(f'keys file not found at {hint}')
    default = os.path.join(os.path.expanduser('~'), '.switch', 'prod.keys')
    if os.path.isfile(default):
        return default
    sys.exit(f'prod.keys not found at {default} (provide --keys <path>)')


def nca_content_type(hactoolnet, keys_path, title_keys, nca_path):
    try:
        r = subprocess.run([hactoolnet, '--keyset', keys_path, '--titlekeys', title_keys,
                            '-t', 'nca', nca_path, '-y'],
                           capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            if 'Content Type:' in line:
                return line.split('Content Type:')[1].strip()
    except Exception:
        pass
    return None


def find_program_nca(hactoolnet, keys_path, title_keys, ncas, label):
    program = None
    print(f'\nidentifying {label} NCAs...')
    for name, path, size in ncas:
        ct = nca_content_type(hactoolnet, keys_path, title_keys, path)
        tag = ct or '?'
        print(f'  {name}: {tag} ({size / 2**20:.0f} MiB)')
        if ct and ct.lower() == 'program':
            if program is None or size > program[2]:
                program = (name, path, size)
    if not program:
        sys.exit(f'no program NCA found in the {label} NSP')
    return program


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('base_nsp', help='path to the base game NSP file')
    ap.add_argument('update_nsp', help='path to the update NSP file (v1.4.3)')
    ap.add_argument('--keys', help='path to prod.keys (default: ~/.switch/prod.keys)')
    ap.add_argument('--hactoolnet', help='path to hactoolnet (default: search PATH)')
    ap.add_argument('--out', default='.', help='output root (default: current directory; creates Dump/<title id>/ under it)')
    args = ap.parse_args()

    hactoolnet = find_hactoolnet(args.hactoolnet)
    keys_path = find_keys(args.keys)
    print(f'hactoolnet: {hactoolnet}')
    print(f'keys: {keys_path}')

    tmp_dir = os.path.join(args.out, 'nsp_tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    base_ncas, base_keys = extract_nsp(args.base_nsp, tmp_dir, 'base')
    update_ncas, update_keys = extract_nsp(args.update_nsp, tmp_dir, 'update')

    all_keys = list(set(base_keys + update_keys))
    title_keys = os.path.join(tmp_dir, 'title.keys')
    with open(title_keys, 'w') as k:
        k.write(''.join(line + '\n' for line in all_keys))
    print(f'\n{len(all_keys)} unique title key(s)')

    base_program = find_program_nca(hactoolnet, keys_path, title_keys, base_ncas, 'base')
    update_program = find_program_nca(hactoolnet, keys_path, title_keys, update_ncas, 'update')

    dump_dir = os.path.join(args.out, 'Dump', TITLE_ID)
    exefs_dir = os.path.join(dump_dir, 'exefs')
    romfs_bin = os.path.join(dump_dir, 'romfs.bin')
    os.makedirs(dump_dir, exist_ok=True)

    print(f'\nextracting with base {base_program[0]} + update {update_program[0]}...')
    cmd = [hactoolnet, '--keyset', keys_path, '--titlekeys', title_keys,
           '-t', 'nca', update_program[1], '--basenca', base_program[1],
           '--exefsdir', exefs_dir, '--romfs', romfs_bin]

    print(f'  {" ".join(cmd)}\n')
    r = subprocess.run(cmd, timeout=600)
    if r.returncode != 0:
        sys.exit(f'hactoolnet failed (exit {r.returncode})')

    if not os.path.isdir(exefs_dir) or not os.listdir(exefs_dir):
        sys.exit(f'exefs not extracted to {exefs_dir}')

    exefs_files = os.listdir(exefs_dir)
    romfs_ok = os.path.isfile(romfs_bin) and os.path.getsize(romfs_bin) > 0
    print(f'exefs: {len(exefs_files)} files ({", ".join(sorted(exefs_files))})')
    if romfs_ok:
        print(f'romfs: {os.path.getsize(romfs_bin) / 2**30:.1f} GiB')
    else:
        print(f'romfs.bin not found or empty — the romfs may need --romfsdir instead')

    print(f'\ndump: {os.path.normpath(dump_dir)}')
    print('run tools/totk_dump.py to verify the dump')


if __name__ == '__main__':
    main()
