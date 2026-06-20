#!/usr/bin/env python3
"""Scan driverpack .sys files for sections driver

  host_pick.py <root>...                  walk folders (recurses into .7z)
  host_pick.py <driver.sys>               full per-section breakdown

Sections measured (page-aligned):
  .data BSS    slack at the end of .data (vsize > raw_sz, no on-disk bytes)
  INIT exec    INIT-named EXEC section
  RWX exec     non-INIT, non-DISCARDABLE EXEC+WRITE section
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

DOS_MAGIC = 0x5A4D
PE_SIG    = b"PE\x00\x00"
PE32_PLUS = 0x20B

SCN_DISCARDABLE = 0x02000000
SCN_EXECUTE     = 0x20000000
SCN_READ        = 0x40000000
SCN_WRITE       = 0x80000000


def page_up(x): return (x + 0xFFF) & ~0xFFF
def u16(d, o): return struct.unpack_from("<H", d, o)[0]
def u32(d, o): return struct.unpack_from("<I", d, o)[0]


def parse_pe(data):
    if len(data) < 0x40 or u16(data, 0) != DOS_MAGIC:
        return None
    e = u32(data, 0x3C)
    if e + 0x108 > len(data) or data[e:e+4] != PE_SIG:
        return None
    oh = e + 24
    if u16(data, oh) != PE32_PLUS:
        return None

    nsec = u16(data, e + 6)
    so   = oh + u16(data, e + 20)
    soi  = u32(data, oh + 56)
    secs = []
    for i in range(nsec):
        o = so + i * 40
        if o + 40 > len(data):
            break
        secs.append({
            "name":   data[o:o+8].split(b"\x00")[0].decode("ascii", "replace"),
            "vsize":  u32(data, o + 8),
            "va":     u32(data, o + 12),
            "raw_sz": u32(data, o + 16),
            "chars":  u32(data, o + 36),
        })
    return {"soi": soi, "secs": secs}


def is_init(name):
    nu = name.upper()
    return nu.startswith("INIT") or nu.startswith(".INIT")


def section_kind(s):
    if s["name"].lower() == ".data":
        slack = max(0, page_up(s["va"] + s["vsize"]) - page_up(s["va"] + s["raw_sz"]))
        if slack:
            return "BSS", slack
    if is_init(s["name"]) and (s["chars"] & SCN_EXECUTE):
        return "INIT-EXEC", page_up(s["vsize"])
    if not is_init(s["name"]) and not (s["chars"] & SCN_DISCARDABLE):
        if (s["chars"] & (SCN_EXECUTE | SCN_WRITE)) == (SCN_EXECUTE | SCN_WRITE):
            return "RWX", page_up(s["vsize"])
    return None, 0


def measure(secs):
    bss = init_size = rwx_size = 0
    init_name = rwx_name = None
    for s in secs:
        kind, size = section_kind(s)
        if kind == "BSS" and size > bss:
            bss = size
        elif kind == "INIT-EXEC" and size > init_size:
            init_size, init_name = size, s["name"]
        elif kind == "RWX" and size > rwx_size:
            rwx_size, rwx_name = size, s["name"]
    return bss, init_size, init_name, rwx_size, rwx_name


def score(bss, init_size, rwx_size, sig):
    s = (rwx_size / 0x10000) * 4.0 + (init_size / 0x10000) + (bss / 0x100000)
    if sig != "Valid":
        s *= 0.5
    return s


def fmt(v):
    return f"0x{v:X}" if v else "-"


def perms(chars):
    return "".join([
        "R" if chars & SCN_READ else "-",
        "W" if chars & SCN_WRITE else "-",
        "X" if chars & SCN_EXECUTE else "-",
    ])


def authcode_status(path):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39)*2)}').Status"],
            capture_output=True, text=True, timeout=15, check=False)
        return r.stdout.strip() or "Unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "n/a"


def authcode_full(path):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$s = Get-AuthenticodeSignature -LiteralPath "
             f"'{path.replace(chr(39), chr(39)*2)}';"
             "if ($s.SignerCertificate) {"
             "  Write-Output ('Status:  ' + $s.Status);"
             "  Write-Output ('Signer:  ' + $s.SignerCertificate.Subject);"
             "  Write-Output ('Issuer:  ' + $s.SignerCertificate.Issuer);"
             "  Write-Output ('Valid:   ' + $s.SignerCertificate.NotBefore.ToString('u')"
             "                + ' -> ' + $s.SignerCertificate.NotAfter.ToString('u'));"
             "  Write-Output ('Thumb:   ' + $s.SignerCertificate.Thumbprint)"
             "} else {"
             "  Write-Output ('Status:  ' + $s.Status)"
             "}"],
            capture_output=True, text=True, timeout=15, check=False)
        return r.stdout.strip() or "Unknown"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "n/a"


def inspect(path):
    try:
        data = open(path, "rb").read()
    except OSError as e:
        print(f"[-] {e}")
        return 2
    pe = parse_pe(data)
    if not pe:
        print(f"[-] not a 64-bit PE: {path}")
        return 2

    print(f"== {os.path.basename(path)} ==")
    print(f"  Path:        {path}")
    print(f"  File size:   0x{len(data):X}")
    print(f"  SizeOfImage: 0x{pe['soi']:X}\n")

    print(f"  {'#':<3}{'Name':<10}{'VA':>11}{'VSize':>11}{'RawSize':>11}  Flags  Tags")
    print("  " + "-" * 82)
    for i, s in enumerate(pe["secs"]):
        kind, _ = section_kind(s)
        tags = []
        if is_init(s["name"]):
            tags.append("init")
        if s["chars"] & SCN_DISCARDABLE:
            tags.append("discardable")
        if kind:
            tags.append(f"<{kind}>")
        print(f"  {i:<3}{s['name']:<10}"
              f"{s['va']:>#11X}{s['vsize']:>#11X}{s['raw_sz']:>#11X}"
              f"  {perms(s['chars'])}    {' '.join(tags)}")

    bss, init_size, init_name, rwx_size, rwx_name = measure(pe["secs"])

    print()
    print("  Summary:")
    print(f"    .data BSS slack: {fmt(bss)}")
    print(f"    INIT exec:       {fmt(init_size)}{f'  ({init_name})' if init_name else ''}")
    print(f"    RWX exec:        {fmt(rwx_size)}{f'  ({rwx_name})' if rwx_name else ''}")

    print()
    print("  Signature:")
    for line in authcode_full(path).splitlines():
        print(f"    {line}")
    return 0


def find_7z():
    for p in (r"C:\Program Files\7-Zip\7z.exe",
              r"C:\Program Files (x86)\7-Zip\7z.exe"):
        if os.path.isfile(p):
            return p
    return shutil.which("7z")


def find_signtool():
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if not base:
            continue
        root = os.path.join(base, "Windows Kits", "10", "bin")
        if not os.path.isdir(root):
            continue
        hits = []
        for dp, _, files in os.walk(root):
            if "signtool.exe" in files and os.sep + "x64" + os.sep in dp + os.sep:
                hits.append(os.path.join(dp, "signtool.exe"))
        if hits:
            return sorted(hits)[-1]
    return None


_SIGNTOOL = None  # lazy-resolved + cached so we don't re-walk SDK on every call


def whcp_check(path, sig=None):
    """Return 'Pass' / 'Fail' / '?' / 'n/a'.

    Pass means signtool /kp accepts the chain under current kernel-mode CI
    policy (post-April-2026 patch revoked legacy cross-signs). Skips the
    signtool call when Authenticode already shows the file is unsigned or
    the catalog isn't reachable -- those will never pass /kp anyway.
    """
    if sig in ("NotSigned", "n/a"):
        return "Fail"
    global _SIGNTOOL
    if _SIGNTOOL is None:
        _SIGNTOOL = find_signtool() or ""
    if not _SIGNTOOL:
        return "?"
    try:
        r = subprocess.run([_SIGNTOOL, "verify", "/kp", path],
                           capture_output=True, text=True, check=False, timeout=20)
        return "Pass" if r.returncode == 0 else "Fail"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "n/a"


def extract_archive_entry(archive, rel, sevenz, dest_dir):
    rel_native = rel.replace("/", os.sep)
    r = subprocess.run(
        [sevenz, "x", "-y", "-bso0", "-bsp0",
         f"-o{dest_dir}", archive, rel_native],
        capture_output=True, text=True, check=False)
    if r.returncode not in (0, 1):
        return None
    src = os.path.join(dest_dir, rel_native)
    return src if os.path.isfile(src) else None


def save_top(rows, n, sevenz, verbose=False):
    dest = os.path.join(os.getcwd(), "result")
    os.makedirs(dest, exist_ok=True)
    saved = 0
    seen = set()

    for r in rows:
        if saved >= n:
            break
        nl = r["name"].lower()
        if nl in seen:
            continue
        seen.add(nl)

        rank = saved + 1
        out_path = os.path.join(dest, f"{rank:02d}_{r['name']}")

        if "!" in r["path"]:
            archive, rel = r["path"].split("!", 1)
            with tempfile.TemporaryDirectory(prefix="hostsave_") as tmp:
                src = extract_archive_entry(archive, rel, sevenz, tmp)
                if not src:
                    vlog(verbose, f"  save skip: {r['name']} (extract failed)")
                    continue
                shutil.copy(src, out_path)
        else:
            try:
                shutil.copy(r["path"], out_path)
            except OSError as e:
                vlog(verbose, f"  save skip: {r['name']} ({e})")
                continue

        r["saved_as"] = out_path
        saved += 1
        vlog(verbose, f"  saved {rank:02d}_{r['name']}  WHCP={r.get('whcp', '-')}")

    return saved, dest


def vlog(verbose, msg):
    if verbose:
        print(msg, file=sys.stderr, flush=True)


def evaluate(file_path, display_path, required, whcp_enabled=True, verbose=False):
    try:
        data = open(file_path, "rb").read()
    except OSError:
        return None
    pe = parse_pe(data)
    if not pe:
        return None
    bss, init_size, _, rwx_size, _ = measure(pe["secs"])
    if max(bss, init_size, rwx_size) < required:
        return None
    sig = authcode_status(file_path)
    whcp = whcp_check(file_path, sig) if whcp_enabled else "-"
    row = {
        "name": os.path.basename(display_path),
        "path": display_path,
        "bss": bss, "init": init_size, "rwx": rwx_size,
        "sig": sig, "whcp": whcp,
        "score": score(bss, init_size, rwx_size, sig),
    }
    vlog(verbose, f"  hit  {row['name']:<28} bss={fmt(bss):<10} "
                  f"init={fmt(init_size):<10} rwx={fmt(rwx_size):<10} "
                  f"sig={sig:<10} whcp={whcp:<5} score={row['score']:.2f}")
    return row


def scan_archive(archive, required, rows, sevenz, whcp_enabled=True, verbose=False):
    count = 0
    with tempfile.TemporaryDirectory(prefix="hostpick_") as tmp:
        vlog(verbose, f"[arc] {archive}")
        r = subprocess.run(
            [sevenz, "x", "-y", "-bso0", "-bsp0",
             f"-o{tmp}", archive, "-r", "*.sys"],
            capture_output=True, text=True, check=False)
        if r.returncode not in (0, 1):
            print(f"[!] 7z extract failed ({r.returncode}): {archive}",
                  file=sys.stderr)
            return 0
        for dp, _, files in os.walk(tmp):
            for f in files:
                if not f.lower().endswith(".sys"):
                    continue
                count += 1
                file_path = os.path.join(dp, f)
                rel = os.path.relpath(file_path, tmp).replace(os.sep, "/")
                row = evaluate(file_path, f"{archive}!{rel}", required,
                               whcp_enabled, verbose)
                if row:
                    rows.append(row)
        vlog(verbose, f"      extracted {count} .sys")
    return count


def scan(roots, required, whcp_enabled=True, verbose=False):
    rows = []
    scanned = 0
    sevenz = find_7z()
    sevenz_warned = False

    if verbose and sevenz:
        vlog(True, f"[7z]  {sevenz}")
    if verbose and whcp_enabled:
        global _SIGNTOOL
        if _SIGNTOOL is None:
            _SIGNTOOL = find_signtool() or ""
        vlog(True, f"[kp]  {_SIGNTOOL or '(signtool not found, WHCP=?)'}")

    for root in roots:
        vlog(verbose, f"[dir] {root}")
        for dp, _, files in os.walk(root, followlinks=True):
            for f in files:
                fl = f.lower()
                full = os.path.join(dp, f)
                if fl.endswith(".sys"):
                    scanned += 1
                    row = evaluate(full, full, required, whcp_enabled, verbose)
                    if row:
                        rows.append(row)
                elif fl.endswith(".7z"):
                    if sevenz:
                        scanned += scan_archive(full, required, rows, sevenz,
                                                whcp_enabled, verbose)
                    elif not sevenz_warned:
                        print("[!] 7z.exe not found; .7z archives skipped. "
                              "Install 7-Zip or add 7z to PATH.", file=sys.stderr)
                        sevenz_warned = True

    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows, scanned


def render_summary(rows, scanned, required, out):
    if not rows:
        out.write(f"[!] no candidates with any section >= 0x{required:X} "
                  f"(scanned {scanned} .sys)\n")
        return

    saved = sum(1 for r in rows if r.get("saved_as"))
    header = f"Scanned: {scanned} .sys files, {len(rows)} match >= 0x{required:X}"
    if saved:
        header += f"  (top {saved} saved to ./result/)"
    out.write(header + "\n\n")

    out.write(f"{'#':<4}{'Score':>7}  {'Sig':<11}{'WHCP':<5}{'Driver':<32}"
              f"{'.data BSS':>12}{'INIT exec':>12}{'RWX exec':>12}  Path\n")
    out.write("-" * 135 + "\n")
    for i, r in enumerate(rows, 1):
        whcp = r.get("whcp", "-")
        out.write(f"{i:<4}{r['score']:>7.2f}  {r['sig']:<11}{whcp:<5}"
                  f"{r['name']:<32}"
                  f"{fmt(r['bss']):>12}{fmt(r['init']):>12}{fmt(r['rwx']):>12}"
                  f"  {r['path']}\n")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+",
                   help="folders to walk, or a single .sys file to inspect")
    p.add_argument("--required", type=lambda x: int(x, 0), default=0xA7000,
                   help="scan threshold for any section column (default 0xA7000)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="log progress and per-hit info to stderr")
    p.add_argument("-o", "--output",
                   help="write the ranked summary to this file instead of stdout")
    p.add_argument("--save", type=int, default=0, metavar="N",
                   help="copy top N unique-by-name candidates into ./result/ "
                        "and run signtool /kp WHCP check on each")
    p.add_argument("--no-whcp", action="store_true",
                   help="skip the per-hit signtool /kp WHCP check (faster)")
    args = p.parse_args()

    if len(args.paths) == 1 and os.path.isfile(args.paths[0]):
        return inspect(args.paths[0])

    roots = []
    for r in args.paths:
        if os.path.isdir(r):
            roots.append(r)
        else:
            print(f"[!] not a directory: {r}", file=sys.stderr)
    if not roots:
        return 1

    rows, scanned = scan(roots, args.required,
                         whcp_enabled=not args.no_whcp, verbose=args.verbose)

    if args.save > 0 and rows:
        sevenz = find_7z()
        saved, dest = save_top(rows, args.save, sevenz, args.verbose)
        print(f"[+] saved {saved} candidate(s) to {dest}", file=sys.stderr)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            render_summary(rows, scanned, args.required, f)
        print(f"[+] wrote {len(rows)} row(s) to {args.output}", file=sys.stderr)
    else:
        render_summary(rows, scanned, args.required, sys.stdout)

    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
