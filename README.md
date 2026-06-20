# UpdatedDriverPackScan

PE-section scanner for finding signed Windows kernel drivers usable for multi purposes. Walks a folder tree of `.sys` files (and `.7z`
archives) and ranks each driver by the size of three section types that
matter for hosting code:

| Column     | What it means |
|------------|---------------|
| `.data BSS` | Slack at the end of `.data` |
| `INIT exec` | EXEC INIT-named section |
| `RWX exec`  | Non-INIT, non-DISCARDABLE section with both `EXECUTE` and `WRITE` flags |
| `Sig`       | Authenticode status (`Valid`, `NotSigned`, etc.) |
| `WHCP`      | `signtool /kp` kernel-mode policy result (`Pass`, `Fail`, `?`, `-`) |

`scan.py` does not need the DriverPack to be unpacked first. `.7z` archives
are extracted into a temp dir per archive, scanned, then deleted &mdash; so
the whole multi-GB pack only ever needs the disk space of one archive's
`.sys` files at a time.

---

## Requirements

- Python 3.8+
- [7-Zip](https://www.7-zip.org/) (auto-detected at the default install path
  or anywhere on `PATH`). Required only when you scan `.7z` archives.
- PowerShell (Windows-only, used for `Get-AuthenticodeSignature`).
- Windows SDK `signtool.exe` (auto-detected under `Windows Kits\10\bin\*\x64`).
  Required for the `WHCP` column. If absent, `WHCP` shows `?`.

---

## Usage

```bash
# Folder scan (recurses into .7z without extracting to disk)
python scan.py "D:\Arch\Reverse Engineering\DriverPack\drivers"

# Per-file deep inspect: every section, full signature block
python scan.py "D:\some\driver.sys"

# Live progress on stderr, summary to stdout
python scan.py "D:\drivers" -v

# Quiet scan, summary to file
python scan.py "D:\drivers" -o results.txt

# Lower the size threshold (default 0xA7000 = 668 KB)
python scan.py "D:\drivers" --required 0x40000

# Save the top 10 unique-by-name candidates into ./result/<rank>_<name>.sys
python scan.py "D:\drivers" --save 10 -o results.txt -v

# Skip the per-hit signtool /kp check (faster scan, WHCP column shows '-')
python scan.py "D:\drivers" --no-whcp
```

---

## Score formula

```
score = (rwx_size  / 64 KB) * 4
      + (init_size / 64 KB)
      + (bss       / 1 MB)
score *= 0.5  if Authenticode status is not "Valid"
```

Higher score = bigger usable section, with a hard penalty for unsigned
drivers.