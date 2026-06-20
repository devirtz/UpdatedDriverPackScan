# UpdatedDriverPackScan

PE section scanner for locating signed Windows kernel drivers with
exploitable section layouts. Walks a folder tree of `.sys` files, including
nested `.7z` archives, and ranks each driver by the size of three section
types relevant to manual mapping.

| Column      | Description |
|-------------|-------------|
| `.data BSS` | Page aligned slack at the end of `.data` (vsize beyond raw size, no on disk bytes). |
| `INIT exec` | Page aligned size of an EXEC section named `INIT`. |
| `RWX exec`  | Page aligned size of a non INIT, non DISCARDABLE section flagged `EXECUTE` and `WRITE`. |
| `Sig`       | Authenticode status from `Get-AuthenticodeSignature` (`Valid`, `NotSigned`, etc). |
| `WHCP`      | `signtool /kp` kernel mode policy result (`Pass`, `Fail`, `?`, `-`). |

The scanner does not require a pre extracted DriverPack. Each `.7z` is
extracted into a temporary directory for the duration of one scan pass and
deleted on completion, so peak disk usage is bounded by the `.sys` payload
of the largest single archive.

## Requirements

- Python 3.8 or later.
- [7-Zip](https://www.7-zip.org/), auto detected at the default install path
  or anywhere on `PATH`. Required only when scanning `.7z` archives.
- PowerShell. Used for `Get-AuthenticodeSignature`.
- Windows SDK `signtool.exe`, auto detected under
  `Windows Kits\10\bin\*\x64`. Required for the `WHCP` column. If absent,
  `WHCP` reports `?`.

## Usage

```bash
# Folder scan, recurses into .7z without persistent extraction.
python scan.py "D:\path\to\driverpack\drivers"

# Per file deep inspect with full signature block.
python scan.py "D:\path\to\driver.sys"

# Stream progress on stderr.
python scan.py "D:\drivers" -v

# Write the ranked summary to a file.
python scan.py "D:\drivers" -o results.txt

# Lower the size threshold (default 0xA7000, 668 KB).
python scan.py "D:\drivers" --required 0x40000

# Save the top 10 unique by name candidates into ./result/<rank>_<name>.sys.
python scan.py "D:\drivers" --save 10 -o results.txt -v

# Skip the per hit signtool /kp check for speed. WHCP column reports '-'.
python scan.py "D:\drivers" --no-whcp
```

## Score formula

```
score = (rwx_size  / 64 KB) * 4
      + (init_size / 64 KB)
      + (bss       / 1 MB)
score *= 0.5  if Authenticode status is not "Valid"
```

The score weights section size only. Authenticode penalty halves the score
for any unsigned, modified, or unverifiable file. WHCP is reported per row
but does not feed back into the score, since the policy result depends on
the verifying machine's CI configuration.

## Latest results

The most recent full pack scan output is in [`./results.txt`](./results.txt).
The top 10 unique driver files saved with `--save 10` are in
[`./result/`](./result/), named `<rank>_<driver>.sys`.

## Source DriverPack

The scan was produced against the offline DriverPack distribution. A torrent
file for the same revision is available under
[`./resource/DriverPack-Offline.torrent`](./resource/DriverPack-Offline.torrent).
