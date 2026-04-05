# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**: Reveals why a zip file may not decompress.
- **`zipdetails -v`**: Offers detailed analysis of zip file format fields.
- **`zipinfo`**: Lists contents of a zip file without extracting them.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Try to repair corrupted zip files.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: A tool for brute-force cracking of zip passwords, effective for passwords up to around 7 characters.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

It's crucial to note that password-protected zip files **do not encrypt filenames or file sizes** within, a security flaw not shared with RAR or 7z files which encrypt this information. Furthermore, zip files encrypted with the older ZipCrypto method are vulnerable to a **plaintext attack** if an unencrypted copy of a compressed file is available. This attack leverages the known content to crack the zip's password, a vulnerability detailed in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) and further explained in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). However, zip files secured with **AES-256** encryption are immune to this plaintext attack, showcasing the importance of choosing secure encryption methods for sensitive data.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers use malformed ZIP metadata to break static tools (jadx/apktool/unzip) while keeping the APK installable on-device. The most common tricks are:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Symptoms:
- `jadx-gui` fails with errors like:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` prompts for a password for core APK files even though a valid APK cannot have encrypted `classes*.dex`, `resources.arsc`, or `AndroidManifest.xml`:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Detection with zipdetails:

```bash
zipdetails -v sample.apk | less
```

Look at the General Purpose Bit Flag for local and central headers. A telltale value is bit 0 set (Encryption) even for core entries:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristic: If an APK installs and runs on-device but core entries appear "encrypted" to tools, the GPBF was tampered with.

Fix by clearing GPBF bit 0 in both Local File Headers (LFH) and Central Directory (CD) entries. Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

Usage:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) Large/custom Extra fields to break parsers

Attackers stuff oversized Extra fields and odd IDs into headers to trip decompilers. In the wild you may see custom markers (e.g., strings like `JADXBLOCK`) embedded there.

Inspection:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Examples observed: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- Alert when Extra fields are unusually large on core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Treat unknown Extra IDs on those entries as suspicious.

Practical mitigation: rebuilding the archive (e.g., re-zipping extracted files) strips malicious Extra fields. If tools refuse to extract due to fake encryption, first clear GPBF bit 0 as above, then repackage:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) File/Directory name collisions (hiding real artifacts)

A ZIP can contain both a file `X` and a directory `X/`. Some extractors and decompilers get confused and may overlay or hide the real file with a directory entry. This has been observed with entries colliding with core APK names like `classes.dex`.

Triage and safe extraction:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Programmatic detection post-fix:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Blue-team detection ideas:
- Flag APKs whose local headers mark encryption (GPBF bit 0 = 1) yet install/run.
- Flag large/unknown Extra fields on core entries (look for markers like `JADXBLOCK`).
- Flag path-collisions (`X` and `X/`) specifically for `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Recent phishing campaigns ship a single blob that is actually **two ZIP files concatenated**. Each has its own End of Central Directory (EOCD) + central directory. Different extractors parse different directories (7zip reads the first, WinRAR the last), letting attackers hide payloads that only some tools show. This also bypasses basic mail gateway AV that inspects only the first directory.

**Triage commands**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```

If more than one EOCD appears or there is "data after payload" warnings, split the blob and inspect each part:

```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" builds a tiny **kernel** (highly compressed DEFLATE block) and reuses it via overlapping local headers. Every central directory entry points to the same compressed data, achieving >28M:1 ratios without nesting archives. Libraries that trust central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) can be forced to allocate petabytes.

**Quick detection (duplicate LFH offsets)**

```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**Handling**
- Perform a dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` and ensure offsets are strictly increasing and unique.
- Cap accepted total uncompressed size and entry count before extraction (`zipdetails -t` or custom parser).
- When you must extract, do it inside a cgroup/VM with CPU+disk limits (avoid unbounded inflation crashes).

---

### Local-header vs central-directory parser confusion

Recent differential-parser research showed that ZIP ambiguity is still exploitable in modern toolchains. The main idea is simple: some software trusts the **Local File Header (LFH)** while others trust the **Central Directory (CD)**, so one archive can present different filenames, paths, comments, offsets, or entry sets to different tools.

Practical offensive uses:
- Make an upload filter, AV pre-scan, or package validator see a benign file in the CD while the extractor honors a different LFH name/path.
- Abuse duplicate names, entries present only in one structure, or ambiguous Unicode path metadata (for example, Info-ZIP Unicode Path Extra Field `0x7075`) so different parsers reconstruct different trees.
- Combine this with path traversal to turn a "harmless" archive view into a write-primitive during extraction. For the extraction side, see [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triage:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

Complement it with:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristics:
- Reject or isolate archives with mismatched LFH/CD names, duplicate filenames, multiple EOCD records, or trailing bytes after the final EOCD.
- Treat ZIPs using unusual Unicode-path extra fields or inconsistent comments as suspicious if different tools disagree on the extracted tree.
- If analysis matters more than preserving the original bytes, repackage the archive with a strict parser after extraction in a sandbox and compare the resulting file list to the original metadata.

This matters beyond package ecosystems: the same ambiguity class can hide payloads from mail gateways, static scanners, and custom ingestion pipelines that "peek" at ZIP contents before a different extractor handles the archive.

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
