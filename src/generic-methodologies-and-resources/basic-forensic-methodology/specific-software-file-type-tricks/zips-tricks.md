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

# ZIPs tricks



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

### 4) Header discrepancies and compression method anomalies (STORE/DEFLATE mismatch)

Some campaigns deliberately set inconsistent values between Local File Headers (LFH) and Central Directory (CD) for core entries, or falsify the compression method (e.g., mark entries as `STORE` even when data is deflated). This causes decompilers to throw generic "invalid ZIP" or size/method mismatch errors, slowing static triage, while Android still installs/loads the APK.

Detection with zipdetails:

```bash
zipdetails -v sample.apk | egrep -n "^(LH|SH|CFH)" -A3 | sed -n '1,200p'
# Compare Method fields for the same filename across LH/CFH
```

Heuristics and fixes:
- If core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) show conflicting Method values between LFH and CFH, treat as malicious tampering.
- Normalization: fully extract and repackage the archive to re-generate consistent headers:

```bash
unzip -qq sample.apk -d /tmp/a && (cd /tmp/a && zip -0 -qr ../repack.apk .)
# Then zipalign/apksigner if you need to re-install (for analysis use only)
```

- If extraction fails due to bogus flags, first clear GPBF bit 0 (fake encryption) as shown above, then re-zip.

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- Android banker/RAT anti-analysis observations (APK header tampering) – [GhostBat RAT: Inside the Resurgence of RTO‑Themed Android Malware](https://cyble.com/blog/ghostbat-rat-inside-the-resurgence-of-rto-themed-android-malware/)

{{#include ../../../banners/hacktricks-training.md}}
