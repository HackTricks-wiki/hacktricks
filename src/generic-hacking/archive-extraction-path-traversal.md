# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Overview

Many archive formats (ZIP, RAR, TAR, 7-ZIP, etc.) allow each entry to carry its own **internal path**. When an extraction utility blindly honours that path, a crafted filename containing `..` or an **absolute path** (e.g. `C:\Windows\System32\`) will be written outside of the user-chosen directory.  
This class of vulnerability is widely known as *Zip-Slip* or **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Consequences range from overwriting arbitrary files to directly achieving **remote code execution (RCE)** by dropping a payload in an **auto-run** location such as the Windows *Startup* folder.

## Root Cause

1. Attacker creates an archive where one or more file headers contain:
   * Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*). 
2. Victim extracts the archive with a vulnerable tool that trusts the embedded path (or follows symlinks) instead of sanitising it or forcing extraction beneath the chosen directory.
3. The file is written in the attacker-controlled location and executed/loaded next time the system or user triggers that path.

### .NET `Path.Combine` + `ZipArchive` traversal

A common .NET anti-pattern is combining the intended destination with **user-controlled** `ZipArchiveEntry.FullName` and extracting without path normalisation:<sup>[[4]](#references)[[8]](#references)</sup>

```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
    foreach (var entry in zip.Entries)
    {
        var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
        entry.ExtractToFile(dest);
    }
}
```

- If `entry.FullName` starts with `..\\` it traverses; if it is an **absolute path** the left-hand component is discarded entirely, yielding an **arbitrary file write** as the extraction identity.
- Proof-of-concept archive to write into a sibling `app` directory watched by a scheduled scanner:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Dropping that ZIP into the monitored inbox results in `C:\samples\app\0xdf.txt`, proving traversal outside `C:\samples\queue\` and enabling follow-on primitives (e.g., DLL hijacks).

## Advanced Archive-Breakout Primitives

Treat extraction as a sequence of filesystem mutations, not as independent filename checks. An entry that is safe when parsed can become unsafe after an earlier member creates or replaces a link; the same issue appears when an extractor caches a directory as safe and later changes its type.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: create `pivot -> /tmp`, then extract a regular member as `pivot/PWNED.txt`. If the extractor follows the first member while materialising the second, the write escapes without `..` in the second name.
* **Directory-cache/TOCTOU collision**: emit directory `d/sub/`, replace `d/sub` with a symlink to `/tmp`, then emit `d/sub/PWNED.txt`. This targets extractors that validate or cache the directory once and do not re-check it before the final write.
* **Hardlink read/overwrite**: TAR and RAR can represent hardlinks. A hardlink to an existing host file may expose its contents if a later component serves the extracted name; a colliding regular entry can instead overwrite the linked inode. This is limited by same-filesystem and OS hardlink-permission rules.
* **Pre-existing or cross-archive pivot**: retry with a non-empty destination. One archive can plant a link and a later extraction can write through it even if each archive passes a stateless header-name check.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Compare names using the semantics of the filesystem that will receive them. Useful differential cases include `LINK` versus `link` on case-insensitive filesystems, NFC versus NFD Unicode spellings, compatibility-equivalent names such as `ﬁle` versus `file`, duplicate members that change a path from directory to symlink, and backslashes interpreted as separators only on Windows. Also test ADS-bearing names on NTFS. These cases can make the validator see two paths while the filesystem resolves one.<sup>[[5]](#references)[[11]](#references)</sup>

A compact corpus should therefore test ordered combinations of **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mixed `/` and `\`, absolute/rooted names, and compressed wrappers such as `.tar.gz`. Run it only in a disposable VM/container and watch both the destination and the intended outside canary path.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows and its Windows RAR/UnRAR components failed to validate filenames during extraction. The flaw used NTFS alternate data streams (ADS) to bypass the selected extraction path and write files to unintended locations.<sup>[[5]](#references)</sup>
A malicious RAR archive containing an entry such as:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET observed malicious LNK files being unpacked there and executed at user logon, providing persistence and a path to RCE.<sup>[[5]](#references)</sup>

### Crafting a PoC Archive (Linux/Mac)

Because CVE-2025-8088 uses a traversal path in an ADS name, use a purpose-built generator to create the RAR, then test extraction only in an isolated lab with a vulnerable WinRAR build.<sup>[[5]](#references)</sup>

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.<sup>[[5]](#references)</sup>

## Newer Cases (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds before **25.00**. The symbolic-link processing flaw was fixed in **25.00** (July 2025) and later.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick symlink-handling fixture (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  This archive contains a symlink entry pointing outside the extraction directory; use a disposable target and verify that the extractor does not follow it. A write-through test also needs a regular-file entry beneath the symlink.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` can extract a ZIP symlink and then dereference it when a later regular member has the same name, turning an apparently in-root write into an out-of-root write.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or reject links and re-resolve every destination immediately before opening it.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (then call `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

Even `tarfile.extractall(filter="data")` and `filter="tar"` have had link-order bypasses. In this case, a hardlink referenced a symlink archived at a deeper path; fallback extraction validated the relative symlink at that deep location but recreated it at the hardlink's shallower location, where the same relative target escaped. This is a useful general test: make validation and materialisation disagree about the base directory or final member type.<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – List both member names and link targets. Flag `../`, `..\\`, absolute/rooted paths, symlinks, hardlinks, special files, duplicate names, type changes, and case/Unicode-equivalent collisions. Preserve entry order during review because the exploit may depend on earlier members.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Ensure the resolved parent plus final basename remains beneath the resolved destination (compare path components, not a raw string prefix). Re-check after every preceding member; a one-time `realpath(join(dest, name))` test is vulnerable to link replacement and may fail for a not-yet-created leaf.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Decompress into a fresh, disposable directory using an extractor with path/symlink checks (for example, bsdtar's default secure checks or 7-Zip ≥ 25.00), then verify the resulting tree contains no outward links. Isolation must prevent an already-triggered escape from reaching host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – A surviving symlink or hardlink can become an arbitrary-file-read primitive when a previewer, CDN, file browser, or package pipeline later opens or serves the extracted name, even if extraction itself created no outside file.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ contain fixes for the cited path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible. For untrusted input, reject symbolic links, hardlinks, devices and FIFOs unless the application explicitly needs them.<sup>[[9]](#references)[[11]](#references)</sup>
3. Extract into a **new empty directory**. Do not merge untrusted members into a tree containing attacker-replaceable paths, and do not reuse a directory planted by an earlier archive.<sup>[[11]](#references)</sup>
4. On Unix, drop privileges and isolate the destination in a **chroot/mount namespace**; on Windows, use **AppContainer** or a sandbox. A post-extraction scan alone is insufficient because an escaped write occurs before the scan.<sup>[[11]](#references)</sup>
5. In custom code, apply the target OS's separator/case/Unicode rules and validate both the member and link target. Resolve and open the destination without following links; do not separate a containment check from a later create/replace operation. The validator must use the exact same base and link-emulation semantics as the write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (fixed in v0.16.3).<sup>[[7]](#references)</sup>
* Any custom extraction logic that validates header strings but not link targets and the final filesystem path used for each write.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Proof-of-Concept Exploit Reported for CVE-2025-11001 in 7-Zip](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Hacking fun with zip-slips, tar-slips, symlinks, hardlinks, collisions, and more](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
