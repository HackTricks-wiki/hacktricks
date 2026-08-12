# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

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

## Newer Cases (2024–2025)

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

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
  ```go
  // go test . with archiver<=3.5.1
  archiver.Unarchive("exploit.zip", "/tmp/safe")
  // exploit.zip holds ../../../../home/user/.ssh/authorized_keys
  ```

## Detection Tips

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`/`, `C:`) or entries of type *symlink* whose target is outside the extraction dir.
* **Canonicalisation** – Ensure `realpath(join(dest, name))` stays inside `realpath(dest)` (compare path components, not only a raw string prefix). Reject otherwise.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress into a disposable directory using an extractor with path/symlink checks (for example, bsdtar's default secure checks or 7-Zip ≥ 25.00), then verify resulting paths stay inside the directory.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run`/`cron` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ contain fixes for the d path/symlink issues.<sup>[[1]](#references)[[5]](#references)</sup>
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (fixed in v0.16.3).<sup>[[7]](#references)</sup>
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

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

{{#include ../banners/hacktricks-training.md}}
