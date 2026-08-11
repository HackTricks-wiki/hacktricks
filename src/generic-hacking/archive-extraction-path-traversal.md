# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

许多 archive 格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带自己的 **internal path**。当 extraction 工具盲目遵循该路径时，包含 `..` 或 **absolute path**（例如 `C:\Windows\System32\`）的 crafted filename 将被写入用户选择目录之外。
这类漏洞通常被称为 *Zip-Slip* 或 **archive extraction path traversal**。<sup>[[6]](#references)</sup>

其后果可能从覆盖任意文件，到通过将 payload 放入 Windows *Startup* 文件夹等 **auto-run** 位置，直接实现 **remote code execution (RCE)**。

## Root Cause

1. Attacker 创建一个 archive，其中一个或多个文件头包含：
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 或者 crafted **symlinks**，其解析结果位于目标目录之外（在 *nix* 的 ZIP/TAR 中很常见）。
2. Victim 使用存在漏洞的工具提取 archive；该工具信任嵌入的路径（或遵循 symlinks），而不是对其进行 sanitising，或强制将内容提取到所选目录之下。
3. 文件被写入 attacker 控制的位置，并在系统或用户下次触发该路径时被执行/加载。

### .NET `Path.Combine` + `ZipArchive` traversal

一种常见的 .NET anti-pattern 是将预期目标路径与 **user-controlled** 的 `ZipArchiveEntry.FullName` 结合，并在未进行 path normalisation 的情况下执行提取：<sup>[[4]](#references)[[8]](#references)</sup>
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
- 如果 `entry.FullName` 以 `..\\` 开头，它会执行路径遍历；如果它是一个**绝对路径**，左侧组件将被完全丢弃，从而以提取身份实现**任意文件写入**。
- 用于写入由 scheduled scanner 监控的同级 `app` 目录的 proof-of-concept archive：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 放入受监控的 inbox 后，会生成 `C:\samples\app\0xdf.txt`，证明其能够 traversal 到 `C:\samples\queue\` 之外，并启用后续利用原语（例如 DLL hijacks）。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 版 WinRAR 及其 Windows RAR/UnRAR 组件在 extraction 期间未能验证文件名。该漏洞利用 NTFS alternate data streams (ADS) 绕过选定的 extraction 路径，并将文件写入非预期位置。<sup>[[5]](#references)</sup>
一个包含如下条目的恶意 RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET 观察到恶意 LNK files 被解压到该位置，并在用户登录时执行，从而提供 persistence 和通往 RCE 的路径。<sup>[[5]](#references)</sup>

### Crafting a PoC Archive (Linux/Mac)

由于 CVE-2025-8088 在 ADS name 中使用 traversal path，因此应使用专用 generator 创建 RAR，然后仅在隔离实验室中使用存在漏洞的 WinRAR build 测试 extraction。<sup>[[5]](#references)</sup>

### Observed Exploitation in the Wild

ESET 报告了 RomCom (Storm-0978/UNC2596) spear-phishing campaigns：这些 campaigns 附加了滥用 CVE-2025-8088 的 RAR archives，用于部署 customised backdoors 并协助 ransomware operations。<sup>[[5]](#references)</sup>

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**：ZIP entries 若为 **symbolic links**，会在 extraction 过程中被 dereference，使 attackers 能够逃逸目标目录并覆盖任意 paths。用户只需进行*打开/解压* archive 的操作。<sup>[[1]](#references)</sup>
* **Affected**：**25.00** 之前的 7-Zip builds。symbolic-link processing flaw 已在 **25.00**（2025 年 7 月）及更高版本中修复。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**：覆盖 `Start Menu/Programs/Startup` 或 service-run locations → code 在下次登录或 service restart 时运行。
* **Quick symlink-handling fixture (Linux)**：
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
该 archive 包含一个指向 extraction directory 外部的 symlink entry；请使用 disposable target，并验证 extractor 不会 follow 它。write-through test 还需要在 symlink 下方放置一个 regular-file entry。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**：`archiver.Unarchive()` 会 follow `../` 和 symlinked ZIP entries，将内容写入 `outputDir` 外部。<sup>[[2]](#references)</sup>
* **Affected**：`github.com/mholt/archiver` ≤ 3.5.1（该 project 现已 deprecated）。
* **Fix**：切换到 `mholt/archives` ≥ 0.1.0，或在 write 前实现 canonical-path checks。
* **Minimal reproduction**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – 列出 archive entries，并标记名称中包含 `../`、`..\\`、*absolute paths*（`/`、`C:`）的 entries，或标记 target 位于 extraction dir 外部的 *symlink* 类型 entries。
* **Canonicalisation** – 确保 `realpath(join(dest, name))` 位于 `realpath(dest)` 内部（比较 path components，而不仅是原始 string prefix）。否则拒绝。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – 使用带有 path/symlink checks 的 extractor（例如 bsdtar 的默认 secure checks 或 7-Zip ≥ 25.00）将内容解压到 disposable directory，然后验证生成的 paths 仍位于该 directory 内部。<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – 如果 archive 被 WinRAR/7-Zip 等打开后不久，有新的 executables 被写入 `Startup`/`Run`/`cron` locations，则发出 alert。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ 和 7-Zip 25.00+ 已包含针对 d path/symlink issues 的 fixes。<sup>[[1]](#references)[[5]](#references)</sup>
2. 在可能的情况下，使用“**Do not extract paths**”/“**Ignore paths**” extraction archives。
3. 在 Unix 上，在 extraction 前 drop privileges 并 mount **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或 sandbox。
4. 如果编写 custom code，应在 create/write **之前**使用 `realpath()`/`PathCanonicalize()` 进行 normalise，并拒绝任何逃逸出 destination 的 entry。

## Additional Affected / Historical Cases

* 2018 – Snyk 发布大规模 *Zip-Slip* advisory，影响许多 Java/Go/JS libraries。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 TAR extraction traversal in slugs（已在 v0.16.3 中修复）。<sup>[[7]](#references)</sup>
* 任何未在 write 前调用 `PathCanonicalize` / `realpath` 的 custom extraction logic。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – 在 .NET 中防止 Zip Slip](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 立即更新 WinRAR tools：RomCom 和其他组织正在利用 zero-day vulnerability（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 公开披露一项严重的任意文件覆盖漏洞：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug 易受 Zip Slip Attack 攻击（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip 中 CVE-2025-11001 的 Proof-of-Concept Exploit 已被报告](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
