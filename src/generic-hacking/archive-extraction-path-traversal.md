# Archive Extraction Path Traversal（"Zip-Slip" / WinRAR CVE-2025-8088）

{{#include ../banners/hacktricks-training.md}}

## 概述

许多 archive 格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带自己的 **internal path**。当 extraction utility 盲目信任该路径时，包含 `..` 或 **absolute path**（例如 `C:\Windows\System32\`）的 crafted filename 就会被写入用户选择目录之外。
这类 vulnerability 通常被称为 *Zip-Slip* 或 **archive extraction path traversal**。<sup>[[6]](#references)</sup>

后果可能包括覆盖任意文件，甚至通过将 payload 写入 Windows *Startup* folder 等 **auto-run** 位置，直接实现 **remote code execution (RCE)**。

## 根本原因

1. Attacker 创建一个 archive，其中一个或多个 file headers 包含：
* Relative traversal sequences（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* Absolute paths（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* 或者 crafted **symlinks**，其解析结果位于 target dir 之外（在 *nix* 的 ZIP/TAR 中很常见）。
2. Victim 使用 vulnerable tool 提取 archive；该工具信任 embedded path（或跟随 symlinks），而不是对其进行 sanitising，或强制将文件提取到所选目录之下。
3. 文件被写入 attacker-controlled location，并在系统或 user 下次触发该路径时被 executed/loaded。

### .NET `Path.Combine` + `ZipArchive` traversal

一种常见的 .NET anti-pattern 是将预期目标路径与 **user-controlled** `ZipArchiveEntry.FullName` 结合，并在未进行 path normalisation 的情况下提取文件：<sup>[[4]](#references)[[8]](#references)</sup>
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
- 如果 `entry.FullName` 以 `..\\` 开头，则会发生路径遍历；如果它是一个**绝对路径**，则左侧组件会被完全丢弃，从而以提取目标的身份实现**任意文件写入**。
- 用于写入由 scheduled scanner 监视的同级 `app` 目录的 PoC archive：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 放入受监控的 inbox 后，会生成 `C:\samples\app\0xdf.txt`，证明可以通过 traversal 路径跳出 `C:\samples\queue\`，并启用后续利用原语（例如 DLL hijacks）。

## 真实世界示例 – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows 及其 Windows RAR/UnRAR components 在 extraction 期间未能验证文件名。该漏洞利用 NTFS alternate data streams (ADS) 绕过所选 extraction path，并将文件写入非预期位置。<sup>[[5]](#references)</sup>
包含如下 entry 的恶意 RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
会最终位于所选输出目录**之外**，并进入用户的 *Startup* 文件夹。ESET 观察到恶意 LNK 文件被解压到该处，并在用户登录时执行，从而实现 persistence 并提供 RCE 路径。<sup>[[5]](#references)</sup>

### 构造 PoC Archive（Linux/Mac）

由于 CVE-2025-8088 在 ADS 名称中使用 traversal path，因此应使用专用生成器创建 RAR，然后仅在隔离 lab 中使用存在漏洞的 WinRAR build 测试 extraction。<sup>[[5]](#references)</sup>

### 实际观察到的 Exploitation

ESET 报告称，RomCom（Storm-0978/UNC2596）的 spear-phishing campaigns 附带滥用 CVE-2025-8088 的 RAR archives，用于部署定制 backdoors 并协助 ransomware operations。<sup>[[5]](#references)</sup>

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**：extraction 期间会对作为 **symbolic links** 的 ZIP entries 进行 dereference，使 attackers 能够逃逸 destination directory 并覆盖任意 paths。用户只需*打开/extract* archive 即可触发。<sup>[[1]](#references)</sup>
* **Affected**：**25.00** 之前的 7-Zip builds。该 symbolic-link processing flaw 已在 **25.00**（2025 年 7 月）及更高版本中修复。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**：覆盖 `Start Menu/Programs/Startup` 或 service-run locations → 代码将在下次 logon 或 service restart 时运行。
* **Quick symlink-handling fixture (Linux)**：
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
该 archive 包含一个指向 extraction directory 外部的 symlink entry；请使用 disposable target，并验证 extractor 不会 follow 它。write-through test 还需要在 symlink 下方存在一个 regular-file entry。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**：`archiver.Unarchive()` 会 follow `../` 和 symlinked ZIP entries，将内容写到 `outputDir` 外部。<sup>[[2]](#references)</sup>
* **Affected**：`github.com/mholt/archiver` ≤ 3.5.1（该 project 现已 deprecated）。
* **Fix**：切换到 `mholt/archives` ≥ 0.1.0，或在 write 前实现 canonical-path checks。
* **Minimal reproduction**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – 列出 archive entries，并标记名称中包含 `../`、`..\\`、*absolute paths*（`/`、`C:`）的 entries，或标记 type 为 *symlink* 且 target 位于 extraction dir 外部的 entries。
* **Canonicalisation** – 确保 `realpath(join(dest, name))` 保持在 `realpath(dest)` 内部（比较 path components，而不只是比较原始 string prefix）。否则拒绝。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – 使用带有 path/symlink checks 的 extractor（例如 bsdtar 的 default secure checks 或 7-Zip ≥ 25.00），将内容 decompress 到 disposable directory，然后验证生成的 paths 仍位于该 directory 内部。<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – 如果 archive 被 WinRAR/7-Zip 等打开后不久，在 `Startup`/`Run`/`cron` locations 中写入了新的 executables，则发出 alert。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ 和 7-Zip 25.00+ 包含针对所引用 path/symlink issues 的 fixes。<sup>[[1]](#references)[[5]](#references)</sup>
2. 尽可能使用“**Do not extract paths**”/“**Ignore paths**” extraction archives。
3. 在 Unix 上，在 extraction 前降低 privileges 并 mount **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或 sandbox。
4. 如果编写 custom code，请在 create/write **之前**使用 `realpath()`/`PathCanonicalize()` 进行 normalise，并拒绝任何逃逸 destination 的 entry。

## Additional Affected / Historical Cases

* 2018 – Snyk 发布大规模 *Zip-Slip* advisory，影响众多 Java/Go/JS libraries。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 TAR extraction traversal in slugs（已在 v0.16.3 中修复）。<sup>[[7]](#references)</sup>
* 任何在 write 前未调用 `PathCanonicalize` / `realpath` 的 custom extraction logic。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – 在 .NET 中防止 Zip Slip](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 立即更新 WinRAR tools：RomCom 和其他团伙正在利用 zero-day vulnerability（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 公开披露 Critical Arbitrary File Overwrite Vulnerability：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug Vulnerable to Zip Slip Attack（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 在 7-Zip 中发现 CVE-2025-11001 的 Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
