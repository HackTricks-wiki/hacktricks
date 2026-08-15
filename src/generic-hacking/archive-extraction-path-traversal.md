# Archive Extraction Path Traversal（"Zip-Slip"）

{{#include ../banners/hacktricks-training.md}}

## 概述

许多 archive 格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带自己的 **内部路径**。当 extraction utility 盲目遵循该路径时，包含 `..` 的 crafted filename 或 **绝对路径**（例如 `C:\Windows\System32\`）将被写入用户选择的目录之外。
此类 vulnerability 广为人知，被称为 *Zip-Slip* 或 **archive extraction path traversal**。<sup>[[6]](#references)</sup>

后果包括覆盖任意文件，甚至通过将 payload 放入 Windows *Startup* 文件夹等 **auto-run** 位置，直接实现 **remote code execution (RCE)**。

## 根本原因

1. Attacker 创建一个 archive，其中一个或多个文件头包含：
* 相对 traversal 序列（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* 绝对路径（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
* 或者 crafted **symlinks**，其解析结果位于目标目录之外（在 *nix* 的 ZIP/TAR 中很常见）。
2. Victim 使用 vulnerable tool 提取 archive，该工具信任嵌入的路径（或遵循 symlinks），而不是对其进行 sanitising，或强制将内容提取到所选目录之下。
3. 文件被写入 attacker-controlled location，并在系统或用户下次触发该路径时执行/加载。

### .NET `Path.Combine` + `ZipArchive` traversal

一种常见的 .NET anti-pattern 是将预期目标路径与 **user-controlled** 的 `ZipArchiveEntry.FullName` 组合，并在未进行 path normalisation 的情况下执行提取：<sup>[[4]](#references)[[8]](#references)</sup>
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
- 如果 `entry.FullName` 以 `..\\` 开头，它会执行路径遍历；如果它是一个**绝对路径**，则左侧组件会被完全丢弃，从而以提取身份实现**任意文件写入**。
- 用于写入由 scheduled scanner 监视的同级 `app` 目录的 PoC archive：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 放入受监控的 inbox 后，会生成 `C:\samples\app\0xdf.txt`，证明其能够 traversal 到 `C:\samples\queue\` 之外，并启用后续利用原语（例如 DLL hijack）。

## Advanced Archive-Breakout Primitives

应将 extraction 视为一系列 filesystem mutations，而不是彼此独立的 filename checks。某个 entry 在解析时可能是安全的，但在更早的 member 创建或替换 link 后可能变得不安全；当 extractor 将某个 directory 缓存为安全对象、而其类型随后发生变化时，也会出现同样的问题。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**：创建 `pivot -> /tmp`，然后将一个 regular member 提取为 `pivot/PWNED.txt`。如果 extractor 在 materialising 第二个 member 时跟随第一个 member，则即使第二个名称中没有 `..`，写入也会逃逸。
* **Directory-cache/TOCTOU collision**：生成 directory `d/sub/`，将 `d/sub` 替换为指向 `/tmp` 的 symlink，然后生成 `d/sub/PWNED.txt`。这针对的是只验证或缓存一次 directory、而不会在最终写入前重新检查它的 extractor。
* **Hardlink read/overwrite**：TAR 和 RAR 可以表示 hardlink。指向现有 host file 的 hardlink 可能在后续组件提供 extracted name 时暴露其内容；发生冲突的 regular entry 则可能改写被链接的 inode。这受到 same-filesystem 和 OS hardlink-permission rules 的限制。
* **Pre-existing or cross-archive pivot**：使用非空 destination 重试。即使每个 archive 都通过了无状态的 header-name check，一个 archive 仍可植入 link，后续 extraction 则可以通过该 link 写入。<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

应根据将接收这些名称的 filesystem 语义进行比较。有用的 differential cases 包括：在 case-insensitive filesystem 上比较 `LINK` 与 `link`、NFC 与 NFD Unicode 拼写、如 `ﬁle` 与 `file` 这类 compatibility-equivalent names、将 path 从 directory 更改为 symlink 的 duplicate members，以及仅在 Windows 上作为 separators 解释的 backslashes。还应测试 NTFS 上包含 ADS 的 names。这些情况可能导致 validator 看到两个 paths，而 filesystem 实际解析为一个。<sup>[[5]](#references)[[11]](#references)</sup>

因此，一个精简的 corpus 应测试以下有序组合：**directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、混合使用 `/` 和 `\`、absolute/rooted names，以及 `.tar.gz` 等 compressed wrappers。只能在 disposable VM/container 中运行，并同时监控 destination 和预期的 outside canary path。<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 版 WinRAR 及其 Windows RAR/UnRAR components 在 extraction 期间未能验证 filenames。该 flaw 利用 NTFS alternate data streams (ADS) 绕过选定的 extraction path，将 files 写入非预期 locations。<sup>[[5]](#references)</sup>
一个包含如下 entry 的恶意 RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET 观察到恶意 LNK 文件被解压到那里，并在用户登录时执行，从而实现持久化并提供 RCE 路径。<sup>[[5]](#references)</sup>

### 构造 PoC Archive（Linux/Mac）

由于 CVE-2025-8088 在 ADS 名称中使用了 traversal path，因此应使用专用生成器创建 RAR，然后仅在隔离实验室中使用存在漏洞的 WinRAR build 测试解压。<sup>[[5]](#references)</sup>

### 野外观察到的 Exploitation

ESET 报告称，RomCom（Storm-0978/UNC2596）开展了 spear-phishing campaigns，附带滥用 CVE-2025-8088 的 RAR archives，以部署定制 backdoors 并促进 ransomware operations。<sup>[[5]](#references)</sup>

## 更新案例（2024–2026）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**：解压过程中会对作为 **symbolic links** 的 ZIP entries 进行 dereference，使攻击者能够逃逸目标目录并覆盖任意路径。用户只需*打开/解压*该 archive 即可触发。<sup>[[1]](#references)</sup>
* **受影响版本**：**25.00** 之前的 7-Zip builds。该 symbolic-link processing flaw 已在 **25.00**（2025 年 7 月）及更高版本中修复。<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**：覆盖 `Start Menu/Programs/Startup` 或 service-run locations → 代码会在下一次登录或 service restart 时运行。
* **简单的 symlink-handling fixture（Linux）**：
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
该 archive 包含一个指向 extraction directory 外部的 symlink entry；请使用 disposable target，并确认 extractor 不会跟随该 symlink。要测试 write-through，还需要在该 symlink 下方放置一个 regular-file entry。

### Go mholt/archiver `Unarchive()` symlink collision（CVE-2025-3445）
* **Bug**：`archiver.Unarchive()` 可以解压 ZIP symlink，随后当后续 regular member 使用相同名称时 dereference 该 symlink，将表面上位于 root 内的写入转变为 root 外的写入。<sup>[[2]](#references)</sup>
* **受影响版本**：`github.com/mholt/archiver` ≤ 3.5.1（该 project 现已 deprecated）。<sup>[[2]](#references)</sup>
* **修复**：切换到 `mholt/archives` ≥ 0.1.0，或拒绝 links，并在打开每个 destination 前立即重新解析。<sup>[[2]](#references)</sup>
* **最小 collision generator**（然后调用 `archiver.Unarchive("exploit.zip", "/tmp/safe")`）：<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass（CVE-2026-11940）

即使使用 `tarfile.extractall(filter="data")` 和 `filter="tar"`，也曾存在 link-order bypass。在此案例中，一个 hardlink 引用了存储在更深路径中的 symlink；fallback extraction 在该深层位置验证了 relative symlink，但却在 hardlink 更浅的位置重新创建它，而相同的 relative target 在那里发生了逃逸。这是一个有用的通用测试：让 validation 与 materialisation 对 base directory 或最终 member type 的判断不一致。<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – 同时列出 member names 和 link targets。标记 `../`、`..\\`、absolute/rooted paths、symlinks、hardlinks、special files、duplicate names、type changes，以及 case/Unicode-equivalent collisions。审查时保留 entry order，因为 exploit 可能依赖之前的 members。<sup>[[11]](#references)</sup>
* **Canonicalisation** – 确保 resolved parent 加上 final basename 后仍位于 resolved destination 下方（比较 path components，而不是原始 string prefix）。在每个 preceding member 之后重新检查；一次性的 `realpath(join(dest, name))` 测试容易受到 link replacement 影响，并且对尚未创建的 leaf 可能失效。<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – 使用带有 path/symlink checks 的 extractor（例如 bsdtar 的默认 secure checks 或 7-Zip ≥ 25.00），将内容解压到全新且 disposable 的 directory，然后确认生成的 tree 不包含任何向外的 links。Isolation 必须阻止已经触发的 escape 访问 host paths。<sup>[[1]](#references)[[9]](#references)</sup>
* **下游读取同样重要** – 即使 extraction 本身没有创建任何外部文件，残留的 symlink 或 hardlink 也可能在 previewer、CDN、file browser 或 package pipeline 后续打开或提供该 extracted name 时，成为 arbitrary-file-read primitive。<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – 当 WinRAR/7-Zip 等程序打开 archive 后不久，有新的 executables 被写入 `Startup`/`Run`/`cron` locations 时发出告警。

## Mitigation & Hardening

1. **更新 extractor** – WinRAR 7.13+ 和 7-Zip 25.00+ 已包含针对所引述 path/symlink issues 的修复。<sup>[[1]](#references)[[5]](#references)</sup>
2. 尽可能使用“**Do not extract paths**”/“**Ignore paths**”解压 archives。对于不可信输入，除非 application 明确需要，否则应拒绝 symbolic links、hardlinks、devices 和 FIFOs。<sup>[[9]](#references)[[11]](#references)</sup>
3. 将 archives 解压到**新的空 directory**中。不要将不可信 members 合并到包含攻击者可替换 paths 的 tree 中，也不要重新使用由之前的 archive 创建的 directory。<sup>[[11]](#references)</sup>
4. 在 Unix 上降低 privileges，并将 destination 隔离在 **chroot/mount namespace** 中；在 Windows 上使用 **AppContainer** 或 sandbox。仅执行 post-extraction scan 并不足够，因为 escaped write 会在扫描之前发生。<sup>[[11]](#references)</sup>
5. 在 custom code 中，应用目标 OS 的 separator/case/Unicode rules，并同时验证 member 和 link target。在不跟随 links 的情况下 resolve 并打开 destination；不要将 containment check 与之后的 create/replace operation 分开。validator 必须使用与 write path 完全相同的 base 和 link-emulation semantics。<sup>[[11]](#references)[[12]](#references)</sup>

## 其他受影响 / 历史案例

* 2018 – Snyk 发布的 Massive *Zip-Slip* advisory，影响许多 Java/Go/JS libraries。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 TAR extraction traversal in slugs（已在 v0.16.3 中修复）。<sup>[[7]](#references)</sup>
* 任何只验证 header strings、却不验证 link targets 以及每次写入所使用的最终 filesystem path 的 custom extraction logic。<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – 防止 .NET 中的 Zip Slip](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 立即更新 WinRAR tools：RomCom 等正在利用 zero-day vulnerability（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 公开披露 Critical Arbitrary File Overwrite Vulnerability：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug 易受 Zip Slip Attack 攻击（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip 中报告了 CVE-2025-11001 的 Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – 使用 zip-slips、tar-slips、symlinks、hardlinks、collisions 等进行 Hacking 的乐趣](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
