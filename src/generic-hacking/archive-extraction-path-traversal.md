# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 概述

许多 archive 格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带其自身的 **内部路径**。当 extraction utility 盲目遵循该路径时，包含 `..` 或**绝对路径**（例如 `C:\Windows\System32\`）的 crafted filename 将被写入用户选择目录之外。
此类 vulnerability 广为人知，被称为 *Zip-Slip* 或 **archive extraction path traversal**。<sup>[[6]](#references)</sup>

其后果包括覆盖任意文件，甚至可以通过将 payload 写入 Windows *Startup* folder 等**自动运行**位置，直接实现**远程代码执行（RCE）**。

## 根本原因

1. Attacker 创建一个 archive，其中一个或多个 file header 包含：
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 或者 crafted **symlinks**，其解析结果位于 target dir 之外（在 *nix* 中的 ZIP/TAR 很常见）。
2. Victim 使用存在 vulnerability 的 tool 提取 archive。该 tool 信任嵌入的 path（或遵循 symlinks），而不是对其进行 sanitising，或强制将内容提取到所选 directory 之下。
3. 文件被写入 attacker-controlled location，并在下次系统或 user 触发该 path 时被执行/加载。

### .NET `Path.Combine` + `ZipArchive` traversal

一种常见的 .NET anti-pattern 是将预期 destination 与 **user-controlled** `ZipArchiveEntry.FullName` 组合，并在未进行 path normalisation 的情况下提取内容：<sup>[[4]](#references)[[8]](#references)</sup>
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
- 如果 `entry.FullName` 以 `..\\` 开头，它会执行路径遍历；如果它是一个**绝对路径**，左侧组件会被完全丢弃，从而以提取身份实现**任意文件写入**。
- 用于写入由计划扫描器监视的同级 `app` 目录的概念验证归档：
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
将该 ZIP 放入受监控的 inbox 后，会生成 `C:\samples\app\0xdf.txt`，这证明了可以遍历到 `C:\samples\queue\` 之外，并启用后续利用原语（例如 DLL hijacks）。

## Advanced Archive-Breakout Primitives

将提取视为一系列文件系统变更，而不是相互独立的文件名检查。某个条目在解析时可能是安全的，但在前一个成员创建或替换链接后可能变得不安全；当提取器将目录缓存为安全对象、而该目录的类型随后发生变化时，也会出现同样的问题。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**：创建 `pivot -> /tmp`，然后将普通成员提取为 `pivot/PWNED.txt`。如果提取器在实例化第二个成员时跟随第一个成员，写入就会逃逸，即使第二个名称中没有 `..`。
* **Directory-cache/TOCTOU collision**：生成目录 `d/sub/`，将 `d/sub` 替换为指向 `/tmp` 的 symlink，然后生成 `d/sub/PWNED.txt`。这会攻击那些只验证或缓存一次目录、且在最终写入前不重新检查目录的提取器。
* **Hardlink read/overwrite**：TAR 和 RAR 可以表示 hardlink。指向主机上现有文件的 hardlink 可能会在后续组件提供提取名称时暴露其内容；而发生冲突的普通条目则可能覆盖该链接指向的 inode。这受到同一文件系统以及 OS hardlink 权限规则的限制。
* **Pre-existing or cross-archive pivot**：使用非空目标目录重试。一个 archive 可以植入链接，后续提取过程可以通过该链接写入，即使每个 archive 都通过了无状态的 header-name 检查。<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

使用将接收这些名称的文件系统的语义进行比较。实用的差分测试用例包括：在大小写不敏感的文件系统上比较 `LINK` 与 `link`、NFC 与 NFD Unicode 拼写、兼容性等价名称（例如 `ﬁle` 与 `file`）、会将路径从目录变为 symlink 的重复成员，以及仅在 Windows 上将反斜杠解释为分隔符的情况。还应测试包含 ADS 的 NTFS 名称。这些情况可能导致 validator 看到两条路径，而文件系统实际解析为一条路径。<sup>[[5]](#references)[[11]](#references)</sup>

因此，一个精简的 corpus 应测试以下有序组合：**directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、混合使用 `/` 和 `\`、绝对/根路径名称，以及 `.tar.gz` 等压缩包装格式。仅在一次性 VM/container 中运行，并同时监控目标路径和预期的外部 canary 路径。<sup>[[11]](#references)</sup>

ZIP 特有的结构歧义可能导致预扫描和实际提取器观察到不同的条目名称或目录树。请参阅 [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion)，不要只信任单个 ZIP library 的输出。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 版 WinRAR 及其 Windows RAR/UnRAR 组件未能在提取过程中验证文件名。该漏洞利用 NTFS alternate data streams (ADS) 绕过选定的提取路径，将文件写入非预期位置。<sup>[[5]](#references)</sup>
一个包含如下条目的恶意 RAR archive：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
最终会位于所选输出目录**之外**，并进入用户的 *Startup* 文件夹。ESET 观察到恶意 LNK 文件在那里被解包，并在用户登录时执行，从而实现持久化并提供 RCE 路径。<sup>[[5]](#references)</sup>

### 构建 PoC Archive（Linux/Mac）

由于 CVE-2025-8088 在 ADS 名称中使用了 traversal 路径，应使用专用生成器创建 RAR，然后仅在隔离实验室中使用存在漏洞的 WinRAR 版本测试解压。<sup>[[5]](#references)</sup>

### 现实中的已观察到的利用

ESET 报告称，RomCom（Storm-0978/UNC2596）开展了 spear-phishing 活动，附带滥用 CVE-2025-8088 的 RAR 压缩包，用于部署定制 backdoor 并协助 ransomware 行动。<sup>[[5]](#references)</sup>

## 更新的案例（2024–2026）

### 7-Zip ZIP symlink traversal → RCE（CVE-2025-11001 / ZDI-25-949）
* **Bug**：解压过程中会对作为 **symbolic links** 的 ZIP 条目进行 dereference，使攻击者能够逃逸目标目录并覆盖任意路径。用户只需*打开/解压*该 archive 即可触发。<sup>[[1]](#references)</sup>
* **受影响版本**：**25.00** 之前的 7-Zip 构建版本。该 symbolic-link 处理缺陷已在 **25.00**（2025 年 7 月）及后续版本中修复。<sup>[[1]](#references)[[10]](#references)</sup>
* **影响路径**：覆盖 `Start Menu/Programs/Startup` 或由 service 运行的位置 → 代码会在下次登录或 service 重启时运行。
* **symlink 处理的快速 fixture（Linux）**：
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
该 archive 包含一个指向解压目录外部的 symlink 条目；应使用 disposable target，并验证 extractor 不会跟随该 symlink。写入测试还需要在该 symlink 下存在一个 regular-file 条目。

### Go mholt/archiver `Unarchive()` symlink collision（CVE-2025-3445）
* **Bug**：`archiver.Unarchive()` 可以解压一个 ZIP symlink，随后当后续的 regular member 具有相同名称时对其进行 dereference，使表面上位于根目录内的写入变成根目录外写入。<sup>[[2]](#references)</sup>
* **受影响版本**：`github.com/mholt/archiver` ≤ 3.5.1（该项目现已 deprecated）。<sup>[[2]](#references)</sup>
* **修复**：切换到 `mholt/archives` ≥ 0.1.0，或拒绝 links，并在打开每个 destination 之前立即重新解析它。<sup>[[2]](#references)</sup>
* **最小 collision generator**（随后调用 `archiver.Unarchive("exploit.zip", "/tmp/safe")`）：<sup>[[2]](#references)</sup>
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

即使使用 `tarfile.extractall(filter="data")` 和 `filter="tar"`，也曾存在通过 link 顺序实现 bypass 的情况。在此案例中，一个 hardlink 引用了存档中更深路径上的 symlink；fallback extraction 在该深层位置验证了相对 symlink，却在 hardlink 更浅层的位置重新创建了它，而相同的相对目标在该位置发生了逃逸。这是一个有用的通用测试：让 validation 与 materialisation 对 base directory 或最终 member type 的判断不一致。<sup>[[12]](#references)</sup>

### Node `tar` 通过 symlink chain 逃逸 hardlink target（GHSA-83g3-92jg-28cx）

Node.js `tar` package 的 `tar.extract()` 接受了一个 hardlink，其 target 从词法上看似包含在内，但实际上通过之前的两个 symlink 解析到了 extraction root 外部。该攻击可使用默认 extraction options 生效：destination-parent 检查覆盖了 hardlink 的 in-root name，而 hardlink target 在未解析完整 chain 以确认其包含关系的情况下就被传递给了 filesystem。`tar` ≤ 7.5.7 受影响；7.5.8 修复了该问题。<sup>[[13]](#references)</sup>

重要的 test fixture 是 members 之间的**有序关系**，而不是这些字面名称：<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
如果 extraction 成功，`exfil` 仍会在输出树中清晰可见，但它会与选定的外部文件共享 inode；读取它会 leak 该文件，写入它则会修改原文件。这说明为什么仅检查最终 pathname、去除绝对路径前缀，或在 hardlink header 中阻止 `..` 都是不够的：必须在应用所有此前已 extraction 的 filesystem state 后，再验证 link targets。<sup>[[13]](#references)</sup>

## Detection Tips

* **Static inspection** – 列出所有 member names 和 link targets。标记 `../`、`..\\`、absolute/rooted paths、symlinks、hardlinks、special files、duplicate names、type changes，以及大小写/Unicode 等价冲突。审查时保留 entry order，因为 exploit 可能依赖更早的 members。<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – 确保 resolved parent 加上 final basename 后仍位于 resolved destination 下方（比较 path components，而不是原始字符串前缀）。在每个 preceding member 后重新检查；一次性的 `realpath(join(dest, name))` 检查容易受到 link replacement 攻击，并且可能因 leaf 尚未创建而失效。<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – 使用带有 path/symlink checks 的 extractor，将内容 decompression 到一个全新的 disposable directory 中（例如，bsdtar 的默认 secure checks 或 7-Zip ≥ 25.00），然后验证生成的 tree 不包含任何指向外部的 links。Isolation 必须阻止已经触发的 escape 访问 host paths。<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – 即使 extraction 本身没有创建任何外部文件，残留的 symlink 或 hardlink 仍可能在 previewer、CDN、file browser 或 package pipeline 随后打开或提供 extracted name 时，成为 arbitrary-file-read primitive。<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – 当 WinRAR/7-Zip 等打开 archive 后不久，在 `Startup`/`Run`/`cron` locations 中写入新的 executables 时发出 alert。

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+、7-Zip 25.00+ 和 Node `tar` 7.5.8+ 已包含针对所引用 path/symlink/link-target issues 的 fixes。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 尽可能使用 “**Do not extract paths**” / “**Ignore paths**” 来 extraction archives。对于不受信任的 input，除非 application 明确需要，否则应拒绝 symbolic links、hardlinks、devices 和 FIFOs。<sup>[[9]](#references)[[11]](#references)</sup>
3. 将 archives extraction 到一个**新的空目录**中。不要将不受信任的 members merge 到包含 attacker-replaceable paths 的 tree 中，也不要重新使用由此前 archive 建立的 directory。<sup>[[11]](#references)</sup>
4. 在 Unix 上降低 privileges，并将 destination 隔离在 **chroot/mount namespace** 中；在 Windows 上使用 **AppContainer** 或 sandbox。仅执行 post-extraction scan 并不足够，因为 escaped write 会在 scan 之前发生。<sup>[[11]](#references)</sup>
5. 在 custom code 中，应用目标 OS 的 separator/case/Unicode rules，并同时验证 member 和 link target。在不跟随 links 的情况下 resolve 并 open destination；不要将 containment check 与之后的 create/replace operation 分开。validator 必须使用与 write path 完全相同的 base 和 link-emulation semantics。<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Snyk 发布大规模 *Zip-Slip* advisory，影响许多 Java/Go/JS libraries。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 slugs TAR extraction traversal（已在 v0.16.3 中修复）。<sup>[[7]](#references)</sup>
* 任何只验证 header strings，却不验证 link targets 以及每次 write 所使用的 final filesystem path 的 custom extraction logic。<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – 防止 .NET 中的 Zip Slip](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 立即更新 WinRAR tools：RomCom 和其他攻击者正在利用 zero-day vulnerability（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 公开披露一项 Critical Arbitrary File Overwrite Vulnerability：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug 易受 Zip Slip Attack 攻击（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip 中 CVE-2025-11001 的 Proof-of-Concept Exploit 报告](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – 使用 zip-slips、tar-slips、symlinks、hardlinks、collisions 等进行 hacking 的乐趣](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar 通过 symlink chain 实现 hardlink target escape](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
