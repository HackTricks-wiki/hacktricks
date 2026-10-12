# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 概述

许多归档格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带自己的**内部路径**。如果解压工具不加检查地使用该路径，包含 `..` 的精心构造的文件名或**绝对路径**（例如 `C:\Windows\System32\`）就会导致文件被写入用户所选目录之外。  
这种漏洞通常称为 *Zip-Slip* 或**归档解压路径穿越**。<sup>[[6]](#references)</sup>

其后果包括覆盖任意文件，甚至通过将 payload 放入 **auto-run** 位置（例如 Windows *Startup* 文件夹）直接实现**远程代码执行（RCE）**。

## 根本原因

1. 攻击者创建一个归档文件，其中一个或多个文件头包含：
   * 相对路径穿越序列（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
   * 绝对路径（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
   * 或会解析到目标目录之外的精心构造的 **symlink**（在 *nix* 上常见）。
2. 受害者使用存在漏洞的工具解压归档文件。该工具信任嵌入的路径（或跟随 symlink），而没有对其进行清理，也没有强制将文件解压到所选目录之下。
3. 文件被写入攻击者控制的位置，并在下次系统或用户触发该路径时执行或加载。

### .NET `Path.Combine` + `ZipArchive` 路径穿越

.NET 中一种常见的反模式是将预期的目标路径与**用户可控的** `ZipArchiveEntry.FullName` 组合，然后在未规范化路径的情况下进行解压：<sup>[[4]](#references)[[8]](#references)</sup>

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

- 如果 `entry.FullName` 以 `..\\` 开头，就会发生路径遍历；如果它是**绝对路径**，左侧组件会被完全丢弃，从而导致**任意文件写入**。
- 用于写入相邻 `app` 目录（由定时扫描器监控）的概念验证归档文件：

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

将该 ZIP 放入受监控的收件箱后，会生成 `C:\samples\app\0xdf.txt`，这证明路径遍历可越出 `C:\samples\queue\`，并可用于后续利用手段（例如 DLL hijacks）。

### 用户可控的解压根目录

还要测试**传给解压器的目录**，而不仅是压缩包成员名称。应用可能会根据标题、项目名称或其他请求字段来确定该目录。像 `../../../../app/module` 这样的值可以在解压器处理任何成员之前，将解压根目录移出上传区域。在这种情况下，即使压缩包只包含安全的基本文件名 `api.py`，也能覆盖应用程序代码。<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

这是一个不同于经典 Zip-Slip 的隔离边界。验证解析后的解压根目录和每个解析后的成员路径。根目录检查可以使用路径组件，而不是字符串前缀：<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

为了进行安全测试，上传一个包含单个 canary 文件的有效 archive，并在每个可能用于选择解压目录的字段中放入路径遍历序列。监控预期目录和一个临时的外部路径。如果目标位置可以访问某个导入模块，覆盖该模块可能会在 worker 重新加载时导致代码执行；重新加载期间出现 HTTP 500 或连接重置，并不能证明写入失败。<sup>[[14]](#references)[[15]](#references)</sup>另请参阅更全面的 [file upload methodology](../pentesting-web/file-upload/)。

## Advanced Archive-Breakout Primitives

应将解压视为一系列文件系统修改，而非互不相关的文件名检查。一个条目在解析时可能是安全的，但之前的成员创建或替换链接后，它就可能变得不安全；当解压器将某个目录缓存为安全目录，而之后该目录的类型发生变化时，也会出现同样的问题。<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**：创建 `pivot -> /tmp`，然后将一个普通成员解压为 `pivot/PWNED.txt`。如果解压器在写入第二个成员时会跟随第一个成员，那么即使第二个名称中没有 `..`，写入也会逃逸到目标目录之外。
* **Directory-cache/TOCTOU collision**：先写入目录 `d/sub/`，再将 `d/sub` 替换为指向 `/tmp` 的 symlink，然后写入 `d/sub/PWNED.txt`。这会攻击那些只验证或缓存一次目录、在最终写入前不再检查目录的解压器。
* **Hardlink read/overwrite**：TAR 和 RAR 可以表示 hardlink。如果 hardlink 指向现有主机文件，后续组件提供解压后的文件名时，可能会暴露该文件的内容；而与之冲突的普通条目则可能覆盖该链接所指向的 inode。这受限于同一文件系统要求和操作系统的 hardlink 权限规则。
* **Pre-existing or cross-archive pivot**：在非空目标目录中重试。即使每个 archive 都通过了无状态的头部文件名检查，一个 archive 仍可能植入链接，后续解压再通过该链接写入。<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

比较名称时，应采用接收这些名称的文件系统所使用的语义。值得测试的差异情况包括：不区分大小写的文件系统上的 `LINK` 与 `link`、NFC 与 NFD Unicode 拼写、`ﬁle` 与 `file` 这类兼容等价名称、通过重复成员将路径从目录改为 symlink，以及仅在 Windows 上被解释为分隔符的反斜杠。还应测试 NTFS 上包含 ADS 的名称。这些情况可能导致验证器看到两个路径，而文件系统将它们解析为同一个路径。<sup>[[5]](#references)[[11]](#references)</sup>

因此，一个精简的测试集应覆盖以下有序组合：**directory → symlink → child**、**symlink → colliding regular file**、**hardlink → colliding regular file**、混用 `/` 和 `\`、绝对/根路径名称，以及 `.tar.gz` 等压缩封装格式。只在一次性 VM/container 中运行，并同时监控目标目录和预期的外部 canary 路径。<sup>[[11]](#references)</sup>

ZIP 特有的结构歧义可能导致预扫描器与实际解压器观察到不同的条目名称或目录树。请参阅 [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion)，不要只信任一个 ZIP 库的输出。

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows 版 WinRAR 及其 Windows RAR/UnRAR 组件在解压时未能验证文件名。该漏洞利用 NTFS alternate data streams (ADS) 绕过选定的解压路径，将文件写入非预期位置。<sup>[[5]](#references)</sup>
一个包含如下条目的恶意 RAR archive：

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

最终会落在所选输出目录**之外**，并进入用户的 *Startup* 文件夹。ESET 观察到恶意 LNK 文件被解包到该文件夹，并在用户登录时执行，从而实现 persistence 并提供 RCE 路径。<sup>[[5]](#references)</sup>

### 制作 PoC Archive（Linux/Mac）

由于 CVE-2025-8088 在 ADS 名称中使用了路径遍历路径，因此请使用专用生成器创建 RAR，并且仅在隔离实验环境中使用存在漏洞的 WinRAR 版本测试解压。<sup>[[5]](#references)</sup>

### 野外观察到的利用情况

ESET 报告称，RomCom（Storm-0978/UNC2596）发起的鱼叉式网络钓鱼活动会附上滥用 CVE-2025-8088 的 RAR 压缩包，用于部署定制后门并协助勒索软件行动。<sup>[[5]](#references)</sup>

## 较新的案例（2024–2026）

### 7-Zip ZIP symlink 路径遍历 → RCE（CVE-2025-11001 / ZDI-25-949）
* **漏洞**：解压时会跟随 ZIP 条目中的**符号链接**，使攻击者能够逃出目标目录并覆盖任意路径。用户只需*打开/解压*压缩包即可触发。<sup>[[1]](#references)</sup>
* **受影响版本**：低于 **25.00** 的 7-Zip 版本。符号链接处理漏洞已在 **25.00**（2025 年 7 月）及更高版本中修复。<sup>[[1]](#references)[[10]](#references)</sup>
* **影响路径**：覆盖 `Start Menu/Programs/Startup` 或服务运行位置 → 在下次登录或服务重启时运行代码。
* **快速 symlink 处理测试样例（Linux）**：
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  此 archive 包含一个指向提取目录之外的 symlink 条目；请使用一次性目标，并验证 extractor 不会跟随它。write-through 测试还需要在 symlink 下方有一个常规文件条目。

### Go mholt/archiver `Unarchive()` symlink 冲突 (CVE-2025-3445)
* **Bug**：`archiver.Unarchive()` 可以先提取 ZIP symlink，然后在后续的常规成员具有相同名称时对其解引用，将看似发生在目录内的写入变成目录外写入。<sup>[[2]](#references)</sup>
* **受影响版本**：`github.com/mholt/archiver` ≤ 3.5.1（该项目现已弃用）。<sup>[[2]](#references)</sup>
* **修复**：切换到 `mholt/archives` ≥ 0.1.0，或者拒绝链接，并在打开每个目标之前重新解析路径。<sup>[[2]](#references)</sup>
* **最小冲突生成器**（然后调用 `archiver.Unarchive("exploit.zip", "/tmp/safe")）：<sup>[[2]](#references)</sup>
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

即使使用 `tarfile.extractall(filter="data")` 和 `filter="tar")`，也曾存在链接顺序绕过问题。在此案例中，一个 hardlink 引用了归档中位于更深路径的 symlink；回退提取逻辑在该深层位置验证了相对 symlink，却在 hardlink 较浅的位置重新创建了它，因此同一个相对目标在新位置逃逸了。这是一个实用的通用测试方法：让验证与实际写入使用不同的基目录，或对最终成员类型作出不同判断。<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape through a symlink chain (GHSA-83g3-92jg-28cx)

Node.js `tar` package 的 `tar.extract()` 接受了一个 hardlink，其目标在词法上看似位于提取根目录内，但经过前面两个 symlink 解析后却落在根目录之外。使用默认提取选项即可发起攻击：目标父目录检查只覆盖了位于根目录内的 hardlink 名称，而 hardlink 目标在未解析完整链接链以确认其是否位于根目录内的情况下，就被传递给了文件系统。`tar` ≤ 7.5.7 受影响；7.5.8 修复了此问题。<sup>[[13]](#references)</sup>

重要的测试样例在于成员之间的**顺序关系**，而不是这些具体名称：<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

如果提取成功，`exfil` 会明显留在输出目录树中，但与选定的外部文件共享同一个 inode；读取它会泄露该文件，写入它则会修改原文件。此绕过说明，仅检查最终路径、移除绝对路径前缀，或在 hardlink header 中阻止 `..` 都不足以防范：验证链接目标时，必须考虑此前已提取的所有文件系统状态。<sup>[[13]](#references)</sup>

## 检测提示

* **静态检查** – 列出所有成员名称和链接目标。标记 `../`、`..\\`、绝对路径/根路径、symlinks、hardlinks、特殊文件、重复名称、类型变更，以及大小写/Unicode 等价冲突。审查时保留条目顺序，因为 exploit 可能依赖此前的成员。<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **规范化** – 确保解析后的父路径加上最终 basename 仍位于解析后的目标目录之下（比较路径组件，而不是原始字符串前缀）。每处理完前一个成员后都要重新检查；仅执行一次 `realpath(join(dest, name))` 测试容易受到链接替换影响，而且对于尚未创建的叶节点可能无法通过检查。<sup>[[3]](#references)[[11]](#references)</sup>
* **沙箱解压** – 使用带路径/符号链接检查功能的解压工具，将文件解压到全新且可丢弃的目录中（例如 bsdtar 默认的安全检查或 7-Zip ≥ 25.00），然后确认生成的目录树中没有指向外部的链接。隔离措施必须确保已经触发的路径逃逸无法访问主机路径。<sup>[[1]](#references)[[9]](#references)</sup>
* **后续读取同样重要** – 即使解压本身没有在外部创建文件，残留的符号链接或硬链接也可能在预览器、CDN、文件浏览器或软件包流水线之后打开或提供已解压文件时，成为任意文件读取原语。<sup>[[11]](#references)</sup>
* **端点监控** – 如果 WinRAR/7-Zip 等程序打开归档文件后不久，`Startup`/`Run`/`cron` 位置出现新写入的可执行文件，则发出警报。

## 缓解与加固

1. **更新解压工具** – WinRAR 7.13+、7-Zip 25.00+ 和 Node `tar` 7.5.8+ 已包含针对所引路径/符号链接/链接目标问题的修复。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 尽可能使用“**不解压路径**”/“**忽略路径**”选项解压归档文件。对于不可信输入，除非应用明确需要，否则应拒绝符号链接、硬链接、设备文件和 FIFO。<sup>[[9]](#references)[[11]](#references)</sup>
3. 将文件解压到**新的空目录**。不要将不可信成员合并到包含攻击者可替换路径的目录树中，也不要重用先前归档文件创建的目录。<sup>[[11]](#references)</sup>
4. 在 Unix 上，降低权限，并将目标目录隔离在 **chroot/mount namespace** 中；在 Windows 上，使用 **AppContainer** 或沙箱。仅在解压后扫描并不足够，因为路径逃逸写入发生在扫描之前。<sup>[[11]](#references)</sup>
5. 在自定义代码中，应用目标操作系统的分隔符/大小写/Unicode 规则，并同时验证成员和链接目标。在不跟随链接的情况下解析并打开目标位置；不要将包含性检查与之后的创建/替换操作分开执行。验证器必须使用与写入路径完全相同的基准路径和链接模拟语义。<sup>[[11]](#references)[[12]](#references)</sup>

## 其他受影响案例 / 历史案例

* 2018 – Snyk 发布大规模 *Zip-Slip* 安全公告，涉及许多 Java/Go/JS 库。<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug`（CVE-2025-0377）中的 slug TAR 解压路径遍历问题（已在 v0.16.3 修复）。<sup>[[7]](#references)</sup>
* 任何自定义解压逻辑：只验证头部字符串，却不验证链接目标以及每次写入所使用的最终文件系统路径。<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip 符号链接 ZIP 路径遍历（CVE-2025-11001）](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip（CVE-2025-3445）](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – 在 .NET 中防止 Zip Slip](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL 劫持链](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 立即更新 WinRAR 工具：RomCom 等正在利用零日漏洞（CVE-2025-8088）](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 公开披露严重的任意文件覆盖漏洞：Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01：go-slug 易受 Zip Slip 攻击（CVE-2025-0377）](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine 方法](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar 安全解压标志](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 报告了针对 7-Zip 中 CVE-2025-11001 的概念验证漏洞利用](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip、tar-slip、符号链接、硬链接、冲突等的有趣安全研究](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile 解压过滤器绕过](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar 硬链接目标通过符号链接链逃逸](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – 用户可控的 SCORM 解压根目录](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Frappe LMS 中的多个漏洞导致远程代码执行](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
