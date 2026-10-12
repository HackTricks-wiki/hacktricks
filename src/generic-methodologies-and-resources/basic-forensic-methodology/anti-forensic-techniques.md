# 反取证技术

{{#include ../../banners/hacktricks-training.md}}

## 时间戳

攻击者可能会想要**更改文件的时间戳**以避免被发现。\
可以在 MFT 的属性 `$STANDARD_INFORMATION` \_\_ 和 \_\_ `$FILE_NAME` 中找到时间戳。

这两个属性都包含 4 个时间戳：**修改时间**、**访问时间**、**创建时间**和 **MFT 记录修改时间**（MACE 或 MACB）。

**Windows 资源管理器**和其他工具显示的是 **`$STANDARD_INFORMATION`** 中的信息。

### TimeStomp - 反取证工具

此工具会**修改** **`$STANDARD_INFORMATION`** 中的时间戳信息，**但不会**修改 **`$FILE_NAME`** 中的信息。因此，可以**识别**可疑活动。

### Usnjrnl

**USN Journal**（Update Sequence Number Journal，更新序列号日志）是 NTFS（Windows NT 文件系统）的功能，用于跟踪卷上的更改。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 工具可以检查这些更改。

![TimeStomp - 反取证工具 - Usnjrnl：USN Journal（Update Sequence Number Journal，更新序列号日志）是 NTFS（Windows NT 文件系统）的功能，用于跟踪卷上的更改。……](<../../images/image (801).png>)

上图是该**工具**显示的**输出**，可以看到文件发生了**一些更改**。

### $LogFile

**文件系统的所有元数据更改都会通过一种称为[预写日志](https://en.wikipedia.org/wiki/Write-ahead_logging)的机制记录下来**。记录的元数据保存在名为 `**$LogFile**` 的文件中，该文件位于 NTFS 文件系统的根目录。可以使用 [LogFileParser](https://github.com/jschicht/LogFileParser) 等工具解析此文件并识别更改。

![Usnjrnl - $LogFile：文件系统的所有元数据更改都会通过一种称为预写日志的机制记录下来。记录的元数据保存在名为 $LogFile 的文件中，该文件位于根目录……](<../../images/image (137).png>)

同样，在工具的输出中可以看到**发生了一些更改**。

使用同一工具，还可以识别时间戳**被修改成了什么时间**：

![Usnjrnl - $LogFile：使用同一工具，可以识别时间戳被修改成了什么时间](<../../images/image (1089).png>)

- CTIME：文件的创建时间
- ATIME：文件的修改时间
- MTIME：文件的 MFT 记录修改时间
- RTIME：文件的访问时间

### `$STANDARD_INFORMATION` 和 `$FILE_NAME` 对比

识别可疑的已修改文件的另一种方法是比较这两个属性中的时间，查找**不匹配**的情况。

### 纳秒

**NTFS** 时间戳的**精度**为 **100 纳秒**。因此，如果发现文件的时间戳类似于 2010-10-10 10:10:**00.000:0000，就非常可疑**。

### SetMace - 反取证工具

此工具可以修改 `$STARNDAR_INFORMATION` 和 `$FILE_NAME` 两个属性。不过，从 Windows Vista 开始，必须在运行中的 OS 上才能修改这些信息。

## 数据隐藏

NFTS 使用簇和最小信息大小。这意味着，如果一个文件占用一个半簇，那么剩下的**半个簇将永远不会被使用**，直到该文件被删除。因此，可以**在这个 slack space 中隐藏数据**。

有一些工具（例如 slacker）可以在这个“隐藏”空间中隐藏数据。不过，分析 `$logfile` 和 `$usnjrnl` 可以发现有数据被添加：

![SetMace - 反取证工具 - 数据隐藏：有一些工具（例如 slacker）可以在这个“隐藏”空间中隐藏数据。不过，分析 $logfile 和 $usnjrnl 可以发现……](<../../images/image (1060).png>)

之后，可以使用 FTK Imager 等工具恢复 slack space。请注意，这类工具可能会以混淆甚至加密的形式保存内容。

## UsbKill

这是一个工具，可在检测到 USB 端口发生任何变化时**关闭计算机**。\
一种发现它的方法是检查正在运行的进程，并**查看每个正在运行的 Python 脚本**。

## Live Linux 发行版

这些发行版在 **RAM** 内存中运行。只有在 NTFS 文件系统以可写权限挂载的情况下，才能检测到它们。如果只以只读权限挂载，就无法检测到入侵。

## 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Windows 延迟自删除

Windows 映像正在运行时，可能会因进程处于活动状态而被锁定。进程可以将删除操作交给子进程 `cmd.exe`，使用 `choice` 作为计时器，并在 shell 执行 `del` 之前退出。延迟可以让原始进程释放其映像句柄；如果完整路径中包含空格，就必须将其括起来。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

当此字符串直接作为参数传递给 `cmd.exe`，而不是从另一个交互式 `cmd` 提示符中键入时，请使用 `&` 而非 `^&`，并使用 `>nul` 而非 `^>nul`。这会移除目录项；**这不是安全擦除**，也不会清除执行痕迹、任务痕迹、文件系统日志或其他取证痕迹。搜寻命令行中同时包含 `choice /T`、`Del` 和父进程映像路径的短暂 `cmd.exe` 子进程。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows 配置

可以禁用多种 Windows 日志记录方式，使取证调查变得困难得多。

### 禁用时间戳 - UserAssist

这是一个注册表项，用于记录用户运行每个可执行文件的日期和时间。

禁用 UserAssist 需要两个步骤：

1. 将两个注册表项 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 和 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 都设为零，以表明我们希望禁用 UserAssist。
2. 清除类似于 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` 的注册表子树。

### 禁用时间戳 - Prefetch

此功能会保存有关已执行应用程序的信息，以提高 Windows 系统的性能。不过，这些信息也可用于取证。

- 执行 `regedit`
- 选择文件路径 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击 `EnablePrefetcher` 和 `EnableSuperfetch`
- 分别选择“修改”，将值从 1（或 3）改为 0
- 重启

### 禁用时间戳 - Last Access Time

每当从 Windows NT 服务器上的 NTFS 卷打开文件夹时，系统都会**更新每个已列出文件夹上的时间戳字段**，该字段称为最后访问时间。在使用频繁的 NTFS 卷上，这可能会影响性能。

1. 打开注册表编辑器 (Regedit.exe)。
2. 浏览到 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找 `NtfsDisableLastAccessUpdate`。如果不存在，请新建此 DWORD，并将其值设为 1，以禁用该功能。
4. 关闭注册表编辑器，然后重启服务器。

### 删除 USB 历史记录

所有**USB 设备条目**都存储在 Windows 注册表的 **USBSTOR** 注册表项下；每当你将 USB 设备插入 PC 或笔记本电脑时，都会创建相应的子项。你可以在此处找到该项：H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除该项**即可删除 USB 历史记录。\
你也可以使用工具 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 确认是否已将它们删除（并删除它们）。

另一个保存 USB 信息的文件是 `C:\Windows\INF` 中的 `setupapi.dev.log`。也应该删除此文件。

### 禁用卷影副本

使用 `vssadmin list shadowstorage` **列出**卷影副本\
运行 `vssadmin delete shadow` **删除**它们

你也可以按照 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) 中提供的步骤，通过 GUI 删除它们。

要禁用卷影副本，请参阅[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 点击 Windows“开始”按钮后，在文本搜索框中输入“services”，打开“服务”程序。
2. 在列表中找到“Volume Shadow Copy”，选中它，然后右键单击并打开“属性”。
3. 在“启动类型”下拉菜单中选择“禁用”，然后点击“应用”和“确定”确认更改。

也可以在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` 中修改卷影副本要复制的文件配置。

### 覆盖已删除的文件

- 你可以使用 **Windows 工具**：`cipher /w:C` 该命令会指示 cipher 清除 C 盘可用的未使用磁盘空间中的所有数据。
- 你也可以使用 [**Eraser**](https://eraser.heidi.ie) 等工具。

### 删除 Windows 事件日志

- Windows + R --> eventvwr.msc --> 展开“Windows 日志” --> 右键单击各个类别并选择“清除日志”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### 禁用 Windows 事件日志

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 在“服务”部分禁用“Windows Event Log”服务
- `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

### 禁用 $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## 高级日志记录与跟踪篡改 (2023-2025)

### PowerShell ScriptBlock/Module 日志记录

近期版本的 Windows 10/11 和 Windows Server 会在
`Microsoft-Windows-PowerShell/Operational` 下保留**丰富的 PowerShell 取证痕迹**（事件 4104/4105/4106）。  
攻击者可以实时禁用或清除这些记录：

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

防御方应监控这些注册表项的更改，以及 PowerShell 事件的大量删除。

### ETW (Event Tracing for Windows) Patch

端点安全产品高度依赖 ETW。2024 年一种流行的规避方法是在内存中 patch `ntdll!EtwEventWrite`/`EtwEventWriteFull`，使每次 ETW 调用都返回 `STATUS_SUCCESS`，而不发出事件：<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

公开的 PoC（例如 `EtwTiSwallow`）会用 PowerShell 或 C++ 实现相同的原语。  
由于补丁是**进程本地的**，在其他进程中运行的 EDR 可能无法发现它。<sup>[[5]](#references)</sup>
检测：比较内存中的 `ntdll` 与磁盘上的版本，或在 user-mode 之前挂钩。

### 替代数据流 (ADS) 复兴

2023 年的恶意软件活动（例如 **FIN12** 加载器）中，曾发现攻击者将第二阶段二进制文件暂存于 ADS 中，以躲避传统扫描器：

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

使用 `dir /R`、`Get-Item -Stream *` 或 Sysinternals `streams64.exe` 枚举数据流。
将主机文件复制到 FAT/exFAT，或通过 SMB 复制，会剥离隐藏数据流，调查人员可借此恢复 payload。

### BYOVD 与 “AuKill”（2023）

在勒索软件入侵中，Bring-Your-Own-Vulnerable-Driver（自带易受攻击的驱动程序）如今已被常规用于**反取证**。  
开源工具 **AuKill** 会加载经过签名但存在漏洞的驱动程序（`procexp152.sys`），在加密和销毁日志**之前**暂停或终止 EDR 和取证传感器：<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

随后移除该驱动，仅留下极少的痕迹。<sup>[[1]](#references)</sup>  
缓解措施：启用 Microsoft vulnerable-driver blocklist（HVCI/SAC），
并对从用户可写路径创建内核服务发出警报。

---

## Linux 反取证：自我修补与云端 C2（2023–2025）

### 对遭入侵的服务进行自我修补以降低检测率（Linux）
攻击者越来越多地在利用服务漏洞后立即对其进行“自我修补”，以防止漏洞被再次利用，并抑制基于漏洞的检测。其做法是用最新的合法上游二进制文件/JAR 替换存在漏洞的组件，让扫描器报告主机已打上补丁，同时保留持久化和 C2。<sup>[[3]](#references)</sup>

示例：Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）。<sup>[[3]](#references)[[4]](#references)</sup>
- 利用漏洞后，攻击者从 Maven Central（repo1.maven.org）获取合法 JAR，删除 ActiveMQ 安装目录中存在漏洞的 JAR，然后重启 broker。
- 这修复了最初的 RCE，同时保留了其他 foothold（cron、SSH 配置更改、独立的 C2 implants）。

操作示例（仅作说明）
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
- 检查服务目录，查找非计划的二进制文件/JAR 替换：
  - Debian/Ubuntu：运行 `dpkg -V activemq`，并将文件哈希/路径与仓库镜像进行比较。
  - RHEL/CentOS：运行 `rpm -Va 'activemq*'`
  - 查找磁盘上存在但不归软件包管理器所有的 JAR 版本，或在非计划情况下更新的符号链接。
- 时间线：运行 `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`，将 ctime/mtime 与入侵时间窗口进行关联。
- Shell 历史记录/进程遥测：查找首次利用后立即通过 `curl`/`wget` 访问 `repo1.maven.org` 或其他制品 CDN 的证据。
- 变更管理：核实由谁应用了该“补丁”及其原因，而不只是确认存在已修补的版本。

### 使用 bearer token 和反分析 stager 的云服务 C2
观察到的攻击手法结合了多种长连接 C2 通道和反分析打包方式：<sup>[[3]](#references)</sup>
- 使用密码保护的 PyInstaller ELF 加载器来妨碍沙箱检测和静态分析（例如，加密的 PYZ、在 `/_MEI*` 下临时解压）。
  - 指标：`strings` 命中 `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` 等字符串。
  - 运行时痕迹：解压到 `/tmp/_MEI*` 或自定义的 `--runtime-tmpdir` 路径。
- 使用 Dropbox 作为后端的 C2，通过硬编码的 OAuth Bearer token 进行通信
  - 网络标记：向 `api.dropboxapi.com` / `content.dropboxapi.com` 发送带有 `Authorization: Bearer <token>` 的请求。
  - 在代理/NetFlow/Zeek/Suricata 日志中搜寻：服务器工作负载向 Dropbox 域发起的出站 HTTPS 连接，但这些工作负载通常不会同步文件。
- 通过隧道建立并行/备用 C2（例如 Cloudflare Tunnel `cloudflared`），在一个通道被阻断时仍能保持控制。
  - 主机 IOC：`cloudflared` 进程/单元、`~/.cloudflared/*.json` 中的配置，以及向 Cloudflare 边缘节点发起的出站 443 连接。

### 用于维持访问的持久化和“安全加固回滚”（Linux 示例）
攻击者经常将自我打补丁与持久访问路径结合使用：<sup>[[3]](#references)</sup>
- Cron/Anacron：修改每个 `/etc/cron.*/` 目录中的 `0anacron` stub，以定期执行。
  - 狩猎：
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH 配置加固回滚：启用 root 登录，并更改低权限账户的默认 shell。
  - 搜寻启用 root 登录的迹象：
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - 查找系统账户上可疑的交互式 shell（例如 `games`）：
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- 随机的短命名 beacon artifacts（8 个字母字符）被写入磁盘，并会联系 cloud C2：
  - 排查：
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

防御人员应将这些痕迹与外部暴露情况和服务修补事件关联起来，以发现用于掩盖初始利用行为的反取证式自我修复。

## References

- [1] [Sophos X-Ops – AuKill：用于禁用 EDR 的武器化易受攻击驱动程序（2023年3月）](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – 为隐蔽性修补 EtwEventWrite：检测与搜寻（2024年6月）](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – 为 persistence 进行修补：DripDropper Linux malware 如何在云端活动](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE（NVD）](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [隐藏 .NET - ETW（Adam Chester / XPN）](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – 揭露嵌入在合法软件中的 SectopRAT 变种](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
