# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、ローカルにキャッシュされたメディア、webhook endpoint、アクティビティの相関分析を目的として、Discord Desktop のキャッシュアーティファクトをトリアージする方法をまとめます。Discord のデスクトップクライアントは Electron を使用しており、Electron はディスクキャッシュなどのセッションデータを `sessionData` に保存します。<sup>[[3]](#references)[[4]](#references)</sup>

## 調査対象 (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

これらは、参照先の parser が使用するデフォルトパスです。Electron ではアプリケーションが `sessionData` を上書きできるため、取得時に実際のプロファイルパスを確認してください。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` という構造は、Chromium の blockfile ディスクキャッシュバックエンドと一致します。Chromium のドキュメントでは異なるキャッシュ実装が区別されているため、バックエンドを確認せずに Simple Cache と判定しないでください。<sup>[[5]](#references)</sup>

`Cache_Data` 内の主要なディスク上の構造:
- `index`: エントリの場所を特定するための Blockfile キャッシュインデックス。
- `data_#`: キャッシュメタデータ、HTTP ヘッダー、レスポンスデータを含むことがある固定サイズのブロックファイル。
- `f_######`: ブロックファイルの上限を超えるデータに使用される個別ファイル。ブロックファイルのヘッダーなしで保存データを含みます。

メッセージ、チャンネル、サーバーを削除しても、すでにローカルにキャッシュされたバイト列が消去されるとは限りません。ただし、Chromium はいつでもキャッシュファイルを破棄または再作成する可能性があります。残存アーティファクトは偶発的に残った証拠として扱い、ファイルの変更時刻は大まかなローカル書き込みの兆候にすぎないため、他のテレメトリと照合してください。<sup>[[5]](#references)[[6]](#references)</sup>

## 復元できる可能性のある情報

取得済みで、まだ破棄されていないデータによっては、キャッシュから添付ファイル、メディア、URL、ファイルハッシュを復元できる場合があります。キャッシュだけでは、アイテムが外部に持ち出されたことの証明にはなりません。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL から参照される添付ファイルやサムネイル。
- 画像、GIF、動画（例: `.jpg`、`.png`、`.gif`、`.webp`、`.mp4`、`.webm`）。
- `https://discord.com/api/webhooks/...` などの webhook URL。<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` などの Discord API 呼び出し。<sup>[[2]](#references)</sup>
- 復元したメディアの SHA-256 ハッシュ。既知のデータセットやインテリジェンスフィードとの照合に使用できます。<sup>[[1]](#references)[[2]](#references)</sup>

## 簡易トリアージ (手動)

- キャッシュを grep して、シグナルの強いアーティファクトを探します。以下のパターンは参照先の parser の URL 表現に基づくもので、トリアージ用のフィルターであり、網羅的な指標ではありません。<sup>[[2]](#references)</sup>
  - Webhook endpoint:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - 添付ファイル/CDN URL:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API 呼び出し:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- キャッシュエントリを変更時刻順に並べ、大まかな時系列を作成します。mtime はファイルシステム上のシグナルであり、それだけでは Discord のオブジェクトが取得または送信された時刻を特定できません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## `f_*` エントリの解析 (HTTP body + headers)

blockfile 形式では、`f_######` ファイルは個別のデータストリームであり、完全な HTTP response で始まるとは限りません。取得したファイルにシリアライズされた HTTP ヘッダーが含まれ、その後に `\r\n\r\n` が続く場合は、最初の区切りで分割して以下を調べます。<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: メディアタイプの推定
- Content-Location または X-Original-URL: 元のリモート URL。プレビューや相関分析に使用
- Content-Encoding: gzip/deflate/br (Brotli) の場合があります。

ヘッダーと body を分割し、必要に応じて `Content-Encoding` に従って展開すると、メディアを抽出できます。参照先の parser は Brotli、gzip、deflate に対応しています。`Content-Type` がない場合はマジックバイトによる判定が役立ちますが、あくまでヒューリスティックです。<sup>[[2]](#references)</sup>

## 自動 DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- 機能: Discord のキャッシュフォルダーを再帰的にスキャンし、webhook/API/添付ファイル URL を検出します。`f_*` の body を解析し、必要に応じてメディアをカービングして、HTML および CSV レポートと、SHA-256 ハッシュを含む任意の時系列を出力します。<sup>[[1]](#references)[[2]](#references)</sup>

CLI の使用例:

```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
  --cache "$env:APPDATA\discord\Cache\Cache_Data" `
  --outdir "C:\IR\discord-cache" `
  --output discord_cache_report `
  --format both `
  --timeline `
  --extra `
  --carve `
  --verbose
```

CLI では、次のオプションと出力名が定義されています:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data ディレクトリへのパス
- --format html|csv|both
- --timeline: 更新時刻順の CSV タイムラインを出力
- --extra: 隣接する Code Cache と GPUCache もスキャン
- --carve: 認識されたメディアシグネチャ（画像/動画）を使って、キャッシュの生バイト列からメディアをカービング
- 出力: `<output>.html`、`<output>.csv`、任意の`<output>_timeline.csv`、抽出またはカービングしたファイルを格納する`<output>_media`フォルダー。

## 分析担当者向けのヒント

- `f_*` ファイルと `data_*` ファイルの更新時刻（mtime）を、ユーザーまたは攻撃者の活動時間帯や独立したテレメトリと照合してください。mtime は確定的なイベントタイムスタンプではありません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 復元したメディアのハッシュ（SHA-256）を計算し、既知の悪性データセットや情報流出データセットと照合してください。<sup>[[1]](#references)[[2]](#references)</sup>
- 抽出した webhook URL は認証情報として扱ってください。生存確認のために呼び出さず、安全に保管し、失効またはローテーションを調整して、関連するネットワークテレメトリを遡及調査に利用してください。<sup>[[7]](#references)</sup>
- サーバー側で削除しても、ローカルにキャッシュされたバイト列が破棄されたとは限りません。取得が可能な場合は、削除やキャッシュの再作成が行われる前に、`Cache` ディレクトリ全体と隣接するキャッシュ（`Code Cache`、`GPUCache`）を収集してください。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite（CLI/GUI）](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord が数百万人のユーザーをシームレスに64ビットアーキテクチャへアップグレードした方法](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [ディスクキャッシュ](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [C2 としての Discord と、そこに残されたキャッシュ証拠](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhook – Webhook を実行](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
