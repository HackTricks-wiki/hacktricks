# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

このページは、Discord Desktop の cache アーティファクトをトリアージして、exfiltrated files、webhook endpoints、activity timelines を復元する方法を要約します。Discord Desktop は Electron/Chromium ベースのアプリで、ディスク上に Chromium Simple Cache を使用します。

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 内の主なオンディスク構造:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

注記: Discord 上でメッセージ/チャンネル/サーバーを削除しても、このローカル cache は消去されません。キャッシュされた項目は残ることが多く、ファイルのタイムスタンプはユーザ活動と整合するため、タイムラインの再構築に使えます。

## What can be recovered

- cdn.discordapp.com/media.discordapp.net 経由で取得された exfiltrated attachments と thumbnails
- 画像、GIF、動画（例: .jpg, .png, .gif, .webp, .mp4, .webm）
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API calls (https://discord.com/api/vX/…)
- beaconing/exfil 活動の相関付けや、インテリジェンス照合のためのメディアのハッシュ取得に有用

## Quick triage (manual)

- 高信号なアーティファクトを検出するために cache を grep:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- キャッシュエントリを最終更新日時でソートして簡易タイムラインを作成 (mtime はオブジェクトがキャッシュに入った時刻を反映):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

f_ で始まるファイルは通常、HTTP レスポンスヘッダの後にボディが続きます。ヘッダブロックは通常 \r\n\r\n で終わります。役立つレスポンスヘッダには以下が含まれます:
- Content-Type: メディアタイプの推定に使用
- Content-Location or X-Original-URL: プレビューや相関のための元のリモート URL
- Content-Encoding: gzip/deflate/br (Brotli) の可能性

ヘッダとボディを分割し、Content-Encoding に基づいて必要なら復号することでメディアを抽出できます。Content-Type がない場合はマジックバイトによる判別が有用です。

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Recursively scans Discord’s cache folder, finds webhook/API/attachment URLs, parses f_* bodies, optionally carves media, and outputs HTML + CSV timeline reports with SHA‑256 hashes.

Example CLI usage:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
主なオプション:
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: 修正時間 (modified time) による並び順の CSV タイムラインを出力
- --extra: 隣接する Code Cache と GPUCache もスキャン
- --carve: regex ヒット付近の生バイト列からメディアをカーブ（抽出）する（images/video）
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## アナリスト向けヒント

- f_* および data_* ファイルの modified time (mtime) をユーザー/攻撃者の活動時間帯と照合してタイムラインを再構築する。
- 回収したメディアのハッシュ (SHA-256) を算出し、known-bad や exfil データセットと比較する。
- 抽出した webhook URLs は生存確認 (liveness) やローテーションのテストが可能。blocklists や retro-hunting プロキシへ追加することを検討する。
- サーバー側で「wiping」しても Cache は残存する。取得が可能なら、Cache ディレクトリ全体と関連する隣接キャッシュ (Code Cache, GPUCache) を収集する。

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
