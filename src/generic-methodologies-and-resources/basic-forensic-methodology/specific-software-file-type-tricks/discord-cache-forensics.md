# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、流出したファイル、webhook endpoints、アクティビティのタイムラインを復元するために、Discord Desktop の cache artifacts を triage する方法をまとめます。Discord Desktop は Electron/Chromium アプリであり、ディスク上で Chromium Simple Cache を使用します。

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 内の主な on-disk structures:<sup>[[1]](#references)</sup>
- index: Simple Cache の index database
- data_#: 複数の cached objects を含むことがある binary cache block files
- f_######: standalone files として保存された個別の cached entries（大きな bodies であることが多い）

注: Discord で messages/channels/servers を削除しても、この local cache は purge されません。Cached items は残ることが多く、file timestamps は user activity と一致するため、timeline reconstruction が可能になります。<sup>[[1]](#references)</sup>

## What can be recovered

- cdn.discordapp.com/media.discordapp.net 経由で取得された exfiltrated attachments と thumbnails
- Images、GIFs、videos（例: .jpg、.png、.gif、.webp、.mp4、.webm）
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- beaconing/exfil activity の correlation や、intel matching のための media hashing に有用<sup>[[1]](#references)</sup>

## Quick triage (manual)

- cache から high-signal artifacts を Grep:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- cached entries を modified time で sort して、quick timeline を作成（mtime は object が cache に入った時刻を反映）:
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

f_ で始まる files には、HTTP response headers と body が続けて含まれます。header block は通常 \r\n\r\n で終了します。有用な response headers:
- Content-Type: media type の推測
- Content-Location or X-Original-URL: correlation 用の original remote URL
- Content-Encoding: gzip/deflate/br（Brotli）の場合がある

headers と body を分離し、Content-Encoding に基づいて必要に応じて decompress することで、media を extract できます。Content-Type がない場合は、magic-byte sniffing が有用です。

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: Discord の cache folder を recursively scan し、webhook/API/attachment URLs を見つけ、f_* bodies を parse し、必要に応じて media を carve して、SHA‑256 hashes 付きの HTML + CSV timeline reports を出力します。<sup>[[2]](#references)</sup>

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
- --cache: Cache_Data へのパス
- --format html|csv|both
- --timeline: 更新時刻順の CSV timeline を出力
- --extra: sibling の Code Cache と GPUCache もスキャン
- --carve: regex ヒット付近の raw bytes からメディア（画像/動画）を carve
- Output: HTML report、CSV report、CSV timeline、carve/extract されたファイルを格納する media folder

## 分析担当者向けのヒント

- f_* および data_* ファイルの modified time（mtime）をユーザー/attacker の活動時間帯と相関させ、timeline を再構築する。
- 復元したメディアを hash（SHA-256）し、既知の悪性データセットまたは exfil データセットと比較する。
- 抽出された webhook URLs は liveness のテストやローテーションが可能。blocklists への追加と proxy の retro-hunting も検討する。
- サーバー側で「wiping」した後も Cache は保持される。acquisition が可能なら、Cache directory 全体と関連する sibling caches（Code Cache、GPUCache）を収集する。<sup>[[1]](#references)</sup>

## 参考文献

- [1] [Discord を C2 として使用した際に残される cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
