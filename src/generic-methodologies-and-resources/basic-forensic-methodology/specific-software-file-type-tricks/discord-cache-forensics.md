# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、Discord Desktopのcache artifactsをtriageして、exfiltrated files、webhook endpoints、activity timelinesを復元する方法をまとめます。Discord DesktopはElectron/Chromium appであり、ディスク上ではChromium Simple Cacheを使用します。

## 確認場所（Windows/macOS/Linux）

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data内の主要なon-disk structures:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: 複数のcached objectsを含むことがあるBinary cache block files
- f_######: standalone filesとして保存された個々のcached entries（大きなbodyであることが多い）

注: Discordでmessages/channels/serversを削除しても、このlocal cacheはpurgeされません。Cached itemsは残っていることが多く、file timestampsはuser activityと一致するため、timeline reconstructionが可能です。<sup>[[1]](#references)</sup>

## 復元できるもの

- cdn.discordapp.com/media.discord.netから取得されたExfiltrated attachmentsとthumbnails
- Images、GIFs、videos（例: .jpg、.png、.gif、.webp、.mp4、.webm）
- Webhook URLs（https://discord.com/api/webhooks/…）<sup>[[3]](#references)</sup>
- Discord API calls（https://discord.com/api/vX/…）
- beaconing/exfil activityのcorrelationや、intel matching用のmedia hashingに有用<sup>[[1]](#references)</sup>

## Quick triage（manual）

- Cacheでhigh-signal artifactsをGrep:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- cached entriesをmodified time順にsortしてquick timelineを作成（mtimeはobjectがcacheに入った時刻を反映）:
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entriesのparsing（HTTP body + headers）

f_で始まるfilesには、HTTP response headersに続いてbodyが含まれています。header blockは通常、\r\n\r\nで終わります。有用なresponse headersには以下があります:
- Content-Type: media typeを推測するため
- Content-LocationまたはX-Original-URL: preview/correlation用のOriginal remote URL
- Content-Encoding: gzip/deflate/br（Brotli）の場合がある

Mediaは、headersとbodyを分割し、必要に応じてContent-Encodingに基づいてdecompressすることでextractできます。Content-Typeがない場合は、Magic-byte sniffingが有用です。

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Discordのcache folderを再帰的にscanし、webhook/API/attachment URLsを見つけ、f_* bodiesをparseし、必要に応じてmediaをcarveして、SHA‑256 hashes付きのHTML + CSV timeline reportsをoutputします。<sup>[[2]](#references)</sup>

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
Key options:
- --cache: Cache_Data へのパス
- --format html|csv|both
- --timeline: 順序付き CSV timeline を出力（modified time 順）
- --extra: sibling の Code Cache と GPUCache もスキャン
- --carve: regex ヒット付近の raw bytes から media（images/video）を carve
- Output: HTML report、CSV report、CSV timeline、carved/extracted files 用の media folder

## Analyst tips

- f_* および data_* files の modified time（mtime）を user/attacker activity windows と相関させ、timeline を再構成する。
- recovered media を hash（SHA-256）し、known-bad または exfil datasets と比較する。
- 抽出された webhook URLs は liveness のテストやローテーションが可能。blocklists への追加と、proxies に対する retro-hunting を検討する。
- server side で「wiping」した後も cache は残存する。acquisition が可能なら、Cache directory 全体と関連する sibling caches（Code Cache、GPUCache）を収集する。<sup>[[1]](#references)</sup>

## References

- [1] [C2 としての Discord と残された cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite（CLI/GUI）](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks - Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
