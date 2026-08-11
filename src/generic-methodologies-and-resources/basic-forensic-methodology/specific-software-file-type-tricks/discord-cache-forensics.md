# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

このページでは、ローカルにキャッシュされたメディア、Webhook endpoint、アクティビティの相関分析を目的として、Discord Desktop のキャッシュアーティファクトをトリアージする方法をまとめます。Discord の desktop client は Electron を使用しており、Electron は `sessionData` の下に disk cache などのセッションデータを保存します。<sup>[[3]](#references)[[4]](#references)</sup>

## 確認場所 (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

これらは参照先の parser が使用する default path です。Electron では application が `sessionData` を override できるため、acquisition 中に実際の profile path を確認してください。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` という layout は Chromium の blockfile disk-cache backend に一致します。Chromium は異なる cache implementation を文書化しているため、backend を確認せずに Simple Cache と分類しないでください。<sup>[[5]](#references)</sup>

`Cache_Data` 内の主な on-disk structure:
- `index`: entry の location 特定に使用される Blockfile cache index。
- `data_#`: cache metadata、HTTP header、response data を格納できる fixed-size block file。
- `f_######`: block-file limit より大きい data に使用される separate file。これらの file には block-file header なしで stored data が含まれます。

message、channel、server を削除しても、すでにローカルに cache された byte が削除されるとは限りません。ただし、Chromium はいつでも cache file を evict または recreate する可能性があります。残存する artifact は opportunistic evidence として扱い、file modification time は他の telemetry と相関させる必要がある、大まかな local-write signal としてのみ使用してください。<sup>[[5]](#references)[[6]](#references)</sup>

## 復元できる可能性があるもの

fetch され、まだ evict されていない内容によっては、cached attachment、media、URL、file hash を triage で復元できる場合があります。ただし、cache だけでは item が exfiltrate されたことを証明できません。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL から参照される attachment と thumbnail。
- 画像、GIF、video (例: `.jpg`、`.png`、`.gif`、`.webp`、`.mp4`、`.webm`)。
- `https://discord.com/api/webhooks/...` のような Webhook URL。<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` のような Discord API call。<sup>[[2]](#references)</sup>
- 復元した media の SHA-256 hash。既知の dataset または intelligence feed との比較に使用できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Quick triage (manual)

- cache を grep して high-signal artifact を探します。これらの pattern は参照先 parser の URL expression を反映したものであり、triage filter であって exhaustive indicator ではありません。<sup>[[2]](#references)</sup>
- Webhook endpoint:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API call:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- cached entry を modified time 順に並べて、おおまかな sequence を作成します。mtime は filesystem signal であり、それだけで Discord object がいつ fetch または send されたかを確定するものではありません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry の parsing (HTTP body + headers)

blockfile layout では、`f_######` file は separate data stream であり、完全な HTTP response から始まるとは限りません。取得した file に serialized HTTP header が含まれ、その後に `\r\n\r\n` が続く場合は、最初の delimiter で split して確認します。<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: media type の推測に使用
- Content-Location または X-Original-URL: preview/correlation 用の original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) の場合があります。

その後、header と body を split し、`Content-Encoding` に従って必要に応じて decompress することで media を extract できます。参照先 parser は Brotli、gzip、deflate を処理します。`Content-Type` がない場合は magic byte sniffing が有用ですが、heuristic にとどまります。<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord の cache folder を recursively scan し、Webhook/API/attachment URL を検出し、`f_*` body を parse します。必要に応じて media を carve し、HTML と CSV report、および optional な chronological timeline と SHA-256 hash を出力します。<sup>[[1]](#references)[[2]](#references)</sup>

Example CLI usage:
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
CLI では以下のオプションと出力名が定義されています:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data directory へのパス
- --format html|csv|both
- --timeline: 順序付けされた CSV timeline（modified time 順）を出力
- --extra: sibling の Code Cache と GPUCache もスキャン
- --carve: 認識された media signature（image/video）を使用して raw cache bytes から media を carve
- 出力: `<output>.html`、`<output>.csv`、任意の `<output>_timeline.csv`、および抽出または carve されたファイルを含む `<output>_media` folder

## Analyst tips

- `f_*` および `data_*` files の modified time（mtime）を、user または attacker の activity window や独立した telemetry と相関させます。mtime は決定的な event timestamp ではありません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 復元した media の hash（SHA-256）を取得し、既知の悪性データセットまたは exfiltration dataset と比較します。<sup>[[1]](#references)[[2]](#references)</sup>
- 抽出された webhook URLs は credentials として扱います。liveness のテストだけを目的に invoke しないでください。安全に保全し、revocation または rotation を調整し、関連する network telemetry を retro-hunting に使用します。<sup>[[7]](#references)</sup>
- Server-side deletion によって local cached bytes が破棄されたとは限りません。acquisition が可能な場合は、eviction または cache recreation の前に `Cache` directory 全体と関連する sibling caches（`Code Cache`、`GPUCache`）を収集します。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord が数百万人のユーザーを 64-Bit Architecture にシームレスにアップグレードした方法](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [C2 としての Discord と残された cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
