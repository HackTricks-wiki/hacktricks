# Discord Cache Forensics (Chromium Disk Cache)

このページでは、ローカルに cached された media、webhook endpoints、activity correlation に関する Discord Desktop cache artifacts の triage 方法をまとめます。Discord の desktop client は Electron を使用しており、Electron は `sessionData` 配下に disk cache などの session data を保存します。<sup>[[3]](#references)[[4]](#references)</sup>

## Where to look (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

これらは参照 parser が使用する default paths です。Electron では application が `sessionData` を override できるため、acquisition 中に実際の profile path を確認してください。<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` の layout は Chromium の blockfile disk-cache backend と一致します。Chromium は異なる cache implementations を文書化しているため、backend を確認せずに Simple Cache と分類しないでください。<sup>[[5]](#references)</sup>

`Cache_Data` 内の主要な on-disk structures:
- `index`: entries の location 特定に使用される Blockfile cache index。
- `data_#`: cache metadata、HTTP headers、response data を含むことがある fixed-size block files。
- `f_######`: block-file limit より大きい data に使用される separate files。これらの files には block-file headers なしで stored data が含まれます。

messages、channels、servers を削除しても、すでに locally cached された bytes が削除されるとは限りません。ただし Chromium はいつでも cache files を evict または recreate する可能性があります。残存 artifacts は opportunistic evidence として扱い、file modification times は rough な local-write signals としてのみ使用してください。これらは他の telemetry と correlation する必要があります。<sup>[[5]](#references)[[6]](#references)</sup>

## What can be recovered

何が fetch され、まだ evict されていないかによって、triage では cached attachments、media、URLs、file hashes を recover できる場合があります。ただし cache だけでは、item が exfiltrated されたことは証明できません。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URLs が参照する attachments と thumbnails。
- Images、GIFs、videos（例: `.jpg`、`.png`、`.gif`、`.webp`、`.mp4`、`.webm`）。
- `https://discord.com/api/webhooks/...` などの Webhook URLs。<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` などの Discord API calls。<sup>[[2]](#references)</sup>
- recovered media の SHA-256 hashes。既知の datasets や intelligence feeds との comparison に使用できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Quick triage (manual)

- cache を grep して high-signal artifacts を探します。これらの patterns は参照 parser の URL expressions を反映したものであり、exhaustive indicators ではなく triage filters です。<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- cached entries を modified time で sort して rough な sequence を作成します。mtime は filesystem signal であり、それだけでは Discord object がいつ fetch または sent されたかを確定できません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

blockfile layout では、`f_######` files は separate data streams であり、完全な HTTP response から始まるとは限りません。acquired file に serialized HTTP headers が含まれ、その後に `\r\n\r\n` が続く場合は、最初の delimiter で split して確認します。<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: media type を推測するため
- Content-Location または X-Original-URL: preview/correlation 用の original remote URL
- Content-Encoding: gzip/deflate/br（Brotli）の場合があります。

その後、headers と body を split し、`Content-Encoding` に従って optional で decompress することで media を extract できます。参照 parser は Brotli、gzip、deflate を処理します。`Content-Type` がない場合は magic-byte sniffing が有用ですが、heuristic であることに変わりはありません。<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser)。<sup>[[1]](#references)</sup>
- Function: Discord の cache folder を recursively scan し、webhook/API/attachment URLs を見つけ、`f_*` bodies を parse し、optional で media を carve します。さらに HTML と CSV reports、および SHA-256 hashes 付きの optional chronological timeline を output します。<sup>[[1]](#references)[[2]](#references)</sup>

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
CLI は以下のオプションと出力名を定義します:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data ディレクトリへのパス
- --format html|csv|both
- --timeline: 順序付けされた CSV timeline（変更時刻順）を出力
- --extra: sibling の Code Cache と GPUCache もスキャン
- --carve: 認識された media signatures（画像/動画）を使用して raw cache bytes から media を carve
- Output: `<output>.html`、`<output>.csv`、任意の `<output>_timeline.csv`、および抽出または carve されたファイルを含む `<output>_media` フォルダー。

## Analyst tips

- `f_*` および `data_*` ファイルの変更時刻（mtime）を、ユーザーまたは攻撃者の活動時間帯や独立した telemetry と相関させます。mtime は決定的なイベントタイムスタンプではありません。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 復元した media を hash 化（SHA-256）し、既知の悪性データセットまたは exfiltration データセットと比較します。<sup>[[1]](#references)[[2]](#references)</sup>
- 抽出された webhook URL は credentials として扱います。liveness をテストするだけの目的で invoke しないでください。安全に保持し、revocation または rotation を調整し、関連する network telemetry を retro-hunting に使用します。<sup>[[7]](#references)</sup>
- Server-side deletion によって、local cached bytes が破棄されたとは限りません。acquisition が可能な場合は、eviction または cache recreation の前に `Cache` ディレクトリ全体と関連する sibling caches（`Code Cache`、`GPUCache`）を収集します。<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord が数百万人のユーザーを 64-bit Architecture にシームレスにアップグレードした方法](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord を C2 として使用した場合に残される cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
