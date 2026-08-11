# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 로컬에 cached된 media, webhook endpoint 및 activity correlation을 위한 Discord Desktop cache artifact의 triage 방법을 요약합니다. Discord의 desktop client는 Electron을 사용하며, Electron은 `sessionData` 아래에 disk cache와 같은 session data를 저장합니다.<sup>[[3]](#references)[[4]](#references)</sup>

## 확인할 위치 (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

이는 참조된 parser가 사용하는 기본 경로입니다. Electron에서는 application이 `sessionData`를 override할 수 있으므로, acquisition 중 실제 profile path를 확인해야 합니다.<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` layout은 Chromium의 blockfile disk-cache backend와 일치합니다. Chromium은 서로 다른 cache implementation을 문서화하고 있으므로, backend를 확인하지 않은 상태에서 이를 Simple Cache라고 labeling하지 마세요.<sup>[[5]](#references)</sup>

`Cache_Data` 내부의 주요 on-disk structure:
- `index`: entry를 찾는 데 사용되는 Blockfile cache index입니다.
- `data_#`: cache metadata, HTTP header 및 response data를 포함할 수 있는 fixed-size block file입니다.
- `f_######`: block-file limit보다 큰 data에 사용되는 별도 file입니다. 이러한 file에는 block-file header가 없는 stored data가 포함됩니다.

Message, channel 또는 server를 삭제해도 이미 로컬에 cached된 byte가 제거된다는 보장은 없습니다. 하지만 Chromium은 언제든지 cache file을 evict하거나 다시 생성할 수 있습니다. 남아 있는 artifact는 opportunistic evidence로 취급하고, file modification time은 다른 telemetry와 correlation해야 하는 대략적인 local-write signal로만 사용하세요.<sup>[[5]](#references)[[6]](#references)</sup>

## 복구할 수 있는 항목

무엇이 fetch되었고 아직 evict되지 않았는지에 따라, triage를 통해 cached attachment, media, URL 및 file hash를 복구할 수 있습니다. cache만으로는 해당 item이 exfiltrated되었다는 사실을 입증할 수 없습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL이 참조하는 attachment 및 thumbnail
- Image, GIF 및 video (예: `.jpg`, `.png`, `.gif`, `.webp`, `.mp4`, `.webm`)
- `https://discord.com/api/webhooks/...`와 같은 webhook URL.<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...`와 같은 Discord API call.<sup>[[2]](#references)</sup>
- 복구한 media를 known dataset 또는 intelligence feed와 비교하기 위한 SHA-256 hash.<sup>[[1]](#references)[[2]](#references)</sup>

## 빠른 triage (manual)

- cache에서 high-signal artifact를 Grep합니다. 이러한 pattern은 참조된 parser의 URL expression을 반영한 것이며, exhaustive indicator가 아닌 triage filter입니다.<sup>[[2]](#references)</sup>
- Webhook endpoint:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API call:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- cached entry를 modified time순으로 정렬하여 대략적인 sequence를 구성합니다. mtime은 filesystem signal이며, Discord object가 fetch되거나 sent된 시점을 단독으로 입증하지 않습니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## `f_*` entry parsing (HTTP body + headers)

blockfile layout에서 `f_######` file은 별도의 data stream이며, 완전한 HTTP response로 시작한다고 보장되지 않습니다. 획득한 file에 serialized HTTP header 다음에 `\r\n\r\n`이 포함되어 있다면, 첫 번째 delimiter에서 split하여 검사합니다.<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: media type을 추론하기 위해 사용
- Content-Location 또는 X-Original-URL: preview/correlation을 위한 원격 원본 URL
- Content-Encoding: gzip/deflate/br(Brotli)일 수 있음

그런 다음 header와 body를 split하고 `Content-Encoding`에 따라 선택적으로 decompress하여 media를 extract할 수 있습니다. 참조된 parser는 Brotli, gzip 및 deflate를 처리합니다. `Content-Type`이 없을 때 magic-byte sniffing이 유용하지만, 여전히 heuristic입니다.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord의 cache folder를 recursively scan하고, webhook/API/attachment URL을 찾으며, `f_*` body를 parse하고, 선택적으로 media를 carve합니다. 또한 HTML 및 CSV report와 선택적인 chronological timeline 및 SHA-256 hash를 output합니다.<sup>[[1]](#references)[[2]](#references)</sup>

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
The CLI는 다음 옵션과 output 이름을 정의합니다:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data directory 경로
- --format html|csv|both
- --timeline: 정렬된 CSV timeline 생성 (modified time 기준)
- --extra: 인접한 Code Cache 및 GPUCache도 함께 scan
- --carve: 인식된 media signature(images/video)를 사용하여 raw cache bytes에서 media carve
- Output: `<output>.html`, `<output>.csv`, 선택적 `<output>_timeline.csv`, 그리고 추출 또는 carve된 파일이 저장되는 `<output>_media` folder

## Analyst tips

- `f_*` 및 `data_*` 파일의 modified time(mtime)을 user 또는 attacker activity window 및 독립적인 telemetry와 상호 연관 분석하십시오. mtime은 확정적인 event timestamp가 아닙니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 복구된 media를 hash(SHA-256)하고 known-bad 또는 exfiltration dataset과 비교하십시오.<sup>[[1]](#references)[[2]](#references)</sup>
- 추출된 webhook URL을 credential로 취급하십시오. 단순히 liveness를 테스트하기 위해 이를 invoke하지 말고, 안전하게 보존하고 revocation 또는 rotation을 조율하며, 관련 network telemetry를 retro-hunting에 사용하십시오.<sup>[[7]](#references)</sup>
- Server-side deletion이 local cached bytes까지 삭제되었음을 보장하지는 않습니다. acquisition이 가능하다면 eviction 또는 cache recreation 전에 전체 `Cache` directory와 관련된 인접 cache(`Code Cache`, `GPUCache`)를 수집하십시오.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [수백만 사용자를 64-Bit Architecture로 원활하게 Upgrade한 Discord](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord를 C2로 사용했을 때 남겨진 cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
