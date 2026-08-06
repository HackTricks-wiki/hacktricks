# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 유출된 파일, webhook endpoint 및 활동 타임라인을 복구하기 위해 Discord Desktop cache artifact를 triage하는 방법을 요약합니다. Discord Desktop은 Electron/Chromium 앱이며 디스크에서 Chromium Simple Cache를 사용합니다.

## 확인할 위치 (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 내부의 주요 디스크 구조:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: 여러 cached object를 포함할 수 있는 binary cache block 파일
- f_######: standalone 파일로 저장된 개별 cached entry (대개 더 큰 body)

참고: Discord에서 message/channel/server를 삭제해도 이 local cache는 제거되지 않습니다. Cached item은 자주 남아 있으며 파일 timestamp가 사용자 활동 시점과 일치하므로 타임라인 재구성이 가능합니다.<sup>[[1]](#references)</sup>

## 복구할 수 있는 항목

- cdn.discordapp.com/media.discordapp.net을 통해 가져온 유출된 attachment 및 thumbnail
- Image, GIF, video (예: .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API call (https://discord.com/api/vX/…)
- Beaconing/exfil activity를 연관 분석하고 intel matching을 위해 media를 hashing하는 데 유용함<sup>[[1]](#references)</sup>

## 빠른 triage (수동)

- Cache에서 high-signal artifact를 grep합니다:
- Webhook endpoint:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API call:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 수정 시간을 기준으로 cached entry를 정렬하여 빠른 타임라인을 구축합니다 (mtime은 object가 cache에 들어온 시점을 반영):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry 파싱 (HTTP body + headers)

f_로 시작하는 파일에는 HTTP response header 다음에 body가 포함됩니다. Header block은 일반적으로 \r\n\r\n에서 끝납니다. 유용한 response header는 다음과 같습니다:
- Content-Type: media type을 추정
- Content-Location 또는 X-Original-URL: correlation 및 preview를 위한 원격 URL
- Content-Encoding: gzip/deflate/br(Brotli)일 수 있음

Header와 body를 분리하고 Content-Encoding에 따라 필요하면 decompress하여 media를 추출할 수 있습니다. Content-Type이 없는 경우 magic-byte sniffing이 유용합니다.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- 기능: Discord의 cache folder를 재귀적으로 scan하고, webhook/API/attachment URL을 찾으며, f_* body를 파싱하고, 선택적으로 media를 carve한 다음 SHA-256 hash가 포함된 HTML + CSV timeline report를 출력합니다.<sup>[[2]](#references)</sup>

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
주요 옵션:
- --cache: Cache_Data 경로
- --format html|csv|both
- --timeline: 정렬된 CSV timeline 생성 (modified time 기준)
- --extra: sibling Code Cache 및 GPUCache도 스캔
- --carve: regex hits 근처의 raw bytes에서 미디어 carve (images/video)
- Output: HTML report, CSV report, CSV timeline 및 carve/extract된 파일이 저장되는 media folder

## Analyst tips

- f_* 및 data_* 파일의 modified time (mtime)을 사용자/공격자 activity window와 연관시켜 timeline을 재구성합니다.
- 복구된 미디어에 hash (SHA-256)를 적용하고 known-bad 또는 exfil datasets와 비교합니다.
- 추출된 webhook URLs의 liveness를 테스트하거나 rotate할 수 있습니다. 해당 URL을 blocklists에 추가하고 proxy에서 retro-hunting하는 것도 고려합니다.
- Server side에서 “wiping”한 후에도 Cache는 유지됩니다. acquisition이 가능하다면 전체 Cache directory와 관련 sibling caches (Code Cache, GPUCache)를 수집합니다.<sup>[[1]](#references)</sup>

## References

- [1] [C2로서의 Discord와 남겨진 cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
