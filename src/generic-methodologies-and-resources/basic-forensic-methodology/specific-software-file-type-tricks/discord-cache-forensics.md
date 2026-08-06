# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지에서는 유출된 파일, webhook endpoint, 활동 타임라인을 복구하기 위해 Discord Desktop cache artifact를 triage하는 방법을 요약합니다. Discord Desktop은 Electron/Chromium app이며 디스크에서 Chromium Simple Cache를 사용합니다.

## 확인할 위치 (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 내부의 주요 디스크 구조:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: 여러 cached object를 포함할 수 있는 binary cache block file
- f_######: standalone file로 저장된 개별 cached entry (대개 더 큰 body)

참고: Discord에서 message/channel/server를 삭제해도 이 로컬 cache가 purge되지는 않습니다. Cached item은 종종 남아 있으며 해당 file timestamp는 user activity 시간과 일치하므로 타임라인 재구성이 가능합니다.<sup>[[1]](#references)</sup>

## 복구할 수 있는 항목

- cdn.discordapp.com/media.discordapp.net을 통해 가져온 유출된 attachment 및 thumbnail
- Image, GIF, video (예: .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API call (https://discord.com/api/vX/…)
- Beaconing/exfil activity를 연관 분석하고 intel matching을 위해 media를 hashing하는 데 유용<sup>[[1]](#references)</sup>

## 빠른 triage (manual)

- Cache에서 high-signal artifact를 Grep:
- Webhook endpoint:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API call:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 빠른 타임라인을 구성하기 위해 cached entry를 modified time순으로 정렬합니다 (mtime은 object가 cache에 들어온 시간을 반영):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry parsing (HTTP body + headers)

f_로 시작하는 file에는 HTTP response header 다음에 body가 포함됩니다. Header block은 일반적으로 \r\n\r\n으로 끝납니다. 유용한 response header:
- Content-Type: Media type 추정
- Content-Location 또는 X-Original-URL: Correlation/preview를 위한 원격 URL
- Content-Encoding: gzip/deflate/br (Brotli)일 수 있음

Header와 body를 분리하고 Content-Encoding에 따라 선택적으로 decompress하여 media를 추출할 수 있습니다. Content-Type이 없는 경우 magic-byte sniffing이 유용합니다.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Discord의 cache folder를 재귀적으로 scan하고, webhook/API/attachment URL을 찾으며, f_* body를 parsing하고, 선택적으로 media를 carve한 다음 SHA‑256 hash가 포함된 HTML + CSV timeline report를 출력합니다.<sup>[[2]](#references)</sup>

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
- --timeline: 정렬된 CSV timeline 출력 (modified time 기준)
- --extra: sibling Code Cache 및 GPUCache도 함께 스캔
- --carve: regex hits 주변의 raw bytes에서 media carve (images/video)
- Output: HTML report, CSV report, CSV timeline 및 carve/extract된 파일이 저장된 media 폴더

## Analyst tips

- f_* 및 data_* 파일의 modified time (mtime)을 user/attacker activity window와 상관 분석하여 timeline을 재구성합니다.
- 복구한 media를 hash (SHA-256)하고 known-bad 또는 exfil datasets와 비교합니다.
- 추출한 webhook URLs는 liveness를 테스트하거나 교체할 수 있습니다. 해당 URL을 blocklists에 추가하고 proxy를 대상으로 retro-hunting하는 것도 고려합니다.
- 서버 측에서 “wiping”한 후에도 Cache가 남아 있습니다. acquisition이 가능하다면 전체 Cache directory와 관련 sibling caches (Code Cache, GPUCache)를 수집합니다.<sup>[[1]](#references)</sup>

## References

- [1] [C2로서의 Discord와 남겨진 cached evidence](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
