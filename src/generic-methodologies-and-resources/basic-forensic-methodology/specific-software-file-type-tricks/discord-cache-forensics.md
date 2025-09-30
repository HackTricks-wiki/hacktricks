# Discord 캐시 포렌식 (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 Discord Desktop 캐시 아티팩트를 신속 분석하여 유출된 파일, webhook 엔드포인트, 활동 타임라인을 복구하는 방법을 요약합니다. Discord Desktop은 Electron/Chromium 앱이며 디스크에 Chromium Simple Cache를 사용합니다.

## Where to look (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data 내부의 주요 온디스크 구조:
- index: Simple Cache index database
- data_#: 여러 캐시된 객체를 포함할 수 있는 이진 캐시 블록 파일
- f_######: 개별 캐시 항목이 독립 파일로 저장된 것(종종 큰 본문)

참고: Discord에서 메시지/채널/서버를 삭제해도 이 로컬 캐시는 제거되지 않습니다. 캐시된 항목은 종종 남아 있으며 파일 타임스탬프는 사용자 활동과 일치하므로 타임라인 재구성이 가능합니다.

## What can be recovered

- cdn.discordapp.com/media.discordapp.net 통해 가져온 유출된 첨부파일 및 썸네일
- 이미지, GIF, 비디오 (예: .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL들 (https://discord.com/api/webhooks/…)
- Discord API 호출 (https://discord.com/api/vX/…)
- 비콘/유출 활동을 상호 연관시키거나 미디어 해시로 인텔 매칭할 때 유용

## Quick triage (manual)

- 캐시에서 고신호 아티팩트를 grep:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 수정 시간으로 캐시 항목을 정렬하여 빠른 타임라인을 구성 (mtime은 객체가 캐시에 들어온 시점을 반영):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing f_* entries (HTTP body + headers)

f_로 시작하는 파일들은 HTTP 응답 헤더 다음에 본문이 옵니다. 헤더 블록은 일반적으로 \r\n\r\n로 끝납니다. 유용한 응답 헤더:
- Content-Type: 미디어 타입 추론
- Content-Location or X-Original-URL: 미리보기/상관관계를 위한 원격 원본 URL
- Content-Encoding: gzip/deflate/br (Brotli) 일 수 있음

미디어는 헤더와 본문을 분리한 뒤 Content-Encoding에 따라 선택적으로 압축 해제하여 추출할 수 있습니다. Content-Type이 없을 때는 매직 바이트 스니핑이 유용합니다.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- 기능: Discord의 캐시 폴더를 재귀 스캔하여 webhook/API/attachment URL을 찾고, f_* 본문을 파싱하며, 선택적으로 미디어를 캐빙하고 SHA‑256 해시와 함께 HTML + CSV 타임라인 리포트를 출력합니다.

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
- --cache: Cache_Data의 경로
- --format html|csv|both
- --timeline: 정렬된 CSV 타임라인을 출력 (수정 시간 기준)
- --extra: 형제 캐시인 Code Cache 및 GPUCache도 스캔
- --carve: 정규식 매치 근처의 원시 바이트에서 미디어(이미지/비디오) 추출
- 출력: HTML 리포트, CSV 리포트, CSV 타임라인, 그리고 카빙/추출된 파일이 들어 있는 미디어 폴더

## 분석가 팁

- f_* 및 data_* 파일의 수정 시간(mtime)을 사용자/공격자의 활동 시간대와 대조하여 타임라인을 재구성하세요.
- 복구된 미디어는 SHA-256으로 해시하고 known-bad 또는 exfil 데이터셋과 비교하세요.
- 추출된 webhook URL은 활성 여부(liveness)를 테스트하거나 교체(rotate)할 수 있습니다; 차단 목록(blocklists)에 추가하고 retro-hunting 프록시에서 소급 탐색하는 것을 고려하세요.
- 서버 측에서 “wiping”을 수행한 이후에도 Cache는 남아 있습니다. 수집(acquisition)이 가능하면 전체 Cache 디렉토리와 관련된 형제 캐시(Code Cache, GPUCache)를 확보하세요.

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
