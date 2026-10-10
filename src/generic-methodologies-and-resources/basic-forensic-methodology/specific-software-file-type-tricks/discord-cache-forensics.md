# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지에서는 Discord Desktop cache artifacts를 triage하여 로컬에 캐시된 미디어, webhook endpoints, activity correlation을 확인하는 방법을 요약합니다. Discord desktop client는 Electron을 사용하며, Electron은 `sessionData` 아래에 disk cache와 같은 session data를 저장합니다.<sup>[[3]](#references)[[4]](#references)</sup>

## 확인할 위치 (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

이 경로는 참조된 parser에서 사용하는 기본 경로입니다. Electron에서는 애플리케이션이 `sessionData`를 재정의할 수 있으므로, acquisition 중 실제 profile 경로를 확인하세요.<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` 구조는 Chromium의 blockfile disk-cache backend와 일치합니다. Chromium 문서에는 서로 다른 cache 구현이 구분되어 있으므로, backend를 확인하지 않은 채 Simple Cache라고 분류하지 마세요.<sup>[[5]](#references)</sup>

`Cache_Data` 내부의 주요 디스크 구조:
- `index`: 항목을 찾는 데 사용하는 Blockfile cache index.
- `data_#`: Cache metadata, HTTP headers, response data가 들어갈 수 있는 고정 크기 block 파일.
- `f_######`: Block 파일 제한보다 큰 데이터를 저장하는 별도 파일. 이 파일에는 block-file headers 없이 저장된 데이터가 들어 있습니다.

메시지, 채널 또는 서버를 삭제해도 이미 로컬에 캐시된 바이트가 제거된다고 보장할 수는 없습니다. 다만 Chromium은 언제든 cache 파일을 evict하거나 다시 만들 수 있습니다. 남아 있는 artifacts는 우연히 보존된 증거로 취급하고, 파일 modification time은 다른 telemetry와 대조해야 하는 대략적인 로컬 쓰기 신호로만 사용하세요.<sup>[[5]](#references)[[6]](#references)</sup>

## 복구할 수 있는 데이터

가져온 뒤 아직 evict되지 않은 데이터에 따라, triage 과정에서 캐시된 attachment, media, URL, file hash를 복구할 수 있습니다. Cache만으로는 항목이 exfiltrated되었다고 입증할 수 없습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL에서 참조하는 attachment 및 thumbnail.
- Images, GIFs, videos (예: `.jpg`, `.png`, `.gif`, `.webp`, `.mp4`, `.webm`).
- `https://discord.com/api/webhooks/...`와 같은 webhook URL.<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...`와 같은 Discord API calls.<sup>[[2]](#references)</sup>
- 복구한 media를 알려진 datasets 또는 intelligence feeds와 비교하기 위한 SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

## 빠른 triage (수동)

- Cache에서 신호가 뚜렷한 artifacts를 grep합니다. 이 패턴은 참조된 parser의 URL expressions를 따르며, 전체 지표가 아닌 triage용 필터입니다.<sup>[[2]](#references)</sup>
  - Webhook endpoints:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Attachment/CDN URLs:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API calls:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- 캐시된 항목을 modified time 기준으로 정렬해 대략적인 순서를 파악합니다. mtime은 파일시스템 신호일 뿐이며, Discord object가 언제 가져오거나 전송되었는지를 단독으로 입증하지 않습니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* 항목 파싱 (HTTP body + headers)

Blockfile 구조에서 `f_######` 파일은 별도의 data stream이며, 완전한 HTTP response로 시작한다고 보장할 수 없습니다. 획득한 파일에 직렬화된 HTTP headers 다음으로 `\r\n\r\n`가 포함되어 있다면, 첫 번째 delimiter에서 나누어 다음 항목을 확인합니다.<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Media type 추정
- Content-Location 또는 X-Original-URL: Preview/correlation을 위한 원격 URL
- Content-Encoding: gzip/deflate/br (Brotli)일 수 있음.

Headers와 body를 분리하고 `Content-Encoding`에 따라 선택적으로 압축을 해제하면 media를 추출할 수 있습니다. 참조된 parser는 Brotli, gzip, deflate를 처리합니다. `Content-Type`이 없는 경우 magic-byte sniffing을 사용할 수 있지만, 이는 어디까지나 휴리스틱입니다.<sup>[[2]](#references)</sup>

## 자동화된 DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- 기능: Discord의 cache 폴더를 재귀적으로 스캔하고, webhook/API/attachment URL을 찾으며, `f_*` body를 파싱하고, 선택적으로 media를 carve합니다. 또한 HTML 및 CSV reports와, SHA-256 hashes가 포함된 선택적 chronological timeline을 출력합니다.<sup>[[1]](#references)[[2]](#references)</sup>

CLI 사용 예:

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

CLI는 다음 옵션과 출력 이름을 정의합니다:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data 디렉터리 경로
- --format html|csv|both
- --timeline: 수정 시간순으로 정렬된 CSV 타임라인 출력
- --extra: 같은 디렉터리에 있는 Code Cache와 GPUCache도 스캔
- --carve: 인식된 미디어 시그니처(이미지/동영상)를 사용해 원시 cache 바이트에서 미디어 추출
- 출력: `<output>.html`, `<output>.csv`, 선택적으로 `<output>_timeline.csv`, 추출하거나 carve한 파일이 담긴 `<output>_media` 폴더.

## 분석가 팁

- `f_*` 및 `data_*` 파일의 수정 시간(mtime)을 사용자 또는 공격자 활동 시간대 및 독립적인 원격 측정 데이터와 대조하세요. mtime은 확정적인 이벤트 타임스탬프가 아닙니다.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- 복구한 미디어의 해시(SHA-256)를 계산하고 알려진 악성 데이터나 유출 데이터셋과 비교하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- 추출한 webhook URL을 자격 증명으로 취급하세요. 작동 여부를 확인하려고 직접 호출하지 말고 안전하게 보관하고, 폐기 또는 교체를 조율하며, 관련 네트워크 원격 측정 데이터를 사용해 과거 활동을 추적하세요.<sup>[[7]](#references)</sup>
- 서버 측에서 삭제해도 로컬에 캐시된 바이트가 반드시 제거되는 것은 아닙니다. 수집이 가능하다면 항목이 제거되거나 cache가 재생성되기 전에 전체 `Cache` 디렉터리와 관련된 같은 디렉터리의 캐시(`Code Cache`, `GPUCache`)를 수집하세요.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord 포렌식 도구 모음(CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord 포렌식 도구 모음 CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord가 수백만 명의 사용자를 64비트 아키텍처로 원활하게 업그레이드한 방법](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [디스크 Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [C2로서의 Discord와 남겨진 캐시 증거](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Webhook 실행](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
