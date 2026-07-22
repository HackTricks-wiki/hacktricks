# AdaptixC2 Configuration Extraction 및 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2는 Windows x86/x64 beacon(EXE/DLL/service EXE/raw shellcode) 및 BOF support를 제공하는 modular open-source post-exploitation/C2 framework입니다. 이 페이지에서는 다음 내용을 다룹니다.
- RC4-packed configuration이 embed되는 방식과 beacon에서 이를 extract하는 방법
- HTTP/SMB/TCP listener의 network/profile indicators
- 관련 Windows technique 페이지 링크와 함께 실제 환경에서 관찰된 일반적인 loader 및 persistence TTPs

최근 upstream release에는 DNS/DoH beacon listener와 별도의 Gopher agent/listener family도 포함되어 있으므로, 특정 sample이 여전히 classic beacon agent를 사용하더라도 최신 Adaptix infrastructure는 기존 HTTP/SMB/TCP surface보다 더 많은 항목을 노출할 수 있습니다.

## Beacon profiles 및 fields

AdaptixC2는 세 가지 주요 beacon type을 지원합니다.
- BEACON_HTTP: configurable server/port/SSL, method, URI, headers, user-agent 및 custom parameter name을 사용하는 web C2
- BEACON_SMB: named-pipe peer-to-peer C2(intranet)
- BEACON_TCP: protocol 시작 부분을 난독화하기 위해 prepended marker를 선택적으로 사용하는 direct socket

이러한 beacon layout은 초기 Adaptix 분석에서 공개적으로 문서화되었으며, 여전히 sample-side extraction을 시작할 때 가장 일반적으로 사용됩니다. 그러나 현재 upstream build에는 server side의 `BeaconDNS` 및 Gopher extender도 포함되어 있으므로, 모든 live Adaptix deployment가 HTTP/SMB/TCP infrastructure만 노출한다고 가정하지 마십시오.

HTTP beacon config에서 관찰되는 일반적인 profile field(decryption 후):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response size parsing에 사용
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

최근 BeaconHTTP build는 여러 URI, user-agent, Host header 및 server 간의 operator-selected rotation도 지원하며, sequential 또는 random selection을 사용할 수 있습니다. Hunting 관점에서 이는 하나의 infected host가 classic RC4-packed beacon family를 벗어나지 않고도 여러 callback path와 header combination으로 traffic을 fan out할 수 있음을 의미합니다.

Example default HTTP profile(beacon build에서):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["172.16.196.1"],
"ports": [4443],
"http_method": "POST",
"uri": "/uri.php",
"parameter": "X-Beacon-Id",
"user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 2,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
관찰된 악성 HTTP 프로필(실제 공격):
```json
{
"agent_type": 3192652105,
"use_ssl": true,
"servers_count": 1,
"servers": ["tech-system[.]online"],
"ports": [443],
"http_method": "POST",
"uri": "/endpoint/api",
"parameter": "X-App-Id",
"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
"http_headers": "\r\n",
"ans_pre_size": 26,
"ans_size": 47,
"kill_date": 0,
"working_time": 0,
"sleep_delay": 4,
"jitter_delay": 0,
"listener_type": 0,
"download_chunk_size": 102400
}
```
## 암호화된 configuration 패킹 및 로드 경로

operator가 builder에서 Create를 클릭하면 AdaptixC2는 암호화된 profile을 beacon의 tail blob으로 삽입합니다. 형식은 다음과 같습니다.
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader는 끝에서 16-byte key를 복사한 다음, N-byte block을 제자리에서 RC4-decrypt합니다:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
실무적 의미:
- 전체 구조는 종종 PE .rdata section 내부에 존재합니다.
- Extraction은 결정적입니다. size를 읽고, 해당 크기의 ciphertext를 읽은 다음, 바로 뒤에 배치된 16바이트 key를 읽고, RC4-decrypt하면 됩니다.

## Configuration extraction workflow (defenders)

beacon logic을 모방하는 extractor를 작성합니다:
1) PE 내부에서 blob을 찾습니다(일반적으로 .rdata). 실용적인 방법은 .rdata에서 그럴듯한 [size|ciphertext|16-byte key] layout을 scan하고 RC4를 시도하는 것입니다.
2) 첫 4바이트를 읽습니다 → size (uint32 LE).
3) 다음 N=size 바이트를 읽습니다 → ciphertext.
4) 마지막 16바이트를 읽습니다 → RC4 key.
5) ciphertext를 RC4-decrypt합니다. 그런 다음 plain profile을 다음과 같이 parse합니다:
- 위에 설명된 u32/boolean scalar
- length-prefixed strings (u32 length 다음에 bytes; trailing NUL이 있을 수 있음)
- arrays: servers_count 다음에 [string, u32 port] pair가 해당 개수만큼 이어짐

pre-extracted blob에서 작동하는 Minimal Python proof-of-concept (standalone, external deps 없음):
```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
S = list(range(256))
j = 0
for i in range(256):
j = (j + S[i] + key[i % len(key)]) & 0xFF
S[i], S[j] = S[j], S[i]
i = j = 0
out = bytearray()
for b in data:
i = (i + 1) & 0xFF
j = (j + S[i]) & 0xFF
S[i], S[j] = S[j], S[i]
K = S[(S[i] + S[j]) & 0xFF]
out.append(b ^ K)
return bytes(out)

class P:
def __init__(self, buf: bytes):
self.b = buf; self.o = 0
def u32(self) -> int:
v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
def u8(self) -> int:
v = self.b[self.o]; self.o += 1; return v
def s(self) -> str:
L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
p = P(plain)
cfg = {}
cfg['agent_type']    = p.u32()
cfg['use_ssl']       = bool(p.u8())
n                    = p.u32()
cfg['servers']       = []
cfg['ports']         = []
for _ in range(n):
cfg['servers'].append(p.s())
cfg['ports'].append(p.u32())
cfg['http_method']   = p.s()
cfg['uri']           = p.s()
cfg['parameter']     = p.s()
cfg['user_agent']    = p.s()
cfg['http_headers']  = p.s()
cfg['ans_pre_size']  = p.u32()
cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
cfg['kill_date']     = p.u32()
cfg['working_time']  = p.u32()
cfg['sleep_delay']   = p.u32()
cfg['jitter_delay']  = p.u32()
cfg['listener_type'] = 0
cfg['download_chunk_size'] = 0x19000
return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```
팁:
- 자동화할 때는 PE parser를 사용해 .rdata를 읽은 다음 sliding window를 적용합니다. 각 offset o에 대해 size = u32(.rdata[o:o+4])를 시도하고, ct = .rdata[o+4:o+4+size], candidate key = 다음 16바이트로 설정합니다. 그런 다음 RC4-decrypt를 수행하고, string fields가 UTF-8로 디코딩되며 길이가 정상인지 확인합니다.
- 동일한 length-prefixed conventions를 따라 SMB/TCP profiles를 parse합니다.

## Custom listener profiles: classic HTTP schema만 하드코딩하지 않기

outer packing format (`u32 size | RC4 ciphertext | 16-byte key`)은 재사용할 수 있으므로, actor-customized listeners도 동일한 extraction workflow를 유지하면서 decrypted field layout을 완전히 변경할 수 있습니다.

최근의 좋은 예로 2026년 4월 Tropic Trooper campaign이 있습니다. 이 campaign에서 extracted Adaptix beacon에는 standard HTTP/TCP profile이 포함되지 않았습니다. 대신 decrypted blob에는 다음과 같은 GitHub transport parameters가 저장되어 있었습니다:
- `repo_owner`
- `repo_name`
- `api_host` (예: `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

실용적인 parser strategy:
- 먼저 평소처럼 outer RC4 blob을 정확히 탐지합니다.
- decryption 후 즉시 HTTP parser를 강제하지 말고, sentinel strings와 field sanity를 기준으로 분기합니다.
- 유용한 sentinels에는 `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings, 또는 명백히 유효한 server/port arrays가 있습니다.
- HTTP parser가 실패했지만 plaintext에 일관된 length-prefixed UTF-8 strings가 포함되어 있다면, false positive로 버리지 말고 sample을 유지한 뒤 alternative schemas를 시도합니다.

해당 campaign에서 custom listener는 GitHub issues를 C2 transport로 사용했으며, beacon은 GitHub API가 operator에게 victim source address를 직접 노출하지 않기 때문에 외부 IP를 확인하기 위해 `ipinfo.io`를 query했습니다.

## Network fingerprinting and hunting

HTTP
- 일반적 특징: operator가 선택한 URI로 POST (예: /uri.php, /endpoint/api)
- beacon ID에 사용되는 custom header parameter (예: X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 또는 당시의 Chrome builds를 모방한 User-agents
- sleep_delay/jitter_delay를 통해 확인되는 polling cadence
- 최신 builds는 callback마다 URIs, user-agents, Host headers, servers를 rotate할 수 있으므로, 단일 path/UA pair를 가정하지 말고 uncommon header names, response-size patterns, TLS reuse, timing을 기준으로 cluster해야 합니다.

SMB/TCP
- web egress가 제한된 intranet C2를 위한 SMB named-pipe listeners
- TCP beacons는 protocol start를 난독화하기 위해 traffic 앞에 몇 바이트를 추가할 수 있음

Current upstream teamserver defaults
- `profile.yaml`에는 현재 teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` 및 `server.rsa.key`, 그리고 HTTP, SMB, TCP, DNS, Beacon agent, Gopher용 extenders가 포함되어 있습니다.
- 일치하지 않는 routes에서 default error handler는 `Server: AdaptixC2` 및 `Adaptix-Version: v1.2`를 반환합니다.
- 기본 404 body에는 `AdaptixC2 404` 및 `You need to enter the correct connection details.`가 포함됩니다.
- 2026년 Internet-wide scans에서 `4321`에 노출된 teamservers와 `43211`에 노출된 beacon listeners가 다수 발견되었습니다. 따라서 두 port는 유용한 seed pivots이지만 exhaustive한 것으로 간주해서는 안 됩니다.

DNS/DoH listener fingerprints
- 현재 BeaconDNS extender는 authoritative하게 응답합니다 (`AA=true`).
- beacon protocol shape과 일치하지 않는 queries, 특히 configured domain 앞에 5개 미만의 labels가 있는 names에는 일반적으로 `TXT "OK"`로 응답합니다.
- configured base TTL을 0으로 두면 listener는 10초 base를 사용하고 최대 59초의 jitter를 추가합니다.
- 따라서 HTTP listener가 노출되지 않은 경우 short-label active probes가 유용합니다.

## Loader and persistence TTPs seen in incidents

In-memory PowerShell loaders
- Base64/XOR payloads를 download (Invoke‑RestMethod / WebClient)
- unmanaged memory를 allocate하고 shellcode를 copy한 뒤, VirtualProtect를 통해 protection을 0x40 (PAGE_EXECUTE_READWRITE)으로 전환
- .NET dynamic invocation으로 실행: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- 2026년 Tropic Trooper chain은 malicious code를 patching the PE entry point 대신 `_security_init_cookie`로 redirect하는 trojanized SumatraPDF executable (TOSHIS loader)을 사용했습니다.
- loader는 Adler-32 hashing으로 APIs를 resolve하고, decoy PDF를 download했으며, second-stage shellcode를 가져온 뒤 WinCrypt의 `CryptDeriveKey`를 통해 hardcoded seed에서 생성한 키로 AES-128-CBC decrypt를 수행하고, Adaptix beacon을 memory에서 reflectively execute했습니다.
- 이후 persistence는 `\MSDNSvc` 또는 `\MicrosoftUDN`과 같은 benign-looking names를 사용하는 scheduled tasks로 이동했으며, 약 2시간마다 agent를 다시 launch하도록 configured되었습니다.

in-memory execution 및 AMSI/ETW 고려 사항은 다음 페이지를 확인하세요:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

관찰된 persistence mechanisms
- logon 시 loader를 다시 launch하는 Startup folder shortcut (.lnk)
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run). `loader.ps1`를 시작하기 위해 "Updater"와 같이 benign-sounding names를 사용하는 경우가 많음
- 취약한 processes를 대상으로 `%APPDATA%\Microsoft\Windows\Templates` 아래에 msimg32.dll을 drop하는 DLL search-order hijack

Technique deep-dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell이 RW→RX transitions를 생성하는지 확인: powershell.exe 내부에서 VirtualProtect를 사용해 PAGE_EXECUTE_READWRITE로 전환
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, 또는 `You need to enter the correct connection details.`가 포함된 unmatched HTTPS 404s
- suspect domains 아래의 short queries에 대해 `AA=true` 및 `TXT "OK"`를 반환하는 DNS responses
- `/repos/<owner>/<repo>/issues`로 향하는 GitHub API traffic 이후 동일한 loader/beacon chain에서 발생하는 `ipinfo.io` lookups
- user 또는 common Startup folders 아래의 Startup .lnk
- 의심스러운 Run keys (예: "Updater") 및 update.ps1/loader.ps1와 같은 loader names
- decoy document를 표시하기 전에 `_security_init_cookie`를 downloader code로 redirect하는 trojanized PE samples
- `%APPDATA%\Microsoft\Windows\Templates` 아래 user-writable DLL paths에 존재하는 msimg32.dll

## Notes on OpSec fields

- KillDate: agent가 self-expires하는 시점 이후의 timestamp
- WorkingTime: business activity에 맞추기 위해 agent가 active 상태여야 하는 hours

이 fields는 clustering에 사용하고 관찰된 quiet periods를 설명하는 데 활용할 수 있습니다.

## YARA and static leads

Unit 42는 beacons (C/C++ 및 Go)와 loader API-hashing constants를 위한 basic YARA를 publish했습니다. 이를 PE .rdata 끝부분 근처의 [size|ciphertext|16-byte-key] layout, default HTTP profile strings, 그리고 `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, `ipinfo.io`와 같은 최신 server/listener markers를 탐지하는 rules로 보완하는 것을 고려하세요.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
