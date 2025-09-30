# AdaptixC2 구성 추출 및 TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2는 Windows x86/x64 beacons(EXE/DLL/service EXE/raw shellcode) 및 BOF를 지원하는 모듈식의 오픈소스 post‑exploitation/C2 프레임워크입니다. 이 페이지는 다음을 문서화합니다:
- RC4‑packed configuration이 어떻게 포함되어 있는지와 beacon에서 이를 추출하는 방법
- HTTP/SMB/TCP 리스너에 대한 네트워크/프로필 지표
- 실제 사례에서 관찰된 일반적인 loader 및 persistence TTPs와 관련 Windows technique 페이지로의 링크

## Beacon 프로필 및 필드

AdaptixC2는 세 가지 주요 beacon 타입을 지원합니다:
- BEACON_HTTP: 서버/포트/SSL, method, URI, headers, user‑agent 및 custom parameter name을 설정할 수 있는 web C2
- BEACON_SMB: named‑pipe 기반의 peer‑to‑peer C2 (intranet)
- BEACON_TCP: 직접 소켓 방식, 선택적으로 프로토콜 시작을 난독화하기 위한 선행 마커(prepended marker) 포함 가능

HTTP beacon 구성(복호화 후)에서 관찰되는 일반적인 프로필 필드:
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – 응답 크기 파싱에 사용
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

예시 기본 HTTP 프로필 (beacon 빌드에서):
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
## 암호화된 구성 패킹 및 로드 경로

운영자가 builder에서 Create를 클릭하면, AdaptixC2는 암호화된 프로파일을 beacon의 tail blob으로 임베드합니다. 형식은 다음과 같습니다:
- 4 바이트: 구성 크기 (uint32, little‑endian)
- N 바이트: RC4‑암호화된 구성 데이터
- 16 바이트: RC4 키

beacon loader는 끝에서 16‑byte 키를 복사하고 N‑byte 블록을 제자리에서 RC4로 복호화합니다:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
실무적 시사점:
- 전체 구조는 종종 PE .rdata 섹션 내부에 위치합니다.
- 추출은 결정적입니다: size를 읽고, 해당 크기의 ciphertext를 읽고, 바로 다음에 위치한 16‑byte 키를 읽은 다음, RC4‑decrypt합니다.

## 구성 추출 워크플로우 (방어자)

beacon logic을 모방하는 extractor를 작성하세요:
1) PE 내부에서 blob을 찾습니다 (일반적으로 .rdata). 실용적인 방법은 .rdata를 스캔하여 합리적인 [size|ciphertext|16‑byte key] 레이아웃을 찾고 RC4를 시도하는 것입니다.
2) 처음 4바이트를 읽습니다 → size (uint32 LE).
3) 다음 N=size 바이트를 읽습니다 → ciphertext.
4) 마지막 16바이트를 읽습니다 → RC4 key.
5) ciphertext를 RC4‑decrypt한 뒤, 평문 프로파일을 다음과 같이 파싱합니다:
- 위에 언급한 것처럼 u32/boolean scalars
- 길이 접두형 문자열 (u32 length 다음에 바이트; 끝의 NUL이 있을 수 있음)
- 배열: servers_count 다음에 그 수만큼의 [string, u32 port] 쌍이 옵니다

사전 추출된 blob에서 동작하는 최소한의 Python proof‑of‑concept(standalone, 외부 종속 없음):
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
- 자동화할 때, PE parser를 사용해 .rdata를 읽고 슬라이딩 윈도우를 적용하세요: 각 오프셋 o에 대해 size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt하고 문자열 필드가 UTF‑8로 디코딩되는지와 길이가 타당한지 확인합니다.
- 동일한 length‑prefixed 규약을 따라 SMB/TCP 프로파일을 파싱하세요.

## 네트워크 지문화 및 헌팅

HTTP
- 일반적: 운영자 선택 URIs로 POST(예: /uri.php, /endpoint/api)
- beacon ID에 사용되는 커스텀 헤더 파라미터(예: X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 또는 당시의 Chrome 빌드를 흉내내는 User‑agents
- sleep_delay/jitter_delay를 통해 보이는 폴링 주기

SMB/TCP
- 웹 egress가 제한된 인트라넷 C2를 위한 SMB named‑pipe 리스너
- TCP beacons는 프로토콜 시작을 은폐하기 위해 트래픽 앞에 몇 바이트를 붙일 수 있음

## 인시던트에서 관찰된 Loader 및 persistence TTPs

메모리 내 PowerShell 로더
- Base64/XOR 페이로드 다운로드 (Invoke‑RestMethod / WebClient)
- unmanaged memory 할당, shellcode 복사, VirtualProtect로 보호를 0x40 (PAGE_EXECUTE_READWRITE)으로 변경
- .NET 동적 호출로 실행: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

메모리 내 실행 및 AMSI/ETW 관련 고려사항은 다음 페이지를 확인하세요:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

관찰된 지속성 메커니즘
- 로그온 시 로더를 재실행하기 위한 Startup 폴더의 바로가기(.lnk)
- Registry Run 키(HKCU/HKLM ...\CurrentVersion\Run), 종종 "Updater"처럼 무해하게 들리는 이름으로 loader.ps1을 시작
- 취약한 프로세스를 대상으로 %APPDATA%\Microsoft\Windows\Templates 아래에 msimg32.dll을 둬서 발생하는 DLL search‑order hijack

기술 심층 분석 및 점검:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

헌팅 아이디어
- PowerShell에서 발생하는 RW→RX 전환: powershell.exe 내부에서 VirtualProtect를 통해 PAGE_EXECUTE_READWRITE
- 동적 호출 패턴 (GetDelegateForFunctionPointer)
- 사용자 또는 공용 Startup 폴더의 Startup .lnk
- 의심스러운 Run 키(예: "Updater") 및 update.ps1/loader.ps1 같은 로더 이름
- msimg32.dll을 포함하는 %APPDATA%\Microsoft\Windows\Templates 아래의 사용자 쓰기 가능한 DLL 경로

## OpSec 필드에 대한 노트

- KillDate: 에이전트가 스스로 만료되는 시점 이후의 타임스탬프
- WorkingTime: 에이전트가 비즈니스 활동에 섞이도록 활성화되어야 하는 시간대

이 필드들은 클러스터링에 사용하거나 관찰된 조용한 기간을 설명하는 데 활용할 수 있습니다.

## YARA 및 정적 단서

Unit 42는 beacons(C/C++ 및 Go)용 기본 YARA와 loader API‑hashing 상수를 공개했습니다. PE .rdata 끝 근처에서 [size|ciphertext|16‑byte‑key] 레이아웃과 기본 HTTP 프로파일 문자열을 찾는 룰로 보완하는 것을 고려하세요.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
