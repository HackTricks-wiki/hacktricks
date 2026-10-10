# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2는 Windows x86/x64 beacon(EXE/DLL/service EXE/raw shellcode)과 BOF를 지원하는 모듈식 오픈 소스 post-exploitation/C2 framework입니다.<sup>[[1]](#references)</sup> 이 페이지에서는 다음을 설명합니다.
- RC4로 패킹된 configuration이 어떻게 삽입되는지, beacon에서 이를 추출하는 방법
- HTTP/SMB/TCP listener의 네트워크/profile 지표
- 실제 환경에서 관찰된 일반적인 loader 및 persistence TTP와 관련 Windows 기법 페이지 링크

최신 upstream 릴리스에는 DNS/DoH beacon listener와 별도의 Gopher agent/listener 제품군도 포함되어 있습니다. 따라서 특정 sample이 여전히 기존 beacon agent를 사용하더라도, 최신 Adaptix 인프라가 기존 HTTP/SMB/TCP 이외의 표면을 노출할 수 있습니다.<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2는 세 가지 기본 beacon 유형을 지원합니다.<sup>[[1]](#references)</sup>
- BEACON_HTTP: 서버/포트/SSL, method, URI, headers, user-agent, 사용자 지정 parameter name을 설정할 수 있는 웹 C2
- BEACON_SMB: named-pipe peer-to-peer C2(인트라넷)
- BEACON_TCP: 직접 소켓 연결. 프로토콜 시작 부분을 난독화하기 위해 앞에 marker를 추가할 수 있음

이는 초기 Adaptix 분석 자료에 공개된 beacon 레이아웃이며, sample 측 추출을 시작할 때 여전히 가장 흔히 사용되는 기준입니다.<sup>[[1]](#references)</sup> 하지만 현재 upstream 빌드에는 서버 측에 `BeaconDNS` 및 Gopher extender도 포함되어 있으므로, 모든 실제 Adaptix 배포가 HTTP/SMB/TCP 인프라만 노출한다고 가정하지 마세요.<sup>[[2]](#references)</sup>

HTTP beacon config에서 관찰되는 일반적인 profile 필드(복호화 후):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (문자열 배열), ports (u32 배열)
- http_method, uri, parameter, user_agent, http_headers (길이 접두사가 있는 문자열)
- ans_pre_size (u32), ans_size (u32) – 응답 크기를 파싱하는 데 사용
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

최근 BeaconHTTP 빌드에서는 operator가 여러 URI, user-agent, Host header, 서버 간 순환 방식을 순차 또는 무작위로 선택할 수 있습니다.<sup>[[2]](#references)</sup> 따라서 위협 헌팅 관점에서는 기존 RC4 패킹 beacon 제품군을 사용하더라도 감염된 단일 호스트가 여러 callback 경로와 header 조합을 이용할 수 있습니다.

기본 HTTP profile 예시(beacon 빌드 기준):<sup>[[1]](#references)</sup>

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

관찰된 악성 HTTP 프로파일(실제 공격):<sup>[[1]](#references)</sup>

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

operator가 builder에서 Create를 클릭하면 AdaptixC2는 암호화된 profile을 beacon의 tail blob으로 삽입합니다. 형식은 다음과 같습니다:<sup>[[1]](#references)</sup>
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

beacon loader는 끝부분에서 16‑byte key를 복사한 다음, N‑byte 블록을 제자리에서 RC4로 복호화합니다:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

실질적인 영향:<sup>[[1]](#references)</sup>
- 전체 구조는 PE의 .rdata 섹션에 있는 경우가 많습니다.
- 추출은 결정적입니다. 크기를 읽고, 해당 크기의 ciphertext를 읽은 다음, 바로 뒤에 배치된 16-byte key를 읽고 RC4로 복호화합니다.

## Configuration 추출 워크플로(방어자)

beacon 로직을 모방하는 extractor를 작성합니다:<sup>[[1]](#references)</sup>
1) PE 내부에서 blob을 찾습니다(일반적으로 .rdata). 실용적인 방법은 .rdata에서 그럴듯한 [size|ciphertext|16-byte key] 레이아웃을 검색하고 RC4를 시도하는 것입니다.
2) 처음 4 bytes를 읽습니다 → size(uint32 LE).
3) 다음 N=size bytes를 읽습니다 → ciphertext.
4) 마지막 16 bytes를 읽습니다 → RC4 key.
5) ciphertext를 RC4로 복호화합니다. 그런 다음 평문 profile을 다음과 같이 파싱합니다:
   - 위에서 설명한 u32/boolean 스칼라
   - 길이 접두사가 있는 문자열(u32 길이 뒤에 bytes가 오며, 끝에 NUL이 있을 수 있음)
   - 배열: servers_count 뒤에 해당 개수만큼 [string, u32 port] 쌍

추출한 blob에서 작동하는 최소 Python proof-of-concept(독립 실행형, 외부 의존성 없음):

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
- 자동화할 때는 PE parser를 사용해 .rdata를 읽은 다음 sliding window를 적용하세요. 각 오프셋 o에서 size = u32(.rdata[o:o+4])를 시도하고, ct = .rdata[o+4:o+4+size], candidate key = 그다음 16바이트로 설정합니다. RC4로 복호화한 뒤 문자열 필드가 UTF-8로 디코딩되고 길이가 적절한지 확인하세요.
- 같은 length-prefixed 규칙에 따라 SMB/TCP profile을 파싱하세요.

## 사용자 지정 listener profile: 고전적인 HTTP schema만 하드코딩하지 마세요

외부 패킹 형식(`u32 size | RC4 ciphertext | 16-byte key`)은 재사용할 수 있으므로, actor가 사용자 지정한 listener도 같은 추출 workflow를 유지하면서 복호화된 필드 레이아웃을 완전히 바꿀 수 있습니다.

좋은 최신 사례는 2026년 3월의 Tropic Trooper 캠페인입니다. 추출된 Adaptix beacon에는 표준 HTTP/TCP profile 대신 다음과 같은 GitHub transport parameter가 저장되어 있었습니다.<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (예: `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

실용적인 parser 전략:
- 먼저 평소와 똑같이 외부 RC4 blob을 탐지합니다.
- 복호화 후 곧바로 HTTP parser를 적용하는 대신, sentinel 문자열과 필드의 유효성을 기준으로 분기합니다.
- 유용한 sentinel에는 `api.github.com`, `/issues?state=open`, HTTP verb/URI, named pipe 형식의 문자열, 또는 명백히 유효한 server/port 배열이 포함됩니다.
- HTTP parser가 실패하더라도 평문에 일관성 있는 length-prefixed UTF-8 문자열이 있으면 false positive로 버리지 말고, 샘플을 보존해 다른 schema를 시도하세요.

이 캠페인에서 사용자 지정 listener는 GitHub issues를 C2 transport로 사용했고, beacon은 `ipinfo.io`를 조회해 외부 IP를 알아냈습니다. GitHub API는 피해자 측 source address를 operator에게 직접 알려주지 않기 때문입니다.<sup>[[5]](#references)</sup>

## 네트워크 fingerprinting 및 헌팅

HTTP:<sup>[[1]](#references)</sup>
- 일반적인 패턴: operator가 선택한 URI로 POST (예: /uri.php, /endpoint/api)
- beacon ID에 사용되는 사용자 지정 header parameter (예: X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 또는 당시의 Chrome build를 흉내 내는 user-agent
- sleep_delay/jitter_delay를 통해 확인할 수 있는 polling 주기
- 최신 build는 callback마다 URI, user-agent, Host header, server를 바꿔 사용할 수 있습니다. 따라서 단일 path/UA 조합을 가정하기보다 흔하지 않은 header 이름, response-size 패턴, TLS 재사용, timing을 기준으로 클러스터링하세요.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- web egress가 제한된 intranet C2용 SMB named-pipe listener
- TCP beacon은 protocol 시작 부분을 난독화하기 위해 traffic 앞에 몇 바이트를 추가할 수 있음

현재 upstream teamserver 기본값
- `profile.yaml`에는 현재 teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key 파일명 `server.rsa.crt` 및 `server.rsa.key`, 그리고 HTTP, SMB, TCP, DNS, Beacon agent, Gopher용 extender가 포함되어 있습니다.<sup>[[2]](#references)</sup>
- 일치하는 route가 없으면 기본 error handler는 `Server: AdaptixC2`와 `Adaptix-Version: v1.2`를 반환합니다.<sup>[[4]](#references)</sup>
- 기본 404 body에는 `AdaptixC2 404`와 `You need to enter the correct connection details`가 포함됩니다.<sup>[[4]](#references)</sup>
- 2026년 인터넷 전역 scan에서는 `4321` 포트에 노출된 teamserver와 `43211` 포트에 노출된 beacon listener가 다수 발견되었습니다. 따라서 두 포트 모두 유용한 시작점이지만, 전체를 포괄하는 것으로 간주해서는 안 됩니다.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprint:<sup>[[4]](#references)</sup>
- 현재 BeaconDNS extender는 authoritative 응답을 합니다 (`AA=true`).
- beacon protocol 형식과 일치하지 않는 query, 특히 설정된 domain 앞의 label이 5개 미만인 이름에는 보통 `TXT "OK"`로 응답합니다.
- 설정된 base TTL을 0으로 두면 listener는 10초를 기본값으로 사용하고 최대 59초의 jitter를 추가합니다.
- HTTP listener가 노출되지 않은 경우 짧은 label을 사용한 active probe가 유용합니다.

## 사고 사례에서 확인된 loader 및 persistence TTP

메모리 내 PowerShell loader:<sup>[[1]](#references)</sup>
- Base64/XOR payload를 다운로드합니다 (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- unmanaged memory를 할당하고 shellcode를 복사한 뒤, VirtualProtect를 통해 보호 속성을 0x40 (PAGE_EXECUTE_READWRITE)으로 변경합니다.<sup>[[7]](#references)</sup>
- .NET dynamic invocation인 Marshal.GetDelegateForFunctionPointer + delegate.Invoke()를 통해 실행합니다.<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loader:<sup>[[5]](#references)</sup>
- 2026년 Tropic Trooper 공격 체인에서는 trojanized SumatraPDF executable (TOSHIS loader)을 사용해 PE entry point를 patch하지 않고 `_security_init_cookie`를 악성 코드로 redirect했습니다.
- loader는 Adler-32 hashing으로 API를 해석하고, decoy PDF를 다운로드한 뒤 2단계 shellcode를 가져왔습니다. 이후 WinCrypt의 `CryptDeriveKey`를 사용해 hardcoded seed로 AES-128-CBC 복호화하고, 메모리에서 Adaptix beacon을 reflective하게 실행했습니다.
- 이후 persistence는 `\MSDNSvc` 또는 `\MicrosoftUDN` 같은 무해해 보이는 이름의 scheduled task로 옮겨갔으며, 대략 두 시간마다 agent를 다시 실행하도록 설정했습니다.

메모리 내 실행 및 AMSI/ETW 관련 고려사항은 다음 페이지를 참조하세요.

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

관찰된 persistence 방식:<sup>[[1]](#references)</sup>
- logon 시 loader를 다시 실행하는 Startup folder shortcut (.lnk)
- Registry Run key (HKCU/HKLM ...\CurrentVersion\Run). loader.ps1을 시작하기 위해 "Updater"처럼 무해해 보이는 이름을 사용하는 경우가 많습니다.<sup>[[10]](#references)</sup>
- 취약한 process를 대상으로 %APPDATA%\Microsoft\Windows\Templates에 msimg32.dll을 저장해 DLL search-order hijack 수행

기법 상세 분석 및 점검:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

헌팅 아이디어
- PowerShell에서 RW→RX 전환이 발생하는지 확인: powershell.exe 내부의 VirtualProtect를 통한 PAGE_EXECUTE_READWRITE 전환.<sup>[[8]](#references)</sup>
- Dynamic invocation 패턴 (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` 또는 `You need to enter the correct connection details`가 포함된 일치하지 않는 HTTPS 404 응답.<sup>[[4]](#references)</sup>
- 의심스러운 domain의 짧은 query에 대한 `AA=true` 및 `TXT "OK"` DNS 응답.<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues`로 향하는 GitHub API traffic 뒤에 같은 loader/beacon chain에서 발생하는 `ipinfo.io` lookup.<sup>[[5]](#references)</sup>
- 사용자 또는 공용 Startup folder 아래의 Startup .lnk.<sup>[[1]](#references)</sup>
- 의심스러운 Run key (예: "Updater") 및 update.ps1/loader.ps1 같은 loader 이름.<sup>[[1]](#references)</sup>
- decoy 문서를 표시하기 전에 `_security_init_cookie`를 downloader code로 redirect하는 trojanized PE sample.<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates 아래 사용자 쓰기 가능 경로에 있는 msimg32.dll.<sup>[[1]](#references)</sup>

## OpSec 필드 참고사항

- KillDate: agent가 자체 만료되는 시점.<sup>[[1]](#references)</sup>
- WorkingTime: 업무 활동에 섞이도록 agent가 활성 상태여야 하는 시간대.<sup>[[1]](#references)</sup>

이 필드는 클러스터링에 활용할 수 있으며, 관찰된 비활성 시간을 설명하는 데도 도움이 됩니다.

## YARA 및 정적 분석 단서

Unit 42는 beacon (C/C++ 및 Go)과 loader API-hashing constant에 대한 기본 YARA를 공개했습니다.<sup>[[1]](#references)</sup> PE .rdata 끝부분 주변의 [size|ciphertext|16-byte-key] 레이아웃, 기본 HTTP profile 문자열, 그리고 `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, `ipinfo.io` 같은 최신 server/listener marker를 찾는 rule로 보완하는 것을 고려하세요.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: 실제 공격에서 활용된 새로운 오픈소스 프레임워크 (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework 문서](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 대규모 오픈소스 C2 프레임워크 fingerprinting (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper의 AdaptixC2 및 사용자 지정 Beacon Listener 활용 (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [메모리 보호 상수 – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
