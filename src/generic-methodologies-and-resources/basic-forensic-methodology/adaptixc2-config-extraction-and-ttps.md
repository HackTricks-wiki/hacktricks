# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2는 Windows x86/x64 beacon(EXE/DLL/service EXE/raw shellcode)과 BOF를 지원하는 모듈형 오픈소스 post-exploitation/C2 framework입니다.<sup>[[1]](#references)</sup> 이 페이지에서는 다음 내용을 다룹니다.
- RC4로 패킹된 configuration이 어떻게 삽입되는지와 beacon에서 이를 추출하는 방법
- HTTP/SMB/TCP listener의 네트워크 및 profile 식별자
- 실제 환경에서 관찰된 일반적인 loader 및 persistence TTP와 관련 Windows technique 페이지 링크

최근 upstream release에는 DNS/DoH beacon listener와 별도의 Gopher agent/listener 제품군도 포함되어 있습니다. 따라서 특정 sample이 여전히 classic beacon agent를 사용하더라도, 최신 Adaptix 인프라가 기존 HTTP/SMB/TCP 외의 표면을 노출할 수 있습니다.<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2는 세 가지 기본 beacon 유형을 지원합니다.<sup>[[1]](#references)</sup>
- BEACON_HTTP: 서버/포트/SSL, method, URI, header, user-agent, custom parameter name을 설정할 수 있는 웹 C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: 직접 socket 연결. protocol 시작을 난독화하기 위해 앞에 marker를 추가할 수도 있음

이는 초기 Adaptix 분석에서 공개적으로 문서화된 beacon 레이아웃이며, sample 측 추출을 시작할 때 여전히 가장 흔히 사용하는 대상입니다.<sup>[[1]](#references)</sup> 그러나 현재 upstream build에는 server 측 `BeaconDNS` 및 Gopher extender도 포함되어 있으므로, 실제 Adaptix 배포 환경이 HTTP/SMB/TCP 인프라만 노출한다고 가정하지 마세요.<sup>[[2]](#references)</sup>

다음 field 요약과 JSON sample은 2025년에 분석한 HTTP 형식을 설명하며, 최신 upstream build의 parser 사양은 아닙니다. 해당 sample의 일반적인 field는 다음과 같습니다(복호화 후).<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response size를 파싱하는 데 사용
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

최근 BeaconHTTP build에서는 operator가 여러 URI, user-agent, Host header, server 간 순차 또는 무작위 rotation을 선택할 수도 있습니다.<sup>[[2]](#references)</sup> 따라서 threat hunting 시 단일 감염 호스트가 classic RC4-packed beacon 제품군을 벗어나지 않으면서도 여러 callback 경로와 header 조합으로 연결을 분산할 수 있습니다.

예시 기본 HTTP profile (beacon build에서 가져옴):<sup>[[1]](#references)</sup>

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

관찰된 악성 HTTP 프로필(실제 공격):<sup>[[1]](#references)</sup>

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

operator가 builder에서 Create를 클릭하면 AdaptixC2는 암호화된 profile을 beacon에 컴파일합니다. PE나 shellcode의 끝에 있다고 가정하지 마세요. 섹션을 스캔하거나 샘플에서 `getProfile()`을 따라 profile 바이트를 찾으세요. 패킹된 형식은 다음과 같습니다:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: 구성 크기 (uint32, 리틀엔디언)
- N bytes: RC4로 암호화된 구성 데이터
- 16 bytes: RC4 키

beacon loader는 끝에서 16-byte 키를 복사한 다음 N-byte 블록을 제자리에서 RC4로 복호화합니다:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

실질적인 의미:<sup>[[1]](#references)</sup>
- 전체 구조는 대개 PE의 .rdata 섹션 안에 있습니다.
- 추출 과정은 결정적입니다. 크기를 읽고, 해당 크기만큼 ciphertext를 읽은 다음, 바로 뒤에 배치된 16바이트 key를 읽고 RC4로 복호화합니다.

## Configuration 추출 워크플로(방어자용)

beacon을 추출하기 전에 일반적인 샘플 분류를 하려면 [Malware Analysis](malware-analysis.md)를 참조하세요.

beacon 로직을 모방하는 extractor를 작성합니다:<sup>[[1]](#references)</sup>
1) PE 내부에서 blob을 찾습니다(일반적으로 .rdata). 실용적인 방법은 .rdata에서 그럴듯한 [size|ciphertext|16-byte key] 레이아웃을 검색하고 RC4를 시도하는 것입니다.
2) 첫 4바이트 읽기 → size(uint32 LE).
3) 다음 N=size 바이트 읽기 → ciphertext.
4) 마지막 16바이트 읽기 → RC4 key.
5) ciphertext를 RC4로 복호화합니다. 그런 다음 다음과 같이 평문 profile을 파싱합니다.
   - 위에 설명한 u32/boolean scalar
   - 길이 프리픽스가 있는 문자열(u32 length 뒤에 bytes가 오며, 끝에 NUL이 있을 수 있음)
   - 배열: servers_count 뒤에 해당 개수만큼의 [string, u32 port] 쌍

2025년 현장 순서의 사전 추출 blob을 대상으로 하는 레거시 HTTP Python proof-of-concept(독립 실행형, 외부 의존성 없음)입니다. 최근 stock 빌드에는 아래의 current-schema parser를 사용하세요:<sup>[[1]](#references)[[11]](#references)</sup>

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

### 현재 stock HTTP 및 DNS 프로필 파싱

현재 upstream은 먼저 little-endian `u32` 값 6개를 저장합니다. 순서는 agent watermark/type, kill date, working time, sleep, jitter, listener watermark/type입니다. HTTP 관련 데이터는 그다음 1바이트 SSL 플래그부터 시작합니다. legacy 예제와 달리 URI, user-agent, Host 헤더 목록에는 개수 정보가 포함되며, 그 뒤에 rotation mode와 proxy 설정이 이어집니다. 따라서 legacy parser는 kill-date 필드에서 SSL 플래그를 읽기 시작해 이 빌드에서 잘못된 결과를 생성합니다. 이 프로필의 문자열 길이와 정수 값은 little-endian 인코딩을 사용하며, 패킹된 문자열은 비어 있지 않을 경우 끝에 NUL을 포함합니다.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

위의 `P` 및 `rc4` helper를 사용해 복호화된 **stock HTTP** plaintext에 이 parser를 적용하세요. HTTP 프로필에 proxy username과 password가 포함될 수 있으므로 RC4 key를 공개 보고서에 포함하지 마세요.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>현재 stock HTTP plaintext 프로필 파싱</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

기본 DNS beacon의 경우, 동일한 여섯 개의 공통 `u32` 필드를 읽은 다음 길이 접두사가 붙은 `domain`, `resolvers`, `doh_resolvers`, `qtype` 문자열을 읽습니다. `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter`, `dns_mode`는 `u32`로 읽고, 이어서 길이 접두사가 붙은 DoH user-agent 문자열을 읽습니다. `dns_mode`는 UDP, DoH 및 두 가지 fallback 방향을 구분합니다. 이는 별도의 레이아웃이므로 DNS plaintext를 HTTP parser로 처리하려고 해서는 안 됩니다.<sup>[[12]](#references)[[13]](#references)</sup>

팁:
- 자동화할 때는 PE parser로 .rdata를 읽은 다음 sliding window를 적용합니다. 각 offset o에 대해 size = u32(.rdata[o:o+4])를 시도하고, ct = .rdata[o+4:o+4+size], candidate key = 다음 16바이트로 설정합니다. RC4로 복호화한 뒤 문자열 필드가 UTF-8로 디코딩되고 길이가 타당한지 확인합니다.
- SMB/TCP profile은 동일한 길이 접두사 규칙에 따라 파싱합니다.

## Custom listener profile: 기존 HTTP schema만 하드코딩하지 않기

외부 패킹 형식(`u32 size | RC4 ciphertext | 16-byte key`)은 재사용할 수 있으므로, actor가 맞춤 설정한 listener도 복호화된 필드 레이아웃을 완전히 바꾸면서 동일한 추출 workflow를 유지할 수 있습니다.

최근의 좋은 사례는 2026년 3월 Tropic Trooper campaign입니다. 추출한 Adaptix beacon에는 표준 HTTP/TCP profile이 없었습니다. 대신 복호화된 blob에 다음과 같은 GitHub transport 매개변수가 저장되어 있었습니다:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (예: `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

실용적인 parser 전략:
- 먼저 평소처럼 외부 RC4 blob을 정확히 탐지합니다.
- 복호화한 후에는 HTTP parser를 바로 적용하지 말고 sentinel 문자열과 필드의 타당성을 기준으로 분기합니다.
- 유용한 sentinel로는 `api.github.com`, `/issues?state=open`, HTTP verb/URI, named-pipe 형식 문자열, 또는 명백히 유효한 server/port 배열이 있습니다.
- HTTP parser가 실패하더라도 plaintext에 일관성 있는 길이 접두사 UTF-8 문자열이 있으면, false positive로 버리지 말고 샘플을 유지한 채 다른 schema를 시도합니다.

해당 campaign에서 custom listener는 GitHub issues를 C2 transport로 사용했고, GitHub API가 victim의 source address를 operator에게 직접 알려주지 않기 때문에 beacon은 외부 IP를 확인하기 위해 `ipinfo.io`를 조회했습니다.<sup>[[5]](#references)</sup> 별도의 issue-plus-repository-file handshake에 대해서는 [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md)을 참조하세요.

## 네트워크 fingerprinting 및 hunting

HTTP:<sup>[[1]](#references)</sup>
- 일반적인 특징: operator가 선택한 URI로 POST 요청 (예: /uri.php, /endpoint/api)
- beacon ID에 사용하는 custom header 매개변수 (예: X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 또는 당시 최신 Chrome 빌드를 모방한 user-agent
- sleep_delay/jitter_delay를 통해 확인할 수 있는 polling 간격
- 최신 빌드는 callback마다 URI, user-agent, Host header 및 server를 바꿀 수 있으므로, 단일 path/UA 쌍을 전제로 하지 말고 흔하지 않은 header 이름, response 크기 패턴, TLS 재사용 및 타이밍을 기준으로 그룹화합니다.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- 웹 egress가 제한된 intranet C2에서 사용하는 SMB named-pipe listener
- TCP beacon은 protocol 시작 부분을 난독화하기 위해 traffic 앞에 몇 바이트를 추가할 수 있음

현재 upstream teamserver 기본값
- 현재 `profile.yaml`에는 teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key 파일명 `server.rsa.crt` 및 `server.rsa.key`, 그리고 HTTP, SMB, TCP, DNS, Beacon agent 및 Gopher용 extender가 포함되어 있습니다.<sup>[[2]](#references)</sup>
- 일치하는 route가 없으면 기본 error handler는 `Server: AdaptixC2` 및 `Adaptix-Version: v1.2`를 반환합니다.<sup>[[4]](#references)</sup>
- 기본 404 body에는 `AdaptixC2 404` 및 `You need to enter the correct connection details`가 포함됩니다.<sup>[[4]](#references)</sup>
- 2026년 인터넷 전역 scan에서는 `4321` 포트에 노출된 teamserver와 `43211` 포트에 노출된 beacon listener가 다수 발견되었습니다. 따라서 두 포트는 유용한 초기 탐색 지점이지만, 모든 사례를 포괄하는 것으로 간주해서는 안 됩니다.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprint:<sup>[[4]](#references)</sup>
- 현재 BeaconDNS extender는 authoritative하게 응답합니다 (`AA=true`).
- beacon protocol 형식과 일치하지 않는 query, 특히 설정된 domain 앞에 label이 5개 미만인 이름에는 일반적으로 `TXT "OK"`로 응답합니다.
- 설정된 기본 TTL을 0으로 두면 listener는 10초를 기본값으로 사용하고 최대 59초의 jitter를 추가합니다.
- 따라서 HTTP listener가 노출되지 않은 경우, 짧은 label을 사용한 active probe가 유용합니다.

## Incident에서 관찰된 loader 및 persistence TTP

In-memory PowerShell loader:<sup>[[1]](#references)</sup>
- Base64/XOR payload를 다운로드합니다 (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- unmanaged memory를 할당하고 shellcode를 복사한 뒤, VirtualProtect를 통해 보호 설정을 0x40 (PAGE_EXECUTE_READWRITE)으로 변경합니다.<sup>[[7]](#references)</sup>
- .NET dynamic invocation으로 실행합니다: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loader:<sup>[[5]](#references)</sup>
- 2026년 Tropic Trooper chain은 PE entry point를 patch하는 대신 `_security_init_cookie`를 악성 코드로 연결하는 trojanized SumatraPDF executable (TOSHIS loader)을 사용했습니다.
- loader는 Adler-32 hashing으로 API를 확인하고, decoy PDF를 다운로드하고, second-stage shellcode를 가져온 다음, 하드코딩된 seed에서 WinCrypt의 `CryptDeriveKey`를 사용해 AES-128-CBC로 복호화하고, Adaptix beacon을 memory에서 reflectively 실행했습니다.
- 이후 persistence는 `\MSDNSvc` 또는 `\MicrosoftUDN`처럼 정상적으로 보이는 이름의 scheduled task를 사용하는 방식으로 바뀌었으며, 약 2시간마다 agent를 다시 실행하도록 설정되었습니다.

In-memory execution 및 AMSI/ETW 고려 사항은 다음 페이지를 참조하세요.

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

관찰된 persistence 기법:<sup>[[1]](#references)</sup>
- 로그인 시 loader를 다시 실행하는 Startup folder 바로가기 (.lnk)
- loader.ps1을 시작하기 위해 흔히 "Updater" 같은 무해해 보이는 이름을 사용하는 Registry Run key (HKCU/HKLM ...\CurrentVersion\Run).<sup>[[10]](#references)</sup>
- 취약한 process를 대상으로 %APPDATA%\Microsoft\Windows\Templates에 msimg32.dll을 배치하는 DLL search-order hijack

기법 심층 분석 및 점검:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting 아이디어
- PowerShell에서 RW→RX 전환이 발생하는지 확인합니다: powershell.exe 내부의 VirtualProtect로 PAGE_EXECUTE_READWRITE 설정.<sup>[[8]](#references)</sup>
- Dynamic invocation 패턴 (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` 또는 `You need to enter the correct connection details`가 포함된 일치하지 않는 HTTPS 404 응답.<sup>[[4]](#references)</sup>
- 의심스러운 domain 아래의 짧은 query에 대해 `AA=true` 및 `TXT "OK"`가 포함된 DNS 응답.<sup>[[4]](#references)</sup>
- 동일한 loader/beacon chain에서 `/repos/<owner>/<repo>/issues`에 대한 GitHub API traffic 이후 발생하는 `ipinfo.io` 조회.<sup>[[5]](#references)</sup>
- 사용자 또는 공용 Startup folder에 있는 Startup .lnk.<sup>[[1]](#references)</sup>
- 의심스러운 Run key (예: "Updater") 및 update.ps1/loader.ps1 같은 loader 이름.<sup>[[1]](#references)</sup>
- decoy 문서를 표시하기 전에 `_security_init_cookie`를 downloader code로 연결하는 trojanized PE sample.<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates 아래의 사용자 쓰기 가능 DLL 경로에 있는 msimg32.dll.<sup>[[1]](#references)</sup>

## OpSec 필드 참고 사항

- KillDate: agent가 자체 만료되는 시점의 timestamp입니다.<sup>[[1]](#references)</sup>
- WorkingTime: 업무 활동에 섞여 보이도록 agent가 활성 상태여야 하는 시간대입니다.<sup>[[1]](#references)</sup>

이 필드는 그룹화에 활용할 수 있으며, 관찰된 활동 중단 시간을 설명하는 데 도움이 됩니다.

## YARA 및 정적 분석 단서

Unit 42는 beacon (C/C++ 및 Go) 및 loader의 API-hashing 상수에 대한 기본 YARA를 공개했습니다.<sup>[[1]](#references)</sup> PE .rdata 끝부분 부근의 [size|ciphertext|16-byte-key] 레이아웃, 기본 HTTP profile 문자열, 그리고 `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, `ipinfo.io` 같은 최신 server/listener marker를 찾는 규칙도 함께 사용하는 방안을 고려하세요.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: 실제 공격에서 활용된 새로운 오픈 소스 프레임워크 (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework 문서](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: 대규모 환경에서 오픈 소스 C2 프레임워크 fingerprinting하기 (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper, AdaptixC2 및 custom Beacon listener로 전환 (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft 문서](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft 문서](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection 상수 – Microsoft 문서](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Key/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profile 생성 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profile 생성 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile 패킹 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
