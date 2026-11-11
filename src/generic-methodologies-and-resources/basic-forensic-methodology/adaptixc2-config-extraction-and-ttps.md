# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 is a modular, open‑source post‑exploitation/C2 framework with Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) and BOF support.<sup>[[1]](#references)</sup> This page documents:
- How its RC4‑packed configuration is embedded and how to extract it from beacons
- Network/profile indicators for HTTP/SMB/TCP listeners
- Common loader and persistence TTPs observed in the wild, with links to relevant Windows technique pages

Recent upstream releases also ship DNS/DoH beacon listeners and the separate Gopher agent/listener family, so modern Adaptix infrastructure may expose more than the original HTTP/SMB/TCP surfaces even when a specific sample still uses the classic beacon agent.<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2 supports three primary beacon types:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 with configurable servers/ports/SSL, method, URI, headers, user‑agent, and a custom parameter name
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, optionally with a prepended marker to obfuscate protocol start

These are the beacon layouts publicly documented in early Adaptix analyses and they are still the most common starting point for sample-side extraction.<sup>[[1]](#references)</sup> However, current upstream builds also ship `BeaconDNS` and Gopher extenders on the server side, so do not assume every live Adaptix deployment exposes only HTTP/SMB/TCP infrastructure.<sup>[[2]](#references)</sup>

The following field summary and JSON samples describe the HTTP format analyzed in 2025; they are not a parser specification for newer upstream builds. Typical fields in those samples (after decryption):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP builds also support operator-selected rotation across multiple URIs, user-agents, Host headers, and servers, with sequential or random selection.<sup>[[2]](#references)</sup> From a hunting perspective this means a single infected host may fan out across several callback paths and header combinations without leaving the classic RC4-packed beacon family.

Example default HTTP profile (from a beacon build):<sup>[[1]](#references)</sup>

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

Observed malicious HTTP profile (real attack):<sup>[[1]](#references)</sup>

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

## Encrypted configuration packing and load path

When the operator clicks Create in the builder, AdaptixC2 compiles the encrypted profile into the beacon. Do not assume it is at the end of the PE or shellcode: locate the profile bytes by section scan or by following `getProfile()` in the sample. The packed format is:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

The beacon loader copies the 16‑byte key from the end and RC4‑decrypts the N‑byte block in place:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Practical implications:<sup>[[1]](#references)</sup>
- The entire structure often lives inside the PE .rdata section.
- Extraction is deterministic: read size, read ciphertext of that size, read the 16‑byte key placed immediately after, then RC4‑decrypt.

## Configuration extraction workflow (defenders)

For general sample triage before carving the beacon, see [Malware Analysis](malware-analysis.md).

Write an extractor that mimics the beacon logic:<sup>[[1]](#references)</sup>
1) Locate the blob inside the PE (commonly .rdata). A pragmatic approach is to scan .rdata for a plausible [size|ciphertext|16‑byte key] layout and attempt RC4.
2) Read first 4 bytes → size (uint32 LE).
3) Read next N=size bytes → ciphertext.
4) Read final 16 bytes → RC4 key.
5) RC4‑decrypt the ciphertext. Then parse the plain profile as:
   - u32/boolean scalars as noted above
   - length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
   - arrays: servers_count followed by that many [string, u32 port] pairs

Legacy HTTP Python proof‑of‑concept (standalone, no external deps) for a pre‑extracted blob in the 2025 field order. Use the current-schema parser below for recent stock builds:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Parse current stock HTTP and DNS profiles

Current upstream packs six little-endian `u32` values first: agent watermark/type, kill date, working time, sleep, jitter, and listener watermark/type. The HTTP-specific data then starts with a one-byte SSL flag. Unlike the legacy example, it has counted URI, user-agent, and Host-header lists followed by rotation mode and proxy settings. Thus the legacy parser starts reading the SSL flag from the kill-date field and produces false results on these builds. String lengths and integer values in this profile use little-endian encoding; packed strings include a trailing NUL when nonempty.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

With the `P` and `rc4` helpers above, use this parser on decrypted **stock HTTP** plaintext. Keep the RC4 key out of public reports: the HTTP profile may contain a proxy username and password.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Parse a current stock HTTP plaintext profile</summary>

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

For a stock DNS beacon, read the same six common `u32` fields, then the length-prefixed `domain`, `resolvers`, `doh_resolvers`, and `qtype` strings. Read `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter`, and `dns_mode` as `u32`, then the length-prefixed DoH user-agent string. `dns_mode` distinguishes UDP, DoH, and the two fallback directions. This is a separate layout: do not force DNS plaintext through the HTTP parser.<sup>[[12]](#references)[[13]](#references)</sup>

Tips:
- When automating, use a PE parser to read .rdata then apply a sliding window: for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt and check that string fields decode as UTF‑8 and lengths are sane.
- Parse SMB/TCP profiles by following the same length‑prefixed conventions.

## Custom listener profiles: don't hard-code only the classic HTTP schema

The outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) is reusable, so actor-customized listeners can keep the same extraction workflow while changing the decrypted field layout completely.

A good recent example is the March 2026 Tropic Trooper campaign, where the extracted Adaptix beacon did not contain a standard HTTP/TCP profile. Instead, the decrypted blob stored GitHub transport parameters such as:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (for example `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- First detect the outer RC4 blob exactly as usual.
- After decryption, branch on sentinel strings and field sanity rather than immediately forcing the HTTP parser.
- Good sentinels include `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings, or obviously valid server/port arrays.
- If the HTTP parser fails but the plaintext contains coherent length-prefixed UTF-8 strings, keep the sample and attempt alternative schemas instead of discarding it as a false positive.

In that campaign the custom listener used GitHub issues as the C2 transport, and the beacon queried `ipinfo.io` to learn its external IP because the GitHub API does not directly reveal the victim source address to the operator.<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP:<sup>[[1]](#references)</sup>
- Common: POST to operator‑selected URIs (e.g., /uri.php, /endpoint/api)
- Custom header parameter used for beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents mimicking Firefox 20 or contemporary Chrome builds
- Polling cadence visible via sleep_delay/jitter_delay
- Newer builds can rotate URIs, user-agents, Host headers, and servers across callbacks, so cluster on uncommon header names, response-size patterns, TLS reuse, and timing instead of assuming a single path/UA pair.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named‑pipe listeners for intranet C2 where web egress is constrained
- TCP beacons may prepend a few bytes before traffic to obfuscate protocol start

Current upstream teamserver defaults
- `profile.yaml` currently ships with teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` and `server.rsa.key`, and extenders for HTTP, SMB, TCP, DNS, Beacon agent, and Gopher.<sup>[[2]](#references)</sup>
- On unmatched routes, the default error handler returns `Server: AdaptixC2` and `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- The stock 404 body contains `AdaptixC2 404` and `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide scans in 2026 found many exposed teamservers on `4321` and many beacon listeners on `43211`, so both ports are useful seed pivots but should not be treated as exhaustive.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- The current BeaconDNS extender answers authoritatively (`AA=true`)
- Queries that do not match the beacon protocol shape — notably names with fewer than 5 labels before the configured domain — are commonly answered with `TXT "OK"`
- If the configured base TTL is left at zero, the listener uses a 10-second base and adds up to 59 seconds of jitter
- This makes short-label active probes useful when no HTTP listener is exposed

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Download Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Allocate unmanaged memory, copy shellcode, switch protection to 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Execute via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- A 2026 Tropic Trooper chain used a trojanized SumatraPDF executable (TOSHIS loader) that redirected `_security_init_cookie` into malicious code instead of patching the PE entry point
- The loader resolved APIs via Adler-32 hashing, downloaded a decoy PDF, fetched second-stage shellcode, decrypted it with AES-128-CBC through WinCrypt (`CryptDeriveKey` from a hardcoded seed), and reflectively executed an Adaptix beacon in memory
- Persistence later moved to scheduled tasks with benign-looking names such as `\MSDNSvc` or `\MicrosoftUDN`, configured to re-launch the agent roughly every two hours

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed:<sup>[[1]](#references)</sup>
- Startup folder shortcut (.lnk) to re‑launch a loader at logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), often with benign‑sounding names like "Updater" to start loader.ps1.<sup>[[10]](#references)</sup>
- DLL search‑order hijack by dropping msimg32.dll under %APPDATA%\Microsoft\Windows\Templates for susceptible processes

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions: VirtualProtect to PAGE_EXECUTE_READWRITE inside powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s with `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, or `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses with `AA=true` and `TXT "OK"` for short queries under suspect domains.<sup>[[4]](#references)</sup>
- GitHub API traffic to `/repos/<owner>/<repo>/issues` followed by `ipinfo.io` lookups from the same loader/beacon chain.<sup>[[5]](#references)</sup>
- Startup .lnk under user or common Startup folders.<sup>[[1]](#references)</sup>
- Suspicious Run keys (e.g., "Updater"), and loader names like update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples that redirect `_security_init_cookie` into downloader code before showing a decoy document.<sup>[[5]](#references)</sup>
- User‑writable DLL paths under %APPDATA%\Microsoft\Windows\Templates containing msimg32.dll.<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: timestamp after which the agent self‑expires.<sup>[[1]](#references)</sup>
- WorkingTime: hours when the agent should be active to blend with business activity.<sup>[[1]](#references)</sup>

These fields can be used for clustering and to explain observed quiet periods.

## YARA and static leads

Unit 42 published basic YARA for beacons (C/C++ and Go) and loader API‑hashing constants.<sup>[[1]](#references)</sup> Consider complementing with rules that look for the [size|ciphertext|16‑byte‑key] layout near PE .rdata end, the default HTTP profile strings, and newer server/listener markers such as `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, and `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profile generation (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profile generation (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile packing (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
