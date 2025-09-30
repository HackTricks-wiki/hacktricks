# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 is a modular, open‑source post‑exploitation/C2 framework with Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) and BOF support. This page documents:
- How its RC4‑packed configuration is embedded and how to extract it from beacons
- Network/profile indicators for HTTP/SMB/TCP listeners
- Common loader and persistence TTPs observed in the wild, with links to relevant Windows technique pages

## Beacon profiles and fields

AdaptixC2 supports three primary beacon types:
- BEACON_HTTP: web C2 with configurable servers/ports/SSL, method, URI, headers, user‑agent, and a custom parameter name
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, optionally with a prepended marker to obfuscate protocol start

Typical profile fields observed in HTTP beacon configs (after decryption):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – used to parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):

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

Observed malicious HTTP profile (real attack):

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

When the operator clicks Create in the builder, AdaptixC2 embeds the encrypted profile as a tail blob in the beacon. The format is:
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

The beacon loader copies the 16‑byte key from the end and RC4‑decrypts the N‑byte block in place:

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Practical implications:
- The entire structure often lives inside the PE .rdata section.
- Extraction is deterministic: read size, read ciphertext of that size, read the 16‑byte key placed immediately after, then RC4‑decrypt.

## Configuration extraction workflow (defenders)

Write an extractor that mimics the beacon logic:
1) Locate the blob inside the PE (commonly .rdata). A pragmatic approach is to scan .rdata for a plausible [size|ciphertext|16‑byte key] layout and attempt RC4.
2) Read first 4 bytes → size (uint32 LE).
3) Read next N=size bytes → ciphertext.
4) Read final 16 bytes → RC4 key.
5) RC4‑decrypt the ciphertext. Then parse the plain profile as:
   - u32/boolean scalars as noted above
   - length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
   - arrays: servers_count followed by that many [string, u32 port] pairs

Minimal Python proof‑of‑concept (standalone, no external deps) that works with a pre‑extracted blob:

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

Tips:
- When automating, use a PE parser to read .rdata then apply a sliding window: for each offset o, try size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt and check that string fields decode as UTF‑8 and lengths are sane.
- Parse SMB/TCP profiles by following the same length‑prefixed conventions.

## Network fingerprinting and hunting

HTTP
- Common: POST to operator‑selected URIs (e.g., /uri.php, /endpoint/api)
- Custom header parameter used for beacon ID (e.g., X‑Beacon‑Id, X‑App‑Id)
- User‑agents mimicking Firefox 20 or contemporary Chrome builds
- Polling cadence visible via sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners for intranet C2 where web egress is constrained
- TCP beacons may prepend a few bytes before traffic to obfuscate protocol start

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Download Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Allocate unmanaged memory, copy shellcode, switch protection to 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Execute via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Check these pages for in‑memory execution and AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Startup folder shortcut (.lnk) to re‑launch a loader at logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), often with benign‑sounding names like "Updater" to start loader.ps1
- DLL search‑order hijack by dropping msimg32.dll under %APPDATA%\Microsoft\Windows\Templates for susceptible processes

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions: VirtualProtect to PAGE_EXECUTE_READWRITE inside powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Startup .lnk under user or common Startup folders
- Suspicious Run keys (e.g., "Updater"), and loader names like update.ps1/loader.ps1
- User‑writable DLL paths under %APPDATA%\Microsoft\Windows\Templates containing msimg32.dll

## Notes on OpSec fields

- KillDate: timestamp after which the agent self‑expires
- WorkingTime: hours when the agent should be active to blend with business activity

These fields can be used for clustering and to explain observed quiet periods.

## YARA and static leads

Unit 42 published basic YARA for beacons (C/C++ and Go) and loader API‑hashing constants. Consider complementing with rules that look for the [size|ciphertext|16‑byte‑key] layout near PE .rdata end and the default HTTP profile strings.

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
