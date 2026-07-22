# AdaptixC2 Configuration Extraction और TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 एक modular, open‑source post‑exploitation/C2 framework है, जिसमें Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) और BOF support है। यह पेज दस्तावेज़ित करता है:
- इसका RC4-packed configuration किस प्रकार embedded है और इसे beacons से कैसे extract किया जाए
- HTTP/SMB/TCP listeners के लिए network/profile indicators
- wild में देखे गए common loader और persistence TTPs, साथ में relevant Windows technique pages के links

हाल की upstream releases में DNS/DoH beacon listeners और अलग Gopher agent/listener family भी शामिल हैं, इसलिए modern Adaptix infrastructure मूल HTTP/SMB/TCP surfaces से अधिक expose कर सकता है, भले ही कोई specific sample अभी भी classic beacon agent का उपयोग करता हो।

## Beacon profiles और fields

AdaptixC2 तीन primary beacon types support करता है:
- BEACON_HTTP: configurable servers/ports/SSL, method, URI, headers, user-agent और custom parameter name वाला web C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, जिसमें protocol start को obfuscate करने के लिए वैकल्पिक रूप से prepended marker हो सकता है

ये beacon layouts early Adaptix analyses में publicly documented थे और sample-side extraction के लिए अभी भी सबसे common starting point हैं। हालांकि, current upstream builds server side पर `BeaconDNS` और Gopher extenders भी ship करते हैं, इसलिए यह assume न करें कि हर live Adaptix deployment केवल HTTP/SMB/TCP infrastructure expose करता है।

HTTP beacon configs में देखे गए typical profile fields (decryption के बाद):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizes parse करने के लिए उपयोग किए जाते हैं
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP builds multiple URIs, user-agents, Host headers और servers के बीच operator-selected rotation भी support करते हैं, जिसमें sequential या random selection हो सकता है। Hunting के दृष्टिकोण से इसका अर्थ है कि एक single infected host कई callback paths और header combinations पर fan out कर सकता है, classic RC4-packed beacon family को छोड़े बिना।

Example default HTTP profile (एक beacon build से):
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
देखा गया malicious HTTP profile (वास्तविक attack):
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
## Encrypted configuration packing और load path

जब operator builder में Create पर क्लिक करता है, AdaptixC2 encrypted profile को beacon में tail blob के रूप में embed करता है। Format है:
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader अंत से 16-byte key को copy करता है और N-byte block को वहीं पर RC4-decrypt करता है:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- पूरी structure अक्सर PE के .rdata section के अंदर रहती है।
- Extraction deterministic है: size पढ़ें, उस size का ciphertext पढ़ें, तुरंत उसके बाद रखी गई 16-byte key पढ़ें, फिर RC4-decrypt करें।

## Configuration extraction workflow (रक्षकों के लिए)

एक extractor लिखें जो beacon logic की नकल करे:
1) PE के अंदर blob को locate करें (आमतौर पर .rdata में)। एक व्यावहारिक तरीका यह है कि .rdata को plausible [size|ciphertext|16-byte key] layout के लिए scan करें और RC4 आज़माएँ।
2) पहले 4 bytes पढ़ें → size (uint32 LE)।
3) अगले N=size bytes पढ़ें → ciphertext।
4) अंतिम 16 bytes पढ़ें → RC4 key।
5) ciphertext को RC4-decrypt करें। फिर plain profile को इस प्रकार parse करें:
- u32/boolean scalars, जैसा ऊपर बताया गया है
- length-prefixed strings (u32 length के बाद bytes; trailing NUL मौजूद हो सकता है)
- arrays: servers_count के बाद उतने ही [string, u32 port] pairs

Minimal Python proof-of-concept (standalone, no external deps), जो pre-extracted blob के साथ काम करता है:
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
- Automation करते समय, `.rdata` को पढ़ने के लिए PE parser का उपयोग करें और फिर sliding window लागू करें: प्रत्येक offset o के लिए, `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, candidate key = अगले 16 bytes आज़माएँ; RC4-decrypt करें और जाँचें कि string fields UTF-8 के रूप में decode हों और lengths उचित हों।
- SMB/TCP profiles को उन्हीं length-prefixed conventions का अनुसरण करके parse करें।

## Custom listener profiles: केवल classic HTTP schema को hard-code न करें

Outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) reusable है, इसलिए actor-customized listeners समान extraction workflow बनाए रख सकते हैं, जबकि decrypted field layout पूरी तरह बदल सकता है।

एक अच्छा हालिया उदाहरण April 2026 का Tropic Trooper campaign है, जिसमें extracted Adaptix beacon में standard HTTP/TCP profile नहीं था। इसके बजाय, decrypted blob में GitHub transport parameters संग्रहीत थे, जैसे:
- `repo_owner`
- `repo_name`
- `api_host` (उदाहरण के लिए `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- सबसे पहले outer RC4 blob को हमेशा की तरह detect करें।
- Decryption के बाद, HTTP parser को तुरंत लागू करने के बजाय sentinel strings और field sanity के आधार पर branch करें।
- अच्छे sentinels में `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings या स्पष्ट रूप से valid server/port arrays शामिल हैं।
- यदि HTTP parser विफल हो जाता है, लेकिन plaintext में coherent length-prefixed UTF-8 strings मौजूद हैं, तो sample को रखें और alternative schemas आज़माएँ; इसे false positive मानकर discard न करें।

उस campaign में custom listener ने GitHub issues को C2 transport के रूप में उपयोग किया, और beacon ने अपना external IP जानने के लिए `ipinfo.io` को query किया, क्योंकि GitHub API operator को victim source address सीधे नहीं दिखाती।

## Network fingerprinting और hunting

HTTP
- Common: operator-selected URIs पर POST (जैसे `/uri.php`, `/endpoint/api`)
- Beacon ID के लिए उपयोग किया जाने वाला custom header parameter (जैसे `X-Beacon-Id`, `X-App-Id`)
- Firefox 20 या contemporary Chrome builds की नकल करने वाले User-agents
- `sleep_delay`/`jitter_delay` के माध्यम से दिखाई देने वाली polling cadence
- Newer builds callbacks के बीच URIs, user-agents, Host headers और servers को rotate कर सकते हैं; इसलिए किसी एक path/UA pair को मानने के बजाय uncommon header names, response-size patterns, TLS reuse और timing के आधार पर cluster करें

SMB/TCP
- ऐसे intranet C2 के लिए SMB named-pipe listeners जहाँ web egress constrained हो
- TCP beacons protocol start को obfuscate करने के लिए traffic से पहले कुछ bytes जोड़ सकते हैं

Current upstream teamserver defaults
- `profile.yaml` में वर्तमान में teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` और `server.rsa.key`, तथा HTTP, SMB, TCP, DNS, Beacon agent और Gopher के extenders शामिल हैं
- Unmatched routes पर, default error handler `Server: AdaptixC2` और `Adaptix-Version: v1.2` लौटाता है
- Stock 404 body में `AdaptixC2 404` और `You need to enter the correct connection details.` शामिल हैं
- 2026 में Internet-wide scans में `4321` पर कई exposed teamservers और `43211` पर कई beacon listeners मिले; इसलिए दोनों ports उपयोगी seed pivots हैं, लेकिन इन्हें exhaustive नहीं मानना चाहिए

DNS/DoH listener fingerprints
- वर्तमान BeaconDNS extender authoritative रूप से उत्तर देता है (`AA=true`)
- वे queries जो beacon protocol shape से मेल नहीं खातीं — विशेष रूप से configured domain से पहले 5 से कम labels वाले names — उन्हें सामान्यतः `TXT "OK"` के साथ उत्तर दिया जाता है
- यदि configured base TTL को zero पर छोड़ा जाता है, तो listener 10-second base का उपयोग करता है और jitter के रूप में अधिकतम 59 seconds जोड़ता है
- HTTP listener exposed न होने पर यह short-label active probes को उपयोगी बनाता है

## Incidents में देखे गए Loader और persistence TTPs

In-memory PowerShell loaders
- Base64/XOR payloads download करते हैं (Invoke-RestMethod / WebClient)
- Unmanaged memory allocate करते हैं, shellcode copy करते हैं, और VirtualProtect के माध्यम से protection को 0x40 (PAGE_EXECUTE_READWRITE) में बदलते हैं
- .NET dynamic invocation के माध्यम से execute करते हैं: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- 2026 की एक Tropic Trooper chain में trojanized SumatraPDF executable (TOSHIS loader) का उपयोग किया गया, जिसने PE entry point को patch करने के बजाय `_security_init_cookie` को malicious code की ओर redirect किया
- Loader ने Adler-32 hashing के माध्यम से APIs resolve कीं, एक decoy PDF download किया, second-stage shellcode fetch किया, उसे hardcoded seed से WinCrypt (`CryptDeriveKey`) के माध्यम से AES-128-CBC से decrypt किया, और Adaptix beacon को memory में reflectively execute किया
- बाद में persistence scheduled tasks पर चली गई, जिनके benign-looking names जैसे `\MSDNSvc` या `\MicrosoftUDN` थे और जिन्हें लगभग हर दो घंटे में agent को फिर से launch करने के लिए configure किया गया था

In-memory execution और AMSI/ETW considerations के लिए इन pages को देखें:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed
- Logon पर loader को फिर से launch करने के लिए Startup folder shortcut (.lnk)
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), अक्सर "Updater" जैसे benign-sounding names के साथ loader.ps1 शुरू करने के लिए
- Susceptible processes के लिए `%APPDATA%\Microsoft\Windows\Templates` के अंतर्गत msimg32.dll drop करके DLL search-order hijack

Technique deep-dives और checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell spawning RW→RX transitions: powershell.exe के अंदर PAGE_EXECUTE_READWRITE पर VirtualProtect
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` या `You need to enter the correct connection details.` वाले unmatched HTTPS 404s
- Suspect domains के अंतर्गत short queries के लिए `AA=true` और `TXT "OK"` वाले DNS responses
- `/repos/<owner>/<repo>/issues` पर GitHub API traffic और उसी loader/beacon chain से `ipinfo.io` lookups
- User या common Startup folders के अंतर्गत Startup .lnk
- Suspicious Run keys (जैसे "Updater") और update.ps1/loader.ps1 जैसे loader names
- ऐसे trojanized PE samples जो decoy document दिखाने से पहले `_security_init_cookie` को downloader code की ओर redirect करते हैं
- `%APPDATA%\Microsoft\Windows\Templates` के अंतर्गत user-writable DLL paths, जिनमें msimg32.dll मौजूद हो

## OpSec fields पर Notes

- KillDate: वह timestamp जिसके बाद agent self-expires
- WorkingTime: वे hours जब agent business activity के साथ blend करने के लिए active रहना चाहिए

इन fields का उपयोग clustering के लिए और देखी गई quiet periods को explain करने के लिए किया जा सकता है।

## YARA और static leads

Unit 42 ने beacons (C/C++ और Go) तथा loader API-hashing constants के लिए basic YARA प्रकाशित किया है। ऐसी rules जोड़ने पर विचार करें जो PE `.rdata` end के निकट `[size|ciphertext|16-byte-key]` layout, default HTTP profile strings और नए server/listener markers जैसे `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` और `ipinfo.io` को देखें।

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
