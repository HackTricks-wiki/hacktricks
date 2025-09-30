# AdaptixC2 Configuration Extraction और TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 एक modular, open‑source post‑exploitation/C2 framework है जिसमें Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) और BOF support शामिल हैं। यह पृष्ठ दस्तावेज़ करता है:
- यह बताना कि इसकी RC4‑packed configuration कैसे embedded है और beacons से इसे कैसे extract किया जाए
- HTTP/SMB/TCP listeners के लिए Network/profile indicators
- वास्तविक दुनिया में देखे गए सामान्य loader और persistence TTPs, साथ ही relevant Windows technique pages के लिंक

## Beacon profiles and fields

AdaptixC2 तीन मुख्य beacon प्रकारों का समर्थन करता है:
- BEACON_HTTP: web C2 जिसमें configurable servers/ports/SSL, method, URI, headers, user‑agent, और एक custom parameter name शामिल हैं
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, वैकल्पिक रूप से protocol start को obfuscate करने के लिए prepended marker के साथ

HTTP beacon configs में सामान्यतः देखे जाने वाले profile fields (decryption के बाद):
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
देखी गई दुर्भावनापूर्ण HTTP प्रोफ़ाइल (वास्तविक हमला):
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
## एन्क्रिप्टेड कॉन्फ़िगरेशन पैकिंग और लोड पाथ

जब ऑपरेटर बिल्डर में Create पर क्लिक करता है, AdaptixC2 एन्क्रिप्टेड प्रोफ़ाइल को beacon में एक tail blob के रूप में एम्बेड कर देता है। फॉर्मेट है:
- 4 bytes: कॉन्फ़िगरेशन का आकार (uint32, little‑endian)
- N bytes: RC4‑एन्क्रिप्टेड कॉन्फ़िगरेशन डेटा
- 16 bytes: RC4 कुंजी

beacon loader अंत से 16‑byte कुंजी को कॉपी करता है और N‑byte ब्लॉक को उसी स्थान पर RC4‑decrypt करता है:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
व्यावहारिक निहितार्थ:
- पूरी संरचना अक्सर PE .rdata सेक्शन के अंदर रहती है।
- निकासी निश्चित है: size पढ़ें, उस size के ciphertext को पढ़ें, तुरंत बाद रखी गई 16‑byte key पढ़ें, फिर RC4‑decrypt करें।

## कॉन्फ़िगरेशन निकासी वर्कफ़्लो (रक्षा करने वाले)

ऐसा extractor लिखें जो beacon logic की नकल करे:
1) PE के अंदर blob को खोजें (आमतौर पर .rdata)। एक व्यावहारिक तरीका यह है कि .rdata को संभावित [size|ciphertext|16‑byte key] लेआउट के लिए स्कैन करें और RC4 आजमाएँ।
2) पहले 4 bytes पढ़ें → size (uint32 LE).
3) अगले N=size bytes पढ़ें → ciphertext.
4) अंतिम 16 bytes पढ़ें → RC4 key.
5) ciphertext को RC4‑decrypt करें। फिर plain profile को इस तरह parse करें:
- u32/boolean scalars जैसा ऊपर बताया गया
- length‑prefixed strings (u32 length के बाद bytes; trailing NUL मौजूद हो सकता है)
- arrays: servers_count के बाद उतने [string, u32 port] जोड़े

Minimal Python proof‑of‑concept (standalone, no external deps) जो pre‑extracted blob के साथ काम करता है:
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
- ऑटोमेशन करते समय, .rdata को पढ़ने के लिए PE parser का उपयोग करें फिर sliding window लागू करें: प्रत्येक offset o के लिए, प्रयास करें size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt करें और जाँचें कि string फ़ील्ड UTF‑8 में decode होते हैं और lengths समझदारी के हैं।
- SMB/TCP profiles को भी वही length‑prefixed सम्मतियाँ फ़ॉलो करके पार्स करें।

## नेटवर्क फ़िंगरप्रिंटिंग और हंटिंग

HTTP
- आम: operator‑selected URIs पर POST (उदा., /uri.php, /endpoint/api)
- Beacon ID के लिए custom header parameter का उपयोग (उदा., X‑Beacon‑Id, X‑App‑Id)
- User‑agents जो Firefox 20 या समकालीन Chrome builds की नकल करते हैं
- Polling cadence जो sleep_delay/jitter_delay के माध्यम से दिखाई देती है

SMB/TCP
- intranet C2 के लिए SMB named‑pipe listeners जहाँ web egress सीमित होता है
- TCP beacons ट्रैफ़िक से पहले कुछ bytes prepend कर सकते हैं ताकि protocol start को अस्पष्ट किया जा सके

## Loader और persistence TTPs जिन्हें incidents में देखा गया

इन‑मेमोरी PowerShell लोडर्स
- Base64/XOR payloads डाउनलोड करते हैं (Invoke‑RestMethod / WebClient)
- unmanaged memory allocate करें, shellcode कॉपी करें, फिर VirtualProtect के माध्यम से protection को 0x40 (PAGE_EXECUTE_READWRITE) में बदलें
- .NET dynamic invocation के जरिए execute करें: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

इन‑मेमोरी execution और AMSI/ETW विचारों के लिए इन पन्नों को देखें:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

देखे गए Persistence mechanisms
- Startup folder shortcut (.lnk) ताकि logon पर loader को पुनः लॉन्च किया जा सके
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), अक्सर "Updater" जैसे benign‑sounding नामों के साथ जो loader.ps1 शुरू करते हैं
- DLL search‑order hijack: प्रभावित प्रक्रियाओं के लिए %APPDATA%\Microsoft\Windows\Templates के अंतर्गत msimg32.dll गिराकर

Technique deep‑dives और चेक्स:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell में RW→RX transitions: powershell.exe के अंदर PAGE_EXECUTE_READWRITE के लिए VirtualProtect कॉल्स
- Dynamic invocation पैटर्न (GetDelegateForFunctionPointer)
- user या common Startup फोल्डर्स के तहत Startup .lnk
- Suspicious Run keys (उदा., "Updater"), और update.ps1/loader.ps1 जैसे loader नाम
- %APPDATA%\Microsoft\Windows\Templates के अंतर्गत user‑writable DLL paths जिनमें msimg32.dll मौजूद हो

## OpSec फ़ील्ड्स पर नोट्स

- KillDate: वह timestamp जिसके बाद एजेंट self‑expire कर देता है
- WorkingTime: वे घंटे जब एजेंट को एक्टिव होना चाहिए ताकि यह business activity में घुलमिल जाए

इन फ़ील्ड्स का उपयोग clustering के लिए और देखी गई शांत अवधि की व्याख्या करने के लिए किया जा सकता है।

## YARA और static लीड्स

Unit 42 ने beacons (C/C++ and Go) और loader API‑hashing constants के लिए बेसिक YARA प्रकाशित किए हैं। इसे पूरक नियमों के साथ बढ़ाने पर विचार करें जो PE .rdata के अंत के पास [size|ciphertext|16‑byte‑key] लेआउट और default HTTP profile strings को ढूंढते हों।

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
