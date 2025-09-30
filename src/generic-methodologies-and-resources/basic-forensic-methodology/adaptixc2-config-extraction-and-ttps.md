# Uchukuaji wa Usanidi wa AdaptixC2 na TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ni framework modular, open‑source ya post‑exploitation/C2 yenye Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) na BOF support. Ukurasa huu unaandika kuhusu:
- Jinsi usanidi wake uliopakiwa kwa RC4 umeingizwa na jinsi ya kuuchota kutoka kwa beacons
- Viashiria vya mtandao/profaili kwa listeners za HTTP/SMB/TCP
- TTPs za kawaida za loader na persistence zilizobainika katika mazingira ya kweli, pamoja na viungo kwa kurasa za mbinu za Windows zinazohusiana

## Beacon profiles and fields

AdaptixC2 inaunga mkono aina tatu kuu za beacon:
- BEACON_HTTP: web C2 yenye servers/ports/SSL zinazoweza kusanidiwa, method, URI, headers, user‑agent, na custom parameter name
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: direct sockets, hiari zikiwa na marker iliyowekwa mwanzoni ili kuficha mwanzo wa protocol

Mashamba ya profaili ya kawaida yaliyobainika katika config za beacon za HTTP (baada ya decryption):
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
Profaili ya HTTP yenye nia mbaya iliyogunduliwa (shambulio la kweli):
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
## Ufungashaji wa usanidi uliosimbwa na njia ya kupakia

Wakati operator anabonyeza Create katika builder, AdaptixC2 inaweka profaili iliyosimbwa kama tail blob ndani ya beacon. Muundo ni:
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4‑encrypted configuration data
- 16 bytes: RC4 key

Beacon loader inakopa 16‑byte key kutoka mwisho na RC4‑decrypts N‑byte block mahali pake:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Matokeo ya vitendo:
- Muundo mzima mara nyingi upo ndani ya sehemu ya PE .rdata.
- Uchimbaji ni isiyobadilika: soma size, soma ciphertext ya ukubwa huo, soma 16‑byte key iliyowekwa mara moja baada yake, kisha RC4‑decrypt.

## Mtiririko wa uchimbaji wa configuration (walinzi)

Andika extractor inayofanana na mantiki ya beacon:
1) Pata blob ndani ya PE (kawaida .rdata). Njia ya vitendo ni kuskena .rdata kutafuta muundo unaowezekana wa [size|ciphertext|16‑byte key] na kujaribu RC4.
2) Soma 4 bytes za kwanza → size (uint32 LE).
3) Soma bytes zifuatazo N=size → ciphertext.
4) Soma 16 bytes za mwisho → RC4 key.
5) RC4‑decrypt the ciphertext. Kisha changanua profaili wazi kama:
- u32/boolean scalars kama ilivyoelezwa hapo juu
- length‑prefixed strings (u32 length followed by bytes; trailing NUL can be present)
- arrays: servers_count ikifuatiwa na idadi hiyo ya jozi [string, u32 port]

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
Vidokezo:
- Wakati unapo-automate, tumia PE parser kusoma .rdata kisha tumia sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4‑decrypt na angalia kwamba string fields zina-decode kama UTF‑8 na lengths ni za busara.
- Parsa profile za SMB/TCP kwa kufuata conventions za length‑prefixed sawa.

## Utambuzi wa sifa za mtandao na uwindaji

HTTP
- Mara nyingi: POST kwa URIs zilizochaguliwa na operator (mf., /uri.php, /endpoint/api)
- Kigezo cha header maalum kinachotumika kwa beacon ID (mf., X‑Beacon‑Id, X‑App‑Id)
- User‑agents zinajaribu kuiga Firefox 20 au matoleo ya Chrome ya sasa
- Mdundo wa polling unaoonekana kupitia sleep_delay/jitter_delay

SMB/TCP
- SMB named‑pipe listeners kwa C2 ya intranet pale ambapo egress ya web imezuiwa
- TCP beacons yanaweza kuweka bytes chache kabla ya trafiki ili kuficha kuanza kwa protocol

## Loader and persistence TTPs zilizoshuhudiwa katika matukio

Loaders za PowerShell ambazo zinafanya kazi ndani ya kumbukumbu
- Pakua payloads za Base64/XOR (Invoke‑RestMethod / WebClient)
- Tenga unmanaged memory, nakili shellcode, badilisha ulinzi kwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect
- Endesha kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Angalia kurasa hizi kuhusu utekelezaji ndani ya kumbukumbu na masuala ya AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mbinu za persistence zilizoshuhudiwa
- Shortcut ya Startup folder (.lnk) ili kuzindua tena loader wakati wa logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na majina yanayosikika kuwa yasiyotishia kama "Updater" kuanzisha loader.ps1
- DLL search‑order hijack kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa processes zinazoweza kuathiriwa

Uchunguzi wa kina wa mbinu na ukaguzi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Mapendekezo ya uwindaji
- PowerShell kuanzisha mabadiliko ya RW→RX: VirtualProtect kwa PAGE_EXECUTE_READWRITE ndani ya powershell.exe
- Mifumo ya dynamic invocation (GetDelegateForFunctionPointer)
- Startup .lnk chini ya folda za Startup za mtumiaji au za kawaida
- Run keys za kushangaza (mf., "Updater"), na majina ya loader kama update.ps1/loader.ps1
- Path za DLL zinazoweza kuandikwa na mtumiaji chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll

## Vidokezo kuhusu sehemu za OpSec

- KillDate: timestamp baada ya hapo agent inajimaliza
- WorkingTime: saa ambazo agent inapaswa kuwa hai ili kuendana na shughuli za kibiashara

Sehemu hizi zinaweza kutumika kwa clustering na kuelezea vipindi vya ukimya vilivyobainishwa.

## YARA na vidokezo vya static

Unit 42 ilichapisha basic YARA kwa beacons (C/C++ and Go) na loader API‑hashing constants. Fikiria kuongeza rules zinatafuta muundo wa [size|ciphertext|16‑byte‑key] karibu na mwisho wa PE .rdata na default HTTP profile strings.

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
