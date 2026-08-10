# Uondoaji wa Configuration ya AdaptixC2 na TTPs

AdaptixC2 ni framework ya modular, open-source ya post-exploitation/C2 yenye beacons za Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) na support ya BOF.<sup>[[1]](#references)</sup> Ukurasa huu unaeleza:
- Jinsi configuration yake iliyopakiwa kwa RC4 inavyopachikwa na jinsi ya kuiondoa kutoka kwenye beacons
- Viashiria vya mtandao/profile kwa HTTP/SMB/TCP listeners
- Loader na persistence TTPs za kawaida zinazoonekana porini, pamoja na links za kurasa husika za Windows techniques

Releases za hivi karibuni za upstream pia zinajumuisha DNS/DoH beacon listeners na family tofauti ya Gopher agent/listener, kwa hiyo Adaptix infrastructure ya kisasa inaweza kufichua zaidi ya surfaces za awali za HTTP/SMB/TCP, hata wakati sample maalum bado inatumia classic beacon agent.<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2 ina support ya aina tatu kuu za beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 yenye servers/ports/SSL, method, URI, headers, user-agent, na custom parameter name zinazoweza kusanidiwa
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, kwa hiari ikiwa na marker iliyowekwa mwanzoni ili kuficha mwanzo wa protocol

Hizi ndizo beacon layouts zilizoandikwa hadharani katika analyses za awali za Adaptix, na bado ndizo sehemu ya kuanzia inayotumika zaidi kwa sample-side extraction.<sup>[[1]](#references)</sup> Hata hivyo, builds za sasa za upstream pia zinajumuisha `BeaconDNS` na Gopher extenders upande wa server, kwa hiyo usidhani kwamba kila Adaptix deployment inayofanya kazi inafichua infrastructure ya HTTP/SMB/TCP pekee.<sup>[[2]](#references)</sup>

Typical profile fields zinazoonekana katika HTTP beacon configs (baada ya decryption):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – hutumika ku-parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Builds za hivi karibuni za BeaconHTTP pia zina support ya operator kuchagua rotation kati ya URIs, user-agents, Host headers, na servers nyingi, kwa selection ya sequential au random.<sup>[[2]](#references)</sup> Kwa mtazamo wa hunting, hii inamaanisha kwamba host moja iliyoambukizwa inaweza kuwasiliana na callback paths na header combinations kadhaa bila kuacha classic RC4-packed beacon family.

Mfano wa default HTTP profile (kutoka kwenye beacon build):<sup>[[1]](#references)</sup>
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
Profaili hasidi ya HTTP iliyozingatiwa (shambulizi halisi):<sup>[[1]](#references)</sup>
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
## Ufungashaji wa configuration iliyosimbwa na njia ya load

Operator anapobofya Create kwenye builder, AdaptixC2 huingiza profile iliyosimbwa kama tail blob kwenye beacon. Muundo ni:<sup>[[1]](#references)</sup>
- baiti 4: ukubwa wa configuration (uint32, little-endian)
- baiti N: data ya configuration iliyosimbwa kwa RC4
- baiti 16: RC4 key

Beacon loader hukopi key ya baiti 16 kutoka mwisho na huondoa usimbaji wa RC4 wa block ya baiti N in place:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Athari za kiutendaji:<sup>[[1]](#references)</sup>
- Muundo mzima mara nyingi huwa ndani ya sehemu ya PE .rdata.
- Extraction ni ya kimaamuzi: soma size, soma ciphertext yenye size hiyo, soma key ya baiti 16 iliyowekwa mara moja baada yake, kisha tumia RC4 kufanya decryption.

## Mtiririko wa extraction ya configuration (defenders)

Andika extractor inayoiga mantiki ya beacon:<sup>[[1]](#references)</sup>
1) Tafuta blob ndani ya PE (kwa kawaida .rdata). Njia ya kiutendaji ni kuchanganua .rdata kwa layout inayowezekana ya [size|ciphertext|16‑byte key] na kujaribu RC4.
2) Soma baiti 4 za kwanza → size (uint32 LE).
3) Soma baiti N zinazofuata, ambapo N=size → ciphertext.
4) Soma baiti 16 za mwisho → RC4 key.
5) Fanya RC4-decrypt ya ciphertext. Kisha parse plain profile kama:
- scalars za u32/boolean kama ilivyoelezwa hapo juu
- strings zenye length-prefix (u32 length ikifuatiwa na bytes; trailing NUL inaweza kuwepo)
- arrays: servers_count ikifuatiwa na idadi hiyo ya jozi za [string, u32 port]

Minimal Python proof-of-concept (standalone, no external deps) inayofanya kazi na blob iliyotolewa awali:
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
- Unapofanya automation, tumia PE parser kusoma .rdata kisha tumia sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4-decrypt kisha hakikisha kwamba string fields zinadecode kama UTF-8 na lengths ziko sahihi.
- Parse SMB/TCP profiles kwa kufuata conventions zilezile za length-prefixed.

## Custom listener profiles: usiweke hard-code schema ya kawaida ya HTTP pekee

Outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) inaweza kutumika tena, hivyo listeners zilizobinafsishwa na actor zinaweza kuendelea kutumia workflow ileile ya extraction huku zikibadilisha kabisa mpangilio wa fields zilizodecryptiwa.

Mfano mzuri wa hivi karibuni ni kampeni ya Tropic Trooper ya Machi 2026, ambapo Adaptix beacon iliyotolewa haikuwa na standard HTTP/TCP profile. Badala yake, blob iliyodecryptiwa ilihifadhi transport parameters za GitHub kama vile:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (kwa mfano `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- Kwanza tambua outer RC4 blob kama kawaida.
- Baada ya decryption, chagua schema kulingana na sentinel strings na field sanity badala ya kulazimisha HTTP parser mara moja.
- Sentinels nzuri ni pamoja na `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings za mtindo wa named pipe, au arrays halali za server/port.
- Ikiwa HTTP parser itashindwa lakini plaintext ina coherent length-prefixed UTF-8 strings, hifadhi sample na ujaribu schemas mbadala badala ya kuiondoa kama false positive.

Katika kampeni hiyo, custom listener ilitumia GitHub issues kama C2 transport, na beacon iliuliza `ipinfo.io` ili kujua external IP yake kwa sababu GitHub API haimwonyeshi operator moja kwa moja source address ya victim.<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP:<sup>[[1]](#references)</sup>
- Kawaida: POST kwenda kwa URIs zilizochaguliwa na operator (kwa mfano, /uri.php, /endpoint/api)
- Custom header parameter inayotumika kwa beacon ID (kwa mfano, X‑Beacon‑Id, X‑App‑Id)
- User-agents zinazoiga Firefox 20 au contemporary Chrome builds
- Polling cadence inayoonekana kupitia sleep_delay/jitter_delay
- Builds mpya zinaweza kubadilisha URIs, user-agents, Host headers, na servers katika callbacks mbalimbali; kwa hiyo, fanya clustering kwa uncommon header names, response-size patterns, TLS reuse, na timing badala ya kudhani kuna pair moja ya path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners kwa intranet C2 ambapo web egress imezuiwa
- TCP beacons zinaweza kuongeza bytes chache kabla ya traffic ili kuficha mwanzo wa protocol

Current upstream teamserver defaults
- `profile.yaml` kwa sasa husafirisha teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` na `server.rsa.key`, pamoja na extenders za HTTP, SMB, TCP, DNS, Beacon agent, na Gopher.<sup>[[2]](#references)</sup>
- Kwenye routes zisizolingana, default error handler hurudisha `Server: AdaptixC2` na `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Stock 404 body ina `AdaptixC2 404` na `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide scans za 2026 ziligundua teamservers nyingi zilizo exposed kwenye `4321` na beacon listeners nyingi kwenye `43211`, hivyo ports zote mbili ni seed pivots muhimu lakini hazipaswi kuchukuliwa kuwa exhaustive.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- BeaconDNS extender ya sasa hujibu authoritatively (`AA=true`)
- Queries zisizolingana na beacon protocol shape — hasa majina yenye labels chini ya 5 kabla ya configured domain — kwa kawaida hujibiwa kwa `TXT "OK"`
- Ikiwa configured base TTL itaachwa ikiwa sifuri, listener hutumia base ya sekunde 10 na kuongeza hadi sekunde 59 za jitter
- Hii hufanya short-label active probes kuwa muhimu wakati hakuna HTTP listener iliyo exposed

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Hupakua Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Hutenga unmanaged memory, hunakili shellcode, na hubadilisha protection kuwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect.<sup>[[7]](#references)</sup>
- Hu-execute kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Chain ya Tropic Trooper ya 2026 ilitumia trojanized SumatraPDF executable (TOSHIS loader) iliyogeuza `_security_init_cookie` kuelekea malicious code badala ya kupatch PE entry point
- Loader iliresolve APIs kupitia Adler-32 hashing, ikapakua decoy PDF, ikafetch second-stage shellcode, ikaidecrypt kwa AES-128-CBC kupitia WinCrypt (`CryptDeriveKey` kutoka hardcoded seed), na ikaexecute Adaptix beacon reflectively kwenye memory
- Persistence baadaye ilihamishwa kwenye scheduled tasks zenye majina yanayoonekana benign kama `\MSDNSvc` au `\MicrosoftUDN`, zilizosanidiwa kuanzisha tena agent takriban kila baada ya saa mbili

Angalia kurasa hizi kuhusu in‑memory execution na masuala ya AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed:<sup>[[1]](#references)</sup>
- Startup folder shortcut (.lnk) ya kuanzisha tena loader wakati wa logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na majina yanayosikika benign kama "Updater" ili kuanzisha loader.ps1.<sup>[[10]](#references)</sup>
- DLL search‑order hijack kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa processes zinazoweza kuathirika

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell inayozalisha RW→RX transitions: VirtualProtect hadi PAGE_EXECUTE_READWRITE ndani ya powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- HTTPS 404s zisizolingana zenye `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, au `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses zenye `AA=true` na `TXT "OK"` kwa short queries chini ya suspect domains.<sup>[[4]](#references)</sup>
- GitHub API traffic kwenda `/repos/<owner>/<repo>/issues` ikifuatiwa na lookups za `ipinfo.io` kutoka kwenye loader/beacon chain hiyo hiyo.<sup>[[5]](#references)</sup>
- Startup .lnk chini ya user au common Startup folders.<sup>[[1]](#references)</sup>
- Suspicious Run keys (kwa mfano, "Updater"), na loader names kama update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples zinazogeuza `_security_init_cookie` kuelekea downloader code kabla ya kuonyesha decoy document.<sup>[[5]](#references)</sup>
- User‑writable DLL paths chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll.<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: timestamp baada yake agent hujimaliza.<sup>[[1]](#references)</sup>
- WorkingTime: saa ambazo agent inapaswa kuwa active ili ichanganyike na shughuli za biashara.<sup>[[1]](#references)</sup>

Fields hizi zinaweza kutumika kwa clustering na kueleza vipindi vya utulivu vilivyoonekana.

## YARA and static leads

Unit 42 ilichapisha basic YARA kwa beacons (C/C++ na Go) na loader API‑hashing constants.<sup>[[1]](#references)</sup> Fikiria kuzikamilisha kwa rules zinazotafuta layout ya [size|ciphertext|16‑byte‑key] karibu na mwisho wa PE .rdata, default HTTP profile strings, na server/listener markers mpya kama `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, na `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Framework Mpya ya Open-Source Iliyotumiwa katika Mashambulizi ya Real-World (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Nyaraka za Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Kufanya Fingerprinting ya Open-Source C2 Framework kwa Kiwango Kikubwa (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Abadilisha Mwelekeo kwenda AdaptixC2 na Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
