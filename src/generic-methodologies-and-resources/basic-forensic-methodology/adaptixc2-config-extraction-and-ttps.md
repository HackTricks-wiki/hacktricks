# Uondoaji wa Configuration ya AdaptixC2 na TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ni mfumo wa modular, open-source wa post-exploitation/C2 wenye Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) na support ya BOF.<sup>[[1]](#references)</sup> Ukurasa huu unaeleza:
- Jinsi configuration yake iliyopakiwa kwa RC4 inavyopachikwa na jinsi ya kuiondoa kutoka kwa beacons
- Viashiria vya network/profile kwa HTTP/SMB/TCP listeners
- Loader na persistence TTPs za kawaida zinazoonekana porini, pamoja na links za kurasa husika za Windows techniques

Recent upstream releases pia zinajumuisha DNS/DoH beacon listeners na familia tofauti ya Gopher agent/listener, hivyo Adaptix infrastructure ya kisasa inaweza kufichua zaidi ya HTTP/SMB/TCP surfaces za awali hata sample maalum inapotumia classic beacon agent.<sup>[[2]](#references)[[3]](#references)</sup>

## Beacon profiles na fields

AdaptixC2 inasaidia aina tatu kuu za beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 yenye servers/ports/SSL zinazoweza kusanidiwa, method, URI, headers, user-agent, na custom parameter name
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, kwa hiari ikiwa na prepended marker ya kuficha mwanzo wa protocol

Hizi ni layouts za beacon zilizowekwa wazi katika analyses za awali za Adaptix na bado ndizo sehemu za kuanzia zinazotumika zaidi kwa extraction upande wa sample.<sup>[[1]](#references)</sup> Hata hivyo, current upstream builds pia zinajumuisha `BeaconDNS` na Gopher extenders upande wa server, hivyo usidhani kila Adaptix deployment inayofanya kazi inafichua infrastructure ya HTTP/SMB/TCP pekee.<sup>[[2]](#references)</sup>

Typical profile fields zinazoonekana katika HTTP beacon configs (baada ya decryption):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – hutumika ku-parse response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP builds pia zinaunga mkono rotation inayochaguliwa na operator kati ya URIs nyingi, user-agents, Host headers, na servers, kwa selection ya sequential au random.<sup>[[2]](#references)</sup> Kwa mtazamo wa hunting, hii inamaanisha host moja iliyoambukizwa inaweza kuwasiliana na callback paths na header combinations kadhaa bila kuacha classic RC4-packed beacon family.

Example default HTTP profile (kutoka kwa beacon build):<sup>[[1]](#references)</sup>
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
Wasifu wa HTTP hasidi uliobainika (shambulio halisi):<sup>[[1]](#references)</sup>
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
## Ufungaji wa configuration iliyosimbwa na load path

Operator anapobofya Create kwenye builder, AdaptixC2 hu-embed profile iliyosimbwa kama tail blob kwenye beacon. Muundo ni:<sup>[[1]](#references)</sup>
- Baiti 4: ukubwa wa configuration (uint32, little‑endian)
- Baiti N: data ya configuration iliyosimbwa kwa RC4
- Baiti 16: RC4 key

Beacon loader hunakili key ya baiti 16 kutoka mwisho kisha hu-decrypt kwa RC4 block ya baiti N in place:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Athari za kiutendaji:<sup>[[1]](#references)</sup>
- Muundo mzima mara nyingi huwa ndani ya sehemu ya PE .rdata.
- Extraction ni ya kidhahiri: soma size, soma ciphertext yenye ukubwa huo, soma key ya baiti 16 iliyowekwa mara moja baada yake, kisha tumia RC4 kufanya decryption.

## Mtiririko wa extraction ya Configuration (watetezi)

Andika extractor inayoiga mantiki ya beacon:<sup>[[1]](#references)</sup>
1) Tafuta blob ndani ya PE (mara nyingi .rdata). Njia ya kivitendo ni kuscan .rdata kutafuta mpangilio unaowezekana wa [size|ciphertext|16‑byte key] na kujaribu RC4.
2) Soma baiti 4 za kwanza → size (uint32 LE).
3) Soma baiti N zinazofuata, ambapo N=size → ciphertext.
4) Soma baiti 16 za mwisho → RC4 key.
5) Fanya RC4-decrypt ya ciphertext. Kisha parse plain profile kama:
- scalars za u32/boolean kama zilivyoonyeshwa hapo juu
- strings zenye length-prefix (u32 length ikifuatiwa na bytes; trailing NUL inaweza kuwepo)
- arrays: servers_count ikifuatiwa na jozi hizo za [string, u32 port]

Minimal Python proof-of-concept (standalone, bila external deps) inayofanya kazi na blob iliyotolewa awali:
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
- Unapofanya automation, tumia PE parser kusoma .rdata kisha utumie sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; fanya RC4-decrypt na uhakikishe kuwa string fields zina-decode kama UTF-8 na lengths ni zenye mantiki.
- Parse SMB/TCP profiles kwa kufuata length-prefixed conventions zilezile.

## Custom listener profiles: usiweke hard-code kwenye classic HTTP schema pekee

Outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) inaweza kutumika tena, kwa hiyo listeners zilizoboreshwa na actor zinaweza kudumisha extraction workflow ileile huku zikibadilisha kabisa decrypted field layout.

Mfano mzuri wa hivi karibuni ni kampeni ya Tropic Trooper ya Aprili 2026, ambapo Adaptix beacon iliyotolewa haikuwa na standard HTTP/TCP profile. Badala yake, decrypted blob ilihifadhi transport parameters za GitHub kama vile:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (kwa mfano `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- Kwanza tambua outer RC4 blob kama kawaida.
- Baada ya decryption, chagua branch kulingana na sentinel strings na field sanity badala ya kulazimisha HTTP parser mara moja.
- Sentinels nzuri ni pamoja na `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings za mtindo wa named-pipe, au server/port arrays zinazoonekana kuwa halali.
- Ikiwa HTTP parser itashindwa lakini plaintext ina coherent length-prefixed UTF-8 strings, hifadhi sample hiyo na ujaribu alternative schemas badala ya kuitupa kama false positive.

Katika kampeni hiyo, custom listener ilitumia GitHub issues kama C2 transport, na beacon ili-query `ipinfo.io` ili kujua external IP yake kwa sababu GitHub API haimwonyeshi operator moja kwa moja source address ya victim.<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP<sup>[[1]](#references)</sup>
- Kawaida: POST kwenda kwenye URIs zilizochaguliwa na operator (kwa mfano, /uri.php, /endpoint/api)
- Custom header parameter inayotumika kwa beacon ID (kwa mfano, X‑Beacon‑Id, X‑App‑Id)
- User-agents zinazoiga Firefox 20 au contemporary Chrome builds
- Polling cadence inayoonekana kupitia sleep_delay/jitter_delay
- Builds mpya zaidi zinaweza kuzungusha URIs, user-agents, Host headers, na servers kwenye callbacks mbalimbali, kwa hiyo cluster kulingana na header names zisizo za kawaida, response-size patterns, TLS reuse, na timing badala ya kudhani kuna single path/UA pair<sup>[[2]](#references)</sup>

SMB/TCP<sup>[[1]](#references)</sup>
- SMB named-pipe listeners kwa intranet C2 mahali web egress imewekewa vikwazo
- TCP beacons zinaweza kuongeza bytes chache kabla ya traffic ili kuficha mwanzo wa protocol

Current upstream teamserver defaults
- `profile.yaml` kwa sasa husafirisha teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` na `server.rsa.key`, pamoja na extenders za HTTP, SMB, TCP, DNS, Beacon agent, na Gopher<sup>[[2]](#references)</sup>
- Kwenye routes zisizolingana, default error handler hurejesha `Server: AdaptixC2` na `Adaptix-Version: v1.2`<sup>[[4]](#references)</sup>
- Default 404 body ina `AdaptixC2 404` na `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- Scans za kiwango cha Internet mwaka 2026 ziligundua teamservers nyingi zilizo wazi kwenye `4321` na beacon listeners nyingi kwenye `43211`, kwa hiyo ports zote mbili ni seed pivots muhimu lakini hazipaswi kuchukuliwa kuwa kamili<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints<sup>[[4]](#references)</sup>
- BeaconDNS extender ya sasa hujibu authoritatively (`AA=true`)
- Queries zisizolingana na beacon protocol shape — hasa names zenye labels chini ya 5 kabla ya configured domain — kwa kawaida hujibiwa kwa `TXT "OK"`
- Ikiwa configured base TTL itaachwa ikiwa sifuri, listener hutumia base ya sekunde 10 na kuongeza hadi sekunde 59 za jitter
- Hii hufanya short-label active probes kuwa muhimu wakati hakuna HTTP listener iliyo wazi

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders<sup>[[1]](#references)</sup>
- Hupakua Base64/XOR payloads (Invoke‑RestMethod / WebClient)<sup>[[9]](#references)</sup>
- Hutenga unmanaged memory, kunakili shellcode, na kubadilisha protection kuwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect<sup>[[7]](#references)</sup>
- Hu-execute kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders<sup>[[5]](#references)</sup>
- Chain ya Tropic Trooper ya 2026 ilitumia trojanized SumatraPDF executable (TOSHIS loader) iliyogeuza `_security_init_cookie` kuelekea malicious code badala ya kupatch PE entry point
- Loader iliresolve APIs kwa Adler-32 hashing, ikapakua decoy PDF, ikachukua second-stage shellcode, ika-decrypt kwa AES-128-CBC kupitia WinCrypt (`CryptDeriveKey` kutoka hardcoded seed), na ika-execute Adaptix beacon reflectively kwenye memory
- Persistence baadaye ilihamishwa kwenye scheduled tasks zenye names zinazoonekana kuwa halali kama `\MSDNSvc` au `\MicrosoftUDN`, zilizosanidiwa kuanzisha tena agent takribani kila baada ya saa mbili

Angalia kurasa hizi kwa masuala ya in‑memory execution na AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms observed<sup>[[1]](#references)</sup>
- Startup folder shortcut (.lnk) ya kuanzisha tena loader wakati wa logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na names zinazoonekana kuwa halali kama "Updater" ili kuanzisha loader.ps1<sup>[[10]](#references)</sup>
- DLL search‑order hijack kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa processes zinazoweza kuathirika

Technique deep‑dives and checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell inayozalisha RW→RX transitions: VirtualProtect kwenda PAGE_EXECUTE_READWRITE ndani ya powershell.exe<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- HTTPS 404s zisizolingana zenye `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, au `You need to enter the correct connection details.`<sup>[[4]](#references)</sup>
- DNS responses zenye `AA=true` na `TXT "OK"` kwa short queries chini ya suspect domains<sup>[[4]](#references)</sup>
- GitHub API traffic kwenda `/repos/<owner>/<repo>/issues` ikifuatiwa na lookups za `ipinfo.io` kutoka kwenye loader/beacon chain ileile<sup>[[5]](#references)</sup>
- Startup .lnk chini ya user au common Startup folders<sup>[[1]](#references)</sup>
- Suspicious Run keys (kwa mfano, "Updater"), na loader names kama update.ps1/loader.ps1<sup>[[1]](#references)</sup>
- Trojanized PE samples zinazoelekeza `_security_init_cookie` kwenye downloader code kabla ya kuonyesha decoy document<sup>[[5]](#references)</sup>
- User‑writable DLL paths chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: timestamp baada yake agent hujimaliza yenyewe<sup>[[1]](#references)</sup>
- WorkingTime: saa ambazo agent inapaswa kuwa active ili ichanganyike na business activity<sup>[[1]](#references)</sup>

Fields hizi zinaweza kutumika kwa clustering na kueleza vipindi vya utulivu vilivyoonekana.

## YARA and static leads

Unit 42 ilichapisha basic YARA kwa beacons (C/C++ na Go) na loader API-hashing constants.<sup>[[1]](#references)</sup> Fikiria kuongezea rules zinazoangalia layout ya [size|ciphertext|16‑byte‑key] karibu na mwisho wa PE .rdata, default HTTP profile strings, na newer server/listener markers kama `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, na `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

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

{{#include ../../banners/hacktricks-training.md}}
