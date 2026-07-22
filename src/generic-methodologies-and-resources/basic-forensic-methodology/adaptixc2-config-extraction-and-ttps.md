# Uchimbaji wa Configuration ya AdaptixC2 na TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ni framework ya modular, open-source ya post-exploitation/C2 yenye beacons za Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) na support ya BOF. Ukurasa huu unaeleza:
- Jinsi configuration yake iliyopakiwa kwa RC4 inavyopachikwa na jinsi ya kuichambua kutoka kwenye beacons
- Viashiria vya mtandao/profile za HTTP/SMB/TCP listeners
- Loader na persistence TTPs za kawaida zinazoonekana katika mazingira halisi, pamoja na links za kurasa husika za Windows techniques

Releases za hivi karibuni za upstream pia zinakuja na DNS/DoH beacon listeners na familia tofauti ya Gopher agent/listener, hivyo miundombinu ya kisasa ya Adaptix inaweza kufichua zaidi ya surfaces za awali za HTTP/SMB/TCP hata kama sample maalum bado inatumia classic beacon agent.

## Beacon profiles na fields

AdaptixC2 inasaidia aina tatu kuu za beacon:
- BEACON_HTTP: web C2 yenye servers/ports za configurable, method, URI, headers, user-agent, na custom parameter name
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, kwa hiari ikiwa na marker iliyowekwa mwanzo ili kuficha mwanzo wa protocol

Hizi ndizo beacon layouts zilizowekwa hadharani katika analyses za awali za Adaptix na bado ndizo sehemu za kawaida za kuanzia kwa extraction upande wa sample. Hata hivyo, builds za sasa za upstream pia zinakuja na `BeaconDNS` na Gopher extenders upande wa server, hivyo usidhani kwamba kila deployment ya Adaptix inayofanya kazi inafichua miundombinu ya HTTP/SMB/TCP pekee.

Fields za kawaida za profile zinazoonekana katika HTTP beacon configs (baada ya decryption):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – hutumika kuchanganua response sizes
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

BeaconHTTP builds za hivi karibuni pia zina support ya rotation iliyochaguliwa na operator kati ya URIs, user-agents, Host headers, na servers nyingi, kwa selection ya sequential au random. Kwa mtazamo wa hunting, hii inamaanisha kuwa host moja iliyoambukizwa inaweza kusambaza callbacks kwenye callback paths na header combinations kadhaa bila kuacha classic RC4-packed beacon family.

Mfano wa default HTTP profile (kutoka kwenye beacon build):
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
Wasifu wa HTTP hasidi uliobainika (shambulio halisi):
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
## Ufungashaji wa usanidi uliosimbwa na njia ya upakiaji

Operator anapobofya Create kwenye builder, AdaptixC2 huingiza profile iliyosimbwa kama tail blob ndani ya beacon. Muundo ni:
- 4 bytes: ukubwa wa configuration (uint32, little-endian)
- N bytes: data ya configuration iliyosimbwa kwa RC4
- 16 bytes: RC4 key

Beacon loader hunakili key ya bytes 16 kutoka mwisho na ku-decrypt block ya N bytes kwa RC4 mahali pake:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Athari za kiutendaji:
- Muundo mzima mara nyingi hupatikana ndani ya PE .rdata section.
- Extraction ni deterministic: soma size, soma ciphertext ya size hiyo, soma key ya 16-byte iliyowekwa mara moja baada yake, kisha fanya RC4-decrypt.

## Workflow ya configuration extraction (defenders)

Andika extractor inayoiga beacon logic:
1) Tafuta blob ndani ya PE (kwa kawaida .rdata). Njia ya kiutendaji ni kuscan .rdata kutafuta layout inayowezekana ya [size|ciphertext|16-byte key] na kujaribu RC4.
2) Soma bytes 4 za kwanza → size (uint32 LE).
3) Soma bytes N zinazofuata, ambapo N=size → ciphertext.
4) Soma bytes 16 za mwisho → RC4 key.
5) Fanya RC4-decrypt ya ciphertext. Kisha parse plain profile kama ifuatavyo:
- u32/boolean scalars kama ilivyobainishwa hapo juu
- strings zenye length-prefix (u32 length ikifuatiwa na bytes; trailing NUL inaweza kuwepo)
- arrays: servers_count ikifuatiwa na idadi hiyo ya jozi za [string, u32 port]

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
- Wakati wa ku-automate, tumia PE parser kusoma .rdata kisha utumie sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; RC4-decrypt na uangalie ikiwa string fields zinadecode kama UTF-8 na lengths ni sahihi.
- Parse SMB/TCP profiles kwa kufuata length-prefixed conventions zilezile.

## Custom listener profiles: usi-hard-code classic HTTP schema pekee

Outer packing format (`u32 size | RC4 ciphertext | 16-byte key`) inaweza kutumika tena, hivyo actor-customized listeners zinaweza kutumia extraction workflow ileile huku zikibadilisha kabisa decrypted field layout.

Mfano mzuri wa hivi karibuni ni campaign ya Tropic Trooper ya Aprili 2026, ambapo Adaptix beacon iliyotolewa haikuwa na standard HTTP/TCP profile. Badala yake, decrypted blob iliweka GitHub transport parameters kama:
- `repo_owner`
- `repo_name`
- `api_host` (kwa mfano `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Practical parser strategy:
- Kwanza tambua outer RC4 blob kama kawaida kabisa.
- Baada ya decryption, branch kwa kutumia sentinel strings na field sanity badala ya kulazimisha HTTP parser mara moja.
- Sentinels nzuri ni pamoja na `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings, au server/port arrays zilizo valid wazi.
- Ikiwa HTTP parser itashindwa lakini plaintext ina coherent length-prefixed UTF-8 strings, hifadhi sample na ujaribu alternative schemas badala ya kuitupa kama false positive.

Katika campaign hiyo custom listener ilitumia GitHub issues kama C2 transport, na beacon ili-query `ipinfo.io` ili kujua external IP yake kwa sababu GitHub API haionyeshi moja kwa moja victim source address kwa operator.

## Network fingerprinting na hunting

HTTP
- Common: POST kwenda kwenye URIs zilizochaguliwa na operator (kwa mfano, /uri.php, /endpoint/api)
- Custom header parameter inayotumika kwa beacon ID (kwa mfano, X‑Beacon‑Id, X‑App‑Id)
- User-agents zinazoiga Firefox 20 au contemporary Chrome builds
- Polling cadence inayoonekana kupitia sleep_delay/jitter_delay
- Builds mpya zinaweza kuzungusha URIs, user-agents, Host headers, na servers katika callbacks mbalimbali, hivyo cluster kwa kutumia uncommon header names, response-size patterns, TLS reuse, na timing badala ya kudhani kuna single path/UA pair

SMB/TCP
- SMB named-pipe listeners kwa intranet C2 ambapo web egress imezuiwa
- TCP beacons zinaweza kuweka bytes chache kabla ya traffic ili kuficha protocol start

Current upstream teamserver defaults
- `profile.yaml` kwa sasa inasafirisha teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` na `server.rsa.key`, pamoja na extenders za HTTP, SMB, TCP, DNS, Beacon agent, na Gopher
- Kwenye unmatched routes, default error handler hurudisha `Server: AdaptixC2` na `Adaptix-Version: v1.2`
- Stock 404 body ina `AdaptixC2 404` na `You need to enter the correct connection details.`
- Internet-wide scans za mwaka 2026 ziligundua teamservers nyingi zilizo exposed kwenye `4321` na beacon listeners nyingi kwenye `43211`, kwa hiyo ports zote mbili ni useful seed pivots lakini hazipaswi kuchukuliwa kuwa exhaustive

DNS/DoH listener fingerprints
- Current BeaconDNS extender hujibu authoritatively (`AA=true`)
- Queries zisizolingana na beacon protocol shape — hasa names zilizo na labels chini ya 5 kabla ya configured domain — kwa kawaida hujibiwa kwa `TXT "OK"`
- Ikiwa configured base TTL itaachwa ikiwa zero, listener hutumia base ya sekunde 10 na kuongeza hadi sekunde 59 za jitter
- Hii hufanya short-label active probes kuwa useful wakati hakuna HTTP listener iliyo exposed

## Loader na persistence TTPs zilizoonekana katika incidents

In‑memory PowerShell loaders
- Hushusha Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Hutenga unmanaged memory, hunakili shellcode, na hubadilisha protection kuwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect
- Hu-execute kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- Chain ya Tropic Trooper ya mwaka 2026 ilitumia trojanized SumatraPDF executable (TOSHIS loader) iliyoredirect `_security_init_cookie` kwenda kwenye malicious code badala ya kupatch PE entry point
- Loader iliresolve APIs kupitia Adler-32 hashing, ikadownload decoy PDF, ikafetch second-stage shellcode, ika-decrypt kwa AES-128-CBC kupitia WinCrypt (`CryptDeriveKey` kutoka hardcoded seed), na ika-execute Adaptix beacon reflectively kwenye memory
- Persistence baadaye ilihamia kwenye scheduled tasks zenye majina yanayoonekana benign kama `\MSDNSvc` au `\MicrosoftUDN`, zilizoconfigurewa ku-re-launch agent takriban kila baada ya saa mbili

Angalia pages hizi kuhusu in‑memory execution na AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms zilizozingatiwa
- Startup folder shortcut (.lnk) ya ku-re-launch loader wakati wa logon
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na majina yanayosikika benign kama "Updater" ili ku-start loader.ps1
- DLL search-order hijack kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa processes zilizo susceptible

Technique deep-dives na checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell inayospawn RW→RX transitions: VirtualProtect kwenda PAGE_EXECUTE_READWRITE ndani ya powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s zenye `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, au `You need to enter the correct connection details.`
- DNS responses zenye `AA=true` na `TXT "OK"` kwa short queries chini ya suspect domains
- GitHub API traffic kwenda `/repos/<owner>/<repo>/issues` ikifuatiwa na lookups za `ipinfo.io` kutoka kwenye loader/beacon chain ileile
- Startup .lnk chini ya user au common Startup folders
- Suspicious Run keys (kwa mfano, "Updater"), na loader names kama update.ps1/loader.ps1
- Trojanized PE samples zinazo-redirect `_security_init_cookie` kwenda kwenye downloader code kabla ya kuonyesha decoy document
- User‑writable DLL paths chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll

## Notes kuhusu OpSec fields

- KillDate: timestamp ambayo baada yake agent hujiexpire
- WorkingTime: saa ambazo agent inapaswa kuwa active ili ilandane na business activity

Fields hizi zinaweza kutumika kwa clustering na kueleza quiet periods zilizoonekana.

## YARA na static leads

Unit 42 ilichapisha basic YARA kwa beacons (C/C++ na Go) pamoja na loader API-hashing constants. Fikiria kuongezea rules zinazoangalia [size|ciphertext|16‑byte‑key] layout karibu na mwisho wa PE .rdata, default HTTP profile strings, na server/listener markers mpya kama `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, na `ipinfo.io`.

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
