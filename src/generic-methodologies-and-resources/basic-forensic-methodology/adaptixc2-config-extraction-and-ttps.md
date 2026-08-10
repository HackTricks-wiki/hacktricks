# AdaptixC2-konfigurasie-ekstraksie en TTP's

AdaptixC2 is ’n modulêre, oopbron post-exploitation/C2-framework met Windows x86/x64-beacons (EXE/DLL/service EXE/raw shellcode) en BOF-ondersteuning.<sup>[[1]](#references)</sup> Hierdie bladsy dokumenteer:
- Hoe sy RC4-gepakte konfigurasie ingebed word en hoe om dit uit beacons te onttrek
- Netwerk-/profielaanwysers vir HTTP/SMB/TCP-listeners
- Algemene loader- en persistence-TTP's wat in die wild waargeneem is, met skakels na relevante Windows-tegniekbladsye

Onlangse upstream-vrystellings sluit ook DNS/DoH-beacon-listeners en die afsonderlike Gopher-agent/listener-familie in, dus kan moderne Adaptix-infrastruktuur meer as die oorspronklike HTTP/SMB/TCP-oppervlakke blootstel, selfs wanneer ’n spesifieke sample steeds die klassieke beacon-agent gebruik.<sup>[[2]](#references)</sup>

## Beacon-profiele en velde

AdaptixC2 ondersteun drie primêre beacon-tipes:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 met konfigureerbare servers/poorte/SSL, metode, URI, headers, user-agent en ’n pasgemaakte parameternaam
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direkte sockets, opsioneel met ’n voorafgevoegde marker om die protokolbegin te obfuskeer

Hierdie is die beacon-uitlegte wat in vroeë Adaptix-analises publiek gedokumenteer is, en hulle is steeds die algemeenste beginpunt vir sample-side-ekstraksie.<sup>[[1]](#references)</sup> Huidige upstream-builds bevat egter ook `BeaconDNS`- en Gopher-extenders aan die server-kant, dus moenie aanvaar dat elke aktiewe Adaptix-deployment slegs HTTP/SMB/TCP-infrastruktuur blootstel nie.<sup>[[2]](#references)</sup>

Tipiese profielvelde wat in HTTP-beacon-konfigurasies waargeneem word (ná dekripsie):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – gebruik om response-groottes te parse
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Onlangse BeaconHTTP-builds ondersteun ook operator-geselekteerde rotasie oor verskeie URI's, user-agents, Host-headers en servers, met sekwensiële of ewekansige seleksie.<sup>[[2]](#references)</sup> Vanuit ’n hunting-perspektief beteken dit dat ’n enkele geïnfekteerde host oor verskeie callback-paaie en header-kombinasies kan uitwaaier sonder om die klassieke RC4-gepakte beacon-familie agter te laat.

Voorbeeld van ’n verstek-HTTP-profiel (uit ’n beacon-build):<sup>[[1]](#references)</sup>
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
Waargenome kwaadwillige HTTP-profiel (werklike aanval):<sup>[[1]](#references)</sup>
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
## Verpakking van geënkripteerde konfigurasie en laaipad

Wanneer die operator in die builder op Create klik, plaas AdaptixC2 die geënkripteerde profiel as ’n tail blob in die beacon. Die formaat is:<sup>[[1]](#references)</sup>
- 4 grepe: konfigurasiegrootte (uint32, little-endian)
- N grepe: RC4-geënkripteerde konfigurasiedata
- 16 grepe: RC4-sleutel

Die beacon loader kopieer die 16-grepe-sleutel vanaf die einde en RC4-dekripteer die N-grepe-blok in plek:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktiese implikasies:<sup>[[1]](#references)</sup>
- Die hele struktuur is dikwels binne die PE .rdata-afdeling.
- Extraction is deterministies: lees size, lees die ciphertext van daardie grootte, lees die 16-byte key wat onmiddellik daarna geplaas is, en voer dan RC4-dekripsie uit.

## Configuration extraction workflow (verdedigers)

Skryf ’n extractor wat die beacon-logika naboots:<sup>[[1]](#references)</sup>
1) Locate the blob inside the PE (algemeen .rdata). ’n Pragmatiese benadering is om .rdata te skandeer vir ’n aanneemlike [size|ciphertext|16-byte key]-uitleg en RC4 te probeer.
2) Read first 4 bytes → size (uint32 LE).
3) Read next N=size bytes → ciphertext.
4) Read final 16 bytes → RC4 key.
5) RC4-decrypt the ciphertext. Parseer dan die plain profile as:
- u32/boolean-scalars soos hierbo aangedui
- length-prefixed strings (u32-lengte gevolg deur bytes; ’n trailing NUL kan teenwoordig wees)
- arrays: servers_count gevolg deur daardie aantal [string, u32 port]-pare

Minimal Python proof-of-concept (standalone, no external deps) that works with a pre-extracted blob:
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
Wenke:
- Wanneer jy outomatiseer, gebruik ’n PE parser om .rdata te lees en pas dan ’n sliding window toe: probeer vir elke offset o die grootte = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidaat-sleutel = volgende 16 grepe; RC4-dekripteer en kontroleer dat string-velde as UTF-8 dekodeer en dat lengtes sinvol is.
- Parse SMB/TCP profiles deur dieselfde length-prefixed konvensies te volg.

## Custom listener profiles: moenie slegs die klassieke HTTP-skema hardkodeer nie

Die buitenste packing format (`u32 size | RC4 ciphertext | 16-byte key`) is herbruikbaar, sodat actor-aangepaste listeners dieselfde extraction workflow kan behou terwyl die decrypted field layout heeltemal verander.

’n Goeie onlangse voorbeeld is die Tropic Trooper campaign van Maart 2026, waar die onttrekte Adaptix beacon nie ’n standaard HTTP/TCP profile bevat het nie. In plaas daarvan het die decrypted blob GitHub transport parameters soos die volgende gestoor:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (byvoorbeeld `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktiese parser-strategie:
- Bespeur eers die buitenste RC4 blob presies soos gewoonlik.
- Na dekripsie, vertak op grond van sentinel strings en field sanity eerder as om onmiddellik die HTTP parser af te dwing.
- Goeie sentinels sluit in `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings, of klaarblyklik geldige server/port arrays.
- As die HTTP parser misluk maar die plaintext samehangende length-prefixed UTF-8 strings bevat, behou die sample en probeer alternatiewe schemas eerder as om dit as ’n false positive weg te gooi.

In daardie campaign het die custom listener GitHub issues as die C2 transport gebruik, en die beacon het `ipinfo.io` bevraagteken om sy eksterne IP te bepaal, omdat die GitHub API nie die victim se source address direk aan die operator openbaar nie.<sup>[[5]](#references)</sup>

## Network fingerprinting en hunting

HTTP:<sup>[[1]](#references)</sup>
- Algemeen: POST na operator-selected URIs (bv. /uri.php, /endpoint/api)
- Custom header parameter wat vir beacon ID gebruik word (bv. X-Beacon-Id, X-App-Id)
- User-agents wat Firefox 20 of huidige Chrome builds naboots
- Polling cadence wat via sleep_delay/jitter_delay sigbaar is
- Nuwer builds kan URIs, user-agents, Host headers en servers tussen callbacks roteer; cluster dus op ongewone header names, response-size patterns, TLS reuse en timing eerder as om ’n enkele path/UA-paar te aanvaar.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners vir intranet C2 waar web egress beperk word
- TCP beacons kan ’n paar grepe voor die traffic plaas om die protokolbegin te verdoesel

Huidige upstream teamserver defaults
- `profile.yaml` bevat tans teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` en `server.rsa.key`, en extenders vir HTTP, SMB, TCP, DNS, Beacon agent en Gopher.<sup>[[2]](#references)</sup>
- Op unmatched routes gee die default error handler `Server: AdaptixC2` en `Adaptix-Version: v1.2` terug.<sup>[[4]](#references)</sup>
- Die stock 404 body bevat `AdaptixC2 404` en `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide scans in 2026 het baie blootgestelde teamservers op `4321` en baie beacon listeners op `43211` gevind; albei poorte is dus nuttige seed pivots, maar moet nie as volledig beskou word nie.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Die huidige BeaconDNS extender antwoord authoritatively (`AA=true`)
- Queries wat nie by die beacon protocol shape pas nie — veral name met minder as 5 labels voor die gekonfigureerde domain — word gewoonlik met `TXT "OK"` beantwoord
- As die gekonfigureerde base TTL op nul gelaat word, gebruik die listener ’n 10-sekonde base en voeg tot 59 sekondes se jitter by
- Dit maak short-label active probes nuttig wanneer geen HTTP listener blootgestel is nie

## Loader- en persistence-TTPs wat in incidents gesien is

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Laai Base64/XOR payloads af (Invoke-RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Ken unmanaged memory toe, kopieer shellcode, en verander protection na 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Voer uit via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- ’n Tropic Trooper chain van 2026 het ’n trojanized SumatraPDF executable (TOSHIS loader) gebruik wat `_security_init_cookie` na malicious code herlei het in plaas daarvan om die PE entry point te patch
- Die loader het APIs via Adler-32 hashing opgelos, ’n decoy PDF afgelaai, tweede-stadium shellcode verkry, dit met AES-128-CBC deur WinCrypt gedekripteer (`CryptDeriveKey` vanaf ’n hardcoded seed), en ’n Adaptix beacon reflectively in memory uitgevoer
- Persistence het later na scheduled tasks verskuif met benign-looking names soos `\MSDNSvc` of `\MicrosoftUDN`, gekonfigureer om die agent ongeveer elke twee uur weer te launch

Kyk na hierdie pages vir in-memory execution en AMSI/ETW-oorwegings:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence-meganismes wat waargeneem is:<sup>[[1]](#references)</sup>
- Startup folder shortcut (.lnk) om ’n loader by logon weer te launch
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), dikwels met benign-sounding names soos "Updater" om loader.ps1 te start.<sup>[[10]](#references)</sup>
- DLL search-order hijack deur msimg32.dll onder %APPDATA%\Microsoft\Windows\Templates te plaas vir susceptible processes

Technique deep-dives en checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting-idees
- PowerShell wat RW→RX transitions uitvoer: VirtualProtect na PAGE_EXECUTE_READWRITE binne powershell.exe.<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s met `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, of `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS responses met `AA=true` en `TXT "OK"` vir short queries onder verdagte domains.<sup>[[4]](#references)</sup>
- GitHub API traffic na `/repos/<owner>/<repo>/issues` gevolg deur `ipinfo.io` lookups vanaf dieselfde loader/beacon chain.<sup>[[5]](#references)</sup>
- Startup .lnk onder user- of algemene Startup-folders.<sup>[[1]](#references)</sup>
- Suspicious Run keys (bv. "Updater"), en loader names soos update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE samples wat `_security_init_cookie` na downloader code herlei voordat ’n decoy document vertoon word.<sup>[[5]](#references)</sup>
- User-writable DLL paths onder %APPDATA%\Microsoft\Windows\Templates wat msimg32.dll bevat.<sup>[[1]](#references)</sup>

## Notas oor OpSec-velde

- KillDate: timestamp waarna die agent self verval.<sup>[[1]](#references)</sup>
- WorkingTime: ure waartydens die agent aktief moet wees om met besigheidsaktiwiteit te meng.<sup>[[1]](#references)</sup>

Hierdie velde kan vir clustering gebruik word en om waargenome stil periodes te verklaar.

## YARA en statiese leidrade

Unit 42 het basiese YARA vir beacons (C/C++ en Go) en loader API-hashing constants gepubliseer.<sup>[[1]](#references)</sup> Oorweeg dit om dit aan te vul met rules wat soek na die [size|ciphertext|16-byte-key]-layout naby die einde van PE .rdata, die default HTTP profile strings, en nuwer server/listener markers soos `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, en `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: ’n Nuwe Open-Source Framework wat in Real-World Attacks Gebruik is (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting van ’n Open-Source C2 Framework op Skaal (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Pivots na AdaptixC2 en Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
