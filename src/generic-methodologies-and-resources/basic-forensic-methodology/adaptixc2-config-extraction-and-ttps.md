# AdaptixC2-konfigurasie-ekstraksie en TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 is ’n modulêre, open-source post-exploitation/C2-framework met Windows x86/x64-beacons (EXE/DLL/service EXE/raw shellcode) en BOF-ondersteuning. Hierdie bladsy dokumenteer:
- Hoe die RC4-packed configuration ingebed is en hoe om dit uit beacons te onttrek
- Network/profile indicators vir HTTP/SMB/TCP listeners
- Algemene loader- en persistence-TTPs wat in die wild waargeneem is, met skakels na relevante Windows-tegniekbladsye

Onlangse upstream releases bevat ook DNS/DoH beacon listeners en die afsonderlike Gopher agent/listener-familie. Moderne Adaptix-infrastruktuur kan dus meer as die oorspronklike HTTP/SMB/TCP-oppervlakke blootstel, selfs wanneer ’n spesifieke sample steeds die klassieke beacon-agent gebruik.

## Beacon-profiele en velde

AdaptixC2 ondersteun drie primêre beacon-tipes:
- BEACON_HTTP: web C2 met konfigureerbare servers/ports/SSL, method, URI, headers, user-agent en ’n custom parameter name
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, opsioneel met ’n prepended marker om die protokolbegin te obfuskeer

Dit is die beacon-layouts wat in vroeë Adaptix-ontledings publiek gedokumenteer is, en dit is steeds die algemeenste beginpunt vir extraction aan die sample-kant. Huidige upstream builds bevat egter ook `BeaconDNS`- en Gopher-extenders aan die server-kant. Moet dus nie aanvaar dat elke aktiewe Adaptix-deployment slegs HTTP/SMB/TCP-infrastruktuur blootstel nie.

Tipiese profile fields wat in HTTP-beacon-configs waargeneem word (ná decryption):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – gebruik om response sizes te parse
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Onlangse BeaconHTTP-builds ondersteun ook operator-selected rotation oor verskeie URIs, user-agents, Host headers en servers, met sequential of random selection. Vanuit ’n hunting-perspektief beteken dit dat ’n enkele besmette host oor verskeie callback paths en header combinations kan uitwyk sonder om die klassieke RC4-packed beacon-familie te verlaat.

Voorbeeld van ’n verstek-HTTP-profiel (uit ’n beacon build):
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
Waargenome kwaadwillige HTTP-profiel (werklike aanval):
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

Wanneer die operator **Create** in die builder klik, embed AdaptixC2 die encrypted profile as ’n tail blob in die beacon. Die formaat is:
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

Die beacon loader kopieer die 16-byte key vanaf die einde en RC4-decrypt die N-byte block in place:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktiese implikasies:
- Die volledige struktuur is dikwels binne die PE .rdata-afdeling.
- Extraction is deterministies: lees die size, lees die ciphertext van daardie grootte, lees die 16-byte key wat onmiddellik daarna geplaas is, en voer dan RC4-dekripsie uit.

## Configuration extraction-werkvloei (verdedigers)

Skryf ’n extractor wat die beacon-logika naboots:
1) Locate die blob binne die PE (gewoonlik .rdata). ’n Pragmatiese benadering is om .rdata te skandeer vir ’n aanneemlike [size|ciphertext|16-byte key]-uitleg en RC4 te probeer.
2) Lees die eerste 4 bytes → size (uint32 LE).
3) Lees die volgende N=size bytes → ciphertext.
4) Lees die laaste 16 bytes → RC4 key.
5) Voer RC4-dekripsie op die ciphertext uit. Parseer dan die plain profile as:
- u32/boolean-scalars soos hierbo aangedui
- length-prefixed strings (u32-lengte gevolg deur bytes; ’n trailing NUL kan teenwoordig wees)
- arrays: servers_count gevolg deur soveel [string, u32 port]-pare

Minimale Python proof-of-concept (standalone, sonder eksterne deps) wat met ’n pre-extracted blob werk:
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
- Wanneer jy outomatiseer, gebruik ’n PE parser om .rdata te lees en pas dan ’n sliding window toe: probeer vir elke offset o die grootte = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidaat-sleutel = volgende 16 grepe; RC4-dekripteer en kontroleer dat string fields as UTF-8 dekodeer en dat lengtes sinvol is.
- Parse SMB/TCP profiles deur dieselfde length-prefixed conventions te volg.

## Custom listener profiles: moenie slegs die klassieke HTTP-schema hardkodeer nie

Die buitenste packing format (`u32 size | RC4 ciphertext | 16-byte key`) is herbruikbaar, dus kan actor-customized listeners dieselfde extraction workflow behou terwyl die decrypted field layout heeltemal verander.

’n Goeie onlangse voorbeeld is die Tropic Trooper-campaign van April 2026, waar die geëkstraheerde Adaptix beacon nie ’n standaard HTTP/TCP-profile bevat het nie. In plaas daarvan het die decrypted blob GitHub transport parameters gestoor, soos:
- `repo_owner`
- `repo_name`
- `api_host` (byvoorbeeld `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktiese parser-strategie:
- Detekteer eers die outer RC4 blob presies soos gewoonlik.
- Ná decryption, vertak op grond van sentinel strings en field sanity eerder as om die HTTP parser onmiddellik af te dwing.
- Goeie sentinels sluit in `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings, of oënskynlik geldige server/port arrays.
- As die HTTP parser misluk maar die plaintext samehangende length-prefixed UTF-8 strings bevat, behou die sample en probeer alternatiewe schemas eerder as om dit as ’n false positive weg te gooi.

In daardie campaign het die custom listener GitHub issues as die C2-transport gebruik, en die beacon het `ipinfo.io` geraadpleeg om sy eksterne IP te bepaal, omdat die GitHub API nie die slagoffer se bronadres direk aan die operator openbaar nie.

## Network fingerprinting en hunting

HTTP
- Algemeen: POST na operator-selected URIs (bv. /uri.php, /endpoint/api)
- Custom header parameter wat vir beacon ID gebruik word (bv. X‑Beacon‑Id, X‑App‑Id)
- User-agents wat Firefox 20 of huidige Chrome-builds naboots
- Polling cadence sigbaar via sleep_delay/jitter_delay
- Nuwer builds kan URIs, user-agents, Host headers en servers oor callbacks roteer; cluster dus op ongewone header names, response-size patterns, TLS reuse en timing eerder as om ’n enkele path/UA-paar te aanvaar

SMB/TCP
- SMB named-pipe listeners vir intranet C2 waar web-egress beperk word
- TCP beacons kan ’n paar grepe voor die traffic plaas om die protokolbegin te obfuskeer

Huidige upstream teamserver defaults
- `profile.yaml` kom tans met teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` en `server.rsa.key`, en extenders vir HTTP, SMB, TCP, DNS, Beacon agent en Gopher
- Vir unmatched routes gee die default error handler `Server: AdaptixC2` en `Adaptix-Version: v1.2` terug
- Die stock 404 body bevat `AdaptixC2 404` en `You need to enter the correct connection details.`
- Internet-wide scans in 2026 het baie exposed teamservers op `4321` en baie beacon listeners op `43211` gevind; albei poorte is dus nuttige seed pivots, maar moet nie as volledig beskou word nie

DNS/DoH listener fingerprints
- Die huidige BeaconDNS extender antwoord authoritatively (`AA=true`)
- Queries wat nie by die beacon protocol shape pas nie — veral names met minder as 5 labels vóór die configured domain — word algemeen met `TXT "OK"` beantwoord
- As die configured base TTL op zero gelaat word, gebruik die listener ’n 10-sekonde base en voeg tot 59 sekondes jitter by
- Dit maak short-label active probes nuttig wanneer geen HTTP listener exposed is nie

## Loader- en persistence-TTPs wat in incidents gesien is

In-memory PowerShell loaders
- Laai Base64/XOR payloads af (Invoke‑RestMethod / WebClient)
- Ken unmanaged memory toe, kopieer shellcode, verander protection na 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect
- Voer uit via .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- ’n Tropic Trooper-chain in 2026 het ’n trojanized SumatraPDF executable (TOSHIS loader) gebruik wat `_security_init_cookie` na malicious code herlei het in plaas daarvan om die PE entry point te patch
- Die loader het APIs via Adler-32 hashing resolved, ’n decoy PDF afgelaai, second-stage shellcode opgehaal, dit met AES-128-CBC deur WinCrypt (`CryptDeriveKey` vanaf ’n hardcoded seed) decrypted, en ’n Adaptix beacon reflectively in memory executed
- Persistence het later na scheduled tasks verskuif met name wat onskuldig lyk, soos `\MSDNSvc` of `\MicrosoftUDN`, wat gekonfigureer is om die agent ongeveer elke twee uur weer te launch

Kyk na hierdie pages vir in-memory execution en AMSI/ETW considerations:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Persistence mechanisms wat waargeneem is
- Startup folder shortcut (.lnk) om ’n loader by logon weer te launch
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), dikwels met name wat onskuldig klink, soos "Updater", om loader.ps1 te start
- DLL search-order hijack deur msimg32.dll onder %APPDATA%\Microsoft\Windows\Templates te drop vir susceptible processes

Technique deep-dives en checks:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell wat RW→RX-transitions spawn: VirtualProtect na PAGE_EXECUTE_READWRITE binne powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s met `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, of `You need to enter the correct connection details.`
- DNS responses met `AA=true` en `TXT "OK"` vir short queries onder suspect domains
- GitHub API traffic na `/repos/<owner>/<repo>/issues` gevolg deur `ipinfo.io` lookups vanaf dieselfde loader/beacon-chain
- Startup .lnk onder user- of algemene Startup-folders
- Suspicious Run keys (bv. "Updater"), en loader names soos update.ps1/loader.ps1
- Trojanized PE samples wat `_security_init_cookie` na downloader code herlei voordat ’n decoy document gewys word
- User-writable DLL paths onder %APPDATA%\Microsoft\Windows\Templates wat msimg32.dll bevat

## Notes on OpSec fields

- KillDate: timestamp waarna die agent self expireer
- WorkingTime: ure waartydens die agent aktief moet wees om met business activity te blend

Hierdie fields kan vir clustering gebruik word en om waargenome quiet periods te verduidelik.

## YARA en static leads

Unit 42 het basiese YARA vir beacons (C/C++ en Go) en loader API-hashing constants gepubliseer. Oorweeg om dit aan te vul met rules wat soek na die [size|ciphertext|16-byte-key]-layout naby die einde van PE .rdata, die default HTTP profile strings, en nuwer server/listener markers soos `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, en `ipinfo.io`.

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
