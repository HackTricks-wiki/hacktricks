# Ekstrakcija konfiguracije i TTP-ovi za AdaptixC2

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 je modularni, open-source post-exploitation/C2 framework sa Windows x86/x64 beaconima (EXE/DLL/service EXE/raw shellcode) i BOF podrškom. Ova stranica dokumentuje:
- Kako je njegova RC4-packed konfiguracija ugrađena i kako se može ekstraktovati iz beacona
- Mrežne/profile indikatore za HTTP/SMB/TCP listenere
- Uobičajene loader i persistence TTP-ove uočene u praksi, sa linkovima ka relevantnim Windows technique stranicama

Novija upstream izdanja takođe uključuju DNS/DoH beacon listenere i zasebnu Gopher agent/listener familiju, pa moderna Adaptix infrastruktura može izložiti više od prvobitnih HTTP/SMB/TCP površina, čak i kada konkretan sample i dalje koristi klasični beacon agent.

## Beacon profili i polja

AdaptixC2 podržava tri primarna tipa beacona:
- BEACON_HTTP: web C2 sa podesivim serverima/portovima/SSL-om, metodom, URI-jem, headerima, user-agentom i prilagođenim nazivom parametra
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direktni sockets, opciono sa prependovanim markerom za obfuskaciju početka protokola

Ovo su layout-i beacona javno dokumentovani u ranim Adaptix analizama i oni su i dalje najčešća početna tačka za extraction na strani sample-a. Međutim, trenutni upstream build-ovi takođe uključuju `BeaconDNS` i Gopher extenders na server strani, pa ne treba pretpostaviti da svaka aktivna Adaptix deployment infrastruktura izlaže samo HTTP/SMB/TCP infrastrukturu.

Tipična profile polja uočena u HTTP beacon konfiguracijama (nakon dešifrovanja):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – koriste se za parsiranje veličina odgovora
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Noviji BeaconHTTP build-ovi takođe podržavaju rotaciju koju bira operator kroz više URI-jeva, user-agentova, Host headera i servera, uz sekvencijalni ili nasumični odabir. Iz perspektive huntinga, to znači da jedan zaraženi host može uspostavljati konekcije ka više callback putanja i kombinacija headera, a da pritom ne napusti klasičnu RC4-packed beacon familiju.

Primer podrazumevanog HTTP profila (iz beacon build-a):
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
Uočeni zlonamerni HTTP profil (stvarni napad):
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
## Pakovanje enkriptovane konfiguracije i putanja učitavanja

Kada operator klikne na Create u builderu, AdaptixC2 ugrađuje enkriptovani profil kao tail blob u beacon. Format je:
- 4 bajta: veličina konfiguracije (uint32, little-endian)
- N bajtova: RC4-enkriptovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Beacon loader kopira 16-bajtni ključ sa kraja i RC4-dešifruje N-bajtni blok na mestu:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktične implikacije:
- Cela struktura se često nalazi unutar PE .rdata sekcije.
- Ekstrakcija je deterministička: pročitajte veličinu, pročitajte ciphertext te veličine, pročitajte 16‑bajtny key postavljen neposredno nakon toga, zatim izvršite RC4-dešifrovanje.

## Workflow za ekstrakciju konfiguracije (defenders)

Napišite extractor koji oponaša beacon logiku:
1) Pronađite blob unutar PE-a (najčešće u .rdata). Praktičan pristup je skeniranje .rdata sekcije u potrazi za verovatnim rasporedom [size|ciphertext|16‑byte key] i pokušaj RC4 operacije.
2) Pročitajte prva 4 bajta → size (uint32 LE).
3) Pročitajte sledećih N=size bajtova → ciphertext.
4) Pročitajte poslednjih 16 bajtova → RC4 key.
5) Izvršite RC4-dešifrovanje ciphertext-a. Zatim parsirajte plain profile kao:
- u32/boolean skalare, kao što je prethodno navedeno
- length-prefixed strings (u32 length praćen bajtovima; završni NUL može biti prisutan)
- arrays: servers_count praćen odgovarajućim brojem parova [string, u32 port]

Minimalni Python proof-of-concept (samostalan, bez eksternih dependencies) koji radi sa prethodno ekstrahovanim blob-om:
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
Saveti:
- Prilikom automatizacije, koristite PE parser za čitanje .rdata, zatim primenite klizni prozor: za svaki offset o pokušajte size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = sledećih 16 bajtova; izvršite RC4-dekripciju i proverite da li se string polja dekodiraju kao UTF-8 i da li su dužine razumne.
- Parsirajte SMB/TCP profiles praćenjem istih konvencija sa dužinskim prefiksom.

## Custom listener profiles: nemojte hard-code-ovati samo klasičnu HTTP šemu

Spoljašnji format pakovanja (`u32 size | RC4 ciphertext | 16-byte key`) može ponovo da se koristi, pa actor-customized listeners mogu zadržati isti extraction workflow i istovremeno potpuno promeniti layout dekriptovanih polja.

Dobar noviji primer je kampanja Tropic Trooper iz aprila 2026, u kojoj extracted Adaptix beacon nije sadržao standardni HTTP/TCP profile. Umesto toga, dekriptovani blob je čuvao GitHub transport parameters kao što su:
- `repo_owner`
- `repo_name`
- `api_host` (na primer `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktična parser strategija:
- Najpre detektujte spoljašnji RC4 blob na uobičajen način.
- Nakon dekripcije, granajte na osnovu sentinel stringova i ispravnosti polja, umesto da odmah primenite HTTP parser.
- Dobri sentineli uključuju `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style strings ili očigledno validne server/port arrays.
- Ako HTTP parser ne uspe, ali plaintext sadrži koherentne UTF-8 strings sa dužinskim prefiksom, sačuvajte sample i pokušajte alternativne schemas umesto da ga odbacite kao false positive.

U toj kampanji custom listener je koristio GitHub issues kao C2 transport, a beacon je upućivao upite ka `ipinfo.io` da sazna svoju eksternu IP adresu, jer GitHub API operatoru ne otkriva direktno izvornu adresu žrtve.

## Network fingerprinting i hunting

HTTP
- Uobičajeno: POST ka URI-jima koje bira operator (npr. /uri.php, /endpoint/api)
- Custom header parameter koji se koristi za beacon ID (npr. X‑Beacon‑Id, X‑App‑Id)
- User-agents koji imitiraju Firefox 20 ili savremene Chrome builds
- Polling cadence vidljiv preko sleep_delay/jitter_delay
- Noviji builds mogu rotirati URI-je, user-agents, Host headers i servers između callback-ova, pa grupišite na osnovu neuobičajenih header names, response-size patterns, TLS reuse i timing-a, umesto da pretpostavite jedan par path/UA

SMB/TCP
- SMB named-pipe listeners za intranet C2 tamo gde je web egress ograničen
- TCP beacons mogu dodati nekoliko bajtova pre saobraćaja radi prikrivanja početka protokola

Current upstream teamserver defaults
- `profile.yaml` trenutno se isporučuje sa teamserver `0.0.0.0:4321`, endpoint-om `/endpoint`, nazivima certificate/key fajlova `server.rsa.crt` i `server.rsa.key`, kao i extenderima za HTTP, SMB, TCP, DNS, Beacon agent i Gopher
- Za unmatched routes, podrazumevani error handler vraća `Server: AdaptixC2` i `Adaptix-Version: v1.2`
- Podrazumevano 404 telo sadrži `AdaptixC2 404` i `You need to enter the correct connection details.`
- Internet-wide scans tokom 2026. pronašli su mnogo exposed teamservers na portu `4321` i mnogo beacon listeners na portu `43211`, pa su oba porta korisni seed pivots, ali ih ne treba smatrati potpunim spiskom

DNS/DoH listener fingerprints
- Trenutni BeaconDNS extender odgovara autoritativno (`AA=true`)
- Na upite koji ne odgovaraju obliku beacon protokola — naročito na nazive sa manje od 5 labels pre configured domain-a — obično se odgovara sa `TXT "OK"`
- Ako je configured base TTL ostavljen na nuli, listener koristi osnovu od 10 sekundi i dodaje do 59 sekundi jitter-a
- Zbog toga su short-label active probes korisne kada nijedan HTTP listener nije izložen

## Loader i persistence TTPs uočeni u incidentima

In‑memory PowerShell loaders
- Preuzimaju Base64/XOR payloads (Invoke‑RestMethod / WebClient)
- Alociraju unmanaged memory, kopiraju shellcode, menjaju zaštitu na 0x40 (PAGE_EXECUTE_READWRITE) putem VirtualProtect
- Izvršavaju se preko .NET dynamic invocation-a: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

Trojanized signed software / staged shellcode loaders
- Lanac Tropic Trooper iz 2026. koristio je trojanized SumatraPDF executable (TOSHIS loader) koji je preusmeravao `_security_init_cookie` u malicious code umesto patching-a PE entry point-a
- Loader je razrešavao API-je putem Adler-32 hashing-a, preuzimao decoy PDF, dohvatao second-stage shellcode, dekriptovao ga AES-128-CBC algoritmom kroz WinCrypt (`CryptDeriveKey` iz hardcoded seed-a) i reflectively izvršavao Adaptix beacon u memoriji
- Persistence je kasnije premešten na scheduled tasks sa benignim nazivima kao što su `\MSDNSvc` ili `\MicrosoftUDN`, konfigurisanima da ponovo pokrenu agent približno svaka dva sata

Pogledajte ove stranice za in‑memory execution i AMSI/ETW razmatranja:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Uočeni persistence mechanisms
- Startup folder shortcut (.lnk) za ponovno pokretanje loader-a prilikom logon-a
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), često sa benignim nazivima kao što je "Updater", za pokretanje loader.ps1
- DLL search-order hijack ubacivanjem msimg32.dll u %APPDATA%\Microsoft\Windows\Templates za susceptible processes

Detaljne analize tehnika i provere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting ideas
- PowerShell koji pokreće RW→RX transitions: VirtualProtect na PAGE_EXECUTE_READWRITE unutar powershell.exe
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- Unmatched HTTPS 404s sa `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ili `You need to enter the correct connection details.`
- DNS responses sa `AA=true` i `TXT "OK"` za short queries unutar sumnjivih domena
- GitHub API traffic ka `/repos/<owner>/<repo>/issues`, praćen `ipinfo.io` lookups iz istog loader/beacon chain-a
- Startup .lnk u user ili common Startup folders
- Sumnjivi Run keys (npr. "Updater") i loader names kao što su update.ps1/loader.ps1
- Trojanized PE samples koji preusmeravaju `_security_init_cookie` u downloader code pre prikazivanja decoy dokumenta
- User-writable DLL paths unutar %APPDATA%\Microsoft\Windows\Templates koji sadrže msimg32.dll

## Napomene o OpSec fields

- KillDate: timestamp nakon kojeg agent sam sebe deaktivira
- WorkingTime: sati tokom kojih agent treba da bude aktivan kako bi se uklopio u poslovne aktivnosti

Ova polja mogu da se koriste za clustering i objašnjenje uočenih perioda neaktivnosti.

## YARA i statički indikatori

Unit 42 je objavio osnovni YARA za beacons (C/C++ i Go) i loader API-hashing constants. Razmotrite dopunu pravilima koja traže layout [size|ciphertext|16-byte-key] u blizini kraja PE .rdata, default HTTP profile strings i novije server/listener markers kao što su `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.

## Reference

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
