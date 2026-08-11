# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 je modularni, open-source post-exploitation/C2 framework sa Windows x86/x64 beaconima (EXE/DLL/service EXE/raw shellcode) i BOF podrškom.<sup>[[1]](#references)</sup> Ova stranica dokumentuje:
- Kako je njegova RC4-packed konfiguracija ugrađena i kako je izvući iz beacona
- Mrežne/profile indikatore za HTTP/SMB/TCP listenere
- Uobičajene loader i persistence TTPs uočene u praksi, sa linkovima ka relevantnim Windows technique stranicama

Nedavna upstream izdanja takođe uključuju DNS/DoH beacon listenere i zasebnu Gopher agent/listener familiju, pa moderna Adaptix infrastruktura može izložiti više od originalnih HTTP/SMB/TCP površina, čak i kada određeni sample i dalje koristi klasični beacon agent.<sup>[[2]](#references)</sup>

## Beacon profili i polja

AdaptixC2 podržava tri primarna tipa beacona:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 sa podesivim serverima/portovima/SSL-om, metodom, URI-jem, headerima, user-agentom i prilagođenim nazivom parametra
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direktni socketi, opciono sa markerom na početku radi obfuskacije početka protokola

Ovo su layout-i beacona javno dokumentovani u ranim Adaptix analizama i oni su i dalje najčešća početna tačka za extraction sa sample strane.<sup>[[1]](#references)</sup> Međutim, aktuelni upstream build-ovi takođe uključuju `BeaconDNS` i Gopher extenders na server strani, pa ne treba pretpostaviti da svaka aktivna Adaptix deployment infrastruktura izlaže samo HTTP/SMB/TCP infrastrukturu.<sup>[[2]](#references)</sup>

Tipična profile polja u HTTP beacon konfiguracijama (nakon decryption-a):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – koriste se za parsiranje veličina response-a
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Nedavni BeaconHTTP build-ovi takođe podržavaju rotaciju koju bira operator između više URI-jeva, user-agentova, Host headera i servera, uz sekvencijalni ili nasumični izbor.<sup>[[2]](#references)</sup> Iz perspektive hunting-a, to znači da jedan kompromitovani host može slati callback-e na više putanja i kombinacija headera, bez napuštanja klasične RC4-packed beacon familije.

Primer podrazumevanog HTTP profila (iz beacon build-a):<sup>[[1]](#references)</sup>
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
Uočeni zlonamerni HTTP profil (stvarni napad):<sup>[[1]](#references)</sup>
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
## Pakovanje šifrovane konfiguracije i putanja učitavanja

Kada operator klikne na Create u builderu, AdaptixC2 ugrađuje šifrovani profil kao tail blob u beacon. Format je:<sup>[[1]](#references)</sup>
- 4 bajta: veličina konfiguracije (uint32, little-endian)
- N bajtova: RC4-šifrovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Beacon loader kopira ključ od 16 bajtova sa kraja i RC4-dešifruje N-bajtni blok direktno na mestu:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktične implikacije:<sup>[[1]](#references)</sup>
- Cela struktura se često nalazi unutar PE odeljka .rdata.
- Ekstrakcija je deterministička: pročitajte veličinu, pročitajte ciphertext te veličine, pročitajte 16-bajtni ključ postavljen neposredno nakon njega, a zatim izvršite RC4-dešifrovanje.

## Tok ekstrakcije konfiguracije (branitelji)

Napišite extractor koji oponaša logiku beacon-a:<sup>[[1]](#references)</sup>
1) Pronađite blob unutar PE-a (obično u .rdata). Praktičan pristup je skeniranje odeljka .rdata u potrazi za mogućim rasporedom [size|ciphertext|16-byte key] i pokušaj RC4-a.
2) Pročitajte prva 4 bajta → size (uint32 LE).
3) Pročitajte sledećih N=size bajtova → ciphertext.
4) Pročitajte poslednjih 16 bajtova → RC4 key.
5) Izvršite RC4-dešifrovanje ciphertext-a. Zatim parsirajte plain profile kao:
- u32/boolean scalars kao što je prethodno navedeno
- strings sa prefiksom dužine (u32 dužina praćena bajtovima; završni NUL može biti prisutan)
- arrays: servers_count praćen odgovarajućim brojem parova [string, u32 port]

Minimalni Python proof-of-concept (samostalan, bez eksternih zavisnosti) koji radi sa prethodno izdvojenim blob-om:
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
- Prilikom automatizacije koristite PE parser za čitanje .rdata, zatim primenite klizni prozor: za svaki ofset o pokušajte veličinu = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidat ključa = narednih 16 bajtova; izvršite RC4 dešifrovanje i proverite da li se string polja dekodiraju kao UTF-8 i da li su dužine razumne.
- Parsirajte SMB/TCP profile praćenjem istih konvencija sa dužinom na početku.

## Custom listener profiles: don't hard-code only the classic HTTP schema

Spoljašnji format pakovanja (`u32 size | RC4 ciphertext | 16-byte key`) može ponovo da se koristi, tako da listeneri prilagođeni od strane aktera mogu zadržati isti workflow za ekstrakciju, uz potpuno izmenjen raspored dešifrovanih polja.

Dobar noviji primer je kampanja Tropic Trooper iz marta 2026, u kojoj ekstrakovani Adaptix beacon nije sadržao standardni HTTP/TCP profil. Umesto toga, dešifrovani blob je čuvao GitHub transportne parametre kao što su:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na primer `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktična strategija za parser:
- Najpre detektujte spoljašnji RC4 blob na uobičajen način.
- Nakon dešifrovanja, granajte na osnovu sentinel stringova i ispravnosti polja, umesto da odmah primenite HTTP parser.
- Dobri sentineli uključuju `api.github.com`, `/issues?state=open`, HTTP glagole/URI-je, stringove u stilu named pipe-a ili očigledno validne nizove servera/portova.
- Ako HTTP parser ne uspe, ali plaintext sadrži koherentne UTF-8 stringove sa dužinom na početku, sačuvajte uzorak i pokušajte alternativne šeme umesto da ga odbacite kao false positive.

U toj kampanji custom listener je koristio GitHub issues kao C2 transport, a beacon je upitom ka `ipinfo.io` saznavao svoju eksternu IP adresu, jer GitHub API operateru ne otkriva direktno izvornu adresu žrtve.<sup>[[5]](#references)</sup>

## Network fingerprinting and hunting

HTTP:<sup>[[1]](#references)</sup>
- Uobičajeno: POST ka URI-jima koje bira operater (npr. /uri.php, /endpoint/api)
- Custom header parametar koji se koristi za beacon ID (npr. X-Beacon-Id, X-App-Id)
- User-agent-i koji oponašaju Firefox 20 ili savremene Chrome buildove
- Učestalost pollinga vidljiva preko sleep_delay/jitter_delay
- Noviji buildovi mogu rotirati URI-je, user-agent-e, Host headere i servere kroz callback-ove, pa umesto pretpostavljanja jednog para putanje/UA treba grupisati na osnovu neuobičajenih naziva headera, obrazaca veličine odgovora, ponovne upotrebe TLS-a i vremenskih obrazaca.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeneri za intranet C2 tamo gde je web izlaz ograničen
- TCP beacon-i mogu dodati nekoliko bajtova ispred saobraćaja radi prikrivanja početka protokola

Current upstream teamserver defaults
- `profile.yaml` trenutno se isporučuje sa teamserver-om na `0.0.0.0:4321`, endpoint-om `/endpoint`, nazivima fajlova sertifikata/ključa `server.rsa.crt` i `server.rsa.key`, kao i extenderima za HTTP, SMB, TCP, DNS, Beacon agent i Gopher.<sup>[[2]](#references)</sup>
- Za nepodudarajuće rute, podrazumevani error handler vraća `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Standardno 404 telo sadrži `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide skeniranja iz 2026. pronašla su veliki broj izloženih teamserver-a na portu `4321` i veliki broj beacon listenera na portu `43211`, pa su oba porta korisni početni pivot-i, ali ih ne treba smatrati sveobuhvatnim.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- Trenutni BeaconDNS extender odgovara autoritativno (`AA=true`)
- Upiti koji ne odgovaraju obliku beacon protokola — naročito nazivi sa manje od 5 labela pre konfigurisane domene — obično dobijaju odgovor `TXT "OK"`
- Ako je konfigurisani osnovni TTL ostavljen na nuli, listener koristi osnovu od 10 sekundi i dodaje do 59 sekundi jitter-a
- Zbog toga su aktivne probe sa kratkim labelama korisne kada HTTP listener nije izložen

## Loader and persistence TTPs seen in incidents

In-memory PowerShell loader-i:<sup>[[1]](#references)</sup>
- Preuzimaju Base64/XOR payload-e (Invoke-RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alociraju unmanaged memoriju, kopiraju shellcode, menjaju zaštitu na 0x40 (PAGE_EXECUTE_READWRITE) putem VirtualProtect.<sup>[[7]](#references)</sup>
- Izvršavaju se putem .NET dynamic invocation-a: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loader-i:<sup>[[5]](#references)</sup>
- Lanac Tropic Trooper iz 2026. koristio je trojanized SumatraPDF executable (TOSHIS loader) koji je preusmeravao `_security_init_cookie` u malicious code umesto patchovanja PE entry point-a
- Loader je razrešavao API-je pomoću Adler-32 hashing-a, preuzimao decoy PDF, dobavljao second-stage shellcode, dešifrovao ga AES-128-CBC algoritmom kroz WinCrypt (`CryptDeriveKey` iz hardcoded seed-a) i reflectively izvršavao Adaptix beacon u memoriji
- Persistence je kasnije prebačena na scheduled tasks sa benignim nazivima kao što su `\MSDNSvc` ili `\MicrosoftUDN`, konfigurisanim da ponovo pokrenu agent približno svaka dva sata

Pogledajte ove stranice za in-memory execution i AMSI/ETW razmatranja:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Uočeni persistence mehanizmi:<sup>[[1]](#references)</sup>
- Prečica (.lnk) u Startup folderu za ponovno pokretanje loader-a prilikom logovanja
- Registry Run ključevi (HKCU/HKLM ...\CurrentVersion\Run), često sa benigno zvučećim nazivima kao što je "Updater", za pokretanje loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijacking postavljanjem msimg32.dll u %APPDATA%\Microsoft\Windows\Templates za osetljive procese

Detaljne analize tehnika i provere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideje za hunting
- PowerShell koji pokreće RW→RX tranzicije: VirtualProtect do PAGE_EXECUTE_READWRITE unutar powershell.exe.<sup>[[8]](#references)</sup>
- Obrasci dynamic invocation-a (GetDelegateForFunctionPointer)
- Nepodudarajući HTTPS 404 odgovori sa `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ili `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS odgovori sa `AA=true` i `TXT "OK"` za kratke upite ispod sumnjivih domena.<sup>[[4]](#references)</sup>
- GitHub API saobraćaj ka `/repos/<owner>/<repo>/issues`, praćen upitima ka `ipinfo.io` iz istog loader/beacon lanca.<sup>[[5]](#references)</sup>
- Startup .lnk u korisničkim ili zajedničkim Startup folderima.<sup>[[1]](#references)</sup>
- Sumnjivi Run ključevi (npr. "Updater") i nazivi loader-a poput update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE uzorci koji preusmeravaju `_security_init_cookie` u downloader code pre prikazivanja decoy dokumenta.<sup>[[5]](#references)</sup>
- DLL putanje sa upisom dozvoljenim korisniku unutar %APPDATA%\Microsoft\Windows\Templates koje sadrže msimg32.dll.<sup>[[1]](#references)</sup>

## Notes on OpSec fields

- KillDate: vremenska oznaka nakon koje agent sam ističe.<sup>[[1]](#references)</sup>
- WorkingTime: sati tokom kojih agent treba da bude aktivan kako bi se uklopio u poslovne aktivnosti.<sup>[[1]](#references)</sup>

Ova polja mogu se koristiti za grupisanje i objašnjavanje uočenih perioda neaktivnosti.

## YARA and static leads

Unit 42 je objavio osnovna YARA pravila za beacon-e (C/C++ i Go) i konstante za loader API-hashing.<sup>[[1]](#references)</sup> Razmotrite dopunu pravilima koja traže raspored [size|ciphertext|16-byte-key] u blizini kraja PE .rdata, podrazumevane stringove HTTP profila i novije server/listener markere kao što su `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

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
