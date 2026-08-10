# Izdvajanje konfiguracije i TTP-ova AdaptixC2

AdaptixC2 je modularni, open-source post-exploitation/C2 framework sa Windows x86/x64 beacon-ima (EXE/DLL/service EXE/raw shellcode) i BOF podrškom.<sup>[[1]](#references)</sup> Ova stranica dokumentuje:
- Kako je njegova RC4-packed konfiguracija ugrađena i kako je izdvojiti iz beacon-a
- Mrežne/profilne indikatore za HTTP/SMB/TCP listenere
- Uobičajene loader i persistence TTP-ove uočene u praksi, sa linkovima ka relevantnim Windows technique stranicama

Novija upstream izdanja takođe isporučuju DNS/DoH beacon listenere i zasebnu Gopher agent/listener familiju, tako da moderna Adaptix infrastruktura može izložiti više od originalnih HTTP/SMB/TCP površina, čak i kada određeni sample i dalje koristi klasični beacon agent.<sup>[[2]](#references)</sup>

## Beacon profili i polja

AdaptixC2 podržava tri primarna tipa beacon-a:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 sa podesivim serverima/portovima/SSL-om, metodom, URI-jem, header-ima, user-agent-om i prilagođenim nazivom parametra
- BEACON_SMB: peer-to-peer C2 preko named pipe-a (intranet)
- BEACON_TCP: direktni socket-i, opciono sa markerom dodatim na početak radi obfuskacije početka protokola

Ovo su layout-i beacon-a javno dokumentovani u ranim Adaptix analizama i oni su i dalje najčešća početna tačka za extraction sa sample-a.<sup>[[1]](#references)</sup> Međutim, aktuelne upstream build verzije takođe isporučuju `BeaconDNS` i Gopher extender-e na serverskoj strani, zato nemojte pretpostaviti da svaka aktivna Adaptix deployment infrastruktura izlaže samo HTTP/SMB/TCP infrastrukturu.<sup>[[2]](#references)</sup>

Tipična profilna polja uočenа u HTTP beacon konfiguracijama (nakon dekripcije):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – koriste se za parsiranje veličina odgovora
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Novije BeaconHTTP build verzije takođe podržavaju rotaciju koju bira operator između više URI-jeva, user-agent-ova, Host header-a i servera, uz sekvencijalni ili nasumični izbor.<sup>[[2]](#references)</sup> Iz perspektive hunting-a, to znači da jedan zaraženi host može koristiti više callback putanja i kombinacija header-a, bez napuštanja klasične RC4-packed beacon familije.

Primer podrazumevanog HTTP profila (iz beacon build verzije):<sup>[[1]](#references)</sup>
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

Kada operator klikne na Create u builderu, AdaptixC2 ugrađuje šifrovani profil kao završni blob u beacon. Format je:<sup>[[1]](#references)</sup>
- 4 bajta: veličina konfiguracije (uint32, little-endian)
- N bajtova: RC4-enkriptovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Loader za beacon kopira ključ od 16 bajtova sa kraja i RC4-dešifruje blok od N bajtova na mestu:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Praktične implikacije:<sup>[[1]](#references)</sup>
- Cela struktura se često nalazi unutar PE .rdata sekcije.
- Izdvajanje je determinističko: pročitajte veličinu, pročitajte ciphertext te veličine, pročitajte 16‑bajtni ključ postavljen neposredno nakon njega, a zatim izvršite RC4 dekripciju.

## Tok izdvajanja konfiguracije (defenders)

Napišite extractor koji oponaša beacon logiku:<sup>[[1]](#references)</sup>
1) Pronađite blob unutar PE-a (najčešće u sekciji .rdata). Praktičan pristup je skeniranje sekcije .rdata u potrazi za verovatnim rasporedom [size|ciphertext|16‑byte key] i pokušaj RC4-a.
2) Pročitajte prva 4 bajta → size (uint32 LE).
3) Pročitajte narednih N=size bajtova → ciphertext.
4) Pročitajte poslednjih 16 bajtova → RC4 key.
5) Izvršite RC4 dekripciju ciphertext-a. Zatim parsirajte plain profile kao:
- u32/boolean scalars kao što je gore navedeno
- length-prefixed strings (u32 length, nakon čega slede bajtovi; završni NUL može biti prisutan)
- arrays: servers_count, nakon čega sledi toliko [string, u32 port] parova

Minimalni Python proof-of-concept (samostalan, bez external deps) koji radi sa prethodno izdvojenim blobom:
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
- Kada automatizujete proces, koristite PE parser za čitanje `.rdata`, zatim primenite klizni prozor: za svaki offset o pokušajte sa size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidat ključ = narednih 16 bajtova; izvršite RC4 dešifrovanje i proverite da li se string polja dekodiraju kao UTF-8 i da li su dužine razumne.
- Parsirajte SMB/TCP profile prateći iste konvencije sa dužinom na početku.

## Custom listener profiles: nemojte hard-code-ovati samo klasičnu HTTP šemu

Spoljašnji format pakovanja (`u32 size | RC4 ciphertext | 16-byte key`) može ponovo da se koristi, tako da listener-i prilagođeni od strane aktera mogu zadržati isti tok ekstrakcije, uz potpuno izmenjen raspored dešifrovanih polja.

Dobar noviji primer je kampanja Tropic Trooper iz marta 2026, u kojoj ekstrahovani Adaptix beacon nije sadržao standardni HTTP/TCP profil. Umesto toga, dešifrovani blob je čuvao GitHub transportne parametre kao što su:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na primer `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktična strategija za parser:
- Najpre detektujte spoljašnji RC4 blob na uobičajen način.
- Nakon dešifrovanja, grananje zasnivajte na sentinel stringovima i validnosti polja, umesto da odmah primenite HTTP parser.
- Dobri sentineli uključuju `api.github.com`, `/issues?state=open`, HTTP glagole/URI-je, stringove u stilu named pipe-a ili očigledno ispravne nizove servera/portova.
- Ako HTTP parser ne uspe, ali plaintext sadrži koherentne UTF-8 stringove sa dužinom na početku, sačuvajte uzorak i pokušajte sa alternativnim šemama umesto da ga odbacite kao false positive.

U toj kampanji, custom listener je koristio GitHub issues kao C2 transport, a beacon je upućivao upite ka `ipinfo.io` da bi saznao svoju eksternu IP adresu, jer GitHub API operatoru ne otkriva direktno izvornu adresu žrtve.<sup>[[5]](#references)</sup>

## Network fingerprinting i hunting

HTTP:<sup>[[1]](#references)</sup>
- Uobičajeno: POST ka URI-jima koje bira operator (npr. /uri.php, /endpoint/api)
- Custom header parametar koji se koristi za beacon ID (npr. X‑Beacon‑Id, X‑App‑Id)
- User-agent-i koji oponašaju Firefox 20 ili savremene Chrome build-ove
- Učestalost polling-a vidljiva kroz sleep_delay/jitter_delay
- Noviji build-ovi mogu rotirati URI-je, user-agent-e, Host header-e i servere između callback-ova, pa grupisanje treba zasnivati na neuobičajenim imenima header-a, obrascima veličine odgovora, ponovnoj upotrebi TLS-a i vremenskim karakteristikama, umesto na pretpostavci o jednom paru putanje/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listener-i za intranet C2 kada je web egress ograničen
- TCP beacon-i mogu dodati nekoliko bajtova pre saobraćaja radi prikrivanja početka protokola

Trenutne podrazumevane vrednosti upstream teamserver-a
- `profile.yaml` trenutno dolazi sa teamserver-om `0.0.0.0:4321`, endpoint-om `/endpoint`, nazivima certificate/key datoteka `server.rsa.crt` i `server.rsa.key`, kao i extender-ima za HTTP, SMB, TCP, DNS, Beacon agent i Gopher.<sup>[[2]](#references)</sup>
- Za rute bez podudaranja, podrazumevani error handler vraća `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Standardno 404 telo sadrži `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internet-wide skeniranja iz 2026. pronašla su veliki broj izloženih teamserver-a na portu `4321` i veliki broj beacon listener-a na portu `43211`, pa su oba porta korisni početni pivot-i, ali ih ne treba smatrati potpunim spiskom.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprint-i:<sup>[[4]](#references)</sup>
- Trenutni BeaconDNS extender odgovara autoritativno (`AA=true`)
- Na upite koji ne odgovaraju obliku beacon protokola — naročito na nazive sa manje od 5 labela pre konfigurisane domene — često se odgovara sa `TXT "OK"`
- Ako je konfigurisani osnovni TTL ostavljen na nuli, listener koristi osnovu od 10 sekundi i dodaje do 59 sekundi jitter-a
- Zbog toga su aktivne sonde sa kratkim labelama korisne kada HTTP listener nije izložen

## Loader i persistence TTP-ovi uočeni u incidentima

In-memory PowerShell loader-i:<sup>[[1]](#references)</sup>
- Preuzimaju Base64/XOR payload-e (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alociraju unmanaged memoriju, kopiraju shellcode i menjaju zaštitu na 0x40 (PAGE_EXECUTE_READWRITE) pomoću VirtualProtect.<sup>[[7]](#references)</sup>
- Izvršavaju kod putem .NET dynamic invocation-a: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loader-i:<sup>[[5]](#references)</sup>
- Lanac Tropic Trooper-a iz 2026. koristio je trojanized SumatraPDF executable (TOSHIS loader) koji je preusmeravao `_security_init_cookie` u maliciozni kod umesto menjanja PE entry point-a
- Loader je rešavao API-je pomoću Adler-32 hashing-a, preuzimao decoy PDF, dovlačio second-stage shellcode, dešifrovao ga AES-128-CBC algoritmom kroz WinCrypt (`CryptDeriveKey` iz hardkodovanog seed-a) i reflectively izvršavao Adaptix beacon u memoriji
- Persistence je kasnije premešten na scheduled tasks sa benignim nazivima kao što su `\MSDNSvc` ili `\MicrosoftUDN`, konfigurisanim da ponovo pokrenu agent približno svaka dva sata

Pogledajte ove stranice za razmatranja u vezi sa izvršavanjem u memoriji i AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Uočeni persistence mehanizmi:<sup>[[1]](#references)</sup>
- Prečica u Startup folderu (.lnk) za ponovno pokretanje loader-a pri prijavljivanju korisnika
- Registry Run ključevi (HKCU/HKLM ...\CurrentVersion\Run), često sa benignim nazivima kao što je "Updater", za pokretanje loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijacking postavljanjem msimg32.dll pod %APPDATA%\Microsoft\Windows\Templates za procese koji su tome podložni

Detaljne analize tehnika i provere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideje za hunting
- PowerShell koji pokreće RW→RX tranzicije: VirtualProtect na PAGE_EXECUTE_READWRITE unutar powershell.exe.<sup>[[8]](#references)</sup>
- Obrasci dynamic invocation-a (GetDelegateForFunctionPointer)
- Nepodudarajući HTTPS 404 odgovori sa `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ili `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS odgovori sa `AA=true` i `TXT "OK"` za kratke upite unutar sumnjivih domena.<sup>[[4]](#references)</sup>
- Saobraćaj ka GitHub API-ju na `/repos/<owner>/<repo>/issues`, nakon čega slede upiti ka `ipinfo.io` iz istog loader/beacon lanca.<sup>[[5]](#references)</sup>
- Startup .lnk u korisničkim ili zajedničkim Startup folderima.<sup>[[1]](#references)</sup>
- Sumnjivi Run ključevi (npr. "Updater") i nazivi loader-a kao što su update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanized PE uzorci koji preusmeravaju `_security_init_cookie` u downloader kod pre prikazivanja decoy dokumenta.<sup>[[5]](#references)</sup>
- DLL putanje kojima korisnik može da piše, pod %APPDATA%\Microsoft\Windows\Templates, koje sadrže msimg32.dll.<sup>[[1]](#references)</sup>

## Napomene o OpSec poljima

- KillDate: vremenska oznaka nakon koje agent sam sebe deaktivira.<sup>[[1]](#references)</sup>
- WorkingTime: sati tokom kojih agent treba da bude aktivan kako bi se uklopio u poslovne aktivnosti.<sup>[[1]](#references)</sup>

Ova polja mogu da se koriste za grupisanje i objašnjavanje uočenih perioda neaktivnosti.

## YARA i statički indikatori

Unit 42 je objavio osnovne YARA za beacon-e (C/C++ i Go), kao i konstante za API-hashing loader-a.<sup>[[1]](#references)</sup> Razmotrite njihovo dopunjavanje pravilima koja traže raspored [size|ciphertext|16-byte-key] u blizini kraja PE `.rdata`, podrazumevane HTTP profile stringove i novije server/listener markere kao što su `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Novi open-source Framework iskorišćen u napadima iz stvarnog sveta (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting open-source C2 Framework-a u velikom obimu (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper prelazi na AdaptixC2 i custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Konstante zaštite memorije – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run ključevi/Startup folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
