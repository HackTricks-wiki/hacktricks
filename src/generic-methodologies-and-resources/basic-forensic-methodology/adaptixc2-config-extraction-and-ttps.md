# Ekstrakcija konfiguracije AdaptixC2 i TTP-ovi

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 je modularni post-exploitation/C2 framework otvorenog koda sa Windows x86/x64 beacon-ima (EXE/DLL/service EXE/raw shellcode) i podrškom za BOF.<sup>[[1]](#references)</sup> Ova stranica dokumentuje:
- Kako je njegova RC4-pakovana konfiguracija ugrađena i kako je izdvojiti iz beacon-a
- Mrežne/profile indikatore za HTTP/SMB/TCP listenere
- Uobičajene loader i persistence TTP-ove uočene u praksi, sa linkovima ka relevantnim stranicama o Windows tehnikama

Nedavna izdanja upstream-a uključuju i DNS/DoH beacon listenere i zasebnu porodicu Gopher agenta/listenera, pa moderna Adaptix infrastruktura može izložiti više od originalnih HTTP/SMB/TCP površina, čak i kada određeni uzorak i dalje koristi klasični beacon agent.<sup>[[2]](#references)</sup>

## Profili i polja beacon-a

AdaptixC2 podržava tri glavna tipa beacon-a:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 sa podesivim serverima/portovima/SSL-om, metodom, URI-jem, zaglavljima, user-agent-om i prilagođenim imenom parametra
- BEACON_SMB: peer-to-peer C2 preko imenovanih cevi (intranet)
- BEACON_TCP: direktni socket-i, opciono sa unapred dodatim markerom za prikrivanje početka protokola

Ovo su rasporedi beacon-a javno dokumentovani u ranim analizama Adaptix-a i još uvek su najčešća polazna tačka za izdvajanje sa strane uzorka.<sup>[[1]](#references)</sup> Međutim, aktuelne upstream verzije uključuju i `BeaconDNS` i Gopher ekstenzije na serverskoj strani, zato nemojte pretpostaviti da svaka aktivna Adaptix implementacija izlaže samo HTTP/SMB/TCP infrastrukturu.<sup>[[2]](#references)</sup>

Tipična polja profila u HTTP beacon konfiguracijama (nakon dešifrovanja):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (niz stringova), ports (niz u32 vrednosti)
- http_method, uri, parameter, user_agent, http_headers (stringovi sa prefiksom dužine)
- ans_pre_size (u32), ans_size (u32) – koriste se za parsiranje veličina odgovora
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Nove verzije BeaconHTTP-a podržavaju i rotaciju koju bira operator, kroz više URI-jeva, user-agent-ova, Host zaglavlja i servera, uz sekvencijalni ili nasumični izbor.<sup>[[2]](#references)</sup> Iz perspektive threat hunting-a, to znači da jedan zaraženi host može da se povezuje preko više callback putanja i kombinacija zaglavlja, a da pritom i dalje koristi klasičnu RC4-pakovanu porodicu beacon-a.

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

Kada operator klikne na Create u builder-u, AdaptixC2 ugrađuje šifrovani profil u beacon kao završni blob. Format je:<sup>[[1]](#references)</sup>
- 4 bajta: veličina konfiguracije (uint32, little-endian)
- N bajtova: RC4-šifrovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Učitavač beacon-a kopira ključ od 16 bajtova sa kraja i RC4-dešifruje blok od N bajtova na mestu:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktične implikacije:<sup>[[1]](#references)</sup>
- Cela struktura se često nalazi unutar PE .rdata sekcije.
- Ekstrakcija je deterministička: pročitajte veličinu, pročitajte ciphertext te veličine, pročitajte 16-bajtni ključ postavljen odmah iza, a zatim dešifrujte pomoću RC4.

## Tok ekstrakcije konfiguracije (defenders)

Napišite extractor koji oponaša beacon logiku:<sup>[[1]](#references)</sup>
1) Pronađite blob unutar PE-a (obično u .rdata). Praktičan pristup je da skenirate .rdata u potrazi za verovatnim rasporedom [size|ciphertext|16-byte key] i pokušate RC4.
2) Pročitajte prva 4 bajta → size (uint32 LE).
3) Pročitajte sledećih N=size bajtova → ciphertext.
4) Pročitajte poslednjih 16 bajtova → RC4 key.
5) Dešifrujte ciphertext pomoću RC4. Zatim parsirajte plain profile kao:
   - u32/boolean skalarne vrednosti, kao što je navedeno iznad
   - stringovi sa prefiksom dužine (u32 dužina, pa bajtovi; završni NUL može biti prisutan)
   - nizovi: servers_count, praćen tolikim brojem parova [string, u32 port]

Minimalni Python proof-of-concept (samostalni, bez eksternih zavisnosti) koji radi sa prethodno izdvojenim blobom:

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
- Pri automatizaciji koristite PE parser da biste pročitali .rdata, a zatim primenite klizni prozor: za svaki offset o probajte size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = sledećih 16 bajtova; dešifrujte RC4-om i proverite da li se string polja dekodiraju kao UTF-8 i da li su dužine razumne.
- Parsirajte SMB/TCP profile prateći iste konvencije sa prefiksom dužine.

## Profili prilagođenih listenera: nemojte hardkodirati samo klasičnu HTTP šemu

Spoljni format pakovanja (`u32 size | RC4 ciphertext | 16-byte key`) može se ponovo koristiti, pa listeneri prilagođeni od strane aktera mogu zadržati isti postupak ekstrakcije, a pritom potpuno promeniti raspored dekriptovanih polja.

Dobar noviji primer je kampanja Tropic Trooper iz marta 2026, u kojoj izdvojeni Adaptix beacon nije sadržao standardni HTTP/TCP profil. Umesto toga, dekriptovani blob je sadržao GitHub transportne parametre kao što su:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na primer `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktična strategija za parser:
- Najpre detektujte spoljni RC4 blob kao i obično.
- Nakon dešifrovanja, granajte na osnovu sentinel stringova i validnosti polja umesto da odmah forsirate HTTP parser.
- Dobri sentineli uključuju `api.github.com`, `/issues?state=open`, HTTP glagole/URI-je, stringove nalik imenima named pipe-ova ili nizove servera/portova koji su očigledno validni.
- Ako HTTP parser ne uspe, ali plaintext sadrži koherentne UTF-8 stringove sa prefiksom dužine, sačuvajte uzorak i pokušajte sa alternativnim šemama umesto da ga odbacite kao lažno pozitivan.

U toj kampanji prilagođeni listener je koristio GitHub issues kao C2 transport, a beacon je upitom ka `ipinfo.io` saznavao svoju eksternu IP adresu jer GitHub API operatoru ne otkriva direktno izvornu adresu žrtve.<sup>[[5]](#references)</sup>

## Mrežno fingerprinting i lov na pretnje

HTTP:<sup>[[1]](#references)</sup>
- Uobičajeno: POST ka URI-jima koje bira operator (npr. /uri.php, /endpoint/api)
- Prilagođeni parametar zaglavlja koji se koristi za beacon ID (npr. X‑Beacon‑Id, X‑App‑Id)
- User-agent stringovi koji imitiraju Firefox 20 ili savremene verzije Chrome-a
- Učestalost polling-a vidljiva kroz sleep_delay/jitter_delay
- Novije verzije mogu da rotiraju URI-je, user-agent stringove, Host zaglavlja i servere između callback-ova, zato grupišite na osnovu neuobičajenih naziva zaglavlja, obrazaca veličine odgovora, ponovne upotrebe TLS-a i vremenskih razmaka, umesto da pretpostavite jedan par putanja/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeneri za intranet C2 u okruženjima sa ograničenim web izlaznim saobraćajem
- TCP beaconi mogu da dodaju nekoliko bajtova ispred saobraćaja kako bi zamaskirali početak protokola

Podrazumevane vrednosti aktuelnog upstream teamserver-a
- `profile.yaml` trenutno dolazi sa teamserver-om na `0.0.0.0:4321`, endpoint-om `/endpoint`, nazivima datoteka sertifikata/ključa `server.rsa.crt` i `server.rsa.key`, kao i extenderima za HTTP, SMB, TCP, DNS, Beacon agent i Gopher.<sup>[[2]](#references)</sup>
- Za rute koje se ne podudaraju, podrazumevani error handler vraća `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Podrazumevano 404 telo sadrži `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skeniranja celog interneta iz 2026. pronašla su mnogo izloženih teamserver-a na portu `4321` i mnogo beacon listenera na portu `43211`, pa oba porta mogu poslužiti kao početne tačke za pivotiranje, ali ih ne treba smatrati iscrpnim.<sup>[[4]](#references)</sup>

Fingerprint-i DNS/DoH listenera:<sup>[[4]](#references)</sup>
- Aktuelni BeaconDNS extender odgovara autoritativno (`AA=true`)
- Na upite koji ne odgovaraju obliku Beacon protokola — naročito na nazive sa manje od 5 labela pre podešenog domena — obično se odgovara sa `TXT "OK"`
- Ako je osnovni TTL podešen na nulu, listener koristi osnovnu vrednost od 10 sekundi i dodaje do 59 sekundi jitter-a
- Zbog toga su aktivne probe sa kratkim labelama korisne kada HTTP listener nije izložen

## Loader i TTP-ovi za persistence uočeni u incidentima

PowerShell loaderi koji rade u memoriji:<sup>[[1]](#references)</sup>
- Preuzimaju Base64/XOR payload-e (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alociraju unmanaged memoriju, kopiraju shellcode i menjaju zaštitu na 0x40 (PAGE_EXECUTE_READWRITE) preko VirtualProtect.<sup>[[7]](#references)</sup>
- Izvršavaju ga putem .NET dynamic invocation-a: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanizovani softver sa potpisom / staged shellcode loaderi:<sup>[[5]](#references)</sup>
- Lanac napada Tropic Trooper iz 2026. koristio je trojanizovani izvršni fajl SumatraPDF (TOSHIS loader), koji je preusmeravao `_security_init_cookie` ka malicioznom kodu umesto da menja PE entry point
- Loader je razrešavao API-je pomoću Adler-32 hash-iranja, preuzimao lažni PDF, pribavljao shellcode druge faze, dešifrovao ga pomoću AES-128-CBC preko WinCrypt-a (`CryptDeriveKey` iz hardkodovanog seed-a) i reflektivno izvršavao Adaptix beacon u memoriji
- Persistence je kasnije prešao na zakazane zadatke sa bezazleno zvučećim nazivima kao što su `\MSDNSvc` ili `\MicrosoftUDN`, konfigurisane tako da ponovo pokreću agenta otprilike svaka dva sata

Pogledajte ove stranice za razmatranja vezana za izvršavanje u memoriji i AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Uočeni mehanizmi persistence:<sup>[[1]](#references)</sup>
- Prečica (.lnk) u Startup folderu za ponovno pokretanje loadera pri prijavljivanju
- Registry Run ključevi (HKCU/HKLM ...\CurrentVersion\Run), često sa bezazleno zvučećim nazivima poput "Updater" za pokretanje loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack ubacivanjem msimg32.dll u %APPDATA%\Microsoft\Windows\Templates za procese podložne napadu

Detaljna analiza tehnika i provere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideje za lov na pretnje
- PowerShell procesi koji prelaze iz RW u RX: VirtualProtect ka PAGE_EXECUTE_READWRITE unutar powershell.exe.<sup>[[8]](#references)</sup>
- Obrasci dynamic invocation-a (GetDelegateForFunctionPointer)
- Nepodudarajući HTTPS 404 odgovori sa `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ili `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS odgovori sa `AA=true` i `TXT "OK"` za kratke upite pod sumnjivim domenima.<sup>[[4]](#references)</sup>
- Saobraćaj ka GitHub API-ju na `/repos/<owner>/<repo>/issues`, posle kog slede upiti ka `ipinfo.io` iz istog lanca loader/beacon.<sup>[[5]](#references)</sup>
- Startup .lnk u korisničkim ili zajedničkim Startup folderima.<sup>[[1]](#references)</sup>
- Sumnjivi Run ključevi (npr. "Updater") i nazivi loadera poput update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanizovani PE uzorci koji preusmeravaju `_security_init_cookie` ka downloader kodu pre prikazivanja lažnog dokumenta.<sup>[[5]](#references)</sup>
- Putanje DLL-ova koje korisnik može da menja, unutar %APPDATA%\Microsoft\Windows\Templates, a koje sadrže msimg32.dll.<sup>[[1]](#references)</sup>

## Napomene o OpSec poljima

- KillDate: vremenska oznaka nakon koje agent sam prestaje da radi.<sup>[[1]](#references)</sup>
- WorkingTime: sati tokom kojih agent treba da bude aktivan kako bi se uklopio u poslovne aktivnosti.<sup>[[1]](#references)</sup>

Ova polja mogu se koristiti za grupisanje i objašnjavanje uočenih perioda neaktivnosti.

## YARA i statički indikatori

Unit 42 je objavio osnovna YARA pravila za beacon-e (C/C++ i Go) i konstante za API hash-iranje u loaderima.<sup>[[1]](#references)</sup> Razmotrite dopunu pravilima koja traže raspored [size|ciphertext|16-byte-key] blizu kraja PE .rdata, podrazumevane HTTP profile stringove i novije markere servera/listenera, kao što su `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Novi open-source framework korišćen u stvarnim napadima (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting open-source C2 framework-a u velikim razmerama (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper prelazi na AdaptixC2 i prilagođeni Beacon listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Konstante za zaštitu memorije – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run ključevi/Startup folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
