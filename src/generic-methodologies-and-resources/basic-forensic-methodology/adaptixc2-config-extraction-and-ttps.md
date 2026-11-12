# Izdvajanje konfiguracije AdaptixC2 i TTP-ovi

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 je modularni post-exploitation/C2 framework otvorenog koda sa Windows x86/x64 beaconima (EXE/DLL/service EXE/raw shellcode) i podrškom za BOF.<sup>[[1]](#references)</sup> Ova stranica dokumentuje:
- Kako je njegova RC4-pakovana konfiguracija ugrađena i kako da se izdvoji iz beacona
- Mrežne/profile indikatore za HTTP/SMB/TCP listenere
- Uobičajene loader i persistence TTP-ove uočene u praksi, uz linkove ka relevantnim stranicama o Windows tehnikama

Nedavna izdanja upstream-a takođe uključuju DNS/DoH beacon listenere i zasebnu porodicu Gopher agenta/listenera, pa moderna Adaptix infrastruktura može izlagati više od originalnih HTTP/SMB/TCP površina, čak i kada konkretan uzorak i dalje koristi klasični beacon agent.<sup>[[2]](#references)</sup>

## Beacon profili i polja

AdaptixC2 podržava tri primarna tipa beacona:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 sa podesivim serverima/portovima/SSL-om, metodom, URI-jem, zaglavljima, user-agentom i prilagođenim imenom parametra
- BEACON_SMB: peer-to-peer C2 preko imenovanih cevi (intranet)
- BEACON_TCP: direktni socket-i, opcionalno sa markerom na početku radi zamagljivanja početka protokola

Ovo su rasporedi beacona javno dokumentovani u ranim analizama Adaptix-a i i dalje predstavljaju najčešću polaznu tačku za izdvajanje podataka iz uzoraka.<sup>[[1]](#references)</sup> Međutim, aktuelne upstream verzije takođe uključuju `BeaconDNS` i Gopher ekstendere na serverskoj strani, pa nemojte pretpostavljati da svaka aktivna Adaptix implementacija izlaže samo HTTP/SMB/TCP infrastrukturu.<sup>[[2]](#references)</sup>

Sledeći pregled polja i JSON primeri opisuju HTTP format analiziran 2025. godine; oni nisu specifikacija parsera za novije upstream verzije. Uobičajena polja u tim primerima (nakon dešifrovanja):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (niz stringova), ports (niz u32 vrednosti)
- http_method, uri, parameter, user_agent, http_headers (stringovi sa prefiksom dužine)
- ans_pre_size (u32), ans_size (u32) – koriste se za parsiranje veličina odgovora
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Novije verzije BeaconHTTP-a podržavaju i rotaciju koju bira operator između više URI-jeva, user-agent vrednosti, Host zaglavlja i servera, uz sekvencijalni ili nasumični izbor.<sup>[[2]](#references)</sup> Iz perspektive threat hunting-a, to znači da jedan zaraženi host može da se povezuje preko više callback putanja i kombinacija zaglavlja, a da i dalje koristi klasičnu porodicu RC4-pakovanih beacona.

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

Kada operator klikne na Create u builder-u, AdaptixC2 kompajlira šifrovani profil u beacon. Nemojte pretpostaviti da se nalazi na kraju PE-a ili shellcode-a: pronađite bajtove profila skeniranjem sekcija ili praćenjem `getProfile()` u primeru. Upakovani format je:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bajta: veličina konfiguracije (uint32, little-endian)
- N bajtova: RC4-šifrovani podaci konfiguracije
- 16 bajtova: RC4 ključ

Učitavač beacon-a kopira 16-bajtni ključ sa kraja i RC4-dešifruje N-bajtni blok na mestu:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktične implikacije:<sup>[[1]](#references)</sup>
- Cela struktura se često nalazi unutar PE .rdata sekcije.
- Ekstrakcija je deterministička: pročitajte veličinu, pročitajte šifrotekst te veličine, pročitajte 16-bajtni ključ postavljen neposredno iza, a zatim dešifrujte pomoću RC4.

## Tok rada za ekstrakciju konfiguracije (defanzivci)

Za opštu trijažu uzorka pre izdvajanja beacon-a, pogledajte [Malware Analysis](malware-analysis.md).

Napišite extractor koji oponaša logiku beacon-a:<sup>[[1]](#references)</sup>
1) Pronađite blob unutar PE-a (obično u .rdata). Praktičan pristup je da skenirate .rdata u potrazi za verovatnim rasporedom [veličina|šifrotekst|16-bajtni ključ] i pokušate RC4.
2) Pročitajte prva 4 bajta → veličina (uint32 LE).
3) Pročitajte sledećih N=size bajtova → šifrotekst.
4) Pročitajte poslednjih 16 bajtova → RC4 ključ.
5) Dešifrujte šifrotekst pomoću RC4. Zatim parsirajte običan profil kao:
   - u32/boolean skalari kao što je navedeno iznad
   - stringovi sa prefiksom dužine (u32 dužina, a zatim bajtovi; završni NUL može biti prisutan)
   - nizovi: servers_count, zatim toliko parova [string, u32 port]

Legacy HTTP Python proof-of-concept (samostalan, bez eksternih zavisnosti) za prethodno izdvojeni blob u redosledu polja iz 2025. Koristite parser trenutne šeme u nastavku za novije stock build-ove:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Parsiranje trenutnih stock HTTP i DNS profila

Trenutni upstream prvo pakuje šest little-endian vrednosti `u32`: watermark/tip agenta, datum gašenja, vreme rada, sleep, jitter i watermark/tip listenera. HTTP-specifični podaci zatim počinju jednobajtnom SSL zastavicom. Za razliku od legacy primera, sadrže liste URI-jeva, user-agent vrednosti i Host zaglavlja sa brojem elemenata, a zatim režim rotacije i podešavanja proxy-ja. Zato legacy parser na ovim buildovima počinje da čita SSL zastavicu iz polja za datum gašenja i daje netačne rezultate. Dužine stringova i celobrojne vrednosti u ovom profilu koriste little-endian kodiranje; upakovani stringovi, ako nisu prazni, završavaju se nulom.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Koristeći gorenavedene pomoćne funkcije `P` i `rc4`, primenite ovaj parser na dešifrovani plaintext **stock HTTP** profila. Nemojte uključivati RC4 ključ u javne izveštaje: HTTP profil može sadržati korisničko ime i lozinku za proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Parsiranje trenutnog stock HTTP plaintext profila</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Za standardni DNS beacon, pročitajte istih šest uobičajenih polja `u32`, a zatim stringove `domain`, `resolvers`, `doh_resolvers` i `qtype`, kojima prethodi njihova dužina. Pročitajte `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` i `dns_mode` kao `u32`, a zatim DoH user-agent string, kojem prethodi dužina. `dns_mode` razlikuje UDP, DoH i dva smera fallback-a. Ovo je poseban raspored polja: ne obrađujte DNS plaintext pomoću HTTP parsera.<sup>[[12]](#references)[[13]](#references)</sup>

Saveti:
- Pri automatizaciji koristite PE parser za čitanje .rdata, a zatim primenite klizni prozor: za svaki offset o, pokušajte size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], a sledećih 16 bajtova uzmite kao candidate key; dešifrujte RC4-om i proverite da li se string polja dekodiraju kao UTF-8 i da li su dužine razumne.
- Profile SMB/TCP parsirajte prateći iste konvencije za polja kojima prethodi dužina.

## Prilagođeni listener profili: nemojte tvrdo kodirati samo klasičnu HTTP šemu

Spoljašnji format pakovanja (`u32 size | RC4 ciphertext | 16-byte key`) može se ponovo koristiti, pa listeneri prilagođeni akteru mogu zadržati isti postupak ekstrakcije, a pritom potpuno promeniti raspored dešifrovanih polja.

Dobar noviji primer je kampanja Tropic Trooper iz marta 2026, u kojoj izdvojeni Adaptix beacon nije sadržao standardni HTTP/TCP profil. Umesto toga, dešifrovani blob je čuvao parametre GitHub transporta, kao što su:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (na primer `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktična strategija za parser:
- Najpre detektujte spoljašnji RC4 blob na uobičajen način.
- Nakon dešifrovanja, odaberite granu na osnovu sentinel stringova i ispravnosti polja, umesto da odmah namećete HTTP parser.
- Dobri sentinel stringovi uključuju `api.github.com`, `/issues?state=open`, HTTP metode/URI-je, stringove nalik imenovanim cevima ili očigledno validne nizove servera/portova.
- Ako HTTP parser ne uspe, ali plaintext sadrži smislene UTF-8 stringove kojima prethodi dužina, sačuvajte uzorak i isprobajte alternativne šeme umesto da ga odbacite kao lažno pozitivan nalaz.

U toj kampanji prilagođeni listener je koristio GitHub issues kao C2 transport, a beacon je upitom ka `ipinfo.io` saznavao svoju eksternu IP adresu, jer GitHub API ne otkriva operatoru direktno izvornu adresu žrtve.<sup>[[5]](#references)</sup> Za odvojeni handshake preko issue-a i datoteke u repozitorijumu pogledajte [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Mrežno fingerprinting i potraga za pretnjama

HTTP:<sup>[[1]](#references)</sup>
- Uobičajeno: POST ka URI-jima koje bira operator (npr. /uri.php, /endpoint/api)
- Prilagođeni parametar zaglavlja koristi se za beacon ID (npr. X‑Beacon‑Id, X‑App‑Id)
- User-agent stringovi koji oponašaju Firefox 20 ili savremene verzije Chrome-a
- Učestalost prozivanja vidljiva je preko sleep_delay/jitter_delay
- Novije verzije mogu da rotiraju URI-je, user-agent stringove, Host zaglavlja i servere tokom callback-ova, zato grupišite po neuobičajenim imenima zaglavlja, obrascima veličine odgovora, ponovnoj upotrebi TLS-a i vremenskim intervalima, umesto da pretpostavljate jedan par putanje/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB listeneri sa imenovanim cevima za intranet C2 kada je izlazni web saobraćaj ograničen
- TCP beacon-i mogu dodati nekoliko bajtova ispred saobraćaja radi prikrivanja početka protokola

Podrazumevane vrednosti aktuelnog upstream teamserver-a
- `profile.yaml` trenutno dolazi sa teamserver-om na `0.0.0.0:4321`, endpoint-om `/endpoint`, nazivima datoteka sertifikata/ključa `server.rsa.crt` i `server.rsa.key`, kao i extender-ima za HTTP, SMB, TCP, DNS, Beacon agent i Gopher.<sup>[[2]](#references)</sup>
- Za rute koje se ne podudaraju, podrazumevani rukovalac greškama vraća `Server: AdaptixC2` i `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Podrazumevano telo odgovora 404 sadrži `AdaptixC2 404` i `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skeniranja celog interneta iz 2026. pronašla su mnogo izloženih teamserver-a na portu `4321` i mnogo beacon listener-a na portu `43211`, pa su oba porta korisna za početne pretrage, ali ne treba ih smatrati iscrpnim skupom.<sup>[[4]](#references)</sup>

Otisci DNS/DoH listener-a:<sup>[[4]](#references)</sup>
- Aktuelni BeaconDNS extender odgovara autoritativno (`AA=true`)
- Na upite koji ne odgovaraju obliku beacon protokola — naročito na nazive sa manje od 5 labela pre podešenog domena — obično se odgovara sa `TXT "OK"`
- Ako je osnovni TTL ostavljen na nuli, listener koristi osnovnu vrednost od 10 sekundi i dodaje do 59 sekundi jitter-a
- Zbog toga su aktivne sonde sa kratkim labelama korisne kada HTTP listener nije izložen

## Loader i TTP-ovi za postojanost primećeni u incidentima

PowerShell loader-i koji se izvršavaju u memoriji:<sup>[[1]](#references)</sup>
- Preuzimaju Base64/XOR payload-e (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Alociraju neupravljanu memoriju, kopiraju shellcode i menjaju zaštitu na 0x40 (PAGE_EXECUTE_READWRITE) pomoću VirtualProtect.<sup>[[7]](#references)</sup>
- Izvršavaju kod pomoću .NET dinamičkog pozivanja: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanizovani potpisani softver / loader-i za staged shellcode:<sup>[[5]](#references)</sup>
- Lanac napada Tropic Trooper iz 2026. koristio je trojanizovanu izvršnu datoteku SumatraPDF (TOSHIS loader), koja je preusmeravala `_security_init_cookie` na zlonamerni kod umesto da menja PE entry point
- Loader je razrešavao API-je pomoću Adler-32 heširanja, preuzimao mamac u obliku PDF-a, pribavljao shellcode drugog stepena, dešifrovao ga pomoću AES-128-CBC preko WinCrypt-a (`CryptDeriveKey` iz hardkodiranog seed-a) i reflektivno izvršavao Adaptix beacon u memoriji
- Postojanost je kasnije prebačena na zakazane zadatke sa bezazleno zvučećim imenima kao što su `\MSDNSvc` ili `\MicrosoftUDN`, podešene da ponovo pokreću agenta približno svaka dva sata

Pogledajte ove stranice za izvršavanje u memoriji i razmatranja u vezi sa AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Primećeni mehanizmi postojanosti:<sup>[[1]](#references)</sup>
- Prečica (.lnk) u Startup folder-u za ponovno pokretanje loader-a pri prijavi
- Registry Run ključevi (HKCU/HKLM ...\CurrentVersion\Run), često sa bezazleno zvučećim imenima kao što je "Updater" za pokretanje loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack ubacivanjem msimg32.dll u %APPDATA%\Microsoft\Windows\Templates za ranjive procese

Detaljna analiza tehnika i provere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ideje za potragu
- PowerShell procesi koji prelaze iz RW u RX: VirtualProtect za PAGE_EXECUTE_READWRITE unutar powershell.exe.<sup>[[8]](#references)</sup>
- Obrasci dinamičkog pozivanja (GetDelegateForFunctionPointer)
- Nepodudarajući HTTPS 404 odgovori sa `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` ili `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS odgovori sa `AA=true` i `TXT "OK"` za kratke upite u okviru sumnjivih domena.<sup>[[4]](#references)</sup>
- Saobraćaj ka GitHub API-ju na `/repos/<owner>/<repo>/issues`, praćen upitima ka `ipinfo.io` iz istog lanca loader-a/beacon-a.<sup>[[5]](#references)</sup>
- Startup .lnk datoteke u korisničkim ili zajedničkim Startup folder-ima.<sup>[[1]](#references)</sup>
- Sumnjivi Run ključevi (npr. "Updater") i nazivi loader-a kao što su update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Trojanizovani PE uzorci koji preusmeravaju `_security_init_cookie` na kod za preuzimanje pre prikazivanja lažnog dokumenta.<sup>[[5]](#references)</sup>
- DLL putanje koje korisnik može da menja, pod %APPDATA%\Microsoft\Windows\Templates, a sadrže msimg32.dll.<sup>[[1]](#references)</sup>

## Napomene o OpSec poljima

- KillDate: vremenska oznaka nakon koje agent sam sebe deaktivira.<sup>[[1]](#references)</sup>
- WorkingTime: sati tokom kojih agent treba da bude aktivan kako bi se uklopio u poslovne aktivnosti.<sup>[[1]](#references)</sup>

Ova polja mogu se koristiti za grupisanje i objašnjenje uočenih perioda neaktivnosti.

## YARA i statički indikatori

Unit 42 je objavio osnovna YARA pravila za beacon-e (C/C++ i Go) i konstante za API heširanje koje koriste loader-i.<sup>[[1]](#references)</sup> Razmotrite dopunu pravilima koja traže raspored [size|ciphertext|16-byte-key] pri kraju PE .rdata sekcije, podrazumevane HTTP profile stringove i novije indikatore servera/listener-a, kao što su `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` i `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Novi open-source framework korišćen u napadima u stvarnom svetu (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Dokumentacija Adaptix Framework-a](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Fingerprinting open-source C2 framework-a u velikom obimu (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper prelazi na AdaptixC2 i prilagođeni Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Konstante za zaštitu memorije – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run ključevi/Startup folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Generisanje AdaptixC2 profila (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser AdaptixC2 beacon profila (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Generisanje AdaptixC2 DNS profila (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Pakovanje AdaptixC2 profila (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
