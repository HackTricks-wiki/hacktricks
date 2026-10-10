# AdaptixC2-konfigurasie-onttrekking en TTP's

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 is ’n modulêre, oopbron post-exploitation/C2-raamwerk met Windows x86/x64-beacons (EXE/DLL/service EXE/raw shellcode) en BOF-ondersteuning.<sup>[[1]](#references)</sup> Hierdie bladsy dokumenteer:
- Hoe die RC4-verpakte konfigurasie ingebed is en hoe om dit uit beacons te onttrek
- Netwerk-/profielaanduiders vir HTTP/SMB/TCP-listeners
- Algemene loader- en persistence-TTP's wat in die praktyk waargeneem is, met skakels na relevante Windows-tegniekbladsye

Onlangse upstream-vrystellings sluit ook DNS/DoH-beacon-listeners en die afsonderlike Gopher-agent-/listener-familie in, dus kan moderne Adaptix-infrastruktuur meer as die oorspronklike HTTP/SMB/TCP-oppervlakke blootstel, selfs wanneer ’n spesifieke sample steeds die klassieke beacon-agent gebruik.<sup>[[2]](#references)</sup>

## Beacon-profiele en velde

AdaptixC2 ondersteun drie primêre beacon-tipes:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 met konfigureerbare servers/ports/SSL, metode, URI, headers, user-agent en ’n pasgemaakte parameternaam
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direkte sockets, opsioneel met ’n voorafgevoegde merker om die begin van die protokol te verdoesel

Dit is die beacon-uitlegte wat vroeg in openbare Adaptix-ontledings gedokumenteer is, en dit is steeds die algemeenste beginpunt vir onttrekking vanaf ’n sample.<sup>[[1]](#references)</sup> Huidige upstream-bouweergawes sluit egter ook `BeaconDNS`- en Gopher-uitbreidings aan die bedienerkant in, dus moet jy nie aanneem dat elke aktiewe Adaptix-ontplooiing slegs HTTP/SMB/TCP-infrastruktuur blootstel nie.<sup>[[2]](#references)</sup>

Tipiese profielvelde wat in HTTP-beacon-konfigurasies waargeneem is (ná dekripsie):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – gebruik om reaksiegroottes te ontleed
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Onlangse BeaconHTTP-bouweergawes ondersteun ook operateurgekose rotasie tussen verskeie URI's, user-agents, Host-headers en servers, met opeenvolgende of ewekansige keuse.<sup>[[2]](#references)</sup> Vanuit ’n hunting-perspektief beteken dit dat ’n enkele besmette gasheer oor verskeie callback-paaie en header-kombinasies kan versprei sonder om die klassieke RC4-verpakte beacon-familie te verlaat.

Voorbeeld van ’n verstek-HTTP-profiel (uit ’n beacon-bouweergawe):<sup>[[1]](#references)</sup>

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

## Geënkripteerde konfigurasieverpakking en laaipad

Wanneer die operateur in die builder op Create klik, sluit AdaptixC2 die geënkripteerde profiel as ’n blob aan die einde van die beacon in. Die formaat is:<sup>[[1]](#references)</sup>
- 4 grepe: konfigurasiegrootte (uint32, little-endian)
- N grepe: RC4-geënkripteerde konfigurasiedata
- 16 grepe: RC4-sleutel

Die beacon loader kopieer die 16-greep-sleutel van die einde af en RC4-dekripteer die N-greep-blok in plek:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktiese implikasies:<sup>[[1]](#references)</sup>
- Die hele struktuur is dikwels in die PE .rdata-afdeling.
- Onttrekking is deterministies: lees die grootte, lees die ciphertext van daardie grootte, lees dan die 16-greep-sleutel wat onmiddellik daarna geplaas is, en dekripteer met RC4.

## Konfigurasie-onttrekkingswerkvloei (verdedigers)

Skryf ’n extractor wat die beacon-logika naboots:<sup>[[1]](#references)</sup>
1) Vind die blob in die PE (gewoonlik .rdata). ’n Praktiese benadering is om .rdata te deursoek vir ’n geloofwaardige [size|ciphertext|16-byte key]-uitleg en RC4 te probeer.
2) Lees die eerste 4 grepe → size (uint32 LE).
3) Lees die volgende N=size grepe → ciphertext.
4) Lees die laaste 16 grepe → RC4-sleutel.
5) Dekripteer die ciphertext met RC4. Ontleed dan die plain profile as:
   - u32/boolean-scalars soos hierbo aangedui
   - lengtevoorafgegaande strings (u32-lengte gevolg deur grepe; ’n afsluitende NUL kan teenwoordig wees)
   - skikkings: servers_count gevolg deur daardie aantal [string, u32-port]-pare

Minimale Python proof-of-concept (selfstandig, sonder eksterne afhanklikhede) wat met ’n voorafonttrekte blob werk:

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
- Wanneer jy dit outomatiseer, gebruik ’n PE-parser om .rdata te lees en pas dan ’n skuifvenster toe: probeer vir elke offset o die grootte = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], kandidaat-sleutel = die volgende 16 grepe. Ontsyfer met RC4 en kyk of stringvelde as UTF-8 gedekodeer word en die lengtes sinvol is.
- Ontleed SMB/TCP-profiele deur dieselfde lengte-voorafgaande konvensies te volg.

## Pasgemaakte listener-profiele: moenie net die klassieke HTTP-skema hardkodeer nie

Die buitenste pakformaat (`u32 size | RC4 ciphertext | 16-byte key`) is herbruikbaar, dus kan akteur-aangepaste listeners dieselfde onttrekkingswerkvloei gebruik terwyl die ontsyferde velduitleg heeltemal verander.

’n Goeie onlangse voorbeeld is die Tropic Trooper-veldtog van Maart 2026, waar die onttrekte Adaptix-beacon nie ’n standaard HTTP/TCP-profiel bevat het nie. In plaas daarvan het die ontsyferde blob GitHub-vervoerparameters soos hierdie gestoor:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (byvoorbeeld `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktiese parserstrategie:
- Bespeur eers die buitenste RC4-blob presies soos gewoonlik.
- Vertak ná ontsleuteling op grond van sentinel-stringe en veldgeldigheid, eerder as om onmiddellik die HTTP-parser af te dwing.
- Goeie sentinels sluit in `api.github.com`, `/issues?state=open`, HTTP-metodes/URI’s, named-pipe-agtige stringe, of klaarblyklik geldige bediener-/poortskikkings.
- As die HTTP-parser misluk, maar die plaintext samehangende lengte-voorafgaande UTF-8-stringe bevat, behou die sample en probeer alternatiewe skemas eerder as om dit as ’n vals positiewe resultaat weg te gooi.

In daardie veldtog het die pasgemaakte listener GitHub-issues as die C2-vervoer gebruik, en die beacon het `ipinfo.io` bevraagteken om sy eksterne IP te bepaal, omdat die GitHub API nie die slagoffer se bronadres direk aan die operateur bekend maak nie.<sup>[[5]](#references)</sup>

## Netwerkvingerafdrukke en jag

HTTP:<sup>[[1]](#references)</sup>
- Algemeen: POST na operateurgekose URI’s (bv. /uri.php, /endpoint/api)
- Pasgemaakte kopparameter wat vir die beacon-ID gebruik word (bv. X‑Beacon‑Id, X‑App‑Id)
- User-agents wat Firefox 20 of hedendaagse Chrome-bouwe naboots
- Die polling-ritme is sigbaar via sleep_delay/jitter_delay
- Nuwer bouwe kan URI’s, user-agents, Host-koppe en bedieners tussen callbacks roteer; groepeer dus op grond van ongewone kopname, antwoordgroottepatrone, TLS-hergebruik en tydsberekening eerder as om een enkele pad/UA-paar te aanvaar.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe-listeners vir intranet-C2 waar webuitgaande verkeer beperk word
- TCP-beacons kan ’n paar grepe voor verkeer voeg om die begin van die protokol te verdoesel

Huidige verstekwaardes van die upstream-teamserver
- `profile.yaml` kom tans met teamserver `0.0.0.0:4321`, eindpunt `/endpoint`, sertifikaat-/sleutellêername `server.rsa.crt` en `server.rsa.key`, en uitbreidings vir HTTP, SMB, TCP, DNS, Beacon-agent en Gopher.<sup>[[2]](#references)</sup>
- Vir roetes wat nie ooreenstem nie, stuur die verstekfouthanteerder `Server: AdaptixC2` en `Adaptix-Version: v1.2` terug.<sup>[[4]](#references)</sup>
- Die standaard 404-liggaam bevat `AdaptixC2 404` en `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Skanderings oor die hele internet in 2026 het baie blootgestelde teamservers op `4321` en baie beacon-listeners op `43211` gevind. Albei poorte is dus nuttige beginpunte vir verdere ondersoek, maar moet nie as volledig beskou word nie.<sup>[[4]](#references)</sup>

DNS/DoH-listener-vingerafdrukke:<sup>[[4]](#references)</sup>
- Die huidige BeaconDNS-uitbreiding antwoord gesaghebbend (`AA=true`)
- Navrae wat nie by die beacon-protokolvorm pas nie — veral name met minder as 5 etikette voor die gekonfigureerde domein — word gewoonlik met `TXT "OK"` beantwoord
- As die gekonfigureerde basis-TTL op nul gelaat word, gebruik die listener ’n basis van 10 sekondes en voeg tot 59 sekondes se jitter by
- Dit maak aktiewe toetse met kort etikette nuttig wanneer geen HTTP-listener blootgestel is nie

## Loader- en volharding-TTP’s wat in voorvalle gesien is

PowerShell-loaders in geheue:<sup>[[1]](#references)</sup>
- Laai Base64/XOR-payloads af (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Ken onbeheerde geheue toe, kopieer shellcode en verander die beskerming na 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Voer uit via .NET-dinamiese aanroeping: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized getekende sagteware / gefaseerde shellcode-loaders:<sup>[[5]](#references)</sup>
- ’n Tropic Trooper-ketting in 2026 het ’n getrojaniseerde SumatraPDF-uitvoerbare lêer (TOSHIS-loader) gebruik wat `_security_init_cookie` na kwaadwillige kode herlei het in plaas daarvan om die PE-ingangspunt te wysig
- Die loader het API’s met Adler-32-hashing opgelos, ’n lok-PDF afgelaai, tweede-fase-shellcode opgehaal, dit met AES-128-CBC via WinCrypt (met `CryptDeriveKey` vanaf ’n hardgekodeerde saad) ontsyfer, en ’n Adaptix-beacon reflektief in geheue uitgevoer
- Volharding is later na geskeduleerde take verskuif, met onskuldig klinkende name soos `\MSDNSvc` of `\MicrosoftUDN`, wat ingestel is om die agent ongeveer elke twee uur weer te begin

Raadpleeg hierdie bladsye vir uitvoering in geheue en oorwegings rakende AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Waargenome volhardingsmeganismes:<sup>[[1]](#references)</sup>
- Kortpad (.lnk) in die Startup-lêergids om ’n loader by aanmelding weer te begin
- Register-Run-sleutels (HKCU/HKLM ...\CurrentVersion\Run), dikwels met onskuldig klinkende name soos "Updater" om loader.ps1 te begin.<sup>[[10]](#references)</sup>
- DLL-soekvolgorde-kaping deur msimg32.dll onder %APPDATA%\Microsoft\Windows\Templates te plaas vir kwesbare prosesse

Tegniekverdiepings en kontroles:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Jagidees
- PowerShell wat RW→RX-oorgange veroorsaak: VirtualProtect na PAGE_EXECUTE_READWRITE binne powershell.exe.<sup>[[8]](#references)</sup>
- Dinamiese aanroeppatrone (GetDelegateForFunctionPointer)
- Onbepaalde HTTPS 404-antwoorde met `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, of `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-antwoorde met `AA=true` en `TXT "OK"` vir kort navrae onder verdagte domeine.<sup>[[4]](#references)</sup>
- GitHub API-verkeer na `/repos/<owner>/<repo>/issues`, gevolg deur `ipinfo.io`-navrae vanaf dieselfde loader/beacon-ketting.<sup>[[5]](#references)</sup>
- Opstart-.lnk in gebruiker- of algemene Startup-lêergidse.<sup>[[1]](#references)</sup>
- Verdagte Run-sleutels (bv. "Updater") en loadername soos update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Getrojaniseerde PE-samples wat `_security_init_cookie` na aflaaikode herlei voordat ’n lokdokument vertoon word.<sup>[[5]](#references)</sup>
- DLL-paaie wat deur gebruikers geskryf kan word onder %APPDATA%\Microsoft\Windows\Templates en msimg32.dll bevat.<sup>[[1]](#references)</sup>

## Aantekeninge oor OpSec-velde

- KillDate: tydstempel waarna die agent self verval.<sup>[[1]](#references)</sup>
- WorkingTime: ure waartydens die agent aktief moet wees om by besigheidsaktiwiteit in te pas.<sup>[[1]](#references)</sup>

Hierdie velde kan vir groepering gebruik word en help om waargenome stil tydperke te verklaar.

## YARA en statiese leidrade

Unit 42 het basiese YARA-reëls vir beacons (C/C++ en Go) en loader-API-hashingkonstantes gepubliseer.<sup>[[1]](#references)</sup> Oorweeg dit om dit aan te vul met reëls wat soek na die [size|ciphertext|16-byte-key]-uitleg naby die einde van PE .rdata, die verstek-HTTP-profielstringe en nuwer bediener-/listener-merkers soos `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` en `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: ’n Nuwe oopbronraamwerk wat in werklike aanvalle benut word (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework-dokumentasie](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Vingerafdrukke van ’n oopbron-C2-raamwerk op groot skaal (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper wend hom tot AdaptixC2 en ’n pasgemaakte Beacon-listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Geheuebeskermingskonstantes – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Register-Run-sleutels/Startup-lêergids](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
