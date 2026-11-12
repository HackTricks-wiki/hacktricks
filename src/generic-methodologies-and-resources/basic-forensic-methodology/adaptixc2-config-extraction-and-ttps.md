# AdaptixC2-konfigurasie-ekstraksie en TTP's

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 is ’n modulêre, oopbron post-exploitation/C2-raamwerk met Windows x86/x64-beacons (EXE/DLL/service EXE/raw shellcode) en BOF-ondersteuning.<sup>[[1]](#references)</sup> Hierdie bladsy dokumenteer:
- Hoe die RC4-verpakte konfigurasie ingebed is en hoe om dit uit beacons te onttrek
- Netwerk-/profiel-aanwysers vir HTTP/SMB/TCP-listeners
- Algemene loader- en persistence-TTP's wat in die natuur waargeneem is, met skakels na relevante Windows-tegniekbladsye

Onlangse upstream-vrystellings sluit ook DNS/DoH-beacon-listeners en die afsonderlike Gopher-agent-/listenerfamilie in. Moderne Adaptix-infrastruktuur kan dus meer as die oorspronklike HTTP/SMB/TCP-oppervlakke blootstel, selfs wanneer ’n spesifieke sample steeds die klassieke beacon-agent gebruik.<sup>[[2]](#references)</sup>

## Beacon-profiele en velde

AdaptixC2 ondersteun drie primêre beacontipes:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web-C2 met konfigureerbare servers/poorte/SSL, metode, URI, headers, user-agent en ’n pasgemaakte parameternaam
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direkte sockets, opsioneel met ’n voorafgevoegde merker om die protokolbegin te verdoesel

Dit is die beacon-uitlegte wat in vroeë Adaptix-ontledings in die openbaar gedokumenteer is, en dit is steeds die algemeenste beginpunt vir ekstraksie aan die sample-kant.<sup>[[1]](#references)</sup> Huidige upstream-bouweergawes sluit egter ook `BeaconDNS`- en Gopher-uitbreidings aan die bedienerkant in; moenie dus aanvaar dat elke lewendige Adaptix-ontplooiing net HTTP/SMB/TCP-infrastruktuur blootstel nie.<sup>[[2]](#references)</sup>

Die volgende veldopsomming en JSON-voorbeelde beskryf die HTTP-formaat wat in 2025 ontleed is; dit is nie ’n parser-spesifikasie vir nuwer upstream-bouweergawes nie. Tipiese velde in daardie voorbeelde (ná dekripsie):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (lengtevoorafgaande strings)
- ans_pre_size (u32), ans_size (u32) – word gebruik om antwoordgroottes te parse
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Onlangse BeaconHTTP-bouweergawes ondersteun ook operateurgekose rotasie oor verskeie URI's, user-agents, Host-headers en servers, met opeenvolgende of ewekansige keuse.<sup>[[2]](#references)</sup> Vanuit ’n jagperspektief beteken dit dat ’n enkele besmette gasheer oor verskeie callback-paaie en header-kombinasies kan versprei sonder om die klassieke RC4-verpakte beacon-familie te verlaat.

Voorbeeld van ’n verstek-HTTP-profiel (uit ’n beacon-bou):<sup>[[1]](#references)</sup>

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

## Geënkripteerde konfigurasiepakking en laaipad

Wanneer die operator in die builder op Create klik, stel AdaptixC2 die geënkripteerde profiel in die beacon saam. Moenie aanvaar dat dit aan die einde van die PE of shellcode is nie: vind die profielgrepe deur ’n afdeling te skandeer of deur `getProfile()` in die voorbeeld te volg. Die gepakte formaat is:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 grepe: konfigurasiegrootte (uint32, little-endian)
- N grepe: RC4-geënkripteerde konfigurasiedata
- 16 grepe: RC4-sleutel

Die beacon-laaier kopieer die 16-greep-sleutel vanaf die einde en RC4-dekripteer die N-greep-blok in plek:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Praktiese implikasies:<sup>[[1]](#references)</sup>
- Die hele struktuur is dikwels in die PE .rdata-afdeling.
- Onttrekking is deterministies: lees die grootte, lees die syfertekskripsie van daardie grootte, lees die 16-greep-sleutel wat onmiddellik daarna geplaas is, en dekripteer dan met RC4.

## Konfigurasie-onttrekkingswerkvloei (verdedigers)

Vir algemene monstertriage voordat die beacon uitgekerf word, sien [Malware Analysis](malware-analysis.md).

Skryf ’n onttrekker wat die beacon-logika naboots:<sup>[[1]](#references)</sup>
1) Vind die blob in die PE (gewoonlik .rdata). ’n Praktiese benadering is om .rdata vir ’n geloofwaardige [grootte|syfertekskripsie|16-greep-sleutel]-uitleg te deursoek en RC4 te probeer.
2) Lees die eerste 4 grepe → grootte (uint32 LE).
3) Lees die volgende N=grootte grepe → syfertekskripsie.
4) Lees die laaste 16 grepe → RC4-sleutel.
5) Dekripteer die syfertekskripsie met RC4. Ontleed dan die gewone profiel as:
   - u32/boolean-skalare soos hierbo aangedui
   - lengtevoorafgegaande stringe (u32-lengte gevolg deur grepe; ’n afsluitende NUL kan voorkom)
   - skikkings: servers_count gevolg deur soveel [string, u32-poort]-pare

Legacy HTTP Python-bewys-van-konsep (selfstandig, geen eksterne afhanklikhede nie) vir ’n vooraf onttrekte blob in die veldvolgorde van 2025. Gebruik die huidige-skema-ontleder hieronder vir onlangse standaardbouweergawes:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Ontleed huidige standaard HTTP- en DNS-profiele

Die huidige upstream-pakket bevat eerste ses little-endian `u32`-waardes: agent-watermerk/-tipe, kill date, werktyd, slaaptyd, jitter en listener-watermerk/-tipe. Die HTTP-spesifieke data begin dan met ’n SSL-vlag van een byte. Anders as die legacy-voorbeeld, bevat dit URI-, user-agent- en Host-header-lyste met tellings, gevolg deur rotasiemodus en proxy-instellings. Die legacy-parser begin dus die SSL-vlag vanaf die kill date-veld lees en lewer verkeerde resultate op hierdie weergawes. Stringlengtes en heelgetalwaardes in hierdie profiel gebruik little-endian-kodering; gepakte stringe sluit ’n afsluitende NUL in wanneer hulle nie leeg is nie.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Gebruik die `P`- en `rc4`-helpers hierbo met hierdie parser op ontsyferde **standaard HTTP**-plaintext. Hou die RC4-sleutel uit openbare verslae: die HTTP-profiel kan ’n proxy-gebruikersnaam en -wagwoord bevat.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Ontleed ’n huidige standaard HTTP-plaintext-profiel</summary>

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

Vir ’n standaard DNS beacon, lees dieselfde ses algemene `u32`-velde, gevolg deur die lengtevoorafgegaande `domain`-, `resolvers`-, `doh_resolvers`- en `qtype`-stringe. Lees `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` en `dns_mode` as `u32`, en dan die lengtevoorafgegane DoH user-agent-string. `dns_mode` onderskei UDP, DoH en die twee terugvalrigtings. Dit is ’n afsonderlike uitleg: moenie DNS-plaintext deur die HTTP-parser dwing nie.<sup>[[12]](#references)[[13]](#references)</sup>

Wenke:
- Wanneer jy outomatiseer, gebruik ’n PE-parser om `.rdata` te lees en pas dan ’n skuifvenster toe: probeer vir elke offset o `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, en `candidate key = next 16 bytes`; dekripteer met RC4 en kyk of stringvelde as UTF-8 dekodeer en die lengtes redelik is.
- Ontleed SMB/TCP-profiele deur dieselfde lengtevoorafgegane konvensies te volg.

## Pasgemaakte listener-profiele: moenie net die klassieke HTTP-skema hardkodeer nie

Die buitenste pakformaat (`u32 size | RC4 ciphertext | 16-byte key`) is herbruikbaar, dus kan akteur-aangepaste listeners dieselfde ekstraksiewerkvloei behou terwyl die gedekripteerde velduitleg heeltemal verander.

’n Goeie onlangse voorbeeld is die Tropic Trooper-veldtog van Maart 2026, waar die onttrekte Adaptix beacon nie ’n standaard HTTP/TCP-profiel bevat het nie. In plaas daarvan het die gedekripteerde blob GitHub-vervoerparameters gestoor, soos:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (byvoorbeeld `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Praktiese parserstrategie:
- Bespeur eers die buitenste RC4-blob presies soos gewoonlik.
- Vertak ná dekripsie op grond van sentinel-stringe en veldgeldigheid, eerder as om dadelik die HTTP-parser af te dwing.
- Goeie sentinels sluit in `api.github.com`, `/issues?state=open`, HTTP-werkwoorde/URI’s, stringe in named-pipe-styl of duidelik geldige bediener-/poort-skikkings.
- As die HTTP-parser misluk, maar die plaintext samehangende lengtevoorafgegane UTF-8-stringe bevat, behou die monster en probeer alternatiewe skemas eerder as om dit as ’n vals positiewe te verwerp.

In daardie veldtog het die pasgemaakte listener GitHub-issues as die C2-vervoerkanaal gebruik, en die beacon het `ipinfo.io` geraadpleeg om sy eksterne IP-adres te bepaal, omdat die GitHub API nie die slagoffer se bronadres direk aan die operateur openbaar nie.<sup>[[5]](#references)</sup> Sien [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md) vir ’n afsonderlike issue-plus-repository-file-handdruk.

## Netwerkvingerafdrukke en jag

HTTP:<sup>[[1]](#references)</sup>
- Algemeen: POST na URI’s wat deur die operateur gekies is (bv. /uri.php, /endpoint/api)
- Pasgemaakte header-parameter wat vir beacon-ID gebruik word (bv. X‑Beacon‑Id, X‑App‑Id)
- User-agents wat Firefox 20 of hedendaagse Chrome-weergawes naboots
- Peilingsfrekwensie sigbaar via sleep_delay/jitter_delay
- Nuwer builds kan URI’s, user-agents, Host-headers en bedieners tussen callbacks roteer; groepeer dus op grond van ongewone headername, reaksiegroottepatrone, TLS-hergebruik en tydsberekening, eerder as om ’n enkele pad/UA-paar te aanvaar.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe-listeners vir intranet-C2 waar webuitgaande verkeer beperk is
- TCP beacons kan ’n paar grepe voor verkeer plaas om die begin van die protokol te verdoesel

Huidige verstekwaardes van die upstream-teamserver
- `profile.yaml` word tans voorsien met teamserver `0.0.0.0:4321`, endpoint `/endpoint`, sertifikaat-/sleutellêername `server.rsa.crt` en `server.rsa.key`, en uitbreidings vir HTTP, SMB, TCP, DNS, Beacon-agent en Gopher.<sup>[[2]](#references)</sup>
- Vir roetes wat nie pas nie, stuur die verstekfouthanteerder `Server: AdaptixC2` en `Adaptix-Version: v1.2` terug.<sup>[[4]](#references)</sup>
- Die standaard 404-liggaam bevat `AdaptixC2 404` en `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Internetwye skanderings in 2026 het baie blootgestelde teamservers op `4321` en baie beacon-listeners op `43211` gevind; albei poorte is dus nuttige beginpunte vir verdere ondersoek, maar moet nie as volledig beskou word nie.<sup>[[4]](#references)</sup>

DNS/DoH-listener-vingerafdrukke:<sup>[[4]](#references)</sup>
- Die huidige BeaconDNS-uitbreiding antwoord gesaghebbend (`AA=true`)
- Navrae wat nie by die beacon-protokolvorm pas nie — veral name met minder as 5 etikette voor die ingestelde domein — kry gewoonlik die antwoord `TXT "OK"`
- As die ingestelde basis-TTL op nul gelaat word, gebruik die listener ’n basis van 10 sekondes en voeg dit tot 59 sekondes se jitter by
- Dit maak aktiewe probes met kort etikette nuttig wanneer geen HTTP-listener blootgestel is nie

## Loader- en volhardings-TTP’s wat in insidente waargeneem is

PowerShell-loaders in geheue:<sup>[[1]](#references)</sup>
- Laai Base64/XOR-payloads af (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Ken onbeheerde geheue toe, kopieer shellcode en verander beskerming na 0x40 (PAGE_EXECUTE_READWRITE) via VirtualProtect.<sup>[[7]](#references)</sup>
- Voer uit via .NET-dinamiese aanroeping: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Getrojaniseerde ondertekende sagteware / gefaseerde shellcode-loaders:<sup>[[5]](#references)</sup>
- ’n Tropic Trooper-ketting in 2026 het ’n getrojaniseerde SumatraPDF-uitvoerbare lêer (TOSHIS-loader) gebruik wat `_security_init_cookie` na kwaadwillige kode herlei het in plaas daarvan om die PE-ingangspunt te wysig
- Die loader het API’s deur Adler-32-hashing opgelos, ’n lok-PDF afgelaai, tweede-fase-shellcode verkry, dit met AES-128-CBC via WinCrypt gedekripteer (`CryptDeriveKey` vanaf ’n hardgekodeerde seed), en ’n Adaptix beacon reflektief in geheue uitgevoer
- Volharding is later na geskeduleerde take verskuif met onskuldig-lykende name soos `\MSDNSvc` of `\MicrosoftUDN`, wat ingestel is om die agent ongeveer elke twee uur weer te begin

Besoek hierdie bladsye vir oorwegings oor uitvoering in geheue en AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Waargenome volhardingsmeganismes:<sup>[[1]](#references)</sup>
- Kortpad in die Startup-lêergids (.lnk) om ’n loader by aanmelding weer te begin
- Registry Run-sleutels (HKCU/HKLM ...\CurrentVersion\Run), dikwels met onskuldig-lykende name soos "Updater" om loader.ps1 te begin.<sup>[[10]](#references)</sup>
- DLL-soekvolgorde-kaping deur msimg32.dll in %APPDATA%\Microsoft\Windows\Templates te plaas vir kwesbare prosesse

Tegniekverdiepings en kontroles:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Jagidees
- PowerShell-prosesse wat RW→RX-oorgange uitvoer: VirtualProtect na PAGE_EXECUTE_READWRITE binne powershell.exe.<sup>[[8]](#references)</sup>
- Patrone van dinamiese aanroeping (GetDelegateForFunctionPointer)
- Ongepaarde HTTPS 404’s met `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` of `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-antwoorde met `AA=true` en `TXT "OK"` vir kort navrae onder verdagte domeine.<sup>[[4]](#references)</sup>
- GitHub API-verkeer na `/repos/<owner>/<repo>/issues` gevolg deur `ipinfo.io`-navrae vanaf dieselfde loader-/beacon-ketting.<sup>[[5]](#references)</sup>
- Opstart-.lnk in gebruiker- of algemene Startup-lêergids.<sup>[[1]](#references)</sup>
- Verdagte Run-sleutels (bv. "Updater") en loadername soos update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Getrojaniseerde PE-monsters wat `_security_init_cookie` na aflaaikode herlei voordat ’n lokdokument vertoon word.<sup>[[5]](#references)</sup>
- Gebruiker-skryfbare DLL-paaie onder %APPDATA%\Microsoft\Windows\Templates wat msimg32.dll bevat.<sup>[[1]](#references)</sup>

## Aantekeninge oor OpSec-velde

- KillDate: tydstempel waarna die agent self verval.<sup>[[1]](#references)</sup>
- WorkingTime: ure wanneer die agent aktief moet wees om by sakebedrywighede in te pas.<sup>[[1]](#references)</sup>

Hierdie velde kan vir groepering gebruik word en help om waargenome stil periodes te verduidelik.

## YARA en statiese leidrade

Unit 42 het basiese YARA vir beacons (C/C++ en Go) en loader-API-hashing-konstantes gepubliseer.<sup>[[1]](#references)</sup> Oorweeg dit om dit aan te vul met reëls wat soek na die [size|ciphertext|16-byte-key]-uitleg naby die einde van PE .rdata, die verstek-HTTP-profielstringe en nuwer bediener-/listener-merkers soos `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` en `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: ’n Nuwe oopbronraamwerk wat in werklike aanvalle gebruik word (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix-raamwerkdokumentasie](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Vingerafdrukke van ’n oopbron-C2-raamwerk op skaal (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper wend hom tot AdaptixC2 en ’n pasgemaakte Beacon-listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Geheuebeskermingskonstantes – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run-sleutels/Startup-lêergids](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2-profielgenerering (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2-beaconprofielparser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS-profielgenerering (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2-profielpakking (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
