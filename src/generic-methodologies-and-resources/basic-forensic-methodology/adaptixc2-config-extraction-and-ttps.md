# AdaptixC2 Utoaji wa Configuration na TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ni framework ya post-exploitation/C2 ya modular na open-source, yenye beacons za Windows x86/x64 (EXE/DLL/service EXE/raw shellcode) na usaidizi wa BOF.<sup>[[1]](#references)</sup> Ukurasa huu unaeleza:
- Jinsi configuration iliyopakiwa kwa RC4 inavyopachikwa na jinsi ya kuitoa kutoka kwa beacons
- Viashiria vya mtandao/profile vya HTTP/SMB/TCP listeners
- TTPs za kawaida za loader na persistence zinazoonekana porini, pamoja na viungo vya kurasa husika za Windows techniques

Matoleo ya hivi karibuni ya upstream pia husambazwa na DNS/DoH beacon listeners na familia tofauti ya Gopher agent/listener, kwa hivyo miundombinu ya kisasa ya Adaptix inaweza kufichua zaidi ya miingiliano ya awali ya HTTP/SMB/TCP, hata kama sample fulani bado inatumia classic beacon agent.<sup>[[2]](#references)</sup>

## Profaili na sehemu za beacon

AdaptixC2 inasaidia aina tatu kuu za beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 yenye servers/ports/SSL, method, URI, headers, user-agent, na jina la custom parameter vinavyoweza kusanidiwa
- BEACON_SMB: C2 ya peer-to-peer inayotumia named-pipe (intranet)
- BEACON_TCP: sockets za moja kwa moja, zenye uwezekano wa kuongezewa marker mwanzoni ili kuficha mwanzo wa protocol

Hizi ndizo layouts za beacon zilizoandikwa hadharani katika uchanganuzi wa awali wa Adaptix na bado ndizo sehemu za kawaida za kuanzia kwa utoaji wa taarifa kutoka upande wa sample.<sup>[[1]](#references)</sup> Hata hivyo, builds za sasa za upstream pia husambazwa na BeaconDNS na Gopher extenders upande wa server, kwa hivyo usidhani kila deployment hai ya Adaptix hufichua miundombinu ya HTTP/SMB/TCP pekee.<sup>[[2]](#references)</sup>

Sehemu za kawaida za profile zinazoonekana katika HTTP beacon configs (baada ya decryption):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – hutumika kuchanganua ukubwa wa response
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Builds za hivi karibuni za BeaconHTTP pia zinaunga mkono operator kuchagua mzunguko wa kutumia URIs nyingi, user-agents, Host headers na servers, kwa mpangilio wa mfuatano au wa nasibu.<sup>[[2]](#references)</sup> Kwa mtazamo wa hunting, hii inamaanisha host moja iliyoambukizwa inaweza kusambaza callbacks zake kupitia njia kadhaa na mchanganyiko wa headers, bila kuacha familia ya kawaida ya beacon iliyopakiwa kwa RC4.

Mfano wa default HTTP profile (kutoka kwa build ya beacon):<sup>[[1]](#references)</sup>

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

Wasifu hasidi wa HTTP ulioonekana (shambulio halisi):<sup>[[1]](#references)</sup>

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

## Upakiaji wa configuration iliyosimbwa kwa njia fiche na njia ya kuipakia

Operator anapobofya Create kwenye builder, AdaptixC2 huweka profile iliyosimbwa kwa njia fiche kama tail blob ndani ya beacon. Muundo ni:<sup>[[1]](#references)</sup>
- Baiti 4: ukubwa wa configuration (uint32, little‑endian)
- Baiti N: data ya configuration iliyosimbwa kwa RC4
- Baiti 16: ufunguo wa RC4

Loader ya beacon hunakili ufunguo wa baiti 16 kutoka mwisho na kusimbua kwa RC4 bloku ya baiti N mahali pake:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Athari za kiutendaji:<sup>[[1]](#references)</sup>
- Muundo mzima mara nyingi huwa ndani ya sehemu ya PE .rdata.
- Uchimbuzi ni wa kuaminika: soma ukubwa, soma ciphertext yenye ukubwa huo, soma ufunguo wa biti 16 uliowekwa mara moja baada yake, kisha fanya RC4-decrypt.

## Mtiririko wa kazi wa uchimbuzi wa usanidi (watetezi)

Andika extractor inayoiga mantiki ya beacon:<sup>[[1]](#references)</sup>
1) Tafuta blob ndani ya PE (mara nyingi .rdata). Mbinu ya vitendo ni kuchanganua .rdata kutafuta mpangilio unaowezekana wa [size|ciphertext|16-byte key] na kujaribu RC4.
2) Soma baiti 4 za kwanza → size (uint32 LE).
3) Soma baiti N zinazofuata, ambapo N=size → ciphertext.
4) Soma baiti 16 za mwisho → ufunguo wa RC4.
5) Fanya RC4-decrypt ya ciphertext. Kisha changanua profile iliyo wazi kama:
   - scalar za u32/boolean kama ilivyoelezwa hapo juu
   - strings zenye urefu ulioainishwa mwanzoni (urefu wa u32 ukifuatiwa na baiti; NUL ya mwisho inaweza kuwepo)
   - arrays: servers_count ikifuatiwa na jozi nyingi hivyo za [string, u32 port]

Python proof-of-concept ndogo kabisa (inayojitegemea, bila vitegemezi vya nje) inayofanya kazi na blob iliyotolewa awali:

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
- Unapo-automate, tumia PE parser kusoma .rdata kisha utumie sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; dekripsi kwa RC4 kisha uhakikishe kuwa sehemu za string zina-decodiwa kama UTF-8 na urefu wake uko katika viwango vinavyofaa.
- Parse profaili za SMB/TCP kwa kufuata kanuni zilezile za urefu ulioambatishwa.

## Profaili maalum za listener: usiweke msimbo mgumu kwa schema ya kawaida ya HTTP pekee

Muundo wa nje wa upakiaji (`u32 size | RC4 ciphertext | 16-byte key`) unaweza kutumika tena, hivyo listeners zilizobinafsishwa na wahusika zinaweza kutumia workflow ileile ya uchimbaji huku zikibadilisha kabisa mpangilio wa sehemu zilizodecryptiwa.

Mfano mzuri wa hivi karibuni ni kampeni ya Tropic Trooper ya Machi 2026, ambapo Adaptix beacon iliyochimbuliwa haikuwa na profaili ya kawaida ya HTTP/TCP. Badala yake, blob iliyodecryptiwa ilihifadhi vigezo vya usafirishaji vya GitHub kama vile:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (kwa mfano `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Mkakati wa vitendo wa parser:
- Kwanza tambua blob ya nje ya RC4 kama kawaida.
- Baada ya decryption, chagua njia kulingana na sentinel strings na uhalali wa sehemu, badala ya kulazimisha parser ya HTTP mara moja.
- Sentinel nzuri ni pamoja na `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, string zinazofanana na named pipe, au arrays za server/port zinazoonekana kuwa halali.
- Ikiwa parser ya HTTP itashindwa lakini plaintext ina string za UTF-8 zenye urefu ulioambatishwa zinazoeleweka, hifadhi sample na ujaribu schema mbadala badala ya kuitupa kama false positive.

Katika kampeni hiyo, listener maalum ilitumia GitHub issues kama usafirishaji wa C2, na beacon iliuliza `ipinfo.io` ili kujua IP yake ya nje kwa sababu GitHub API haionyeshi moja kwa moja anwani chanzo ya mwathiriwa kwa operator.<sup>[[5]](#references)</sup>

## Utambuzi wa alama za mtandao na utafutaji wa vitisho

HTTP:<sup>[[1]](#references)</sup>
- Ya kawaida: POST kwa URI zilizochaguliwa na operator (kwa mfano, /uri.php, /endpoint/api)
- Kigezo maalum cha header kinachotumika kwa beacon ID (kwa mfano, X‑Beacon‑Id, X‑App‑Id)
- User-agent zinazoiga Firefox 20 au matoleo ya sasa ya Chrome
- Mzunguko wa polling unaoonekana kupitia sleep_delay/jitter_delay
- Matoleo mapya yanaweza kubadilisha URI, user-agent, Host headers na servers kati ya callback, kwa hiyo vikundi vitengeneze kwa kutumia majina ya header yasiyo ya kawaida, mifumo ya ukubwa wa majibu, matumizi tena ya TLS na muda badala ya kudhani kuna jozi moja tu ya path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners za SMB named-pipe kwa C2 ya intranet ambako ufikiaji wa nje kupitia web umezuiwa
- TCP beacons zinaweza kuongeza baiti chache kabla ya trafiki ili kuficha mwanzo wa protocol

Mipangilio chaguomsingi ya sasa ya upstream teamserver
- `profile.yaml` kwa sasa huja na teamserver `0.0.0.0:4321`, endpoint `/endpoint`, majina ya faili za certificate/key `server.rsa.crt` na `server.rsa.key`, na extenders za HTTP, SMB, TCP, DNS, Beacon agent na Gopher.<sup>[[2]](#references)</sup>
- Kwa routes zisizolingana, error handler chaguomsingi hurudisha `Server: AdaptixC2` na `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Mwili wa kawaida wa 404 una `AdaptixC2 404` na `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Scans za mtandao mzima mwaka 2026 ziligundua teamservers nyingi zilizo wazi kwenye `4321` na beacon listeners nyingi kwenye `43211`, kwa hiyo ports zote mbili ni pivots nzuri za kuanzia lakini hazipaswi kuchukuliwa kuwa ndizo pekee.<sup>[[4]](#references)</sup>

Alama za DNS/DoH listener:<sup>[[4]](#references)</sup>
- Extender ya sasa ya BeaconDNS hujibu kwa mamlaka (`AA=true`)
- Maswali yasiyolingana na muundo wa protocol ya beacon — hasa majina yenye labels chini ya 5 kabla ya domain iliyosanidiwa — mara nyingi hujibiwa kwa `TXT "OK"`
- Ikiwa TTL ya msingi iliyosanidiwa itaachwa sifuri, listener hutumia msingi wa sekunde 10 na kuongeza hadi sekunde 59 za jitter
- Hii hufanya probes amilifu zenye labels fupi kuwa muhimu wakati hakuna HTTP listener iliyo wazi

## Loader na TTP za persistence zilizoonekana kwenye matukio

Loaders za PowerShell zinazoendeshwa kwenye memory:<sup>[[1]](#references)</sup>
- Hupakua payload za Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Hutenga memory isiyosimamiwa, kunakili shellcode, kubadilisha ulinzi kuwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect.<sup>[[7]](#references)</sup>
- Hutekeleza kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software iliyotiwa Trojan na kusainiwa / loaders za shellcode za hatua kwa hatua:<sup>[[5]](#references)</sup>
- Mlolongo wa Tropic Trooper wa 2026 ulitumia executable ya SumatraPDF iliyotiwa Trojan (TOSHIS loader) iliyoelekeza `_security_init_cookie` kwenye msimbo hasidi badala ya kurekebisha sehemu ya kuanzia ya PE
- Loader ilitatua APIs kwa kutumia Adler-32 hashing, ikapakua PDF ya chambo, ikachukua shellcode ya hatua ya pili, ikaidecrypt kwa AES-128-CBC kupitia WinCrypt (`CryptDeriveKey` kutoka seed iliyowekwa moja kwa moja kwenye msimbo), kisha ikatekeleza Adaptix beacon kwa reflection ndani ya memory
- Baadaye persistence ilihamia kwenye scheduled tasks zenye majina yanayoonekana ya kawaida kama `\MSDNSvc` au `\MicrosoftUDN`, zilizosanidiwa kumzindua tena agent takribani kila baada ya saa mbili

Angalia kurasa hizi kuhusu utekelezaji ndani ya memory na mambo ya kuzingatia ya AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mbinu za persistence zilizoonekana:<sup>[[1]](#references)</sup>
- Njia ya mkato ya Startup folder (.lnk) ya kumzindua tena loader mtumiaji anapoingia
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na majina yanayoonekana ya kawaida kama "Updater" ili kuanzisha loader.ps1.<sup>[[10]](#references)</sup>
- Utekaji wa mpangilio wa utafutaji wa DLL kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa michakato iliyo hatarini

Uchunguzi wa kina wa mbinu na ukaguzi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Mawazo ya utafutaji wa vitisho
- PowerShell inayoanzisha mabadiliko ya RW→RX: VirtualProtect hadi PAGE_EXECUTE_READWRITE ndani ya powershell.exe.<sup>[[8]](#references)</sup>
- Miundo ya dynamic invocation (GetDelegateForFunctionPointer)
- Majibu ya HTTPS 404 yasiyolingana yenye `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, au `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Majibu ya DNS yenye `AA=true` na `TXT "OK"` kwa maswali mafupi chini ya domains zinazotiliwa shaka.<sup>[[4]](#references)</sup>
- Trafiki ya GitHub API kwenda `/repos/<owner>/<repo>/issues` ikifuatiwa na maombi ya `ipinfo.io` kutoka kwa mlolongo huohuo wa loader/beacon.<sup>[[5]](#references)</sup>
- .lnk ya Startup chini ya folda za Startup za mtumiaji au za pamoja.<sup>[[1]](#references)</sup>
- Run keys zinazotiliwa shaka (kwa mfano, "Updater"), na majina ya loader kama update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Sample za PE zilizotiwa Trojan zinazoelekeza `_security_init_cookie` kwenye msimbo wa kupakua kabla ya kuonyesha hati ya chambo.<sup>[[5]](#references)</sup>
- Njia za DLL zinazoweza kuandikwa na mtumiaji chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll.<sup>[[1]](#references)</sup>

## Maelezo kuhusu sehemu za OpSec

- KillDate: muhuri wa wakati ambao ukishapita agent hujizima yenyewe.<sup>[[1]](#references)</sup>
- WorkingTime: saa ambazo agent inapaswa kuwa hai ili ichanganyike na shughuli za biashara.<sup>[[1]](#references)</sup>

Sehemu hizi zinaweza kutumiwa kupanga sampuli katika makundi na kueleza vipindi vya ukimya vilivyoonekana.

## YARA na vidokezo vya uchanganuzi tuli

Unit 42 ilichapisha YARA ya msingi kwa beacons (C/C++ na Go) na constants za API-hashing za loader.<sup>[[1]](#references)</sup> Fikiria kuiongezea kwa rules zinazotafuta mpangilio wa [size|ciphertext|16-byte-key] karibu na mwisho wa PE .rdata, string za profaili ya kawaida ya HTTP, na alama mpya za server/listener kama `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, na `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Mfumo Mpya wa Open-Source Unaotumiwa katika Mashambulizi Halisi (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Nyaraka za Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Kutambua Mfumo wa C2 wa Open-Source kwa Kiwango Kikubwa (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Yahamia AdaptixC2 na Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constants za ulinzi wa memory – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
