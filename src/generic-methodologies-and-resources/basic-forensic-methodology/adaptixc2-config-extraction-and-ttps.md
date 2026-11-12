# Uchimbuzi wa Usanidi wa AdaptixC2 na TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 ni framework ya post-exploitation/C2 ya chanzo-wazi na yenye moduli, yenye Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) na usaidizi wa BOF.<sup>[[1]](#references)</sup> Ukurasa huu unaeleza:
- Jinsi usanidi wake uliopakiwa kwa RC4 unavyopachikwa na jinsi ya kuuchimbua kutoka kwa beacons
- Viashiria vya mtandao/profile vya HTTP/SMB/TCP listeners
- TTPs za kawaida za loader na persistence zinazoonekana porini, pamoja na viungo vya kurasa husika za mbinu za Windows

Matoleo ya hivi karibuni ya upstream pia hujumuisha DNS/DoH beacon listeners na familia tofauti ya Gopher agent/listener, kwa hiyo miundombinu ya kisasa ya Adaptix inaweza kufichua zaidi ya nyuso asili za HTTP/SMB/TCP, hata wakati sample maalum bado inatumia beacon agent ya kawaida.<sup>[[2]](#references)</sup>

## Beacon profiles na sehemu zake

AdaptixC2 inasaidia aina tatu kuu za beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: web C2 yenye seva/ports/SSL zinazoweza kusanidiwa, method, URI, headers, user-agent na jina la parameter maalum
- BEACON_SMB: peer-to-peer C2 ya named-pipe (intranet)
- BEACON_TCP: direct sockets, zenye uwezekano wa kuweka marker mwanzoni ili kuficha mwanzo wa protocol

Hizi ndizo beacon layouts zilizoandikwa hadharani katika uchanganuzi wa awali wa Adaptix, na bado ndizo mwanzo wa kawaida zaidi wa uchimbuzi upande wa sample.<sup>[[1]](#references)</sup> Hata hivyo, builds za sasa za upstream pia hujumuisha `BeaconDNS` na Gopher extenders upande wa server, kwa hiyo usidhani kila deployment hai ya Adaptix hufichua miundombinu ya HTTP/SMB/TCP pekee.<sup>[[2]](#references)</sup>

Muhtasari ufuatao wa sehemu na JSON samples unaeleza format ya HTTP iliyochanganuliwa mwaka 2025; si specification ya parser kwa builds mpya zaidi za upstream. Sehemu za kawaida katika samples hizo (baada ya decryption):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – hutumika kuchanganua ukubwa wa majibu
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Builds za hivi karibuni za BeaconHTTP pia zinaunga mkono rotation inayochaguliwa na operator kati ya URIs, user-agents, Host headers na servers nyingi, kwa uteuzi wa mfuatano au wa nasibu.<sup>[[2]](#references)</sup> Kwa mtazamo wa hunting, hii inamaanisha host moja iliyoambukizwa inaweza kutumia njia kadhaa za callback na mchanganyiko wa headers bila kuacha familia ya beacon ya kawaida iliyopakiwa kwa RC4.

Mfano wa HTTP profile chaguomsingi (kutoka kwa beacon build):<sup>[[1]](#references)</sup>

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

## Upakiaji wa configuration iliyosimbwa na njia ya kuipakia

Operator anapobofya Create kwenye builder, AdaptixC2 hukusanya profile iliyosimbwa ndani ya beacon. Usidhani kuwa iko mwishoni mwa PE au shellcode: tafuta bytes za profile kwa kuchanganua sections au kwa kufuatilia `getProfile()` kwenye sample. Umbizo lililopakiwa ni:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- Bytes 4: ukubwa wa configuration (uint32, little-endian)
- Bytes N: data ya configuration iliyosimbwa kwa RC4
- Bytes 16: ufunguo wa RC4

Beacon loader hunakili ufunguo wa bytes 16 kutoka mwisho kisha hutumia RC4 kufungua block ya bytes N mahali pake:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Athari za kiutendaji:<sup>[[1]](#references)</sup>
- Muundo mzima mara nyingi huwa ndani ya sehemu ya PE .rdata.
- Utoaji ni wa moja kwa moja: soma ukubwa, soma ciphertext yenye ukubwa huo, soma ufunguo wa baiti 16 uliowekwa mara moja baada yake, kisha tekeleza RC4-decrypt.

## Mtiririko wa kazi wa kutoa usanidi (watetezi)

Kwa uchunguzi wa jumla wa sampuli kabla ya kutoa beacon, tazama [Malware Analysis](malware-analysis.md).

Andika extractor inayoiga mantiki ya beacon:<sup>[[1]](#references)</sup>
1) Tafuta blob ndani ya PE (kwa kawaida .rdata). Mbinu ya vitendo ni kuchanganua .rdata ili kupata mpangilio unaowezekana wa [size|ciphertext|16-byte key] na kujaribu RC4.
2) Soma baiti 4 za kwanza → size (uint32 LE).
3) Soma baiti N=size zinazofuata → ciphertext.
4) Soma baiti 16 za mwisho → ufunguo wa RC4.
5) Tekeleza RC4-decrypt kwenye ciphertext. Kisha changanua wasifu wa maandishi wazi kama ifuatavyo:
   - scalars za u32/boolean kama ilivyoelezwa hapo juu
   - strings zenye urefu uliotangulizwa (urefu wa u32 ukifuatiwa na baiti; NUL ya mwisho inaweza kuwepo)
   - arrays: servers_count ikifuatiwa na idadi hiyo ya jozi za [string, u32 port]

Proof-of-concept ya Python ya Legacy HTTP (inayojitegemea, haina utegemezi wa nje) kwa blob iliyotolewa awali kwa mpangilio wa sehemu wa 2025. Tumia parser ya current-schema iliyo hapa chini kwa builds za hivi karibuni za stock:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Changanua HTTP na DNS profiles za sasa zinazotolewa kwa chaguo-msingi

Upstream ya sasa huweka kwanza thamani sita za `u32` za little-endian: watermark/type ya agent, kill date, working time, sleep, jitter, na watermark/type ya listener. Data mahususi ya HTTP huanza na flag ya SSL ya baiti moja. Tofauti na mfano wa zamani, ina orodha zenye idadi maalum za URI, user-agent, na vichwa vya Host, zikifuatiwa na hali ya mzunguko na mipangilio ya proxy. Kwa hiyo, parser ya zamani huanza kusoma flag ya SSL kutoka kwenye sehemu ya kill-date na kutoa matokeo yasiyo sahihi kwenye builds hizi. Urefu wa string na thamani za integer katika profile hii hutumia encoding ya little-endian; strings zilizopakiwa huwa na NUL ya mwisho zinapokuwa si tupu.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Kwa kutumia helpers za `P` na `rc4` zilizo hapo juu, tumia parser hii kwenye plaintext ya **HTTP ya kawaida** iliyosimbuliwa. Usiweke RC4 key kwenye ripoti za umma: HTTP profile inaweza kuwa na jina la mtumiaji na nenosiri la proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Changanua profile ya sasa ya plaintext ya HTTP ya kawaida</summary>

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

Kwa DNS beacon ya kawaida, soma fields sita za kawaida za `u32`, kisha strings za `domain`, `resolvers`, `doh_resolvers`, na `qtype` zenye urefu uliotangulia. Soma `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter`, na `dns_mode` kama `u32`, kisha string ya DoH user-agent yenye urefu uliotangulia. `dns_mode` hutofautisha UDP, DoH, na mielekeo miwili ya fallback. Huu ni mpangilio tofauti: usilazimishe maandishi ya DNS kupitia parser ya HTTP.<sup>[[12]](#references)[[13]](#references)</sup>

Vidokezo:
- Unapo-automate, tumia PE parser kusoma .rdata kisha utumie sliding window: kwa kila offset o, jaribu size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = next 16 bytes; fanya RC4-decrypt na uhakikishe kuwa string fields zina-decodiwa kama UTF-8 na urefu wake ni wa maana.
- Parse profaili za SMB/TCP kwa kufuata kanuni zilezile za length-prefixed.

## Profaili maalum za listener: usiweke kwenye code schema ya kawaida ya HTTP pekee

Muundo wa nje wa packing (`u32 size | RC4 ciphertext | 16-byte key`) unaweza kutumika tena, kwa hiyo listener zilizobinafsishwa na actor zinaweza kuendelea kutumia workflow ileile ya extraction huku zikibadilisha kabisa mpangilio wa fields baada ya decryption.

Mfano mzuri wa hivi karibuni ni kampeni ya Tropic Trooper ya Machi 2026, ambapo Adaptix beacon iliyotolewa haikuwa na profaili ya kawaida ya HTTP/TCP. Badala yake, blob iliyofanyiwa decryption ilihifadhi vigezo vya usafirishaji vya GitHub kama vile:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (kwa mfano `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Mkakati wa vitendo wa parser:
- Kwanza gundua blob ya nje ya RC4 kama kawaida kabisa.
- Baada ya decryption, chagua parser kulingana na sentinel strings na uhalali wa fields badala ya kulazimisha mara moja parser ya HTTP.
- Sentinel nzuri ni pamoja na `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, strings zinazofanana na named pipe, au arrays za server/port zinazoonekana kuwa halali.
- Ikiwa parser ya HTTP itashindwa lakini plaintext ina strings za UTF-8 zenye urefu uliotangulia na zinazoeleweka, hifadhi sample na ujaribu schema mbadala badala ya kuitupa kama false positive.

Katika kampeni hiyo, listener maalum ilitumia GitHub issues kama usafirishaji wa C2, na beacon iliuliza `ipinfo.io` ili kujua IP yake ya nje kwa sababu GitHub API haionyeshi moja kwa moja anwani ya chanzo ya victim kwa operator.<sup>[[5]](#references)</sup> Kwa handshake tofauti inayotumia issue pamoja na repository file, tazama [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Fingerprinting na utafutaji kwenye mtandao

HTTP:<sup>[[1]](#references)</sup>
- Ya kawaida: POST kwenda kwenye URI zilizochaguliwa na operator (kwa mfano, /uri.php, /endpoint/api)
- Custom header parameter inayotumika kwa beacon ID (kwa mfano, X‑Beacon‑Id, X‑App‑Id)
- User-agent zinazoiga Firefox 20 au matoleo ya kisasa ya Chrome
- Muda wa polling unaoonekana kupitia sleep_delay/jitter_delay
- Builds mpya zaidi zinaweza kubadilisha URI, user-agent, Host headers, na servers kati ya callbacks, kwa hiyo panga kwa kutumia majina ya header yasiyo ya kawaida, mifumo ya ukubwa wa majibu, matumizi tena ya TLS, na muda badala ya kudhani kuwa kuna jozi moja tu ya path/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener za SMB named-pipe kwa C2 ya intranet pale ambapo web egress ina vikwazo
- TCP beacons zinaweza kuweka bytes chache kabla ya traffic ili kuficha mwanzo wa protocol

Mipangilio chaguomsingi ya sasa ya upstream teamserver
- `profile.yaml` kwa sasa huja na teamserver `0.0.0.0:4321`, endpoint `/endpoint`, majina ya faili za certificate/key `server.rsa.crt` na `server.rsa.key`, pamoja na extenders za HTTP, SMB, TCP, DNS, Beacon agent, na Gopher.<sup>[[2]](#references)</sup>
- Kwa routes zisizolingana, error handler chaguomsingi hurudisha `Server: AdaptixC2` na `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Mwili chaguomsingi wa 404 una `AdaptixC2 404` na `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Scans za mtandao mzima mwaka 2026 ziligundua teamservers nyingi zilizo wazi kwenye `4321` na listener nyingi za beacon kwenye `43211`, kwa hiyo ports zote mbili ni sehemu nzuri za kuanzia utafutaji lakini hazipaswi kuchukuliwa kuwa ndizo pekee.<sup>[[4]](#references)</sup>

Alama za fingerprint za listener za DNS/DoH:<sup>[[4]](#references)</sup>
- Extender ya sasa ya BeaconDNS hujibu kwa mamlaka (`AA=true`)
- Queries zisizolingana na umbo la protocol ya beacon — hasa majina yenye labels chini ya 5 kabla ya domain iliyosanidiwa — mara nyingi hujibiwa kwa `TXT "OK"`
- Ikiwa TTL msingi uliosanidiwa utaachwa kuwa sifuri, listener hutumia msingi wa sekunde 10 na kuongeza hadi sekunde 59 za jitter
- Hii hufanya active probes zenye labels fupi kuwa muhimu pale ambapo hakuna listener ya HTTP iliyo wazi

## Loader na TTP za persistence zilizoonekana kwenye matukio

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Hupakua payload za Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Hutenga memory isiyodhibitiwa, hunakili shellcode, hubadilisha ulinzi kuwa 0x40 (PAGE_EXECUTE_READWRITE) kupitia VirtualProtect.<sup>[[7]](#references)</sup>
- Hutekeleza kupitia .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Software iliyotiwa Trojan na kusainiwa / staged shellcode loaders:<sup>[[5]](#references)</sup>
- Mnyororo wa Tropic Trooper wa 2026 ulitumia executable ya SumatraPDF iliyotiwa Trojan (TOSHIS loader) iliyoelekeza `_security_init_cookie` kwenye code hasidi badala ya kurekebisha PE entry point
- Loader ilitatua APIs kwa Adler-32 hashing, ikapakua PDF ya udanganyifu, ikapata shellcode ya hatua ya pili, ika-decrypt kwa AES-128-CBC kupitia WinCrypt (`CryptDeriveKey` kutoka seed iliyowekwa kwenye code), kisha ikatekeleza Adaptix beacon ndani ya memory kwa reflection
- Baadaye persistence ilihamishiwa kwenye scheduled tasks zenye majina yanayoonekana kutokuwa na madhara kama `\MSDNSvc` au `\MicrosoftUDN`, zilizosanidiwa kuwasha tena agent takriban kila baada ya saa mbili

Angalia kurasa hizi kwa masuala ya in-memory execution na AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Mbinu za persistence zilizoonekana:<sup>[[1]](#references)</sup>
- Njia ya mkato ya Startup folder (.lnk) ya kuwasha tena loader mtumiaji anapoingia
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), mara nyingi zikiwa na majina yanayoonekana kutokuwa na madhara kama "Updater" ili kuanzisha loader.ps1.<sup>[[10]](#references)</sup>
- DLL search-order hijack kwa kuweka msimg32.dll chini ya %APPDATA%\Microsoft\Windows\Templates kwa processes zinazoweza kuathiriwa

Maelezo ya kina ya techniques na ukaguzi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Mawazo ya hunting
- PowerShell ikianzisha mabadiliko ya RW→RX: VirtualProtect kwenda PAGE_EXECUTE_READWRITE ndani ya powershell.exe.<sup>[[8]](#references)</sup>
- Miundo ya dynamic invocation (GetDelegateForFunctionPointer)
- Majibu ya HTTPS 404 yasiyolingana yenye `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, au `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Majibu ya DNS yenye `AA=true` na `TXT "OK"` kwa queries fupi chini ya domains zinazotiliwa shaka.<sup>[[4]](#references)</sup>
- Traffic ya GitHub API kwenda `/repos/<owner>/<repo>/issues` ikifuatiwa na lookup za `ipinfo.io` kutoka kwenye mnyororo huohuo wa loader/beacon.<sup>[[5]](#references)</sup>
- .lnk za Startup chini ya user au common Startup folders.<sup>[[1]](#references)</sup>
- Run keys zinazotia shaka (kwa mfano, "Updater"), na majina ya loader kama update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- PE samples zilizotiwa Trojan zinazoelekeza `_security_init_cookie` kwenye downloader code kabla ya kuonyesha document ya udanganyifu.<sup>[[5]](#references)</sup>
- Njia za DLL zinazoweza kuandikwa na user chini ya %APPDATA%\Microsoft\Windows\Templates zenye msimg32.dll.<sup>[[1]](#references)</sup>

## Maelezo kuhusu fields za OpSec

- KillDate: timestamp ambayo ikipita agent hujifuta yenyewe.<sup>[[1]](#references)</sup>
- WorkingTime: saa ambazo agent inapaswa kuwa active ili ifanane na shughuli za kawaida za biashara.<sup>[[1]](#references)</sup>

Fields hizi zinaweza kutumika kupanga sampuli katika makundi na kueleza vipindi vya ukimya vilivyoonekana.

## YARA na viashiria vya static

Unit 42 ilichapisha YARA ya msingi kwa beacons (C/C++ na Go) na constants za loader API-hashing.<sup>[[1]](#references)</sup> Fikiria kuongezea rules zinazotafuta muundo wa [size|ciphertext|16-byte-key] karibu na mwisho wa PE .rdata, strings chaguomsingi za HTTP profile, na viashiria vipya vya server/listener kama `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, na `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Mfumo Mpya wa Open-Source Uliotumika Katika Mashambulizi Halisi (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Nyaraka za Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Kutambua kwa Fingerprinting Mfumo wa Open-Source C2 kwa Kiwango Kikubwa (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper Yahamia AdaptixC2 na Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Constants za ulinzi wa memory – Nyaraka za Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Uzalishaji wa AdaptixC2 profile (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser ya AdaptixC2 beacon profile (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Uzalishaji wa AdaptixC2 DNS profile (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile packing (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
