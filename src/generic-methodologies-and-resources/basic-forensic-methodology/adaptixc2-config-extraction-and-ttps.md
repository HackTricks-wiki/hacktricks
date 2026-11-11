# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 एक modular, open-source post-exploitation/C2 framework है, जिसमें Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) और BOF support शामिल हैं।<sup>[[1]](#references)</sup> यह पेज बताता है:
- इसकी RC4-packed configuration कैसे embedded होती है और beacons से इसे कैसे extract किया जाए
- HTTP/SMB/TCP listeners के network/profile indicators
- जंगली परिवेश में देखे गए सामान्य loader और persistence TTPs, और संबंधित Windows technique pages के links

हाल के upstream releases में DNS/DoH beacon listeners और अलग Gopher agent/listener family भी शामिल हैं, इसलिए आधुनिक Adaptix infrastructure में मूल HTTP/SMB/TCP surfaces से अधिक चीज़ें उजागर हो सकती हैं, भले ही कोई खास sample अभी भी classic beacon agent का उपयोग करता हो।<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2 तीन प्राथमिक beacon types को support करता है:<sup>[[1]](#references)</sup>
- BEACON_HTTP: configurable servers/ports/SSL, method, URI, headers, user-agent और custom parameter name वाला web C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, जिनमें protocol start को obfuscate करने के लिए वैकल्पिक रूप से पहले marker जोड़ा जा सकता है

ये वे beacon layouts हैं जिन्हें शुरुआती Adaptix analyses में सार्वजनिक रूप से document किया गया था, और sample-side extraction के लिए ये अब भी सबसे सामान्य शुरुआती बिंदु हैं।<sup>[[1]](#references)</sup> हालांकि, मौजूदा upstream builds में server side पर `BeaconDNS` और Gopher extenders भी शामिल हैं, इसलिए यह न मानें कि हर live Adaptix deployment केवल HTTP/SMB/TCP infrastructure ही उजागर करता है।<sup>[[2]](#references)</sup>

नीचे दिया गया field summary और JSON samples 2025 में analyze किए गए HTTP format का वर्णन करते हैं; ये नए upstream builds के लिए parser specification नहीं हैं। उन samples में आमतौर पर पाए जाने वाले fields (decryption के बाद):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizes parse करने के लिए उपयोग किए जाते हैं
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

हाल के BeaconHTTP builds में operator द्वारा चुने गए कई URIs, user-agents, Host headers और servers के बीच sequential या random selection के साथ rotation भी support होता है।<sup>[[2]](#references)</sup> Hunting के नज़रिए से इसका मतलब है कि एक ही infected host कई callback paths और header combinations के ज़रिए संपर्क कर सकता है, और फिर भी classic RC4-packed beacon family का ही उपयोग कर सकता है।

उदाहरण के लिए default HTTP profile (beacon build से):<sup>[[1]](#references)</sup>

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

देखा गया दुर्भावनापूर्ण HTTP profile (वास्तविक हमला):<sup>[[1]](#references)</sup>

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

## एन्क्रिप्टेड कॉन्फ़िगरेशन पैकिंग और लोड पाथ

जब operator builder में Create पर क्लिक करता है, तो AdaptixC2 एन्क्रिप्टेड प्रोफ़ाइल को beacon में compile करता है। यह न मानें कि यह PE या shellcode के अंत में है: section scan करके या sample में `getProfile()` को follow करके प्रोफ़ाइल के bytes खोजें। पैक किया गया format है:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bytes: configuration size (uint32, little‑endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

beacon loader अंत से 16-byte key कॉपी करता है और N-byte block को वहीं RC4 से decrypt करता है:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

व्यावहारिक निहितार्थ:<sup>[[1]](#references)</sup>
- पूरी structure अक्सर PE के .rdata section में रहती है।
- Extraction नियतात्मक है: size पढ़ें, उतने size का ciphertext पढ़ें, उसके तुरंत बाद रखी 16-byte key पढ़ें, फिर RC4-decrypt करें।

## Configuration extraction workflow (रक्षकों के लिए)

Beacon को carve करने से पहले सामान्य sample triage के लिए, [Malware Analysis](malware-analysis.md) देखें।

ऐसा extractor लिखें जो beacon logic की नकल करे:<sup>[[1]](#references)</sup>
1) PE में blob खोजें (आमतौर पर .rdata में)। एक व्यावहारिक तरीका है कि .rdata को संभावित [size|ciphertext|16-byte key] layout के लिए scan करें और RC4 आज़माएँ।
2) पहले 4 bytes पढ़ें → size (uint32 LE)।
3) अगले N=size bytes पढ़ें → ciphertext।
4) अंतिम 16 bytes पढ़ें → RC4 key।
5) ciphertext को RC4-decrypt करें। फिर plain profile को इस तरह parse करें:
   - ऊपर बताए गए u32/boolean scalars
   - length-prefixed strings (u32 length के बाद bytes; अंत में NUL हो सकता है)
   - arrays: servers_count के बाद उतने ही [string, u32 port] pairs

2025 field order में पहले से निकाले गए blob के लिए Legacy HTTP Python proof-of-concept (standalone, कोई external deps नहीं)। हालिया stock builds के लिए नीचे दिया गया current-schema parser इस्तेमाल करें:<sup>[[1]](#references)[[11]](#references)</sup>

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

### मौजूदा stock HTTP और DNS profiles को पार्स करना

मौजूदा upstream पहले छह little-endian `u32` मान पैक करता है: agent watermark/type, kill date, working time, sleep, jitter और listener watermark/type। इसके बाद HTTP-विशिष्ट डेटा एक-बाइट वाले SSL flag से शुरू होता है। पुराने उदाहरण से अलग, इसमें URI, user-agent और Host-header सूचियों के साथ उनकी संख्या, फिर rotation mode और proxy settings शामिल हैं। इसलिए पुराने parser में इन builds पर SSL flag को kill-date field से पढ़ना शुरू किया जाता है और गलत परिणाम मिलते हैं। इस profile में string lengths और integer values little-endian encoding का उपयोग करते हैं; nonempty packed strings के अंत में NUL होता है।<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

ऊपर दिए गए `P` और `rc4` helpers का उपयोग करके, decrypted **stock HTTP** plaintext पर इस parser को चलाएँ। RC4 key को सार्वजनिक reports में शामिल न करें: HTTP profile में proxy username और password हो सकते हैं।<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>मौजूदा stock HTTP plaintext profile को पार्स करना</summary>

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

एक stock DNS beacon के लिए, वही छह सामान्य `u32` fields पढ़ें, फिर length-prefixed `domain`, `resolvers`, `doh_resolvers`, और `qtype` strings पढ़ें। `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter`, और `dns_mode` को `u32` के रूप में पढ़ें, फिर length-prefixed DoH user-agent string पढ़ें। `dns_mode` UDP, DoH, और fallback की दोनों दिशाओं में अंतर बताता है। यह एक अलग layout है: DNS plaintext को HTTP parser से force न करें।<sup>[[12]](#references)[[13]](#references)</sup>

सुझाव:
- Automation करते समय, `.rdata` पढ़ने के लिए PE parser का उपयोग करें, फिर sliding window लागू करें: हर offset `o` के लिए, `size = u32(.rdata[o:o+4])` आज़माएँ, `ct = .rdata[o+4:o+4+size]` लें, और अगले 16 bytes को candidate key मानें; फिर RC4-decrypt करें और जाँचें कि string fields UTF-8 के रूप में decode हों और lengths उचित हों।
- SMB/TCP profiles को parse करने के लिए भी length-prefixed conventions का पालन करें।

## Custom listener profiles: केवल classic HTTP schema को hard-code न करें

बाहरी packing format (`u32 size | RC4 ciphertext | 16-byte key`) का फिर से उपयोग किया जा सकता है, इसलिए actor-customized listeners वही extraction workflow अपना सकते हैं, जबकि decrypted field layout पूरी तरह बदल सकता है।

हाल का एक अच्छा उदाहरण March 2026 का Tropic Trooper campaign है, जिसमें निकाले गए Adaptix beacon में standard HTTP/TCP profile नहीं था। इसके बजाय, decrypted blob में GitHub transport parameters थे, जैसे:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (उदाहरण के लिए `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

व्यावहारिक parser रणनीति:
- सबसे पहले, सामान्य तरीके से बाहरी RC4 blob का पता लगाएँ।
- Decryption के बाद, तुरंत HTTP parser लागू करने के बजाय sentinel strings और field sanity के आधार पर आगे की प्रक्रिया चुनें।
- अच्छे sentinels में `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-जैसी strings, या स्पष्ट रूप से मान्य server/port arrays शामिल हैं।
- यदि HTTP parser विफल हो, लेकिन plaintext में सुसंगत length-prefixed UTF-8 strings हों, तो sample को false positive मानकर हटाने के बजाय सुरक्षित रखें और अन्य schemas आज़माएँ।

उस campaign में custom listener ने C2 transport के रूप में GitHub issues का उपयोग किया, और beacon ने अपना external IP जानने के लिए `ipinfo.io` से query की, क्योंकि GitHub API operator को सीधे victim का source address नहीं बताती।<sup>[[5]](#references)</sup>

## Network fingerprinting और hunting

HTTP:<sup>[[1]](#references)</sup>
- सामान्य: operator द्वारा चुने गए URIs पर POST (जैसे, /uri.php, /endpoint/api)
- Beacon ID के लिए custom header parameter का उपयोग (जैसे, X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 या समकालीन Chrome builds की नकल करने वाले user-agents
- `sleep_delay`/`jitter_delay` के ज़रिए polling cadence दिखाई देती है
- नए builds callbacks के बीच URIs, user-agents, Host headers, और servers बदल सकते हैं, इसलिए एक ही path/UA pair मानने के बजाय असामान्य header names, response-size patterns, TLS reuse, और timing के आधार पर cluster करें।<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- जहाँ web egress सीमित हो, वहाँ intranet C2 के लिए SMB named‑pipe listeners
- TCP beacons protocol start को obfuscate करने के लिए traffic से पहले कुछ bytes जोड़ सकते हैं

मौजूदा upstream teamserver defaults
- `profile.yaml` में वर्तमान में teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` और `server.rsa.key`, तथा HTTP, SMB, TCP, DNS, Beacon agent, और Gopher के extenders शामिल हैं।<sup>[[2]](#references)</sup>
- जिन routes का मिलान नहीं होता, उन पर default error handler `Server: AdaptixC2` और `Adaptix-Version: v1.2` लौटाता है।<sup>[[4]](#references)</sup>
- stock 404 body में `AdaptixC2 404` और `You need to enter the correct connection details` शामिल हैं।<sup>[[4]](#references)</sup>
- 2026 में इंटरनेट-व्यापी scans में `4321` पर कई exposed teamservers और `43211` पर कई beacon listeners मिले; इसलिए दोनों ports उपयोगी शुरुआती pivots हैं, लेकिन इन्हें exhaustive नहीं मानना चाहिए।<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- मौजूदा BeaconDNS extender authoritative जवाब देता है (`AA=true`)
- Beacon protocol के आकार से मेल न खाने वाली queries — विशेष रूप से configured domain से पहले 5 से कम labels वाले names — का जवाब अक्सर `TXT "OK"` से दिया जाता है
- यदि configured base TTL शून्य पर छोड़ा जाए, तो listener 10-second base का उपयोग करता है और इसमें अधिकतम 59 seconds का jitter जोड़ता है
- HTTP listener exposed न होने पर, इससे short-label active probes उपयोगी साबित होते हैं

## Incidents में देखे गए Loader और persistence TTPs

In‑memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Base64/XOR payloads download करते हैं (Invoke‑RestMethod / WebClient)।<sup>[[9]](#references)</sup>
- Unmanaged memory allocate करते हैं, shellcode copy करते हैं, और VirtualProtect के ज़रिए protection को 0x40 (PAGE_EXECUTE_READWRITE) पर बदलते हैं।<sup>[[7]](#references)</sup>
- .NET dynamic invocation के ज़रिए execute करते हैं: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()।<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- 2026 के एक Tropic Trooper chain में trojanized SumatraPDF executable (TOSHIS loader) का उपयोग हुआ, जिसने PE entry point को patch करने के बजाय `_security_init_cookie` को malicious code की ओर redirect किया
- Loader ने Adler-32 hashing के ज़रिए APIs resolve किए, एक decoy PDF download किया, second-stage shellcode प्राप्त किया, WinCrypt के ज़रिए AES-128-CBC से उसे decrypt किया (hardcoded seed से `CryptDeriveKey`), और Adaptix beacon को memory में reflectively execute किया
- बाद में persistence को `\MSDNSvc` या `\MicrosoftUDN` जैसे सामान्य दिखने वाले नामों वाले scheduled tasks पर स्थानांतरित किया गया, जो लगभग हर दो घंटे में agent को फिर से launch करने के लिए configured थे

In‑memory execution और AMSI/ETW के पहलुओं के लिए ये पेज देखें:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

देखे गए persistence mechanisms:<sup>[[1]](#references)</sup>
- Logon पर loader को फिर से launch करने के लिए Startup folder shortcut (.lnk)
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), अक्सर `Updater` जैसे सामान्य दिखने वाले नामों के साथ, ताकि loader.ps1 शुरू हो सके।<sup>[[10]](#references)</sup>
- प्रभावित प्रक्रियाओं के लिए %APPDATA%\Microsoft\Windows\Templates में msimg32.dll डालकर DLL search‑order hijack करना

तकनीक की विस्तृत जानकारी और जाँच:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting के सुझाव
- PowerShell में RW→RX transitions: powershell.exe के अंदर VirtualProtect द्वारा PAGE_EXECUTE_READWRITE का उपयोग।<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- ऐसे unmatched HTTPS 404s जिनमें `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, या `You need to enter the correct connection details` हों।<sup>[[4]](#references)</sup>
- संदिग्ध domains के अंतर्गत short queries के लिए `AA=true` और `TXT "OK"` वाले DNS responses।<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues` पर GitHub API traffic के बाद उसी loader/beacon chain से `ipinfo.io` lookups।<sup>[[5]](#references)</sup>
- User या common Startup folders में Startup .lnk।<sup>[[1]](#references)</sup>
- संदिग्ध Run keys (जैसे, "Updater"), और update.ps1/loader.ps1 जैसे loader names।<sup>[[1]](#references)</sup>
- ऐसे trojanized PE samples जो decoy document दिखाने से पहले `_security_init_cookie` को downloader code की ओर redirect करते हैं।<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates के अंतर्गत user-writable DLL paths, जिनमें msimg32.dll हो।<sup>[[1]](#references)</sup>

## OpSec fields पर टिप्पणियाँ

- KillDate: वह timestamp जिसके बाद agent स्वयं समाप्त हो जाता है।<sup>[[1]](#references)</sup>
- WorkingTime: वे घंटे जब agent को business activity में घुलने-मिलने के लिए सक्रिय रहना चाहिए।<sup>[[1]](#references)</sup>

इन fields का उपयोग clustering और देखे गए निष्क्रिय समय को समझाने के लिए किया जा सकता है।

## YARA और static संकेत

Unit 42 ने beacons (C/C++ और Go) तथा loader API-hashing constants के लिए बुनियादी YARA प्रकाशित किया है।<sup>[[1]](#references)</sup> ऐसे rules जोड़ने पर विचार करें जो PE `.rdata` के अंत के पास [size|ciphertext|16-byte-key] layout, default HTTP profile strings, और नए server/listener markers जैसे `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, और `ipinfo.io` को खोजें।<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: वास्तविक दुनिया के हमलों में उपयोग किया गया एक नया Open-Source Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework दस्तावेज़](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: बड़े पैमाने पर Open-Source C2 Framework की Fingerprinting (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper ने AdaptixC2 और Custom Beacon Listener का उपयोग शुरू किया (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profile generation (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profile generation (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profile packing (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
