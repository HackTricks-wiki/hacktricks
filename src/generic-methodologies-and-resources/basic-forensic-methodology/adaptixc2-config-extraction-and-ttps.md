# AdaptixC2 Configuration Extraction and TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 एक modular, open-source post-exploitation/C2 framework है, जिसमें Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) और BOF support शामिल है।<sup>[[1]](#references)</sup> यह पेज बताता है:
- इसकी RC4-packed configuration कैसे embedded होती है और beacons से इसे कैसे extract किया जाता है
- HTTP/SMB/TCP listeners के network/profile indicators
- आम loader और persistence TTPs, जो वास्तविक हमलों में देखे गए हैं, तथा संबंधित Windows technique pages के links

हाल के upstream releases में DNS/DoH beacon listeners और अलग Gopher agent/listener family भी शामिल हैं। इसलिए आधुनिक Adaptix infrastructure में मूल HTTP/SMB/TCP surfaces से अधिक चीज़ें दिखाई दे सकती हैं, भले ही कोई विशिष्ट sample अभी भी classic beacon agent का उपयोग करता हो।<sup>[[2]](#references)</sup>

## Beacon profiles and fields

AdaptixC2 तीन प्राथमिक beacon types को support करता है:<sup>[[1]](#references)</sup>
- BEACON_HTTP: configurable servers/ports/SSL, method, URI, headers, user-agent और custom parameter name के साथ web C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: direct sockets, जिनमें protocol start को obfuscate करने के लिए पहले marker जोड़ा जा सकता है

ये वे beacon layouts हैं जिन्हें शुरुआती Adaptix analyses में सार्वजनिक रूप से document किया गया था, और sample-side extraction के लिए आज भी ये सबसे आम शुरुआती बिंदु हैं।<sup>[[1]](#references)</sup> हालांकि, मौजूदा upstream builds में server side पर `BeaconDNS` और Gopher extenders भी शामिल हैं, इसलिए यह न मानें कि हर live Adaptix deployment केवल HTTP/SMB/TCP infrastructure ही expose करता है।<sup>[[2]](#references)</sup>

HTTP beacon configs में (decryption के बाद) आम तौर पर दिखने वाले profile fields:<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (strings का array), ports (u32 का array)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response sizes parse करने के लिए उपयोग किए जाते हैं
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

हाल के BeaconHTTP builds में operator द्वारा चुने गए कई URIs, user-agents, Host headers और servers के बीच sequential या random rotation का भी support है।<sup>[[2]](#references)</sup> Hunting के नज़रिए से, इसका मतलब है कि एक infected host कई callback paths और header combinations का उपयोग कर सकता है, फिर भी classic RC4-packed beacon family का हिस्सा बना रहता है।

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

देखा गया दुर्भावनापूर्ण HTTP प्रोफ़ाइल (वास्तविक हमला):<sup>[[1]](#references)</sup>

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

## Encrypted configuration की packing और load path

जब operator builder में Create पर क्लिक करता है, तो AdaptixC2 encrypted profile को beacon में tail blob के रूप में जोड़ता है। इसका format है:<sup>[[1]](#references)</sup>
- 4 bytes: configuration का size (uint32, little‑endian)
- N bytes: RC4 से encrypted configuration data
- 16 bytes: RC4 key

beacon loader अंत से 16‑byte key कॉपी करता है और N‑byte block को उसी जगह RC4 से decrypt करता है:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

व्यावहारिक निहितार्थ:<sup>[[1]](#references)</sup>
- पूरी structure अक्सर PE के .rdata section में होती है।
- Extraction deterministic है: size पढ़ें, उस size का ciphertext पढ़ें, तुरंत बाद रखी गई 16‑byte key पढ़ें, फिर RC4‑decrypt करें।

## Configuration extraction workflow (defenders)

ऐसा extractor लिखें जो beacon logic की नकल करे:<sup>[[1]](#references)</sup>
1) PE के अंदर blob ढूँढें (आमतौर पर .rdata में)। एक व्यावहारिक तरीका है .rdata में संभावित [size|ciphertext|16-byte key] layout को scan करना और RC4 आज़माना।
2) पहले 4 bytes पढ़ें → size (uint32 LE)।
3) अगले N=size bytes पढ़ें → ciphertext।
4) आखिरी 16 bytes पढ़ें → RC4 key।
5) ciphertext को RC4‑decrypt करें। फिर plain profile को इस तरह parse करें:
   - ऊपर बताए अनुसार u32/boolean scalars
   - length-prefixed strings (u32 length के बाद bytes; अंत में NUL हो सकता है)
   - arrays: servers_count के बाद उतने ही [string, u32 port] pairs

Pre-extracted blob के साथ काम करने वाला न्यूनतम Python proof-of-concept (standalone, कोई external deps नहीं):

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

सुझाव:
- स्वचालित प्रक्रिया में, `.rdata` पढ़ने के लिए PE parser का उपयोग करें, फिर sliding window लागू करें: हर offset `o` के लिए, `size = u32(.rdata[o:o+4])` आज़माएँ, `ct = .rdata[o+4:o+4+size]` लें, और अगले 16 bytes को candidate key मानें। RC4 से decrypt करें और जाँचें कि string fields UTF-8 में decode होते हैं तथा उनकी lengths उचित हैं।
- SMB/TCP profiles को इसी length-prefixed परंपरा का पालन करते हुए parse करें।

## Custom listener profiles: केवल classic HTTP schema को hard-code न करें

बाहरी packing format (`u32 size | RC4 ciphertext | 16-byte key`) दोबारा इस्तेमाल किया जा सकता है। इसलिए actor द्वारा customized listeners extraction की वही workflow बनाए रख सकते हैं, जबकि decrypted field layout पूरी तरह बदल सकता है।

हाल का एक अच्छा उदाहरण March 2026 का Tropic Trooper campaign है, जिसमें निकाले गए Adaptix beacon में standard HTTP/TCP profile नहीं था। इसके बजाय, decrypted blob में GitHub transport parameters थे, जैसे:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (उदाहरण के लिए `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

व्यावहारिक parser रणनीति:
- सबसे पहले, हमेशा की तरह बाहरी RC4 blob पहचानें।
- Decryption के बाद, तुरंत HTTP parser लागू करने के बजाय sentinel strings और fields की वैधता के आधार पर आगे बढ़ें।
- अच्छे sentinel में `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe जैसे strings, या स्पष्ट रूप से मान्य server/port arrays शामिल हैं।
- अगर HTTP parser विफल हो, लेकिन plaintext में सुसंगत length-prefixed UTF-8 strings हों, तो sample को false positive मानकर हटाने के बजाय रखें और दूसरे schemas आज़माएँ।

इस campaign में custom listener ने C2 transport के रूप में GitHub issues का इस्तेमाल किया, और beacon ने अपना external IP जानने के लिए `ipinfo.io` से query की, क्योंकि GitHub API operator को सीधे victim का source address नहीं दिखाती।<sup>[[5]](#references)</sup>

## Network fingerprinting और hunting

HTTP:<sup>[[1]](#references)</sup>
- आम तौर पर: operator द्वारा चुने गए URIs पर POST (जैसे, /uri.php, /endpoint/api)
- Beacon ID के लिए इस्तेमाल किया गया custom header parameter (जैसे, X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 या मौजूदा Chrome builds की नकल करने वाले user-agents
- `sleep_delay`/`jitter_delay` के ज़रिए दिखने वाली polling cadence
- नए builds callbacks के बीच URIs, user-agents, Host headers और servers बदल सकते हैं। इसलिए एक ही path/UA जोड़ी मानने के बजाय, असामान्य header names, response-size patterns, TLS reuse और timing के आधार पर समूह बनाएँ।<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- ऐसे intranet C2 के लिए SMB named-pipe listeners जहाँ web egress सीमित हो
- TCP beacons protocol start को छिपाने के लिए traffic से पहले कुछ bytes जोड़ सकते हैं

मौजूदा upstream teamserver defaults
- `profile.yaml` में फिलहाल teamserver `0.0.0.0:4321`, endpoint `/endpoint`, certificate/key filenames `server.rsa.crt` और `server.rsa.key`, और HTTP, SMB, TCP, DNS, Beacon agent तथा Gopher के extenders शामिल हैं।<sup>[[2]](#references)</sup>
- जिन routes का मिलान नहीं होता, उन पर default error handler `Server: AdaptixC2` और `Adaptix-Version: v1.2` लौटाता है।<sup>[[4]](#references)</sup>
- सामान्य 404 body में `AdaptixC2 404` और `You need to enter the correct connection details` शामिल हैं।<sup>[[4]](#references)</sup>
- 2026 में किए गए Internet-wide scans में `4321` पर कई exposed teamservers और `43211` पर कई beacon listeners मिले। इसलिए दोनों ports शुरुआती खोज के लिए उपयोगी हैं, लेकिन इन्हें सभी संभावित ports न मानें।<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprints:<sup>[[4]](#references)</sup>
- मौजूदा BeaconDNS extender authoritative जवाब देता है (`AA=true`)
- जो queries beacon protocol के स्वरूप से मेल नहीं खातीं—खास तौर पर, configured domain से पहले 5 से कम labels वाले नाम—उनका जवाब आम तौर पर `TXT "OK"` होता है
- यदि configured base TTL शून्य छोड़ा गया हो, तो listener 10-second base का उपयोग करता है और उसमें 59 सेकंड तक का jitter जोड़ता है
- HTTP listener उपलब्ध न होने पर, इससे छोटे-label वाले active probes उपयोगी होते हैं

## Incidents में देखे गए Loader और persistence TTPs

In-memory PowerShell loaders:<sup>[[1]](#references)</sup>
- Base64/XOR payloads डाउनलोड करते हैं (Invoke‑RestMethod / WebClient)।<sup>[[9]](#references)</sup>
- Unmanaged memory allocate करते हैं, shellcode copy करते हैं, और VirtualProtect के ज़रिए protection को 0x40 (PAGE_EXECUTE_READWRITE) पर बदलते हैं।<sup>[[7]](#references)</sup>
- .NET dynamic invocation के ज़रिए execute करते हैं: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loaders:<sup>[[5]](#references)</sup>
- 2026 की Tropic Trooper chain में trojanized SumatraPDF executable (TOSHIS loader) का इस्तेमाल हुआ। उसने PE entry point को patch करने के बजाय `_security_init_cookie` को malicious code की ओर redirect किया।
- Loader ने Adler-32 hashing से APIs resolve किए, एक decoy PDF डाउनलोड किया, second-stage shellcode हासिल किया, WinCrypt के ज़रिए AES-128-CBC से उसे decrypt किया (`CryptDeriveKey` में hardcoded seed का इस्तेमाल करके), और Adaptix beacon को memory में reflectively execute किया।
- बाद में persistence के लिए `\MSDNSvc` या `\MicrosoftUDN` जैसे सामान्य दिखने वाले नामों वाले scheduled tasks इस्तेमाल किए गए, जो लगभग हर दो घंटे में agent को फिर से launch करने के लिए configured थे।

In-memory execution और AMSI/ETW से जुड़ी बातों के लिए ये पेज देखें:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

देखे गए persistence mechanisms:<sup>[[1]](#references)</sup>
- Logon पर loader को फिर से launch करने के लिए Startup folder shortcut (.lnk)
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), जिनमें अक्सर loader.ps1 शुरू करने के लिए "Updater" जैसे सामान्य दिखने वाले नाम इस्तेमाल होते हैं।<sup>[[10]](#references)</sup>
- Susceptible processes के लिए DLL search-order hijack, जिसमें %APPDATA%\Microsoft\Windows\Templates के अंतर्गत msimg32.dll रखा जाता है

Technique के विस्तृत विश्लेषण और जाँच:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting के सुझाव
- PowerShell में RW→RX transitions: powershell.exe के भीतर PAGE_EXECUTE_READWRITE पर VirtualProtect।<sup>[[8]](#references)</sup>
- Dynamic invocation patterns (GetDelegateForFunctionPointer)
- ऐसे unmatched HTTPS 404s जिनमें `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404`, या `You need to enter the correct connection details` हों।<sup>[[4]](#references)</sup>
- Suspect domains के अंतर्गत छोटी queries के लिए `AA=true` और `TXT "OK"` वाले DNS responses।<sup>[[4]](#references)</sup>
- `/repos/<owner>/<repo>/issues` पर GitHub API traffic, जिसके बाद उसी loader/beacon chain से `ipinfo.io` lookups हों।<sup>[[5]](#references)</sup>
- User या common Startup folders में Startup .lnk।<sup>[[1]](#references)</sup>
- संदिग्ध Run keys (जैसे "Updater"), और update.ps1/loader.ps1 जैसे loader names।<sup>[[1]](#references)</sup>
- ऐसे trojanized PE samples, जो decoy document दिखाने से पहले `_security_init_cookie` को downloader code की ओर redirect करते हैं।<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates के अंतर्गत user-writable DLL paths, जिनमें msimg32.dll हो।<sup>[[1]](#references)</sup>

## OpSec fields पर नोट्स

- KillDate: वह timestamp जिसके बाद agent स्वयं समाप्त हो जाता है।<sup>[[1]](#references)</sup>
- WorkingTime: वे घंटे जब agent को business activity के साथ घुलने-मिलने के लिए सक्रिय रहना चाहिए।<sup>[[1]](#references)</sup>

इन fields का उपयोग समूह बनाने और दिखाई देने वाले निष्क्रिय समय को समझाने के लिए किया जा सकता है।

## YARA और static संकेत

Unit 42 ने beacons (C/C++ और Go) तथा loader API-hashing constants के लिए बुनियादी YARA प्रकाशित की है।<sup>[[1]](#references)</sup> ऐसी rules भी जोड़ने पर विचार करें जो PE `.rdata` के अंत के पास `[size|ciphertext|16-byte-key]` layout, default HTTP profile strings, और नए server/listener markers जैसे `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open`, और `ipinfo.io` खोजें।<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: वास्तविक हमलों में इस्तेमाल किया गया एक नया Open-Source Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: बड़े पैमाने पर Open-Source C2 Framework की Fingerprinting (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper ने AdaptixC2 और Custom Beacon Listener का इस्तेमाल किया (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
