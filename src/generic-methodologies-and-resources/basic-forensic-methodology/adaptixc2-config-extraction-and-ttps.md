# AdaptixC2 Yapılandırma Extraction ve TTP'leri

AdaptixC2, Windows x86/x64 beacon'leri (EXE/DLL/service EXE/raw shellcode) ve BOF desteğine sahip modüler, open-source bir post-exploitation/C2 framework'üdür.<sup>[[1]](#references)</sup> Bu sayfada şunlar belgelenmektedir:
- RC4-packed yapılandırmasının nasıl embedded edildiği ve beacon'lerden nasıl extract edileceği
- HTTP/SMB/TCP listener'ları için network/profile indicator'ları
- Sahada gözlemlenen yaygın loader ve persistence TTP'leri ile ilgili Windows technique sayfalarına bağlantılar

Recent upstream release'lar ayrıca DNS/DoH beacon listener'ları ile ayrı Gopher agent/listener ailesini de sunmaktadır; bu nedenle belirli bir sample hâlâ klasik beacon agent'ını kullansa bile modern Adaptix altyapısı orijinal HTTP/SMB/TCP yüzeylerinden daha fazlasını expose edebilir.<sup>[[2]](#references)</sup>

## Beacon profilleri ve alanları

AdaptixC2 üç primary beacon type'ını destekler:<sup>[[1]](#references)</sup>
- BEACON_HTTP: yapılandırılabilir server/port/SSL, method, URI, header, user-agent ve custom parameter name özelliklerine sahip web C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: protokol başlangıcını obfuscate etmek için isteğe bağlı olarak prepended marker kullanılabilen direct socket'ler

Bunlar erken Adaptix analizlerinde public olarak belgelenen beacon layout'larıdır ve sample-side extraction için hâlâ en yaygın başlangıç noktalarıdır.<sup>[[1]](#references)</sup> Ancak current upstream build'ler server tarafında `BeaconDNS` ve Gopher extender'larını da sunmaktadır; bu nedenle her live Adaptix deployment'ının yalnızca HTTP/SMB/TCP altyapısı expose ettiğini varsaymayın.<sup>[[2]](#references)</sup>

HTTP beacon config'lerinde gözlemlenen typical profile field'ları (decryption sonrasında):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response size'larını parse etmek için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Recent BeaconHTTP build'leri ayrıca operator tarafından seçilen birden fazla URI, user-agent, Host header ve server arasında sequential veya random selection ile rotation'ı desteklemektedir.<sup>[[2]](#references)</sup> Hunting açısından bu, tek bir infected host'un klasik RC4-packed beacon family'sinden ayrılmadan birden fazla callback path'ine ve header kombinasyonuna fan out edebileceği anlamına gelir.

Örnek default HTTP profile (bir beacon build'inden):<sup>[[1]](#references)</sup>
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
Gözlemlenen kötü amaçlı HTTP profili (gerçek saldırı):<sup>[[1]](#references)</sup>
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
## Şifrelenmiş yapılandırma paketleme ve yükleme yolu

Operator builder'da Create'e tıkladığında AdaptixC2, şifrelenmiş profili beacon içine tail blob olarak gömer. Format şöyledir:<sup>[[1]](#references)</sup>
- 4 bayt: yapılandırma boyutu (uint32, little-endian)
- N bayt: RC4 ile şifrelenmiş yapılandırma verisi
- 16 bayt: RC4 anahtarı

Beacon loader, sondaki 16 baytlık anahtarı kopyalar ve N baytlık bloğun şifresini yerinde RC4 ile çözer:<sup>[[1]](#references)</sup>
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Pratik çıkarımlar:<sup>[[1]](#references)</sup>
- Tüm yapı genellikle PE'nin .rdata bölümünde bulunur.
- Extraction deterministiktir: size değerini oku, bu boyuttaki ciphertext'i oku, hemen ardından yerleştirilmiş 16-byte key'i oku, ardından RC4 ile decrypt et.

## Configuration extraction workflow (defenders)

Beacon logic'i taklit eden bir extractor yazın:<sup>[[1]](#references)</sup>
1) PE içindeki blob'u (genellikle .rdata) bulun. Pratik bir yaklaşım, .rdata bölümünü makul bir [size|ciphertext|16-byte key] düzeni için taramak ve RC4'ü denemektir.
2) İlk 4 byte'ı okuyun → size (uint32 LE).
3) Sonraki N=size byte'ı okuyun → ciphertext.
4) Son 16 byte'ı okuyun → RC4 key.
5) Ciphertext'i RC4 ile decrypt edin. Ardından plain profile'ı şu şekilde parse edin:
- Yukarıda belirtildiği gibi u32/boolean scalar'lar
- length-prefixed string'ler (u32 length ve ardından byte'lar; sonda NUL bulunabilir)
- array'ler: servers_count ve ardından bu sayıda [string, u32 port] çifti

Önceden extract edilmiş bir blob ile çalışan minimal Python proof-of-concept (standalone, external deps olmadan):
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
İpuçları:
- Otomasyon sırasında, `.rdata` bölümünü okumak için bir PE parser kullanın ve kayan pencere uygulayın: her `o` offset'i için `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, aday key = sonraki 16 byte olacak şekilde deneyin; RC4 ile decrypt edin ve string alanlarının UTF-8 olarak decode edildiğini, uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı length-prefixed kurallarını izleyerek parse edin.

## Custom listener profilleri: yalnızca klasik HTTP schema'sını hard-code etmeyin

Dış paketleme formatı (`u32 size | RC4 ciphertext | 16-byte key`) yeniden kullanılabilir olduğundan, actor tarafından özelleştirilmiş listener'lar decrypted field layout'u tamamen değiştirirken aynı extraction workflow'unu koruyabilir.

İyi ve güncel bir örnek, çıkarılan Adaptix beacon'ın standart bir HTTP/TCP profili içermediği Mart 2026 Tropic Trooper campaign'idir. Bunun yerine decrypted blob, aşağıdakiler gibi GitHub transport parametrelerini depoluyordu:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (örneğin `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Pratik parser stratejisi:
- Önce outer RC4 blob'unu her zamanki gibi tespit edin.
- Decryption sonrasında HTTP parser'ını hemen zorlamak yerine sentinel string'lere ve field sanity kontrollerine göre branch uygulayın.
- İyi sentinel'ler arasında `api.github.com`, `/issues?state=open`, HTTP verb/URI'leri, named-pipe-style string'ler veya açıkça geçerli server/port array'leri bulunur.
- HTTP parser başarısız olursa ancak plaintext tutarlı length-prefixed UTF-8 string'ler içeriyorsa sample'ı koruyun ve false positive olarak discard etmek yerine alternatif schema'ları deneyin.

Bu campaign'de custom listener, C2 transport olarak GitHub issues kullandı ve beacon, GitHub API victim source address'i operator'e doğrudan göstermediği için external IP'sini öğrenmek üzere `ipinfo.io`'yu sorguladı.<sup>[[5]](#references)</sup>

## Network fingerprinting ve hunting

HTTP:<sup>[[1]](#references)</sup>
- Yaygın: operator tarafından seçilen URI'lere POST (ör. `/uri.php`, `/endpoint/api`)
- Beacon ID için kullanılan custom header parameter'ı (ör. `X‑Beacon‑Id`, `X‑App‑Id`)
- Firefox 20'yi veya güncel Chrome build'lerini taklit eden user-agent'lar
- `sleep_delay`/`jitter_delay` üzerinden görülebilen polling cadence
- Daha yeni build'ler callback'ler arasında URI'leri, user-agent'ları, Host header'larını ve server'ları rotate edebilir; bu nedenle tek bir path/UA çifti varsaymak yerine alışılmadık header name'leri, response-size pattern'lerini, TLS reuse'u ve timing'i cluster'layın.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Web egress'in kısıtlı olduğu intranet C2 için SMB named-pipe listener'ları
- TCP beacon'ları protocol start'ını obfuscate etmek için traffic'ten önce birkaç byte ekleyebilir

Güncel upstream teamserver default'ları
- `profile.yaml` şu anda teamserver için `0.0.0.0:4321`, `/endpoint` endpoint'ini, `server.rsa.crt` ve `server.rsa.key` certificate/key filename'lerini ve HTTP, SMB, TCP, DNS, Beacon agent ile Gopher için extender'ları içerir.<sup>[[2]](#references)</sup>
- Eşleşmeyen route'larda default error handler `Server: AdaptixC2` ve `Adaptix-Version: v1.2` döndürür.<sup>[[4]](#references)</sup>
- Standart 404 body'si `AdaptixC2 404` ve `You need to enter the correct connection details` içerir.<sup>[[4]](#references)</sup>
- 2026'daki Internet-wide scan'ler `4321` üzerinde çok sayıda exposed teamserver ve `43211` üzerinde çok sayıda beacon listener buldu; bu nedenle her iki port da yararlı seed pivot'lardır, ancak exhaustive kabul edilmemelidir.<sup>[[4]](#references)</sup>

DNS/DoH listener fingerprint'leri:<sup>[[4]](#references)</sup>
- Mevcut BeaconDNS extender authoritative olarak yanıt verir (`AA=true`)
- Beacon protocol shape'ine uymayan query'ler — özellikle configured domain'den önce 5'ten az label içeren name'ler — genellikle `TXT "OK"` ile yanıtlanır
- Configured base TTL sıfır olarak bırakılırsa listener, 10 saniyelik bir base kullanır ve 59 saniyeye kadar jitter ekler
- Bu, HTTP listener expose edilmediğinde short-label active probe'ları yararlı kılar

## Incident'lerde görülen Loader ve persistence TTP'leri

In-memory PowerShell loader'ları:<sup>[[1]](#references)</sup>
- Base64/XOR payload'larını indirir (`Invoke‑RestMethod` / WebClient).<sup>[[9]](#references)</sup>
- Unmanaged memory allocate eder, shellcode'u kopyalar ve `VirtualProtect` aracılığıyla protection'ı 0x40'a (`PAGE_EXECUTE_READWRITE`) geçirir.<sup>[[7]](#references)</sup>
- .NET dynamic invocation ile execute eder: `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`.<sup>[[6]](#references)</sup>

Trojanized signed software / staged shellcode loader'ları:<sup>[[5]](#references)</sup>
- 2026 Tropic Trooper chain'i, PE entry point'ini patch etmek yerine `_security_init_cookie`'yu malicious code'a yönlendiren trojanized bir SumatraPDF executable'ı (TOSHIS loader) kullandı
- Loader, API'leri Adler-32 hashing ile resolve etti, bir decoy PDF indirdi, second-stage shellcode'u çekti, hardcoded bir seed'den WinCrypt (`CryptDeriveKey`) aracılığıyla AES-128-CBC ile decrypt etti ve memory'de bir Adaptix beacon'ı reflectively execute etti
- Persistence daha sonra `\MSDNSvc` veya `\MicrosoftUDN` gibi benign görünen name'lere sahip scheduled task'lere taşındı; bunlar agent'ı yaklaşık iki saatte bir yeniden launch edecek şekilde configure edildi

In-memory execution ve AMSI/ETW değerlendirmeleri için şu sayfalara bakın:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mechanism'leri:<sup>[[1]](#references)</sup>
- Logon sırasında bir loader'ı yeniden launch etmek için Startup folder shortcut'ı (`.lnk`)
- Registry Run key'leri (`HKCU/HKLM ...\CurrentVersion\Run`); loader.ps1'i başlatmak için genellikle `"Updater"` gibi benign-sounding name'ler kullanılır.<sup>[[10]](#references)</sup>
- Savunmasız process'ler için `%APPDATA%\Microsoft\Windows\Templates` altına `msimg32.dll` bırakarak DLL search-order hijack

Technique deep-dive'ları ve kontroller:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting fikirleri
- PowerShell'in RW→RX transition'ları başlatması: `powershell.exe` içinde `PAGE_EXECUTE_READWRITE`'a `VirtualProtect`.<sup>[[8]](#references)</sup>
- Dynamic invocation pattern'leri (`GetDelegateForFunctionPointer`)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` veya `You need to enter the correct connection details` içeren eşleşmemiş HTTPS 404'leri.<sup>[[4]](#references)</sup>
- Şüpheli domain'ler altındaki short query'ler için `AA=true` ve `TXT "OK"` içeren DNS response'ları.<sup>[[4]](#references)</sup>
- Aynı loader/beacon chain'inden gelen `/repos/<owner>/<repo>/issues` adresine GitHub API traffic'i ve ardından `ipinfo.io` lookup'ları.<sup>[[5]](#references)</sup>
- User veya common Startup folder'ları altındaki Startup `.lnk` dosyaları.<sup>[[1]](#references)</sup>
- Şüpheli Run key'leri (ör. `"Updater"`) ve `update.ps1`/`loader.ps1` gibi loader name'leri.<sup>[[1]](#references)</sup>
- Decoy document göstermeden önce `_security_init_cookie`'yu downloader code'una yönlendiren trojanized PE sample'ları.<sup>[[5]](#references)</sup>
- `%APPDATA%\Microsoft\Windows\Templates` altında `msimg32.dll` içeren user-writable DLL path'leri.<sup>[[1]](#references)</sup>

## OpSec field'ları hakkında notlar

- KillDate: agent'ın self-expire olması gereken timestamp.<sup>[[1]](#references)</sup>
- WorkingTime: business activity ile blend olmak için agent'ın active olması gereken saatler.<sup>[[1]](#references)</sup>

Bu field'lar clustering için ve gözlemlenen quiet period'ları açıklamak üzere kullanılabilir.

## YARA ve static lead'ler

Unit 42, beacon'lar (C/C++ ve Go) ve loader API-hashing constant'ları için basic YARA yayınladı.<sup>[[1]](#references)</sup> Bunları, PE `.rdata` sonu yakınındaki `[size|ciphertext|16-byte-key]` layout'unu, default HTTP profile string'lerini ve `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` ve `ipinfo.io` gibi daha yeni server/listener marker'larını arayan rule'larla tamamlamayı düşünün.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Gerçek Dünya Saldırılarında Kullanılan Yeni Bir Open-Source Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Open-Source Bir C2 Framework'ünü Büyük Ölçekte Fingerprint Etmek (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper, AdaptixC2 ve Custom Beacon Listener'a Yöneliyor (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
