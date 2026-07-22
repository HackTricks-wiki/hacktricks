# AdaptixC2 Yapılandırma Çıkarma ve TTP'ler

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2, Windows x86/x64 beacon'larına (EXE/DLL/service EXE/raw shellcode) ve BOF desteğine sahip modüler, open-source bir post-exploitation/C2 framework'üdür. Bu sayfa şunları belgeler:
- RC4-packed yapılandırmasının nasıl gömüldüğünü ve beacon'lardan nasıl çıkarılacağını
- HTTP/SMB/TCP listener'ları için network/profile göstergelerini
- Wild ortamda gözlemlenen yaygın loader ve persistence TTP'lerini ve ilgili Windows technique sayfalarına bağlantıları

Güncel upstream sürümleri ayrıca DNS/DoH beacon listener'larını ve ayrı Gopher agent/listener ailesini de içerir. Bu nedenle belirli bir sample hâlâ klasik beacon agent'ını kullansa bile modern Adaptix altyapısı, orijinal HTTP/SMB/TCP yüzeylerinden daha fazlasını açığa çıkarabilir.

## Beacon profilleri ve alanları

AdaptixC2 üç primary beacon type destekler:
- BEACON_HTTP: yapılandırılabilir server/port/SSL, method, URI, header, user-agent ve özel parameter name özelliklerine sahip web C2
- BEACON_SMB: named-pipe peer-to-peer C2 (intranet)
- BEACON_TCP: protocol başlangıcını obfuscate etmek için başına marker eklenebilen direct socket'ler

Bunlar, erken Adaptix analizlerinde publicly documented edilen beacon layout'larıdır ve sample-side extraction için hâlâ en yaygın başlangıç noktalarıdır. Ancak güncel upstream build'ler server tarafında `BeaconDNS` ve Gopher extender'larını da içerir. Bu nedenle her live Adaptix deployment'ının yalnızca HTTP/SMB/TCP infrastructure açığa çıkardığını varsaymayın.

HTTP beacon config'lerinde (decryption sonrasında) gözlemlenen typical profile field'ları:
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length-prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response size'larını parse etmek için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Güncel BeaconHTTP build'leri ayrıca operator tarafından birden fazla URI, user-agent, Host header ve server arasında sequential veya random selection yapılmasını destekler. Hunting açısından bu, tek bir infected host'un klasik RC4-packed beacon family'sinden ayrılmadan birden fazla callback path ve header combination'a yayılabileceği anlamına gelir.

Örnek default HTTP profile (bir beacon build'inden):
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
Gözlemlenen kötü amaçlı HTTP profili (gerçek saldırı):
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
## Şifreli yapılandırma paketleme ve yükleme yolu

Operator builder'da Create'e tıkladığında AdaptixC2, şifreli profile beacon içinde tail blob olarak gömer. Format:
- 4 bytes: configuration size (uint32, little-endian)
- N bytes: RC4-encrypted configuration data
- 16 bytes: RC4 key

Beacon loader, sondaki 16-byte key'i kopyalar ve N-byte block'u yerinde RC4 ile decrypt eder:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Pratik sonuçlar:
- Tüm yapı çoğunlukla PE .rdata section içinde bulunur.
- Extraction deterministiktir: size değerini okuyun, bu size değerindeki ciphertext'i okuyun, hemen ardından yerleştirilmiş 16-byte key'i okuyun ve ardından RC4 ile decrypt edin.

## Configuration extraction workflow (defenders)

Beacon mantığını taklit eden bir extractor yazın:
1) Blob'u PE içinde bulun (genellikle .rdata). Pratik bir yaklaşım, .rdata içinde makul bir [size|ciphertext|16-byte key] düzenini taramak ve RC4'ü denemektir.
2) İlk 4 byte'ı okuyun → size (uint32 LE).
3) Sonraki N=size byte'ı okuyun → ciphertext.
4) Son 16 byte'ı okuyun → RC4 key.
5) Ciphertext'i RC4 ile decrypt edin. Ardından plain profile'ı şu şekilde parse edin:
- Yukarıda belirtildiği gibi u32/boolean scalar'lar
- Length-prefixed string'ler (u32 length ve ardından byte'lar; sondaki NUL mevcut olabilir)
- Array'ler: servers_count ve ardından bu sayıda [string, u32 port] çifti

Pre-extracted blob ile çalışan, standalone ve external deps gerektirmeyen minimal Python proof-of-concept:
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
- Otomatikleştirme sırasında `.rdata` bölümünü okumak için bir PE parser kullanın, ardından kayan pencere uygulayın: her `o` offset’i için `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, aday key = sonraki 16 byte olacak şekilde deneyin; RC4 ile decrypt edin ve string alanlarının UTF-8 olarak decode edildiğini ve uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı length-prefixed kuralları izleyerek parse edin.

## Custom listener profilleri: yalnızca klasik HTTP şemasını hard-code etmeyin

Dış paketleme formatı (`u32 size | RC4 ciphertext | 16-byte key`) yeniden kullanılabilir olduğundan actor tarafından özelleştirilmiş listener’lar, decrypt edilen field layout’unu tamamen değiştirirken aynı extraction workflow’unu koruyabilir.

Buna iyi bir güncel örnek, extracted Adaptix beacon’ın standart bir HTTP/TCP profili içermediği Nisan 2026 Tropic Trooper campaign’idir. Bunun yerine decrypted blob, aşağıdaki gibi GitHub transport parametrelerini saklıyordu:
- `repo_owner`
- `repo_name`
- `api_host` (örneğin `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Pratik parser stratejisi:
- Önce outer RC4 blob’unu her zamanki gibi tespit edin.
- Decryption sonrasında HTTP parser’ı hemen zorlamak yerine sentinel string’lere ve field sanity kontrollerine göre dallanma yapın.
- İyi sentinel’ler arasında `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, named-pipe-style string’ler veya açıkça geçerli server/port array’leri bulunur.
- HTTP parser başarısız olursa ancak plaintext tutarlı length-prefixed UTF-8 string’ler içeriyorsa sample’ı koruyun ve false positive olarak discard etmek yerine alternative schema’ları deneyin.

Bu campaign’de custom listener, C2 transport olarak GitHub issues kullanıyordu ve beacon, GitHub API’sinin victim source address’ini operator’a doğrudan göstermemesi nedeniyle external IP’sini öğrenmek için `ipinfo.io` sorguluyordu.

## Network fingerprinting ve hunting

HTTP
- Yaygın: operator tarafından seçilen URI’lere POST (ör. `/uri.php`, `/endpoint/api`)
- Beacon ID için kullanılan custom header parameter (ör. `X-Beacon-Id`, `X-App-Id`)
- Firefox 20 veya güncel Chrome build’lerini taklit eden user-agent’lar
- `sleep_delay`/`jitter_delay` üzerinden görülebilen polling cadence
- Daha yeni build’ler callback’ler arasında URI’leri, user-agent’ları, Host header’larını ve server’ları rotate edebilir; bu nedenle tek bir path/UA çifti varsaymak yerine yaygın olmayan header name’leri, response-size pattern’lerini, TLS reuse’u ve timing’i temel alarak cluster oluşturun

SMB/TCP
- Web egress’in kısıtlandığı intranet C2 için SMB named-pipe listener’ları
- TCP beacon’ları protocol başlangıcını obfuscate etmek için traffic öncesine birkaç byte ekleyebilir

Current upstream teamserver defaults
- `profile.yaml` şu anda teamserver için `0.0.0.0:4321`, `/endpoint` endpoint’ini, `server.rsa.crt` ve `server.rsa.key` certificate/key filename’lerini ve HTTP, SMB, TCP, DNS, Beacon agent ve Gopher extender’larını içerir
- Eşleşmeyen route’larda default error handler `Server: AdaptixC2` ve `Adaptix-Version: v1.2` döndürür
- Stock 404 body’si `AdaptixC2 404` ve `You need to enter the correct connection details.` içerir
- 2026’daki Internet-wide scan’ler `4321` üzerinde çok sayıda exposed teamserver ve `43211` üzerinde çok sayıda beacon listener buldu; bu nedenle her iki port da faydalı seed pivot’larıdır, ancak exhaustive kabul edilmemelidir

DNS/DoH listener fingerprint’leri
- Güncel BeaconDNS extender authoritative yanıt verir (`AA=true`)
- Beacon protocol shape’i ile eşleşmeyen query’ler — özellikle configured domain öncesinde 5’ten az label içeren name’ler — çoğunlukla `TXT "OK"` ile yanıtlanır
- Configured base TTL sıfır bırakılırsa listener, 10 saniyelik bir base kullanır ve buna 59 saniyeye kadar jitter ekler
- Bu durum, HTTP listener expose edilmediğinde short-label active probe’larını kullanışlı kılar

## Incident’lerde görülen Loader ve persistence TTP’leri

In-memory PowerShell loader’ları
- Base64/XOR payload’ları indirir (`Invoke-RestMethod` / WebClient)
- Unmanaged memory allocate eder, shellcode’u kopyalar, `VirtualProtect` üzerinden protection’ı 0x40’a (`PAGE_EXECUTE_READWRITE`) değiştirir
- .NET dynamic invocation ile çalıştırır: `Marshal.GetDelegateForFunctionPointer` + `delegate.Invoke()`

Trojanized signed software / staged shellcode loader’ları
- 2026 Tropic Trooper chain’i, PE entry point’i patch etmek yerine `_security_init_cookie`’ı malicious code’a redirect eden trojanized bir SumatraPDF executable’ı (TOSHIS loader) kullandı
- Loader, API’leri Adler-32 hashing ile resolve etti, decoy PDF indirdi, second-stage shellcode’u fetch etti, WinCrypt üzerinden (`CryptDeriveKey`, hardcoded seed’den) AES-128-CBC ile decrypt etti ve Adaptix beacon’ını memory’de reflectively execute etti
- Persistence daha sonra `\MSDNSvc` veya `\MicrosoftUDN` gibi benign-looking name’lere sahip scheduled task’lere taşındı; bu task’ler agent’ı yaklaşık iki saatte bir yeniden launch edecek şekilde configure edildi

In-memory execution ve AMSI/ETW konuları için bu sayfalara bakın:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mekanizmaları
- Logon sırasında loader’ı yeniden launch etmek için Startup folder shortcut’ı (`.lnk`)
- Loader.ps1’i başlatmak için çoğunlukla `"Updater"` gibi benign-sounding name’lere sahip Registry Run key’leri (HKCU/HKLM `...\CurrentVersion\Run`)
- Susceptible process’ler için `%APPDATA%\Microsoft\Windows\Templates` altına `msimg32.dll` bırakarak DLL search-order hijacking

Teknik deep-dive’ları ve kontrolleri:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting fikirleri
- PowerShell’in RW→RX transition’ları oluşturması: `powershell.exe` içinde `PAGE_EXECUTE_READWRITE`’a `VirtualProtect`
- Dynamic invocation pattern’leri (`GetDelegateForFunctionPointer`)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` veya `You need to enter the correct connection details.` içeren eşleşmeyen HTTPS 404’ler
- Şüpheli domain’ler altında short query’ler için `AA=true` ve `TXT "OK"` içeren DNS response’ları
- `/repos/<owner>/<repo>/issues` adresine GitHub API traffic’i ve aynı loader/beacon chain’inden gelen `ipinfo.io` lookup’ları
- User veya common Startup folder’ları altındaki Startup `.lnk` dosyaları
- Şüpheli Run key’leri (ör. `"Updater"`) ve `update.ps1`/`loader.ps1` gibi loader name’leri
- Decoy document göstermeden önce `_security_init_cookie`’ı downloader code’a redirect eden trojanized PE sample’ları
- `%APPDATA%\Microsoft\Windows\Templates` altında `msimg32.dll` içeren user-writable DLL path’leri

## OpSec field’leri hakkında notlar

- KillDate: agent’ın self-expire olacağı timestamp
- WorkingTime: agent’ın business activity ile blend olmak için active olması gereken saatler

Bu field’ler clustering için ve gözlemlenen quiet period’ları açıklamak amacıyla kullanılabilir.

## YARA ve static ipuçları

Unit 42, beacon’lar (C/C++ ve Go) ve loader API-hashing constant’ları için basic YARA yayımladı. Bunları, PE `.rdata` sonuna yakın `[size|ciphertext|16-byte-key]` layout’una, default HTTP profile string’lerine ve `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` ve `ipinfo.io` gibi daha yeni server/listener marker’larına bakan rule’larla tamamlamayı düşünün.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [AdaptixC2: Fingerprinting an Open-Source C2 Framework at Scale (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [Tropic Trooper Pivots to AdaptixC2 and Custom Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
