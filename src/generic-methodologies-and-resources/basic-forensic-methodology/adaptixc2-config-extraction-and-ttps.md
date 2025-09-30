# AdaptixC2 Yapılandırma Çıkarımı ve TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2, Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) ve BOF desteğine sahip modüler, open‑source post‑exploitation/C2 framework'üdür. Bu sayfa şunları belgeliyor:
- RC4‑packed yapılandırmasının beacons içine nasıl gömüldüğünü ve beacons'tan nasıl çıkarılacağını
- HTTP/SMB/TCP listener'ları için ağ/profil göstergeleri
- Gerçek dünyada gözlemlenen yaygın loader ve persistence TTPs'leri; ilgili Windows teknik sayfalarına bağlantılar ile

## Beacon profilleri ve alanları

AdaptixC2 üç ana beacon tipini destekler:
- BEACON_HTTP: yapılandırılabilir servers/ports/SSL, method, URI, headers, user‑agent ve özel bir parameter name ile web C2
- BEACON_SMB: named‑pipe peer‑to‑peer C2 (intranet)
- BEACON_TCP: protokol başlangıcını gizlemek için isteğe bağlı olarak öne konan bir marker ile direct sockets

HTTP beacon konfigürasyonlarında gözlemlenen tipik profil alanları (şifre çözme sonrasında):
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – response boyutlarını parse etmek için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Example default HTTP profile (from a beacon build):
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
## Şifrelenmiş yapılandırma paketleme ve yükleme yolu

Operatör builder'da Create'a tıkladığında, AdaptixC2 şifrelenmiş profili beacon'ın sonuna bir tail blob olarak gömer. Formatı:
- 4 bayt: yapılandırma boyutu (uint32, little‑endian)
- N bayt: RC4 ile şifrelenmiş yapılandırma verisi
- 16 bayt: RC4 anahtarı

Beacon loader sondan 16 baytlık anahtarı kopyalar ve N baytlık bloğu yerinde RC4 ile çözer:
```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```
Practical implications:
- Tüm yapı genellikle PE .rdata bölümünün içinde bulunur.
- Çıkarma işlemi deterministiktir: boyutu oku, o boyutta ciphertext oku, hemen ardından yerleştirilen 16‑byte anahtarı oku, ardından RC4‑decrypt uygula.

## Konfigürasyon çıkarma iş akışı (savunucular)

Write an extractor that mimics the beacon logic:
1) PE içinde blob'u bulun (çoğunlukla .rdata). Pragmatik bir yaklaşım, .rdata'ı olası bir [size|ciphertext|16‑byte key] düzeni için taramak ve RC4 denemektir.
2) İlk 4 bytes'ı oku → size (uint32 LE).
3) Sonraki N=size bytes'ı oku → ciphertext.
4) Son 16 bytes'ı oku → RC4 key.
5) Ciphertext'i RC4‑decrypt edin. Sonra düz metin profili şu şekilde ayrıştırın:
- u32/boolean scalars yukarıda belirtildiği gibi
- length‑prefixed strings (u32 length followed by bytes; trailing NUL bulunabilir)
- arrays: servers_count ardından o kadar [string, u32 port] çifti

Önceden çıkarılmış bir blob ile çalışan minimal Python proof‑of‑concept (standalone, harici bağımlılık yok):
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
- Otomasyon yaparken, .rdata okumak için bir PE parser kullanın ve ardından sliding window uygulayın: her offset o için size = u32(.rdata[o:o+4]) deneyin, ct = .rdata[o+4:o+4+size], aday anahtar = sonraki 16 byte; RC4‑decrypt uygulayıp string alanların UTF‑8 olarak çözüldüğünü ve uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı length‑prefixed kurallarını takip ederek parse edin.

## Network fingerprinting and hunting

HTTP
- Yaygın: operator‑selected URI’lere POST (ör. /uri.php, /endpoint/api)
- Beacon ID için kullanılan custom header parametresi (ör. X‑Beacon‑Id, X‑App‑Id)
- Firefox 20 veya o dönemin Chrome build’lerini taklit eden User‑agents
- sleep_delay/jitter_delay ile görülebilen polling cadence

SMB/TCP
- Web egress’in kısıtlı olduğu intranet C2 için SMB named‑pipe dinleyicileri
- TCP beacon’lar protokol başlangıcını obfuscate etmek için trafik öncesi birkaç byte ekleyebilir

## Loader and persistence TTPs seen in incidents

In‑memory PowerShell loaders
- Base64/XOR payload’lar indirir (Invoke‑RestMethod / WebClient)
- unmanaged memory allocate eder, shellcode kopyalar, VirtualProtect ile korumayı 0x40 (PAGE_EXECUTE_READWRITE) olarak değiştirir
- .NET dynamic invocation ile çalıştırır: Marshal.GetDelegateForFunctionPointer + delegate.Invoke()

In‑memory execution ve AMSI/ETW ile ilgili hususlar için bu sayfaları kontrol edin:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mekanizmaları
- Logon’da bir loader’ı yeniden başlatmak için Startup klasöründe shortcut (.lnk)
- Registry Run anahtarları (HKCU/HKLM ...\CurrentVersion\Run), genellikle "Updater" gibi masum görünen isimlerle loader.ps1’i başlatmak için
- msimg32.dll gibi DLL dosyasını %APPDATA%\Microsoft\Windows\Templates altına bırakıp susceptible process’lerde DLL search‑order hijack

Tekniğe dair derinlemesine incelemeler ve kontrol listesi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting fikirleri
- PowerShell içinde RW→RX geçişleri: powershell.exe içinde VirtualProtect ile PAGE_EXECUTE_READWRITE
- Dynamic invocation pattern’ları (GetDelegateForFunctionPointer)
- Kullanıcı veya common Startup klasörleri altındaki .lnk’ler
- Şüpheli Run anahtarları (ör. "Updater") ve update.ps1/loader.ps1 gibi loader isimleri
- %APPDATA%\Microsoft\Windows\Templates altında kullanıcı tarafından yazılabilir DLL yolları ve içinde msimg32.dll bulunan dosyalar

## Notes on OpSec fields

- KillDate: agent’in kendini geçersiz kılacağı zaman damgası
- WorkingTime: agent’in iş aktivitesiyle karışmak için aktif olması gereken saatler

Bu alanlar kümelendirme için kullanılabilir ve gözlemlenen sessiz dönemleri açıklamaya yardımcı olur.

## YARA and static leads

Unit 42, beacon’lar (C/C++ ve Go) ve loader API‑hashing sabitleri için temel YARA yayınladı. PE .rdata sonu yakınında [size|ciphertext|16‑byte‑key] düzenini ve varsayılan HTTP profile string’lerini arayan kurallarla tamamlamayı düşünün.

## References

- [AdaptixC2: A New Open-Source Framework Leveraged in Real-World Attacks (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [Adaptix Framework Docs](https://adaptix-framework.gitbook.io/adaptix-framework)
- [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [Memory protection constants – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

{{#include ../../banners/hacktricks-training.md}}
