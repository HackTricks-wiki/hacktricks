# AdaptixC2 Yapılandırma Çıkarma ve TTP'ler

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2, Windows x86/x64 beacon'ları (EXE/DLL/service EXE/raw shellcode) ve BOF desteği sunan modüler, açık kaynaklı bir post-exploitation/C2 framework'üdür.<sup>[[1]](#references)</sup> Bu sayfada şunlar belgelenmektedir:
- RC4 ile paketlenmiş yapılandırmasının nasıl gömüldüğü ve beacon'lardan nasıl çıkarılacağı
- HTTP/SMB/TCP listener'ları için ağ/profil göstergeleri
- Sahada gözlemlenen yaygın loader ve persistence TTP'leri; ilgili Windows teknik sayfalarına bağlantılarla birlikte

Güncel upstream sürümleri ayrıca DNS/DoH beacon listener'ları ve ayrı Gopher agent/listener ailesini de içerir. Bu nedenle, belirli bir örnek hâlâ klasik beacon agent'ını kullansa bile modern Adaptix altyapısı, orijinal HTTP/SMB/TCP yüzeylerinden daha fazlasını açığa çıkarabilir.<sup>[[2]](#references)</sup>

## Beacon profilleri ve alanlar

AdaptixC2 üç temel beacon türünü destekler:<sup>[[1]](#references)</sup>
- BEACON_HTTP: yapılandırılabilir sunucular/portlar/SSL, yöntem, URI, başlıklar, user-agent ve özel parametre adı içeren web C2
- BEACON_SMB: adlandırılmış pipe kullanan eşler arası C2 (intranet)
- BEACON_TCP: doğrudan soketler; protokol başlangıcını gizlemek için başına bir işaretçi eklenebilir

Bunlar, ilk Adaptix analizlerinde herkese açık olarak belgelenen beacon düzenleridir ve örnek tarafından çıkarma işlemi için hâlâ en yaygın başlangıç noktalarıdır.<sup>[[1]](#references)</sup> Ancak güncel upstream derlemeleri sunucu tarafında `BeaconDNS` ve Gopher extender'larını da içerir; bu nedenle her canlı Adaptix dağıtımının yalnızca HTTP/SMB/TCP altyapısını açığa çıkardığını varsaymayın.<sup>[[2]](#references)</sup>

HTTP beacon yapılandırmalarında (şifre çözme sonrasında) gözlemlenen tipik profil alanları:<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (dize dizisi), ports (u32 dizisi)
- http_method, uri, parameter, user_agent, http_headers (uzunluğu belirtilmiş dizeler)
- ans_pre_size (u32), ans_size (u32) – yanıt boyutlarını ayrıştırmak için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Güncel BeaconHTTP derlemeleri ayrıca operatörün, birden çok URI, user-agent, Host başlığı ve sunucu arasında sıralı veya rastgele seçimle geçiş yapmasını destekler.<sup>[[2]](#references)</sup> Bu, avlama açısından tek bir ele geçirilmiş ana bilgisayarın klasik RC4 ile paketlenmiş beacon ailesinden çıkmadan birden çok callback yolu ve başlık bileşimine yayılabileceği anlamına gelir.

Örnek varsayılan HTTP profili (beacon derlemesinden):<sup>[[1]](#references)</sup>

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

## Şifrelenmiş yapılandırmanın paketlenmesi ve yükleme yolu

Operatör builder'da Create'e tıkladığında AdaptixC2, şifrelenmiş profili beacon'ın sonuna bir blob olarak ekler. Biçim şöyledir:<sup>[[1]](#references)</sup>
- 4 bayt: yapılandırma boyutu (uint32, little-endian)
- N bayt: RC4 ile şifrelenmiş yapılandırma verisi
- 16 bayt: RC4 anahtarı

Beacon loader, 16 baytlık anahtarı sondan kopyalar ve N baytlık bloğu yerinde RC4 ile şifresini çözer:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Pratik etkiler:<sup>[[1]](#references)</sup>
- Yapının tamamı genellikle PE .rdata bölümünde bulunur.
- Çıkarma deterministiktir: boyutu oku, bu boyuttaki ciphertext'i oku, hemen ardından yerleştirilmiş 16 baytlık anahtarı oku, sonra RC4 ile şifreyi çöz.

## Yapılandırma çıkarma iş akışı (savunucular)

Beacon mantığını taklit eden bir extractor yazın:<sup>[[1]](#references)</sup>
1) Blob'u PE içinde bulun (genellikle .rdata). Uygulanabilir bir yaklaşım, .rdata bölümünü makul bir [size|ciphertext|16-byte key] düzeni için taramak ve RC4'ü denemektir.
2) İlk 4 baytı oku → size (uint32 LE).
3) Sonraki N=size baytı oku → ciphertext.
4) Son 16 baytı oku → RC4 key.
5) Ciphertext'in şifresini RC4 ile çözün. Ardından düz profili şu şekilde ayrıştırın:
   - yukarıda belirtildiği gibi u32/boolean skalerler
   - uzunluk önekli dizeler (u32 uzunluk ve ardından baytlar; sonda NUL bulunabilir)
   - diziler: servers_count ve ardından belirtilen sayıda [string, u32 port] çifti

Önceden çıkarılmış bir blob ile çalışan, harici bağımlılığı olmayan minimal bir Python proof-of-concept:

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
- Otomasyon sırasında `.rdata` verisini okumak için bir PE parser kullanın, ardından kayan pencere uygulayın: Her `o` offset’i için `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, aday anahtar = sonraki 16 bayt olacak şekilde deneyin; RC4 ile şifreyi çözün ve string alanlarının UTF-8 olarak çözümlendiğini, uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı uzunluk önekli kuralları izleyerek ayrıştırın.

## Özel listener profilleri: yalnızca klasik HTTP şemasını sabit kodlamayın

Dış paketleme biçimi (`u32 size | RC4 ciphertext | 16-byte key`) yeniden kullanılabilir; bu nedenle aktörlerce özelleştirilmiş listener'lar, çözülen alan düzenini tamamen değiştirirken aynı çıkarma iş akışını koruyabilir.

Yakın tarihli iyi bir örnek, çıkarılan Adaptix beacon'ın standart bir HTTP/TCP profili içermediği Mart 2026 Tropic Trooper kampanyasıdır. Bunun yerine, çözülen blob aşağıdakiler gibi GitHub taşıma parametrelerini içeriyordu:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (örneğin `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Uygulanabilir parser stratejisi:
- Önce dış RC4 blob'unu her zamanki gibi tespit edin.
- Şifre çözme işleminden sonra, HTTP parser'ını hemen zorlamak yerine sentinel string'lere ve alanların makullüğüne göre dallanın.
- İyi sentinel'ler arasında `api.github.com`, `/issues?state=open`, HTTP fiilleri/URI'leri, adlandırılmış pipe biçimindeki string'ler veya açıkça geçerli sunucu/port dizileri bulunur.
- HTTP parser'ı başarısız olursa ancak düz metin tutarlı, uzunluk önekli UTF-8 string'ler içeriyorsa örneği saklayın ve false positive olarak elemek yerine alternatif şemaları deneyin.

Bu kampanyada özel listener, C2 taşıması olarak GitHub issues'u kullandı. GitHub API'si kurbanın kaynak adresini operatöre doğrudan göstermediğinden beacon, harici IP'sini öğrenmek için `ipinfo.io`'yu sorguladı.<sup>[[5]](#references)</sup>

## Ağ parmak izi çıkarma ve tehdit avcılığı

HTTP:<sup>[[1]](#references)</sup>
- Yaygın: Operatör tarafından seçilen URI'lere POST (ör. /uri.php, /endpoint/api)
- Beacon ID için kullanılan özel header parametresi (ör. X‑Beacon‑Id, X‑App‑Id)
- Firefox 20'yi veya güncel Chrome sürümlerini taklit eden user-agent'lar
- `sleep_delay`/`jitter_delay` üzerinden görülebilen yoklama sıklığı
- Daha yeni sürümler callback'ler arasında URI'leri, user-agent'ları, Host header'larını ve sunucuları değiştirebilir; bu nedenle tek bir path/UA çiftini varsaymak yerine yaygın olmayan header adlarına, yanıt boyutu örüntülerine, TLS'nin yeniden kullanılmasına ve zamanlamaya göre kümelendirin.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Web egress'in kısıtlı olduğu intranet C2 için SMB named-pipe listener'ları
- TCP beacon'ları, protokol başlangıcını gizlemek için trafiğin önüne birkaç bayt ekleyebilir

Güncel upstream teamserver varsayılanları
- `profile.yaml` dosyası şu anda teamserver için `0.0.0.0:4321`, `/endpoint` endpoint'ini, `server.rsa.crt` ve `server.rsa.key` sertifika/anahtar dosyalarını ve HTTP, SMB, TCP, DNS, Beacon agent ve Gopher için extender'ları içeriyor.<sup>[[2]](#references)</sup>
- Eşleşmeyen route'larda varsayılan hata handler'ı `Server: AdaptixC2` ve `Adaptix-Version: v1.2` döndürüyor.<sup>[[4]](#references)</sup>
- Standart 404 yanıt gövdesinde `AdaptixC2 404` ve `You need to enter the correct connection details` bulunuyor.<sup>[[4]](#references)</sup>
- 2026'da internet genelinde yapılan taramalarda `4321` portunda çok sayıda açık teamserver, `43211` portunda ise çok sayıda beacon listener bulundu. Bu nedenle her iki port da başlangıç noktası olarak kullanışlıdır ancak tüm olasılıkları kapsadıkları varsayılmamalıdır.<sup>[[4]](#references)</sup>

DNS/DoH listener parmak izleri:<sup>[[4]](#references)</sup>
- Güncel BeaconDNS extender'ı yetkili yanıt veriyor (`AA=true`)
- Beacon protokolü biçimiyle eşleşmeyen sorgular — özellikle yapılandırılmış domain'den önce 5'ten az label içeren adlar — genellikle `TXT "OK"` yanıtı alıyor
- Yapılandırılmış temel TTL sıfır bırakılırsa listener, 10 saniyelik bir temel değer kullanıyor ve buna 59 saniyeye kadar jitter ekliyor
- Bu nedenle HTTP listener'ı açık değilken kısa-label etkin sorguları kullanışlıdır

## Olaylarda görülen loader ve persistence TTP'leri

Bellek içi PowerShell loader'ları:<sup>[[1]](#references)</sup>
- Base64/XOR payload'ları indirir (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Yönetilmeyen bellek ayırır, shellcode'u kopyalar ve VirtualProtect aracılığıyla korumayı 0x40'a (PAGE_EXECUTE_READWRITE) geçirir.<sup>[[7]](#references)</sup>
- .NET dynamic invocation ile yürütür: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Truva atı bulaştırılmış imzalı yazılımlar / aşamalı shellcode loader'ları:<sup>[[5]](#references)</sup>
- 2026 Tropic Trooper zincirinde, PE entry point'ini yamamak yerine `_security_init_cookie` işlevini kötü amaçlı koda yönlendiren, truva atı bulaştırılmış bir SumatraPDF executable'ı (TOSHIS loader) kullanıldı
- Loader, API'leri Adler-32 hashing kullanarak çözdü, bir yem PDF indirdi, ikinci aşama shellcode'u aldı, WinCrypt üzerinden AES-128-CBC ile şifresini çözdü (sabit kodlanmış bir seed'den `CryptDeriveKey` kullanarak) ve Adaptix beacon'ı bellekte reflectively yürüttü
- Persistence daha sonra `\MSDNSvc` veya `\MicrosoftUDN` gibi zararsız görünen adlara sahip ve agent'ı yaklaşık iki saatte bir yeniden başlatacak şekilde yapılandırılmış scheduled task'lara taşındı

Bellek içi yürütme ve AMSI/ETW konuları için şu sayfalara bakın:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mekanizmaları:<sup>[[1]](#references)</sup>
- Oturum açıldığında loader'ı yeniden başlatmak için Startup klasöründe kısayol (.lnk)
- Registry Run key'leri (HKCU/HKLM ...\CurrentVersion\Run); genellikle loader.ps1'i başlatmak için "Updater" gibi zararsız görünen adlar kullanılır.<sup>[[10]](#references)</sup>
- Etkilenen süreçler için %APPDATA%\Microsoft\Windows\Templates altına msimg32.dll bırakarak DLL arama sırası hijacking'i

Teknik incelemeleri ve kontroller:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Tehdit avcılığı fikirleri
- PowerShell'de RW→RX geçişleri oluşturan süreçler: powershell.exe içinde PAGE_EXECUTE_READWRITE'e VirtualProtect çağrısı.<sup>[[8]](#references)</sup>
- Dynamic invocation örüntüleri (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` veya `You need to enter the correct connection details` içeren, eşleşmeyen HTTPS 404 yanıtları.<sup>[[4]](#references)</sup>
- Şüpheli domain'ler altında kısa sorgulara `AA=true` ve `TXT "OK"` içeren DNS yanıtları.<sup>[[4]](#references)</sup>
- Aynı loader/beacon zincirinden gelen `/repos/<owner>/<repo>/issues` adresine GitHub API trafiği ve ardından gelen `ipinfo.io` sorguları.<sup>[[5]](#references)</sup>
- Kullanıcıya ait veya ortak Startup klasörlerindeki başlangıç .lnk dosyaları.<sup>[[1]](#references)</sup>
- Şüpheli Run key'leri (ör. "Updater") ve update.ps1/loader.ps1 gibi loader adları.<sup>[[1]](#references)</sup>
- Yem belgeyi göstermeden önce `_security_init_cookie` işlevini downloader koduna yönlendiren truva atı bulaştırılmış PE örnekleri.<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates altındaki, kullanıcı tarafından yazılabilir ve msimg32.dll içeren DLL yolları.<sup>[[1]](#references)</sup>

## OpSec alanları hakkında notlar

- KillDate: Agent'ın kendini devre dışı bırakacağı zaman damgası.<sup>[[1]](#references)</sup>
- WorkingTime: Agent'ın iş etkinliğine uyum sağlamak için etkin olması gereken saatler.<sup>[[1]](#references)</sup>

Bu alanlar, kümelendirme yapmak ve gözlemlenen sessiz dönemleri açıklamak için kullanılabilir.

## YARA ve statik ipuçları

Unit 42, beacon'lar (C/C++ ve Go) ile loader API-hashing sabitleri için temel YARA kuralları yayımladı.<sup>[[1]](#references)</sup> Bunları, PE `.rdata` bölümünün sonuna yakın `[size|ciphertext|16-byte-key]` düzenini, varsayılan HTTP profil string'lerini ve `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` ve `ipinfo.io` gibi daha yeni sunucu/listener işaretlerini arayan kurallarla tamamlamayı değerlendirin.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: Gerçek Dünya Saldırılarında Kullanılan Yeni Bir Açık Kaynak Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Belgeleri](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Açık Kaynak Bir C2 Framework'ünün Ölçekli Parmak İzi Çıkarımı (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper, AdaptixC2 ve Özel Beacon Listener'a Yöneliyor (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Bellek koruma sabitleri – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Key'leri/Startup Klasörü](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
