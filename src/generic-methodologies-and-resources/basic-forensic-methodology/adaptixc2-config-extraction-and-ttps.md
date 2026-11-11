# AdaptixC2 Yapılandırma Çıkarma ve TTP'ler

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2; Windows x86/x64 beacon'ları (EXE/DLL/service EXE/raw shellcode) ve BOF desteği sunan modüler, açık kaynaklı bir post-exploitation/C2 framework'üdür.<sup>[[1]](#references)</sup> Bu sayfada şunlar açıklanmaktadır:
- RC4 ile paketlenmiş yapılandırmanın nasıl gömüldüğü ve beacon'lardan nasıl çıkarılacağı
- HTTP/SMB/TCP listener'ları için ağ/profil göstergeleri
- Vahşi ortamda gözlemlenen yaygın loader ve persistence TTP'leri ve ilgili Windows teknik sayfalarına bağlantılar

Son upstream sürümleri ayrıca DNS/DoH beacon listener'ları ve ayrı Gopher agent/listener ailesiyle birlikte sunuluyor. Bu nedenle, belirli bir örnek hâlâ klasik beacon agent'ını kullanıyor olsa bile, modern Adaptix altyapısı orijinal HTTP/SMB/TCP yüzeylerinden daha fazlasını açığa çıkarabilir.<sup>[[2]](#references)</sup>

## Beacon profilleri ve alanları

AdaptixC2 üç temel beacon türünü destekler:<sup>[[1]](#references)</sup>
- BEACON_HTTP: yapılandırılabilir sunucular/portlar/SSL, method, URI, headers, user-agent ve özel parametre adı içeren web C2
- BEACON_SMB: adlandırılmış pipe kullanan eşler arası C2 (intranet)
- BEACON_TCP: protokol başlangıcını gizlemek için başına bir işaretçi eklenebilen doğrudan socket'ler

Bunlar, ilk Adaptix analizlerinde herkese açık olarak belgelenen beacon düzenleridir ve örnek tarafındaki çıkarma işlemleri için hâlâ en yaygın başlangıç noktasıdır.<sup>[[1]](#references)</sup> Ancak güncel upstream sürümler sunucu tarafında `BeaconDNS` ve Gopher extender'ları da içerir. Bu nedenle, çalışan her Adaptix dağıtımının yalnızca HTTP/SMB/TCP altyapısını açığa çıkardığını varsaymayın.<sup>[[2]](#references)</sup>

Aşağıdaki alan özeti ve JSON örnekleri, 2025'te analiz edilen HTTP formatını açıklar; daha yeni upstream sürümleri için parser spesifikasyonu değildir. Bu örneklerdeki tipik alanlar (şifre çözme sonrasında):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (string dizisi), ports (u32 dizisi)
- http_method, uri, parameter, user_agent, http_headers (uzunluk önekli string'ler)
- ans_pre_size (u32), ans_size (u32) – yanıt boyutlarını ayrıştırmak için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Güncel BeaconHTTP sürümleri ayrıca operatörün birden fazla URI, user-agent, Host header'ı ve sunucu arasında sıralı veya rastgele seçimle rotasyon yapmasını destekler.<sup>[[2]](#references)</sup> Bu, tehdit avcılığı açısından, tek bir virüslü host'un klasik RC4 ile paketlenmiş beacon ailesinden çıkmadan birden fazla callback yolu ve header kombinasyonunu kullanabileceği anlamına gelir.

Örnek varsayılan HTTP profili (beacon build'inden):<sup>[[1]](#references)</sup>

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

Operatör builder'da Create'e tıkladığında AdaptixC2, şifrelenmiş profili beacon'a derler. Profilin PE veya shellcode'un sonunda olduğunu varsaymayın: profil baytlarını bölüm taramasıyla veya örnekte `getProfile()` işlevini izleyerek bulun. Paketlenmiş biçim şöyledir:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bayt: yapılandırma boyutu (uint32, little‑endian)
- N bayt: RC4 ile şifrelenmiş yapılandırma verisi
- 16 bayt: RC4 anahtarı

Beacon loader, 16 baytlık anahtarı sondan kopyalar ve N baytlık bloğun şifresini yerinde RC4 ile çözer:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Pratik etkileri:<sup>[[1]](#references)</sup>
- Yapının tamamı genellikle PE .rdata bölümünde bulunur.
- Çıkarma deterministiktir: boyutu oku, bu boyuttaki ciphertext'i oku, hemen ardından yerleştirilmiş 16 baytlık anahtarı oku, sonra RC4 ile şifreyi çöz.

## Yapılandırma çıkarma iş akışı (savunmacılar)

Beacon'ı çıkarmadan önce genel örnek triyajı için [Malware Analysis](malware-analysis.md) sayfasına bakın.

Beacon mantığını taklit eden bir çıkarıcı yazın:<sup>[[1]](#references)</sup>
1) Blob'u PE içinde bulun (genellikle .rdata). Uygulanabilir bir yaklaşım, .rdata'yı olası bir [size|ciphertext|16‑byte key] düzeni için taramak ve RC4'ü denemektir.
2) İlk 4 baytı oku → size (uint32 LE).
3) Sonraki N=size baytı oku → ciphertext.
4) Son 16 baytı oku → RC4 key.
5) Ciphertext'in RC4 ile şifresini çöz. Ardından düz profili şöyle ayrıştır:
   - yukarıda belirtildiği şekilde u32/boolean skalerler
   - uzunluk önekli dizeler (u32 uzunluk ve ardından baytlar; sonda NUL bulunabilir)
   - diziler: servers_count ve ardından bu sayıda [string, u32 port] çifti

2025 saha sıralamasındaki önceden çıkarılmış bir blob için Legacy HTTP Python proof-of-concept (bağımsız, harici bağımlılık yok). Yeni stock build'ler için aşağıdaki current-schema parser'ı kullanın:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Mevcut stock HTTP ve DNS profillerini ayrıştırma

Güncel upstream önce altı little-endian `u32` değeri içerir: agent watermark/type, kill date, çalışma süresi, sleep, jitter ve listener watermark/type. HTTP’ye özgü veriler daha sonra tek baytlık bir SSL flag’iyle başlar. Legacy örneğin aksine, ardından sayımlı URI, user-agent ve Host-header listeleri, rotation mode ve proxy ayarları gelir. Bu nedenle legacy parser, SSL flag’ini kill-date alanından okumaya başlar ve bu build’lerde hatalı sonuçlar üretir. Bu profilde string uzunlukları ve integer değerleri little-endian encoding kullanır; packed string’ler boş olmadığında sondaki bir NUL içerir.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Yukarıdaki `P` ve `rc4` helper’larıyla, şifresi çözülmüş **stock HTTP** plaintext üzerinde bu parser’ı kullanın. HTTP profili proxy username ve password içerebileceğinden RC4 key’ini herkese açık raporlarda paylaşmayın.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Mevcut bir stock HTTP plaintext profilini ayrıştırma</summary>

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

Standart bir DNS beacon için aynı altı yaygın `u32` alanını, ardından uzunluk önekli `domain`, `resolvers`, `doh_resolvers` ve `qtype` dizelerini okuyun. `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` ve `dns_mode` değerlerini `u32` olarak, ardından uzunluk önekli DoH user-agent dizesini okuyun. `dns_mode`, UDP, DoH ve iki fallback yönünü birbirinden ayırır. Bu ayrı bir yerleşimdir: DNS plaintext verisini HTTP parser'ından geçirmeye çalışmayın.<sup>[[12]](#references)[[13]](#references)</sup>

İpuçları:
- Otomasyon yaparken, .rdata'yı okumak için bir PE parser kullanın ve ardından kayan pencere uygulayın: her o offset'i için size = u32(.rdata[o:o+4]) değerini deneyin, ct = .rdata[o+4:o+4+size] olarak alın, sonraki 16 baytı aday key olarak belirleyin; RC4 ile şifresini çözün ve dize alanlarının UTF-8 olarak çözüldüğünü, uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı uzunluk önekli kuralları izleyerek ayrıştırın.

## Özel listener profilleri: yalnızca klasik HTTP şemasını sabit kodlamayın

Dış paketleme biçimi (`u32 size | RC4 ciphertext | 16-byte key`) yeniden kullanılabilir; böylece aktörün özelleştirdiği listener'lar, şifresi çözülen alan yerleşimini tamamen değiştirse de aynı çıkarım iş akışını kullanabilir.

Buna iyi bir güncel örnek, çıkarılan Adaptix beacon'ın standart bir HTTP/TCP profili içermediği Mart 2026 Tropic Trooper kampanyasıdır. Bunun yerine, şifresi çözülen blob şu GitHub transport parametrelerini içeriyordu:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (örneğin `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Uygulanabilir parser stratejisi:
- Önce dış RC4 blob'unu her zamanki gibi tespit edin.
- Şifre çözme işleminden sonra, hemen HTTP parser'ını zorlamak yerine sentinel dizelere ve alanların makullüğüne göre dallanın.
- İyi sentinel'lar arasında `api.github.com`, `/issues?state=open`, HTTP fiilleri/URI'ler, named pipe biçimli dizeler veya bariz şekilde geçerli sunucu/port dizileri bulunur.
- HTTP parser başarısız olursa ancak plaintext tutarlı, uzunluk önekli UTF-8 dizeleri içeriyorsa örneği atıp yanlış pozitif saymak yerine saklayın ve alternatif şemaları deneyin.

Bu kampanyada özel listener, C2 transport olarak GitHub issues'ı kullandı ve beacon, GitHub API'si kurbanın kaynak adresini doğrudan operatöre göstermediği için harici IP'sini öğrenmek üzere `ipinfo.io`'ya sorgu gönderdi.<sup>[[5]](#references)</sup>

## Ağ parmak izi çıkarma ve tehdit avcılığı

HTTP:<sup>[[1]](#references)</sup>
- Yaygın: operatörün seçtiği URI'lere POST (ör. /uri.php, /endpoint/api)
- Beacon ID için kullanılan özel header parametresi (ör. X‑Beacon‑Id, X‑App‑Id)
- Firefox 20'yi veya güncel Chrome derlemelerini taklit eden user-agent'lar
- sleep_delay/jitter_delay üzerinden gözlemlenebilen polling sıklığı
- Daha yeni derlemeler callback'ler arasında URI'leri, user-agent'ları, Host header'larını ve sunucuları değiştirebilir; bu nedenle tek bir path/UA ikilisi varsaymak yerine yaygın olmayan header adları, yanıt boyutu örüntüleri, TLS yeniden kullanımı ve zamanlamaya göre kümeleme yapın.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Web çıkışının kısıtlı olduğu durumlarda intranet C2 için SMB named-pipe listener'ları
- TCP beacon'ları, protokol başlangıcını gizlemek amacıyla trafiğin önüne birkaç bayt ekleyebilir

Mevcut upstream teamserver varsayılanları
- `profile.yaml` şu anda teamserver için `0.0.0.0:4321`, `/endpoint` endpoint'ini, `server.rsa.crt` ve `server.rsa.key` sertifika/anahtar dosya adlarını ve HTTP, SMB, TCP, DNS, Beacon agent ve Gopher için extender'ları içerir.<sup>[[2]](#references)</sup>
- Eşleşmeyen route'larda varsayılan hata işleyicisi `Server: AdaptixC2` ve `Adaptix-Version: v1.2` döndürür.<sup>[[4]](#references)</sup>
- Standart 404 gövdesinde `AdaptixC2 404` ve `You need to enter the correct connection details` bulunur.<sup>[[4]](#references)</sup>
- 2026'da internet genelinde yapılan taramalarda `4321` portunda çok sayıda açık teamserver ve `43211` portunda çok sayıda beacon listener bulundu; bu nedenle her iki port da başlangıç pivot noktaları olarak kullanışlıdır ancak tüm olasılıkları kapsadıkları varsayılmamalıdır.<sup>[[4]](#references)</sup>

DNS/DoH listener parmak izleri:<sup>[[4]](#references)</sup>
- Mevcut BeaconDNS extender yetkili yanıt verir (`AA=true`)
- Beacon protokol biçimiyle eşleşmeyen sorgular — özellikle yapılandırılan domain'den önce 5'ten az label içeren adlar — genellikle `TXT "OK"` yanıtı alır
- Yapılandırılan temel TTL sıfır bırakılırsa listener, 10 saniyelik bir temel değer kullanır ve buna 59 saniyeye kadar jitter ekler
- Bu nedenle, HTTP listener açığa çıkmadığında kısa label'larla yapılan aktif yoklamalar işe yarar

## Olaylarda görülen loader ve persistence TTP'leri

Bellek içi PowerShell loader'ları:<sup>[[1]](#references)</sup>
- Base64/XOR payload'ları indirir (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Yönetilmeyen bellek ayırır, shellcode'u kopyalar ve VirtualProtect aracılığıyla korumayı 0x40 (PAGE_EXECUTE_READWRITE) olarak değiştirir.<sup>[[7]](#references)</sup>
- .NET dynamic invocation ile çalıştırır: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Trojan'laştırılmış imzalı yazılım / aşamalı shellcode loader'ları:<sup>[[5]](#references)</sup>
- 2026'da görülen bir Tropic Trooper zincirinde, PE entry point'ini yamamak yerine `_security_init_cookie` işlevini kötü amaçlı koda yönlendiren trojan'laştırılmış bir SumatraPDF çalıştırılabilir dosyası (TOSHIS loader) kullanıldı
- Loader, API'leri Adler-32 hashing ile çözdü, sahte bir PDF indirdi, ikinci aşama shellcode'u aldı, WinCrypt aracılığıyla AES-128-CBC ile (sabit kodlanmış bir seed'den `CryptDeriveKey` kullanarak) şifresini çözdü ve bellekteki bir Adaptix beacon'ı reflectively çalıştırdı
- Persistence daha sonra, agent'ı yaklaşık iki saatte bir yeniden başlatacak şekilde yapılandırılmış, `\MSDNSvc` veya `\MicrosoftUDN` gibi zararsız görünen adlara sahip scheduled task'lere taşındı

Bellek içi çalıştırma ve AMSI/ETW konuları için şu sayfalara göz atın:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mekanizmaları:<sup>[[1]](#references)</sup>
- Oturum açıldığında loader'ı yeniden başlatmak için Startup klasöründe kısayol (.lnk)
- Registry Run key'leri (HKCU/HKLM ...\CurrentVersion\Run); çoğunlukla loader.ps1'i başlatmak için "Updater" gibi zararsız görünen adlar kullanılır.<sup>[[10]](#references)</sup>
- Etkilenen süreçler için %APPDATA%\Microsoft\Windows\Templates altına msimg32.dll bırakarak DLL search-order hijacking

Tekniğin ayrıntılı incelemeleri ve kontroller:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Tehdit avcılığı fikirleri
- PowerShell'de RW→RX geçişleri oluşturan süreçler: powershell.exe içinde PAGE_EXECUTE_READWRITE'e VirtualProtect geçişleri.<sup>[[8]](#references)</sup>
- Dynamic invocation örüntüleri (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` veya `You need to enter the correct connection details` içeren, eşleşmeyen HTTPS 404 yanıtları.<sup>[[4]](#references)</sup>
- Şüpheli domain'ler altındaki kısa sorgulara `AA=true` ve `TXT "OK"` içeren DNS yanıtları.<sup>[[4]](#references)</sup>
- Aynı loader/beacon zincirinden gelen `/repos/<owner>/<repo>/issues` adresine GitHub API trafiği ve ardından `ipinfo.io` sorguları.<sup>[[5]](#references)</sup>
- Kullanıcıya ait veya ortak Startup klasörlerindeki başlangıç .lnk dosyaları.<sup>[[1]](#references)</sup>
- Şüpheli Run key'leri (ör. "Updater") ve update.ps1/loader.ps1 gibi loader adları.<sup>[[1]](#references)</sup>
- Sahte bir belgeyi göstermeden önce `_security_init_cookie` işlevini downloader koduna yönlendiren trojan'laştırılmış PE örnekleri.<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates altındaki, kullanıcı tarafından yazılabilir ve msimg32.dll içeren DLL yolları.<sup>[[1]](#references)</sup>

## OpSec alanları hakkında notlar

- KillDate: agent'ın kendini sonlandıracağı zaman damgası.<sup>[[1]](#references)</sup>
- WorkingTime: agent'ın iş etkinliğine uyum sağlamak için aktif olması gereken saatler.<sup>[[1]](#references)</sup>

Bu alanlar, kümelendirme ve gözlemlenen sessiz dönemleri açıklama amacıyla kullanılabilir.

## YARA ve statik ipuçları

Unit 42, beacon'lar (C/C++ ve Go) ile loader API-hashing sabitleri için temel YARA kuralları yayımladı.<sup>[[1]](#references)</sup> Kuralları; PE .rdata sonuna yakın [size|ciphertext|16-byte-key] yerleşimini, varsayılan HTTP profil dizelerini ve `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` ve `ipinfo.io` gibi daha yeni sunucu/listener işaretleyicilerini arayacak şekilde genişletmeyi değerlendirin.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Gerçek Dünya Saldırılarında Kullanılan Yeni Bir Açık Kaynak Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Belgeleri](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Açık Kaynak Bir C2 Framework'ünün Büyük Ölçekte Parmak İzinin Çıkarılması (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper, AdaptixC2 ve Özel Beacon Listener'a Yöneliyor (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Bellek koruma sabitleri – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Key'leri/Startup Klasörü](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profil oluşturma (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profil parser'ı (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profili oluşturma (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profil paketleme (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
