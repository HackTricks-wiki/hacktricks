# AdaptixC2 Yapılandırma Çıkarma ve TTP’ler

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2, Windows x86/x64 beacon’ları (EXE/DLL/service EXE/raw shellcode) ve BOF desteği bulunan modüler, açık kaynaklı bir post-exploitation/C2 framework’üdür.<sup>[[1]](#references)</sup> Bu sayfada şunlar belgelenmektedir:
- RC4 ile paketlenmiş yapılandırmasının nasıl gömüldüğü ve beacon’lardan nasıl çıkarılacağı
- HTTP/SMB/TCP listener’ları için ağ/profil göstergeleri
- İlgili Windows technique sayfalarına bağlantılarla, sahada gözlemlenen yaygın loader ve persistence TTP’leri

Son upstream sürümler ayrıca DNS/DoH beacon listener’ları ile ayrı Gopher agent/listener ailesini de sunuyor. Bu nedenle, belirli bir örnek hâlâ klasik beacon agent’ını kullansa bile modern Adaptix altyapısı orijinal HTTP/SMB/TCP yüzeylerinden daha fazlasını açığa çıkarabilir.<sup>[[2]](#references)</sup>

## Beacon profilleri ve alanlar

AdaptixC2 üç temel beacon türünü destekler:<sup>[[1]](#references)</sup>
- BEACON_HTTP: yapılandırılabilir sunucular/portlar/SSL, method, URI, headers, user-agent ve özel bir parametre adı içeren web C2
- BEACON_SMB: adlandırılmış pipe kullanan eşler arası C2 (intranet)
- BEACON_TCP: protokol başlangıcını gizlemek için başına bir işaretçi eklenebilen doğrudan soketler

Bunlar, ilk Adaptix analizlerinde kamuya açık şekilde belgelenen beacon düzenleridir ve örnek tarafında çıkarma işlemi için hâlâ en yaygın başlangıç noktalarıdır.<sup>[[1]](#references)</sup> Ancak güncel upstream build’ler sunucu tarafında `BeaconDNS` ve Gopher extender’larını da sunuyor. Bu nedenle her canlı Adaptix kurulumunun yalnızca HTTP/SMB/TCP altyapısını açığa çıkardığını varsaymayın.<sup>[[2]](#references)</sup>

Aşağıdaki alan özeti ve JSON örnekleri, 2025’te analiz edilen HTTP formatını açıklar; bunlar daha yeni upstream build’ler için bir parser spesifikasyonu değildir. Bu örneklerdeki tipik alanlar (şifre çözme sonrasında):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (string dizisi), ports (u32 dizisi)
- http_method, uri, parameter, user_agent, http_headers (uzunluk önekli string’ler)
- ans_pre_size (u32), ans_size (u32) – yanıt boyutlarını ayrıştırmak için kullanılır
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Güncel BeaconHTTP build’leri ayrıca operator tarafından seçilen birden fazla URI, user-agent, Host header ve sunucu arasında sıralı veya rastgele geçişi destekler.<sup>[[2]](#references)</sup> Bu, tehdit avcılığı açısından, tek bir ele geçirilmiş host’un klasik RC4 ile paketlenmiş beacon ailesinden ayrılmadan birden fazla callback yolu ve header kombinasyonu kullanabileceği anlamına gelir.

Örnek varsayılan HTTP profili (bir beacon build’inden):<sup>[[1]](#references)</sup>

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

Operatör builder'da Create'e tıkladığında AdaptixC2, şifrelenmiş profili beacon'a derler. Bunun PE'nin veya shellcode'un sonunda olduğunu varsaymayın: profil baytlarını bölüm taramasıyla veya örnekteki `getProfile()` işlevini izleyerek bulun. Paketlenmiş biçim şöyledir:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 bayt: yapılandırma boyutu (uint32, little-endian)
- N bayt: RC4 ile şifrelenmiş yapılandırma verisi
- 16 bayt: RC4 anahtarı

Beacon loader, 16 baytlık anahtarı sondan kopyalar ve N baytlık bloğun şifresini yerinde RC4 ile çözer:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Pratik sonuçlar:<sup>[[1]](#references)</sup>
- Tüm yapı çoğu zaman PE .rdata bölümünde bulunur.
- Çıkarma deterministiktir: boyutu oku, bu boyuttaki ciphertext'i oku, hemen arkasına yerleştirilmiş 16 baytlık anahtarı oku, ardından RC4 ile şifre çöz.

## Yapılandırma çıkarma iş akışı (savunucular)

Beacon'ı carve etmeden önce genel sample triage için bkz. [Malware Analysis](malware-analysis.md).

Beacon mantığını taklit eden bir extractor yazın:<sup>[[1]](#references)</sup>
1) Blob'u PE içinde bulun (genellikle .rdata). Uygulanabilir bir yaklaşım, .rdata içinde makul bir [size|ciphertext|16-byte key] düzeni taramak ve RC4'ü denemektir.
2) İlk 4 baytı oku → boyut (uint32 LE).
3) Sonraki N=size baytı oku → ciphertext.
4) Son 16 baytı oku → RC4 anahtarı.
5) Ciphertext'in RC4 ile şifresini çöz. Ardından düz profil'i şu şekilde ayrıştır:
   - yukarıda belirtildiği gibi u32/boolean skalerleri
   - uzunluk önekli dizeler (u32 uzunluk ve ardından baytlar; sonda NUL bulunabilir)
   - diziler: servers_count ve ardından bu sayıda [string, u32 port] çifti

2025'teki alan sırasını kullanan, önceden çıkarılmış bir blob için eski HTTP Python proof-of-concept'i (bağımsız, harici bağımlılık gerektirmez). Güncel stock build'ler için aşağıdaki current-schema parser'ı kullanın:<sup>[[1]](#references)[[11]](#references)</sup>

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

Güncel upstream önce altı little-endian `u32` değeri paketler: agent watermark/type, kill date, çalışma zamanı, sleep, jitter ve listener watermark/type. HTTP’ye özgü veriler daha sonra tek baytlık bir SSL flag’iyle başlar. Legacy örneğinden farklı olarak, bu profilde sayıları belirtilmiş URI, user-agent ve Host-header listeleri; ardından da rotation mode ve proxy ayarları bulunur. Bu nedenle legacy parser, SSL flag’ini kill-date alanından okumaya başlar ve bu sürümlerde hatalı sonuçlar üretir. Bu profilde string uzunlukları ve integer değerleri little-endian encoding kullanır; boş olmayan paketlenmiş string’lerin sonunda NUL bulunur.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Yukarıdaki `P` ve `rc4` helper’larını kullanarak, şifresi çözülmüş **stock HTTP** plaintext üzerinde bu parser’ı kullanın. RC4 key’ini herkese açık raporlarda paylaşmayın: HTTP profili bir proxy username ve password içerebilir.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Güncel bir stock HTTP plaintext profilini ayrıştırma</summary>

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

Standart bir DNS beacon için aynı altı yaygın `u32` alanı, ardından uzunluk önekli `domain`, `resolvers`, `doh_resolvers` ve `qtype` dizelerini okuyun. `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` ve `dns_mode` alanlarını `u32` olarak, ardından uzunluk önekli DoH user-agent dizesini okuyun. `dns_mode`, UDP, DoH ve iki fallback yönünü birbirinden ayırır. Bu ayrı bir düzendir: DNS plaintext verisini HTTP parser üzerinden işlemeye zorlamayın.<sup>[[12]](#references)[[13]](#references)</sup>

İpuçları:
- Otomasyon yaparken `.rdata` verisini okumak için bir PE parser kullanın, ardından kayan pencere uygulayın: her `o` ofseti için `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, aday anahtar = sonraki 16 bayt olacak şekilde deneyin; RC4 ile şifresini çözün ve dize alanlarının UTF-8 olarak çözüldüğünü, uzunlukların makul olduğunu kontrol edin.
- SMB/TCP profillerini aynı uzunluk önekli kuralları izleyerek ayrıştırın.

## Özel listener profilleri: yalnızca klasik HTTP şemasını sabit kodlamayın

Dış paketleme biçimi (`u32 size | RC4 ciphertext | 16-byte key`) yeniden kullanılabilir; bu nedenle actor tarafından özelleştirilmiş listener'lar, çözülen alan düzenini tamamen değiştirirken aynı çıkarma iş akışını kullanabilir.

Yakın tarihli iyi bir örnek, çıkarılan Adaptix beacon'ın standart bir HTTP/TCP profili içermediği Mart 2026 Tropic Trooper kampanyasıdır. Bunun yerine, çözülen blob aşağıdaki gibi GitHub taşıma parametrelerini içeriyordu:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (örneğin `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Uygulanabilir parser stratejisi:
- Önce dış RC4 blob'unu her zamanki gibi tespit edin.
- Şifre çözme işleminden sonra hemen HTTP parser'ı zorlamak yerine sentinel dizelerine ve alanların makullüğüne göre dallanın.
- İyi sentinel'lar arasında `api.github.com`, `/issues?state=open`, HTTP fiilleri/URI'leri, named-pipe biçimindeki dizeler veya geçerli olduğu açık sunucu/port dizileri bulunur.
- HTTP parser başarısız olursa ancak plaintext tutarlı uzunluk önekli UTF-8 dizeleri içeriyorsa, örneği yanlış pozitif sayıp atmak yerine koruyun ve alternatif şemaları deneyin.

Bu kampanyada özel listener, C2 taşıması olarak GitHub issues'ı kullandı; beacon ise GitHub API'si kurbanın kaynak adresini doğrudan operatöre göstermediğinden harici IP'sini öğrenmek için `ipinfo.io`'ya sorgu gönderdi.<sup>[[5]](#references)</sup> Ayrı bir issue ve repository dosyası el sıkışması için bkz. [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Ağ parmak izi çıkarma ve hunting

HTTP:<sup>[[1]](#references)</sup>
- Yaygın: operatörün seçtiği URI'lere POST (ör. /uri.php, /endpoint/api)
- Beacon ID için kullanılan özel header parametresi (ör. X‑Beacon‑Id, X‑App‑Id)
- Firefox 20'yi veya güncel Chrome sürümlerini taklit eden user-agent'lar
- `sleep_delay`/`jitter_delay` ile görülebilen polling aralığı
- Daha yeni sürümler callback'ler arasında URI'leri, user-agent'ları, Host header'larını ve sunucuları değiştirebilir; bu nedenle tek bir path/UA çiftini varsaymak yerine alışılmadık header adlarına, yanıt boyutu örüntülerine, TLS yeniden kullanımına ve zamanlamaya göre kümelendirin.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Web egress'in kısıtlı olduğu intranet C2 için SMB named-pipe listener'ları
- TCP beacon'ları, protokol başlangıcını gizlemek için trafiğin önüne birkaç bayt ekleyebilir

Mevcut upstream teamserver varsayılanları
- `profile.yaml` şu anda `0.0.0.0:4321` teamserver'ı, `/endpoint` endpoint'ini, `server.rsa.crt` ve `server.rsa.key` sertifika/anahtar dosyalarını ve HTTP, SMB, TCP, DNS, Beacon agent ve Gopher extender'larını içerir.<sup>[[2]](#references)</sup>
- Eşleşmeyen route'larda varsayılan hata işleyicisi `Server: AdaptixC2` ve `Adaptix-Version: v1.2` döndürür.<sup>[[4]](#references)</sup>
- Standart 404 gövdesinde `AdaptixC2 404` ve `You need to enter the correct connection details` bulunur.<sup>[[4]](#references)</sup>
- 2026'daki internet çapındaki taramalarda `4321` portunda çok sayıda açık teamserver ve `43211` portunda çok sayıda beacon listener bulundu; bu nedenle her iki port da başlangıç pivotları için kullanışlıdır ancak kapsamlı kabul edilmemelidir.<sup>[[4]](#references)</sup>

DNS/DoH listener parmak izleri:<sup>[[4]](#references)</sup>
- Mevcut BeaconDNS extender yetkili yanıt verir (`AA=true`)
- Beacon protokolü biçimiyle eşleşmeyen sorgular — özellikle yapılandırılmış domain öncesinde 5'ten az label içeren adlar — genellikle `TXT "OK"` yanıtı alır
- Yapılandırılmış temel TTL sıfır bırakılırsa listener 10 saniyelik bir temel değer kullanır ve en fazla 59 saniyelik jitter ekler
- Bu sayede, HTTP listener açığa çıkmadığında kısa label'larla yapılan active probe'lar kullanışlı olur

## Olaylarda görülen loader ve persistence TTP'leri

Bellek içi PowerShell loader'ları:<sup>[[1]](#references)</sup>
- Base64/XOR payload'ları indirir (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Yönetilmeyen bellek ayırır, shellcode'u kopyalar, VirtualProtect aracılığıyla korumayı 0x40 (PAGE_EXECUTE_READWRITE) olarak değiştirir.<sup>[[7]](#references)</sup>
- .NET dynamic invocation ile çalıştırır: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Truva atı eklenmiş imzalı yazılımlar / aşamalı shellcode loader'ları:<sup>[[5]](#references)</sup>
- 2026'daki bir Tropic Trooper zincirinde, PE entry point'ini yamamak yerine `_security_init_cookie` işlevini kötü amaçlı koda yönlendiren, truva atı eklenmiş bir SumatraPDF çalıştırılabilir dosyası (TOSHIS loader) kullanıldı
- Loader, API'leri Adler-32 hashing ile çözdü, sahte bir PDF indirdi, ikinci aşama shellcode'u aldı, WinCrypt aracılığıyla AES-128-CBC ile şifresini çözdü (sabit kodlanmış bir seed'den `CryptDeriveKey` kullanarak) ve Adaptix beacon'ı bellekte reflectively çalıştırdı
- Persistence daha sonra, agent'ı yaklaşık iki saatte bir yeniden başlatacak şekilde yapılandırılmış, `\MSDNSvc` veya `\MicrosoftUDN` gibi zararsız görünen adlara sahip scheduled task'lara taşındı

Bellek içi çalıştırma ve AMSI/ETW konuları için şu sayfalara bakın:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Gözlemlenen persistence mekanizmaları:<sup>[[1]](#references)</sup>
- Oturum açıldığında loader'ı yeniden başlatmak için Startup folder kısayolu (.lnk)
- `loader.ps1`'i başlatmak için sıklıkla "Updater" gibi zararsız görünen adlar kullanan Registry Run key'leri (HKCU/HKLM ...\CurrentVersion\Run).<sup>[[10]](#references)</sup>
- Etkilenebilir süreçler için %APPDATA%\Microsoft\Windows\Templates altına msimg32.dll bırakarak DLL search-order hijack

Teknik incelemeleri ve kontroller:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Hunting fikirleri
- RW→RX geçişleri başlatan PowerShell: powershell.exe içinde PAGE_EXECUTE_READWRITE değerine VirtualProtect çağrısı.<sup>[[8]](#references)</sup>
- Dynamic invocation örüntüleri (GetDelegateForFunctionPointer)
- `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` veya `You need to enter the correct connection details` içeren eşleşmeyen HTTPS 404 yanıtları.<sup>[[4]](#references)</sup>
- Şüpheli domain'ler altındaki kısa sorgulara verilen `AA=true` ve `TXT "OK"` içeren DNS yanıtları.<sup>[[4]](#references)</sup>
- Aynı loader/beacon zincirinden gelen `/repos/<owner>/<repo>/issues` adresine yönelik GitHub API trafiğinin ardından yapılan `ipinfo.io` sorguları.<sup>[[5]](#references)</sup>
- Kullanıcının veya ortak Startup folder'larının altındaki başlangıç .lnk dosyaları.<sup>[[1]](#references)</sup>
- Şüpheli Run key'leri (ör. "Updater") ve update.ps1/loader.ps1 gibi loader adları.<sup>[[1]](#references)</sup>
- Sahte bir belge gösterilmeden önce `_security_init_cookie` işlevini downloader koduna yönlendiren truva atı eklenmiş PE örnekleri.<sup>[[5]](#references)</sup>
- %APPDATA%\Microsoft\Windows\Templates altındaki, kullanıcı tarafından yazılabilir DLL path'lerinde bulunan msimg32.dll dosyaları.<sup>[[1]](#references)</sup>

## OpSec alanları hakkında notlar

- KillDate: agent'ın kendini sonlandıracağı zaman damgası.<sup>[[1]](#references)</sup>
- WorkingTime: agent'ın iş etkinliğine uyum sağlamak için aktif olması gereken saatler.<sup>[[1]](#references)</sup>

Bu alanlar, kümelendirme ve gözlemlenen sessiz dönemleri açıklamak için kullanılabilir.

## YARA ve statik ipuçları

Unit 42, beacon'lar (C/C++ ve Go) ve loader API hashing sabitleri için temel YARA kuralları yayımladı.<sup>[[1]](#references)</sup> Bunları, PE `.rdata` sonuna yakın [size|ciphertext|16-byte-key] düzenini, varsayılan HTTP profile dizelerini ve `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` ve `ipinfo.io` gibi daha yeni server/listener işaretleyicilerini arayan kurallarla tamamlamayı değerlendirin.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Gerçek Dünya Saldırılarında Kullanılan Yeni Bir Açık Kaynak Framework (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Adaptix Framework Belgeleri](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Açık Kaynaklı Bir C2 Framework'ünün Ölçekli Parmak İzi Çıkarımı (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper, AdaptixC2'ye ve Özel Beacon Listener'a Yöneliyor (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Bellek koruma sabitleri – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Key'leri/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [AdaptixC2 profil oluşturma (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [AdaptixC2 beacon profile parser'ı (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [AdaptixC2 DNS profil oluşturma (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [AdaptixC2 profil paketleme (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
