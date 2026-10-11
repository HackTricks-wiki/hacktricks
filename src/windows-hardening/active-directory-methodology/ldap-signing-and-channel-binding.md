# LDAP İmzalama ve Kanal Bağlama Güçlendirmesi

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli?

LDAP relay/MITM saldırıları, kimliği doğrulanmış bir LDAP bağlamı elde etmek için kimlik doğrulamayı bir etki alanı denetleyicisine iletir. Birbiriyle ilişkili iki denetim bu yolları azaltır:

- **LDAP channel binding (CBT)**, uygun kimlik doğrulamayı LDAPS tarafından kullanılan TLS sunucu sertifikasına/kanalına bağlayarak kanallar arası relay saldırılarını zorlaştırır.
- **LDAP signing**, SASL LDAP bind işlemleri için bütünlük koruması gerektirir. Gizlilik sağlamaz; LDAP içeriğinin de şifrelenmesi gerekiyorsa TLS kullanın.<sup>[[2]](#references)</sup>

**Hızlı güvenlik durumu kontrolü**: `netexec ldap <dc> -u user -p pass` gibi araçlar, gözlemlenen signing ve channel-binding ilkesini bildirir. `(signing:None)` ve `(channel binding:Never)` denetimlerin eksik olduğunu gösterir; ancak başarılı bir relay, yine de yakalanan kimlik doğrulama türüne, EPA davranışına, hesap ayrıcalıklarına, hedef protokole ve relay korumalarına bağlıdır. Relay edilen principal gerekli haklara sahipse KrbRelayUp gibi araçlar `msDS-AllowedToActOnBehalfOfOtherIdentity` özniteliğine yazabilir, kaynak tabanlı kısıtlı yetkilendirmeyi (RBCD) yapılandırabilir ve ayrıcalıklı bir principal’ı taklit etmek için ortaya çıkan yetkilendirme yolunu kullanabilir.<sup>[[4]](#references)</sup>

**Server 2025 DC’leri**, **LDAP server signing requirements Enforcement** adlı yeni bir GPO’yu kullanıma sunar. Bu ilke **Not Configured** bırakıldığında varsayılan olarak **Require Signing** olur. Zorunlu kılmayı önlemek için bu ilkeyi açıkça **Disabled** olarak ayarlamanız gerekir.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (yalnızca LDAPS)

- **Gereksinimler**:
  - CVE-2017-8563 yaması (2017), Authentication için Extended Protection desteği ekler.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022), LDAPS CBT için “what-if” telemetrisini ekler.<sup>[[2]](#references)</sup>
- **GPO (DC’ler)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (varsayılan, CBT yok)
  - `When Supported` (kısmi zorunlu kılma: CBT destekleyen istemciler geçerli bir belirteç göndermelidir; CBT desteği olmayan istemciler bind işlemi gerçekleştirebilir ve denetim olayları oluşturulur)
  - `Always` (zorunlu kılma: geçerli CBT olmadan yapılan LDAPS bind işlemlerini reddeder)<sup>[[1]](#references)</sup>
- **Denetim**: Aşağıdakileri görmek için **When Supported** ayarını belirleyin:
  - **3074** – Zorunlu kılınsaydı LDAPS bind işlemi CBT doğrulamasında başarısız olacaktı.
  - **3075** – LDAPS bind işleminde CBT verisi yoktu ve zorunlu kılınsaydı reddedilecekti.
  - (Eski derlemelerde **3039** olayı CBT hatalarını bildirmeye devam eder.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Zorunlu kılma**: LDAPS istemcileri CBT gönderdikten sonra **Always** olarak ayarlayın; yalnızca **LDAPS** üzerinde etkilidir (ham 389 üzerinde değil).<sup>[[1]](#references)</sup>

`When Supported` yalnızca denetim yapmaz: CBT destekleyen istemciler için CBT’yi doğrularken CBT desteği olmayan istemcilere izin verir. [Microsoft ilke başvurusu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), sürüme bağlı varsayılanları açıklar. LDAP signing, LDAP/389 üzerindeki uygun bind işlemlerine uygulanır; channel binding ise TLS ile korunan LDAP kimlik doğrulamasına uygulanır.


## LDAP Signing

- **İstemci GPO’su**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows’ta varsayılan olan `Negotiate signing` yerine).<sup>[[1]](#references)</sup>
- **DC GPO’su**:
  - Eski: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: Eski ilkeyi `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` ayarını belirleyin (`Not Configured` varsayılan olarak zorunlu kılar; bunu önlemek için `Disabled` olarak ayarlayın).<sup>[[1]](#references)</sup>
- **Uyumluluk**: Basit bind veya imzasız SASL bind kullanan Windows dışı cihaz ve uygulamaların envanterini çıkarın. Microsoft, bakımı sürdürülen Windows sürümlerinde desteği belgeliyor; eski istemcilerle uyumluluğa ilişkin ifadeler, XP sürüm sınırına indirgenmek yerine gerçek istemci yığınıyla doğrulanmalıdır.<sup>[[2]](#references)</sup>

## Önce denetim, sonra devreye alma (önerilen süre yaklaşık 30 gün)

1. İmzasız bind işlemlerini günlüğe kaydetmek için her DC’de LDAP arayüz tanılamasını etkinleştirin (Olay **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Kısmi CBT zorlaması ve telemetri için DC GPO `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın; önce eski istemcilerle uyumluluğu doğrulayın.<sup>[[1]](#references)</sup>
3. Directory Service olaylarını izleyin:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow bind'leri (imzalama gereksinimlerine uymuyor).
   - **3074/3075** – başarısız olacak veya CBT içermeyecek LDAPS bind'leri (2019/2022'de KB4520412 ve yukarıdaki 2. adımı gerektirir).
4. Ayrı değişikliklerle zorunlu kılın:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC'ler).
   - `LDAP client signing requirements` = **Require signing** (istemciler).
   - `LDAP server signing requirements` = **Require signing** (DC'ler) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding ve LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding ve signing gereksinimleri](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay azaltma güncellemesi](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing devre dışı → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
