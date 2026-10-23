# LDAP Signing ve Channel Binding Sertleştirmesi

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli?

LDAP relay/MITM saldırıları, kimliği doğrulanmış bir LDAP bağlamı elde etmek için kimlik doğrulamayı bir domain controller'a iletir. [İsim çözümleme poisoning ve relay genel bakışı](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) daha geniş iş akışını ele alır. Birbiriyle ilişkili iki kontrol bu saldırı yollarını azaltır:

- **LDAP channel binding (CBT)**, ilgili kimlik doğrulamayı LDAPS tarafından kullanılan TLS sunucu sertifikasına/kanalına bağlayarak kanallar arası relay saldırılarını zorlaştırır.
- **LDAP signing**, SASL LDAP bind işlemlerinde bütünlük koruması gerektirir. Gizlilik sağlamaz; LDAP içeriğinin de şifrelenmesi gerekiyorsa TLS kullanın.<sup>[[2]](#references)</sup>

**Hızlı güvenlik durumu kontrolü**: `netexec ldap <dc> -u user -p pass` gibi araçlar, gözlemlenen signing ve channel-binding ilkelerini bildirir. `(signing:None)` ve `(channel binding:Never)` değerleri kontrollerin eksik olduğunu gösterir; ancak relay işleminin başarılı olması yakalanan kimlik doğrulama türüne, EPA davranışına, hesap ayrıcalıklarına, hedef protokole ve relay korumalarına bağlıdır. Relay edilen kimliğin gerekli haklara sahip olması durumunda KrbRelayUp gibi araçlar `msDS-AllowedToActOnBehalfOfOtherIdentity` değerini yazabilir, resource-based constrained delegation (RBCD) yapılandırabilir ve ayrıcalıklı bir kimliğe bürünmek için ortaya çıkan delegation yolunu kullanabilir.<sup>[[4]](#references)</sup>

**Server 2025 DC'ler**, **Not Configured** bırakıldığında varsayılan olarak **Require Signing** değerini kullanan yeni bir GPO (**LDAP server signing requirements Enforcement**) sunar. Bu zorunluluğu önlemek için ilgili ilkeyi açıkça **Disabled** olarak ayarlamanız gerekir.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (yalnızca LDAPS)

- **Gereksinimler**:
  - CVE-2017-8563 yaması (2017), Extended Protection for Authentication desteği ekler.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022), LDAPS CBT için “what-if” telemetrisi ekler.<sup>[[2]](#references)</sup>
- **GPO (DC'ler)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (varsayılan, CBT yok)
  - `When Supported` (kısmi enforcement: CBT destekleyen istemciler geçerli bir token sağlamalıdır; CBT desteği olmayan istemciler bind işlemi yapmaya devam edebilir ve denetim olayları oluşturulur)
  - `Always` (enforce: geçerli CBT olmadan yapılan LDAPS bind işlemlerini reddeder)<sup>[[1]](#references)</sup>
- **Denetim**: Şunları görmek için **When Supported** değerini ayarlayın:
  - **3074** – Enforcement etkin olsaydı LDAPS bind işlemi CBT doğrulamasında başarısız olurdu.
  - **3075** – LDAPS bind işleminde CBT verisi yoktu ve enforcement etkin olsaydı işlem reddedilirdi.
  - (Eski sürümlerde **3039** olayı CBT hatalarını göstermeye devam eder.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS istemcileri CBT göndermeye başladıktan sonra **Always** değerini ayarlayın; bu ayar yalnızca **LDAPS** için geçerlidir (ham 389 için değil).<sup>[[1]](#references)</sup>

`When Supported` yalnızca denetim amaçlı değildir: CBT destekleyen istemciler için CBT'yi doğrularken CBT desteği olmayan istemcilere izin verir. [Microsoft ilke başvurusu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), sürüme bağlı varsayılanları açıklar. LDAP signing, LDAP/389 üzerindeki ilgili bind işlemlerine uygulanır; channel binding ise TLS korumalı LDAP kimlik doğrulamasına uygulanır.


## LDAP Signing

- **İstemci GPO'su**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows'ta varsayılan olan `Negotiate signing` yerine).<sup>[[1]](#references)</sup>
- **DC GPO'su**:
  - Eski ayar: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: Eski ilkeyi `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` olarak ayarlayın (`Not Configured` varsayılan olarak enforcement uygular; bunu önlemek için `Disabled` olarak ayarlayın).<sup>[[1]](#references)</sup>
- **Uyumluluk**: Simple bind veya imzasız SASL bind kullanan Windows dışı cihaz ve uygulamaların envanterini çıkarın. Microsoft, bakımı sürdürülen Windows sürümlerinde desteği belgeliyor; eski istemci uyumluluğuna ilişkin ifadeler, XP sürüm eşiğine indirgenmek yerine gerçek istemci yığınına göre doğrulanmalıdır.<sup>[[2]](#references)</sup>

## Önce denetim, ardından devreye alma (önerilen süre: yaklaşık 30 gün)

1. İmzasız bind işlemlerini kaydetmek için her DC'de LDAP arayüzü tanılamasını etkinleştirin (Olay **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Kısmi CBT enforcement ve telemetri için DC GPO `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın; önce eski istemcilerle uyumluluğu doğrulayın.<sup>[[1]](#references)</sup>
3. Directory Service olaylarını izleyin:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – imzasız/imzasız-izin verilen bind'ler (signing uyumluluğu yok).
   - **3074/3075** – başarısız olacak veya CBT içermeyecek LDAPS bind'leri (2019/2022'de KB4520412 ve yukarıdaki 2. adım gerekir).
4. Ayrı değişikliklerle enforcement uygulayın:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC'ler).
   - `LDAP client signing requirements` = **Require signing** (istemciler).
   - `LDAP server signing requirements` = **Require signing** (DC'ler) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding ve LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding ve signing gereksinimleri](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay azaltma güncelleştirmesi](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing devre dışı → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
