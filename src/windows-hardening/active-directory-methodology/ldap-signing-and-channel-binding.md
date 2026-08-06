# LDAP Signing ve Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli

LDAP relay/MITM, saldırganların authenticated context elde etmek için bind isteklerini Domain Controller'lara iletmesine olanak tanır. İki server-side kontrol bu yolları etkisizleştirir:

- **LDAP Channel Binding (CBT)**, bir LDAPS bind işlemini belirli TLS tunnel'ına bağlayarak farklı channel'lar üzerinden yapılan relay/replay saldırılarını engeller.
- **LDAP Signing**, integrity-protected LDAP mesajlarını zorunlu kılar; böylece kurcalamayı ve unsigned relay saldırılarının çoğunu önler.

**Hızlı offensive kontrol**: `netexec ldap <dc> -u user -p pass` gibi araçlar server posture bilgisini yazdırır. `(signing:None)` ve `(channel binding:Never)` görürseniz Kerberos/NTLM **relay'leri LDAP'a** yapılabilir durumdadır (örneğin KrbRelayUp kullanılarak RBCD için `msDS-AllowedToActOnBehalfOfOtherIdentity` yazılabilir ve administrator'lar impersonate edilebilir).<sup>[[4]](#references)</sup>

**Server 2025 DC'leri**, varsayılan olarak **Require Signing** değerini kullanan yeni bir GPO (**LDAP server signing requirements Enforcement**) sunar; politika **Not Configured** olarak bırakıldığında bu değer kullanılır. Enforcement'ı önlemek için bu politikayı açıkça **Disabled** olarak ayarlamanız gerekir.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (yalnızca LDAPS)

- **Gereksinimler**:
- CVE-2017-8563 patch'i (2017), Extended Protection for Authentication desteğini ekler.<sup>[[3]](#references)</sup>
- **GPO (DC'ler)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (varsayılan, CBT yok)
- `When Supported` (audit: failures üretir, block etmez)
- `Always` (enforce: geçerli CBT olmadan yapılan LDAPS bind işlemlerini reddeder)<sup>[[1]](#references)</sup>
- **Audit**: aşağıdakileri görünür hale getirmek için **When Supported** olarak ayarlayın:
- **3074** – LDAPS bind işlemi, enforcement uygulanmış olsaydı CBT validation nedeniyle başarısız olurdu.
- **3075** – LDAPS bind işlemi CBT verilerini içermiyordu ve enforcement uygulanmış olsaydı reddedilirdi.
- (Event **3039**, eski build'lerde CBT failure'larını göstermeye devam eder.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: LDAPS client'ları CBT gönderdiğinde **Always** olarak ayarlayın; yalnızca **LDAPS** üzerinde etkilidir (raw 389 üzerinde değil).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows'ta varsayılan değer olan `Negotiate signing` yerine).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan değer `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: legacy policy'yi `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` olarak ayarlayın (`Not Configured` = varsayılan olarak enforced; bunu önlemek için `Disabled` olarak ayarlayın).<sup>[[1]](#references)</sup>
- **Uyumluluk**: yalnızca **XP SP3+** LDAP signing'i destekler; enforcement etkinleştirildiğinde daha eski sistemler çalışmayı durdurur.

## Önce audit rollout'u (önerilen süre yaklaşık 30 gün)

1. unsigned bind işlemlerini loglamak (Event **2889**) için her DC üzerinde LDAP interface diagnostics'i etkinleştirin:<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT telemetry’yi başlatmak için DC GPO `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın.<sup>[[1]](#references)</sup>
3. Directory Service event’lerini izleyin:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (signing uyumsuz).
- **3074/3075** – başarısız olacak veya CBT’yi atlayacak LDAPS binds (2019/2022’de KB4520412 ve yukarıdaki 2. adım gerekir).
4. Ayrı değişikliklerle enforce edin:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DC’ler).
- `LDAP client signing requirements` = **Require signing** (client’lar).
- `LDAP server signing requirements` = **Require signing** (DC’ler) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
