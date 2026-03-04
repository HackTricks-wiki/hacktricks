# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Neden önemlidir

LDAP relay/MITM, saldırganların bind isteğini Domain Controller'lara iletip kimlik doğrulanmış bağlamlar elde etmesine izin verir. Bu yolları zayıflatan iki sunucu tarafı kontrol vardır:

- **LDAP Channel Binding (CBT)** bir LDAPS bind'ini belirli TLS tüneline bağlar; farklı kanallar arasındaki relay/replay'leri bozar.
- **LDAP Signing** bütünlüğü korunmuş LDAP mesajlarını zorunlu kılar; değiştirmeyi ve çoğu imzasız relay'i engeller.

**Hızlı saldırı kontrolü**: `netexec ldap <dc> -u user -p pass` gibi araçlar sunucunun duruşunu yazdırır. Eğer `(signing:None)` ve `(channel binding:Never)` görürseniz, Kerberos/NTLM **relays to LDAP** mümkündür (ör. KrbRelayUp kullanarak RBCD için `msDS-AllowedToActOnBehalfOfOtherIdentity` yazmak ve yöneticileri taklit etmek).

**Server 2025 DCs** yeni bir GPO (**LDAP server signing requirements Enforcement**) tanıtır; bu GPO **Not Configured** bırakıldığında varsayılan olarak **Require Signing** olur. Zorlamadan kaçınmak için bu policy'yi açıkça **Disabled** olarak ayarlamanız gerekir.

## LDAP Channel Binding (LDAPS yalnızca)

- **Gereksinimler**:
- CVE-2017-8563 yaması (2017) Extended Protection for Authentication desteği ekler.
- **KB4520412** (Server 2019/2022) LDAPS CBT "what-if" telemetrisi ekler.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (varsayılan, CBT yok)
- `When Supported` (denetim: başarısızlıkları kaydeder, engellemez)
- `Always` (zorla: geçerli CBT olmadan LDAPS bind'lerini reddeder)
- **Denetim**: durumları ortaya çıkarmak için **When Supported**'ı ayarlayın:
- **3074** – Eğer zorlanmış olsaydı, LDAPS bind CBT doğrulamasını geçemeyecekti.
- **3075** – LDAPS bind CBT verisini atladı ve zorlanmış olsaydı reddedilecekti.
- (Event **3039**, daha eski build'lerde hâlâ CBT hatalarını bildirir.)
- **Enforcement**: LDAPS istemcileri CBT gönderdiğinde **Always** olarak ayarlayın; sadece **LDAPS** için etkilidir (ham 389 için değil).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows'ta varsayılan `Negotiate signing` ile karşılaştırıldığında).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan `None`).
- **Server 2025**: legacy policy'yi `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` olarak ayarlayın (Not Configured = varsayılan olarak uygulanır; önlemek için `Disabled` olarak ayarlayın).
- **Uyumluluk**: LDAP signing yalnızca Windows **XP SP3+** tarafından desteklenir; daha eski sistemler enforcement etkinleştirildiğinde bozulur.

## Öncelikle denetim ile dağıtım (önerilen ~30 gün)

1. Her DC'de imzasız bind'leri kaydetmek için LDAP arayüz diagnostics özelliğini etkinleştirin (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT telemetrisini başlatmak için DC GPO `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın.
3. Directory Service olaylarını izleyin:
- **2889** – unsigned/unsigned-allow binds (imzalama uyumlu değil).
- **3074/3075** – CBT'yi başarısız kılacak veya atlayacak LDAPS binds (2019/2022 için KB4520412 ve yukarıdaki adım 2 gerektirir).
4. Ayrı değişikliklerle uygulayın:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **veya** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Kaynaklar

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
