# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Neden önemli

LDAP relay/MITM, saldırganların bind işlemlerini kimlik doğrulamalı bağlamlar elde etmek için Domain Controller'lara iletmesine izin verir. Bu yolları kesen iki sunucu tarafı kontrolü vardır:

- **LDAP Channel Binding (CBT)**, bir LDAPS bind'ini belirli TLS tüneline bağlar; bu, farklı kanallar arasında yapılan relay/replay'leri engeller.
- **LDAP Signing**, bütünlüğü korunmuş LDAP mesajlarını zorunlu kılar; değiştirmeyi ve çoğu imzasız relay'i önler.

**Hızlı ofensif kontrol**: `netexec ldap <dc> -u user -p pass` gibi araçlar sunucu duruşunu gösterir. Eğer `(signing:None)` ve `(channel binding:Never)` görürseniz, Kerberos/NTLM **relays to LDAP** mümkündür (ör. KrbRelayUp kullanarak RBCD için `msDS-AllowedToActOnBehalfOfOtherIdentity` yazmak ve yöneticileri taklit etmek).

**Server 2025 DCs** yeni bir GPO (**LDAP server signing requirements Enforcement**) getirir; bu GPO varsayılan olarak **Not Configured** bırakıldığında **Require Signing** olarak uygulanır. Zorlamayı önlemek için bu politikayı açıkça **Disabled** olarak ayarlamanız gerekir.

## LDAP Channel Binding (LDAPS only)

- **Gereksinimler**:
- CVE-2017-8563 yaması (2017) Extended Protection for Authentication desteği ekler.
- **KB4520412** (Server 2019/2022) LDAPS CBT “what-if” telemetrisi ekler.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (varsayılan, CBT yok)
- `When Supported` (denetim: hatalar raporlanır, engellemez)
- `Always` (zorla: geçerli CBT olmadan LDAPS bind'lerini reddeder)
- **Denetim**: ortaya çıkarmak için **When Supported** olarak ayarlayın:
- **3074** – LDAPS bind, zorlanmış olsaydı CBT doğrulamasında başarısız olurdu.
- **3075** – LDAPS bind CBT verisini atladı ve zorlanmış olsaydı reddedilirdi.
- (Event **3039** eski yapı sürümlerinde hâlâ CBT hatalarını bildirir.)
- **Zorlama**: LDAPS istemcileri CBT gönderdiğinde **Always** olarak ayarlayın; yalnızca **LDAPS** (ham 389 değil) üzerinde etkilidir.

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (modern Windows'te varsayılan `Negotiate signing`'e karşın).
- **DC GPO**:
- Eski: `Domain controller: LDAP server signing requirements` = `Require signing` (varsayılan `None`).
- **Server 2025**: legacy politikayı `None` olarak bırakın ve `LDAP server signing requirements Enforcement` = `Enabled` olarak ayarlayın (Not Configured = varsayılan olarak zorlanır; önlemek için `Disabled` olarak ayarlayın).
- **Uyumluluk**: LDAP signing yalnızca Windows **XP SP3+** tarafından desteklenir; eski sistemler zorlamalar etkinleştirildiğinde bozulacaktır.

## Denetim-öncelikli dağıtım (önerilen ~30 gün)

1. Her DC'de imzasız bind'leri kaydetmek için LDAP arayüz tanılama günlüklerini etkinleştirin (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. CBT telemetrisi başlatmak için DC GPO `LDAP server channel binding token requirements` = **When Supported** olarak ayarlayın.
3. Directory Service olaylarını izleyin:
- **2889** – unsigned/unsigned-allow binds (imzalama uyumsuz).
- **3074/3075** – LDAPS binds that would fail or omit CBT (2019/2022 için KB4520412 ve yukarıdaki adım 2 gereklidir).
4. Ayrı değişikliklerle uygulayın:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Referanslar

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
