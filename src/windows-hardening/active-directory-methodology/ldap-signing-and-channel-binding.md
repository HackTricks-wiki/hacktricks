# Hardening LDAP Signing і Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

LDAP relay/MITM дає attackers змогу переспрямовувати binds до Domain Controllers для отримання authenticated contexts. Два server-side controls обмежують ці шляхи:

- **LDAP Channel Binding (CBT)** прив’язує LDAPS bind до конкретного TLS tunnel, блокуючи relays/replays між різними channels.
- **LDAP Signing** вимагає integrity-protected LDAP messages, запобігаючи tampering і більшості unsigned relays.

**Швидка offensive перевірка**: такі tools, як `netexec ldap <dc> -u user -p pass`, виводять server posture. Якщо ви бачите `(signing:None)` і `(channel binding:Never)`, **relays до LDAP** через Kerberos/NTLM можливі (наприклад, за допомогою KrbRelayUp можна записати `msDS-AllowedToActOnBehalfOfOtherIdentity` для RBCD та impersonate administrators).<sup>[[4]](#references)</sup>

**Server 2025 DCs** впроваджують нову GPO (**LDAP server signing requirements Enforcement**), яка за замовчуванням встановлює **Require Signing**, якщо залишити її **Not Configured**. Щоб уникнути enforcement, потрібно явно встановити цю policy у **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (лише LDAPS)

- **Requirements**:
- Patch для CVE-2017-8563 (2017) додає підтримку Extended Protection for Authentication.<sup>[[3]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (за замовчуванням, без CBT)
- `When Supported` (audit: генерує failures, але не блокує)
- `Always` (enforce: відхиляє LDAPS binds без valid CBT)<sup>[[1]](#references)</sup>
- **Audit**: встановіть **When Supported**, щоб виявляти:
- **3074** – LDAPS bind завершився б невдало під час CBT validation, якби enforcement був увімкнений.
- **3075** – LDAPS bind не містив CBT data і був би відхилений, якби enforcement був увімкнений.
- (Event **3039** також сигналізує про CBT failures у старіших builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**: встановіть **Always**, щойно LDAPS clients почнуть надсилати CBTs; це ефективно лише для **LDAPS** (не для raw 389).<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (на відміну від стандартного `Negotiate signing` у modern Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням — `None`).<sup>[[2]](#references)</sup>
- **Server 2025**: залиште legacy policy зі значенням `None` і встановіть `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforcement за замовчуванням; встановіть `Disabled`, щоб уникнути його).<sup>[[1]](#references)</sup>
- **Compatibility**: лише Windows **XP SP3+** підтримує LDAP signing; старіші systems перестануть працювати після ввімкнення enforcement.

## Audit-first rollout (рекомендовано приблизно 30 днів)

1. Увімкніть LDAP interface diagnostics на кожному DC, щоб log unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Set DC GPO `LDAP server channel binding token requirements` = **When Supported** to start CBT telemetry.<sup>[[1]](#references)</sup>
3. Відстежуйте події Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds (невідповідність вимогам signing).
- **3074/3075** – LDAPS binds, які завершилися б помилкою або не містили CBT (потрібен KB4520412 для 2019/2022 і наведений вище крок 2).
4. Застосовуйте вимоги в окремих змінах:<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **або** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Посилання

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - вимоги LDAP channel binding і signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - оновлення для mitigation LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
