# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

LDAP relay/MITM дає атакуючим можливість переспрямовувати binds на Domain Controllers, щоб отримати автентифіковані контексти. Два серверні механізми загальмовують ці шляхи:

- **LDAP Channel Binding (CBT)** прив'язує LDAPS bind до конкретного TLS тунелю, що руйнує relays/replays між різними каналами.
- **LDAP Signing** змушує LDAP-повідомлення мати захист цілісності, запобігаючи підміні та більшості unsigned relays.

**Quick offensive check**: інструменти на кшталт `netexec ldap <dc> -u user -p pass` показують поточну конфігурацію сервера. Якщо ви бачите `(signing:None)` і `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** можливі (наприклад, використовуючи KrbRelayUp для запису `msDS-AllowedToActOnBehalfOfOtherIdentity` для RBCD та імітації адміністраторів).

**Server 2025 DCs** вводять новий GPO (**LDAP server signing requirements Enforcement**), який за замовчуванням встановлюється в **Require Signing**, якщо залишити **Not Configured**. Щоб уникнути примусового застосування, ви маєте явно встановити цю політику в **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 patch (2017) додає підтримку Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) додає LDAPS CBT “what-if” телеметрію.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (за замовчуванням, без CBT)
- `When Supported` (audit: реєструє збої, не блокує)
- `Always` (enforce: відхиляє LDAPS binds без валідного CBT)
- **Audit**: встановіть **When Supported** щоб виявити:
- **3074** – LDAPS bind провалив би валідацію CBT, якби було enforced.
- **3075** – LDAPS bind пропустив CBT-дані і був би відхилений при enforcement.
- (Event **3039** все ще сигналізує про помилки CBT на старіших збірках.)
- **Enforcement**: встановіть **Always** після того, як LDAPS клієнти почнуть надсилати CBT; ефективно лише для **LDAPS** (не для raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` за замовчуванням у сучасних Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням `None`).
- **Server 2025**: залиште legacy політику в `None` і встановіть `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = примусово застосовується за замовчуванням; встановіть `Disabled` щоб уникнути цього).
- **Compatibility**: лише Windows **XP SP3+** підтримують LDAP signing; старіші системи зламаються при ввімкненому enforcement.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Налаштуйте DC GPO `LDAP server channel binding token requirements` = **When Supported**, щоб увімкнути телеметрію CBT.
3. Відстежуйте події Directory Service:
- **2889** – unsigned/unsigned-allow binds (підпис не відповідає вимогам).
- **3074/3075** – LDAPS binds, які зазнають невдачі або опускають CBT (вимагає KB4520412 для 2019/2022 та кроку 2 вище).
4. Впроваджуйте окремими змінами:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Посилання

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
