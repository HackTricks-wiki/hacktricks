# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

LDAP relay/MITM дозволяє зловмисникам переспрямовувати binds до Domain Controllers, щоб отримати автентифіковані контексти. Два контролі на стороні сервера перекривають ці вектори:

- **LDAP Channel Binding (CBT)** прив'язує LDAPS bind до конкретного TLS‑тунелю, унеможливлюючи relays/replays між різними каналами.
- **LDAP Signing** забезпечує цілісність LDAP‑повідомлень, запобігаючи підробці та більшості unsigned relays.

**Quick offensive check**: інструменти на кшталт `netexec ldap <dc> -u user -p pass` виводять стан сервера. Якщо бачите `(signing:None)` і `(channel binding:Never)`, Kerberos/NTLM **relays to LDAP** можливі (наприклад, використовуючи KrbRelayUp щоб записати `msDS-AllowedToActOnBehalfOfOtherIdentity` для RBCD і імітувати адміністраторів).

**Server 2025 DCs** вводять нову GPO (**LDAP server signing requirements Enforcement**), яка за замовчуванням стає **Require Signing**, якщо залишена **Not Configured**. Щоб уникнути примусового застосування, потрібно явно встановити цю політику в **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Вимоги**:
- патч CVE-2017-8563 (2017) додає підтримку Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) додає LDAPS CBT “what-if” телеметрію.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT) -> `Never` (за замовчуванням, без CBT)
- `When Supported` (audit: emits failures, does not block) -> `When Supported` (audit: реєструє невдачі, не блокує)
- `Always` (enforce: rejects LDAPS binds without valid CBT) -> `Always` (enforce: відхиляє LDAPS binds без валідного CBT)
- **Audit**: set **When Supported** to surface:
- **3074** – LDAPS bind would have failed CBT validation if enforced. -> **3074** – LDAPS bind не пройшов би валідацію CBT, якби enforcement був увімкнений.
- **3075** – LDAPS bind omitted CBT data and would be rejected if enforced. -> **3075** – LDAPS bind пропустив CBT-дані і був би відхилений при enforcement.
- (Event **3039** still signals CBT failures on older builds.) -> (Event **3039** все ще сигналізує про помилки CBT на старіших збірках.)
- **Enforcement**: set **Always** once LDAPS clients send CBTs; only effective on **LDAPS** (not raw 389). -> **Enforcement**: встановіть **Always**, коли LDAPS‑клієнти почнуть надсилати CBT; діє тільки для **LDAPS** (не для raw 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows). -> **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (проти `Negotiate signing`, що є значенням за замовчуванням у сучасних Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`). -> Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням `None`).
- **Server 2025**: leave legacy policy at `None` and set `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = enforced by default; set `Disabled` to avoid it). -> **Server 2025**: залиште legacy політику на `None` і встановіть `LDAP server signing requirements Enforcement` = `Enabled` (Not Configured = застосовується за замовчуванням; встановіть `Disabled`, щоб уникнути цього).
- **Compatibility**: only Windows **XP SP3+** supports LDAP signing; older systems will break when enforcement is enabled. -> **Compatibility**: тільки Windows **XP SP3+** підтримує LDAP signing; старіші системи перестануть працювати при увімкненні enforcement.

## Audit-first rollout (recommended ~30 days)

1. Enable LDAP interface diagnostics on each DC to log unsigned binds (Event **2889**): -> 1. Увімкніть діагностику LDAP‑інтерфейсу на кожному DC, щоб логувати unsigned binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Налаштуйте DC GPO `LDAP server channel binding token requirements` = **When Supported**, щоб почати телеметрію CBT.
3. Моніторьте події Directory Service:
- **2889** – unsigned/unsigned-allow binds (несумісність підпису).
- **3074/3075** – LDAPS binds, які зазнали б відмови або пропустили CBT (вимагає KB4520412 на 2019/2022 та кроку 2 вище).
4. Застосуйте окремими змінами:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **або** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
