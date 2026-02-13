# Зміцнення безпеки LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

LDAP relay/MITM дозволяє зловмисникам пересилати binds до Domain Controllers, щоб отримати автентифіковані контексти. Два серверні механізми заглушають ці шляхи:

- **LDAP Channel Binding (CBT)** прив'язує LDAPS bind до конкретного TLS тунелю, блокуючи relays/replays між різними каналами.
- **LDAP Signing** вимагає цілісно-захищені LDAP-повідомлення, запобігаючи підробці і більшості unsigned relays.

**Server 2025 DCs** вводять нову GPO (**LDAP server signing requirements Enforcement**), яка за замовчуванням встановлюється в **Require Signing**, якщо залишити **Not Configured**. Щоб уникнути її застосування, потрібно явно встановити цю політику в **Disabled**.

## LDAP Channel Binding (LDAPS only)

- **Вимоги**:
- CVE-2017-8563 patch (2017) додає підтримку Extended Protection for Authentication.
- **KB4520412** (Server 2019/2022) додає LDAPS CBT “what-if” телеметрію.
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (за замовчуванням, без CBT)
- `When Supported` (аудит: фіксує помилки, не блокує)
- `Always` (примус: відхиляє LDAPS binds без валідного CBT)
- **Аудит**: встановіть **When Supported**, щоб виявити:
- **3074** – LDAPS bind не пройшов би перевірку CBT, якби було примусово.
- **3075** – LDAPS bind не містив даних CBT і був би відхилений при примусі.
- (Подія **3039** все ще сигналізує про помилки CBT на старіших збірках.)
- **Примусове застосування**: встановіть **Always**, коли LDAPS клієнти почнуть надсилати CBT; ефективно лише для **LDAPS** (не для порту 389).

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (на відміну від `Negotiate signing`, яке є за замовчуванням у сучасних Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням — `None`).
- **Server 2025**: залиште спадкову політику в `None` і встановіть LDAP server signing requirements Enforcement = `Enabled` (`Not Configured` = застосовується за замовчуванням; встановіть `Disabled`, щоб уникнути цього).
- **Сумісність**: тільки Windows **XP SP3+** підтримує LDAP signing; старіші системи перестануть працювати при увімкненому примусі.

## Розгортання з акцентом на аудит (рекомендується ~30 днів)

1. Увімкніть LDAP interface diagnostics на кожному DC, щоб логувати unsigned binds (Подія **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. Налаштуйте GPO DC `LDAP server channel binding token requirements` = **When Supported** щоб почати телеметрію CBT.
3. Моніторте події Directory Service:
- **2889** – unsigned/unsigned-allow binds (підпис не відповідає вимогам).
- **3074/3075** – LDAPS binds, які б зазнали невдачі або пропустили CBT (вимагає KB4520412 на 2019/2022 і кроку 2 вище).
4. Впровадьте окремими змінами:
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## Посилання

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
