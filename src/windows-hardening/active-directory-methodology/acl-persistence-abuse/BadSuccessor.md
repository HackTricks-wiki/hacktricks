# Зловживання ACL/ACE Active Directory

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Делеговані керовані облікові записи служб (**dMSAs**) є новим типом принципу AD, введеним з **Windows Server 2025**. Вони призначені для заміни застарілих облікових записів служб, дозволяючи одноклікову "міграцію", яка автоматично копіює імена службових принципів (SPN), членство в групах, налаштування делегування та навіть криптографічні ключі старого облікового запису в новий dMSA, забезпечуючи безперервний перехід для додатків і усуваючи ризик Kerberoasting.

Дослідники Akamai виявили, що один атрибут — **`msDS‑ManagedAccountPrecededByLink`** — вказує KDC, який застарілий обліковий запис "наступає" на dMSA. Якщо зловмисник може записати цей атрибут (і переключити **`msDS‑DelegatedMSAState` → 2**), KDC з радістю створить PAC, який **успадковує кожен SID обраної жертви**, ефективно дозволяючи dMSA видавати себе за будь-якого користувача, включаючи адміністраторів домену.

## Що таке dMSA?

* Побудований на основі технології **gMSA**, але зберігається як новий клас AD **`msDS‑DelegatedManagedServiceAccount`**.
* Підтримує **міграцію за запитом**: виклик `Start‑ADServiceAccountMigration` зв'язує dMSA зі застарілим обліковим записом, надає застарілому обліковому запису права на запис до `msDS‑GroupMSAMembership` і переключає `msDS‑DelegatedMSAState` = 1.
* Після `Complete‑ADServiceAccountMigration` застарілий обліковий запис відключається, і dMSA стає повністю функціональним; будь-який хост, який раніше використовував застарілий обліковий запис, автоматично отримує дозвіл на отримання пароля dMSA.
* Під час аутентифікації KDC вбудовує підказку **KERB‑SUPERSEDED‑BY‑USER**, щоб клієнти Windows 11/24H2 прозоро повторно намагалися з dMSA.

## Вимоги для атаки
1. **Принаймні один Windows Server 2025 DC**, щоб клас LDAP dMSA та логіка KDC існували.
2. **Будь-які права на створення об'єктів або запис атрибутів на OU** (будь-який OU) – наприклад, `Create msDS‑DelegatedManagedServiceAccount` або просто **Create All Child Objects**. Akamai виявив, що 91 % реальних орендарів надають такі "безпечні" дозволи OU не адміністраторам.
3. Можливість запускати інструменти (PowerShell/Rubeus) з будь-якого хоста, приєднаного до домену, для запиту квитків Kerberos.
*Не потрібно контролювати жертву; атака ніколи безпосередньо не торкається цільового облікового запису.*

## Покроково: BadSuccessor*підвищення привілеїв

1. **Знайдіть або створіть dMSA, яким ви керуєте**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

Оскільки ви створили об'єкт всередині OU, до якого можете записувати, ви автоматично володієте всіма його атрибутами.

2. **Симулюйте "завершену міграцію" у двох записах LDAP**:
- Встановіть `msDS‑ManagedAccountPrecededByLink = DN` будь-якої жертви (наприклад, `CN=Administrator,CN=Users,DC=lab,DC=local`).
- Встановіть `msDS‑DelegatedMSAState = 2` (міграція завершена).

Такі інструменти, як **Set‑ADComputer, ldapmodify** або навіть **ADSI Edit**, працюють; права адміністратора домену не потрібні.

3. **Запросіть TGT для dMSA** — Rubeus підтримує прапорець `/dmsa`:

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

Повернений PAC тепер містить SID 500 (Адміністратор) плюс групи адміністраторів домену/підприємства.

## Зібрати всі паролі користувачів

Під час легітимних міграцій KDC повинен дозволити новому dMSA розшифровувати **квитки, видані старому обліковому запису до переходу**. Щоб уникнути порушення активних сесій, він поміщає як поточні, так і попередні ключі в новий ASN.1 об'єкт, званий **`KERB‑DMSA‑KEY‑PACKAGE`**.

Оскільки наша фальшива міграція стверджує, що dMSA "наступає" на жертву, KDC добросовісно копіює RC4-HMAC ключ жертви в список **попередніх ключів** – навіть якщо dMSA ніколи не мав "попереднього" пароля. Цей RC4 ключ не має солі, тому він фактично є NT хешем жертви, надаючи зловмиснику **можливість офлайн-ламання або "pass-the-hash"**.

Отже, масове зв'язування тисяч користувачів дозволяє зловмиснику скинути хеші "в масштабах", перетворюючи **BadSuccessor на як підвищення привілеїв, так і на примітив компрометації облікових даних**.

## Інструменти

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## Посилання

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
