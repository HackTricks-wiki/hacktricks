# Посилення захисту LDAP Signing і Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

LDAP relay/MITM-атаки пересилають автентифікацію до контролера домену, щоб отримати автентифікований контекст LDAP. У [огляді отруєння розпізнавання імен і relay-атак](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) описано ширший сценарій. Два пов’язані засоби захисту зменшують ризик таких атак:

- **LDAP channel binding (CBT)** прив’язує відповідну автентифікацію до сертифіката TLS-сервера/каналу, що використовується LDAPS, ускладнюючи relay між каналами.
- **LDAP signing** вимагає захисту цілісності для LDAP-прив’язок SASL. Він не забезпечує конфіденційність; використовуйте TLS, якщо вміст LDAP також потрібно шифрувати.<sup>[[2]](#references)</sup>

**Швидка перевірка налаштувань**: такі інструменти, як `netexec ldap <dc> -u user -p pass`, показують виявлену політику signing і channel binding. `(signing:None)` і `(channel binding:Never)` свідчать про відсутність відповідних засобів захисту, але успішний relay усе одно залежить від типу перехопленої автентифікації, поведінки EPA, привілеїв облікового запису, цільового протоколу та захисту від relay. Якщо перехоплений principal має необхідні права, такі інструменти, як KrbRelayUp, можуть записати `msDS-AllowedToActOnBehalfOfOtherIdentity`, налаштувати делегування з обмеженнями на основі ресурсів (RBCD) і використати отриманий шлях делегування для імітації привілейованого principal.<sup>[[4]](#references)</sup>

**Контролери домену Server 2025** додають нову GPO (**LDAP server signing requirements Enforcement**), яка за замовчуванням має значення **Require Signing**, якщо залишити її в стані **Not Configured**. Щоб уникнути примусового застосування політики, її потрібно явно встановити в **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (лише LDAPS)

- **Вимоги**:
  - Патч CVE-2017-8563 (2017) додає підтримку Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) додає телеметрію LDAPS CBT у режимі «what-if».<sup>[[2]](#references)</sup>
- **GPO (контролери домену)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (за замовчуванням, без CBT)
  - `When Supported` (часткове застосування: клієнти з підтримкою CBT мають надати дійсний токен; клієнти без підтримки CBT усе ще можуть встановити прив’язку, а також створюються події аудиту)
  - `Always` (застосування: відхиляє прив’язки LDAPS без дійсного CBT)<sup>[[1]](#references)</sup>
- **Аудит**: установіть **When Supported**, щоб виявляти:
  - **3074** – прив’язка LDAPS не пройшла б перевірку CBT у разі застосування політики.
  - **3075** – у прив’язці LDAPS не було даних CBT, тому її було б відхилено в разі застосування політики.
  - (Подія **3039** і далі сигналізує про помилки CBT у старіших збірках.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Застосування**: установіть **Always**, коли клієнти LDAPS надсилатимуть CBT; це діє лише для **LDAPS** (не для звичайного порту 389).<sup>[[1]](#references)</sup>

`When Supported` — це не лише режим аудиту: він перевіряє CBT для клієнтів із відповідною підтримкою, водночас дозволяючи підключатися клієнтам без неї. У [довідці Microsoft щодо політики](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) описано залежні від версії значення за замовчуванням. LDAP signing застосовується до відповідних прив’язок через LDAP/389; channel binding — до автентифікації LDAP, захищеної TLS.


## LDAP Signing

- **GPO клієнта**: `Network security: LDAP client signing requirements` = `Require signing` (на відміну від стандартного `Negotiate signing` у сучасних версіях Windows).<sup>[[1]](#references)</sup>
- **GPO контролера домену**:
  - Застаріла: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням — `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: залиште застарілу політику зі значенням `None` і встановіть `LDAP server signing requirements Enforcement` = `Enabled` (за замовчуванням політика застосовується, якщо встановлено Not Configured; щоб уникнути її застосування, установіть `Disabled`).<sup>[[1]](#references)</sup>
- **Сумісність**: перевірте пристрої та програми, що не працюють на Windows і використовують прості прив’язки або прив’язки SASL без підпису. Microsoft документує підтримку в актуальних версіях Windows; сумісність із застарілими клієнтами слід перевіряти на реальному стеку клієнта, а не зводити до вимоги щодо версії XP.<sup>[[2]](#references)</sup>

## Спершу аудит (рекомендовано — близько 30 днів)

1. Увімкніть діагностику інтерфейсу LDAP на кожному контролері домену, щоб реєструвати прив’язки без підпису (подія **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. У DC GPO `LDAP server channel binding token requirements` = **When Supported** для часткового застосування CBT і збору телеметрії; спершу перевірте сумісність зі старими клієнтами.<sup>[[1]](#references)</sup>
3. Відстежуйте події Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – прив’язування без підпису/з дозволом на відсутність підпису (невідповідність вимогам підписування).
   - **3074/3075** – прив’язування LDAPS, що завершилися б помилкою або не містили б CBT (потрібен KB4520412 на 2019/2022 і крок 2 вище).
4. Застосовуйте вимоги окремими змінами:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DC).
   - `LDAP client signing requirements` = **Require signing** (клієнти).
   - `LDAP server signing requirements` = **Require signing** (DC) **або** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Прив’язування каналу LDAP і підписування LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Вимоги до прив’язування каналу LDAP і підписування LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Оновлення для пом’якшення атак LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (підписування LDAP вимкнено → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
