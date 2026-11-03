# Посилення захисту LDAP Signing і Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Чому це важливо

Атаки LDAP relay/MITM пересилають автентифікацію контролеру домену, щоб отримати автентифікований контекст LDAP. У [огляді poisoning розпізнавання імен і relay-атак](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) описано ширший сценарій. Два пов’язані засоби контролю зменшують ці ризики:

- **LDAP channel binding (CBT)** прив’язує відповідну автентифікацію до сертифіката TLS-сервера/каналу, що використовується LDAPS, ускладнюючи relay між каналами.
- **LDAP signing** вимагає захисту цілісності для LDAP-прив’язок SASL. Він не забезпечує конфіденційність; використовуйте TLS, якщо вміст LDAP також потрібно шифрувати.<sup>[[2]](#references)</sup>

**Швидка перевірка стану**: такі інструменти, як `netexec ldap <dc> -u user -p pass`, показують виявлені політики signing і channel binding. `(signing:None)` і `(channel binding:Never)` вказують на відсутність цих засобів захисту, але успішний relay і надалі залежить від типу перехопленої автентифікації, поведінки EPA, привілеїв облікового запису, цільового протоколу й засобів захисту від relay. Якщо ретрансльований суб’єкт має потрібні права, такі інструменти, як KrbRelayUp, можуть записати `msDS-AllowedToActOnBehalfOfOtherIdentity`, налаштувати делегування з обмеженням на основі ресурсів (RBCD) і скористатися отриманим шляхом делегування для імперсонації привілейованого суб’єкта.<sup>[[4]](#references)</sup>

**Контролери домену Server 2025** додають нову GPO (**LDAP server signing requirements Enforcement**), яка за замовчуванням встановлює значення **Require Signing**, якщо параметр залишити **Not Configured**. Щоб уникнути примусового застосування політики, потрібно явно встановити для неї значення **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (лише LDAPS)

- **Вимоги**:
  - Виправлення CVE-2017-8563 (2017) додає підтримку Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) додає телеметрію LDAPS CBT у режимі «what-if».<sup>[[2]](#references)</sup>
- **GPO (контролери домену)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (за замовчуванням, без CBT)
  - `When Supported` (часткове застосування: клієнти з підтримкою CBT мають надати дійсний токен; клієнти без підтримки CBT усе ще можуть виконати прив’язку, а також генеруються події аудиту)
  - `Always` (примусове застосування: відхиляє прив’язки LDAPS без дійсного CBT)<sup>[[1]](#references)</sup>
- **Аудит**: встановіть **When Supported**, щоб виявляти:
  - **3074** – прив’язка LDAPS не пройшла б перевірку CBT, якби політика застосовувалася примусово.
  - **3075** – у прив’язці LDAPS не було даних CBT, і її було б відхилено за примусового застосування політики.
  - (Подія **3039** і далі сигналізує про збої CBT у старіших збірках.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Примусове застосування**: встановіть **Always**, коли клієнти LDAPS надсилатимуть CBT; це працює лише для **LDAPS** (не для звичайного порту 389).<sup>[[1]](#references)</sup>

`When Supported` — це не лише режим аудиту: він перевіряє CBT для клієнтів із відповідною підтримкою, дозволяючи підключення клієнтам без неї. У [довідці Microsoft щодо політики](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) описано залежні від версії значення за замовчуванням. LDAP signing застосовується до відповідних прив’язок через LDAP/389; channel binding — до автентифікації LDAP, захищеної TLS.

## LDAP Signing

- **GPO клієнта**: `Network security: LDAP client signing requirements` = `Require signing` (на відміну від `Negotiate signing`, що є значенням за замовчуванням у сучасних версіях Windows).<sup>[[1]](#references)</sup>
- **GPO контролера домену**:
  - Застарілий параметр: `Domain controller: LDAP server signing requirements` = `Require signing` (за замовчуванням — `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: залиште для застарілої політики значення `None` і встановіть для `LDAP server signing requirements Enforcement` значення `Enabled` (`Not Configured` означає примусове застосування за замовчуванням; щоб уникнути цього, встановіть `Disabled`).<sup>[[1]](#references)</sup>
- **Сумісність**: перевірте пристрої та програми не на Windows, які використовують прості прив’язки або непідписані прив’язки SASL. Microsoft документує підтримку в актуальних версіях Windows; заяви про сумісність зі старими клієнтами слід перевіряти для конкретного стека клієнта, а не зводити до порогової версії XP.<sup>[[2]](#references)</sup>

## Шляхи relay і повторна автентифікація signed-SASL

Якщо вимагається **лише signing**, relay на LDAPS усе ще може спрацювати, коли channel binding не застосовується примусово: TLS забезпечує цілісність транспортного рівня. Якщо вимагається **лише channel binding**, звичайний LDAP не має TLS-каналу, до якого можна прив’язатися; relay може автентифікуватися через TCP 389, а потім використати StartTLS для операцій, що потребують TLS, якщо ретрансльований суб’єкт має необхідні права. Примусове застосування обох засобів захисту закриває ці типові альтернативи, однак не зупиняло описану нижче вразливість на невиправлених контролерах домену.<sup>[[5]](#references)</sup>

### Додавання LDAP-операції після ретрансльованої прив’язки

На вразливих контролерах домену Windows Server 2016–2025 спершу встановіть **підписане з’єднання LDAP SASL NTLM** через TCP 389 як суб’єкт X, використовуючи облікові дані, ключ сеансу яких вам відомий (або контекст NTLM SASL для anonymous, якщо він приймається). Примусьте суб’єкт Y автентифікуватися **через SMB** до relay. Пересилайте NTLM NEGOTIATE від Y і CHALLENGE від контролера домену через запити Bind GSS-SPNEGO у вже наявному LDAP-з’єднанні X. Клієнт Windows SMB встановлює `NTLMSSP_NEGOTIATE_SIGN`, тому для отриманої LDAP-прив’язки потрібен підписаний рівень SASL; обмін, що починається через HTTP/WebDAV, зазвичай не має цього прапорця й у цьому випадку не є взаємозамінним.<sup>[[5]](#references)</sup>

Коли Y надсилає NTLM AUTHENTICATE, помістіть **два окремі LDAP-повідомлення в один SASL-запис із префіксом довжини**: BindRequest із цією відповіддю, а потім ModifyRequest. Підпишіть увесь запис відомим ключем X. Вразливий контролер домену перевіряє запис за ключем X, завершує прив’язку й перемикає авторизацію з’єднання на Y, а потім виконує решту ModifyRequest як Y, не перевіряючи запис повторно за ключем Y. Це не розкриває пароль або ключ сеансу Y; подальший запис, підписаний X, буде відхилено. Запис RBCD у `msDS-AllowedToActOnBehalfOfOtherIdentity` або запис тіньових облікових даних у `msDS-KeyCredentialLink` усе одно вимагає, щоб Y мав дозвіл на цільовий об’єкт. Див. [RBCD](resource-based-constrained-delegation.md), [тіньові облікові дані](acl-persistence-abuse/shadow-credentials.md) і, якщо ретранслюється обліковий запис комп’ютера контролера домену, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Це обхід захисту для **звичайного LDAP**, а не обхід LDAP channel binding для LDAPS. У LDAPS з’єднання захищає TLS, а Windows не встановлює рівень підписування NTLM SASL із ключем X, необхідний для цього способу об’єднання записів. Якщо TCP 389 недоступний, цю техніку не можна просто перенести на TCP 636. Оновлення безпеки за жовтень 2026 року запобігають виконанню операції в тому самому записі, відкидаючи решту даних після зміни суб’єкта з’єднання під час Bind.<sup>[[5]](#references)</sup> KB5126646 — це оновлення для Windows Server 2025; для інших уражених випусків Server використовуються інші номери KB.<sup>[[7]](#references)</sup>

Дослідник створив [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo), що обгортає модифікований `ntlmrelayx.py` для цього сценарію. Для роботи потрібне джерело примусової автентифікації **SMB**, закріплена версія дерева Impacket з API підписування LDAP/контексту безпеки (PyPI Impacket 0.13.1 не підходить) і контрольований зловмисником обліковий запис для початкової підписаної прив’язки. Для запису RBCD вкажіть DN об’єкта-жертви та SID контрольованого комп’ютера, що виконує делегування; для іншого дозволеного запису використовуйте `-attribute` разом із `-value` або `-value-hex`. Перевірте результат незалежним підписаним зчитуванням інструмента, а не вважайте повідомлення `FAILED` на стороні relay доказом невдалого виконання ModifyRequest.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Окремо ініціюйте автентифікацію SMB; див. [примусову автентифікацію NTLM із привілеями](printers-spooler-service-abuse.md) для одного з варіантів примусу та [огляд relay-атак](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) для інших. Команда та реалізація інструмента описані в його репозиторії.<sup>[[6]](#references)</sup>

## Поетапне впровадження з попереднім аудитом (рекомендовано ~30 днів)

1. Увімкніть діагностику інтерфейсу LDAP на кожному DC, щоб реєструвати прив’язування без підпису (подія **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Установіть для GPO контролера домену `LDAP server channel binding token requirements` значення **When Supported** для часткового застосування CBT і збору телеметрії; спершу перевірте сумісність зі старими клієнтами.<sup>[[1]](#references)</sup>
3. Відстежуйте події Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – прив’язування без підпису або з дозволом на прив’язування без підпису (невідповідність вимогам підписування).
   - **3074/3075** – прив’язування LDAPS, яке завершилося б помилкою або не містило б CBT (потрібна KB4520412 на Server 2019/2022 і виконання кроку 2 вище).
4. Застосовуйте вимоги окремими змінами:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (контролери домену).
   - `LDAP client signing requirements` = **Require signing** (клієнти).
   - `LDAP server signing requirements` = **Require signing** (контролери домену) **або** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec — Прив’язування каналу LDAP і підписування LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 — Вимоги до прив’язування каналу LDAP і підписування LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 — Оновлення для пом’якшення атак ретрансляції LDAP](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (підписування LDAP вимкнено → ретрансляція Kerberos → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Підписаний, запечатаний і ретрансльований: стиль NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Доказ концепції LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Інформація про випуски Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
