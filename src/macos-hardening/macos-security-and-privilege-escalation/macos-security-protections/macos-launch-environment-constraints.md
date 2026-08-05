# Обмеження запуску/середовища macOS і Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Launch constraints у macOS були запроваджені для підвищення безпеки шляхом **регулювання того, як, ким і звідки може бути ініційований процес**. Запроваджені в macOS Ventura, вони надають framework, який класифікує **кожен системний binary в окремі категорії обмежень**, визначені в **trust cache** — списку, що містить системні binaries і відповідні їм hashes​. Ці обмеження поширюються на кожен executable binary у системі та передбачають набір **правил**, що визначають вимоги для **запуску певного binary**. Правила охоплюють self constraints, яким має відповідати binary, parent constraints, яким має відповідати його parent process, і responsible constraints, яких мають дотримуватися інші відповідні entities​.

Механізм поширюється на third-party apps через **Environment Constraints**, починаючи з macOS Sonoma, що дає developers змогу захищати свої apps, визначаючи **набір keys і values для environment constraints.**

Ви визначаєте **launch environment і library constraints** у constraint dictionaries, які зберігаєте у **`launchd` property list files** або в **окремих property list** files, що використовуються під час code signing.

Існує 4 типи constraints:

- **Self Constraints**: Constraints, застосовані до **запущеного** binary.
- **Parent Process**: Constraints, застосовані до **parent процесу** (наприклад, **`launchd`**, що запускає XP service)
- **Responsible Constraints**: Constraints, застосовані до **процесу, який викликає service** у XPC communication
- **Library load constraints**: Використовуйте library load constraints, щоб вибірково описати code, який може бути loaded

Отже, коли process намагається запустити інший process — викликаючи `execve(_:_:_:)` або `posix_spawn(_:_:_:_:_:)` — operating system перевіряє, чи **executable** file **відповідає його власному self constraint**. Також перевіряється, чи executable **parent** process **відповідає parent constraint** executable, а executable **responsible** process **відповідає responsible process constrain**t executable. Якщо будь-яке з цих launch constraints не виконується, operating system не запускає program.

Якщо під час loading library будь-яка частина **library constraint не є істинною**, ваш process **не завантажує** library.

## LC Categories

LC складається з **facts** і **logical operations** (and, or..), які поєднують facts.

[**Facts, які може використовувати LC, задокументовані**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Наприклад:

- is-init-proc: Boolean value, що вказує, чи має executable бути initialization process операційної системи (`launchd`).
- is-sip-protected: Boolean value, що вказує, чи має executable бути file, захищеним System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean value, що вказує, чи operating system loaded executable з authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: Boolean value, що вказує, чи operating system loaded executable з authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:`Boolean value, що вказує, чи operating system loaded executable з currently-booted system volume.
- Inside /System...
- ...

Коли Apple binary підписується, він **призначається до категорії LC** всередині **trust cache**.

- **iOS 16 LC categories** були [**reversed і задокументовані тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Поточні **LC categories (macOS 14** - Somona) були reversed, а їхні [**описи можна знайти тут**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Наприклад, Category 1 має вигляд:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Має бути на System або Cryptexes volume.
- `launch-type == 1`: Має бути системною службою (plist у LaunchDaemons).
- `validation-category == 1`: Виконуваний файл операційної системи.
- `is-init-proc`: Launchd

### Реверсинг категорій LC

Ви можете знайти більше інформації [**тут**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), але загалом вони визначені в **AMFI (AppleMobileFileIntegrity)**, тому потрібно завантажити Kernel Development Kit, щоб отримати **KEXT**. Символи, що починаються з **`kConstraintCategory`**, є **цікавими**. Після їхнього вилучення ви отримаєте потік, закодований у DER (ASN.1), який потрібно декодувати за допомогою [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) або бібліотеки python-asn1 та її скрипту `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), що надасть зрозуміліший рядок.<sup>[[3]](#references)</sup>

## Обмеження середовища

Це Launch Constraints, налаштовані для **застосунків сторонніх розробників**. Розробник може вибрати **факти** та **логічні операнди**, які використовуватимуться в його застосунку для обмеження доступу до нього.

Перерахувати Environment Constraints застосунку можна за допомогою:
```bash
codesign -d -vvvv app.app
```
## Кеші довіри

У **macOS** є кілька кешів довіри:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

А в iOS, схоже, він розташований у **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> У macOS, що працює на пристроях із Apple Silicon, якщо підписаний Apple binary відсутній у кеші довіри, AMFI відмовиться його завантажувати.

### Перелік кешів довіри

Попередні файли кешів довіри мають формат **IMG4** і **IM4P**, причому IM4P є секцією payload формату IMG4.

Ви можете використовувати [**pyimg4**](https://github.com/m1stadev/PyIMG4), щоб витягти payload баз даних:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Іншим варіантом може бути використання інструмента [**img4tool**](https://github.com/tihmstar/img4tool), який працюватиме навіть на M1, навіть якщо реліз старий, а також на x86_64, якщо встановити його у відповідні розташування).

Тепер можна використати інструмент [**trustcache**](https://github.com/CRKatri/trustcache), щоб отримати інформацію у зручному для читання форматі:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Кеш довіри має таку структуру, тому **категорія LC є 4-м стовпцем**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Потім можна використати такий скрипт, як [**цей**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), щоб видобути дані.

З цих даних можна перевірити програми зі **значенням launch constraints `0`** — саме вони не мають обмежень ([**перевірте тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), що означає кожне значення).<sup>[[6]](#references)</sup>

## Заходи протидії атакам

Launch Constraints могли б запобігти кільком старим атакам, **гарантуючи, що процес не буде виконано в непередбачених умовах:** наприклад, із неочікуваних розташувань або внаслідок виклику неочікуваним батьківським процесом (якщо його має запускати лише launchd).

Крім того, Launch Constraints також **запобігають downgrade-атакам.**

Однак вони **не запобігають поширеним зловживанням XPC**, ін'єкціям коду **Electron** або **dylib injections** без library validation (якщо невідомі team IDs, яким дозволено завантажувати бібліотеки).<sup>[[3]](#references)</sup>

### Захист XPC Daemon

У релізі Sonoma важливим моментом є **конфігурація відповідальності** XPC service демона. XPC service відповідає сам за себе, на відміну від ситуації, коли відповідальність покладається на клієнта, що підключається. Це задокументовано у звіті про feedback FB13206884. Така конфігурація може здаватися недосконалою, оскільки дозволяє певні взаємодії з XPC service:

- **Запуск XPC Service**: якщо вважати це помилкою, така конфігурація не дозволяє ініціювати XPC service через код attacker.
- **Підключення до активного Service**: якщо XPC service уже запущено (можливо, його активувала оригінальна програма), перешкод для підключення до нього немає.

Хоча впровадження обмежень для XPC service може бути корисним, **звужуючи вікно для потенційних атак**, це не усуває основну проблему. Безпека XPC service фундаментально потребує **ефективної перевірки клієнта, що підключається**. Це залишається єдиним способом посилити безпеку service. Також варто зазначити, що згадана конфігурація відповідальності наразі працює, що може не відповідати задуму розробників.<sup>[[3]](#references)</sup>

### Захист Electron

Навіть якщо вимагається, щоб програма була **відкрита через LaunchService** (в обмеженнях для батьківських процесів), цього можна досягти за допомогою **`open`** (який може встановлювати env variables) або через **Launch Services API** (де можна вказати env variables).<sup>[[3]](#references)</sup>

### CVE-2025-43253 — перевизначення вбудованих обмежень під час spawn

Launch constraints (офіційно **lightweight code requirements**, *LWCR*) застосовуються **AMFI MAC policy**. `posix_spawn` дозволяє caller передати довільний blob до MAC policy через **`posix_spawnattr_setmacpolicyinfo_np()`**, і AMFI приймав наданий caller LWCR dictionary через цей шлях. Помилка полягала в тому, що **обмеження, надані attacker, замінювали вбудовані обмеження binary**, замість того щоб додатково перевірятися разом із ними:

- Створити мінімальний (навіть порожній) launch-constraints dictionary.
- Встановити **категорію обмеження `127`** — значення, яке AMFI дозволяє в spawn attributes, але **не застосовує**: воно лише записує `Launch Constraint Violation (not enforcing)` у журнал замість блокування виконання.
- Передати його через spawn attributes, після чого процес запускається в контексті, який його реальні self/parent constraints заборонили б.

Після виправлення перевіряються **і вбудовані, і надані constraints**, тому наданий dictionary більше не може послабити вбудовані обмеження.<sup>[[2]](#references)</sup>

> [!TIP]
> Під час аудиту застосування constraints шукайте саме таку загальну конструкцію: API, який дозволяє ненадійним вхідним даним *надавати* policy, зазвичай є цікавим, якщо policy engine розглядає надане значення як заміну, а не як додаткову вимогу.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
