# Обмеження Launch/Environment у macOS та Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Launch constraints у macOS були впроваджені для підвищення безпеки шляхом **регулювання того, як, ким і звідки може бути запущений процес**. Запроваджені в macOS Ventura, вони надають framework, який категоризує **кожен системний binary до окремих категорій обмежень**, визначених у **trust cache** — списку, що містить системні binaries та їхні відповідні хеші. Ці обмеження поширюються на кожен executable binary у системі та містять набір **правил**, що визначають вимоги для **запуску певного binary**. Правила охоплюють self constraints, яким має відповідати binary, parent constraints, яким має відповідати його батьківський процес, і responsible constraints, яких мають дотримуватися інші відповідні сутності.

Механізм поширюється на сторонні apps через **Environment Constraints**, починаючи з macOS Sonoma, що дозволяє розробникам захищати свої apps, задаючи **набір ключів і значень для environment constraints.**

Ви визначаєте **launch environment та library constraints** у словниках constraints, які або зберігаєте у **файлах списків властивостей `launchd`**, або в **окремих файлах списків властивостей**, що використовуються під час code signing.

Існує 4 типи constraints:

- **Self Constraints**: Constraints, застосовані до **запущеного** binary.
- **Parent Process**: Constraints, застосовані до **батьківського процесу** (наприклад, **`launchd`**, що запускає XP service)
- **Responsible Constraints**: Constraints, застосовані до **процесу, який викликає service** у XPC communication
- **Library load constraints**: Використовуйте library load constraints для вибіркового опису коду, який може бути завантажений

Отже, коли процес намагається запустити інший процес — викликаючи `execve(_:_:_:)` або `posix_spawn(_:_:_:_:_:_:)` — operating system перевіряє, чи **executable** file відповідає його **власному self constraint**. Також перевіряється, чи executable **батьківського** **процесу** відповідає **parent constraint** executable, а executable **відповідального** **процесу** — **responsible process constraint** executable. Якщо будь-яке з цих launch constraints не виконано, operating system не запускає програму.

Якщо під час завантаження library будь-яка частина **library constraint не є істинною**, ваш процес **не завантажує** library.

## Категорії LC

LC складається з **facts** і **логічних операцій** (and, or...), які комбінують facts.

[**Facts, які може використовувати LC, задокументовані**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Наприклад:

- is-init-proc: Boolean value, що вказує, чи має executable бути процесом ініціалізації operating system (`launchd`).
- is-sip-protected: Boolean value, що вказує, чи має executable бути file, захищеним System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Boolean value, що вказує, чи operating system завантажила executable з авторизованого, автентифікованого APFS volume.
- `on-authorized-authapfs-volume`: Boolean value, що вказує, чи operating system завантажила executable з авторизованого, автентифікованого APFS volume.
- Cryptexes volume
- `on-system-volume:`Boolean value, що вказує, чи operating system завантажила executable із поточного завантаженого system volume.
- Inside /System...
- ...

Коли Apple binary підписується, **йому призначається категорія LC** всередині **trust cache**.

- **Категорії LC в iOS 16** були [**reversed і задокументовані тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Поточні **категорії LC (macOS 14** - Somona) були reversed, а їхні [**описи можна знайти тут**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Наприклад, Category 1 має вигляд:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Має знаходитися на System або Cryptexes volume.
- `launch-type == 1`: Має бути системною службою (plist у LaunchDaemons).
- `validation-category == 1`: Виконуваний файл операційної системи.
- `is-init-proc`: Launchd

### Реверсинг категорій LC

Більше інформації [**є тут**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), але загалом вони визначені в **AMFI (AppleMobileFileIntegrity)**, тому потрібно завантажити Kernel Development Kit, щоб отримати **KEXT**. Символи, що починаються з **`kConstraintCategory`**, є **цікавими**. Після їхнього вилучення ви отримаєте потік у форматі DER (ASN.1), який потрібно декодувати за допомогою [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) або бібліотеки python-asn1 і її скрипта `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), що надасть вам зрозуміліший рядок.<sup>[3]</sup>

## Обмеження середовища

Це Launch Constraints, налаштовані для **сторонніх застосунків**. Розробник може вибрати **факти** та **логічні операнди**, які використовуються в його застосунку для обмеження доступу до нього.

Перелічити Environment Constraints застосунку можна за допомогою:
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
> У macOS, що працює на пристроях Apple Silicon, якщо бінарний файл, підписаний Apple, відсутній у кеші довіри, AMFI відмовиться його завантажувати.

### Перелік кешів довіри

Попередні файли кешу довіри мають формат **IMG4** і **IM4P**, причому IM4P є секцією payload формату IMG4.

Для видобування payload баз даних можна використати [**pyimg4**](https://github.com/m1stadev/PyIMG4):
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
(Іншим варіантом може бути використання інструмента [**img4tool**](https://github.com/tihmstar/img4tool), який працюватиме навіть на M1, навіть якщо release старий, а також на x86_64, якщо встановити його у відповідні місця).

Тепер можна використовувати інструмент [**trustcache**](https://github.com/CRKatri/trustcache), щоб отримати інформацію у зручному для читання форматі:
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
Кеш довіри має наведену нижче структуру, тому **категорія LC є 4-м стовпцем**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Після цього можна використати такий скрипт, як [**цей**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), щоб отримати дані.

З цих даних можна перевірити Apps зі **значенням launch constraints `0`**, тобто ті, для яких обмеження не застосовуються ([**перевірте тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), що означає кожне значення).<sup>[6]</sup>

## Пом'якшення атак

Launch Constraints могли б запобігти кільком старим атакам, **гарантуючи, що процес не буде виконано в непередбачених умовах:** наприклад, із непередбачених розташувань або викликано непередбаченим батьківським процесом (якщо його має запускати лише launchd).

Крім того, Launch Constraints також **запобігають downgrade-атакам.**

Однак вони **не запобігають поширеним зловживанням XPC**, ін'єкціям коду **Electron** або **dylib injection** без library validation (якщо невідомі team IDs, яким дозволено завантажувати libraries).<sup>[3]</sup>

### Захист XPC Daemon

У релізі Sonoma важливим моментом є **конфігурація відповідальності** XPC service daemon. XPC service відповідає сам за себе, на відміну від підключеного client, який є відповідальним. Це задокументовано у звіті про feedback FB13206884. Така конфігурація може здаватися недосконалою, оскільки дозволяє певні взаємодії з XPC service:

- **Запуск XPC Service**: якщо це вважати bug, така конфігурація не дозволяє ініціювати XPC service через code атакувальника.
- **Підключення до активного Service**: якщо XPC service уже запущено (можливо, його активувала оригінальна application), жодних перешкод для підключення до нього немає.

Хоча застосування constraints до XPC service може бути корисним, **звужуючи вікно для потенційних атак**, це не усуває основну проблему. Безпека XPC service фундаментально потребує **ефективної перевірки підключеного client**. Це залишається єдиним способом посилити безпеку service. Також варто зазначити, що згадана конфігурація відповідальності наразі працює, що може не відповідати задуму розробників.<sup>[3]</sup>

### Захист Electron

Навіть якщо вимагається, щоб application **була відкрита через LaunchService** (у parent constraints), цього можна досягти за допомогою **`open`** (який може встановлювати env variables) або через **Launch Services API** (де можна вказати env variables).<sup>[3]</sup>

### CVE-2025-43253 - Перевизначення вбудованих constraints під час spawn

Launch constraints (офіційно **lightweight code requirements**, *LWCR*) застосовуються **AMFI MAC policy**. `posix_spawn` дозволяє caller передати довільний blob до MAC policy через **`posix_spawnattr_setmacpolicyinfo_np()`**, і AMFI приймав наданий caller-ом словник LWCR через цей шлях. Проблема полягала в тому, що **constraints, надані атакувальником, замінювали вбудовані constraints binary**, замість того щоб перевірятися додатково до них:

- Створити мінімальний (навіть порожній) словник launch-constraints.
- Встановити **категорію constraint у `127`** — значення, яке AMFI дозволяє в spawn attributes, але **не застосовує**: воно лише записує `Launch Constraint Violation (not enforcing)` у log замість блокування execution.
- Передати його через spawn attributes, після чого process запускається в context, який його реальні self/parent constraints заборонили б.

Після виправлення **перевіряються і вбудовані, і надані constraints**, тому наданий словник більше не може послабити вбудований.<sup>[2]</sup>

> [!TIP]
> Під час аудиту застосування constraints варто шукати саме таку загальну схему: API, який дозволяє ненадійному input *надавати* policy, зазвичай становить інтерес, якщо policy engine сприймає надане значення як заміну, а не як додаткову вимогу.

## Посилання

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Обхід Launch Constraints у macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Детальний огляд Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Чому system app або command tool не запускається? Launch constraints і trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Захистіть свою Mac app за допомогою environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Опис Launch Constraints, представлених в iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints у macOS Sonoma (14) (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
