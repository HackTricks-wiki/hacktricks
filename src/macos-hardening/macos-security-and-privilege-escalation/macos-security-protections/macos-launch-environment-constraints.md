# Обмеження запуску/середовища macOS і Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Обмеження запуску в macOS запровадили для підвищення безпеки, **регулюючи, як, ким і звідки можна запускати процес**. Цей механізм з’явився в macOS Ventura та надає інфраструктуру, яка розподіляє **кожен системний бінарний файл за окремими категоріями обмежень**. Ці категорії визначено в **trust cache** — списку системних бінарних файлів і відповідних хешів​. Обмеження поширюються на кожен виконуваний бінарний файл у системі та містять набір **правил**, що визначають вимоги до **запуску певного бінарного файлу**. Правила охоплюють обмеження для самого бінарного файлу, які він має задовольняти; обмеження для батьківського процесу, яким має відповідати його батьківський процес; і обмеження для відповідального процесу, яких мають дотримуватися інші відповідні сутності​.<sup>[[1]](#references)[[4]](#references)</sup>

Починаючи з macOS Sonoma, механізм поширюється і на сторонні програми через **обмеження середовища**, що дає розробникам змогу захистити свої програми, вказавши **набір ключів і значень для обмежень середовища.**<sup>[[5]](#references)</sup>

**Обмеження середовища запуску та завантаження бібліотек** визначають у словниках обмежень, які можна зберігати у **файлах списків властивостей `launchd`** або в **окремих файлах списків властивостей**, що використовуються для підписування коду.<sup>[[5]](#references)</sup>

Існує 4 типи обмежень:

- **Обмеження для самого процесу**: застосовуються до **запущеного** бінарного файлу.
- **Батьківський процес**: обмеження, що застосовуються до **батьківського процесу** (наприклад, **`launchd`**, який запускає службу XP)
- **Відповідальний процес**: обмеження, що застосовуються до **процесу, який викликає службу** під час взаємодії XPC
- **Обмеження завантаження бібліотек**: використовуйте їх, щоб вибірково визначати код, який можна завантажувати

Коли процес намагається запустити інший процес — викликавши `execve(_:_:_:)` або `posix_spawn(_:_:_:_:_:_:)` — операційна система перевіряє, чи **виконуваний** файл **задовольняє** власне **обмеження для самого себе**. Вона також перевіряє, чи **виконуваний файл батьківського процесу** **задовольняє** **обмеження батьківського процесу** для цього виконуваного файлу, і чи **виконуваний файл відповідального процесу** **задовольняє обмеження відповідального процесу** для цього виконуваного файлу. Якщо будь-яке з цих обмежень запуску не виконується, операційна система не запускає програму.

Якщо під час завантаження бібліотеки будь-яка частина **обмеження бібліотеки не виконується**, процес **не завантажує** бібліотеку.

## Категорії LC

LC складається з **фактів** і **логічних операцій** (and, or тощо), які поєднують факти.

[**Факти, які може використовувати LC, задокументовано**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Наприклад:

- is-init-proc: Булеве значення, яке вказує, чи має виконуваний файл бути процесом ініціалізації операційної системи (`launchd`).
- is-sip-protected: Булеве значення, яке вказує, чи має виконуваний файл бути файлом, захищеним System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Булеве значення, яке вказує, чи завантажила операційна система виконуваний файл з авторизованого автентифікованого тому APFS.
- `on-authorized-authapfs-volume`: Булеве значення, яке вказує, чи завантажила операційна система виконуваний файл з авторизованого автентифікованого тому APFS.
  - Том Cryptexes
- `on-system-volume:`Булеве значення, яке вказує, чи завантажила операційна система виконуваний файл із поточного завантаженого системного тому.
  - Усередині /System...
- ...

Під час підписування бінарного файлу Apple **призначає його категорії LC** у **trust cache**.

- **Категорії LC в iOS 16** [**було відновлено й задокументовано тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Поточні **категорії LC (macOS 14 — Somona)** було відновлено, а їхні [**описи можна знайти тут**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Наприклад, категорія 1:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Має бути на томі System або Cryptexes.
- `launch-type == 1`: Має бути системною службою (plist у LaunchDaemons).
- `validation-category == 1`: Виконуваний файл операційної системи.
- `is-init-proc`: Launchd

### Реверсинг категорій LC

Детальніше про це можна прочитати [**тут**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), але загалом вони визначені в **AMFI (AppleMobileFileIntegrity)**, тому потрібно завантажити Kernel Development Kit, щоб отримати **KEXT**. Цікавими є символи, що починаються з **`kConstraintCategory`**. Після їхнього вилучення ви отримаєте потік у форматі DER (ASN.1), який потрібно декодувати за допомогою [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) або бібліотеки python-asn1 та її скрипту `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master). У результаті ви отримаєте зрозуміліший рядок.<sup>[[3]](#references)[[8]](#references)</sup>

## Обмеження середовища

Це налаштовані Launch Constraints у **сторонніх застосунках**. Розробник може вибрати **факти** та **логічні оператори**, які використовуватимуться в його застосунку для обмеження доступу до нього.

Перелічити Environment Constraints застосунку можна так:

```bash
codesign -d -vvvv app.app
```

## Кеші довіри

У **macOS** є кілька кешів довіри:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

В iOS, схоже, він розташований у **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> У macOS на пристроях Apple Silicon AMFI відмовиться завантажувати бінарний файл, підписаний Apple, якщо його немає в кеші довіри.

### Перелік кешів довіри

Файли кешів довіри, згадані вище, мають формат **IMG4** та **IM4P**, причому IM4P є секцією даних формату IMG4.

Для вилучення даних із баз можна скористатися [**pyimg4**](https://github.com/m1stadev/PyIMG4):

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

(Інший варіант — скористатися інструментом [**img4tool**](https://github.com/tihmstar/img4tool), який працюватиме навіть на M1, хоча реліз застарілий і призначений для x86_64, якщо встановити його у відповідні каталоги).

Тепер можна скористатися інструментом [**trustcache**](https://github.com/CRKatri/trustcache), щоб отримати інформацію у зручному для читання форматі:

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

Кеш довіри має таку структуру, тому **категорія LC — це 4-й стовпець**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Після цього можна скористатися скриптом, наприклад [**цим**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), щоб витягти дані.

За цими даними можна знайти програми зі **значенням launch constraints `0`** — саме вони не мають обмежень ([**тут**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) наведено пояснення кожного значення).<sup>[[6]](#references)</sup>

## Attack Mitigations

Launch Constraints могли б запобігти кільком давнім атакам, **гарантуючи, що процес не запускатиметься за неочікуваних умов**: наприклад, із неочікуваного розташування або неочікуваним батьківським процесом (якщо запускати його має лише launchd).

Крім того, Launch Constraints також **запобігають downgrade-атакам**.

Однак вони **не запобігають типовим зловживанням XPC**, ін’єкціям коду **Electron** або **dylib-ін’єкціям** за відсутності перевірки бібліотек (якщо тільки не відомі team ID, яким дозволено завантажувати бібліотеки).<sup>[[3]](#references)</sup>

### XPC Daemon Protection

У випуску Sonoma варто звернути увагу на **конфігурацію відповідальності** XPC-сервісу демона. За сам XPC-сервіс відповідає він сам, а не клієнт, який до нього під’єднується. Це описано у звіті про помилку FB13206884. Така схема може здаватися хибною, оскільки допускає певну взаємодію з XPC-сервісом:

- **Запуск XPC Service**: якщо вважати це помилкою, така схема не дозволяє запускати XPC-сервіс за допомогою коду зловмисника.
- **Під’єднання до активного сервісу**: якщо XPC-сервіс уже запущений (можливо, його активувала початкова програма), жодних перешкод для під’єднання до нього немає.

Установлення обмежень для XPC-сервісу може бути корисним, **звужуючи вікно для потенційних атак**, але це не усуває основну проблему. Для забезпечення безпеки XPC-сервісу необхідно **належним чином перевіряти клієнта, який під’єднується**. Це єдиний спосіб посилити безпеку сервісу. Також варто зазначити, що згадана конфігурація відповідальності наразі працює, хоча це може не відповідати задуму розробників.<sup>[[3]](#references)</sup>

### Electron Protection

Навіть якщо вимагається, щоб програму **відкривав LaunchService** (в обмеженнях батьківського процесу), це можна зробити за допомогою **`open`** (яка може встановлювати змінні середовища) або **Launch Services API** (у якому можна вказати змінні середовища).<sup>[[3]](#references)</sup>

Загальний опис механізму MACF, що лежить в основі атрибутів запуску, специфічних для політик, див. у статті [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Перевизначення вбудованих обмежень під час запуску

Launch constraints (офіційна назва — **lightweight code requirements**, *LWCR*) забезпечуються **політикою AMFI MAC**. `posix_spawn` дає змогу виклику передавати довільний blob політиці MAC через **`posix_spawnattr_setmacpolicyinfo_np()`**, і AMFI приймала переданий викликом словник LWCR через цей шлях. Помилка полягала в тому, що **обмеження, передані зловмисником, замінювали вбудовані обмеження бінарного файла**, а не перевірялися додатково до них:

- Створіть мінімальний словник launch constraints (навіть порожній).
- Установіть **категорію обмеження `127`** — це значення AMFI дозволяє в атрибутах запуску, але **не застосовує**: замість блокування виконання воно лише записує в журнал `Launch Constraint Violation (not enforcing)`.
- Передайте словник через атрибути запуску — процес запуститься в контексті, який його справжні обмеження self/parent заборонили б.

Після виправлення перевіряються **і** вбудовані, **і** передані обмеження, тож переданий словник більше не може послабити вбудовані обмеження.<sup>[[2]](#references)</sup>

> [!TIP]
> Саме на такі ситуації варто звертати увагу під час аудиту застосування обмежень: API, що дозволяє недовіреним даним *задавати* політику, може бути вразливим, якщо механізм політик сприймає передане значення як заміну, а не як додаткову вимогу.



## References

- [1] [Objective by the Sea #OBTS v6.0, день 2 (пряма трансляція)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: обхід Launch Constraints у macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Поглиблений огляд Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Чому не запускається системна програма або інструмент командного рядка? Launch constraints і кеші довіри - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Захистіть програму для Mac за допомогою обмежень середовища - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Опис Launch Constraints, доданих в iOS 16 (gist LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints у macOS Sonoma (14) (gist theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Більше, ніж старі добрі LaunchAgents — про це тут](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
