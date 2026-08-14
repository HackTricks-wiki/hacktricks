# Обробники розширень файлів і URL scheme у macOS

{{#include ../../banners/hacktricks-training.md}}

## База даних LaunchServices

Це база даних усіх встановлених у macOS застосунків, яку можна запитувати для отримання інформації про кожен встановлений застосунок, зокрема про підтримувані **URL schemes**, **типи документів**, **UTI** та обробники за замовчуванням.

Цю базу даних можна витягти за допомогою:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Або за допомогою інструмента [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** є ядром бази даних. Він надає **кілька XPC-сервісів**, таких як `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інші. Але для використання відкритих XPC-функцій застосункам також **потрібні певні entitlements**, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler` для зміни застосунків за замовчуванням для MIME-типів або URL-схем, а також інші.

**`/System/Library/CoreServices/launchservicesd`** реєструє сервіс `com.apple.coreservices.launchservicesd`, і до нього можна звертатися, щоб отримати інформацію про запущені застосунки. Звертатися до нього можна за допомогою системного інструмента **`/usr/bin/lsappinfo`** або [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З погляду оператора, майте на увазі, що зазвичай існує **два корисні представлення**:

- **Реєстраційна база даних**, якою керують LaunchServices / `lsd` (на основі файлів `.csstore`).
- **Ефективні значення за замовчуванням для користувача**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` у масиві `LSHandlers`.

Ця відмінність має значення: застосунок може бути **зареєстрований** як такий, що здатен обробляти певний тип або схему, але **поточним застосунком за замовчуванням** усе ще може бути інший bundle ID.

У нових версіях macOS пошук зареєстрованих застосунків не обмежується `/Applications`: застосунки в інших доступних для Spotlight папках, а також на підключених або спільних томах можуть потрапляти до реєстру. Тому під час triage зберігайте інформацію про `path` і том із виводу `lsregister -dump` та не припускайте, що unregistering застосунку буде постійним, поки bundle залишається доступним для пошуку.<sup>[[4]](#references)</sup>

## Обробники застосунків для розширень файлів і URL-схем

Наступний рядок може бути корисним для пошуку застосунків, які можуть відкривати файли залежно від розширення:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Або використайте щось на кшталт [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Ви також можете перевірити розширення, які підтримує застосунок, виконавши:
```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
## Перелік ефективних обробників

Найкориснішим файлом для **типових налаштувань поточного користувача** зазвичай є:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Щоб отримати дамп обробників **URL scheme** із нього:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб вивести обробники **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб визначити дерево UTI зразка файлу:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Якщо вам потрібен зручніший CLI для перегляду або зміни параметрів за замовчуванням:
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
### Перевизначення `Open With` для окремих файлів

Розв’язання обробника також має **рівень, специфічний для файлу**. Перш ніж використовувати UTI файлу та глобальне значення за замовчуванням для користувача, LaunchServices перевіряє розширений атрибут `com.apple.LaunchServices.OpenWith`. Finder створює його, коли для одного файлу вибрано **Always Open With**; його значенням є двійковий список властивостей, що містить шлях до програми, ідентифікатор bundle та селектор версії.<sup>[[3]](#references)</sup>

Перевірте та декодуйте його, не довіряючи розширенню імені файлу:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Це корисно, коли одна lure відкривається в неочікуваному застосунку, хоча `duti`, `dutix` або `LSHandlers` повідомляють про безпечне глобальне значення за замовчуванням. У контрольованій лабораторії точне непрозоре значення можна скопіювати з файлу, налаштованого через Finder; його видалення відновлює звичайне визначення за типом:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Цікаві ключі Info.plist

Під час triage bundle застосунку найбільше значення мають такі ключі:

- **`CFBundleDocumentTypes`**: групи документів, які bundle заявляє як такі, що може відкривати.
- **`LSItemContentTypes`**: **сучасний / рекомендований** спосіб прив’язки типів документів до UTI.
- **`LSHandlerRank`**: рейтинг, який використовує LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes, реалізовані застосунком.
- **`UTExportedTypeDeclarations`**: UTI, якими застосунок **володіє**.
- **`UTImportedTypeDeclarations`**: UTI, якими застосунок не володіє, але хоче, щоб система їх розпізнавала.

Корисна команда для швидкого triage:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Тонка, але важлива деталь: якщо присутній **`LSItemContentTypes`**, старіші ключі, такі як **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`**, фактично є legacy compatibility data. Для фактичного визначення handler спочатку зосередьтеся на UTI path.

## Offensive notes

Applications не потрібно запускати, щоб вони стали цікавими. Dropped або cloned `.app` bundle може бути **автоматично розібраний `lsd` одразу після запису на диск**, а його оголошені document types / URL schemes можуть бути зареєстровані, навіть якщо користувач ніколи не запускає bundle.

Це корисно як для дослідження **persistence / hijacking**, так і для **initial-access chains**:

- Malicious app може заявити права на **рідкісне розширення** або **custom UTI** і чекати, доки victim відкриє lure file.
- Malicious app може зареєструвати **custom URL scheme**, доступну з browser, Electron app, office document, chat client або іншого helper app.<sup>[[1]](#references)</sup>
- Щоб відокремити звичайне default resolution від тестування конкретного candidate handler, викличте scheme через LaunchServices за допомогою `open 'targetscheme://host/path?value=test'`, а потім націльтеся на конкретний зареєстрований bundle за допомогою `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Це корисно для аудиту того, як receiving app перевіряє та декодує URL components, контрольовані attacker.<sup>[[1]](#references)</sup>
- Якщо ви редагуєте app bundle після його створення, можна змусити LaunchServices повторно розібрати його за допомогою:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Під час тестування підозрілих bundles звертайте особливу увагу на:

- **`LSHandlerRank=Owner`** для нетипових типів.
- **Широкі масиви `CFBundleDocumentTypes`**, які заявляють підтримку багатьох розширень.
- **Helper / wrapper apps**, чия єдина цікава поведінка прихована за document або URI handler.
- **Файли, подібні до shortcut** (`.webloc`, `.inetloc`, `.fileloc`), які зрештою передають обробку до LaunchServices. Щодо трюків у стилі `.fileloc` та пов’язаних із ними аспектів Gatekeeper перегляньте [цю іншу сторінку](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Якщо ваша мета — пасивне виконання коду лише під час переходу до теки або вибору файлу, також перегляньте спеціальну сторінку про [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана поверхня обробників файлів.



## References

- [1] [Objective-See - Віддалена експлуатація Mac через custom URL schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Обхід Gate: детальніший погляд на вразливості Gatekeeper у macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Як macOS відкриває файл у правильній програмі](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Керування LaunchServices у macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
