# Обробники застосунків для розширень файлів і URL scheme

{{#include ../../banners/hacktricks-training.md}}

## База даних LaunchServices

Це база даних усіх встановлених застосунків у macOS, яку можна запитувати для отримання інформації про кожен встановлений застосунок, зокрема про підтримувані **URL schemes**, **типи документів**, **UTIs** і обробники за замовчуванням.

Цю базу даних можна отримати за допомогою:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Або за допомогою інструмента [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** є ядром бази даних. Він надає **кілька XPC-сервісів**, як-от `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інші. Однак для використання відкритих XPC-функцій застосункам також потрібні **певні entitlements**, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler` для зміни застосунків за замовчуванням для MIME-типів або URL-схем, а також інші.

**`/System/Library/CoreServices/launchservicesd`** реєструє сервіс `com.apple.coreservices.launchservicesd`, і до нього можна звертатися для отримання інформації про запущені застосунки. До нього можна звертатися за допомогою системного інструмента **`/usr/bin/lsappinfo`** або [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З погляду оператора слід пам’ятати, що зазвичай є **два корисні представлення**:

- **Реєстраційна база даних**, якою керують LaunchServices / `lsd` (на основі файлів `.csstore`).
- **Ефективні defaults для користувача**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` у масиві `LSHandlers`.

Ця відмінність важлива: застосунок може бути **зареєстрований** як такий, що підтримує певний тип або схему, але **поточним default** усе ще може бути інший bundle ID.

## Обробники застосунків для розширень файлів і URL-схем

Наведений нижче рядок може бути корисним для пошуку застосунків, які можуть відкривати файли залежно від розширення:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Або використовуйте щось на кшталт [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Також можна перевірити розширення, які підтримує застосунок, виконавши:
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

Найкориснішим файлом для **типових програм поточного користувача** зазвичай є:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Щоб отримати дамп обробників **URL scheme** з нього:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб отримати dump обробників **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб визначити дерево UTI для зразка файлу:
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
## Цікаві ключі Info.plist

Під час triage bundle застосунку найбільше значення мають такі ключі:

- **`CFBundleDocumentTypes`**: групи документів, які bundle заявляє як підтримувані для відкриття.
- **`LSItemContentTypes`**: **сучасний / рекомендований** спосіб прив’язування типів документів до UTI.
- **`LSHandlerRank`**: рейтинг, який використовується LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes, реалізовані застосунком.
- **`UTExportedTypeDeclarations`**: UTI, якими застосунок **володіє**.
- **`UTImportedTypeDeclarations`**: UTI, якими застосунок не володіє, але хоче, щоб система їх розпізнавала.

Корисна швидка команда для triage:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Тонка, але важлива деталь: якщо присутній **`LSItemContentTypes`**, старіші ключі, як-от **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`**, фактично є застарілими даними для сумісності. Для фактичного визначення обробника спочатку орієнтуйтеся на шлях UTI.

## Операційні нотатки

Застосунки не потрібно запускати, щоб вони стали цікавими. Скопійований або клонований пакет `.app` може бути **автоматично проаналізований `lsd` одразу після запису на диск**, а оголошені ним типи документів / URL schemes можуть бути зареєстровані, навіть якщо користувач ніколи не запускає пакет.

Це корисно як для дослідження **persistence / hijacking**, так і для **ланцюгів initial access**:

- Шкідливий застосунок може заявити права на **рідкісне розширення** або **custom UTI** і чекати, доки жертва відкриє файл-приманку.
- Шкідливий застосунок може зареєструвати **custom URL scheme**, доступну з браузера, Electron app, офісного документа, chat client або іншого helper app.<sup>[[1]](#references)</sup>
- Якщо відредагувати пакет застосунку після його збирання, можна змусити LaunchServices повторно проаналізувати його за допомогою:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Під час тестування підозрілих bundles звертайте особливу увагу на:

- **`LSHandlerRank=Owner`** для нетипових типів.
- **Широкі масиви `CFBundleDocumentTypes`**, що заявляють підтримку багатьох розширень.
- **Helper / wrapper apps**, чия єдина цікава поведінка прихована за document або URI handler.
- **Файли, схожі на ярлики** (`.webloc`, `.inetloc`, `.fileloc`), які зрештою передають обробку до LaunchServices. Для трюків у стилі `.fileloc` і пов’язаних із ними аспектів Gatekeeper перегляньте [цю іншу сторінку](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Якщо ваша мета — пасивне виконання коду лише під час переходу до теки або вибору файлу, також перегляньте спеціальну сторінку про [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана поверхня file handler.

## Посилання


- [1] [Objective-See — Віддалена експлуатація Mac через Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs — Обхід Gate: детальніше про вразливості Gatekeeper у macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
