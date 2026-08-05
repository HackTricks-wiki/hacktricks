# Обробники застосунків для розширень файлів і схем URL

{{#include ../../banners/hacktricks-training.md}}

## База даних LaunchServices

Це база даних усіх установлених у macOS застосунків, яку можна запитувати для отримання інформації про кожен установлений застосунок, зокрема про підтримувані **URL schemes**, **типи документів**, **UTIs** і обробники за замовчуванням.

Цю базу даних можна вивантажити за допомогою:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Або за допомогою інструмента [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** є ядром бази даних. Він надає **кілька XPC-сервісів**, як-от `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інші. Але для використання відкритих XPC-функцій застосункам також потрібні **певні entitlements**, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler` для зміни стандартних застосунків для MIME-типів або URL-схем, а також інші.

**`/System/Library/CoreServices/launchservicesd`** реєструє сервіс `com.apple.coreservices.launchservicesd`, і до нього можна надсилати запити, щоб отримати інформацію про запущені застосунки. Запити можна виконувати за допомогою системного інструмента **`/usr/bin/lsappinfo`** або [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З точки зору оператора, слід пам’ятати, що зазвичай існує **два корисні представлення**:

- **Реєстраційна база даних**, якою керують LaunchServices / `lsd` (на основі файлів `.csstore`).
- **Ефективні стандартні налаштування для користувача**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` у масиві `LSHandlers`.

Ця відмінність важлива: застосунок може бути **зареєстрований** як такий, що може обробляти певний тип або схему, але **поточним стандартним** усе ще може бути інший bundle ID.

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

Найкориснішим файлом для **типових налаштувань поточного користувача** зазвичай є:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Щоб витягти обробники **URL scheme** з нього:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб виконати **dump** обробників **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб визначити дерево UTI для зразка файлу:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Якщо вам потрібен зручніший CLI для перегляду або зміни значень за замовчуванням:
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

Під час первинного аналізу bundle застосунку найбільше значення мають такі ключі:

- **`CFBundleDocumentTypes`**: групи документів, які bundle заявляє як такі, що може відкривати.
- **`LSItemContentTypes`**: **сучасний / рекомендований** спосіб прив’язування типів документів до UTI.
- **`LSHandlerRank`**: рейтинг, який використовує LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: власні URI-схеми, реалізовані застосунком.
- **`UTExportedTypeDeclarations`**: UTI, якими застосунок **володіє**.
- **`UTImportedTypeDeclarations`**: UTI, якими застосунок не володіє, але хоче, щоб система їх розпізнавала.

Корисна команда для швидкого первинного аналізу:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Тонка, але важлива деталь: якщо присутній **`LSItemContentTypes`**, старіші ключі, як-от **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`**, фактично є legacy-даними для сумісності. Для фактичного визначення handler спочатку зосередьтеся на шляху UTI.

## Offensive notes

Applications не потрібно запускати, щоб вони стали цікавими. Скинутий або клонований `.app` bundle може бути **автоматично розібраний `lsd`, щойно його буде записано на диск**, а його оголошені document types / URL schemes можуть бути зареєстровані, навіть якщо користувач ніколи не запускав bundle.

Це корисно як для дослідження **persistence / hijacking**, так і для **initial-access chains**:

- Шкідливий app може заявити **рідкісне розширення** або **custom UTI** і чекати, доки victim відкриє файл-приманку.
- Шкідливий app може зареєструвати **custom URL scheme**, доступну з browser, Electron app, office document, chat client або іншого helper app.<sup>[[1]](#references)</sup>
- Якщо відредагувати app bundle після його створення, можна змусити LaunchServices повторно розібрати його за допомогою:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Під час тестування підозрілих bundle особливу увагу приділяйте:

- **`LSHandlerRank=Owner`** для нетипових типів.
- **Широким масивам `CFBundleDocumentTypes`**, які заявляють підтримку багатьох розширень.
- **Helper / wrapper apps**, єдина цікава поведінка яких прихована за обробником документа або URI.
- **Файлам, схожим на ярлики** (`.webloc`, `.inetloc`, `.fileloc`), які зрештою передають обробку до LaunchServices. Щодо трюків у стилі `.fileloc` та пов’язаних із ними аспектів Gatekeeper дивіться [цю іншу сторінку](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Якщо ваша мета — пасивний code-execution лише під час переходу до папки або вибору файлу, також перегляньте спеціальну сторінку про [генератори Quick Look](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана поверхня обробників файлів.

## Посилання

- [1] [Objective-See - Віддалена експлуатація Mac через Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Обхід Gate: детальніший погляд на недоліки Gatekeeper у macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
