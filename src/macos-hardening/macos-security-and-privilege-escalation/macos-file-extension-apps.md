# Обробники застосунків для file extension та URL scheme у macOS

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Це база даних усіх встановлених застосунків у macOS, яку можна запитувати, щоб отримати інформацію про кожен встановлений застосунок, таку як підтримувані **URL schemes**, **document types**, **UTIs** і стандартні обробники.

Цю базу даних можна вивантажити за допомогою:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Або використовуючи інструмент [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** — це мозок бази даних. Він надає **кілька XPC services** на кшталт `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інших. Але він також **вимагає певних entitlements** для applications, щоб вони могли використовувати відкриті XPC функціональності, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler`, щоб змінювати default apps для MIME types або URL schemes та інші.

**`/System/Library/CoreServices/launchservicesd`** оголошує service `com.apple.coreservices.launchservicesd` і до нього можна звернутися, щоб отримати information про запущені applications. До нього можна звернутися за допомогою системного інструмента **`/usr/bin/lsappinfo`** або з [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З точки зору оператора, майте на увазі, що зазвичай існують **два корисні подання**:

- **registration database**, якою керує LaunchServices / `lsd` (на основі файлів `.csstore`).
- **per-user effective defaults**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` в масиві `LSHandlers`.

Ця відмінність має значення: application може бути **зареєстрована** як здатна обробляти type або scheme, але **поточний default** все ще може належати іншому bundle ID.

## File Extension & URL scheme app handlers

Наступний рядок може бути корисним, щоб знайти applications, які можуть відкривати файли залежно від extension:
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
Ви також можете перевірити розширення, які підтримує застосунок, зробивши так:
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
## Перелік ефективних handlers

Найкорисніший файл для **current user's defaults** зазвичай:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Щоб вивантажити обробники **URL scheme** з нього:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб вивантажити обробники **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Щоб розв’язати дерево UTI для зразка файлу:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Якщо ви хочете зручніший CLI для запиту або зміни defaults:
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

Під час triage application bundle ці ключі мають найбільше значення:

- **`CFBundleDocumentTypes`**: document groups, які bundle заявляє, що може відкривати.
- **`LSItemContentTypes`**: **modern / preferred** спосіб зв’язати document types з UTIs.
- **`LSHandlerRank`**: ranking, який використовує LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: custom URI schemes, реалізовані app.
- **`UTExportedTypeDeclarations`**: UTIs, якими app **володіє**.
- **`UTImportedTypeDeclarations`**: UTIs, якими app не володіє, але хоче, щоб system їх розпізнав.

Корисна швидка triage команда:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Нюанс, який легко пропустити, але він важливий: якщо присутній **`LSItemContentTypes`**, старі ключі на кшталт **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`** фактично є legacy-даними для сумісності. Для фактичного визначення handler спочатку зосередьтеся на шляху UTI.

## Offensive notes

Applications не потрібно запускати, щоб вони стали цікавими. Скинутий або клонований `.app` bundle може бути **автоматично parsed by `lsd` as soon as it is written to disk**, і його оголошені document types / URL schemes можуть бути зареєстровані без того, щоб користувач коли-небудь запускав bundle.

Це корисно і для **persistence / hijacking research**, і для **initial-access chains**:

- Шкідливий app може заявити **рідкісне розширення** або **custom UTI** і чекати, поки жертва відкриє lure file.
- Шкідливий app може зареєструвати **custom URL scheme**, до якого можна звернутися з browser, Electron app, office document, chat client або іншого helper app.
- Якщо ви редагуєте app bundle після збірки, ви можете змусити LaunchServices повторно parsed його за допомогою:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Під час тестування підозрілих bundle звертайте особливу увагу на:

- **`LSHandlerRank=Owner`** для незвичних типів.
- **Широкі масиви `CFBundleDocumentTypes`**, які заявляють багато extension.
- **Helper / wrapper apps**, у яких єдина цікава поведінка схована за document або URI handler.
- **Файли на кшталт shortcut** (`.webloc`, `.inetloc`, `.fileloc`), які в підсумку передають обробку до LaunchServices. Для `.fileloc`-подібних трюків і пов’язаних кутів атаки на Gatekeeper дивіться [this other page](macos-security-protections/macos-fs-tricks/README.md).

Якщо ваша мета — пасивне виконання code лише від відкриття папки або вибору файлу, також перевірте окрему сторінку про [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана surface обробки файлів.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
