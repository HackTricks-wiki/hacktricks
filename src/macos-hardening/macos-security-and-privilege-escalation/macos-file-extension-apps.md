# Обробники застосунків macOS для розширень файлів і схем URL

{{#include ../../banners/hacktricks-training.md}}

## База даних LaunchServices

Це база даних усіх установлених у macOS застосунків. Її можна запитувати, щоб отримати інформацію про кожен установлений застосунок, зокрема про підтримувані **схеми URL**, **типи документів**, **UTI** та обробники за замовчуванням.

Цю базу даних можна вивантажити за допомогою:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Або за допомогою інструмента [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** — це мозок бази даних. Він надає **кілька XPC-сервісів**, як-от `.lsd.installation`, `.lsd.open`, `.lsd.openurl` тощо. Але для використання наданих функцій XPC він також **вимагає певних entitlements** від програм, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler`, щоб змінювати програми за замовчуванням для MIME-типів або схем URL тощо.

**`/System/Library/CoreServices/launchservicesd`** реєструє сервіс `com.apple.coreservices.launchservicesd`; до нього можна звернутися, щоб отримати інформацію про запущені програми. Для запитів можна використовувати системний інструмент **`/usr/bin/lsappinfo`** або [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З погляду оператора, майте на увазі, що зазвичай є **два корисні представлення**:

- **База даних реєстрації**, якою керують LaunchServices / `lsd` (зберігається у файлах `.csstore`).
- **Ефективні налаштування за замовчуванням для кожного користувача**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` у масиві `LSHandlers`.

Ця відмінність важлива: програма може бути **зареєстрована** як така, що може обробляти тип або схему, але **поточною програмою за замовчуванням** усе ще може бути інший bundle ID.

У новіших версіях macOS пошук зареєстрованих програм не обмежується `/Applications`: програми з інших доступних папок, видимих у Spotlight, а також із змонтованих або спільних томів можуть потрапити до реєстру. Тому під час тріажу зберігайте дані про `path` і том із виводу `lsregister -dump` і не вважайте, що скасування реєстрації програми буде остаточним, поки її bundle залишається доступним для пошуку.<sup>[[4]](#references)</sup>

## Обробники файлів за розширенням і схем URL

Наведений нижче рядок може бути корисним для пошуку програм, які можуть відкривати файли залежно від їхнього розширення:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

Або скористайтеся чимось на кшталт [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

Також можна перевірити розширення, які підтримує програма, виконавши:

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

Щоб зробити дамп обробників **URL scheme** з нього:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Щоб отримати дамп обробників **content-type / UTI**:

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

### Перевизначення `Open With` для окремих файлів

Визначення обробника також має **рівень для окремих файлів**. Перш ніж використовувати UTI файлу та глобальне значення за замовчуванням для користувача, LaunchServices перевіряє розширений атрибут `com.apple.LaunchServices.OpenWith`. Finder створює його, коли для одного файлу вибрано **Завжди відкривати за допомогою**; його значення — двійковий список властивостей, що містить шлях до застосунку, ідентифікатор пакета та селектор версії.<sup>[[3]](#references)</sup>

Перегляньте та декодуйте його, не довіряючи розширенню імені файлу:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Це корисно, коли одна приманка відкривається в неочікуваній програмі, хоча `duti`, `dutix` або `LSHandlers` указує на безпечну глобальну програму за замовчуванням. У контрольованій лабораторії точне непрозоре значення можна скопіювати з файлу, налаштованого через Finder; його видалення відновлює звичайне визначення програми за типом:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Цікаві ключі Info.plist

Під час первинного аналізу пакета програми найважливіші такі ключі:

- **`CFBundleDocumentTypes`**: групи документів, які пакет заявляє, що може відкривати.
- **`LSItemContentTypes`**: **сучасний / рекомендований** спосіб прив’язати типи документів до UTI.
- **`LSHandlerRank`**: пріоритет, який використовує LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: власні URI-схеми, які реалізує програма.
- **`UTExportedTypeDeclarations`**: UTI, якими програма **володіє**.
- **`UTImportedTypeDeclarations`**: UTI, якими програма не володіє, але які вона хоче, щоб система розпізнавала.

Для швидкого первинного аналізу стане в пригоді така команда:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Тонка, але важлива деталь: якщо **`LSItemContentTypes`** присутній, старіші ключі, як-от **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`**, фактично є застарілими даними для сумісності. Для фактичного визначення обробника насамперед зосередьтеся на шляху UTI.

## Нотатки для атак

Щоб застосунки стали цікавими, їх не обов’язково запускати. Щойно скинутий на диск або клонований bundle `.app` може бути **автоматично проаналізований `lsd`**, а оголошені ним типи документів і URL-схеми можуть зареєструватися, навіть якщо користувач ніколи не запускав bundle.

Це корисно як для дослідження **persistence / hijacking**, так і для **ланцюжків початкового доступу**:

- Шкідливий застосунок може заявити **рідкісне розширення** або **custom UTI** і чекати, поки жертва відкриє файл-приманку.
- Шкідливий застосунок може зареєструвати **custom URL scheme**, доступну з браузера, застосунку Electron, офісного документа, клієнта чату чи іншого допоміжного застосунку.<sup>[[1]](#references)</sup>
- Щоб відокремити звичайне визначення обробника за замовчуванням від тестування конкретного кандидата, викличте схему через LaunchServices командою `open 'targetscheme://host/path?value=test'`, а потім вкажіть конкретний зареєстрований bundle командою `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Це корисно для перевірки того, як застосунок-одержувач перевіряє та декодує компоненти URL, контрольовані зловмисником.<sup>[[1]](#references)</sup>
- Якщо відредагувати bundle застосунку після його збирання, можна примусово запустити його повторний аналіз LaunchServices за допомогою:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Під час перевірки підозрілих bundles звертайте особливу увагу на:

- **`LSHandlerRank=Owner`** для рідкісних типів.
- **Широкі масиви `CFBundleDocumentTypes`**, що заявляють підтримку багатьох розширень.
- **Допоміжні / оболонкові apps**, у яких єдина цікава поведінка активується через обробник документа або URI.
- **Файли, схожі на ярлики** (`.webloc`, `.inetloc`, `.fileloc`), які зрештою передають керування LaunchServices. Про трюки у стилі `.fileloc` та пов’язані з ними аспекти Gatekeeper дивіться [цю іншу сторінку](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Якщо ваша мета — пасивне виконання коду лише від переходу до папки або вибору файла, перегляньте також окрему сторінку про [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана поверхня обробників файлів.



## References

- [1] [Objective-See - Віддалена експлуатація Mac через власні URL-схеми](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Обхід Gate: детальніший погляд на вразливості Gatekeeper у macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Як macOS відкриває файл у відповідній програмі](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Керування LaunchServices у macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
