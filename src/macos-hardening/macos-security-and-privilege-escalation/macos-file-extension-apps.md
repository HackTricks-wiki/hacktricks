# Обробники розширень файлів і схем URL у macOS

{{#include ../../banners/hacktricks-training.md}}

## База даних LaunchServices

Це база даних усіх установлених у macOS програм, з якої можна отримати інформацію про кожну програму, зокрема про підтримувані **схеми URL**, **типи документів**, **UTI** та обробники за замовчуванням.

Цю базу даних можна вивантажити за допомогою:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Або за допомогою інструмента [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** — це ядро бази даних. Він надає **кілька XPC-сервісів**, як-от `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інші. Але для використання доступних функцій XPC застосункам також потрібні **певні entitlements**, наприклад `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler`, щоб змінювати програми за замовчуванням для MIME-типів чи схем URL, та інші.

**`/System/Library/CoreServices/launchservicesd`** реєструє сервіс `com.apple.coreservices.launchservicesd`, до якого можна звертатися, щоб отримати інформацію про запущені застосунки. Звертатися до нього можна за допомогою системного інструмента **`/usr/bin/lsappinfo`** або [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

З погляду оператора варто пам’ятати, що зазвичай є **два корисні способи перегляду**:

- **База даних реєстрації**, якою керують LaunchServices / `lsd` (зберігається у файлах `.csstore`).
- **Ефективні значення за замовчуванням для кожного користувача**, що зберігаються в `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` у масиві `LSHandlers`.

Ця відмінність важлива: застосунок може бути **зареєстрований** як такий, що може обробляти певний тип або схему, але **поточним застосунком за замовчуванням** усе ще може бути інший bundle ID.

У новіших випусках macOS пошук зареєстрованих застосунків не обмежується каталогом `/Applications`: до реєстру можуть потрапляти застосунки з інших доступних папок, видимих для Spotlight, а також із підключених чи спільних томів. Тому під час triage зберігайте інформацію про `path` і том із виводу `lsregister -dump` та не вважайте скасування реєстрації застосунку остаточним, доки його bundle залишається доступним для пошуку.<sup>[[4]](#references)</sup>

## Обробники застосунків для розширень файлів і схем URL

Наступний рядок може бути корисним для пошуку застосунків, які можуть відкривати файли залежно від розширення:

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

Щоб вивести обробники **content-type / UTI**:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Щоб визначити дерево UTI для зразкового файлу:

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

Визначення обробника також має **специфічний для файлу** рівень. Перш ніж перейти до UTI файлу та глобального типового обробника користувача, LaunchServices перевіряє розширений атрибут `com.apple.LaunchServices.OpenWith`. Finder створює його, коли для одного файлу вибрано **Завжди відкривати за допомогою**; його значення — це бінарний список властивостей, що містить шлях до програми, ідентифікатор bundle та селектор версії.<sup>[[3]](#references)</sup>

Перевірте й декодуйте його, не довіряючи розширенню імені файлу:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Це корисно, коли одна приманка відкривається в неочікуваній програмі, хоча `duti`, `dutix` або `LSHandlers` указує на безпечну глобальну програму за замовчуванням. У контрольованому лабораторному середовищі точне непрозоре значення можна скопіювати з файла, налаштованого через Finder; його видалення відновлює звичайне визначення програми за типом файла:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Цікаві ключі Info.plist

Під час первинного аналізу пакета програми найбільше значення мають такі ключі:

- **`CFBundleDocumentTypes`**: групи документів, які пакет заявляє, що може відкривати.
- **`LSItemContentTypes`**: **сучасний / рекомендований** спосіб прив’язати типи документів до UTI.
- **`LSHandlerRank`**: рейтинг, який використовує LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: власні URI-схеми, які реалізує програма.
- **`UTExportedTypeDeclarations`**: UTI, якими програма **володіє**.
- **`UTImportedTypeDeclarations`**: UTI, якими програма не володіє, але які хоче, щоб система розпізнавала.

Корисна команда для швидкого первинного аналізу:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Важлива, хоч і непомітна деталь: якщо присутній **`LSItemContentTypes`**, старіші ключі, як-от **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** і **`CFBundleTypeOSTypes`**, фактично є застарілими даними для сумісності. Під час фактичного визначення обробника спершу зосередьтеся на шляху UTI.

## Нотатки для атак

Застосунки не обов’язково мають запускатися, щоб їхні реєстрації обробників стали цікавими, але **самого створення бандла `.app` недостатньо, щоб гарантувати негайну реєстрацію**. Finder може зареєструвати застосунок, коли виявить його, зокрема коли користувач переглядає його теку; реєстрація також може відбутися під час завантаження системи чи входу користувача або через явний виклик реєстрації. Перед тестуванням перевірте `lsregister -dump`. Сама реєстрація не запускає застосунок і не робить його ефективним типовим обробником.<sup>[[5]](#references)</sup> Вимоги для persistence див. у розділі [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Це корисно як для дослідження **persistence / hijacking**, так і для **ланцюжків initial access**:

- Шкідливий застосунок може заявити підтримку **рідкісного розширення** або **custom UTI** й чекати, доки жертва відкриє файл-приманку.
- Шкідливий застосунок може зареєструвати **custom URL scheme**, до якої можна звернутися з браузера, застосунку Electron, офісного документа, клієнта чату або іншого допоміжного застосунку.<sup>[[1]](#references)</sup>
- Щоб відокремити звичайне визначення типового обробника від тестування конкретного кандидата, викличте схему через LaunchServices командою `open 'targetscheme://host/path?value=test'`, а потім вкажіть конкретний зареєстрований бандл командою `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Це корисно для аудиту того, як застосунок-одержувач перевіряє та декодує контрольовані зловмисником компоненти URL.<sup>[[1]](#references)</sup>
- Якщо після збирання відредагувати бандл застосунку, можна примусово змусити LaunchServices повторно його розібрати за допомогою:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Під час тестування підозрілих bundle особливу увагу звертайте на:

- **`LSHandlerRank=Owner`** для рідкісних типів.
- **Широкі масиви `CFBundleDocumentTypes`**, у яких заявлено багато розширень.
- **Допоміжні застосунки / wrapper-застосунки**, у яких єдина цікава поведінка доступна лише через обробник документа чи URI.
- **Файли, схожі на ярлики** (`.webloc`, `.inetloc`, `.fileloc`), які зрештою передають керування LaunchServices. Щодо трюків у стилі `.fileloc` та пов’язаних із ними аспектів Gatekeeper див. [цю іншу сторінку](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Параметри URL, що передаються в подальші опції

Підтвердження браузера для зовнішнього протоколу лише дозволяє відкрити обробник; воно не робить параметри URL надійними. Простежте шлях від парсера URL у застосунку-одержувачі до будь-якої бібліотеки, медіамеханізму, допоміжного процесу чи опції запису файлів. Шукайте префікс ключів запиту, який перетворює поля URL на назви подальших опцій. Перевірте буквальні роздільники та роздільники з percent-encoding, використовуючи нешкідливий маркер в одноразовому обліковому записі.<sup>[[6]](#references)</sup>

Перевірте **остаточну опцію, прийняту подальшим компонентом**, а не лише початковий парсинг у застосунку. Один обробник дозволяв префіксованим ключам запиту досягати команд введення mpv; блокування цієї опції все одно залишало шлях для запису файлів. Перевіряйте доступний клас опцій, а не лише один відомий небезпечний ключ.<sup>[[7]](#references)</sup>

### Вбудований обробник `applescript://`

Обробник URL `applescript://com.apple.scripteditor` приймає `action=new` і параметр `script` із URL-кодуванням. Тому посилання в браузері може відкрити Script Editor із уже вставленим у редактор AppleScript, контрольованим зловмисником, оминаючи крок вставлення в Terminal. **Автоматичного виконання немає**: браузер може запитати дозвіл на відкриття Script Editor, а користувач має запустити скрипт.<sup>[[8]](#references)</sup>

У новіших версіях macOS може з’являтися попередження для документа зі скриптом, а XProtect сканує AppleScript під час виконання.<sup>[[8]](#references)[[9]](#references)</sup>

Використайте нешкідливу локальну перевірку, щоб протестувати обробник і запити на macOS, що оцінюється; скрипт має лише з’явитися в редакторі, доки не буде натиснуто **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Якщо ваша мета — пасивне виконання коду лише через перегляд папки або вибір файлу, перегляньте також окрему сторінку про [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), оскільки це інша, але тісно пов’язана поверхня обробників файлів.



## References

- [1] [Objective-See — віддалена експлуатація Mac через користувацькі URL-схеми](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs — обхід Gate: детальніший погляд на вразливості Gatekeeper у macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company — як macOS відкриває файл у відповідній програмі](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company — керування LaunchServices у macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple — основні поняття Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer — дослідження виконання команд через URL-схему IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA — небезпечна обробка параметрів mpv у URL-схемі](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs — техніка ClickFix використовує Script Editor замість Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple — захист Terminal і скриптів](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
