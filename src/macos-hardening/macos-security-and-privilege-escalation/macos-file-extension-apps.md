# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Це база даних усіх встановлених додатків у macOS, яку можна запитувати для отримання інформації про кожен встановлений додаток, таку як URL-схеми, які він підтримує, та MIME-типи.

Можливо вивантажити цю базу даних за допомогою:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Або використовуючи інструмент [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** є мозком бази даних. Він надає **кілька XPC сервісів** таких як `.lsd.installation`, `.lsd.open`, `.lsd.openurl` та інші. Але він також **вимагає деяких прав** для застосунків, щоб мати можливість використовувати відкриті XPC функціональності, такі як `.launchservices.changedefaulthandler` або `.launchservices.changeurlschemehandler` для зміни стандартних застосунків для mime-типів або схем URL та інших.

**`/System/Library/CoreServices/launchservicesd`** заявляє про сервіс `com.apple.coreservices.launchservicesd` і може бути запитаний для отримання інформації про запущені застосунки. Його можна запитати за допомогою системного інструменту /**`usr/bin/lsappinfo`** або з [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Обробники застосунків для розширень файлів та схем URL

Наступний рядок може бути корисним для знаходження застосунків, які можуть відкривати файли в залежності від розширення:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Або використовуйте щось на зразок [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Ви також можете перевірити розширення, підтримувані додатком, виконавши:
```
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
{{#include ../../banners/hacktricks-training.md}}
