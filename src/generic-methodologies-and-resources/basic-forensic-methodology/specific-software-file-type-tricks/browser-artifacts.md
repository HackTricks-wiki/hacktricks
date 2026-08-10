# Артефакти браузера

## Артефакти браузерів <a href="#id-3def" id="id-3def"></a>

Артефакти браузера містять різні типи даних, що зберігаються веббраузерами, як-от історія навігації, закладки та дані кешу. Ці артефакти зберігаються у спеціальних папках операційної системи, розташування та назви яких відрізняються залежно від браузера, але зазвичай містять подібні типи даних.

Ось короткий опис найпоширеніших артефактів браузера:

- **Історія навігації**: відстежує відвідування користувачем вебсайтів і допомагає визначити відвідування шкідливих сайтів.
- **Дані автозаповнення**: пропозиції на основі частих пошукових запитів, які в поєднанні з історією навігації дають додаткові відомості.
- **Закладки**: сайти, збережені користувачем для швидкого доступу.
- **Розширення та додатки**: розширення або додатки браузера, встановлені користувачем.
- **Кеш**: зберігає вебвміст (наприклад, зображення та JavaScript-файли) для пришвидшення завантаження вебсайтів і є цінним джерелом для forensic analysis.
- **Облікові дані**: збережені облікові дані для входу.
- **Favicons**: піктограми, пов'язані з вебсайтами, які відображаються у вкладках і закладках та можуть надати додаткову інформацію про відвідування користувачем.
- **Сеанси браузера**: дані, пов'язані з відкритими сеансами браузера.
- **Завантаження**: записи про файли, завантажені через браузер.
- **Дані форм**: інформація, введена у вебформи та збережена для майбутніх пропозицій автозаповнення.
- **Ескізи**: зображення-попередні перегляди вебсайтів.
- **Custom Dictionary.txt**: слова, додані користувачем до словника браузера.

## Firefox

Firefox організовує дані користувача в профілі, що зберігаються у визначених місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Файл `profiles.ini` у цих каталогах містить список профілів користувача. Дані кожного профілю зберігаються в папці, назва якої вказана у змінній `Path` у файлі `profiles.ini` і яка розташована в тому самому каталозі, що й сам файл `profiles.ini`. Якщо папка профілю відсутня, її могли видалити.

У кожній папці профілю можна знайти кілька важливих файлів:<sup>[[1]](#references)</sup>

- **places.sqlite**: зберігає історію, закладки та завантаження. У Windows такі інструменти, як [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), можуть отримувати доступ до даних історії.
- Використовуйте спеціальні SQL-запити для вилучення інформації про історію та завантаження.
- **bookmarkbackups**: містить резервні копії закладок.
- **formhistory.sqlite**: зберігає дані вебформ.
- **handlers.json**: керує обробниками протоколів.
- **persdict.dat**: слова користувацького словника.
- **addons.json** та **extensions.sqlite**: інформація про встановлені додатки та розширення.
- **cookies.sqlite**: сховище cookie; у Windows для перевірки можна використовувати [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** або **startupCache**: дані кешу, доступні через такі інструменти, як [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: зберігає Favicons.
- **prefs.js**: налаштування та параметри користувача.
- **downloads.sqlite**: стара база даних завантажень, тепер інтегрована в places.sqlite.
- **thumbnails**: ескізи вебсайтів.
- **logins.json**: зашифрована інформація для входу.
- **key4.db** або **key3.db**: зберігає ключі шифрування для захисту конфіденційної інформації.

Крім того, перевірити налаштування браузера для захисту від фішингу можна, виконавши пошук записів `browser.safebrowsing` у `prefs.js`; вони вказують, чи ввімкнені або вимкнені функції безпечного перегляду.<sup>[[2]](#references)</sup>

Щоб спробувати розшифрувати master password, можна використати [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
За допомогою наведеного нижче скрипту та виклику можна вказати файл паролів для brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Артефакти браузерів - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome зберігає профілі користувачів у певних розташуваннях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

У цих каталогах більшість даних користувача можна знайти в папках **Default/** або **ChromeDefaultData/**. Значний обсяг даних містять такі файли:<sup>[[1]](#references)</sup>

- **History**: Містить URL-адреси, завантаження та пошукові ключові слова. У Windows для читання історії можна використовувати [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Стовпець "Transition Type" має різні значення, зокрема клацання користувача на посиланнях, введені URL-адреси, надсилання форм і перезавантаження сторінок.
- **Cookies**: Зберігає cookies. Для перегляду доступний [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Містить кешовані дані. Для перегляду користувачі Windows можуть скористатися [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Настільні apps на основі Electron (наприклад, Discord) також використовують Chromium Simple Cache і залишають значну кількість артефактів на диску. Дивіться:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Закладки користувача.
- **Web Data**: Містить історію форм.
- **Favicons**: Зберігає favicons вебсайтів.
- **Login Data**: Містить облікові дані для входу, як-от імена користувачів і паролі.
- **Current Session**/**Current Tabs**: Дані про поточний сеанс перегляду та відкриті вкладки.
- **Last Session**/**Last Tabs**: Інформація про сайти, активні під час останнього сеансу перед закриттям Chrome.
- **Extensions**: Каталоги browser extensions і addons.
- **Thumbnails**: Зберігає ескізи вебсайтів.
- **Preferences**: Файл із великою кількістю інформації, зокрема налаштуваннями plugins, extensions, pop-ups, notifications тощо.
- **Browser’s built-in anti-phishing**: Щоб перевірити, чи ввімкнено anti-phishing і захист від malware, виконайте `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. У виводі знайдіть `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **Відновлення даних SQLite DB**

Як видно з попередніх розділів, Chrome і Firefox використовують бази даних **SQLite** для зберігання даних. **Видалені записи можна відновити за допомогою інструмента** [**sqlparse**](https://github.com/padfoot999/sqlparse) **або** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 керує своїми даними та метаданими в різних розташуваннях, що допомагає відокремлювати збережену інформацію та відповідні відомості для зручного доступу й керування.

### Зберігання метаданих

Метадані Internet Explorer зберігаються в `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (де VX може бути V01, V16 або V24). Файл `V01.log` може містити час модифікації, що не збігається з `WebcacheVX.data`, що вказує на необхідність відновлення за допомогою `esentutl /r V01 /d`. Ці метадані, що зберігаються в базі даних ESE, можна відновити та переглянути за допомогою таких інструментів, як photorec і [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), відповідно. У таблиці **Containers** можна визначити конкретні таблиці або контейнери, де зберігається кожен сегмент даних, зокрема відомості про кеш інших інструментів Microsoft, таких як Skype.

### Перегляд кешу

Інструмент [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) дає змогу переглядати кеш; для цього потрібно вказати розташування папки з видобутими даними кешу. Метадані кешу містять ім’я файлу, каталог, кількість доступів, походження URL-адреси та часові мітки створення, доступу, модифікації й завершення дії кешу.

### Керування cookies

Cookies можна переглядати за допомогою [IECookiesView](https://www.nirsoft.net/utils/iecookies.html); метадані містять імена, URL-адреси, кількість доступів та різні часові відомості. Постійні cookies зберігаються в `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, а cookies сеансу перебувають у пам’яті.

### Відомості про завантаження

Метадані завантажень доступні через [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); конкретні контейнери містять такі дані, як URL-адреса, тип файлу та місце завантаження. Фізичні файли можна знайти в `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Історія перегляду

Для перегляду історії перегляду можна використовувати [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), указавши розташування видобутих файлів історії та налаштувавши Internet Explorer. Ці метадані містять час модифікації й доступу, а також кількість доступів. Файли історії розташовані в `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Введені URL-адреси

Введені URL-адреси та час їх використання зберігаються в реєстрі в `NTUSER.DAT` за адресами `Software\Microsoft\InternetExplorer\TypedURLs` і `Software\Microsoft\InternetExplorer\TypedURLsTime`. Вони відстежують останні 50 URL-адрес, введених користувачем, і час їх останнього введення.

## Microsoft Edge

Microsoft Edge зберігає дані користувача в `%userprofile%\Appdata\Local\Packages`. Шляхи до різних типів даних:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Дані Safari зберігаються в `/Users/$User/Library/Safari`. Основні файли:<sup>[[3]](#references)</sup>

- **History.db**: Містить таблиці `history_visits` і `history_items` з URL-адресами та часовими мітками відвідувань. Для запитів використовуйте `sqlite3`.
- **Downloads.plist**: Інформація про завантажені файли.
- **Bookmarks.plist**: Зберігає URL-адреси закладок.
- **TopSites.plist**: Найчастіше відвідувані сайти.
- **Extensions.plist**: Список browser extensions Safari. Для отримання даних використовуйте `plutil` або `pluginkit`.
- **UserNotificationPermissions.plist**: Домени, яким дозволено надсилати push notifications. Для аналізу використовуйте `plutil`.
- **LastSession.plist**: Вкладки з останнього сеансу. Для аналізу використовуйте `plutil`.
- **Browser’s built-in anti-phishing**: Перевірте за допомогою `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Відповідь 1 означає, що функцію активовано.<sup>[[2]](#references)</sup>

## Opera

Дані Opera зберігаються в `/Users/$USER/Library/Application Support/com.operasoftware.Opera` і використовують такий самий формат для історії та завантажень, як Chrome.

- **Browser’s built-in anti-phishing**: Перевірте, чи має `fraud_protection_enabled` у файлі Preferences значення `true`, за допомогою `grep`.<sup>[[2]](#references)</sup>

Ці шляхи та команди важливі для доступу до даних перегляду, що зберігаються різними web browsers, і їх розуміння.

## References

- [1] [Криміналістичний аналіз web browsers: посібник із проведення криміналістичного аналізу web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Реагування на інциденти macOS | Частина 3: маніпуляції із системою](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Реагування на інциденти OS X: написання скриптів та аналіз, автор Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
