# Артефакти браузера

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти браузерів <a href="#id-3def" id="id-3def"></a>

Артефакти браузера містять різні типи даних, що зберігаються веббраузерами, як-от історія навігації, закладки та дані кешу. Ці артефакти зберігаються у спеціальних папках операційної системи, розташування та назви яких відрізняються залежно від браузера, але зазвичай містять подібні типи даних.

Ось перелік найпоширеніших артефактів браузера:

- **Історія навігації**: відстежує відвідування користувачем вебсайтів і допомагає виявляти відвідування шкідливих сайтів.
- **Дані автозаповнення**: пропозиції на основі частих пошукових запитів, що в поєднанні з історією навігації дають додаткову інформацію.
- **Закладки**: сайти, збережені користувачем для швидкого доступу.
- **Extensions та Add-ons**: встановлені користувачем browser extensions або add-ons.
- **Кеш**: зберігає вебконтент (наприклад, зображення, JavaScript-файли) для пришвидшення завантаження вебсайтів і є цінним джерелом для forensic analysis.
- **Logins**: збережені облікові дані для входу.
- **Favicons**: іконки, пов’язані з вебсайтами, які відображаються у вкладках і закладках та можуть надати додаткову інформацію про відвідування користувачем.
- **Browser Sessions**: дані, пов’язані з відкритими browser sessions.
- **Downloads**: записи про файли, завантажені через браузер.
- **Form Data**: інформація, введена у вебформи та збережена для майбутніх пропозицій автозаповнення.
- **Thumbnails**: зображення попереднього перегляду вебсайтів.
- **Custom Dictionary.txt**: слова, додані користувачем до словника браузера.

## Firefox

Firefox упорядковує дані користувача в профілях, що зберігаються у спеціальних місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Файл `profiles.ini` у цих каталогах містить перелік профілів користувача. Дані кожного профілю зберігаються в папці, назва якої вказана у змінній `Path` у файлі `profiles.ini`; ця папка розташована в тому самому каталозі, що й сам `profiles.ini`. Якщо папка профілю відсутня, можливо, її було видалено.

У папці кожного профілю можна знайти кілька важливих файлів:<sup>[[1]](#references)</sup>

- **places.sqlite**: зберігає історію, закладки та завантаження. Такі інструменти, як [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) у Windows, можуть отримувати доступ до даних історії.
- Використовуйте спеціальні SQL-запити для отримання інформації про історію та завантаження.
- **bookmarkbackups**: містить резервні копії закладок.
- **formhistory.sqlite**: зберігає дані вебформ.
- **handlers.json**: керує обробниками протоколів.
- **persdict.dat**: слова користувацького словника.
- **addons.json** та **extensions.sqlite**: інформація про встановлені add-ons та extensions.
- **cookies.sqlite**: сховище cookie; для перевірки у Windows доступний [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** або **startupCache**: дані кешу, доступні через такі інструменти, як [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: зберігає favicons.
- **prefs.js**: налаштування та параметри користувача.
- **downloads.sqlite**: стара база даних завантажень, тепер інтегрована в places.sqlite.
- **thumbnails**: мініатюри вебсайтів.
- **logins.json**: зашифрована інформація для входу.
- **key4.db** або **key3.db**: зберігає ключі шифрування для захисту конфіденційної інформації.

Крім того, перевірити налаштування браузера для захисту від phishing можна, виконавши пошук записів `browser.safebrowsing` у `prefs.js`, що дає змогу визначити, чи ввімкнено або вимкнено функції безпечного перегляду.<sup>[[2]](#references)</sup>

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

Google Chrome зберігає профілі користувачів у певних місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

У цих каталогах більшість даних користувача можна знайти в папках **Default/** або **ChromeDefaultData/**. Важливі дані містяться в таких файлах:<sup>[[1]](#references)</sup>

- **History**: Містить URL-адреси, завантаження та пошукові ключові слова. У Windows для читання історії можна використовувати [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Стовпець "Transition Type" має різні значення, зокрема кліки користувача на посиланнях, введені URL-адреси, надсилання форм і перезавантаження сторінок.
- **Cookies**: Зберігає cookies. Для перевірки доступний [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Містить кешовані дані. Для перевірки користувачі Windows можуть скористатися [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Desktop apps на основі Electron (наприклад, Discord) також використовують Chromium Simple Cache і залишають значні артефакти на диску. Дивіться:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Закладки користувача.
- **Web Data**: Містить історію форм.
- **Favicons**: Зберігає favicons вебсайтів.
- **Login Data**: Містить облікові дані для входу, зокрема імена користувачів і паролі.
- **Current Session**/**Current Tabs**: Дані про поточний сеанс перегляду та відкриті вкладки.
- **Last Session**/**Last Tabs**: Інформація про сайти, активні під час останнього сеансу перед закриттям Chrome.
- **Extensions**: Каталоги browser extensions і addons.
- **Thumbnails**: Зберігає мініатюри вебсайтів.
- **Preferences**: Файл із великою кількістю інформації, зокрема налаштуваннями plugins, extensions, pop-ups, notifications та іншими параметрами.
- **Browser’s built-in anti-phishing**: Щоб перевірити, чи ввімкнено anti-phishing і захист від malware, виконайте `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. У результаті знайдіть `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Як можна побачити в попередніх розділах, Chrome і Firefox використовують бази даних **SQLite** для зберігання даних. **Відновити видалені записи можна за допомогою інструмента** [**sqlparse**](https://github.com/padfoot999/sqlparse) **або** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 керує своїми даними та metadata у різних місцях, що допомагає відокремлювати збережену інформацію від відповідних відомостей для зручного доступу й керування.

### Зберігання metadata

Metadata для Internet Explorer зберігаються в `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (де VX може бути V01, V16 або V24). Файл `V01.log` може містити час модифікації, що не збігається з `WebcacheVX.data`, що вказує на потребу відновлення за допомогою `esentutl /r V01 /d`. Ці metadata, що зберігаються в ESE database, можна відновити й перевірити за допомогою таких інструментів, як photorec і [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), відповідно. У таблиці **Containers** можна визначити конкретні таблиці або контейнери, у яких зберігається кожен сегмент даних, зокрема відомості про cache для інших Microsoft tools, таких як Skype.

### Перевірка cache

Інструмент [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) дає змогу перевіряти cache; для цього потрібно вказати розташування папки вилучення cache data. Metadata cache містять ім’я файлу, каталог, кількість доступів, походження URL і часові позначки створення, доступу, модифікації та завершення терміну дії cache.

### Керування cookies

Cookies можна переглядати за допомогою [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Metadata охоплюють імена, URL, кількість доступів і різні часові відомості. Постійні cookies зберігаються в `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, а session cookies перебувають у пам’яті.

### Відомості про завантаження

Metadata завантажень доступні через [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); окремі контейнери містять такі дані, як URL, тип файлу та місце завантаження. Фізичні файли можна знайти в `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Історія перегляду

Для перегляду історії перегляду можна використовувати [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html); для цього потрібно вказати розташування вилучених файлів історії та налаштувати Internet Explorer. Metadata містять час модифікації й доступу, а також кількість доступів. Файли історії розташовані в `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Введені URL-адреси

Введені URL-адреси та час їх використання зберігаються в registry у `NTUSER.DAT` за адресами `Software\Microsoft\InternetExplorer\TypedURLs` і `Software\Microsoft\InternetExplorer\TypedURLsTime`. Вони містять останні 50 URL-адрес, введених користувачем, і час їх останнього введення.

## Microsoft Edge

Microsoft Edge зберігає дані користувача в `%userprofile%\Appdata\Local\Packages`. Шляхи до різних типів даних:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Дані Safari зберігаються в `/Users/$User/Library/Safari`. Основні файли:<sup>[[3]](#references)</sup>

- **History.db**: Містить таблиці `history_visits` і `history_items` з URL-адресами та часовими позначками відвідувань. Для запитів використовуйте `sqlite3`.
- **Downloads.plist**: Інформація про завантажені файли.
- **Bookmarks.plist**: Зберігає URL-адреси закладок.
- **TopSites.plist**: Найчастіше відвідувані сайти.
- **Extensions.plist**: Список browser extensions Safari. Для отримання даних використовуйте `plutil` або `pluginkit`.
- **UserNotificationPermissions.plist**: Домени, яким дозволено надсилати push notifications. Для аналізу використовуйте `plutil`.
- **LastSession.plist**: Вкладки з останнього сеансу. Для аналізу використовуйте `plutil`.
- **Browser’s built-in anti-phishing**: Перевірте за допомогою `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Відповідь 1 означає, що функцію активовано.<sup>[[2]](#references)</sup>

## Opera

Дані Opera зберігаються в `/Users/$USER/Library/Application Support/com.operasoftware.Opera` і використовують той самий формат, що й Chrome, для history та downloads.

- **Browser’s built-in anti-phishing**: Перевірте, чи має `fraud_protection_enabled` у файлі Preferences значення `true`, за допомогою `grep`.<sup>[[2]](#references)</sup>

Ці шляхи та команди важливі для доступу до даних перегляду, що зберігаються різними web browsers, і їх розуміння.

## References

- [1] [Forensics web browsers: посібник із проведення forensic analysis web browsers](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Incident Response у macOS | Частина 3: Маніпуляції системою](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Incident Response в OS X: Scripting і Analysis, автор Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
