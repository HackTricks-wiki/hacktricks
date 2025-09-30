# Артефакти браузера

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

Артефакти браузера включають різні типи даних, які зберігають веб-браузери, такі як історія переходів, закладки та кеш. Ці артефакти зберігаються у специфічних папках в операційній системі, відрізняючись за розташуванням і назвою між браузерами, але зазвичай містять схожі типи даних.

Короткий опис найпоширеніших артефактів браузера:

- **Navigation History**: Слідкує за відвідинами користувачем вебсайтів, корисно для ідентифікації переходів на зловмисні сайти.
- **Autocomplete Data**: Пропозиції на основі частих пошукових запитів, дають додаткову інформацію при комбінуванні з історією переходів.
- **Bookmarks**: Сайти, збережені користувачем для швидкого доступу.
- **Extensions and Add-ons**: Розширення або додатки, встановлені користувачем.
- **Cache**: Зберігає веб-контент (наприклад, зображення, JavaScript-файли) для пришвидшення завантаження сторінок, цінний для судово-медичного аналізу.
- **Logins**: Збережені облікові дані.
- **Favicons**: Іконки, пов’язані з вебсайтами, що з’являються у вкладках і закладках, корисні для додаткової інформації про відвідини.
- **Browser Sessions**: Дані, пов’язані з відкритими сесіями браузера.
- **Downloads**: Записи про файли, завантажені через браузер.
- **Form Data**: Інформація, введена у веб-форми, збережена для автозаповнення в майбутньому.
- **Thumbnails**: Зображення-прев’ю сайтів.
- **Custom Dictionary.txt**: Слова, додані користувачем у словник браузера.

## Firefox

Firefox організовує дані користувача в профілях, що зберігаються в певних місцях залежно від операційної системи:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles/`

Файл `profiles.ini` в цих директоріях перераховує профілі користувача. Дані кожного профілю зберігаються в папці, вказаній у змінній `Path` всередині `profiles.ini`, яка знаходиться в тій самій директорії, що й `profiles.ini`. Якщо папка профілю відсутня, можливо її було видалено.

У кожній папці профілю можна знайти кілька важливих файлів:

- **places.sqlite**: Зберігає історію, закладки та завантаження. Інструменти на кшталт [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) на Windows можуть отримати доступ до даних історії.
- Використовуйте специфічні SQL-запити для витягання інформації про історію та завантаження.
- **bookmarkbackups**: Містить резервні копії закладок.
- **formhistory.sqlite**: Зберігає дані веб-форм.
- **handlers.json**: Керує обробниками протоколів.
- **persdict.dat**: Слова з користувацького словника.
- **addons.json** та **extensions.sqlite**: Інформація про встановлені аддони та розширення.
- **cookies.sqlite**: Зберігання cookie; для перегляду на Windows доступний [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** або **startupCache**: Дані кешу, доступні через інструменти на кшталт [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Зберігає favicons.
- **prefs.js**: Налаштування та переваги користувача.
- **downloads.sqlite**: Стара база даних завантажень, тепер інтегрована в places.sqlite.
- **thumbnails**: Ескізи сайтів.
- **logins.json**: Зашифровані дані входу.
- **key4.db** або **key3.db**: Зберігає ключі шифрування для захисту конфіденційної інформації.

Також перевірка налаштувань антифішингу браузера може бути здійснена пошуком записів `browser.safebrowsing` у `prefs.js`, що вказує, чи увімкнені або вимкнені функції безпечного перегляду.

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
With the following script and call you can specify a password file to brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome зберігає профілі користувачів у певних місцях залежно від операційної системи:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

У цих директоріях більшість даних користувача знаходяться в папках **Default/** або **ChromeDefaultData/**. Наступні файли містять важливу інформацію:

- **History**: Містить URL, завантаження та ключові слова пошуку. У Windows для читання history можна використати [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Стовпець "Transition Type" має різні значення, включаючи кліки користувача по посиланнях, введені URL, відправку форм і перезавантаження сторінки.
- **Cookies**: Зберігає cookies. Для перегляду доступний [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Містить кешовані дані. Для огляду користувачі Windows можуть використати [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Electron-based desktop apps (e.g., Discord) також використовують Chromium Simple Cache і залишають багаті артефакти на диску. Див.:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Закладки користувача.
- **Web Data**: Містить історію форм.
- **Favicons**: Зберігає favicon сайтів.
- **Login Data**: Містить облікові дані для входу, такі як імена користувачів і паролі.
- **Current Session**/**Current Tabs**: Дані про поточну сесію браузера та відкриті вкладки.
- **Last Session**/**Last Tabs**: Інформація про сайти, активні під час останньої сесії перед закриттям Chrome.
- **Extensions**: Директорії для розширень і додатків браузера.
- **Thumbnails**: Зберігає мініатюри сайтів.
- **Preferences**: Файл, багатий на інформацію, включаючи налаштування плагінів, розширень, спливаючих вікон, сповіщень тощо.
- **Browser’s built-in anti-phishing**: Щоб перевірити, чи увімкнено захист від фішингу та шкідливого ПЗ, виконайте `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Шукайте `{"enabled: true,"}` у виводі.

## **SQLite DB Data Recovery**

Як видно з попередніх розділів, і Chrome, і Firefox використовують **SQLite** бази даних для зберігання даних. Можна **відновити видалені записи за допомогою інструменту** [**sqlparse**](https://github.com/padfoot999/sqlparse) **або** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 керує своїми даними та метаданими в різних місцях, що дозволяє розділяти збережену інформацію та відповідні деталі для зручного доступу й управління.

### Metadata Storage

Метадані Internet Explorer зберігаються в `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (де VX — V01, V16 або V24). Додатково файл `V01.log` може показувати невідповідність часу модифікації з `WebcacheVX.data`, що вказує на необхідність ремонту за допомогою `esentutl /r V01 /d`. Ці метадані, які розміщені в ESE базі даних, можна відновити та проаналізувати за допомогою інструментів типу photorec і [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). У таблиці **Containers** можна визначити конкретні таблиці або контейнери, де зберігається кожен сегмент даних, включаючи деталі кешу для інших Microsoft-інструментів, таких як Skype.

### Cache Inspection

Інструмент [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) дозволяє оглядати кеш, вимагаючи вказати папку з витягнутими даними кешу. Метадані кешу включають ім’я файлу, директорію, лічильник доступів, URL-джерело та часові мітки створення, доступу, модифікації і терміну дії кешу.

### Cookies Management

Куки можна дослідити за допомогою [IECookiesView](https://www.nirsoft.net/utils/iecookies.html); метадані охоплюють імена, URL, лічильники доступів та різні часові деталі. Постійні куки зберігаються в `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, тоді як сесійні куки перебувають у пам’яті.

### Download Details

Метадані про завантаження доступні через [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), причому певні контейнери зберігають дані такі як URL, тип файлу і місце завантаження. Файли на диску можна знайти в `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Для перегляду історії браузера можна використати [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), вказавши місце витягнутих файлів історії і налаштувавши інструмент для Internet Explorer. Метадані включають часи модифікації й доступу, а також лічильники доступів. Файли історії розташовані в `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Введені URL та часи їх використання зберігаються в реєстрі в NTUSER.DAT за шляхами `Software\Microsoft\InternetExplorer\TypedURLs` та `Software\Microsoft\InternetExplorer\TypedURLsTime`, відстежуючи останні 50 URL, введених користувачем, та часи їхнього останнього вводу.

## Microsoft Edge

Microsoft Edge зберігає дані користувача в `%userprofile%\Appdata\Local\Packages`. Шляхи до різних типів даних:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Дані Safari зберігаються в `/Users/$User/Library/Safari`. Ключові файли включають:

- **History.db**: Містить таблиці `history_visits` і `history_items` з URL та часовими мітками відвідувань. Використовуйте `sqlite3` для запитів.
- **Downloads.plist**: Інформація про завантажені файли.
- **Bookmarks.plist**: Збережені закладки.
- **TopSites.plist**: Найчастіше відвідувані сайти.
- **Extensions.plist**: Список розширень Safari. Використовуйте `plutil` або `pluginkit` для отримання інформації.
- **UserNotificationPermissions.plist**: Домени, яким дозволено надсилати сповіщення. Використовуйте `plutil` для парсингу.
- **LastSession.plist**: Вкладки з останньої сесії. Використовуйте `plutil` для парсингу.
- **Browser’s built-in anti-phishing**: Перевірте за допомогою `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Відповідь 1 означає, що функція активна.

## Opera

Дані Opera розташовані в `/Users/$USER/Library/Application Support/com.operasoftware.Opera` і мають формат історії та завантажень, подібний до Chrome.

- **Browser’s built-in anti-phishing**: Переконайтеся, що `fraud_protection_enabled` у файлі Preferences встановлено в `true`, використовуючи `grep`.

Ці шляхи та команди є ключовими для доступу та розуміння даних перегляду, що зберігаються різними веб-браузерами.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
