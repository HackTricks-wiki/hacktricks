# Артефакти браузера

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти браузерів <a href="#id-3def" id="id-3def"></a>

Артефакти браузера охоплюють різні типи даних, які зберігаються веббраузерами, як-от історія навігації, закладки та дані кешу. Ці артефакти зберігаються в окремих папках операційної системи. Їхнє розташування та назви відрізняються залежно від браузера, однак зазвичай вони містять подібні типи даних.

Нижче наведено найпоширеніші артефакти браузера:

- **Історія навігації**: відстежує відвідування користувачем вебсайтів і допомагає виявити відвідування шкідливих сайтів.
- **Дані автозаповнення**: пропозиції на основі частих пошукових запитів, які разом з історією навігації дають змогу отримати додаткову інформацію.
- **Закладки**: сайти, збережені користувачем для швидкого доступу.
- **Розширення та доповнення**: встановлені користувачем розширення або доповнення браузера.
- **Кеш**: зберігає вебвміст (наприклад, зображення та файли JavaScript), щоб пришвидшити завантаження вебсайтів; має цінність для forensic analysis.
- **Облікові дані**: збережені облікові дані для входу.
- **Фавікони**: піктограми вебсайтів, що відображаються на вкладках і в закладках та надають додаткову інформацію про відвідування користувача.
- **Сеанси браузера**: дані про відкриті сеанси браузера.
- **Завантаження**: записи про файли, завантажені через браузер.
- **Дані форм**: інформація, введена у вебформи та збережена для майбутніх пропозицій автозаповнення.
- **Мініатюри**: зображення попереднього перегляду вебсайтів.
- **Custom Dictionary.txt**: слова, додані користувачем до словника браузера.

## Firefox

Firefox зберігає дані користувача в профілях, розташованих у різних місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Файл `profiles.ini` у цих каталогах містить перелік профілів користувача. Дані кожного профілю зберігаються в папці, назва якої вказана у змінній `Path` у файлі `profiles.ini`. Ця папка розташована в тому самому каталозі, що й сам файл `profiles.ini`. Якщо папка профілю відсутня, можливо, її було видалено.

У папці кожного профілю можна знайти кілька важливих файлів:<sup>[[1]](#references)</sup>

- **places.sqlite**: зберігає історію, закладки та завантаження. У Windows отримати доступ до даних історії можна за допомогою таких інструментів, як [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html).
  - Використовуйте спеціальні SQL-запити, щоб отримати інформацію про історію та завантаження.
- **bookmarkbackups**: містить резервні копії закладок.
- **formhistory.sqlite**: зберігає дані вебформ.
- **handlers.json**: керує обробниками протоколів.
- **persdict.dat**: слова з користувацького словника.
- **addons.json** та **extensions.sqlite**: інформація про встановлені доповнення та розширення.
- **cookies.sqlite**: сховище cookie-файлів; у Windows їх можна переглядати за допомогою [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** або **startupCache**: дані кешу, доступні через такі інструменти, як [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: зберігає фавікони.
- **prefs.js**: налаштування та параметри користувача.
- **downloads.sqlite**: стара база даних завантажень, тепер інтегрована в places.sqlite.
- **thumbnails**: мініатюри вебсайтів.
- **logins.json**: зашифровані дані для входу.
- **key4.db** або **key3.db**: зберігає ключі шифрування, які захищають конфіденційну інформацію.

Крім того, налаштування захисту браузера від фішингу можна перевірити, знайшовши у файлі `prefs.js` записи `browser.safebrowsing`. Вони вказують, чи ввімкнено безпечний перегляд.<sup>[[2]](#references)</sup>

Щоб розшифрувати збережені дані для входу з доступного профілю, потрібно ввести або окремо відновити Основний пароль Firefox, якщо його було налаштовано: сам профіль не містить цього пароля. Переконайтеся, що відновлені дані для входу справді дають змогу автентифікуватися у відповідному вебобліковому записі. Для доступу root в Unix потрібне окреме підтвердження, що ці облікові дані також приймає механізм автентифікації Unix для root. Переглянути збережені дані для входу можна за допомогою [firefox_decrypt](https://github.com/unode/firefox_decrypt). У наведеному нижче прикладі перевіряються можливі варіанти Основного пароля з файлу паролів:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Артефакти браузерів — Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome зберігає профілі користувачів у певних місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

У цих каталогах більшість даних користувача можна знайти в папках **Default/** або **ChromeDefaultData/**. Значний обсяг даних містять такі файли:<sup>[[1]](#references)</sup>

- **History**: містить URL-адреси, завантаження та пошукові запити. У Windows для перегляду історії можна використовувати [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Стовпець «Transition Type» має різні значення, зокрема кліки користувача на посилання, введені URL-адреси, надсилання форм і перезавантаження сторінок.
- **Cookies**: зберігає cookies. Для перегляду доступний [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: містить кешовані дані. Для перегляду користувачі Windows можуть скористатися [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Настільні програми на основі Electron (наприклад, Discord) також використовують Chromium Simple Cache і залишають чимало артефактів на диску. Див.:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: закладки користувача.
- **Web Data**: містить історію заповнення форм.
- **Favicons**: зберігає favicon вебсайтів.
- **Login Data**: містить облікові дані для входу, як-от імена користувачів і паролі.
- **Current Session**/**Current Tabs**: дані про поточний сеанс перегляду та відкриті вкладки.
- **Last Session**/**Last Tabs**: інформація про сайти, активні під час останнього сеансу перед закриттям Chrome.
- **Extensions**: каталоги розширень і доповнень браузера.
- **Thumbnails**: зберігає мініатюри вебсайтів.
- **Preferences**: файл із великою кількістю інформації, зокрема налаштуваннями плагінів, розширень, спливних вікон, сповіщень тощо.
- **Вбудований у браузер захист від фішингу**: щоб перевірити, чи ввімкнено захист від фішингу та шкідливого ПЗ, виконайте `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Знайдіть у виведенні `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Каталог `Local Extension Settings/<extension-id>/` у профілі Chromium може містити локальний стан розширення, зокрема матеріал ключа менеджера паролів. Наприклад, [Passbolt повідомляє, що його зашифрований приватний ключ зберігається в локальному сховищі розширення браузера](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), а його [ідентифікатор розширення Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) дає змогу визначити відповідний каталог. Сама наявність каталогу не доводить, що в ньому є ключ, і не розблоковує сховище: користувач повинен мати доступ до даних профілю, придатний приватний ключ і парольну фразу, а також авторизований шлях відновлення/автентифікації на сервері. Для елемента сховища, що містить пароль облікового запису операційної системи, потрібно окремо перевірити повторне використання облікового запису. Під час звичайного переліку слід вказувати лише шлях до сховища, не вивантажуючи файли LevelDB чи секретні значення.

## **Відновлення даних SQLite DB**

Як видно з попередніх розділів, Chrome і Firefox використовують бази даних **SQLite** для зберігання даних. **Видалені записи можна відновити за допомогою інструмента** [**sqlparse**](https://github.com/padfoot999/sqlparse) **або** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 керує своїми даними та метаданими в різних місцях, що допомагає відокремлювати збережену інформацію від відповідних деталей для зручного доступу й керування.

### Зберігання метаданих

Метадані Internet Explorer зберігаються в `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (де VX — це V01, V16 або V24). Файл `V01.log` може мати час модифікації, що не збігається з часом у `WebcacheVX.data`, і вказувати на потребу відновлення за допомогою `esentutl /r V01 /d`. Ці метадані зберігаються в базі даних ESE; для їх відновлення та перегляду можна використовувати такі інструменти, як photorec і [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), відповідно. У таблиці **Containers** можна визначити конкретні таблиці або контейнери, де зберігається кожен сегмент даних, зокрема кеш інших інструментів Microsoft, як-от Skype.

### Перегляд кешу

Інструмент [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) дає змогу переглядати кеш; для цього потрібно вказати розташування папки з витягнутими даними кешу. Метадані кешу містять ім’я файлу, каталог, кількість доступів, вихідний URL і часові позначки створення, доступу, модифікації та завершення терміну дії кешу.

### Керування Cookies

Переглянути cookies можна за допомогою [IECookiesView](https://www.nirsoft.net/utils/iecookies.html); метадані містять назви, URL-адреси, кількість доступів і різні часові дані. Постійні cookies зберігаються в `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, а cookies сеансу — в пам’яті.

### Дані про завантаження

Метадані завантажень доступні через [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); у певних контейнерах зберігаються такі дані, як URL, тип файлу та місце завантаження. Фізичні файли можна знайти в `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Історія перегляду

Для перегляду історії браузера можна використовувати [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html); для цього потрібно вказати розташування витягнутих файлів історії та налаштувати інструмент для Internet Explorer. Метадані містять час модифікації та доступу, а також кількість доступів. Файли історії розташовані в `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Введені URL-адреси

Введені URL-адреси та час їх використання зберігаються в реєстрі у `NTUSER.DAT` за шляхами `Software\Microsoft\InternetExplorer\TypedURLs` і `Software\Microsoft\InternetExplorer\TypedURLsTime`. Там відстежуються останні 50 URL-адрес, введених користувачем, і час їх останнього введення.

## Microsoft Edge

Microsoft Edge зберігає дані користувача в `%userprofile%\Appdata\Local\Packages`. Шляхи до різних типів даних:<sup>[[1]](#references)</sup>

- **Шлях до профілю**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Історія, Cookies і завантаження**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Налаштування, закладки та список для читання**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Кеш**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Останні активні сеанси**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Дані Safari зберігаються в `/Users/$User/Library/Safari`. До ключових файлів належать:<sup>[[3]](#references)</sup>

- **History.db**: містить таблиці `history_visits` і `history_items` з URL-адресами та часовими позначками відвідувань. Для запитів використовуйте `sqlite3`.
- **Downloads.plist**: інформація про завантажені файли.
- **Bookmarks.plist**: зберігає URL-адреси закладок.
- **TopSites.plist**: сайти, які відвідують найчастіше.
- **Extensions.plist**: список розширень браузера Safari. Щоб отримати цей список, використовуйте `plutil` або `pluginkit`.
- **UserNotificationPermissions.plist**: домени, яким дозволено надсилати push-сповіщення. Для аналізу використовуйте `plutil`.
- **LastSession.plist**: вкладки з останнього сеансу. Для аналізу використовуйте `plutil`.
- **Вбудований у браузер захист від фішингу**: перевірте за допомогою `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Відповідь 1 означає, що функцію ввімкнено.<sup>[[2]](#references)</sup>

## Opera

Дані Opera зберігаються в `/Users/$USER/Library/Application Support/com.operasoftware.Opera`; формат історії та завантажень такий самий, як у Chrome.

- **Вбудований у браузер захист від фішингу**: перевірте за допомогою `grep`, чи має `fraud_protection_enabled` у файлі Preferences значення `true`.<sup>[[2]](#references)</sup>

Ці шляхи та команди важливі для доступу до даних перегляду, які зберігають різні веббраузери, і їх аналізу.

## References

- [1] [Комп’ютерна криміналістика веббраузерів: посібник з аналізу веббраузерів](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Реагування на інциденти в macOS | Частина 3: маніпуляції системою](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Реагування на інциденти в OS X: створення скриптів та аналіз, автор Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
