# Артефакти браузера

{{#include ../../../banners/hacktricks-training.md}}

## Артефакти браузерів <a href="#id-3def" id="id-3def"></a>

Артефакти браузера охоплюють різні типи даних, що зберігаються веббраузерами, як-от історія навігації, закладки та дані кешу. Ці артефакти містяться у визначених папках операційної системи. Їхнє розташування та назви відрізняються залежно від браузера, але зазвичай у них зберігаються однакові типи даних.

Ось короткий огляд найпоширеніших артефактів браузера:

- **Історія навігації**: відстежує відвідування користувачем вебсайтів і допомагає виявляти переходи на шкідливі сайти.
- **Дані автозаповнення**: пропозиції на основі частих пошукових запитів, які в поєднанні з історією навігації можуть дати корисну інформацію.
- **Закладки**: сайти, збережені користувачем для швидкого доступу.
- **Розширення та додатки**: розширення браузера або додатки, встановлені користувачем.
- **Кеш**: зберігає вебконтент (наприклад, зображення та файли JavaScript), щоб пришвидшити завантаження сайтів, і є цінним джерелом для forensic analysis.
- **Дані входу**: збережені облікові дані.
- **Фавікони**: значки вебсайтів, що відображаються на вкладках і в закладках та можуть надати додаткову інформацію про відвідування користувача.
- **Сеанси браузера**: дані про відкриті сеанси браузера.
- **Завантаження**: записи про файли, завантажені через браузер.
- **Дані форм**: інформація, введена у вебформи й збережена для майбутніх пропозицій автозаповнення.
- **Ескізи**: зображення попереднього перегляду вебсайтів.
- **Custom Dictionary.txt**: слова, додані користувачем до словника браузера.

## Firefox

Firefox зберігає дані користувача в профілях, розташованих у різних місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Файл `profiles.ini` у цих каталогах містить перелік профілів користувачів. Дані кожного профілю зберігаються в папці, назва якої вказана у змінній `Path` файлу `profiles.ini`. Ця папка розташована в тому самому каталозі, що й сам файл `profiles.ini`. Якщо папки профілю немає, можливо, її видалили.

У кожній папці профілю можна знайти кілька важливих файлів:<sup>[[1]](#references)</sup>

- **places.sqlite**: зберігає історію, закладки та завантаження. У Windows доступ до даних історії можна отримати за допомогою інструментів на кшталт [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html).
  - Використовуйте спеціальні SQL-запити, щоб отримати дані про історію та завантаження.
- **bookmarkbackups**: містить резервні копії закладок.
- **formhistory.sqlite**: зберігає дані вебформ.
- **handlers.json**: керує обробниками протоколів.
- **persdict.dat**: містить слова користувацького словника.
- **addons.json** і **extensions.sqlite**: містять інформацію про встановлені додатки та розширення.
- **cookies.sqlite**: сховище cookies; у Windows для їх перегляду доступний [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** або **startupCache**: дані кешу, доступні через такі інструменти, як [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: зберігає фавікони.
- **prefs.js**: налаштування та параметри користувача.
- **downloads.sqlite**: застаріла база даних завантажень, тепер інтегрована в places.sqlite.
- **thumbnails**: ескізи вебсайтів.
- **logins.json**: зашифрована інформація для входу.
- **key4.db** або **key3.db**: зберігає ключі шифрування для захисту конфіденційної інформації.

Крім того, перевірити налаштування браузера для захисту від фішингу можна, знайшовши записи `browser.safebrowsing` у `prefs.js`. Вони вказують, чи ввімкнено функції безпечного перегляду.<sup>[[2]](#references)</sup>

Щоб розшифрувати збережені дані для входу з доступного профілю, потрібно надати або окремо відновити [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), якщо її налаштовано; у профілі цей пароль не зберігається. Переконайтеся, що відновлені облікові дані дають змогу ввійти у відповідний вебобліковий запис. Для доступу root у Unix потрібне окреме підтвердження того, що ці облікові дані також приймаються для автентифікації root у Unix. Переглянути збережені дані для входу можна за допомогою [firefox_decrypt](https://github.com/unode/firefox_decrypt). У наведеному нижче прикладі перевіряються можливі паролі Primary Password із файлу паролів:

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

Google Chrome зберігає профілі користувачів у визначених місцях залежно від операційної системи:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

У цих каталогах більшість даних користувача можна знайти в папках **Default/** або **ChromeDefaultData/**. У наведених нижче файлах містяться важливі дані:<sup>[[1]](#references)</sup>

- **History**: містить URL-адреси, завантаження та пошукові запити. У Windows для перегляду історії можна скористатися [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html). Стовпець "Transition Type" має різні значення, зокрема клацання користувачем посилань, введення URL-адрес, надсилання форм і перезавантаження сторінок.
- **Cookies**: зберігає cookies. Для перегляду можна скористатися [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: містить кешовані дані. Користувачі Windows можуть переглянути їх за допомогою [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Настільні застосунки на основі Electron (наприклад, Discord) також використовують Chromium Simple Cache і залишають багато артефактів на диску. Див.:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: закладки користувача.
- **Web Data**: містить історію заповнення форм.
- **Favicons**: зберігає favicon вебсайтів.
- **Login Data**: містить облікові дані для входу, як-от імена користувачів і паролі.
- **Current Session**/**Current Tabs**: дані про поточний сеанс перегляду та відкриті вкладки.
- **Last Session**/**Last Tabs**: інформація про сайти, відкриті під час останнього сеансу перед закриттям Chrome.
- **Extensions**: каталоги розширень і доповнень браузера.
- **Thumbnails**: зберігає мініатюри вебсайтів.
- **Preferences**: файл із великою кількістю інформації, зокрема налаштуваннями плагінів, розширень, спливних вікон, сповіщень тощо.
- **Вбудований у браузер захист від фішингу**: щоб перевірити, чи ввімкнено захист від фішингу та шкідливого ПЗ, виконайте `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Знайдіть у виводі `{"enabled: true,"}`.<sup>[[2]](#references)</sup>

Каталог `Local Extension Settings/<extension-id>/` у профілі Chromium може містити локальний стан розширення, зокрема ключовий матеріал менеджера паролів. Наприклад, [Passbolt повідомляє, що його зашифрований приватний ключ зберігається в локальному сховищі браузерного розширення](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), а його [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) дає змогу визначити відповідний каталог. Сама наявність каталогу не доводить, що ключ там є, і не розблоковує сховище: користувач повинен мати доступ до даних профілю, придатний приватний ключ і парольну фразу, а також авторизований шлях відновлення або автентифікації на сервері. Для елемента сховища, що містить пароль облікового запису операційної системи, потрібна окрема перевірка повторного використання облікових даних. Під час звичайного переліку слід указувати лише шлях до сховища, не виводячи файли LevelDB або секретні значення.

## **Відновлення даних SQLite DB**

Як можна побачити в попередніх розділах, Chrome і Firefox використовують бази даних **SQLite** для зберігання даних. **Видалені записи можна відновити за допомогою інструмента** [**sqlparse**](https://github.com/padfoot999/sqlparse) **або** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 зберігає свої дані та метадані в різних місцях, що допомагає розділити збережену інформацію та пов’язані з нею відомості для зручного доступу й керування.

### Зберігання метаданих

Метадані Internet Explorer зберігаються в `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (де VX — це V01, V16 або V24). Файл `V01.log` поруч може мати час модифікації, що не збігається з часом у `WebcacheVX.data`, і це може свідчити про необхідність відновлення за допомогою `esentutl /r V01 /d`. Ці метадані, що зберігаються в базі даних ESE, можна відновити та переглянути за допомогою таких інструментів, як photorec і [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), відповідно. У таблиці **Containers** можна визначити конкретні таблиці або контейнери, де зберігається кожен сегмент даних, зокрема дані кешу інших інструментів Microsoft, наприклад Skype.

### Перегляд кешу

Інструмент [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) дає змогу переглядати кеш; для цього потрібно вказати каталог, до якого витягнуто дані кешу. Метадані кешу містять ім’я файлу, каталог, кількість доступів, вихідну URL-адресу та часові позначки створення, доступу, модифікації й завершення строку дії кешу.

### Керування cookies

Cookies можна переглянути за допомогою [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Метадані містять імена, URL-адреси, кількість доступів та різні часові дані. Постійні cookies зберігаються в `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, а сеансові cookies — у пам’яті.

### Відомості про завантаження

Метадані завантажень доступні через [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); окремі контейнери містять такі дані, як URL-адреса, тип файлу та місце завантаження. Фізичні файли можна знайти в `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Історія перегляду

Для перегляду історії можна скористатися [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), указавши розташування витягнутих файлів історії та налаштувавши Internet Explorer. Ці метадані містять час модифікації та доступу, а також кількість доступів. Файли історії розташовані в `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Введені URL-адреси

Введені URL-адреси та час їх використання зберігаються в реєстрі у `NTUSER.DAT` за шляхами `Software\Microsoft\InternetExplorer\TypedURLs` і `Software\Microsoft\InternetExplorer\TypedURLsTime`. Там відстежуються останні 50 URL-адрес, введених користувачем, і час їх останнього введення.

## Microsoft Edge

Microsoft Edge зберігає дані користувача в `%userprofile%\Appdata\Local\Packages`. Шляхи до різних типів даних:<sup>[[1]](#references)</sup>

- **Шлях до профілю**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Історія, cookies і завантаження**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Налаштування, закладки та список для читання**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Кеш**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Останні активні сеанси**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Дані Safari зберігаються в `/Users/$User/Library/Safari`. Важливі файли:<sup>[[3]](#references)</sup>

- **History.db**: містить таблиці `history_visits` і `history_items` з URL-адресами та часовими позначками відвідувань. Для запитів використовуйте `sqlite3`.
- **Downloads.plist**: інформація про завантажені файли.
- **Bookmarks.plist**: зберігає URL-адреси закладок.
- **TopSites.plist**: найчастіше відвідувані сайти.
- **Extensions.plist**: список розширень браузера Safari. Щоб отримати його, скористайтеся `plutil` або `pluginkit`.
- **UserNotificationPermissions.plist**: домени, яким дозволено надсилати push-сповіщення. Для аналізу скористайтеся `plutil`.
- **LastSession.plist**: вкладки з останнього сеансу. Для аналізу скористайтеся `plutil`.
- **Вбудований у браузер захист від фішингу**: перевірте за допомогою `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Відповідь `1` означає, що функцію ввімкнено.<sup>[[2]](#references)</sup>

## Opera

Дані Opera зберігаються в `/Users/$USER/Library/Application Support/com.operasoftware.Opera`; для історії та завантажень використовується формат Chrome.

- **Вбудований у браузер захист від фішингу**: перевірте за допомогою `grep`, чи має параметр `fraud_protection_enabled` у файлі Preferences значення `true`.<sup>[[2]](#references)</sup>

Ці шляхи та команди важливі для доступу до даних перегляду, збережених різними веббраузерами, і розуміння їхнього вмісту.

## References

- [1] [Криміналістичний аналіз веббраузерів: посібник з аналізу веббраузерів](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Реагування на інциденти в macOS | Частина 3: маніпуляції системою](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Реагування на інциденти в OS X: скрипти та аналіз, автор Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
