# Захист macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper зазвичай використовують для позначення поєднання **Quarantine + Gatekeeper + XProtect** — 3 модулів безпеки macOS, які намагаються **перешкодити користувачам виконувати потенційно шкідливе програмне забезпечення, завантажене з Інтернету**.

Додаткова інформація:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Обмеження процесів

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Sandbox macOS **обмежує застосунки**, що працюють усередині sandbox, **дозволеними діями, визначеними в Sandbox profile**, з яким запускається застосунок. Це допомагає гарантувати, що **застосунок отримуватиме доступ лише до очікуваних ресурсів**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** — це security framework. Він призначений для **керування дозволами** застосунків, зокрема шляхом регулювання їхнього доступу до чутливих функцій. Сюди належать такі елементи, як **служби геолокації, контакти, фотографії, мікрофон, камера, accessibility і повний доступ до диска**. TCC гарантує, що застосунки можуть отримати доступ до цих функцій лише після явної згоди користувача, посилюючи таким чином приватність і контроль над персональними даними.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints у macOS — це функція безпеки для **регулювання ініціації процесів** шляхом визначення того, **хто може запустити** процес, **як** і **звідки**. Представлені в macOS Ventura, вони класифікують системні binary у категорії обмежень усередині **trust cache**. Кожен executable binary має набір **правил** для свого **запуску**, зокрема обмеження **self**, **parent** і **responsible**. У macOS Sonoma ці функції були поширені на сторонні застосунки як **Environment Constraints**. Вони допомагають пом’якшити потенційні system exploitations, регулюючи умови запуску процесів.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) — ще одна частина security infrastructure macOS. Як випливає з назви, основна функція MRT — **видаляти відоме malware із заражених систем**.

Після виявлення malware на Mac (XProtect або іншим способом) MRT можна використовувати для автоматичного **видалення malware**. MRT непомітно працює у фоні й зазвичай запускається під час оновлення системи або завантаження нових malware definitions (схоже, правила, за якими MRT виявляє malware, містяться всередині binary).

Хоча XProtect і MRT є частинами заходів безпеки macOS, вони виконують різні функції:

- **XProtect** — preventative tool. Він **перевіряє файли під час їхнього завантаження** (через певні застосунки), і якщо виявляє відомі типи malware, **перешкоджає відкриттю файлу**, не даючи malware заразити систему.
- **MRT**, зі свого боку, — **reactive tool**. Він працює після виявлення malware у системі, маючи на меті видалити шкідливе програмне забезпечення та очистити систему.

Застосунок MRT розташований у **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Керування фоновими завданнями

**macOS** тепер **показує сповіщення** щоразу, коли інструмент використовує відому **техніку для забезпечення persistence виконання коду** (наприклад, Login Items, Daemons...), щоб користувач краще розумів, **яке програмне забезпечення забезпечує persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Це працює за допомогою **daemon**, розташованого в `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`, і **agent** у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** визначає, що щось встановлено в persistent folder, шляхом **отримання FSEvents** і створення певних **handlers** для них.<sup>[[1]](#references)</sup>

Крім того, існує plist-файл із переліком **добре відомих застосунків**, які часто забезпечують persistence; його підтримує Apple, і він розташований у: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Перерахування

Можна **перерахувати всі** налаштовані фонові елементи за допомогою cli-інструмента Apple:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Крім того, цю інформацію також можна отримати за допомогою [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ця інформація зберігається у **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, а Terminal потребує FDA.<sup>[[2]](#references)</sup>

### Втручання в BTM

Коли виявляється новий persistence, генерується подія типу **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Отже, будь-який спосіб **перешкодити** надсиланню цієї **події** або **сповістити** користувача через **agent** допоможе зловмиснику _**обійти**_ BTM.<sup>[[1]](#references)</sup>

- **Скидання бази даних**: виконання наведеної нижче команди скидає базу даних (яку має бути перебудовано з нуля). Однак після цього **нові сповіщення про persistence не з’являються, доки систему не буде перезавантажено**.<sup>[[1]](#references)</sup>
- Потрібні права **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Зупинка Agent**: Можна надіслати Agent сигнал зупинки, щоб він **не сповіщав користувача**, коли виявляються нові події.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Якщо **процес, який створив persistence, одразу після цього завершується**, daemon намагається **отримати інформацію** про нього, **зазнає невдачі** й **не може надіслати подію**, яка вказує, що новий елемент зберігається.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: «Розвінчання міфів про керування фоновими завданнями macOS (і його обхід)» - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Новий інструмент для розробників: «DumpBTM» - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Керування елементами входу та фоновими завданнями на Mac - розгортання платформ Apple](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
