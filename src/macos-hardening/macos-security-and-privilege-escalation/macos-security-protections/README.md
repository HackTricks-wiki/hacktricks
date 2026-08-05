# Захист macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper зазвичай використовують для позначення поєднання **Quarantine + Gatekeeper + XProtect** — 3 модулів безпеки macOS, які намагаються **не допустити запуск потенційно шкідливого програмного забезпечення, завантаженого користувачами**.

Більше інформації:


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

MacOS Sandbox **обмежує застосунки**, що працюють усередині sandbox, **дозволеними діями, визначеними в профілі Sandbox**, з яким працює застосунок. Це допомагає гарантувати, що **застосунок матиме доступ лише до очікуваних ресурсів**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** — це фреймворк безпеки. Він призначений для **керування дозволами** застосунків, зокрема шляхом регулювання їхнього доступу до чутливих функцій. До них належать такі елементи, як **служби геолокації, контакти, фотографії, мікрофон, камера, accessibility і повний доступ до диска**. TCC гарантує, що застосунки можуть отримати доступ до цих функцій лише після явної згоди користувача, посилюючи таким чином конфіденційність і контроль над персональними даними.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints у macOS — це функція безпеки для **регулювання запуску процесів** шляхом визначення **того, хто може запустити** процес, **як** і **звідки**. Запроваджені в macOS Ventura, вони розподіляють системні binary-файли за категоріями обмежень у межах **trust cache**. Кожен executable binary має набір **правил** для свого **запуску**, включно з обмеженнями **self**, **parent** і **responsible**. У macOS Sonoma ці функції були поширені на сторонні застосунки як **Environment Constraints** і допомагають зменшити ризик потенційної експлуатації системи, регулюючи умови запуску процесів.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) — ще одна складова інфраструктури безпеки macOS. Як випливає з назви, основна функція MRT — **видалення відомого malware із заражених систем**.

Після виявлення malware на Mac (за допомогою XProtect або іншим способом) MRT можна використовувати для автоматичного **видалення malware**. MRT непомітно працює у фоновому режимі й зазвичай запускається під час оновлення системи або завантаження нового визначення malware (схоже, що правила, за якими MRT виявляє malware, містяться всередині binary-файлу).

Хоча XProtect і MRT є складовими заходів безпеки macOS, вони виконують різні функції:

- **XProtect** — це превентивний інструмент. Він **перевіряє файли під час їх завантаження** (через певні застосунки) і, якщо виявляє будь-які відомі типи malware, **не дозволяє відкрити файл**, запобігаючи зараженню системи malware.
- **MRT**, навпаки, — це **реактивний інструмент**. Він працює після виявлення malware у системі, маючи на меті видалити шкідливе програмне забезпечення та очистити систему.

Застосунок MRT розташований у **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Керування фоновими завданнями

**macOS** тепер **сповіщає** щоразу, коли інструмент використовує добре відому **техніку для збереження виконання коду** (наприклад, Login Items, Daemons...), щоб користувач краще розумів, **яке програмне забезпечення зберігає persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Це працює за допомогою **daemon**, розташованого в `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`, і **agent** у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** визначає, що щось встановлено в persistent-папці, шляхом **отримання FSEvents** і створення відповідних **handlers**.<sup>[[1]](#references)</sup>

Крім того, існує plist-файл із переліком **добре відомих застосунків**, які часто забезпечують persistence; Apple підтримує цей файл, розташований у: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>.
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

Можна **перерахувати всі** налаштовані фонові елементи за допомогою інструмента Apple cli:<sup>[[3]](#references)</sup>
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
Ця інформація зберігається в **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, а Terminal потребує FDA.<sup>[[2]](#references)</sup>

### Втручання в BTM

Коли виявляється нова persistence, генерується подія типу **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Отже, будь-який спосіб **перешкодити** надсиланню цієї **події** або **сповіщенню користувача агентом** допоможе attacker _**обійти**_ BTM.<sup>[[1]](#references)</sup>

- **Скидання бази даних**: виконання наведеної нижче команди скине базу даних (система має перебудувати її з нуля), однак з певної причини після цього про **нову persistence** не надходитимуть сповіщення, доки систему не буде перезавантажено.<sup>[[1]](#references)</sup>
- Потрібен **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Зупинка агента**: Можна надіслати агенту сигнал зупинки, щоб він **не сповіщав користувача** про виявлення нових загроз.<sup>[[1]](#references)</sup>
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
- **Bug**: Якщо **процес, який створив persistence, швидко завершує роботу одразу після цього**, daemon спробує **отримати інформацію** про нього, **зазнає невдачі** й **не зможе надіслати подію**, яка вказує, що новий об'єкт забезпечує persistence.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
