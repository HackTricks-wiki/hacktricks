# Захист macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper зазвичай використовується для позначення комбінації **Quarantine + Gatekeeper + XProtect** — 3 модулів безпеки macOS, які намагаються **не дозволити користувачам виконувати потенційно шкідливе програмне забезпечення, завантажене з мережі**.

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

Sandbox macOS **обмежує застосунки**, що працюють усередині sandbox, **дозволеними діями, визначеними в профілі Sandbox**, з яким працює застосунок. Це допомагає гарантувати, що **застосунок отримуватиме доступ лише до очікуваних ресурсів**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** — це security framework. Він призначений для **керування дозволами** застосунків, зокрема регулювання їхнього доступу до чутливих функцій. Сюди належать такі елементи, як **служби геолокації, контакти, фотографії, мікрофон, камера, accessibility і full disk access**. TCC гарантує, що застосунки можуть отримувати доступ до цих функцій лише після явної згоди користувача, посилюючи конфіденційність і контроль над персональними даними.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints у macOS — це функція безпеки для **регулювання запуску процесів** шляхом визначення **того, хто може запустити** процес, **як** і **звідки**. Запроваджені в macOS Ventura, вони розподіляють системні binaries за категоріями constraints у **trust cache**. Кожен executable binary має набір **правил** для свого **запуску**, зокрема **self**, **parent** і **responsible** constraints. Розширені для third-party застосунків як **Environment** Constraints у macOS Sonoma, ці функції допомагають зменшити ризик потенційної exploitation системи, регулюючи умови запуску процесів.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) — ще одна частина security infrastructure macOS. Як випливає з назви, основна функція MRT — **видаляти відоме malware із заражених систем**.

Після виявлення malware на Mac (XProtect або іншим способом) MRT можна використовувати для автоматичного **видалення malware**. MRT непомітно працює у фоновому режимі та зазвичай запускається під час оновлення системи або завантаження нового визначення malware (схоже, правила, за якими MRT виявляє malware, містяться всередині binary).

Хоча XProtect і MRT є частинами security measures macOS, вони виконують різні функції:

- **XProtect** — це preventative tool. Він **перевіряє файли під час їх завантаження** (через певні застосунки), і якщо виявляє будь-які відомі типи malware, **не дозволяє відкрити файл**, запобігаючи зараженню системи malware.
- **MRT**, натомість, — це **reactive tool**. Він працює після виявлення malware у системі, маючи на меті видалити небезпечне програмне забезпечення та очистити систему.

Застосунок MRT розташований у **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Керування фоновими завданнями

**macOS** тепер **попереджає** щоразу, коли інструмент використовує добре відому **technique для persistence code execution** (наприклад, Login Items, Daemons...), щоб користувач краще розумів, **яке програмне забезпечення зберігає persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Це працює за допомогою **daemon**, розташованого в `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`, і **agent** у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** визначає, що щось встановлено в persistent folder, шляхом **отримання FSEvents** і створення відповідних **handlers**.<sup>[[1]](#references)</sup>

Крім того, існує plist-файл, що містить **добре відомі застосунки**, які часто забезпечують persistence; він підтримується apple і розташований у: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Можна **перерахувати всі** налаштовані фонові елементи, запустивши інструмент командного рядка Apple:<sup>[[3]](#references)</sup>
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

Коли виявляється нова persistence, генерується подія типу **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Отже, будь-який спосіб **перешкодити** надсиланню цієї **події** або **сповістити** користувача агентом допоможе зловмиснику _**обійти**_ BTM.<sup>[[1]](#references)</sup>

- **Скидання database**: виконання наведеної нижче команди скине database (її має бути перебудовано з нуля), однак з незрозумілої причини після цього про нову persistence **не надходитимуть сповіщення, доки систему не буде перезавантажено**.<sup>[[1]](#references)</sup>
- Потрібен **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Зупинка Agent**: Можна надіслати Agent сигнал зупинки, щоб він **не сповіщав користувача** про виявлення нових загроз.<sup>[[1]](#references)</sup>
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
- **Bug**: Якщо **процес, який створив persistence, одразу після цього завершує роботу**, daemon спробує **отримати інформацію** про нього, **зазнає невдачі** та **не зможе надіслати event**, який повідомляє про створення нової persistence.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: «Demystifying (& Bypassing) macOS's Background Task Management» - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: «DumpBTM» - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
