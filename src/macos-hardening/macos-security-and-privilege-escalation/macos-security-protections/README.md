# Захисні механізми macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper зазвичай використовується для позначення поєднання **Quarantine + Gatekeeper + XProtect** — 3 модулів безпеки macOS, які намагаються **запобігти виконанню користувачами потенційно шкідливого завантаженого програмного забезпечення**.

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

Sandbox у macOS **обмежує застосунки**, що працюють усередині sandbox, **дозволеними діями, указаними в профілі Sandbox**, із яким запущено застосунок. Це допомагає гарантувати, що **застосунок матиме доступ лише до очікуваних ресурсів**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** — це security framework. Він призначений для **керування дозволами** застосунків, зокрема шляхом регулювання їхнього доступу до чутливих функцій. Це включає такі елементи, як **служби геолокації, контакти, фотографії, мікрофон, камера, accessibility та full disk access**. TCC гарантує, що застосунки можуть отримати доступ до цих функцій лише після явної згоди користувача, посилюючи таким чином приватність і контроль над персональними даними.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints у macOS — це security feature для **регулювання запуску процесів** шляхом визначення **того, хто може запустити** процес, **як** і **звідки**. Вони були представлені в macOS Ventura та категоризують системні binary у категорії обмежень усередині **trust cache**. Кожен executable binary має набір **правил** для свого **запуску**, зокрема обмеження **self**, **parent** і **responsible**. У macOS Sonoma ці функції були розширені на сторонні застосунки як **Environment Constraints**; вони допомагають зменшити ризик потенційних system exploitations, регулюючи умови запуску процесів.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) — це ще одна частина security infrastructure macOS. Як випливає з назви, основна функція MRT — **видаляти відоме malware із заражених систем**.

Після виявлення malware на Mac (XProtect або іншим способом) MRT можна використовувати для автоматичного **видалення malware**. MRT непомітно працює у background і зазвичай запускається під час оновлення системи або завантаження нового визначення malware (схоже, правила, які MRT використовує для виявлення malware, містяться всередині binary).

Хоча XProtect і MRT є частинами security measures macOS, вони виконують різні функції:

- **XProtect** — це preventative tool. Він **перевіряє файли під час їхнього завантаження** (через певні застосунки), і якщо виявляє будь-які відомі типи malware, **запобігає відкриттю файлу**, не даючи malware заразити систему.
- **MRT**, натомість, — це **reactive tool**. Він працює після виявлення malware у системі, маючи на меті видалити шкідливе програмне забезпечення та очистити систему.

Застосунок MRT розташований у **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Керування Background Tasks

**macOS** тепер **сповіщає** щоразу, коли інструмент використовує добре відому **техніку для persistence виконання коду** (наприклад, Login Items, Daemons...), щоб користувач краще розумів, **яке програмне забезпечення забезпечує persistence**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Це працює за допомогою **daemon**, розташованого в `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd`, і **agent** у `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

Спосіб, у який **`backgroundtaskmanagementd`** визначає, що щось інстальовано в persistent folder, полягає в **отриманні FSEvents** і створенні для них певних **handlers**.<sup>[1]</sup>

Крім того, існує plist-файл із переліком **добре відомих застосунків**, які часто забезпечують persistence; Apple підтримує його за адресою: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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
### Enumeration

It's possible to **enumerate all** the налаштовані фонові елементи за допомогою Apple cli tool:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Крім того, цю інформацію також можна переглянути за допомогою [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ця інформація зберігається у **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, і Terminal потребує FDA.<sup>[2]</sup>

### Втручання в BTM

Коли виявляється новий persistence, надсилається event типу **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Отже, будь-який спосіб **запобігти** надсиланню цього **event** або **сповіщенню** користувача агентом допоможе attacker'у _**обійти**_ BTM.<sup>[1]</sup>

- **Скидання бази даних**: виконання наведеної нижче команди скине базу даних (її має бути перебудовано з нуля), однак з невідомої причини після цього про **новий persistence** не надходитимуть сповіщення, доки систему не буде перезавантажено.<sup>[1]</sup>
- Потрібен **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Зупинка Agent**: Можна надіслати агенту сигнал зупинки, щоб він **не сповіщав користувача** про виявлення нових загроз.<sup>[1]</sup>
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
- **Bug**: Якщо **process, який створив persistence, швидко завершується одразу після цього**, daemon спробує **отримати інформацію** про нього, **зазнає невдачі** та **не зможе надіслати event**, який вказує на те, що новий об'єкт використовує persistence.<sup>[1]</sup>

## References

- [1] [OBTS v6.0: «Demystifying (& Bypassing) macOS's Background Task Management» - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: «DumpBTM» - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Керування login items і background tasks на Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
