# Red Teaming у macOS

{{#include ../../banners/hacktricks-training.md}}


## Зловживання MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Якщо вам вдасться **скомпрометувати облікові дані адміністратора** для доступу до платформи керування, ви **потенційно зможете скомпрометувати всі комп'ютери**, поширивши своє malware на ці машини.

Для red teaming у середовищах MacOS наполегливо рекомендується мати певне розуміння принципів роботи MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Використання MDM як C2

MDM матиме дозвіл на встановлення, опитування або видалення профілів, встановлення застосунків, створення локальних облікових записів адміністратора, встановлення пароля firmware, зміну ключа FileVault...

Щоб запустити власний MDM, потрібно, щоб **ваш CSR був підписаний постачальником**, що можна спробувати зробити за допомогою [**https://mdmcert.download/**](https://mdmcert.download/). А щоб запустити власний MDM для пристроїв Apple, можна використати [**MicroMDM**](https://github.com/micromdm/micromdm).

Однак для встановлення застосунку на зареєстрований пристрій він усе ще має бути підписаний обліковим записом розробника... однак під час enrolment у MDM **пристрій додає SSL-сертифікат MDM як довірений CA**, тож тепер ви можете підписувати будь-що.<sup>[4]</sup>

Щоб зареєструвати пристрій у MDM, потрібно встановити файл **`mobileconfig`** від імені root; його можна доставити через файл **pkg** (його можна стиснути в zip, і під час завантаження із Safari його буде розпаковано).

**Agent Orthrus у Mythic** використовує цю техніку.

### Зловживання JAMF PRO

JAMF може запускати **custom scripts** (скрипти, розроблені sysadmin), **native payloads** (створення локального облікового запису, встановлення пароля EFI, моніторинг файлів/процесів...) і **MDM** (конфігурації пристроїв, сертифікати пристроїв...).<sup>[5]</sup>

#### Self-enrolment у JAMF

Перейдіть на сторінку на кшталт `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи **увімкнено self-enrolment**. Якщо так, система може **запитати облікові дані для доступу**.

Для виконання password spraying attack можна використати скрипт [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py).

Крім того, після знаходження правильних облікових даних можна буде brute-force інші імена користувачів за допомогою наведеної нижче форми:

![Зловживання JAMF PRO - Self-enrolment у JAMF: Крім того, після знаходження правильних облікових даних можна буде brute-force інші імена користувачів за допомогою наведеної нижче форми](<../../images/image (107).png>)

#### Аутентифікація пристрою JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Бінарний файл **`jamf`** містив секрет для відкриття keychain, який на момент виявлення був **спільним** для всіх і мав значення: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Крім того, jamf **зберігається** як **LaunchDaemon** у **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Захоплення пристрою JAMF

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
Отже, зловмисник міг би розмістити шкідливий пакет (`pkg`), який під час встановлення **перезаписує цей файл**, задаючи **URL-адресу до Mythic C2 listener від Typhon agent**, що дає змогу використовувати JAMF як C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### Імітація JAMF

Щоб **імітувати комунікацію** між пристроєм і JMF, вам потрібно:

- **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** із: `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

Використовуючи цю інформацію, **створіть VM** зі **викраденим** Hardware **UUID** і з **вимкненим SIP**, помістіть **JAMF keychain**, встановіть **hook** на **agent** Jamf і викрадіть його інформацію.

#### Викрадення secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ви також можете моніторити розташування `/Library/Application Support/Jamf/tmp/` на наявність **custom scripts**, які адміністратори можуть захотіти виконати через Jamf, оскільки вони **поміщаються сюди, виконуються та видаляються**. Ці scripts **можуть містити credentials**.

Однак **credentials** можуть передаватися цим scripts як **parameters**, тому вам потрібно буде моніторити `ps aux | grep -i jamf` (навіть без root).

Скрипт [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може прослуховувати додавання нових файлів і нові аргументи процесів.

### Віддалений доступ до macOS

А також щодо "спеціальних" **мережевих** **протоколів** MacOS:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

У деяких випадках ви виявите, що **комп’ютер MacOS підключений до AD**. У цьому сценарії вам слід спробувати **перерахувати** active directory так, як ви це зазвичай робите. Знайдіть **допомогу** на таких сторінках:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Деякий **локальний інструмент MacOS**, який також може вам допомогти, — це `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Також існують деякі tools, підготовлені для MacOS, щоб автоматично виконувати enumeration AD і працювати з kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound — це розширення для auditing tool Bloodhound, яке дає змогу збирати та імпортувати зв’язки Active Directory на хостах MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost — це проєкт Objective-C, розроблений для взаємодії з API Heimdal krb5 у macOS. Мета проєкту — забезпечити якісніше security testing Kerberos на пристроях macOS за допомогою native API без необхідності встановлення будь-яких інших framework або packages на target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): інструмент JavaScript for Automation (JXA) для виконання enumeration Active Directory.

### Інформація про домен
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Користувачі

Існує три типи користувачів MacOS:

- **Локальні користувачі** — керуються локальною службою OpenDirectory і жодним чином не підключені до Active Directory.
- **Мережеві користувачі** — тимчасові користувачі Active Directory, яким для автентифікації потрібне підключення до сервера DC.
- **Мобільні користувачі** — користувачі Active Directory із локальною резервною копією облікових даних і файлів.

Локальна інформація про користувачів і групи зберігається в папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача з іменем _mark_ зберігається у файлі _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у файлі _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Окрім використання зв’язків HasSession і AdminTo, **MacHound додає до бази даних Bloodhound ще три нові зв’язки**:<sup>[2]</sup>

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
Додаткова інформація: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

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
За допомогою отриманих service tickets можна спробувати отримати доступ до shares на інших комп’ютерах:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Доступ до Keychain

Keychain, найімовірніше, містить конфіденційну інформацію, яка в разі доступу без створення prompt може допомогти просунутися під час red team exercise:


{{#ref}}
macos-keychain.md
{{#endref}}

## Зовнішні сервіси

MacOS Red Teaming відрізняється від звичайного Windows Red Teaming, оскільки **MacOS зазвичай безпосередньо інтегрована з кількома зовнішніми платформами**. Поширена конфігурація MacOS передбачає доступ до комп'ютера за допомогою **синхронізованих облікових даних OneLogin і доступ до кількох зовнішніх сервісів** (таких як github, aws...) через OneLogin.

## Різні red team техніки

### Safari

Коли файл завантажується в Safari, якщо це **«безпечний» файл**, його буде **автоматично відкрито**. Наприклад, якщо ви **завантажите zip-архів**, його буде автоматично розпаковано:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Посилання

- [1] [Збираючи яблука: Red Teaming середовищ MacOS у 2021 році - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Представляємо MacHound: рішення для атак на macOS на основі Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - команди перерахування домену (еквіваленти dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Переходьте на темний бік, у нас є Apple: перетворення керування macOS на зловмисне](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: «Погляд зловмисника на конфігурації Jamf» - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
