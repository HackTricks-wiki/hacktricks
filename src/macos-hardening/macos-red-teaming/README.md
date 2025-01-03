# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Зловживання MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Якщо вам вдасться **компрометувати облікові дані адміністратора** для доступу до платформи управління, ви можете **потенційно скомпрометувати всі комп'ютери**, розповсюджуючи своє шкідливе ПЗ на машинах.

Для red teaming в середовищах MacOS настійно рекомендується мати певне розуміння того, як працюють MDM:

{{#ref}}
macos-mdm/
{{#endref}}

### Використання MDM як C2

MDM матиме дозвіл на встановлення, запит або видалення профілів, встановлення додатків, створення локальних облікових записів адміністратора, встановлення пароля firmware, зміну ключа FileVault...

Щоб запустити свій власний MDM, вам потрібно **підписати свій CSR постачальником**, що ви можете спробувати отримати з [**https://mdmcert.download/**](https://mdmcert.download/). А для запуску свого власного MDM для пристроїв Apple ви можете використовувати [**MicroMDM**](https://github.com/micromdm/micromdm).

Однак, щоб встановити додаток на зареєстрованому пристрої, вам все ще потрібно, щоб він був підписаний обліковим записом розробника... однак, під час реєстрації в MDM **пристрій додає SSL сертифікат MDM як довірений CA**, тому ви тепер можете підписувати що завгодно.

Щоб зареєструвати пристрій в MDM, вам потрібно встановити **`mobileconfig`** файл як root, який можна доставити через **pkg** файл (ви можете стиснути його в zip, і коли його завантажать з safari, він буде розпакований).

**Mythic agent Orthrus** використовує цю техніку.

### Зловживання JAMF PRO

JAMF може виконувати **кастомні скрипти** (скрипти, розроблені системним адміністратором), **рідні корисні навантаження** (створення локальних облікових записів, встановлення пароля EFI, моніторинг файлів/процесів...) та **MDM** (конфігурації пристроїв, сертифікати пристроїв...).

#### Самостійна реєстрація JAMF

Перейдіть на сторінку, таку як `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи мають вони **увімкнену самостійну реєстрацію**. Якщо так, це може **попросити облікові дані для доступу**.

Ви можете використовувати скрипт [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) для виконання атаки на підбор паролів.

Більше того, після знаходження відповідних облікових даних ви зможете брутфорсити інші імена користувачів за допомогою наступної форми:

![](<../../images/image (107).png>)

#### Аутентифікація пристрою JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Бінарний файл **`jamf`** містив секрет для відкриття ключниці, який на момент виявлення був **спільним** серед усіх, і це було: **`jk23ucnq91jfu9aj`**.\
Більше того, jamf **постійно** працює як **LaunchDaemon** в **`/Library/LaunchAgents/com.jamf.management.agent.plist`**.

#### Захоплення пристрою JAMF

**JSS** (Jamf Software Server) **URL**, який буде використовувати **`jamf`**, знаходиться в **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Цей файл в основному містить URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Отже, зловмисник може встановити шкідливий пакет (`pkg`), який **перезаписує цей файл**, налаштовуючи **URL на Mythic C2 слухача з агента Typhon**, щоб тепер мати можливість зловживати JAMF як C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Імітація

Щоб **імітувати комунікацію** між пристроєм і JMF, вам потрібно:

- **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF ключ** з: `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

З цією інформацією, **створіть ВМ** з **викраденим** апаратним **UUID** і з **вимкненим SIP**, скиньте **JAMF ключ**, **підключіть** агент Jamf і викрадіть його інформацію.

#### Викрадення секретів

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Ви також можете моніторити місце `/Library/Application Support/Jamf/tmp/` для **кастомних скриптів**, які адміністратори можуть захотіти виконати через Jamf, оскільки вони **розміщуються тут, виконуються і видаляються**. Ці скрипти **можуть містити облікові дані**.

Однак, **облікові дані** можуть передаватися цим скриптам як **параметри**, тому вам потрібно буде моніторити `ps aux | grep -i jamf` (навіть не будучи root).

Скрипт [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може слухати нові файли, що додаються, і нові аргументи процесу.

### macOS Віддалений доступ

А також про **MacOS** "спеціальні" **мережеві** **протоколи**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

В деяких випадках ви виявите, що **комп'ютер MacOS підключений до AD**. У цьому сценарії вам слід спробувати **перерахувати** активний каталог, як ви звикли. Знайдіть деяку **допомогу** на наступних сторінках:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Деякий **локальний інструмент MacOS**, який також може вам допомогти, це `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Також є кілька інструментів, підготовлених для MacOS, щоб автоматично перераховувати AD та працювати з kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound - це розширення до інструменту аудиту Bloodhound, що дозволяє збирати та імпортувати відносини Active Directory на MacOS хостах.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost - це проект на Objective-C, призначений для взаємодії з API Heimdal krb5 на macOS. Мета проекту - забезпечити кращий тестування безпеки навколо Kerberos на пристроях macOS, використовуючи рідні API без необхідності в інших фреймворках або пакетах на цілі.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Інструмент JavaScript для автоматизації (JXA) для виконання перерахунку Active Directory.

### Інформація про домен
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Користувачі

Три типи користувачів MacOS:

- **Локальні користувачі** — Керуються локальною службою OpenDirectory, вони не пов'язані жодним чином з Active Directory.
- **Мережеві користувачі** — Вольатильні користувачі Active Directory, які потребують з'єднання з сервером DC для аутентифікації.
- **Мобільні користувачі** — Користувачі Active Directory з локальною резервною копією своїх облікових даних та файлів.

Локальна інформація про користувачів та групи зберігається у папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача з ім'ям _mark_ зберігається у _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у _/var/db/dslocal/nodes/Default/groups/admin.plist_.

На додаток до використання країв HasSession та AdminTo, **MacHound додає три нові краї** до бази даних Bloodhound:

- **CanSSH** - сутність, якій дозволено SSH до хоста
- **CanVNC** - сутність, якій дозволено VNC до хоста
- **CanAE** - сутність, якій дозволено виконувати скрипти AppleEvent на хості
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
Більше інформації в [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ пароль

Отримати паролі за допомогою:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Можливо отримати пароль **`Computer$`** всередині системного ключа.

### Over-Pass-The-Hash

Отримайте TGT для конкретного користувача та служби:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Як тільки TGT зібрано, його можна ввести в поточну сесію за допомогою:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Керберостинг
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
З отриманими квитками сервісу можна спробувати отримати доступ до загальних папок на інших комп'ютерах:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Доступ до Ключниці

Ключниця, ймовірно, містить чутливу інформацію, яка, якщо отримати доступ без генерації запиту, може допомогти просунутися в вправі червоної команди:

{{#ref}}
macos-keychain.md
{{#endref}}

## Зовнішні Сервіси

MacOS Red Teaming відрізняється від звичайного Windows Red Teaming, оскільки зазвичай **MacOS інтегровано з кількома зовнішніми платформами безпосередньо**. Звичайна конфігурація MacOS полягає в доступі до комп'ютера за допомогою **синхронізованих облікових даних OneLogin та доступу до кількох зовнішніх сервісів** (таких як github, aws...) через OneLogin.

## Різні техніки червоної команди

### Safari

Коли файл завантажується в Safari, якщо це "безпечний" файл, він буде **автоматично відкритий**. Тож, наприклад, якщо ви **завантажите zip**, він буде автоматично розпакований:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Посилання

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
