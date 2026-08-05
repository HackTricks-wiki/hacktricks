# Мережеві служби та протоколи macOS

{{#include ../../banners/hacktricks-training.md}}

## Служби віддаленого доступу

Це поширені служби macOS для віддаленого доступу до системи.\
Увімкнути або вимкнути ці служби можна в `System Settings` --> `Sharing`

- **VNC**, відомий як “Screen Sharing” (tcp:5900)
- **SSH**, який називається “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), або “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, відомий як “Remote Apple Event” (tcp:3031)

Перевірте, чи ввімкнено якийсь із них, виконавши:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Перелік конфігурації спільного доступу локально

Якщо ви вже маєте локальне виконання коду на Mac, **перевірте налаштований стан**, а не лише сокети, що прослуховують з'єднання. `systemsetup` і `launchctl` зазвичай показують, чи службу адміністративно ввімкнено, тоді як `kickstart` і `system_profiler` допомагають підтвердити фактичну конфігурацію ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) — це розширена версія [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), адаптована для macOS і доповнена додатковими функціями. Помітною вразливістю ARD є метод автентифікації пароля контрольного екрана, який використовує лише перші 8 символів пароля, що робить його вразливим до [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) за допомогою таких інструментів, як Hydra або [GoRedShell](https://github.com/ahhh/GoRedShell/), оскільки стандартні обмеження частоти запитів відсутні.<sup>[[3]](#references)</sup>

Вразливі екземпляри можна виявити за допомогою скрипта `vnc-info` у **nmap**. Сервіси, що підтримують `VNC Authentication (2)`, особливо вразливі до brute force attacks через усікання пароля до 8 символів.

Щоб увімкнути ARD для різних адміністративних завдань, як-от privilege escalation, доступу до GUI або моніторингу користувачів, використайте таку команду:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD забезпечує гнучкі рівні керування, зокрема спостереження, спільне керування та повне керування, а сесії зберігаються навіть після зміни пароля користувача. Він дає змогу безпосередньо надсилати команди Unix і виконувати їх від імені root для адміністративних користувачів. Планування завдань і Remote Spotlight search є важливими функціями, що дають змогу віддалено виконувати пошук конфіденційних файлів із низьким впливом на роботу кількох машин.

З погляду оператора, **Monterey 12.1+ змінив робочі процеси віддаленого ввімкнення** в керованих флотах. Якщо ви вже контролюєте MDM жертви, команда Apple `EnableRemoteDesktop` часто є найпростішим способом активувати функціональність віддаленого робочого стола в новіших системах. Якщо ви вже отримали foothold на хості, `kickstart` і надалі корисний для перевірки або переналаштування привілеїв ARD з командного рядка.

#### Apple Screen Sharing (RFB 003.889 / security type 36) зловживання file-copy до автентифікації

Нещодавні дослідження `screensharingd` показали, що Apple Screen Sharing не завжди використовує лише класичну VNC-автентифікацію: новіші збірки працюють із **RFB `003.889`** і оголошують **security type `36`**, де спочатку виконується автентифікація через **SRP**, а **ChaCha20-Poly1305** встановлюється лише після успішного виконання `ccsrp_server_verify_session`. У публічному описі зазначено, що bug виправлено в **macOS Tahoe 26.6** (**27 липня 2026 року**).<sup>[[8]](#references)[[9]](#references)</sup>

Корисна закономірність, яку варто запам’ятати, — це **stale-status parser bypass**: після успішного читання 4-байтової довжини кожна гілка для завеликого значення або помилки повинна повертати нову помилку. У вразливих збірках довжина SRP-фрейму у форматі **big-endian**, що дорівнює **`>= 32768`**, змушує шлях відхилення повторно використати попередній успішний результат `NetBufferRead` (`0`), тому викликаючий код позначає сесію як автентифіковану, хоча перевірка пароля не виконувалася, а транспортне шифрування не встановлювалося. Оскільки непрочитані байти залишаються у спільному буфері сокета, атакувальник може **поставити в одну TCP-передачу malformed SRP-дані та post-auth RFB-повідомлення** й домогтися їхнього розбору як **автентифікованого трафіку у відкритому тексті**.<sup>[[8]](#references)</sup>

Після обходу Apple's proprietary **file-copy** message **`0x22`** перетворюється на **примітив читання/запису файлів із правами root**, оскільки `screensharingd` працює від імені root:<sup>[[8]](#references)</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: довільне читання файлів
- `kind=2` / `StartFileReceive`: довільний запис файлів
- Різні значення `sid` дають змогу об'єднувати кілька транзакцій в одному з'єднанні
- У `kind=101` (`NewItem`) встановіть байт `14` / `arg[0]` у `0x01` для звичайного файлу, зміщення payload `+42` — у **ненульовий** розмір файлу у big-endian, а зміщення payload `+0x5a` — у потрібний режим Unix (`0600`, якщо ціллю є crontab)

Цікаві post-write pivots для шляхів, доступних для запису, включають **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** і **`/var/root/.ssh/authorized_keys`**. **SIP не зупиняє обхід автентифікації або читання файлів від root**, але блокує деякі цілі запису, такі як **`/var/at`**, тому виконання на основі cron працює лише з вимкненим SIP. На хостах із типовим увімкненим SIP розглядайте це як **"запис файлів від root у привілейовані файли, які автоматично споживаються системою"**, а не як негайне виконання коду.<sup>[[8]](#references)</sup>

Ще одна проблема SRP з того самого дослідження: сервери повинні перевіряти **`A mod N != 0`** (відповідно до RFC 5054), а не лише `A > 0`. Прийняття **`A = N`** може примусово встановити спільний секрет у нуль і підірвати перевірку пароля.<sup>[[8]](#references)[[10]](#references)</sup>

**Ідеї для виявлення**

- Сесії типу Security `36`, у яких довжина першого SRP-фрейму становить **`>= 32768`**
- Сесії, які починають обробляти незашифрований трафік копіювання файлів **`0x22`** до успішного підтвердження SRP / встановлення шифру
- Повторні короткоживучі спроби підключення до **TCP/5900** разом із кількома значеннями `sid` для копіювання файлів в одному сплеску
- Несподіване створення **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** або **`/var/root/.ssh/authorized_keys`** після відкриття Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple називає цю функцію **Remote Application Scripting** у сучасних System Settings. Під капотом вона віддалено відкриває **Apple Event Manager** через **EPPC** на **TCP/3031** за допомогою сервісу `com.apple.AEServer`. Palo Alto Unit 42 знову звернули на неї увагу як на практичний примітив **macOS lateral movement**, оскільки дійсні облікові дані разом з увімкненим сервісом RAE дають оператору змогу керувати scriptable applications на віддаленому Mac.<sup>[[6]](#references)</sup>

Корисні перевірки:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Якщо ви вже маєте права admin/root на цільовій системі й хочете увімкнути його:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Базовий тест підключення з іншого Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
На практиці випадок зловживання не обмежується Finder. Будь-яка **scriptable application**, яка приймає необхідні Apple events, стає віддаленою attack surface, що робить RAE особливо цікавим після викрадення облікових даних у внутрішніх macOS-мережах.

#### Нещодавні вразливості Screen-Sharing / ARD (2023-2025)

| Рік | CVE | Компонент | Вплив | Виправлено у |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Некоректне відображення сесії могло призвести до передавання *неправильного* робочого столу або вікна, що спричиняло витік конфіденційної інформації|macOS Sonoma 14.2.1 (грудень 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Користувач із доступом до screen sharing міг переглядати **екран іншого користувача** через проблему керування станом|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (жовтень-грудень 2024) |

**Поради щодо hardening**

* Вимикайте *Screen Sharing*/*Remote Management*, якщо вони не є суворо необхідними.
* Підтримуйте macOS повністю оновленою (Apple зазвичай випускає security fixes для трьох останніх основних релізів).
* Використовуйте **Strong Password** і, коли можливо, залишайте вимкненим параметр *“VNC viewers may control screen with password”*.
* Розміщуйте сервіс за VPN замість відкриття TCP 5900/3283 для Internet.
* Додайте правило Application Firewall, щоб обмежити `ARDAgent` локальною підмережею:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Протокол Bonjour

Bonjour, технологія, розроблена Apple, дає змогу **пристроям в одній мережі виявляти служби, які пропонують один одному**. Також відомий як Rendezvous, **Zero Configuration** або Zeroconf, цей протокол дає пристрою змогу підключитися до TCP/IP-мережі, **автоматично вибрати IP-адресу** та транслювати свої служби іншим мережевим пристроям.

Zero Configuration Networking, що надається Bonjour, гарантує, що пристрої можуть:

- **Автоматично отримати IP-адресу**, навіть за відсутності DHCP-сервера.
- Виконувати **перетворення імені на адресу** без DNS-сервера.
- **Виявляти служби**, доступні в мережі.

Пристрої, що використовують Bonjour, призначають собі **IP-адресу з діапазону 169.254/16** і перевіряють її унікальність у мережі. Macs підтримують запис таблиці маршрутизації для цієї підмережі, що можна перевірити за допомогою `netstat -rn | grep 169`.

Для DNS Bonjour використовує протокол **Multicast DNS (mDNS)**. mDNS працює через **порт 5353/UDP**, використовуючи **стандартні DNS-запити**, але надсилаючи їх на **multicast-адресу 224.0.0.251**. Це гарантує, що всі пристрої мережі, які прослуховують, можуть отримувати запити та відповідати на них, забезпечуючи оновлення своїх записів.

Після підключення до мережі кожен пристрій самостійно обирає ім’я, яке зазвичай закінчується на **.local** і може походити від hostname або генеруватися випадковим чином.

Виявлення служб у мережі забезпечується за допомогою **DNS Service Discovery (DNS-SD)**. Використовуючи формат DNS SRV-записів, DNS-SD застосовує **DNS PTR-записи**, щоб уможливити перелік кількох служб. Клієнт, який шукає певну службу, надсилає запит PTR-запису для `<Service>.<Domain>` і отримує у відповідь список PTR-записів у форматі `<Instance>.<Service>.<Domain>`, якщо служба доступна на кількох хостах.

Утиліту `dns-sd` можна використовувати для **виявлення та реклами мережевих служб**. Нижче наведено кілька прикладів її використання:

### Пошук SSH-служб

Для пошуку SSH-служб у мережі використовується така команда:
```bash
dns-sd -B _ssh._tcp
```
Ця команда ініціює пошук сервісів \_ssh.\_tcp і виводить такі відомості, як мітка часу, прапорці, інтерфейс, домен, тип сервісу та назва екземпляра.

### Реклама HTTP-сервісу

Щоб прорекламувати HTTP-сервіс, можна використати:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ця команда реєструє HTTP-сервіс із назвою "Index" на порту 80 із шляхом `/index.html`.

Щоб потім шукати HTTP-сервіси в мережі:
```bash
dns-sd -B _http._tcp
```
Коли служба запускається, вона оголошує про свою доступність усім пристроям у підмережі, multicast-розсилаючи інформацію про свою присутність. Пристроям, які зацікавлені в цих службах, не потрібно надсилати запити — достатньо просто прослуховувати ці оголошення.

Для зручнішого користувацького інтерфейсу застосунок **Discovery - DNS-SD Browser**, доступний в Apple App Store, може візуалізувати служби, доступні у вашій локальній мережі.

Також можна написати власні скрипти для перегляду та виявлення служб за допомогою бібліотеки `python-zeroconf`. Скрипт [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) демонструє створення service browser для служб `_http._tcp.local.`, виводячи додані або видалені служби:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Пошук Bonjour, специфічний для macOS

У мережах macOS Bonjour часто є найпростішим способом знайти **поверхні віддаленого адміністрування**, не взаємодіючи безпосередньо з ціллю. Apple Remote Desktop може виявляти клієнтів через Bonjour, тому ті самі дані виявлення корисні для зловмисника.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Для ширших технік **mDNS spoofing, impersonation і cross-subnet discovery** перегляньте спеціальну сторінку:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Перерахування Bonjour через мережу

* **Nmap NSE** – виявлення сервісів, оголошених одним хостом:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Скрипт `dns-service-discovery` надсилає запит `_services._dns-sd._udp.local`, а потім перераховує типи кожного оголошеного сервісу.

* **mdns_recon** – Python-інструмент, який сканує цілі діапазони в пошуках *misconfigured* mDNS responder-ів, що відповідають на unicast-запити (корисно для виявлення пристроїв, доступних через підмережі/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Це поверне хости, які надають SSH через Bonjour за межами локального каналу.

### Зауваження щодо безпеки та нещодавні вразливості (2024-2025)

| Рік | CVE | Рівень критичності | Проблема | Виправлено в |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Середній|Логічна помилка в *mDNSResponder* дозволяла спеціально сформованому пакету спричинити **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (вересень 2024) |
|2025|CVE-2025-31222|Високий|Проблему коректності в *mDNSResponder* можна було використати для **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (травень 2025) |

**Рекомендації щодо пом'якшення ризиків**

1. Обмежте UDP 5353 областю *link-local* – блокуйте його або застосовуйте rate-limit на wireless controller-ах, маршрутизаторах і host-based firewall.
2. Повністю вимкніть Bonjour у системах, яким не потрібне service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. У середовищах, де Bonjour потрібен усередині мережі, але ніколи не повинен перетинати мережеві межі, використовуйте обмеження профілю *AirPlay Receiver* (MDM) або mDNS proxy.
4. Увімкніть **System Integrity Protection (SIP)** і підтримуйте macOS в актуальному стані – обидві наведені вище вразливості було швидко виправлено, але для повного захисту потрібен увімкнений SIP.

### Вимкнення Bonjour

Якщо є занепокоєння щодо безпеки або інші причини вимкнути Bonjour, це можна зробити за допомогою такої команди:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Посилання

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Volume I: Analysis - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - About the security content of macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - About the security content of macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
