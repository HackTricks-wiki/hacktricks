# Мережеві служби та протоколи macOS

{{#include ../../banners/hacktricks-training.md}}

## Служби віддаленого доступу

Це поширені служби macOS для віддаленого доступу до системи.\
Увімкнути/вимкнути ці служби можна в `Системні параметри` --> `Спільний доступ`

- **VNC**, відомий як «Спільний доступ до екрана» (tcp:5900)
- **SSH**, який називається «Віддалений вхід» (tcp:22)
- **Apple Remote Desktop** (ARD), або «Віддалене керування» (tcp:3283, tcp:5900)
- **AppleEvent**, відомий як «Віддалені події Apple» (tcp:3031)

Перевірте, чи ввімкнено якусь із них, виконавши:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Локальне перерахування конфігурації спільного доступу

Якщо ви вже отримали локальне виконання коду на Mac, **перевірте налаштований стан**, а не лише сокети, що прослуховуються. `systemsetup` і `launchctl` зазвичай показують, чи увімкнено службу адміністративно, тоді як `kickstart` і `system_profiler` допомагають підтвердити фактичну конфігурацію ARD/Sharing:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Apple Remote Desktop (ARD) — це розширена версія [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), адаптована для macOS і доповнена додатковими функціями. Помітною вразливістю ARD є метод автентифікації для пароля екрана керування, який використовує лише перші 8 символів пароля, що робить його вразливим до [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) за допомогою таких інструментів, як Hydra або [GoRedShell](https://github.com/ahhh/GoRedShell/), оскільки стандартні обмеження частоти запитів відсутні.<sup>[3]</sup>

Вразливі екземпляри можна виявити за допомогою скрипта `vnc-info` у **nmap**. Сервіси, що підтримують `VNC Authentication (2)`, особливо вразливі до brute force attacks через обрізання пароля до 8 символів.

Щоб увімкнути ARD для різних адміністративних завдань, зокрема privilege escalation, доступу до GUI або моніторингу користувачів, використайте таку команду:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD забезпечує гнучкі рівні контролю, зокрема спостереження, спільний контроль і повний контроль, причому сесії зберігаються навіть після зміни паролів користувачів. Він дає змогу безпосередньо надсилати Unix-команди та виконувати їх від імені root для адміністративних користувачів. Планування завдань і Remote Spotlight search є важливими функціями, що забезпечують віддалений пошук чутливих файлів на кількох машинах із мінімальним впливом.

З погляду оператора, **Monterey 12.1+ змінила робочі процеси віддаленого ввімкнення** в керованих флотах. Якщо ви вже контролюєте MDM жертви, команда Apple `EnableRemoteDesktop` часто є найчистішим способом активувати функціональність remote desktop у новіших системах. Якщо ви вже маєте foothold на хості, `kickstart` і надалі корисний для перевірки або переналаштування привілеїв ARD з командного рядка.

#### Apple Screen Sharing (RFB 003.889 / security type 36) зловживання file-copy до автентифікації

Нещодавні дослідження `screensharingd` показали, що Apple Screen Sharing не завжди використовує лише класичну VNC-аутентифікацію: новіші збірки працюють із **RFB `003.889`** і оголошують **security type `36`**, де спочатку автентифікація виконується через **SRP**, а **ChaCha20-Poly1305** встановлюється лише після успішного виконання `ccsrp_server_verify_session`. У публічному описі зазначено, що вразливість виправлено в **macOS Tahoe 26.6** (**27 липня 2026 року**).<sup>[8][9]</sup>

Корисний шаблон, який варто запам’ятати, — це **stale-status parser bypass**: після успішного читання 4-байтової довжини кожна гілка для надмірного розміру або помилки повинна повертати нову помилку. У вразливих збірках довжина SRP-фрейму у форматі **big-endian**, що дорівнює **`>= 32768`**, змушує шлях відхилення повторно використати попередній успішний результат `NetBufferRead` (`0`), тому викликаючий код позначає сесію як автентифіковану, хоча перевірка пароля не виконувалася, а транспортне шифрування не встановлювалося. Оскільки непрочитані байти залишаються у спільному socket buffer, зловмисник може **передати malformed SRP data і post-auth RFB messages в одному TCP burst** і змусити їх оброблятися як **cleartext authenticated traffic**.<sup>[8]</sup>

Після обходу захисту власне повідомлення Apple **file-copy** **`0x22`** перетворюється на **root file read/write primitive**, оскільки `screensharingd` працює від імені root:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: довільне читання файлів
- `kind=2` / `StartFileReceive`: довільний запис файлів
- Різні значення `sid` дають змогу поставити в чергу кілька транзакцій в одному з’єднанні
- У `kind=101` (`NewItem`) встановіть byte `14` / `arg[0]` у `0x01` для звичайного файлу, payload offset `+42` — у **ненульовий** розмір файлу у big-endian, а payload offset `+0x5a` — у потрібний Unix mode (`0600`, якщо ціллю є crontab)

Цікаві post-write pivots у writable paths включають **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** і **`/var/root/.ssh/authorized_keys`**. **SIP не зупиняє auth bypass або root file read**, але блокує деякі write targets, як-от **`/var/at`**, тому виконання на основі cron працює лише з вимкненим SIP. На хостах із типовим увімкненим SIP слід думати радше про **"root file write into privileged auto-consumed files"**, ніж про негайне виконання коду.<sup>[8]</sup>

Ще одна SRP-помилка з того самого дослідження: сервери повинні перевіряти **`A mod N != 0`** (відповідно до RFC 5054), а не лише **`A > 0`**. Прийняття **`A = N`** може примусово встановити спільний секрет у нульове значення та підірвати перевірку пароля.<sup>[8][10]</sup>

**Ідеї для виявлення**

- Сеанси Security type `36`, у яких довжина першого SRP frame становить **`>= 32768`**
- Сеанси, які починають обробляти незашифрований трафік копіювання файлів **`0x22`** до успішної SRP proof / cipher install
- Повторні короткоживучі спроби підключення до **TCP/5900** разом із кількома значеннями file-copy `sid` в одному burst
- Несподіване створення **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** або **`/var/root/.ssh/authorized_keys`** після доступу через Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Apple називає цю функцію **Remote Application Scripting** у сучасних System Settings. На нижчому рівні вона віддалено відкриває **Apple Event Manager** через **EPPC** на **TCP/3031** за допомогою сервісу `com.apple.AEServer`. Palo Alto Unit 42 знову звернула на неї увагу як на практичний примітив **macOS lateral movement**, оскільки дійсні облікові дані разом з увімкненим сервісом RAE дають оператору змогу керувати scriptable applications на віддаленому Mac.<sup>[6]</sup>

Корисні перевірки:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Якщо ви вже маєте права адміністратора/root на цільовій системі й хочете увімкнути його:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Базовий тест підключення з іншого Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
На практиці випадок зловживання не обмежується Finder. Будь-яка **scriptable application**, яка приймає необхідні Apple events, стає віддаленою поверхнею атаки, що робить RAE особливо цікаливим після викрадення облікових даних у внутрішніх macOS-мережах.

#### Нещодавні вразливості Screen-Sharing / ARD (2023-2025)

| Рік | CVE | Компонент | Вплив | Виправлено у |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Некоректне відображення сеансу могло призвести до передавання *неправильного* робочого столу або вікна, що спричиняло витік конфіденційної інформації|macOS Sonoma 14.2.1 (грудень 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Користувач із доступом до Screen Sharing міг переглядати **екран іншого користувача** через проблему керування станом|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (жовтень-грудень 2024) |

**Поради з hardening**

* Вимикайте *Screen Sharing*/*Remote Management*, якщо вони не є абсолютно необхідними.
* Підтримуйте macOS повністю оновленою (Apple зазвичай випускає security fixes для трьох останніх основних релізів).
* Використовуйте **Strong Password** і за можливості залишайте опцію *“VNC viewers may control screen with password”* **вимкненою**.
* Розміщуйте сервіс за VPN замість відкриття TCP 5900/3283 в Internet.
* Додайте правило Application Firewall, щоб обмежити `ARDAgent` локальною підмережею:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Протокол Bonjour

Bonjour, технологія, розроблена Apple, дає змогу **пристроям в одній мережі виявляти служби, які вони пропонують один одному**. Також відомий як Rendezvous, **Zero Configuration** або Zeroconf, цей протокол дає змогу пристрою приєднатися до TCP/IP-мережі, **автоматично вибрати IP-адресу** та транслювати свої служби іншим пристроям мережі.

Zero Configuration Networking, який надає Bonjour, забезпечує можливість пристроям:

- **Автоматично отримувати IP-адресу**, навіть за відсутності DHCP-сервера.
- Виконувати **перетворення імені на адресу** без потреби в DNS-сервері.
- **Виявляти служби**, доступні в мережі.

Пристрої, що використовують Bonjour, призначають собі **IP-адресу з діапазону 169.254/16** і перевіряють її унікальність у мережі. Macs підтримують запис у таблиці маршрутизації для цієї підмережі, який можна перевірити за допомогою `netstat -rn | grep 169`.

Для DNS Bonjour використовує **протокол Multicast DNS (mDNS)**. mDNS працює через **порт 5353/UDP**, застосовуючи **стандартні DNS-запити**, але спрямовуючи їх на **multicast-адресу 224.0.0.251**. Такий підхід гарантує, що всі пристрої мережі, які прослуховують цей трафік, можуть отримувати запити та відповідати на них, спрощуючи оновлення своїх записів.

Після приєднання до мережі кожен пристрій самостійно вибирає ім’я, яке зазвичай закінчується на **.local** і може бути похідним від hostname або згенерованим випадковим чином.

Виявлення служб у мережі забезпечує **DNS Service Discovery (DNS-SD)**. Використовуючи формат DNS SRV-записів, DNS-SD застосовує **DNS PTR-записи**, щоб уможливити перелік кількох служб. Клієнт, який шукає певну службу, запитує PTR-запис для `<Service>.<Domain>` і отримує у відповідь список PTR-записів у форматі `<Instance>.<Service>.<Domain>`, якщо служба доступна на кількох хостах.

Утиліту `dns-sd` можна використовувати для **виявлення та реклами мережевих служб**. Ось кілька прикладів її використання:

### Пошук SSH-служб

Для пошуку SSH-служб у мережі використовується наведена нижче команда:
```bash
dns-sd -B _ssh._tcp
```
Ця команда ініціює пошук сервісів \_ssh.\_tcp і виводить такі дані, як timestamp, flags, interface, domain, тип сервісу та назва instance.

### Рекламування HTTP-сервісу

Щоб прорекламувати HTTP-сервіс, можна використати:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ця команда реєструє HTTP-сервіс із назвою "Index" на порту 80 із шляхом `/index.html`.

Щоб потім виконати пошук HTTP-сервісів у мережі:
```bash
dns-sd -B _http._tcp
```
Коли сервіс запускається, він повідомляє про свою доступність усім пристроям у підмережі, транслюючи інформацію про свою присутність за допомогою multicast. Пристроям, які зацікавлені в цих сервісах, не потрібно надсилати запити — достатньо просто прослуховувати ці оголошення.

Для зручнішого інтерфейсу застосунок **Discovery - DNS-SD Browser**, доступний в Apple App Store, може візуалізувати сервіси, доступні у вашій локальній мережі.

Також можна написати власні скрипти для перегляду та виявлення сервісів за допомогою бібліотеки `python-zeroconf`. Скрипт [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) демонструє створення браузера сервісів для сервісів `_http._tcp.local.`, виводячи додані або видалені сервіси:
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
### Пошук специфічних для macOS служб Bonjour

У мережах macOS Bonjour часто є найпростішим способом знайти **поверхні віддаленого адміністрування**, не взаємодіючи безпосередньо з цільовою системою. Apple Remote Desktop може виявляти клієнтів через Bonjour, тому ті самі дані виявлення корисні зловмиснику.
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
Для ширших технік **mDNS spoofing, impersonation та cross-subnet discovery** перегляньте спеціальну сторінку:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Перерахування Bonjour у мережі

* **Nmap NSE** – виявлення services, advertised одним host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Скрипт `dns-service-discovery` надсилає запит `_services._dns-sd._udp.local`, а потім перераховує кожен advertised service type.

* **mdns_recon** – Python tool, який сканує цілі діапазони в пошуках *misconfigured* mDNS responders, що відповідають на unicast queries (корисно для пошуку devices, доступних через subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Ця команда поверне hosts, які надають SSH через Bonjour за межами локального link.

### Міркування щодо безпеки та нещодавні vulnerabilities (2024-2025)

| Рік | CVE | Рівень небезпеки | Проблема | Виправлено в |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Середній|Логічна помилка в *mDNSResponder* дозволяла crafted packet викликати **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (вересень 2024) |
|2025|CVE-2025-31222|Високий|Проблему коректності в *mDNSResponder* можна було використати для **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (травень 2025) |

**Рекомендації щодо mitigation**

1. Обмежте UDP 5353 областю *link-local* – блокуйте або обмежуйте його rate на wireless controllers, routers та host-based firewalls.
2. Повністю вимкніть Bonjour у системах, яким не потрібен service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. У середовищах, де Bonjour потрібен внутрішньо, але ніколи не має перетинати network boundaries, використовуйте обмеження профілю *AirPlay Receiver* (MDM) або mDNS proxy.
4. Увімкніть **System Integrity Protection (SIP)** і підтримуйте macOS в актуальному стані – обидві наведені vulnerabilities були швидко виправлені, але для повного захисту вони покладалися на ввімкнений SIP.

### Вимкнення Bonjour

Якщо є побоювання щодо безпеки або інші причини вимкнути Bonjour, це можна зробити за допомогою такої команди:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Посилання

- [1] [Посібник Mac-хакера](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [Мистецтво Mac Malware, том I: Аналіз — Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx — MacOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD — CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD — CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 — Lateral Movement on macOS: унікальні та популярні техніки й приклади з реального світу](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support — відомості про вміст оновлень безпеки macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support — відомості про вміст оновлень безпеки macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 — використання протоколу Secure Remote Password (SRP) для автентифікації TLS](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
