# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Це загальні служби macOS для віддаленого доступу до них.\
Ви можете увімкнути/вимкнути ці служби в `System Settings` --> `Sharing`

- **VNC**, відомий як “Screen Sharing” (tcp:5900)
- **SSH**, називається “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), або “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, відомий як “Remote Apple Event” (tcp:3031)

Перевірте, чи будь-яка з них увімкнена, запустивши:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) є покращеною версією [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), адаптованою для macOS, що пропонує додаткові функції. Помітною вразливістю в ARD є метод аутентифікації для пароля контролю екрану, який використовує лише перші 8 символів пароля, що робить його вразливим до [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) з такими інструментами, як Hydra або [GoRedShell](https://github.com/ahhh/GoRedShell/), оскільки немає стандартних обмежень швидкості.

Вразливі екземпляри можна виявити за допомогою скрипта `vnc-info` від **nmap**. Сервіси, що підтримують `VNC Authentication (2)`, особливо схильні до атак методом грубої сили через обрізання пароля до 8 символів.

Щоб увімкнути ARD для різних адміністративних завдань, таких як підвищення привілеїв, доступ до GUI або моніторинг користувачів, використовуйте наступну команду:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD надає різноманітні рівні контролю, включаючи спостереження, спільний контроль та повний контроль, з сесіями, які зберігаються навіть після зміни пароля користувача. Це дозволяє надсилати команди Unix безпосередньо, виконуючи їх як root для адміністративних користувачів. Планування завдань та пошук Remote Spotlight є помітними функціями, що полегшують віддалений, маловпливовий пошук чутливих файлів на кількох машинах.

#### Останні вразливості Screen-Sharing / ARD (2023-2025)

| Рік | CVE | Компонент | Вплив | Виправлено в |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Неправильне відображення сесії може призвести до передачі *неправильного* робочого столу або вікна, що призводить до витоку чутливої інформації|macOS Sonoma 14.2.1 (Грудень 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Обхід захисту пам'яті ядра, який можна з'єднати після успішного віддаленого входу (активно експлуатувався в природі)|macOS Ventura 13.6.4 / Sonoma 14.4 (Березень 2024) |

**Поради з посилення безпеки**

* Вимкніть *Screen Sharing*/*Remote Management*, коли це не є строго необхідним.
* Тримайте macOS повністю оновленою (Apple зазвичай випускає виправлення безпеки для останніх трьох основних версій).
* Використовуйте **Сильний Пароль** *та* забезпечте, щоб опція *“VNC viewers may control screen with password”* була **вимкнена** коли це можливо.
* Розмістіть сервіс за VPN замість того, щоб відкривати TCP 5900/3283 в Інтернет.
* Додайте правило брандмауера програми, щоб обмежити `ARDAgent` локальною підмережею:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Протокол

Bonjour, технологія, розроблена Apple, дозволяє **пристроям в одній мережі виявляти послуги, які вони пропонують**. Відомий також як Rendezvous, **Zero Configuration** або Zeroconf, він дозволяє пристрою приєднуватися до TCP/IP мережі, **автоматично вибирати IP-адресу** та транслювати свої послуги іншим мережевим пристроям.

Zero Configuration Networking, що надається Bonjour, забезпечує, що пристрої можуть:

- **Автоматично отримувати IP-адресу** навіть за відсутності DHCP-сервера.
- Виконувати **переклад імені в адресу** без необхідності в DNS-сервері.
- **Виявляти послуги**, доступні в мережі.

Пристрої, що використовують Bonjour, призначать собі **IP-адресу з діапазону 169.254/16** та перевірять її унікальність у мережі. Macs підтримують запис у таблиці маршрутизації для цієї підмережі, що можна перевірити за допомогою `netstat -rn | grep 169`.

Для DNS Bonjour використовує **протокол Multicast DNS (mDNS)**. mDNS працює через **порт 5353/UDP**, використовуючи **стандартні DNS-запити**, але націлюючись на **мульткаст-адресу 224.0.0.251**. Цей підхід забезпечує, що всі прослуховуючі пристрої в мережі можуть отримувати та відповідати на запити, полегшуючи оновлення своїх записів.

При приєднанні до мережі кожен пристрій самостійно вибирає ім'я, яке зазвичай закінчується на **.local**, що може бути похідним від імені хоста або випадково згенерованим.

Виявлення послуг у мережі полегшується за допомогою **DNS Service Discovery (DNS-SD)**. Використовуючи формат DNS SRV записів, DNS-SD використовує **DNS PTR записи** для можливості переліку кількох послуг. Клієнт, що шукає конкретну послугу, запитуватиме PTR запис для `<Service>.<Domain>`, отримуючи у відповідь список PTR записів у форматі `<Instance>.<Service>.<Domain>`, якщо послуга доступна з кількох хостів.

Утиліта `dns-sd` може бути використана для **виявлення та реклами мережевих послуг**. Ось кілька прикладів її використання:

### Пошук SSH Послуг

Щоб шукати SSH послуги в мережі, використовується наступна команда:
```bash
dns-sd -B _ssh._tcp
```
Ця команда ініціює перегляд для \_ssh.\_tcp сервісів і виводить деталі, такі як мітка часу, прапори, інтерфейс, домен, тип сервісу та ім'я екземпляра.

### Реклама HTTP Сервісу

Щоб рекламувати HTTP сервіс, ви можете використовувати:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ця команда реєструє HTTP-сервіс з назвою "Index" на порту 80 з шляхом `/index.html`.

Щоб потім шукати HTTP-сервіси в мережі:
```bash
dns-sd -B _http._tcp
```
Коли служба запускається, вона оголошує про свою доступність для всіх пристроїв у підмережі, мультикастуючи свою присутність. Пристрої, зацікавлені в цих службах, не повинні надсилати запити, а просто слухати ці оголошення.

Для більш зручного інтерфейсу додаток **Discovery - DNS-SD Browser**, доступний в Apple App Store, може візуалізувати служби, що пропонуються у вашій локальній мережі.

Альтернативно, можна написати власні скрипти для перегляду та виявлення служб, використовуючи бібліотеку `python-zeroconf`. Скрипт [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) демонструє створення браузера служб для `_http._tcp.local.`, виводячи додані або видалені служби:
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
### Перерахунок Bonjour через мережу

* **Nmap NSE** – виявлення служб, які рекламуються одним хостом:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Скрипт `dns-service-discovery` надсилає запит `_services._dns-sd._udp.local`, а потім перераховує кожен рекламований тип служби.

* **mdns_recon** – інструмент на Python, який сканує цілі діапазони в пошуках *неправильно налаштованих* mDNS відповідей, які відповідають на унікатні запити (корисно для знаходження пристроїв, доступних через підмережі/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Це поверне хости, які відкривають SSH через Bonjour за межами локальної мережі.

### Заходи безпеки та недавні вразливості (2024-2025)

| Рік | CVE | Серйозність | Проблема | Виправлено в |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Середня|Логічна помилка в *mDNSResponder* дозволила зловмисному пакету викликати **відмову в обслуговуванні**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Вересень 2024) |
|2025|CVE-2025-31222|Висока|Проблема коректності в *mDNSResponder* може бути використана для **локального підвищення привілеїв**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Травень 2025) |

**Рекомендації щодо пом'якшення**

1. Обмежте UDP 5353 до *локальної мережі* – заблокуйте або обмежте його на бездротових контролерах, маршрутизаторах та хостових брандмауерах.
2. Повністю вимкніть Bonjour на системах, які не потребують виявлення служб:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Для середовищ, де Bonjour потрібен внутрішньо, але ніколи не повинен перетинати мережеві межі, використовуйте обмеження профілю *AirPlay Receiver* (MDM) або mDNS проксі.
4. Увімкніть **Захист цілісності системи (SIP)** та підтримуйте macOS в актуальному стані – обидві вразливості були швидко виправлені, але залежали від увімкнення SIP для повного захисту.

### Вимкнення Bonjour

Якщо є побоювання щодо безпеки або інші причини для вимкнення Bonjour, його можна вимкнути за допомогою наступної команди:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Посилання

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
