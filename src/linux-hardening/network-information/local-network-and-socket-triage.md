# Локальна мережа та аналіз сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на Linux-хості найкорисніші мережеві цілі часто не доступні ззовні. Служби, доступні лише через loopback, мережі veth, Unix-сокети, тимчасові listeners, захоплення пакетів і локальні правила firewall можуть розкрити облікові дані або поверхні атаки, доступні лише локально.

На цій сторінці розглянуто практичні локальні техніки post-exploitation, а не загальний remote network pentesting.

## Перелік служб, доступних через loopback і локальних служб

Спочатку визначте служби, що прослуховують з’єднання, адреси, на яких вони прив’язані, і процес-власник, якщо дозволяють права доступу.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Важливі закономірності:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: доступні через усі інтерфейси IPv4, якщо доступ не обмежено фільтрацією.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` або `192.168.0.0/16` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, мережі контейнерів або локального лабораторного середовища.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-сокети в `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні поверхні IPC.<sup>[[5]](#references)</sup>

Для історичної [проблеми розбору сокетів snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) перевірте запущений daemon, його локальний API-сокет і встановлений пакет або ревізію snap на наявність виправлення для відповідного дистрибутива. Помилка стосувалася перевірки snapd адреси сокета клієнта, а не `snap-confine`; файл `snap-confine` із set-user-ID або сам рядок версії upstream не підтверджують наявність вразливості. Ubuntu постачала виправлення у версіях пакетів, специфічних для кожного релізу, а snapd міг оновитися через snap окремо від пакета дистрибутива. Перш ніж оцінювати межу привілейованого API, перевірте фактичну збірку, що запущена, і доступність локального сокета. Пасивне перерахування не повинно надсилати спеціально сформований запит сокету або встановлювати snap.

Listener loopback, запущений через [`socat` з `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html), може передавати локальні дані клієнта окремій програмі. Перш ніж вважати власний сервіс, що належить root, потенційним шляхом підвищення привілеїв, зіставте команду listener, шлях до виконуваного файла, ефективну ідентичність дочірнього процесу, локальну доступність і автентифікацію. Для підтвердження помилки безпеки пам’яті або небезпечного шляху від введених даних до команди потрібні докази щодо конкретного бінарного файла та його збірки; сам номер порту, процес `socat` або власник root цього не підтверджують. Пасивне перерахування має обмежуватися метаданими процесу, сокета й файла, а не надсиланням даних сервісу.

Локальний Salt master може слухати TCP-порти 4505 і 4506, зокрема на loopback або опублікованому контейнером порту хоста. [Примітки до випуску Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) описують вразливість CVE-2020-11651, яка давала змогу викликати методи без автентифікації; її виправили в upstream-версіях 2019.2.4 і 3000.2. Перш ніж вважати її потенційним шляхом підвищення привілеїв, зіставте listener із фактичним процесом `salt-master`, доступним інтерфейсом, встановленим пакетом і виправленнями постачальника, а також ефективною ідентичністю контейнера або хоста; сам порт або версія upstream не є доказом. Якщо master працює в контейнері, вплив на root хоста — це окрема межа: перевірте, чи змонтовано в контейнер доступний сокет API середовища виконання хоста, і чи можна ним скористатися. Пасивне перерахування не повинно надсилати запити до сервера запитів Salt або створювати контейнер для визначення наявності вразливості. Див. [документацію Salt щодо портів](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) і [тріаж API середовища виконання](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Перевіряйте локальні порти за допомогою легких проб.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Використовуйте `nmap` локально, якщо він доступний.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Приховані veth і підмережі контейнерів

У контейнеризованих або лабораторних середовищах служби часто доступні лише через bridge або підмережу veth. Перелічіть інтерфейси й маршрути, перш ніж вважати службу недоступною.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Знайдіть ймовірні локальні підмережі.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Обережно зондуйте виявлену підмережу.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Ця техніка корисна, коли вебпанель, debug endpoint або допоміжна служба приховані від зовнішнього сканування, але доступні з скомпрометованого хоста чи мережі контейнера.

Служба notebook на loopback-інтерфейсі може використовувати для автентифікації токен запуску, виведений у вивід процесу. Якщо цей вивід перенаправлено до журналу, доступного іншому локальному обліковому запису, токен може перетнути межу між користувачами й дозволити виконання коду від імені облікового запису сервера notebook. Перш ніж вважати шлях до журналу вектором підвищення привілеїв, зіставте власника процесу, що прослуховує порт, розташування журналу та дозволи на нього, поточні налаштування токена й засоби контролю доступу до notebook. Під час пасивного перерахування переглядайте метадані журналів; не виводьте токени й не підключайтеся до служби лише для класифікації хоста.

## Локальний pivot за допомогою socat або SSH

Якщо служба прив’язана до loopback-інтерфейсу, відкрийте до неї доступ через дозволений канал, а не змінюйте саму службу.

Перенаправте локальну HTTP-службу за допомогою SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Прокиньте локальний порт за допомогою `socat`, якщо вже маєте доступ до shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Перенаправте Unix-сокет у TCP для локального тестування.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Це саме по собі нічого не експлуатує. Воно робить доступною лише локальну поверхню атаки з ваших інструментів, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing і прості протоколи

Не кожен сервіс використовує HTTP. Багато локальних сервісів розкривають достатньо інформації через банер або однорядковий протокол.

Базові проби.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

Перевірка HTTP без браузера.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Для TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Мета — визначити протокол, схему автентифікації, версію та те, чи довіряє сервіс локальним клієнтам.

Для aiohttp listener перевірте конфігурацію static route і версію. CVE-2024-23334 стосується aiohttp до версії 3.9.2, якщо для static route увімкнено `follow_symlinks=True`: запити до цього маршруту можуть читати файли за межами static root. Якщо сервіс працює від root, він може надавати доступ до файлів, доступних для читання root, за умови, що маршрут доступний. Банер версії або прив’язка до loopback самі по собі не підтверджують наявність вразливої конфігурації чи доступ до файлів.<sup>[[27]](#references)</sup>

## Захоплення loopback-трафіку

Локальний трафік може містити заголовки, bearer tokens, облікові дані Basic Auth або специфічні для застосунку секрети.<sup>[[17]](#references)[[25]](#references)</sup> Захоплюйте трафік лише в авторизованих середовищах.

Захоплення HTTP-трафіку loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Захоплення певної локальної служби.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Декодуйте Basic Auth із перехопленого або записаного в журнал заголовка.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Корисні рядки, які варто шукати в текстових дампах:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Журналювання ключів TLS

Якщо в лабораторному середовищі ви можете керувати змінними середовища процесу клієнта, `SSLKEYLOGFILE` дає змогу розшифровувати TLS-сеанси у Wireshark або сумісних інструментах.<sup>[[19]](#references)[[20]](#references)</sup> Це корисно для аналізу локального HTTPS-трафіку без атак на сам TLS.

Запустіть клієнт із увімкненим журналюванням ключів.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Захоплюйте трафік одночасно.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує журналювання ключів у стилі NSS і ви можете встановити змінну середовища до встановлення з’єднання.<sup>[[20]](#references)[[21]](#references)</sup>

## Взаємодія з Unix-сокетами та Command Injection

Unix-сокети — це локальні кінцеві точки IPC.<sup>[[5]](#references)</sup> Вони можуть надавати HTTP API, власні протоколи або небезпечні обробники команд.<sup>[[12]](#references)[[14]](#references)</sup>

Сокет, власником якого є root і для групи якого встановлено право запису, є межею авторизації, але сам по собі не є вразливістю. Перевірте його групу та режим доступу відносно поточного облікового запису, визначте процес, що прослуховує сокет, і з’ясуйте, які дані цей процес приймає від клієнтів, перш ніж оцінювати ризик. Зокрема, привілейована служба, яка виконує надісланий PHP-код, може перетнути ще одну межу, якщо також довіряє вибраному викликачем шляху до `php.ini` або дозволяє викликачу змінювати `disable_functions` чи `open_basedir`; перевірте ефективну конфігурацію та шлях валідації служби. У [посібнику з конфігурації PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) описано ці директиви. Самі лише метадані сокета не свідчать про можливість виконання коду.

Знайдіть сокети.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Взаємодійте з HTTP через Unix-сокет.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Взаємодійте з raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Якщо дані з сокета, контрольовані користувачем, передаються до shell або привілейованого helper, це може призвести до command injection.<sup>[[26]](#references)</sup> Приклад див. у розділі [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables і авторизована зміна правил

Локальні правила firewall можуть пояснити, чому сервіс доступний локально, але заблокований ззовні, або чому високий порт недоступний через певний інтерфейс.<sup>[[22]](#references)</sup>

Перевірте правила.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Шукайте відкидання трафіку, що впливають на цільовий порт.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

У дозволеній лабораторії видаліть конкретне правило блокування за його дескриптором.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Надавайте перевагу видаленню точного handle, а не очищенню цілих таблиць. Техніка полягає в тому, щоб визначити конкретний фільтр, який спричиняє таку поведінку, і змінити лише це правило.<sup>[[22]](#references)</sup>

## Швидкий робочий процес

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Надавайте пріоритет службам, доступним лише локально, запущеним від імені користувача з вищими привілеями, які надають функції адміністрування/налагодження або довіряють клієнтам із loopback/мережі контейнерів.

## References

- [1] [ss(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Архітектура адресації IP версії 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Перенаправлення (довідковий посібник Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [виклик timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Методи сканування портів (довідник Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Виявлення хостів (довідник Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Визначення портів і порядок сканування (довідник Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — сторінка посібника OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Посібник із командного рядка curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — документація OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Схема HTTP-автентифікації «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [виклик base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — документація OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — вікі Wireshark](https://wiki.wireshark.org/tls)
- [21] [Посібник користувача Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Посібник nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Розподіл адрес для приватних мереж (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Інфраструктура авторизації OAuth 2.0: використання токенів Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Неналежна нейтралізація спеціальних символів, що використовуються в команді ОС](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Повідомлення супровідників aiohttp: обхід маршрутів static із follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
