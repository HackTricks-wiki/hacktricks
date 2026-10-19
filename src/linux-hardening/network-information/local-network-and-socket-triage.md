# Тріаж локальної мережі та сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на хості Linux найкорисніші мережеві цілі часто не доступні ззовні. Служби, доступні лише через loopback, мережі veth, Unix-сокети, тимчасові слухачі, перехоплення пакетів і локальні правила firewall можуть розкрити облікові дані або локальні поверхні для атак.

Ця сторінка присвячена практичним локальним технікам post-exploitation, а не загальному віддаленому pentesting.

## Перелік служб loopback і локальних служб

Спершу визначте служби, що прослуховують з’єднання, їхні адреси прив’язки та процес-власник, якщо це дозволяють права доступу.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Важливі шаблони:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: доступні через усі інтерфейси IPv4, якщо доступ не фільтрується.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` або `192.168.0.0/16` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, мережі контейнерів або локального лабораторного середовища.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-сокети в `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні поверхні IPC.<sup>[[5]](#references)</sup>

Для історичної проблеми з парсингом сокетів у [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), перевірте запущений демон, його локальний API-сокет і встановлений пакет або ревізію snap на наявність виправлення для відповідного дистрибутива. Помилка стосувалася перевірки snapd адреси сокета клієнта, а не `snap-confine`; сам факт наявності файла `snap-confine` із set-user-ID або рядка версії upstream не дає змоги встановити, чи є система вразливою. Ubuntu постачала виправлення у версіях пакетів, специфічних для кожного випуску, а snapd міг оновлюватися через snap незалежно від пакета дистрибутива. Перш ніж оцінювати межу привілейованого API, перевірте фактичну збірку, що запущена, і доступність локального сокета. Під час пасивного переліку не надсилайте спеціально сформований запит до сокета й не встановлюйте snap.

Слухач loopback, запущений через [`socat` з `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html), може передавати локальний клієнтський ввід окремій програмі. Перш ніж розглядати власний сервіс, що належить root, як можливий шлях до підвищення привілеїв, зіставте команду слухача, шлях до виконуваного файла, ідентичність дочірнього процесу, доступність із локальної системи та автентифікацію. Порушення безпеки пам’яті або небезпечний шлях від вводу до команди потребують доказів для конкретного бінарного файла й збірки; самі лише номер порту, процес `socat` або власник root цього не підтверджують. Пасивний перелік має обмежуватися метаданими процесу, сокета й файла, а не надсиланням даних до сервісу.

Локальний Salt master може слухати TCP-порти 4505 і 4506, зокрема на loopback або порту хоста, опублікованому контейнером. У [примітках до випуску Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) описано вразливість CVE-2020-11651, яка давала змогу викликати методи без автентифікації та була виправлена в upstream-версіях 2019.2.4 і 3000.2. Перш ніж розглядати це як можливий шлях до підвищення привілеїв, зіставте слухач із фактичним процесом `salt-master`, доступним інтерфейсом, встановленим пакетом і виправленнями постачальника, а також із фактичною ідентичністю контейнера чи хоста; самі лише порт або upstream-версія нічого не доводять. Якщо master працює в контейнері, вплив на root хоста — це окрема межа: перевірте, чи змонтовано в контейнер доступний сокет API середовища виконання хоста, до якого є доступ. Під час пасивного переліку не надсилайте запити до сервера Salt і не створюйте контейнер, щоб визначити наявність вразливості. Див. [документацію Salt щодо портів](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) і [тріаж API середовища виконання](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Визначайте локальні порти за допомогою легких проб.<sup>[[6]](#references)[[7]](#references)</sup>

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

У контейнеризованих або лабораторних середовищах сервіси часто доступні лише через підмережу bridge або veth. Перш ніж вважати сервіс недоступним, перелічіть інтерфейси та маршрути.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Знайдіть імовірні локальні підмережі.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Обережно дослідіть виявлену підмережу.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Техніка корисна, коли вебпанель, налагоджувальна кінцева точка або допоміжна служба прихована від зовнішнього сканування, але доступна зі скомпрометованого хоста або мережі контейнера.

## Токени служби Notebook між обліковими записами користувачів

Служба Notebook, прив’язана до loopback, може використовувати для автентифікації токен запуску, виведений у процесний журнал. Якщо цей вивід перенаправлено до журналу, доступного для читання іншому локальному обліковому запису, токен може перетнути межу між користувачами й дозволити виконання коду від імені облікового запису сервера Notebook. Перш ніж розглядати шлях до журналу як потенційну можливість підвищення привілеїв, зіставте власника процесу, що прослуховує порт, місце збереження журналу та його дозволи, поточну конфігурацію токена й засоби контролю доступу до Notebook. Під час пасивної розвідки перевіряйте метадані журналів; не виводьте токени й не підключайтеся до служби лише для класифікації хоста.

Служба Jupyter Lab також може розкривати свій токен у доступному для читання `ExecStart` systemd або в командному рядку запущеного процесу (`ps auxww`), а не лише в журналах запуску. У наведеному прикладі `User=analyst` і `--ServerApp.token` вказували як на облікові дані, так і на обліковий запис, від імені якого працював процес, що прослуховував `127.0.0.1:8888`. Маючи доступ до хоста, токен і `ssh -L 8888:127.0.0.1:8888 user@host` дали змогу отримати доступ до Terminal у Jupyter Lab від імені користувача служби. Перевіряйте разом ефективного користувача юніта, аргументи процесу, порт прослуховування та чинність токена; прив’язка до loopback сама по собі не є межею авторизації.<sup>[[28]](#references)</sup>

## Локальний Pivot за допомогою socat або SSH

Якщо служба прив’язана до loopback, надайте до неї доступ через дозволений канал замість зміни самої служби.

Перенаправте локальну HTTP-службу через SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

З'єднайте локальний порт через `socat`, якщо вже маєте доступ до shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Пробросьте Unix-сокет на TCP для локального тестування.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Це саме по собі нічого не експлуатує. Воно робить поверхню, доступну лише локально, доступною з ваших інструментів, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing і прості протоколи

Не кожен сервіс використовує HTTP. Багато локальних сервісів leak достатньо інформації через банер або однорядковий протокол.

Базові перевірки.<sup>[[13]](#references)</sup>

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

Для listener на aiohttp перевірте конфігурацію static route, а також версію. CVE-2024-23334 стосується aiohttp до версії 3.9.2, якщо для static route увімкнено `follow_symlinks=True`: запити до цього маршруту можуть читати файли поза кореневим каталогом статики. Якщо сервіс працює від root, він може відкривати файли, доступні для читання root, за умови, що маршрут доступний. Банер версії або прив’язка до loopback самі по собі не підтверджують вразливу конфігурацію чи доступ до файлів.<sup>[[27]](#references)</sup>

## Захоплення loopback-трафіку

Локальний трафік може розкривати заголовки, bearer-токени, облікові дані Basic Auth або специфічні для застосунку секрети.<sup>[[17]](#references)[[25]](#references)</sup> Захоплюйте трафік лише в авторизованих середовищах.

Захоплюйте loopback HTTP-трафік.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Перехопіть трафік конкретної локальної служби.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Декодуйте Basic Auth із перехопленого або занесеного до журналу заголовка.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Корисні рядки для пошуку в текстових дампах:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Журналювання ключів TLS

Якщо в лабораторії ви можете контролювати середовище процесу клієнта, `SSLKEYLOGFILE` дає змогу розшифровувати TLS-сеанси у Wireshark або сумісних інструментах.<sup>[[19]](#references)[[20]](#references)</sup> Це корисно для аналізу локального HTTPS-трафіку без атак на сам TLS.

Запустіть клієнт з увімкненим журналюванням ключів.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Захоплюйте трафік одночасно.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує журналювання ключів у стилі NSS і ви можете налаштувати середовище до встановлення з’єднання.<sup>[[20]](#references)[[21]](#references)</sup>

## Взаємодія з Unix-сокетами та Command Injection

Unix-сокети — це локальні кінцеві точки IPC.<sup>[[5]](#references)</sup> Вони можуть надавати HTTP API, власні протоколи або небезпечні обробники команд.<sup>[[12]](#references)[[14]](#references)</sup>

Сокет, власником якого є root і для групи якого встановлено дозвіл на запис, — це межа авторизації, а не вразливість сама по собі. Порівняйте його групу й режим доступу з поточним обліковим записом, визначте процес, що прослуховує сокет, і перевірте, які дані цей процес приймає від клієнтів, перш ніж оцінювати ризик. Зокрема, привілейована служба, яка виконує переданий PHP-код, може перетнути ще одну межу, якщо також довіряє шляху до `php.ini`, вибраному викликачем, або дозволяє йому змінювати `disable_functions` чи `open_basedir`; перевірте фактичну конфігурацію та шлях валідації служби. У [посібнику з конфігурації PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) описано ці директиви. Самі лише метадані сокета не підтверджують можливість виконання коду.

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

Якщо введені користувачем дані із сокета передаються до shell або привілейованого допоміжного процесу, це може призвести до command injection.<sup>[[26]](#references)</sup> Приклад див. у розділі [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables і авторизована зміна правил

Правила локального брандмауера можуть пояснити, чому служба видима локально, але заблокована ззовні, або чому високий порт недоступний через певний інтерфейс.<sup>[[22]](#references)</sup>

Перевірте правила.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Шукайте відкидання пакетів, що впливають на цільовий порт.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

В авторизованій лабораторії видаліть конкретне правило блокування за handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Надавайте перевагу видаленню точного handle, а не очищенню цілих таблиць. Техніка полягає в тому, щоб визначити точне правило фільтрації, яке спричиняє таку поведінку, і змінити лише його.<sup>[[22]](#references)</sup>

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

Надавайте пріоритет службам, які доступні лише локально, працюють від імені привілейованішого користувача, надають функції адміністрування/налагодження або довіряють клієнтам із loopback/мережі контейнерів.

## References

- [1] [ss(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Архітектура адресації IP версії 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Перенаправлення (довідковий посібник Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [виклик timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Методи сканування портів (довідник Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Виявлення вузлів (довідник Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Специфікація портів і порядок сканування (довідник Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — сторінка посібника OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Посібник з інструмента командного рядка curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — документація OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Схема HTTP-аутентифікації «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [виклик base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — документація OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — вікі Wireshark](https://wiki.wireshark.org/tls)
- [21] [Посібник користувача Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Посібник nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Розподіл адрес для приватних мереж (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Фреймворк авторизації OAuth 2.0: використання токенів Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Неналежна нейтралізація спеціальних символів в OS-команді](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Повідомлення від супроводжувачів aiohttp: обхід шляхів у статичних маршрутах із follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — токен Jupyter відкрито через systemd і аргументи процесу](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
