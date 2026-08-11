# Тріаж локальної мережі та сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на Linux-хості найкорисніші мережеві цілі часто не відкриті ззовні. Сервіси, доступні лише через loopback, мережі veth, Unix-сокети, тимчасові слухачі, захоплення пакетів і локальні правила firewall можуть розкрити облікові дані або локальні поверхні атаки.

Ця сторінка зосереджена на практичних локальних post-exploitation techniques, а не на загальному віддаленому мережевому pentesting.

## Перелік loopback і локальних сервісів

Почніть із визначення сервісів, які прослуховують з'єднання, їхніх адрес прив'язки та процесу-власника, якщо це дозволяють права доступу.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Важливі закономірності:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: доступні через усі IPv4-інтерфейси, якщо доступ не фільтрується.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` або `192.168.0.0/16` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, container або локальні lab-мережі.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-сокети в `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні IPC-поверхні.<sup>[[5]](#references)</sup>

Визначайте локальні порти за допомогою легких probe.<sup>[[6]](#references)[[7]](#references)</sup>
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

Контейнеризовані середовища або лабораторні середовища часто відкривають доступ до сервісів лише через bridge або підмережу veth. Перелічіть інтерфейси та маршрути, перш ніж вважати, що сервіс недоступний.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Знайдіть ймовірні локальні підмережі.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Обережно проскануйте виявлену підмережу.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Цей метод корисний, коли web-панель, debug endpoint або допоміжний сервіс прихований від зовнішніх сканувань, але доступний із скомпрометованого хоста або мережі контейнера.

## Локальний pivot за допомогою socat або SSH

Якщо сервіс прив’язаний до loopback, відкрийте до нього доступ через дозволений канал, не змінюючи сам сервіс.

Перенаправте локальний HTTP-сервіс, доступний лише локально, за допомогою SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Прокиньте локальний порт за допомогою `socat`, якщо ви вже маєте доступ до shell.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Перенаправте Unix-сокет до TCP для локального тестування.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Це саме по собі нічого не експлуатує. Воно робить поверхню, доступну лише локально, досяжною з ваших інструментів, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing і прості протоколи

Не кожен сервіс працює через HTTP. Багато локальних сервісів розкривають достатньо інформації через банер або однорядковий протокол.

Базові probes.<sup>[[13]](#references)</sup>
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
Мета полягає у визначенні протоколу, схеми автентифікації, версії та того, чи довіряє сервіс локальним клієнтам.

## Перехоплення loopback-трафіку

Локальний трафік може розкрити заголовки, bearer-токени, облікові дані Basic Auth або специфічні для застосунку секрети.<sup>[[17]](#references)[[25]](#references)</sup> Перехоплюйте трафік лише в авторизованих середовищах.

Перехоплюйте loopback HTTP-трафік.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Захопити конкретну локальну службу.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Розкодуйте Basic Auth із перехопленого або записаного в журналі заголовка.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Корисні рядки для пошуку в текстових захопленнях:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Якщо в лабораторії ви можете контролювати середовище процесу клієнта, `SSLKEYLOGFILE` може зробити сеанси TLS доступними для розшифрування у Wireshark або сумісних інструментах.<sup>[[19]](#references)[[20]](#references)</sup> Це корисно для розуміння локального HTTPS-трафіку без атаки на сам TLS.

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
Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує журналювання ключів у стилі NSS і ви можете встановити середовище до встановлення з'єднання.<sup>[[20]](#references)[[21]](#references)</sup>

## Взаємодія з Unix-сокетами та ін'єкція команд

Unix-сокети є локальними кінцевими точками IPC.<sup>[[5]](#references)</sup> Вони можуть надавати HTTP API, користувацькі протоколи або небезпечні обробники команд.<sup>[[12]](#references)[[14]](#references)</sup>

Знайдіть сокети.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Взаємодіяти з HTTP через Unix-сокет.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Взаємодіяти з raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Якщо контрольований користувачем ввід через socket передається до shell або privileged helper, це може призвести до command injection.<sup>[[26]](#references)</sup> Для цілеспрямованого прикладу див. [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables та авторизовані зміни правил

Локальні правила firewall можуть пояснити, чому сервіс локально видимий, але заблокований віддалено, або чому високий порт здається недоступним з одного інтерфейсу.<sup>[[22]](#references)</sup>

Перегляньте правила.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Шукайте drops, що впливають на цільовий порт.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
В авторизованій лабораторії видаліть конкретне правило блокування за його ідентифікатором.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Надавайте перевагу видаленню точного handle, а не очищенню цілих таблиць. Техніка полягає у визначенні точного фільтра, що спричиняє таку поведінку, і зміні лише цього правила.<sup>[[22]](#references)</sup>

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
Надавайте пріоритет сервісам, які доступні лише локально, працюють від імені привілейованого користувача, надають адміністративні/debug-функції або довіряють клієнтам loopback/container-network.

## References

- [1] [ss(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Архітектура адресації IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Перенаправлення (довідковий посібник Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [виклик timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Методи сканування портів (довідковий посібник Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Виявлення хостів (довідковий посібник Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Специфікація портів і порядок сканування (довідковий посібник Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — сторінка посібника OpenBSD](https://man.openbsd.org/nc.1)
- [14] [посібник інструмента командного рядка curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — документація OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: схема HTTP-аутентифікації «Basic»](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [виклик base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — документація OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Посібник користувача Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [посібник nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Розподіл адрес для приватних мереж (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Платформа авторизації OAuth 2.0: використання токенів Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Неправильна нейтралізація спеціальних елементів, використаних в OS Command](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
