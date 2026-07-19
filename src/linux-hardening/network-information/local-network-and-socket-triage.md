# Тріаж локальної мережі та сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на Linux-хості найкорисніші мережеві цілі часто не доступні ззовні. Сервіси, доступні лише через loopback, мережі veth, Unix-сокети, тимчасові listeners, захоплення пакетів і локальні правила firewall можуть розкрити облікові дані або локальні attack surface.

Ця сторінка зосереджена на практичних техніках локального post-exploitation, а не на загальному віддаленому network pentesting.

## Перелік loopback і локальних сервісів

Почніть із визначення сервісів, що прослуховують з’єднання, їхніх bind-адрес і процесу-власника, якщо це дозволяють права:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Важливі закономірності:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.
- `0.0.0.0:<port>`: доступні через усі IPv4-інтерфейси, якщо доступ не фільтрується.
- `172.x`, `10.x` або `192.168.x` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, мережі контейнерів або локальні лабораторні мережі.
- Unix sockets у `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні IPC-поверхні.

Зіставте локальні порти за допомогою легких probes:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Використовуйте `nmap` локально, якщо він доступний:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Приховані veth і підмережі контейнерів

Контейнеризовані або лабораторні середовища часто відкривають сервіси лише через bridge або підмережу veth. Перш ніж вважати, що сервіс недоступний, проведіть інвентаризацію інтерфейсів і маршрутів:
```bash
ip -br addr
ip route
ip neigh
```
Знайти ймовірні локальні підмережі:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Обережно перевірте виявлену підмережу:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Ця техніка корисна, коли web-панель, debug endpoint або допоміжний сервіс приховані від зовнішнього сканування, але доступні з compromised host або мережі контейнера.

## Local Pivot за допомогою socat або SSH

Якщо сервіс прив’язаний до loopback, відкрийте до нього доступ через дозволений канал, не змінюючи сам сервіс.

Пробросьте локальний HTTP-сервіс через SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
З’єднайте локальний порт через `socat`, якщо ви вже маєте доступ до shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Перенаправити Unix-сокет у TCP для локального тестування:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Це саме по собі нічого не експлуатує. Воно робить локально доступну поверхню досяжною з ваших інструментів, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing і прості протоколи

Не кожен сервіс працює через HTTP. Багато локальних сервісів розкривають достатньо інформації через банер або однорядковий протокол.

Базові probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Перевірка HTTP без браузера:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Для TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Мета полягає у визначенні протоколу, схеми автентифікації, версії та того, чи довіряє сервіс локальним клієнтам.

## Перехоплення Loopback-трафіку

Локальний трафік може розкривати заголовки, bearer-токени, облікові дані Basic Auth або специфічні для застосунку секрети. Перехоплюйте трафік лише в авторизованих середовищах.

Перехоплення loopback HTTP-трафіку:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Захоплення певного локального сервісу:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Декодування Basic Auth із перехопленого або записаного в журнал заголовка:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Корисні рядки, які слід шукати в текстових перехопленнях:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## Журналювання ключів TLS

Якщо в лабораторії ви можете контролювати середовище процесу клієнта, `SSLKEYLOGFILE` може зробити TLS-сеанси доступними для розшифрування у Wireshark або сумісних інструментах. Це корисно для розуміння локального HTTPS-трафіку без атак на сам TLS.

Запустіть клієнт із увімкненим журналюванням ключів:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Одночасно захоплюйте трафік:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує журналювання ключів у стилі NSS і ви можете встановити середовище до встановлення з'єднання.

## Взаємодія з Unix-сокетами та Command Injection

Unix-сокети є локальними кінцевими точками IPC. Вони можуть надавати HTTP API, власні протоколи або небезпечні обробники команд.

Знайдіть сокети:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Взаємодіяти з HTTP через Unix-сокет:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Взаємодія з raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Якщо введені користувачем дані через socket передаються до shell або привілейованого helper, це може призвести до command injection. Зосереджений приклад див. у [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables і санкціоновані зміни правил

Локальні правила firewall можуть пояснити, чому сервіс видимий локально, але заблокований віддалено, або чому високий порт здається недоступним через один з інтерфейсів.

Перегляньте правила:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Шукайте відкинуті пакети, що впливають на цільовий порт:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
В авторизованій лабораторії видаліть конкретне правило блокування за його ідентифікатором:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Надавайте перевагу видаленню точного handle замість очищення всіх таблиць. Техніка полягає у визначенні точного фільтра, який спричиняє таку поведінку, і зміні лише цього правила.

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
Пріоритезуйте служби, доступні лише локально, що працюють від імені привілейованішого користувача, надають адміністративні/debug-функції або довіряють клієнтам loopback/container-network.
