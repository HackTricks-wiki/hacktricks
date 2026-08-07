# Тріаж локальної мережі та сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на Linux host найкорисніші мережеві цілі часто не відкриті ззовні. Сервіси, доступні лише через loopback, veth-мережі, Unix-сокети, тимчасові listeners, захоплення пакетів і локальні правила firewall можуть розкрити облікові дані або локальні attack surface.

Ця сторінка зосереджена на практичних локальних post-exploitation techniques, а не на загальному віддаленому network pentesting.

## Перелік loopback і локальних сервісів

Почніть із визначення listening services, їхніх bind addresses і процесу-власника, якщо це дозволяють permissions:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Важливі закономірності:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.
- `0.0.0.0:<port>`: доступні через усі інтерфейси IPv4, якщо доступ не фільтрується.
- `172.x`, `10.x` або `192.168.x` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, мережі контейнерів або локального lab.
- Unix sockets у `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні поверхні IPC.

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

Контейнеризовані середовища або лабораторні середовища часто відкривають сервіси лише через bridge або підмережу veth. Перелічіть інтерфейси та маршрути, перш ніж вважати, що сервіс недоступний:
```bash
ip -br addr
ip route
ip neigh
```
Знайти ймовірні локальні підмережі:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Обережно проскануйте виявлену підмережу:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Техніка корисна, коли web-панель, debug endpoint або helper service приховані від зовнішніх сканувань, але доступні з compromised host або container network.

## Local Pivot With socat or SSH

Якщо service прив'язаний до loopback, передайте його через дозволений channel замість зміни самого service.

Перенаправте локальний HTTP service лише через SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
З'єднайте локальний порт за допомогою `socat`, якщо ви вже маєте доступ до shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Перенаправлення Unix-сокета до TCP для локального тестування:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Це саме по собі нічого не exploit. Воно робить доступною для ваших інструментів поверхню, доступну лише локально, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing і прості протоколи

Не кожен сервіс є HTTP. Багато локальних сервісів leak достатньо інформації через банер або однорядковий протокол.

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
Перехоплення конкретного локального сервісу:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Розкодувати Basic Auth із перехопленого або записаного в журнал заголовка:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Корисні рядки, які варто шукати в текстових перехопленнях:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Якщо в лабораторному середовищі ви можете контролювати середовище процесу клієнта, `SSLKEYLOGFILE` може зробити TLS-сесії доступними для розшифрування у Wireshark або сумісних інструментах. Це корисно для аналізу локального HTTPS-трафіку без атак на сам TLS.

Запустіть клієнт із увімкненим логуванням ключів:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Захоплюйте трафік одночасно:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує ведення журналу ключів у стилі NSS і ви можете встановити середовище до встановлення з'єднання.

## Unix Socket Interaction and Command Injection

Unix sockets є локальними кінцевими точками IPC. Вони можуть надавати HTTP API, власні протоколи або небезпечні обробники команд.

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
Якщо керований користувачем socket input передається до shell або привілейованого helper, це може призвести до command injection. Для цілеспрямованого прикладу див. [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables і авторизовані зміни правил

Локальні правила firewall можуть пояснити, чому сервіс видимий локально, але заблокований віддалено, або чому високий порт здається недоступним з одного інтерфейсу.

Перевірте правила:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Шукайте відкидання пакетів, що впливають на цільовий порт:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
В авторизованій лабораторії видаліть конкретне блокувальне правило за ідентифікатором handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Надавайте перевагу видаленню точного handle, а не очищенню всіх таблиць. Техніка полягає в тому, щоб визначити точний фільтр, який спричиняє таку поведінку, і змінити лише це правило.

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
Надавайте пріоритет службам, які доступні лише локально, працюють від імені привілейованого користувача, надають адміністративні функції або функції налагодження чи довіряють клієнтам із loopback/container network.

{{#include ../../banners/hacktricks-training.md}}
