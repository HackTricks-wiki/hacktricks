# Локальний аналіз мережі та сокетів

{{#include ../../banners/hacktricks-training.md}}

Після отримання shell на Linux-хості найкорисніші мережеві цілі часто не доступні ззовні. Сервіси, доступні лише через loopback, мережі veth, Unix-сокети, тимчасові listeners, захоплення пакетів і локальні правила firewall можуть розкрити облікові дані або локальні attack surface.

Ця сторінка зосереджена на практичних локальних техніках post-exploitation, а не на загальному remote network pentesting.

## Перерахування loopback і локальних сервісів

Почніть із визначення сервісів, що прослуховують з’єднання, їхніх bind-адрес і процесу-власника, якщо це дозволяють права:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Важливі закономірності:

- `127.0.0.1:<port>` або `[::1]:<port>`: за замовчуванням доступні лише з хоста.
- `0.0.0.0:<port>`: доступні через усі інтерфейси IPv4, якщо не фільтруються.
- `172.x`, `10.x` або `192.168.x` на `veth*`, `docker*`, `br-*`, `cni*`: імовірно, мережі контейнерів або локальних лабораторій.
- Unix-сокети в `/run`, `/var/run`, `/tmp` або каталогах застосунків: локальні поверхні IPC.

Зіставте локальні порти за допомогою легких перевірок:
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

Контейнеризовані або лабораторні середовища часто відкривають доступ до сервісів лише через bridge або підмережу veth. Перелічіть інтерфейси та маршрути, перш ніж вважати, що сервіс недоступний:
```bash
ip -br addr
ip route
ip neigh
```
Знайдіть ймовірні локальні підмережі:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Обережно перевірте виявлену підмережу:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Ця техніка корисна, коли web-панель, debug endpoint або допоміжний сервіс прихований від зовнішніх сканувань, але доступний із compromised host або мережі container.

## Local Pivot за допомогою socat або SSH

Якщо сервіс прив’язаний до loopback, відкрийте до нього доступ через дозволений канал, не змінюючи сам сервіс.

Перенаправте локальний HTTP-сервіс через SSH:
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
Це саме по собі нічого не експлуатує. Воно робить доступною з вашого tooling локальну поверхню, щоб ви могли взаємодіяти з нею як зі звичайним сервісом.

## Banner Grabbing та прості протоколи

Не кожен сервіс працює через HTTP. Багато локальних сервісів leak достатньо інформації через banner або однорядковий протокол.

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

## Захоплення Loopback-трафіку

Локальний трафік може розкривати заголовки, bearer tokens, облікові дані Basic Auth або специфічні для застосунку секрети. Виконуйте захоплення лише в авторизованих середовищах.

Захоплення Loopback HTTP-трафіку:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Перехоплення певного локального сервісу:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Розкодувати Basic Auth із перехопленого або записаного в логах заголовка:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Корисні рядки, які слід шукати в текстових перехопленнях:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Якщо ви можете контролювати середовище процесу клієнта в лабораторії, `SSLKEYLOGFILE` може зробити TLS-сеанси придатними для розшифрування у Wireshark або сумісних інструментах. Це корисно для розуміння локального HTTPS-трафіку без безпосередньої атаки на TLS.

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
Потім завантажте `/tmp/tls.pcap` і `/tmp/sslkeys.log` у Wireshark. Це працює лише тоді, коли клієнтська бібліотека підтримує ведення журналу ключів у стилі NSS і ви можете встановити середовище до встановлення з’єднання.

## Взаємодія з Unix-сокетами та Command Injection

Unix-сокети є локальними кінцевими точками IPC. Вони можуть надавати HTTP API, користувацькі протоколи або небезпечні обробники команд.

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
Взаємодіяти з raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Якщо керований користувачем ввід через socket передається до shell або привілейованого helper, це може призвести до command injection. Для цілеспрямованого прикладу див. [Socket Command Injection](socket-command-injection.md).

## Перевірка nftables і авторизовані зміни правил

Локальні правила firewall можуть пояснити, чому service доступний локально, але заблокований віддалено, або чому високий порт здається недоступним через один з інтерфейсів.

Перегляньте правила:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Шукайте правила DROP, що впливають на цільовий порт:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
В авторизованій лабораторії видаліть конкретне правило блокування за handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Надавайте перевагу видаленню точного handle, а не очищенню всіх таблиць. Суть техніки полягає в тому, щоб визначити точний фільтр, який спричиняє таку поведінку, і змінити лише це правило.

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
Надавайте пріоритет службам, доступним лише локально, що працюють від імені користувача з вищими привілеями, надають адміністративні функції або функції налагодження чи довіряють клієнтам loopback/container-network.
{{#include ../../banners/hacktricks-training.md}}
