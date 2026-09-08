# Лабораторні роботи з авторизованої емуляції супротивника

Ці вправи відтворюють **архітектуру, яку можна спостерігати**, а не несанкціоновану компрометацію. Виконуйте їх на виділеному Linux-хості для лабораторних робіт із Docker, без конфіденційних облікових даних і без маршрутів до сторонніх цілей. Назви фіксовані, щоб teardown був однозначним.

{% hint style="danger" %}
Не замінюйте наведені власні контейнери, APs, маршрутизатори, облікові записи або синтетичні транзакції загальнодоступними проксі, Wi-Fi сусіда, production CDN tenant, яким ви не керуєте, або реальними незаконними коштами. Письмовий дозвіл має охоплювати кожну систему та радіосередовище.
{% endhint %}

## Лабораторна робота 1: власний ORB і ланцюжок redirector

**Мета:** показати, що target записує лише exit, тоді як кожен relay бачить сусідні hops. Це імітує структуру T1090.003/T1584 без скомпрометованих пристроїв.

**Вимоги:** Docker Engine і невикористані назви контейнерів, що починаються з `ht-orb-`.

### Створення
```bash
docker network create ht-orb-entry
docker network create ht-orb-transit
docker network create ht-orb-target

docker run -d --name ht-orb-target --network ht-orb-target nginx:alpine

docker run -d --name ht-orb-r2 --network ht-orb-transit \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-target:80
docker network connect ht-orb-target ht-orb-r2

docker run -d --name ht-orb-r1 --network ht-orb-entry \
alpine/socat -d -d TCP-LISTEN:8080,fork,reuseaddr TCP:ht-orb-r2:8080
docker network connect ht-orb-transit ht-orb-r1

docker run --rm --network ht-orb-entry curlimages/curl:latest \
-sS http://ht-orb-r1:8080/ >/dev/null
```
### Перевірте межі видимості
```bash
docker logs ht-orb-target
docker logs ht-orb-r1
docker logs ht-orb-r2
docker inspect -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{.IPAddress}}{{println}}{{end}}' \
ht-orb-r1 ht-orb-r2 ht-orb-target
```
Очікуваний результат: Nginx записує адресу `ht-orb-r2` на `ht-orb-target`, а не одноразового клієнта. Логи relay показують підключення лише з їхньої суміжної мережі. Перевірка control plane Docker усе ще дає змогу відтворити весь шлях — аналогічно до доказів від provider/controller.

### Експерименти з виявлення

1. Повторюйте запити кожні 60 секунд і побудуйте графік часу між надходженнями та кількості байтів.
2. Замініть `ht-orb-r2` новим іменованим контейнером/адресою, але збережіть ту саму періодичність і запит до application; підтвердьте, що правило, яке використовує лише IP, втрачає ланцюжок, хоча поведінка все ще пов’язує його.
3. Виконайте захоплення трафіку на трьох Docker bridge за допомогою `tcpdump` на lab host і порівняйте часові мітки.
4. Зупиніть `ht-orb-r2`; перевірте, що прямого fallback від entry до target немає.

### Згортання
```bash
docker rm -f ht-orb-r1 ht-orb-r2 ht-orb-target
docker network rm ht-orb-entry ht-orb-transit ht-orb-target
```
## Лабораторна робота 2: SNI/Host mismatch та redirector logging

**Мета:** відтворити routing primitive, що лежить в основі domain fronting, на приватному локальному edge та показати, де це видно. Публічний CDN не використовується.

### Створення локального TLS edge
```bash
ht_front_dir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
-subj '/CN=front.lab' \
-keyout "$ht_front_dir/key.pem" -out "$ht_front_dir/cert.pem"

cat >"$ht_front_dir/default.conf" <<'EOF'
log_format routing '$remote_addr sni=$ssl_server_name host=$host request="$request"';
server {
listen 443 ssl;
server_name front.lab;
ssl_certificate /etc/nginx/tls/cert.pem;
ssl_certificate_key /etc/nginx/tls/key.pem;
access_log /var/log/nginx/access.log routing;
location / {
if ($host != origin.lab) { return 404; }
proxy_pass http://ht-front-target:80;
}
}
EOF

docker network create ht-front-net
docker run -d --name ht-front-target --network ht-front-net nginx:alpine
docker run -d --name ht-front-edge --network ht-front-net -p 127.0.0.1:8443:443 \
-v "$ht_front_dir/default.conf:/etc/nginx/conf.d/default.conf:ro" \
-v "$ht_front_dir:/etc/nginx/tls:ro" nginx:alpine
```
### Надішліть і спостерігайте невідповідність
```bash
curl -k --resolve front.lab:8443:127.0.0.1 \
-H 'Host: origin.lab' https://front.lab:8443/
docker logs ht-front-edge
```
Очікувані поля журналу містять `sni=front.lab host=origin.lab`. Перехоплення пакетів на ділянці клієнт—edge розкриває SNI, якщо не використовується ECH; HTTP Host на цій ділянці зашифрований. Edge, що завершує з'єднання, бачить обидва значення.

Тепер надішліть звичайний запит і підтвердьте, що policy його відхиляє:
```bash
curl -k --resolve front.lab:8443:127.0.0.1 https://front.lab:8443/
```
### Твердження щодо виявлення

Створюйте сповіщення щодо `sni != host` лише після нормалізації портів і регістру та перевірки відомих винятків для reverse-proxy. Додайте контекст процесу й tenant/origin перед визначенням рівня серйозності.

### Завершення
```bash
docker rm -f ht-front-edge ht-front-target
docker network rm ht-front-net
rm -rf -- "$ht_front_dir"
```
## Лабораторна робота 3: телеметрія fast-flux DNS

**Мета:** створити безпечний DNS dataset із низьким TTL і структурою, подібною до multi-ASN, та перевірити аналітичне правило. Повернуті адреси документації RFC 5737 є нерутованими для цієї мети.

### Запустіть authoritative server
```bash
ht_dns_dir="$(mktemp -d)"
cat >"$ht_dns_dir/Corefile" <<'EOF'
.:53 {
log
errors
file /zones/db.lab lab
}
EOF

mkdir -p "$ht_dns_dir/zones"
cat >"$ht_dns_dir/zones/db.lab" <<'EOF'
$ORIGIN lab.
@ 60 IN SOA ns.lab. hostmaster.lab. 1 60 60 60 5
@ 60 IN NS ns.lab.
ns 60 IN A 192.0.2.53
flux 5 IN A 192.0.2.10
flux 5 IN A 198.51.100.20
flux 5 IN A 203.0.113.30
EOF

docker run -d --name ht-flux-dns -p 127.0.0.1:1053:53/udp \
-v "$ht_dns_dir/Corefile:/Corefile:ro" \
-v "$ht_dns_dir/zones:/zones:ro" coredns/coredns:latest -conf /Corefile

for query_number in 1 2 3 4 5; do
dig @127.0.0.1 -p 1053 flux.lab A +noall +answer
done
docker logs ht-flux-dns
```
Очікуваний результат: кожна відповідь містить три documentation IPs і TTL тривалістю 5 секунд. Справжній fast flux також обертає підмножини з часом; змініть серійний номер зони/адреси та перезапустіть цей одноразовий сервер, щоб створити кілька епох.

### Аналітична перевірка

Для п’ятихвилинного вікна обчисліть `median(TTL)`, кількість унікальних відповідей, кількість унікальних synthetic ASN/geography labels і churn відповідей. Вимагайте щонайменше двох підозрілих вимірів, а також події процесу/подальшої активності. Запустіть ту саму аналітику для відомого зразка CDN, щоб виміряти кількість false positives.

### Завершення
```bash
docker rm -f ht-flux-dns
rm -rf -- "$ht_dns_dir"
```
## Лабораторна робота 4: nearest-neighbor wireless pivot

**Мета:** відтворити невідповідність меж APT28 із використанням двох власних “організацій”. Оскільки команди для Wi-Fi-обладнання/драйверів відрізняються, ця лабораторна робота визначає ролі та докази, які можна перевірити, а не створює враження, що одна команда `hostapd` підходить для кожного радіомодуля.

### Обладнання

- дві власні AP на ізольованих лабораторних каналах/SSID `HT-NEIGHBOR` і `HT-TARGET`;
- один цільовий сервіс, доступний лише з `HT-TARGET`;
- один власний dual-radio Linux pivot, здатний підключатися до обох AP;
- одна workstation для remote-control за `HT-NEIGHBOR`;
- журнали RADIUS/NAC або асоціацій AP, журнали DHCP і журнали аудиту/процесів pivot.

### Процедура

1. Фізично ізолюйте або послабте сигнал у системі так, щоб жоден SSID не виходив за межі авторизованої зони. Підтвердьте це за допомогою обстеження.
2. Налаштуйте `HT-TARGET` з ідентифікатором для вправи та навмисно вимкніть перевірку сертифіката пристрою/posture validation під час першого запуску. Зафіксуйте це як умову, що перевіряється.
3. Підключіть перший інтерфейс pivot до `HT-NEIGHBOR`, а другий — до `HT-TARGET`. **Не** вмикайте загальний bridge; дозвольте через host firewall лише цільовий сервіс/порт.
4. На workstation відкрийте authenticated tunnel до pivot і запитайте цільовий сервіс через нього.
5. Зафіксуйте створення процесу/інтерфейсу pivot, асоціації з обома AP, цільову подію RADIUS, DHCP lease і source address цілі.
6. Попросіть detection team відтворити ланцюжок без карти контролера.
7. Увімкніть EAP-TLS/managed-device posture на `HT-TARGET`, видаліть схвалений target certificate pivot і повторіть процедуру. Доступ має завершитися відмовою на етапі admission.
8. Повторіть процедуру з randomized MAC, який використовується вперше. Перевірте, що рішення щодо certificate/device і далі працює, а жодне правило не вважає сам MAC ідентичністю.

### Критерії успішності

- Спочатку ціль бачить локального Wi-Fi-клієнта, а не workstation.
- Joined telemetry ідентифікує один pivot з одночасними шляхами до neighbor-control і target-radio.
- Admission на основі certificate/device блокує другий запуск.
- Жоден пакет не досягає мережі за межами ізольованої лабораторії.

## Лабораторна робота 5: dead-drop resolver sequence

**Мета:** виявити процес, який читає об’єкт, що виглядає легітимним, декодує pointer і негайно підключається до другого сервісу.

### Побудова
```bash
docker network create ht-ddr-net
docker run -d --name ht-ddr-c2 --network ht-ddr-net nginx:alpine

docker run -d --name ht-ddr-web --network ht-ddr-net python:3-alpine \
sh -c 'mkdir -p /srv && printf aHR0cDovL2h0LWRkci1jMjo4MC8= > /srv/profile.txt && python -m http.server 8000 -d /srv'

docker run --rm --name ht-ddr-client --network ht-ddr-net python:3-alpine \
python -c 'import base64,urllib.request; p=urllib.request.urlopen("http://ht-ddr-web:8000/profile.txt").read(); u=base64.b64decode(p).decode(); print(urllib.request.urlopen(u).status)'

docker logs ht-ddr-web
docker logs ht-ddr-c2
```
Закодований вміст: `http://ht-ddr-c2:80/`. Робоче виявлення об'єднує той самий короткоживучий процес/контейнер, який читає `/profile.txt`, декодує вміст і протягом кількох секунд зв'язується з `ht-ddr-c2`. Обчисліть хеш і збережіть відповідь об'єкта.

### Завершення роботи
```bash
docker rm -f ht-ddr-web ht-ddr-c2
docker network rm ht-ddr-net
```
## Лабораторна робота 6: synthetic peel-chain і bridge graph

**Мета:** практикувати трасування value без реальних assets, accounts або services.

### Створення та трасування dataset
```bash
ht_graph_dir="$(mktemp -d)"
cat >"$ht_graph_dir/edges.csv" <<'EOF'
time,chain,source,destination,amount,label
10:00,A,theft,a1,100,source
10:10,A,a1,shop1,3,payment
10:10,A,a1,a2,96.9,change
10:20,A,a2,shop2,4,payment
10:20,A,a2,a3,92.8,change
10:30,A,a3,bridge_in,90,bridge_deposit
10:36,X,bridge_in,bridge_out,89.5,bridge_link_inference
10:36,B,bridge_out,b1,89.5,bridge_withdrawal
10:50,B,b1,exchange,89,service_deposit
EOF

python3 - "$ht_graph_dir/edges.csv" <<'PY'
import csv, sys
edges = list(csv.DictReader(open(sys.argv[1], newline="")))
frontier, seen = {"theft"}, set()
while frontier:
src = frontier.pop()
for e in edges:
if e["source"] == src and (src, e["destination"]) not in seen:
seen.add((src, e["destination"]))
print(f'{e["time"]} {e["chain"]}: {src} -> {e["destination"]} {e["amount"]} [{e["label"]}]')
frontier.add(e["destination"])
PY
```
Аналітики повинні визначити pattern peel/change, розглядати bridge link як окремий висновок, підтверджений доказами, обчислити різницю у fee/value та позначити exchange як запит на off-chain evidence. Змініть одне значення або час і задокументуйте, як змінюється рівень впевненості.

### Розбір
```bash
rm -rf -- "$ht_graph_dir"
```
## Lab 7: пасивний сенсор сигналізації трафіку

**Мета:** відтворити мережеву сигнатуру пасивного implant, активованого magic value, без створення shell, persistence або remote access. Listener прив’язується лише до loopback і записує нешкідливу подію.
```bash
ht_signal_dir="$(mktemp -d)"
cat >"$ht_signal_dir/listener.py" <<'PY'
import hmac, socket

token = b"HT-LAB-ACTIVATE"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 45679))
for _ in range(2):
data, peer = sock.recvfrom(1024)
if hmac.compare_digest(data, token):
print(f"authorized lab activation from {peer[0]}", flush=True)
PY

python3 "$ht_signal_dir/listener.py" >"$ht_signal_dir/events.log" &
ht_signal_pid=$!
sleep 1

python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"ordinary-traffic", ("127.0.0.1", 45679))
s.sendto(b"HT-LAB-ACTIVATE", ("127.0.0.1", 45679))
PY

wait "$ht_signal_pid"
cat "$ht_signal_dir/events.log"
rm -rf -- "$ht_signal_dir"
```
Очікуваний результат: звичайний трафік не створює жодної події застосунку; це робить лише призначений токен. Під час виконання захопіть loopback-трафік і перевірте, чи мережевий сенсор усе ще бачить обидві дейтаграми. Потім оцініть host controls, які виявляють неочікуваний довготривалий packet listener або фільтр packet-capture. Реальні пасивні імпланти RedPenguin перевіряли трафік на маршрутизаторі та надавали небезпечні функціональні можливості; ця лабораторна робота навмисно не робить ні того, ні іншого.

## Шаблон звіту про вправу

Для кожної лабораторної роботи зафіксуйте:

- авторизацію та ізольовану область;
- гіпотезу та техніку ATT&CK;
- топологію й таблицю спостерігачів;
- точний час початку/завершення та хеші конфігурацій;
- очікувані події для кожного сенсора;
- фактично спостережені події та прогалини зберігання;
- аналітичну логіку, поріг і приклад false positive;
- чи цільова команда відтворила шлях;
- результат повторного тестування mitigation; і
- докази teardown/recovery.

Вправа є незавершеною, доки detection не буде повторно виконано після mitigation, а всі ресурси лабораторної роботи не буде видалено.

## References

- [1] [MITRE ATT&CK — Багатоланцюговий проксі (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [2] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [3] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [4] [Volexity — Атака The Nearest Neighbor](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [5] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [6] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
