# Κόλπα του Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Βελτιώστε τις δεξιότητές σας στο Wireshark

### Tutorials

Τα παρακάτω tutorials είναι εξαιρετικά για να μάθετε μερικά χρήσιμα βασικά κόλπα:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Αναλυμένες πληροφορίες

**Expert Information**

Κάνοντας κλικ στο _**Analyze** --> **Expert Information**_ θα έχετε μια **επισκόπηση** του τι συμβαίνει στα **αναλυμένα** πακέτα:

![Tutorials - Αναλυμένες πληροφορίες: Κάνοντας κλικ στο Analyze -- Expert Information θα έχετε μια επισκόπηση του τι συμβαίνει στα αναλυμένα πακέτα](<../../../images/image (256).png>)

**Resolved Addresses**

Στην ενότητα _**Statistics --> Resolved Addresses**_ μπορείτε να βρείτε διάφορες **πληροφορίες** που "**επιλύθηκαν**" από το Wireshark, όπως η αντιστοίχιση θύρας/transport με πρωτόκολλο, MAC με κατασκευαστή κ.λπ. Είναι ενδιαφέρον να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Resolved Addresses μπορείτε να βρείτε διάφορες πληροφορίες που " επιλύθηκαν " από το Wireshark, όπως η αντιστοίχιση θύρας/transport με πρωτόκολλο, MAC με τον...](<../../../images/image (893).png>)

**Protocol Hierarchy**

Στην ενότητα _**Statistics --> Protocol Hierarchy**_ μπορείτε να βρείτε τα **πρωτόκολλα** που **εμπλέκονται** στην επικοινωνία και δεδομένα σχετικά με αυτά.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Protocol Hierarchy μπορείτε να βρείτε τα πρωτόκολλα που εμπλέκονται στην επικοινωνία και δεδομένα σχετικά με αυτά](<../../../images/image (586).png>)

**Conversations**

Στην ενότητα _**Statistics --> Conversations**_ μπορείτε να βρείτε μια **σύνοψη των συνομιλιών** στην επικοινωνία και δεδομένα σχετικά με αυτές.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Conversations μπορείτε να βρείτε μια σύνοψη των συνομιλιών στην επικοινωνία και δεδομένα σχετικά με αυτές](<../../../images/image (453).png>)

**Endpoints**

Στην ενότητα _**Statistics --> Endpoints**_ μπορείτε να βρείτε μια **σύνοψη των endpoints** στην επικοινωνία και δεδομένα σχετικά με καθένα από αυτά.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Endpoints μπορείτε να βρείτε μια σύνοψη των endpoints στην επικοινωνία και δεδομένα σχετικά με καθένα από αυτά](<../../../images/image (896).png>)

**DNS info**

Στην ενότητα _**Statistics --> DNS**_ μπορείτε να βρείτε στατιστικά στοιχεία σχετικά με το καταγεγραμμένο DNS request.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- DNS μπορείτε να βρείτε στατιστικά στοιχεία σχετικά με το καταγεγραμμένο DNS request](<../../../images/image (1063).png>)

**I/O Graph**

Στην ενότητα _**Statistics --> I/O Graph**_ μπορείτε να βρείτε ένα **γράφημα της επικοινωνίας.**

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- I/O Graph μπορείτε να βρείτε ένα γράφημα της επικοινωνίας](<../../../images/image (992).png>)

### Filters

Εδώ μπορείτε να βρείτε φίλτρα του Wireshark ανάλογα με το πρωτόκολλο: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Στις τρέχουσες εκδόσεις του Wireshark χρησιμοποιήστε το `tls.*` αντί για τα παλιά ονόματα φίλτρων `ssl.*`.\
Άλλα ενδιαφέροντα φίλτρα:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Κάντε pivot στο SNI που αποστέλλεται στο ClientHello, ακόμη και όταν δεν μπορείτε να αποκρυπτογραφήσετε το payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Διαχωρίστε γρήγορα τις classic HTTPS, HTTP/2 και HTTP/3 capable sessions
- `quic or http3`
- Βρείτε σύγχρονη UDP/443 traffic που θα παραλειφθεί αν εξετάσετε μόνο TCP conversations

### Search

Αν θέλετε να κάνετε **αναζήτηση** για **περιεχόμενο** μέσα στα **πακέτα** των sessions, πατήστε _CTRL+f_. Μπορείτε να προσθέσετε νέες στήλες στη βασική γραμμή πληροφοριών (No., Time, Source κ.λπ.) πατώντας το δεξί κουμπί και στη συνέχεια την επιλογή edit column.

### Following multiplexed streams

Οι πρόσφατες εκδόσεις του Wireshark μπορούν να ακολουθούν απευθείας streams των `TLS`, `HTTP/2` και `QUIC`. Σε θορυβώδεις captures αυτό είναι συνήθως ταχύτερο από τη χρήση μόνο του `Follow TCP Stream`, ειδικά όταν πολλά requests μοιράζονται την ίδια connection.

### Free pcap labs

**Εξασκηθείτε με τα δωρεάν challenges του:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Εντοπισμός Domains

Μπορείτε να προσθέσετε μια στήλη που εμφανίζει το Host HTTP header:

![Free pcap labs - Εντοπισμός Domains: Μπορείτε να προσθέσετε μια στήλη που εμφανίζει το Host HTTP header](<../../../images/image (639).png>)

Και μια στήλη που προσθέτει το Server name από μια initiating HTTPS connection (**tls.handshake.type == 1**):

![Free pcap labs - Εντοπισμός Domains: Και μια στήλη που προσθέτει το Server name από μια initiating HTTPS connection ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Αν το capture είναι κυρίως κρυπτογραφημένο, η προσθήκη αυτών των πεδίων ως στηλών θα επιταχύνει σημαντικά το triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Αυτό σας επιτρέπει να ομαδοποιείτε sessions με βάση το hostname, το ALPN (`http/1.1`, `h2`, `h3` κ.λπ.) και το client fingerprint, ακόμη και όταν το ίδιο το payload παραμένει κρυπτογραφημένο. Για decrypted HTTP/2 και HTTP/3 captures, είναι επίσης χρήσιμο να προσθέσετε τα `http2.header.value` ή `http3.headers.header.value` ως στήλες και να κάνετε pivot στα paths, authorities και άλλα ενδιαφέροντα metadata.<sup>[[2]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Εντοπισμός τοπικών hostnames

### Από DHCP

Στο τρέχον Wireshark, αντί για `bootp` πρέπει να αναζητήσετε `DHCP`

![Εντοπισμός τοπικών hostnames - Από DHCP: Στο τρέχον Wireshark, αντί για bootp πρέπει να αναζητήσετε DHCP](<../../../images/image (1013).png>)

### Από NBNS

![Από DHCP - Από NBNS: Στο τρέχον Wireshark, αντί για bootp πρέπει να αναζητήσετε DHCP](<../../../images/image (1003).png>)

## Αποκρυπτογράφηση TLS

### Αποκρυπτογράφηση https traffic με το private key του server

_edit > preferences > protocols > tls >_

![Αποκρυπτογράφηση TLS - Αποκρυπτογράφηση https traffic με το private key του server: Αποκρυπτογράφηση https traffic με το private key του server](<../../../images/image (1103).png>)

Πατήστε _Edit_ και προσθέστε όλα τα δεδομένα του server και το private key (_IP, Port, Protocol, Key file και password_)

Αυτή η μέθοδος λειτουργεί μόνο σε περιορισμένο αριθμό περιπτώσεων. Για τρέχον traffic TLS 1.3 / ECDHE, η παρακάτω μέθοδος καταγραφής των session keys είναι συνήθως η πρακτική επιλογή.<sup>[[1]](#references)</sup>

### Αποκρυπτογράφηση https traffic με συμμετρικά session keys

Τόσο το Firefox όσο και το Chrome έχουν τη δυνατότητα να καταγράφουν TLS session keys, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για την αποκρυπτογράφηση TLS traffic. Αυτό επιτρέπει τη λεπτομερή ανάλυση ασφαλών επικοινωνιών. Περισσότερες λεπτομέρειες σχετικά με τον τρόπο εκτέλεσης αυτής της αποκρυπτογράφησης θα βρείτε σε έναν οδηγό στο [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Αυτή είναι επίσης η συνήθης μέθοδος για την αποκρυπτογράφηση σύγχρονων captures TLS 1.3 και QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Για να το εντοπίσετε, αναζητήστε μέσα στο περιβάλλον τη μεταβλητή `SSLKEYLOGFILE`

Ένα αρχείο με shared keys θα μοιάζει με αυτό:

![Αποκρυπτογράφηση https traffic με το private key του server - Αποκρυπτογράφηση https traffic με συμμετρικά session keys: Ένα αρχείο με shared keys θα μοιάζει με αυτό](<../../../images/image (820).png>)

Εάν το capture είναι `pcapng`, ελέγξτε εάν περιέχει ήδη ενσωματωμένα decryption secrets πριν αναζητήσετε στο filesystem του host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Για να το εισαγάγετε στο Wireshark, μεταβείτε στο \_edit > preferences > protocols > tls > και εισαγάγετέ το στο πεδίο (Pre)-Master-Secret log filename:

![Αποκρυπτογράφηση https traffic με το ιδιωτικό κλειδί του server - Αποκρυπτογράφηση https traffic με συμμετρικά session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Επικοινωνία ADB

Εξαγάγετε ένα APK από μια επικοινωνία ADB όπου στάλθηκε το APK:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
## Παραπομπές

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Αποκρυπτογράφηση και ανάλυση HTTP/3 traffic στο Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Αποκρυπτογράφηση TLS Browser Traffic με Wireshark – Ο εύκολος τρόπος!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
