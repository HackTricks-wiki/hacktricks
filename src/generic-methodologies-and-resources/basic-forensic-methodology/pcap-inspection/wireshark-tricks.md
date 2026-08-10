# Κόλπα του Wireshark

## Βελτιώστε τις δεξιότητές σας στο Wireshark

### Tutorials

Τα παρακάτω tutorials είναι εξαιρετικά για να μάθετε μερικά χρήσιμα βασικά κόλπα:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Αναλυμένες πληροφορίες

**Πληροφορίες ειδικού**

Κάνοντας κλικ στο _**Analyze** --> **Expert Information**_ θα έχετε μια **επισκόπηση** του τι συμβαίνει στα **αναλυμένα** πακέτα:

![Tutorials - Αναλυμένες πληροφορίες: Κάνοντας κλικ στο Analyze -- Expert Information θα έχετε μια επισκόπηση του τι συμβαίνει στα αναλυμένα πακέτα](<../../../images/image (256).png>)

**Επιλυμένες διευθύνσεις**

Στην ενότητα _**Statistics --> Resolved Addresses**_ μπορείτε να βρείτε διάφορες **πληροφορίες** που **επιλύθηκαν** από το wireshark, όπως θύρα/transport σε protocol, MAC στον κατασκευαστή κ.λπ. Είναι ενδιαφέρον να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Resolved Addresses μπορείτε να βρείτε διάφορες πληροφορίες που " επιλύθηκαν " από το wireshark, όπως θύρα/transport σε protocol, MAC στον...](<../../../images/image (893).png>)

**Ιεραρχία πρωτοκόλλων**

Στην ενότητα _**Statistics --> Protocol Hierarchy**_ μπορείτε να βρείτε τα **protocols** που **εμπλέκονται** στην επικοινωνία και δεδομένα σχετικά με αυτά.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Protocol Hierarchy μπορείτε να βρείτε τα protocols που εμπλέκονται στην επικοινωνία και δεδομένα σχετικά με αυτά](<../../../images/image (586).png>)

**Συνομιλίες**

Στην ενότητα _**Statistics --> Conversations**_ μπορείτε να βρείτε μια **σύνοψη των συνομιλιών** στην επικοινωνία και δεδομένα σχετικά με αυτές.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Conversations μπορείτε να βρείτε μια σύνοψη των συνομιλιών στην επικοινωνία και δεδομένα σχετικά με αυτές](<../../../images/image (453).png>)

**Endpoints**

Στην ενότητα _**Statistics --> Endpoints**_ μπορείτε να βρείτε μια **σύνοψη των endpoints** στην επικοινωνία και δεδομένα σχετικά με καθένα από αυτά.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- Endpoints μπορείτε να βρείτε μια σύνοψη των endpoints στην επικοινωνία και δεδομένα σχετικά με καθένα από αυτά](<../../../images/image (896).png>)

**Πληροφορίες DNS**

Στην ενότητα _**Statistics --> DNS**_ μπορείτε να βρείτε στατιστικά στοιχεία σχετικά με το καταγεγραμμένο αίτημα DNS.

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- DNS μπορείτε να βρείτε στατιστικά στοιχεία σχετικά με το καταγεγραμμένο αίτημα DNS](<../../../images/image (1063).png>)

**Γράφημα I/O**

Στην ενότητα _**Statistics --> I/O Graph**_ μπορείτε να βρείτε ένα **γράφημα της επικοινωνίας.**

![Tutorials - Αναλυμένες πληροφορίες: Στην ενότητα Statistics -- I/O Graph μπορείτε να βρείτε ένα γράφημα της επικοινωνίας](<../../../images/image (992).png>)

### Filters

Εδώ μπορείτε να βρείτε φίλτρα του wireshark ανάλογα με το protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Στο τρέχον Wireshark χρησιμοποιήστε `tls.*` αντί για τα παλιά ονόματα φίλτρων `ssl.*`.<sup>[[1]](#references)</sup>\
Άλλα ενδιαφέροντα φίλτρα:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS κίνηση
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS κίνηση + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP και αρχική HTTPS κίνηση + TCP SYN + αιτήματα DNS
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot στο SNI που αποστέλλεται στο ClientHello, ακόμη και όταν δεν μπορείτε να αποκρυπτογραφήσετε το payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Γρήγορος διαχωρισμός των sessions που υποστηρίζουν κλασικό HTTPS, HTTP/2 και HTTP/3
- `quic or http3`
- Εντοπισμός σύγχρονης κίνησης UDP/443 που θα παραλειφθεί αν εξετάζετε μόνο TCP conversations

### Αναζήτηση

Αν θέλετε να **αναζητήσετε** **περιεχόμενο** μέσα στα **πακέτα** των sessions, πατήστε _CTRL+f_. Μπορείτε να προσθέσετε νέα layers στην κύρια γραμμή πληροφοριών (No., Time, Source κ.λπ.) πατώντας το δεξί κουμπί και στη συνέχεια την επιλογή επεξεργασίας στήλης.

### Παρακολούθηση multiplexed streams

Το Wireshark μπορεί να παρακολουθεί απευθείας streams των `TLS`, `HTTP/2` και `QUIC`. Τα παράθυρα διαλόγου HTTP/2 και QUIC εμφανίζουν selectors για connections και substreams, γεγονός που βοηθά στην απομόνωση multiplexed streams που μοιράζονται την ίδια connection χαμηλότερου επιπέδου.<sup>[[4]](#references)</sup>

### Δωρεάν εργαστήρια pcap

**Εξασκηθείτε με τα δωρεάν challenges του:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Αναγνώριση Domains

Μπορείτε να προσθέσετε μια στήλη που εμφανίζει το Host HTTP header:

![Free pcap labs - Αναγνώριση Domains: Μπορείτε να προσθέσετε μια στήλη που εμφανίζει το Host HTTP header](<../../../images/image (639).png>)

Και μια στήλη που προσθέτει το όνομα του Server από μια αρχική HTTPS connection (**tls.handshake.type == 1**):

![Free pcap labs - Αναγνώριση Domains: Και μια στήλη που προσθέτει το όνομα του Server από μια αρχική HTTPS connection ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Αν το capture είναι κυρίως κρυπτογραφημένο, η προσθήκη αυτών των πεδίων ως στηλών θα επιταχύνει σημαντικά το triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Αυτό σας επιτρέπει να ομαδοποιείτε sessions βάσει hostname, ALPN (`http/1.1`, `h2`, `h3` κ.λπ.) και client fingerprint, ακόμη και όταν το ίδιο το payload παραμένει κρυπτογραφημένο. Για αποκρυπτογραφημένα captures HTTP/2 και HTTP/3, είναι επίσης χρήσιμο να προσθέσετε τα `http2.header.value` ή `http3.headers.header.value` ως στήλες και να κάνετε pivot σε paths, authorities και άλλα ενδιαφέροντα metadata.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Εντοπισμός τοπικών hostnames

### Από DHCP

Στο τρέχον Wireshark, αντί για `bootp`, πρέπει να αναζητήσετε το `DHCP`

![Εντοπισμός τοπικών hostnames - Από DHCP: Στο τρέχον Wireshark, αντί για bootp, πρέπει να αναζητήσετε το DHCP](<../../../images/image (1013).png>)

### Από NBNS

![Από DHCP - Από NBNS: Στο τρέχον Wireshark, αντί για bootp, πρέπει να αναζητήσετε το DHCP](<../../../images/image (1003).png>)

## Αποκρυπτογράφηση TLS

### Αποκρυπτογράφηση https traffic με το private key του server

_Επεξεργασία > προτιμήσεις > πρωτόκολλα > tls >_

![Αποκρυπτογράφηση TLS - Αποκρυπτογράφηση https traffic με το private key του server: Αποκρυπτογράφηση https traffic με το private key του server](<../../../images/image (1103).png>)

Πατήστε _Edit_ και προσθέστε όλα τα δεδομένα του server και το private key (_IP, Port, Protocol, Key file και password_)

Αυτή η μέθοδος λειτουργεί μόνο σε περιορισμένο αριθμό περιπτώσεων. Για σύγχρονο traffic TLS 1.3 / ECDHE, η παρακάτω μέθοδος καταγραφής session key είναι συνήθως η πρακτική επιλογή.<sup>[[1]](#references)</sup>

### Αποκρυπτογράφηση https traffic με συμμετρικά session keys

Τόσο ο Firefox όσο και ο Chrome έχουν τη δυνατότητα να καταγράφουν session keys TLS, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για την αποκρυπτογράφηση traffic TLS. Αυτό επιτρέπει τη λεπτομερή ανάλυση ασφαλών επικοινωνιών. Περισσότερες λεπτομέρειες σχετικά με τον τρόπο εκτέλεσης αυτής της αποκρυπτογράφησης μπορείτε να βρείτε σε έναν οδηγό στο [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Αυτή είναι επίσης η κανονική μέθοδος για την αποκρυπτογράφηση σύγχρονων captures TLS 1.3 και QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Για να το εντοπίσετε, αναζητήστε μέσα στο environment τη μεταβλητή `SSLKEYLOGFILE`

Ένα αρχείο με shared keys θα μοιάζει ως εξής:

![Αποκρυπτογράφηση https traffic με το private key του server - Αποκρυπτογράφηση https traffic με συμμετρικά session keys: Ένα αρχείο με shared keys θα μοιάζει ως εξής](<../../../images/image (820).png>)

Αν το capture είναι `pcapng`, ελέγξτε αν περιέχει ήδη ενσωματωμένα secrets αποκρυπτογράφησης, πριν αναζητήσετε στο filesystem του host:<sup>[[1]](#references)</sup>
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Για να το εισαγάγετε στο Wireshark, μεταβείτε στο \_edit > preferences > protocols > tls > και εισαγάγετέ το στο (Pre)-Master-Secret log filename:

![Αποκρυπτογράφηση https traffic με το ιδιωτικό κλειδί του server - Αποκρυπτογράφηση https traffic με symmetric session keys: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## ADB communication

Εξαγάγετε ένα APK από μια ADB communication όπου στάλθηκε το APK:
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
## References

- [1] [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [2] [Αποκρυπτογράφηση και ανάλυση HTTP/3 traffic στο Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Αποκρυπτογράφηση TLS Browser Traffic με Wireshark – Ο εύκολος τρόπος!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Παρακολούθηση Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Αναφορά Display Filters: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Αναφορά Display Filters: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Αναφορά Display Filters: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
{{#include ../../../banners/hacktricks-training.md}}
