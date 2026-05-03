# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Βελτίωσε τις δεξιότητές σου στο Wireshark

### Tutorials

Τα παρακάτω tutorials είναι εξαιρετικά για να μάθεις μερικά ωραία βασικά tricks:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Αναλυμένες Πληροφορίες

**Expert Information**

Κάνοντας κλικ στο _**Analyze** --> **Expert Information**_ θα έχεις μια **επισκόπηση** του τι συμβαίνει στα πακέτα που έχουν **αναλυθεί**:

![](<../../../images/image (256).png>)

**Resolved Addresses**

Στο _**Statistics --> Resolved Addresses**_ μπορείς να βρεις διάφορες **πληροφορίες** που έχουν "**resolved**" από το wireshark, όπως port/transport σε protocol, MAC στον κατασκευαστή, κ.λπ. Είναι ενδιαφέρον να ξέρεις τι εμπλέκεται στην επικοινωνία.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Στο _**Statistics --> Protocol Hierarchy**_ μπορείς να βρεις τα **protocols** που **εμπλέκονται** στην επικοινωνία και δεδομένα γι’ αυτά.

![](<../../../images/image (586).png>)

**Conversations**

Στο _**Statistics --> Conversations**_ μπορείς να βρεις μια **σύνοψη των conversations** στην επικοινωνία και δεδομένα γι’ αυτά.

![](<../../../images/image (453).png>)

**Endpoints**

Στο _**Statistics --> Endpoints**_ μπορείς να βρεις μια **σύνοψη των endpoints** στην επικοινωνία και δεδομένα για το καθένα από αυτά.

![](<../../../images/image (896).png>)

**DNS info**

Στο _**Statistics --> DNS**_ μπορείς να βρεις στατιστικά για το DNS request που έχει καταγραφεί.

![](<../../../images/image (1063).png>)

**I/O Graph**

Στο _**Statistics --> I/O Graph**_ μπορείς να βρεις ένα **γράφημα της επικοινωνίας.**

![](<../../../images/image (992).png>)

### Filters

Εδώ μπορείς να βρεις wireshark filter ανάλογα με το protocol: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Στο τρέχον Wireshark χρησιμοποίησε `tls.*` αντί για τα παλιά ονόματα φίλτρων `ssl.*`.\
Άλλα ενδιαφέροντα filters:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP and initial HTTPS traffic + TCP SYN + DNS requests
- `tls.handshake.extensions_server_name contains "example.com"`
- Pivot στο SNI που στάλθηκε στο ClientHello ακόμα κι όταν δεν μπορείς να αποκρυπτογραφήσεις το payload
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
- Διαχώρισε γρήγορα κλασικές HTTPS, HTTP/2 και HTTP/3 capable sessions
- `quic or http3`
- Βρες σύγχρονη UDP/443 traffic που θα χαθεί αν ελέγχεις μόνο TCP conversations

### Search

Αν θέλεις να **search** για **content** μέσα στα **packets** των sessions, πάτησε _CTRL+f_. Μπορείς να προσθέσεις νέα layers στην κύρια μπάρα πληροφοριών (No., Time, Source, κ.λπ.) πατώντας το δεξί κουμπί και μετά το edit column.

### Following multiplexed streams

Οι πρόσφατες εκδόσεις του Wireshark μπορούν να ακολουθήσουν απευθείας `TLS`, `HTTP/2` και `QUIC` streams. Σε captures με πολύ θόρυβο αυτό είναι συνήθως πιο γρήγορο από το να χρησιμοποιείς μόνο `Follow TCP Stream`, ειδικά όταν πολλά requests μοιράζονται την ίδια connection.

### Free pcap labs

**Practice with the free challenges of:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Μπορείς να προσθέσεις μια στήλη που δείχνει το Host HTTP header:

![](<../../../images/image (639).png>)

Και μια στήλη που προσθέτει το Server name από μια initiating HTTPS connection (**tls.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

Αν το capture είναι κυρίως encrypted, η προσθήκη αυτών των πεδίων ως columns θα επιταχύνει πολύ το triage:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Αυτό σου επιτρέπει να ομαδοποιείς sessions ανά hostname, ALPN (`http/1.1`, `h2`, `h3`, κ.λπ.) και client fingerprint ακόμα κι όταν το payload παραμένει encrypted. Για decrypted HTTP/2 και HTTP/3 captures, είναι επίσης χρήσιμο να προσθέσεις `http2.header.value` ή `http3.headers.header.value` ως columns και να κάνεις pivot σε paths, authorities και άλλα ενδιαφέροντα metadata.
```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
-e frame.number -e ip.src -e ip.dst \
-e tls.handshake.extensions_server_name \
-e tls.handshake.extensions_alpn_str \
-e tls.handshake.ja3 -e tls.handshake.ja4
```
## Αναγνώριση τοπικών hostnames

### Από DHCP

Στο current Wireshark αντί για `bootp` πρέπει να αναζητήσεις `DHCP`

![](<../../../images/image (1013).png>)

### Από NBNS

![](<../../../images/image (1003).png>)

## Αποκρυπτογράφηση TLS

### Αποκρυπτογράφηση https traffic με το ιδιωτικό κλειδί του server

_edit > preferences > protocols > tls >_

![](<../../../images/image (1103).png>)

Πάτησε _Edit_ και πρόσθεσε όλα τα δεδομένα του server και του private key (_IP, Port, Protocol, Key file and password_)

Αυτή η μέθοδος λειτουργεί μόνο σε περιορισμένο αριθμό περιπτώσεων. Για current TLS 1.3 / ECDHE traffic, το session key log method παρακάτω είναι συνήθως η πρακτική επιλογή.

### Αποκρυπτογράφηση https traffic με συμμετρικά session keys

Τόσο ο Firefox όσο και ο Chrome έχουν τη δυνατότητα να καταγράφουν TLS session keys, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για την αποκρυπτογράφηση TLS traffic. Αυτό επιτρέπει εις βάθος ανάλυση των secure communications. Περισσότερες λεπτομέρειες για το πώς να κάνεις αυτή την αποκρυπτογράφηση μπορείς να βρεις σε έναν οδηγό στο [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/). Αυτή είναι επίσης η κανονική προσέγγιση για την αποκρυπτογράφηση modern TLS 1.3 και QUIC/HTTP/3 captures.

Για να το εντοπίσεις αυτό, αναζήτησε μέσα στο environment τη μεταβλητή `SSLKEYLOGFILE`

Ένα αρχείο shared keys θα μοιάζει κάπως έτσι:

![](<../../../images/image (820).png>)

Αν το capture είναι `pcapng`, έλεγξε αν περιέχει ήδη embedded decryption secrets πριν ψάξεις στο host filesystem:
```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```
Για να το εισαγάγετε στο wireshark, μεταβείτε σε \_edit > preferences > protocols > tls > και εισαγάγετέ το στο (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Εξαγάγετε ένα APK από μια ADB communication όπου το APK στάλθηκε:
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
## Αναφορές

- [Wireshark TLS wiki](https://wiki.wireshark.org/TLS)
- [Decrypting and parsing HTTP/3 traffic in Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)

{{#include ../../../banners/hacktricks-training.md}}
