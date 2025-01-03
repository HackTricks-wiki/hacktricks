# Wireshark tricks

{{#include ../../../banners/hacktricks-training.md}}

## Βελτιώστε τις δεξιότητές σας στο Wireshark

### Tutorials

Τα παρακάτω tutorials είναι καταπληκτικά για να μάθετε μερικά ωραία βασικά κόλπα:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Analysed Information

**Expert Information**

Κάνοντας κλικ στο _**Analyze** --> **Expert Information**_ θα έχετε μια **επισκόπηση** του τι συμβαίνει στα πακέτα **που αναλύθηκαν**:

![](<../../../images/image (256).png>)

**Resolved Addresses**

Κάτω από _**Statistics --> Resolved Addresses**_ μπορείτε να βρείτε πολλές **πληροφορίες** που "έχουν **επιλυθεί**" από το wireshark όπως θύρα/μεταφορά σε πρωτόκολλο, MAC στον κατασκευαστή, κ.λπ. Είναι ενδιαφέρον να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![](<../../../images/image (893).png>)

**Protocol Hierarchy**

Κάτω από _**Statistics --> Protocol Hierarchy**_ μπορείτε να βρείτε τα **πρωτόκολλα** **που εμπλέκονται** στην επικοινωνία και δεδομένα σχετικά με αυτά.

![](<../../../images/image (586).png>)

**Conversations**

Κάτω από _**Statistics --> Conversations**_ μπορείτε να βρείτε μια **σύνοψη των συνομιλιών** στην επικοινωνία και δεδομένα σχετικά με αυτές.

![](<../../../images/image (453).png>)

**Endpoints**

Κάτω από _**Statistics --> Endpoints**_ μπορείτε να βρείτε μια **σύνοψη των endpoints** στην επικοινωνία και δεδομένα σχετικά με το καθένα από αυτά.

![](<../../../images/image (896).png>)

**DNS info**

Κάτω από _**Statistics --> DNS**_ μπορείτε να βρείτε στατιστικά σχετικά με το DNS αίτημα που καταγράφηκε.

![](<../../../images/image (1063).png>)

**I/O Graph**

Κάτω από _**Statistics --> I/O Graph**_ μπορείτε να βρείτε ένα **γράφημα της επικοινωνίας.**

![](<../../../images/image (992).png>)

### Filters

Εδώ μπορείτε να βρείτε φίλτρα wireshark ανάλογα με το πρωτόκολλο: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Άλλα ενδιαφέροντα φίλτρα:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- HTTP και αρχική κίνηση HTTPS
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- HTTP και αρχική κίνηση HTTPS + TCP SYN
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- HTTP και αρχική κίνηση HTTPS + TCP SYN + DNS αιτήματα

### Search

Αν θέλετε να **αναζητήσετε** **περιεχόμενο** μέσα στα **πακέτα** των συνεδριών πατήστε _CTRL+f_. Μπορείτε να προσθέσετε νέα επίπεδα στη βασική γραμμή πληροφοριών (No., Χρόνος, Πηγή, κ.λπ.) πατώντας το δεξί κουμπί και στη συνέχεια την επεξεργασία στήλης.

### Free pcap labs

**Εξασκηθείτε με τις δωρεάν προκλήσεις του:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identifying Domains

Μπορείτε να προσθέσετε μια στήλη που να δείχνει την κεφαλίδα Host HTTP:

![](<../../../images/image (639).png>)

Και μια στήλη που προσθέτει το όνομα του διακομιστή από μια αρχική σύνδεση HTTPS (**ssl.handshake.type == 1**):

![](<../../../images/image (408) (1).png>)

## Identifying local hostnames

### From DHCP

Στο τρέχον Wireshark αντί για `bootp` πρέπει να αναζητήσετε `DHCP`

![](<../../../images/image (1013).png>)

### From NBNS

![](<../../../images/image (1003).png>)

## Decrypting TLS

### Decrypting https traffic with server private key

_edit>preference>protocol>ssl>_

![](<../../../images/image (1103).png>)

Πατήστε _Edit_ και προσθέστε όλα τα δεδομένα του διακομιστή και το ιδιωτικό κλειδί (_IP, Θύρα, Πρωτόκολλο, Αρχείο κλειδιού και κωδικό πρόσβασης_)

### Decrypting https traffic with symmetric session keys

Και οι δύο Firefox και Chrome έχουν τη δυνατότητα να καταγράφουν τα κλειδιά συνεδρίας TLS, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για να αποκρυπτογραφήσουν την κίνηση TLS. Αυτό επιτρέπει σε βάθος ανάλυση των ασφαλών επικοινωνιών. Περισσότερες λεπτομέρειες σχετικά με το πώς να εκτελέσετε αυτήν την αποκρυπτογράφηση μπορείτε να βρείτε σε έναν οδηγό στο [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Για να το ανιχνεύσετε αναζητήστε μέσα στο περιβάλλον τη μεταβλητή `SSLKEYLOGFILE`

Ένα αρχείο κοινών κλειδιών θα φαίνεται έτσι:

![](<../../../images/image (820).png>)

Για να το εισάγετε στο wireshark πηγαίνετε στο \_edit > preference > protocol > ssl > και εισάγετε το στο (Pre)-Master-Secret log filename:

![](<../../../images/image (989).png>)

## ADB communication

Εξαγάγετε ένα APK από μια επικοινωνία ADB όπου το APK στάλθηκε:
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
{{#include ../../../banners/hacktricks-training.md}}
