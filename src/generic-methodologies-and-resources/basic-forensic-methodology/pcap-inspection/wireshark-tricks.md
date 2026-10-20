# Κόλπα του Wireshark

{{#include ../../../banners/hacktricks-training.md}}

## Βελτιώστε τις δεξιότητές σας στο Wireshark

### Εκπαιδευτικά μαθήματα

Τα παρακάτω εκπαιδευτικά μαθήματα είναι εξαιρετικά για να μάθετε μερικά χρήσιμα βασικά κόλπα:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Πληροφορίες ανάλυσης

**Πληροφορίες ειδικών**

Κάνοντας κλικ στο _**Analyze** --> **Expert Information**_ θα δείτε μια **επισκόπηση** των συμβάντων στα **αναλυμένα** πακέτα:

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Κάνοντας κλικ στο Analyze -- Expert Information θα δείτε μια επισκόπηση των συμβάντων στα αναλυμένα πακέτα](<../../../images/image (256).png>)

**Επιλυμένες διευθύνσεις**

Στην ενότητα _**Statistics --> Resolved Addresses**_ μπορείτε να βρείτε διάφορες **πληροφορίες** που «**επιλύθηκαν**» από το Wireshark, όπως αντιστοιχίσεις θύρας/μεταφοράς σε πρωτόκολλο, MAC σε κατασκευαστή κ.λπ. Είναι χρήσιμο να γνωρίζετε τι εμπλέκεται στην επικοινωνία.

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- Resolved Addresses μπορείτε να βρείτε διάφορες πληροφορίες που «επιλύθηκαν» από το Wireshark, όπως αντιστοιχίσεις θύρας/μεταφοράς σε πρωτόκολλο, MAC σε...](<../../../images/image (893).png>)

**Ιεραρχία πρωτοκόλλων**

Στην ενότητα _**Statistics --> Protocol Hierarchy**_ μπορείτε να βρείτε τα **πρωτόκολλα** που **συμμετέχουν** στην επικοινωνία, καθώς και δεδομένα σχετικά με αυτά.

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- Protocol Hierarchy μπορείτε να βρείτε τα πρωτόκολλα που συμμετέχουν στην επικοινωνία, καθώς και δεδομένα σχετικά με αυτά](<../../../images/image (586).png>)

**Συνομιλίες**

Στην ενότητα _**Statistics --> Conversations**_ μπορείτε να βρείτε μια **σύνοψη των συνομιλιών** στην επικοινωνία, καθώς και δεδομένα σχετικά με αυτές.

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- Conversations μπορείτε να βρείτε μια σύνοψη των συνομιλιών στην επικοινωνία, καθώς και δεδομένα σχετικά με αυτές](<../../../images/image (453).png>)

**Τερματικά σημεία**

Στην ενότητα _**Statistics --> Endpoints**_ μπορείτε να βρείτε μια **σύνοψη των τερματικών σημείων** στην επικοινωνία, καθώς και δεδομένα για καθένα από αυτά.

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- Endpoints μπορείτε να βρείτε μια σύνοψη των τερματικών σημείων στην επικοινωνία, καθώς και δεδομένα για καθένα από αυτά](<../../../images/image (896).png>)

**Πληροφορίες DNS**

Στην ενότητα _**Statistics --> DNS**_ μπορείτε να βρείτε στατιστικά στοιχεία για τα καταγεγραμμένα αιτήματα DNS.

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- DNS μπορείτε να βρείτε στατιστικά στοιχεία για τα καταγεγραμμένα αιτήματα DNS](<../../../images/image (1063).png>)

**Γράφημα I/O**

Στην ενότητα _**Statistics --> I/O Graph**_ μπορείτε να δείτε ένα **γράφημα της επικοινωνίας.**

![Εκπαιδευτικά μαθήματα - Πληροφορίες ανάλυσης: Στην ενότητα Statistics -- I/O Graph μπορείτε να δείτε ένα γράφημα της επικοινωνίας](<../../../images/image (992).png>)

### Φίλτρα

Εδώ μπορείτε να βρείτε φίλτρα Wireshark ανάλογα με το πρωτόκολλο: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Στις τρέχουσες εκδόσεις του Wireshark χρησιμοποιήστε το `tls.*` αντί για τα παλιά ονόματα φίλτρων `ssl.*`.<sup>[[1]](#references)</sup>\
Άλλα ενδιαφέροντα φίλτρα:

- `(http.request or tls.handshake.type == 1) and !(udp.port eq 1900)`
  - HTTP και αρχική κίνηση HTTPS
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
  - HTTP και αρχική κίνηση HTTPS + TCP SYN
- `(http.request or tls.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
  - HTTP και αρχική κίνηση HTTPS + TCP SYN + αιτήματα DNS
- `tls.handshake.extensions_server_name contains "example.com"`
  - Εντοπίστε κίνηση με βάση το SNI που αποστέλλεται στο ClientHello, ακόμη κι όταν δεν μπορείτε να αποκρυπτογραφήσετε το περιεχόμενο
- `tls.handshake.extensions_alpn_str == "h2" or tls.handshake.extensions_alpn_str == "h3"`
  - Διαχωρίστε γρήγορα τις κλασικές συνεδρίες HTTPS, HTTP/2 και HTTP/3
- `quic or http3`
  - Εντοπίστε σύγχρονη κίνηση UDP/443 που θα παραβλέψετε αν εξετάσετε μόνο συνομιλίες TCP

### Αναζήτηση

Για να **αναζητήσετε** **περιεχόμενο** μέσα στα **πακέτα** των συνεδριών, πατήστε _CTRL+f_. Μπορείτε να προσθέσετε νέες στήλες στη γραμμή κύριων πληροφοριών (No., Time, Source κ.λπ.) κάνοντας δεξί κλικ και επιλέγοντας επεξεργασία στήλης.

### Παρακολούθηση πολυπλεγμένων ροών

Το Wireshark μπορεί να παρακολουθεί απευθείας ροές `TLS`, `HTTP/2` και `QUIC`. Τα παράθυρα διαλόγου HTTP/2 και QUIC εμφανίζουν επιλογείς σύνδεσης και υποροής, διευκολύνοντας την απομόνωση πολυπλεγμένων ροών που μοιράζονται την ίδια σύνδεση χαμηλότερου επιπέδου.<sup>[[4]](#references)</sup>

Όταν έχετε διαθέσιμα κλειδιά συνεδρίας, εντοπίστε πρώτα το αναγνωριστικό ροής του αιτήματος και, στη συνέχεια, παρακολουθήστε αυτήν την υποροή αντί για ολόκληρη τη συνομιλία TCP ή UDP. Το παράδειγμα `0,1` επιλέγει το HTTP/2 stream ID 1 στη ροή TCP 0· για QUIC χρησιμοποιήστε το `follow,quic,utf-8,<connection-number>,<stream-id>`. Η παρακολούθηση μόνο μιας πλειάδας πέντε στοιχείων μπορεί να αναμείξει ανεξάρτητα αιτήματα ή να μην εντοπίσει μια σύνδεση QUIC μετά από μετεγκατάσταση.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http2.headers.authority || http3.headers.authority' -T fields \
  -e tcp.stream -e http2.streamid -e quic.connection.number \
  -e quic.stream.stream_id -e http2.headers.authority \
  -e http3.headers.authority
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -q -z 'follow,http2,utf-8,0,1'
```

### Δωρεάν εργαστήρια pcap

**Εξασκηθείτε με τις δωρεάν προκλήσεις του:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Αναγνώριση domains

Μπορείτε να προσθέσετε μια στήλη που εμφανίζει την HTTP κεφαλίδα Host:

![Δωρεάν εργαστήρια pcap - Αναγνώριση domains: Μπορείτε να προσθέσετε μια στήλη που εμφανίζει την HTTP κεφαλίδα Host](<../../../images/image (639).png>)

Και μια στήλη που προσθέτει το όνομα διακομιστή από μια αρχική σύνδεση HTTPS (**tls.handshake.type == 1**):

![Δωρεάν εργαστήρια pcap - Αναγνώριση domains: Και μια στήλη που προσθέτει το όνομα διακομιστή από μια αρχική σύνδεση HTTPS ( tls.handshake.type == 1 )](<../../../images/image (408) (1).png>)

Αν η καταγραφή είναι κυρίως κρυπτογραφημένη, η προσθήκη αυτών των πεδίων ως στηλών θα επιταχύνει σημαντικά την αρχική διαλογή:

- `tls.handshake.extensions_server_name`
- `tls.handshake.extensions_alpn_str`
- `tls.handshake.ja3`
- `tls.handshake.ja4` (Wireshark 4.2+)

Έτσι, μπορείτε να ομαδοποιείτε τις συνεδρίες με βάση το hostname, το ALPN (`http/1.1`, `h2`, `h3` κ.λπ.) και το αποτύπωμα του client, ακόμη κι όταν το ίδιο το payload παραμένει κρυπτογραφημένο. Για αποκρυπτογραφημένες καταγραφές HTTP/2 και HTTP/3, είναι επίσης χρήσιμο να προσθέσετε τα `http2.header.value` ή `http3.headers.header.value` ως στήλες και να αναζητήσετε paths, authorities και άλλα ενδιαφέροντα metadata.<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str \
  -e tls.handshake.ja3 -e tls.handshake.ja4
```

### ECH: μην εκλάβετε το εξωτερικό SNI ως τον πραγματικό προορισμό

Το Encrypted ClientHello (ECH) μπορεί να τοποθετήσει ένα δημόσιο όνομα κάλυψης στο ορατό εξωτερικό SNI, ενώ κρυπτογραφεί το εσωτερικό όνομα. Επομένως, μια απογραφή domain που βασίζεται μόνο στο SNI μπορεί να αποδώσει την κίνηση ECH σε λάθος προορισμό. Η επέκταση ECH από μόνη της δεν αποδεικνύει ότι το ECH πέτυχε: οι clients μπορούν να στείλουν μια επέκταση GREASE ECH. Στο Wireshark 4.2+, εντοπίστε τις εξωτερικές προσφορές ECH με το ακόλουθο φίλτρο και θεωρήστε το αναφερόμενο SNI πιθανό όνομα κάλυψης, όχι τον ιστότοπο που ζητήθηκε.<sup>[[5]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng \
  -Y 'tls.handshake.type == 1 && tls.ech.client_hello_type == 0' \
  -T fields -e frame.number -e ip.dst \
  -e tls.handshake.extensions_server_name -e tls.ech.config_id
```

Αν έχετε τα αντίστοιχα κλειδιά συνεδρίας του client, εξετάστε το αποκρυπτογραφημένο HTTP authority/Host αντί να συμπεραίνετε την προέλευση από το εξωτερικό SNI. Χωρίς τα κλειδιά, ελέγξτε άλλα καταγεγραμμένα στοιχεία προέλευσης, όπως plaintext DNS, αλλά μην ταυτίζετε το εξωτερικό SNI με το κρυφό όνομα.<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
tshark -r capture.pcapng -o tls.keylog_file:keys.log \
  -Y 'http.host || http2.headers.authority || http3.headers.authority' \
  -T fields -e ip.dst -e http.host \
  -e http2.headers.authority -e http3.headers.authority
```

## Αναγνώριση τοπικών hostnames

### Από DHCP

Στο τρέχον Wireshark, αντί για `bootp`, πρέπει να αναζητήσετε `DHCP`

![Αναγνώριση τοπικών hostnames - Από DHCP: Στο τρέχον Wireshark, αντί για bootp, πρέπει να αναζητήσετε DHCP](<../../../images/image (1013).png>)

### Από NBNS

![Από DHCP - Από NBNS: Στο τρέχον Wireshark, αντί για bootp, πρέπει να αναζητήσετε DHCP](<../../../images/image (1003).png>)

## Αποκρυπτογράφηση TLS

Η αποκρυπτογράφηση του Wi-Fi link layer είναι ξεχωριστή από την αποκρυπτογράφηση της συνεδρίας TLS· δείτε την [ανάλυση Wi-Fi PCAP](wifi-pcap-analysis.md) για τις απαιτήσεις κλειδιού και handshake.

### Αποκρυπτογράφηση της κίνησης https με το ιδιωτικό κλειδί του server

_edit > preferences > protocols > tls >_

![Αποκρυπτογράφηση TLS - Αποκρυπτογράφηση της κίνησης https με το ιδιωτικό κλειδί του server: Αποκρυπτογράφηση της κίνησης https με το ιδιωτικό κλειδί του server](<../../../images/image (1103).png>)

Πατήστε _Edit_ και προσθέστε όλα τα δεδομένα του server και του ιδιωτικού κλειδιού (_IP, Port, Protocol, Key file και password_)

Αυτή η μέθοδος λειτουργεί μόνο σε περιορισμένο αριθμό περιπτώσεων. Για την τρέχουσα κίνηση TLS 1.3 / ECDHE, η μέθοδος καταγραφής κλειδιών συνεδρίας που ακολουθεί είναι συνήθως η πρακτική επιλογή.<sup>[[1]](#references)</sup>

### Αποκρυπτογράφηση της κίνησης https με συμμετρικά κλειδιά συνεδρίας

Τόσο το Firefox όσο και το Chrome μπορούν να καταγράφουν κλειδιά συνεδριών TLS, τα οποία μπορούν να χρησιμοποιηθούν με το Wireshark για την αποκρυπτογράφηση της κίνησης TLS. Αυτό επιτρέπει την εις βάθος ανάλυση των ασφαλών επικοινωνιών. Περισσότερες λεπτομέρειες για την εκτέλεση αυτής της αποκρυπτογράφησης θα βρείτε στον οδηγό του [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).<sup>[[3]](#references)</sup> Αυτή είναι επίσης η συνήθης μέθοδος για την αποκρυπτογράφηση σύγχρονων καταγραφών TLS 1.3 και QUIC/HTTP/3.<sup>[[2]](#references)</sup>

Για να το εντοπίσετε, αναζητήστε τη μεταβλητή `SSLKEYLOGFILE` στο περιβάλλον.

Ένα αρχείο κοινόχρηστων κλειδιών θα μοιάζει ως εξής:

![Αποκρυπτογράφηση της κίνησης https με το ιδιωτικό κλειδί του server - Αποκρυπτογράφηση της κίνησης https με συμμετρικά κλειδιά συνεδρίας: Ένα αρχείο κοινόχρηστων κλειδιών θα μοιάζει ως εξής](<../../../images/image (820).png>)

Αν η καταγραφή είναι `pcapng`, ελέγξτε αν περιέχει ήδη ενσωματωμένα μυστικά αποκρυπτογράφησης, πριν ψάξετε στο σύστημα αρχείων του host:<sup>[[1]](#references)</sup>

```bash
editcap --extract-secrets capture.pcapng tls-secrets.txt
```

Για να το εισαγάγετε στο Wireshark, μεταβείτε στο \_edit > preferences > protocols > tls > και εισαγάγετέ το στο πεδίο (Pre)-Master-Secret log filename:

![Αποκρυπτογράφηση κίνησης HTTPS με το ιδιωτικό κλειδί του server - Αποκρυπτογράφηση κίνησης HTTPS με συμμετρικά κλειδιά συνεδρίας: editcap --extract-secrets capture.pcapng tls-secrets.txt](<../../../images/image (989).png>)

## Επικοινωνία ADB

Εξαγωγή ενός APK από επικοινωνία ADB κατά την οποία στάλθηκε το APK:

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

- [1] [Wiki του Wireshark για TLS](https://wiki.wireshark.org/TLS)
- [2] [Αποκρυπτογράφηση και ανάλυση της κίνησης HTTP/3 στο Wireshark](https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/)
- [3] [Αποκρυπτογράφηση κίνησης TLS browser με το Wireshark – ο εύκολος τρόπος!](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)
- [4] [Παρακολούθηση ροών πρωτοκόλλων](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)
- [5] [Αναφορά φίλτρων εμφάνισης: Transport Layer Security](https://www.wireshark.org/docs/dfref/t/tls.html)
- [6] [Αναφορά φίλτρων εμφάνισης: HyperText Transfer Protocol 2](https://www.wireshark.org/docs/dfref/h/http2.html)
- [7] [Αναφορά φίλτρων εμφάνισης: Hypertext Transfer Protocol Version 3](https://www.wireshark.org/docs/dfref/h/http3.html)
- [8] [RFC 9849: Κρυπτογραφημένο Client Hello TLS](https://www.rfc-editor.org/rfc/rfc9849.html)
- [9] [Εγχειρίδιο TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
{{#include ../../../banners/hacktricks-training.md}}
