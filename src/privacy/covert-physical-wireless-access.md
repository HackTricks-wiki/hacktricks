# Συγκαλυμμένη φυσική και ασύρματη πρόσβαση

{{#include ../banners/hacktricks-training.md}}

Για μια λεπτομερή, εγκεκριμένη από τον ιδιοκτήτη υλοποίηση που καλύπτει outbound rendezvous, ανάκτηση ισχύος/uplink, ελάχιστα secrets αποθηκευμένα στη συσκευή, δοκιμές capture και monitoring για πιθανή ανακάλυψη, δείτε το [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Η αλλαγή της network path μπορεί επίσης να αλλάξει την εμφανή φυσική προέλευση. Ένας εξελιγμένος actor μπορεί να χρησιμοποιήσει ένα κοντινό compromised system, μια κρυφή συσκευή, δημόσια πρόσβαση, cellular backhaul ή έναν satellite receiver, ώστε τα logs του target να υποδεικνύουν διαφορετικό σημείο από αυτό του operator. Κανένα από αυτά δεν εξαλείφει τα φυσικά, radio ή provider evidence· μεταφέρει την απόδοση ευθύνης σε διαφορετικά datasets.

## Πίνακας τεχνικών

| Technique | Εμφανής προέλευση | Απαραίτητη προϋπόθεση | Evidence υψηλής αξίας |
|---|---|---|---|
| Nearby wireless pivot | μια επιχείρηση/οικία δίπλα στο target | compromised dual-homed host και πρόσβαση στο target Wi-Fi | endpoint logs του γειτονικού host, RF association και target RADIUS/DHCP |
| Public/guest network | NAT του χώρου ή tunnel exit | νόμιμη πρόσβαση ή bypass του access control | captive portal, DHCP, AP association, CCTV και payment/location records |
| Covert drop device | wired, Wi-Fi ή cellular address του target/κοντινής περιοχής | φυσική τοποθέτηση ή παράδοση | switchport/USB, RF, inventory, power και outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT ή dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account και traffic timing |
| Satellite-link abuse | subscriber address μέσα στο beam footprint | weakness ειδική για το protocol και την υπηρεσία | RF location, uplink flow, impossible RTT/routing και provider records |

## Nearest-neighbor attack

Η Volexity τεκμηρίωσε μια επιχείρηση της APT28/GRU το 2022, κατά την οποία ο actor βρισκόταν μακριά από το τελικό target. Έκανε password spraying στη public service του target για να αποκτήσει valid credentials, όμως το MFA απέτρεπε το άμεσο Internet login. Το enterprise Wi-Fi του target αποδεχόταν αυτά τα credentials χωρίς MFA. Ο actor παραβίασε οργανισμούς που βρίσκονταν φυσικά κοντά στο target, εντόπισε ένα σύστημα με dual-homed σύνδεση και wireless reach και χρησιμοποίησε αυτό το σύστημα για authentication στο Wi-Fi του target. Η Volexity ονόμασε αυτή την τεχνική **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Η καινοτομία έγκειται στη σύνθεση. Κανένας operator δεν μεταβαίνει στον στόχο και το MFA της υπηρεσίας που είναι εκτεθειμένη στο Internet εξακολουθεί να λειτουργεί. Ο παραβιασμένος γείτονας παρέχει τη φυσική εγγύτητα· το κλεμμένο credential του στόχου παρέχει τη λογική πρόσβαση· το Wi-Fi του στόχου γίνεται η διαδρομή υπέρβασης του ορίου.

### Προαπαιτούμενα και ορατότητα

- Ένα κοντινό σύστημα πρέπει να μπορεί να ελεγχθεί απομακρυσμένα και να διαθέτει συμβατό radio ή πρόσβαση σε άλλο κοντινό pivot.
- Το SSID του στόχου πρέπει να φτάνει σε αυτό το σύστημα και η πρόσβαση στο Wi-Fi πρέπει να αποδέχεται ένα επαναχρησιμοποιήσιμο credential/certificate/device state.
- Το pivot συχνά χρειάζεται δύο ταυτόχρονες διαδρομές: μία πίσω προς τον operator και μία μέσα στο WLAN του στόχου.
- Ο στόχος μπορεί να δει ένα νέο station MAC και ένα έγκυρο username, αλλά κανένα αντίστοιχο managed-device certificate, posture, ιστορικό ή αναμενόμενη είσοδο στο κτίριο.
- Τα logs του endpoint του γείτονα ενδέχεται να εμφανίζουν wireless scans, νέα profiles, αλλαγές interfaces, tunneling και δραστηριότητα remote-control.

### Ανίχνευση και πρόληψη

1. Απαιτήστε certificate-backed EAP-TLS και managed-device posture για εταιρικό Wi-Fi· μην θεωρείτε επαρκές ένα password που απέτυχε στο MFA στο Internet μόνο και μόνο επειδή φτάνει μέσω radio.
2. Συσχετίστε τον έλεγχο ταυτότητας RADIUS με την ταυτότητα MDM/NAC, το ιστορικό binding station/device, την τοποθεσία του AP, τα συμβάντα φυσικής πρόσβασης και τις ταυτόχρονες sessions.
3. Δημιουργήστε alert όταν ένας λογαριασμός συνδέεται για πρώτη φορά, από ασυνήθιστο AP edge, χωρίς managed certificate ή ενώ η ίδια ταυτότητα είναι ενεργή αλλού.
4. Παρακολουθείτε endpoints που μπορούν να κάνουν bridging interfaces. Σε Windows, Linux και network appliances, διερευνήστε μη αναμενόμενα WLAN profiles, ρυθμίσεις forwarding/NAT, virtual adapters και persistent tunnels.
5. Μειώστε τη μη απαραίτητη διαρροή σήματος με λογική τοποθέτηση AP και σχεδιασμό ισχύος. Αυτό είναι υποστηρικτικό μέτρο και όχι authentication.
6. Συντονίστε το incident response με γειτονικούς ενοίκους: η τελική πηγή radio μπορεί να είναι και η ίδια θύμα.

Το [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) αναπαράγει αυτά τα observables χωρίς επίθεση σε γείτονα.

## Δημόσιοι χώροι και Wi-Fi τρίτων

Η χρήση Wi-Fi από café, ξενοδοχείο, αεροδρόμιο ή δήμο αλλάζει τη διεύθυνση IP που εμφανίζεται στον προορισμό. Δεν δημιουργεί ανωνυμία. Ο χώρος ή ο πάροχός του μπορεί να διατηρεί το AP association, το device MAC, το DHCP lease, τον λογαριασμό captive-portal, την επικύρωση μέσω SMS/email και τα flow logs. Η φυσική είσοδος, το CCTV, οι αγορές, τα mobile-location records και τα travel records μπορούν να συνδέσουν το ψηφιακό συμβάν με ένα άτομο.

Ένας actor μπορεί να προσπαθήσει να μειώσει ένα από τα διαθέσιμα ίχνη χρησιμοποιώντας randomized MAC addresses, ξεχωριστή συσκευή, μετρητά ή tunnel. Η συσχέτιση μεταξύ επιπέδων παραμένει δυνατή μέσω της ώρας άφιξης, επαναλαμβανόμενων μοτίβων χρήσης χώρου, radio fingerprints, συμπεριφοράς του portal, χρονισμού της κίνησης, καταγραφών από κάμερες και του παρόχου του tunnel. Ένα VPN μεταφέρει επίσης τον προορισμό από τα logs του χώρου στα logs του VPN· δεν εξαλείφει τη γνώση του χώρου ότι η συσκευή ήταν παρούσα.

Οι defenders δημόσιων δικτύων πρόσβασης πρέπει να απομονώνουν τους clients, να αποκλείουν την πλευρική κίνηση, να χρησιμοποιούν WPA2/3-Enterprise ή per-device keys όπου είναι εφικτό, να διατηρούν αναλογικά DHCP/RADIUS/security logs, να προστατεύουν τα captive portals και να δημοσιεύουν διαδικασία αναφοράς abuse. Τα Red teams πρέπει να χρησιμοποιούν έναν τέτοιο χώρο μόνο όταν οι όροι του και το engagement το επιτρέπουν· η παράκαμψη portal, η κλοπή πρόσβασης ή η στόχευση άλλων επισκεπτών δεν αποτελεί εξουσιοδοτημένη συντόμευση testing.

## Covert drop devices και warshipping

Ένα drop είναι ένα μικρό σύστημα που τοποθετείται ή παραδίδεται σε έναν χώρο και στη συνέχεια ελέγχεται μέσω outbound Ethernet, Wi-Fi ή cellular. Το «warshipping» συσκευάζει τη συσκευή έτσι ώστε μια συνηθισμένη παράδοση να τη μεταφέρει μέσα στην περίμετρο του radio. Το πιθανό hardware κυμαίνεται από single-board computer έως τροποποιημένο charger, USB peripheral, network appliance ή battery-powered modem.

Αρχιτεκτονική λειτουργίας:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Η συσκευή μπορεί να παρέχει απομακρυσμένο foothold, να εκτελεί wireless μετρήσεις, να προσομοιώνει ένα εξουσιοδοτημένο exercise peripheral ή να κάνει relay της κίνησης. Η φαινομενική προέλευσή της είναι τοπική, αλλά δημιουργεί φυσικά artifacts: σειριακούς αριθμούς, συσκευασίες, fingerprints, κάμερες, logs πρόσβασης, κατανάλωση ρεύματος, USB descriptors, διαπραγμάτευση switchport, DHCP fingerprints, συμπεριφορά MAC OUI/randomization, RF emissions και επαναλαμβανόμενες rendezvous connections.

### Defensive controls

- Διατηρείτε διαδικασίες για την αίθουσα παραλαβών και το asset inventory· επιθεωρείτε απρόσμενα ηλεκτρονικά και πακέτα που απευθύνονται σε ανύπαρκτο προσωπικό.
- Χρησιμοποιείτε 802.1X/NAC σε wired και wireless access, απενεργοποιείτε τις μη χρησιμοποιούμενες θύρες και τοποθετείτε τις άγνωστες συσκευές σε περιορισμένο remediation VLAN.
- Δημιουργήστε alerts για νέα DHCP fingerprints, locally administered MACs που παραμένουν, νέες USB network/HID συσκευές, μη εξουσιοδοτημένα Wi-Fi Direct/Bluetooth και outbound tunnels μεγάλης διάρκειας.
- Δημιουργήστε baseline για τη συμπεριφορά των switchport, power-over-Ethernet, DNS και TLS. Ένα μικρό host χωρίς εγγραφή στο inventory, που πραγματοποιεί περιοδικές encrypted connections, αποτελεί ισχυρότερο σήμα από το “Raspberry Pi OUI” από μόνο του.
- Κατά τη διάρκεια ενός exercise, καταγράψτε στο inventory, επισημάνετε, οριοθετήστε το scope, κρυπτογραφήστε, παρέχετε remote kill, ορίστε προθεσμία ανάκτησης και βεβαιωθείτε ότι η απώλεια δεν μπορεί να αποκαλύψει επαναχρησιμοποιήσιμα credentials.

## Cellular και eSIM backhaul

Ένα cellular modem παρακάμπτει το Internet gateway του στόχου και μπορεί να διατηρεί ένα drop προσβάσιμο πίσω από carrier NAT μέσω ενός outbound rendezvous. Οι mobile διευθύνσεις μπορεί να αλλάζουν ή να είναι κοινόχρηστες· ο cellular operator εξακολουθεί να διαθέτει ισχυρά στοιχεία για τον συνδρομητή και το δίκτυο: ταυτότητα SIM/eSIM, IMSI, εκχωρημένες διευθύνσεις/θύρες, χρονισμό cell/sector, καθώς και records λογαριασμού/πληρωμών και roaming.

Από την πλευρά της επιχείρησης, εντοπίζετε απρόσμενα modems και personal hotspots με wireless/RF surveys, inventory των USB/PCI endpoints, περιορισμούς MDM, παρακολούθηση rogue SSID και φυσική επιθεώρηση. Ένα drop που χρησιμοποιεί cellular για control μπορεί και πάλι να εντοπιστεί από τη local Ethernet/Wi-Fi συμπεριφορά του και τις radio emissions του.

Για authorized exercises, ο οργανισμός θα πρέπει να είναι ιδιοκτήτης της subscription και του modem, να καταγράφει τα identifiers μαζί με τον controller και να επιβεβαιώνει ότι οι όροι του carrier/provider επιτρέπουν την κίνηση. Μια prepaid label ή αγορά με cryptocurrency δεν διαγράφει τα records των κεραιών, της συσκευής ή του καταστήματος.

## MAC randomization και device fingerprinting

Τα σύγχρονα συστήματα μπορούν να χρησιμοποιούν ένα locally administered random MAC ανά δίκτυο. Αυτό μειώνει το παθητικό μακροχρόνιο tracking μέσω ενός σταθερού factory MAC· δεν αποκρύπτει:

- τον χρονισμό των probe/association και το σύνολο των ζητούμενων network capabilities·
- τα 802.11 information elements, τα supported rates και τη vendor-specific συμπεριφορά·
- τις DHCP options/hostname, τα IPv6 identifiers και το captive-portal/browser fingerprint·
- την authenticated 802.1X identity ή το certificate·
- το higher-layer account, το tunnel και το traffic pattern· ή
- τη φυσική παρατήρηση.

Οι defenders δεν θα πρέπει να χρησιμοποιούν MAC allowlists ως authentication. Συνδέστε την radio identity με το certificate/device posture και αντιμετωπίζετε τα μεταβαλλόμενα MACs ως φυσιολογικά, εκτός εάν άλλο context είναι ανώμαλο.

## Satellite-link hijacking

Η Kaspersky τεκμηρίωσε ότι η Turla εκμεταλλευόταν αδυναμίες σε παλαιότερο one-way DVB-S satellite Internet. Στο μοντέλο που αναφέρθηκε, ένας νόμιμος remote subscriber έστελνε outbound requests μέσω terrestrial link, αλλά λάμβανε downstream data μέσω ενός unencrypted wide-area satellite broadcast. Ένας actor εντός της κάλυψης του satellite μπορούσε να παρατηρεί το downlink, να επιλέγει μια ενεργή subscriber IP και να φροντίζει ώστε οι C2 replies να απευθύνονται σε αυτή την IP. Τόσο ο νόμιμος subscriber όσο και ο actor λάμβαναν το broadcast· ο actor εξήγαγε την κίνηση για την επιλεγμένη port, ενώ ο νόμιμος subscriber απέρριπτε τα unsolicited packets. Στη συνέχεια, ο C2 operator φαινόταν να χρησιμοποιεί μια διεύθυνση satellite-provider σε διαφορετική γεωγραφική περιοχή.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Αυτό αφορούσε συγκεκριμένο protocol/service, είχε περιορισμένο bandwidth και δεν ισοδυναμούσε με παραβίαση ενός σύγχρονου αμφίδρομου κρυπτογραφημένου satellite terminal. Επίσης, δεν έκρυβε τη διαδρομή του outbound request του actor από έναν επαρκώς ικανό observer. Οι ευκαιρίες εντοπισμού περιλαμβάνουν ασύμμετρη/αδύνατη δρομολόγηση, traffic προς subscriber που δεν ξεκίνησε τη ροή, ασυνήθιστες destination ports, provider telemetry, διερεύνηση της τοποθεσίας του receiver/RF και τη malware configuration. Χρησιμοποιήστε αυτή την περίπτωση για να αμφισβητήσετε την υπόθεση ότι το geolocating ενός C2 IP αποκαλύπτει τη γεωγραφική θέση του controller — όχι ως build recipe.

## Φύλλο εργασίας συσχέτισης physical-to-digital

Όταν μια φαινομενικά τοπική source είναι ύποπτη, δημιουργήστε ένα ενιαίο timeline:

1. συγχρονίστε τα clocks των AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch και συστημάτων physical access·
2. εντοπίστε το πρώτο radio association ή link-up, όχι μόνο το πρώτο alert·
3. αντιστοιχίστε το station με το certificate, το device posture, το DHCP fingerprint και την τοποθεσία του switch/AP·
4. αναζητήστε ταυτόχρονη δραστηριότητα remote-control/tunnel σε κοντινά συστήματα·
5. εξετάστε deliveries, visitors, inventory exceptions, cameras και RF findings σύμφωνα με την ισχύουσα policy/law·
6. διατηρήστε τη suspected device και την volatile network state· μην κάνετε τυφλά power-cycle·
7. προσδιορίστε αν η φαινομενική source είναι infrastructure που ελέγχεται από τον actor ή άλλο victim.

## References

- [1] [Volexity — Η επίθεση Nearest Neighbor: Πώς ένα ρωσικό APT weaponized κοντινά Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: command and control του APT στον ουρανό](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Οδηγίες για την ασφάλεια των Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
