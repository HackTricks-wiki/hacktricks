# Covert Physical and Wireless Access

Για μια λεπτομερή, εγκεκριμένη από τον ιδιοκτήτη υλοποίηση που καλύπτει outbound rendezvous, ανάκτηση τροφοδοσίας/uplink, ελάχιστα secrets αποθηκευμένα στη συσκευή, capture testing και monitoring για πιθανή ανακάλυψη, δείτε το [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Η αλλαγή της διαδρομής του δικτύου μπορεί επίσης να αλλάξει την εμφανή φυσική προέλευση. Ένας εξελιγμένος actor μπορεί να χρησιμοποιήσει ένα κοντινό compromised σύστημα, μια κρυφή συσκευή, δημόσια πρόσβαση, cellular backhaul ή έναν satellite receiver, ώστε τα logs του target να υποδεικνύουν διαφορετικό σημείο από αυτό του operator. Κανένα από αυτά δεν εξαλείφει τα φυσικά, radio ή provider στοιχεία· μεταφέρει την απόδοση ευθύνης σε διαφορετικά datasets.

## Technique matrix

| Τεχνική | Εμφανής προέλευση | Απαραίτητη προϋπόθεση | Evidence υψηλής αξίας |
|---|---|---|---|
| Nearby wireless pivot | μια επιχείρηση/κατοικία δίπλα στο target | compromised dual-homed host και πρόσβαση στο Wi-Fi του target | endpoint logs του γειτονικού host, RF association και RADIUS/DHCP του target |
| Public/guest network | NAT του venue ή έξοδος tunnel | νόμιμη πρόσβαση ή bypass των access controls | captive portal, DHCP, AP association, CCTV και payment/location records |
| Covert drop device | wired, Wi-Fi ή cellular διεύθυνση του target/κοντινής περιοχής | φυσική τοποθέτηση ή παράδοση | switchport/USB, RF, inventory, power και outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT ή dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account και traffic timing |
| Satellite-link abuse | subscriber address εντός της περιοχής κάλυψης του beam | weakness ειδική για το protocol και την υπηρεσία | RF location, uplink flow, impossible RTT/routing και provider records |

## Nearest-neighbor attack

Η Volexity τεκμηρίωσε μια επιχείρηση των APT28/GRU το 2022, στην οποία ο actor βρισκόταν απομακρυσμένα από το ultimate target. Εκτέλεσε password spraying στη δημόσια υπηρεσία του target για να αποκτήσει valid credentials, όμως το MFA απέτρεψε την απευθείας σύνδεση από το Internet. Το enterprise Wi-Fi του target αποδεχόταν αυτά τα credentials χωρίς MFA. Ο actor παραβίασε οργανισμούς που βρίσκονταν σε κοντινή φυσική απόσταση από το target, εντόπισε ένα dual-homed σύστημα με wireless reach και χρησιμοποίησε αυτό το σύστημα για να πραγματοποιήσει authentication στο Wi-Fi του target. Η Volexity ονόμασε αυτή την τεχνική **Nearest Neighbor Attack**.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Η καινοτομία βρίσκεται στη σύνθεση. Κανένας operator δεν μεταβαίνει στον στόχο και το Internet-facing service's MFA εξακολουθεί να λειτουργεί. Ο compromised neighbor παρέχει τη φυσική εγγύτητα· το stolen target credential παρέχει logical access· το target Wi-Fi γίνεται η διαδρομή υπέρβασης των ορίων.

### Προαπαιτούμενα και ορατότητα

- Ένα κοντινό σύστημα πρέπει να είναι remotely controllable και να διαθέτει συμβατό radio ή πρόσβαση σε άλλο κοντινό pivot.
- Το target SSID πρέπει να φτάνει σε αυτό το σύστημα και το Wi-Fi admission πρέπει να αποδέχεται reusable credential/certificate/device state.
- Το pivot συχνά χρειάζεται δύο ταυτόχρονες διαδρομές: μία πίσω στον operator και μία προς το target WLAN.
- Ο στόχος μπορεί να δει ένα νέο station MAC και ένα legitimate username, αλλά κανένα αντίστοιχο managed-device certificate, posture, history ή expected building entry.
- Τα logs του neighbor endpoint μπορεί να εμφανίζουν wireless scans, νέα profiles, αλλαγές interfaces, tunneling και remote-control activity.

### Ανίχνευση και πρόληψη

1. Απαιτήστε certificate-backed EAP-TLS και managed-device posture για enterprise Wi-Fi· μην θεωρείτε επαρκές ένα password που απέτυχε στο MFA στο Internet μόνο και μόνο επειδή φτάνει μέσω radio.
2. Συσχετίστε το RADIUS authentication με ταυτότητα MDM/NAC, ιστορικό station/device binding, τοποθεσία AP, συμβάντα physical access και ταυτόχρονες sessions.
3. Δημιουργήστε alert όταν ένας λογαριασμός κάνει association για πρώτη φορά, από ασυνήθιστο AP edge, χωρίς managed certificate ή ενώ η ίδια ταυτότητα είναι ενεργή αλλού.
4. Παρακολουθείτε endpoints που μπορούν να κάνουν bridging interfaces. Σε Windows, Linux και network appliances, διερευνήστε απρόσμενα WLAN profiles, ρυθμίσεις forwarding/NAT, virtual adapters και persistent tunnels.
5. Μειώστε την περιττή διαρροή σήματος με συνετή τοποθέτηση AP και σχεδιασμό ισχύος. Αυτό είναι supporting control και όχι authentication.
6. Συντονίστε το incident response με neighboring tenants: η τελική πηγή radio μπορεί να είναι και η ίδια θύμα.

Το [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) αναπαράγει αυτά τα observables χωρίς επίθεση σε neighbor.

## Public venues και third-party Wi-Fi

Η χρήση Wi-Fi σε café, hotel, airport ή municipal venue αλλάζει τη διεύθυνση IP που εμφανίζεται σε έναν destination. Δεν δημιουργεί anonymity. Το venue ή ο provider του μπορεί να διατηρεί AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation και flow logs. Τα αρχεία φυσικής εισόδου, CCTV, αγορών, mobile-location και ταξιδιών μπορούν να συνδέσουν το digital event με ένα άτομο.

Ένας actor μπορεί να προσπαθήσει να μειώσει ένα από τα αναγνωριστικά χρησιμοποιώντας randomized MAC addresses, ξεχωριστή συσκευή, μετρητά ή tunnel. Η συσχέτιση μεταξύ layers παραμένει δυνατή μέσω της ώρας άφιξης, επαναλαμβανόμενων patterns χρήσης του venue, radio fingerprints, συμπεριφοράς του portal, χρονισμού της κίνησης, footage από κάμερες και του tunnel provider. Ένα VPN μεταφέρει επίσης τον destination από τα venue logs στα VPN logs· δεν αφαιρεί τη γνώση του venue ότι η συσκευή ήταν παρούσα.

Οι defenders δημόσιων access networks θα πρέπει να απομονώνουν τους clients, να αποκλείουν lateral traffic, να χρησιμοποιούν WPA2/3-Enterprise ή per-device keys όπου είναι εφικτό, να διατηρούν αναλογικά DHCP/RADIUS/security logs, να προστατεύουν τα captive portals και να δημοσιεύουν διαδικασία για abuse. Τα red teams θα πρέπει να χρησιμοποιούν τέτοιο venue μόνο όταν το επιτρέπουν οι όροι του και το engagement· η παράκαμψη portal, η κλοπή access ή η στόχευση άλλων guests δεν αποτελεί authorized testing shortcut.

## Covert drop devices και warshipping

Ένα drop είναι ένα μικρό σύστημα που τοποθετείται ή παραδίδεται σε έναν χώρο και στη συνέχεια ελέγχεται μέσω outbound Ethernet, Wi-Fi ή cellular. Το “Warshipping” συσκευάζει τη συσκευή έτσι ώστε η συνηθισμένη παράδοση να τη μεταφέρει εντός του radio perimeter. Το πιθανό hardware κυμαίνεται από single-board computer έως modified charger, USB peripheral, network appliance ή battery-powered modem.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Η συσκευή μπορεί να παρέχει απομακρυσμένο foothold, να πραγματοποιεί wireless μετρήσεις, να emulates ένα εξουσιοδοτημένο exercise peripheral ή να κάνει relay traffic. Η φαινομενική προέλευσή της είναι τοπική, αλλά δημιουργεί physical artifacts: σειριακούς αριθμούς, συσκευασίες, fingerprints, κάμερες, access logs, κατανάλωση ρεύματος, USB descriptors, switchport negotiation, DHCP fingerprints, συμπεριφορά MAC OUI/randomization, RF emissions και επαναλαμβανόμενες rendezvous connections.

### Αμυντικοί έλεγχοι

- Διατηρείτε διαδικασίες για την αίθουσα παραλαβών και την απογραφή assets· επιθεωρείτε απρόσμενα ηλεκτρονικά και πακέτα που απευθύνονται σε ανύπαρκτους υπαλλήλους.
- Χρησιμοποιείτε 802.1X/NAC σε wired και wireless access, απενεργοποιείτε τις αχρησιμοποίητες θύρες και τοποθετείτε άγνωστες συσκευές σε restricted remediation VLAN.
- Δημιουργείτε alerts για νέα DHCP fingerprints, locally administered MACs που παραμένουν, νέες USB network/HID devices, μη εξουσιοδοτημένα Wi-Fi Direct/Bluetooth και long-lived outbound tunnels.
- Δημιουργήστε baseline για switchport, power-over-Ethernet, DNS και TLS behavior. Ένα μικρό host χωρίς record στην απογραφή που πραγματοποιεί περιοδικές encrypted connections αποτελεί ισχυρότερο σήμα από το “Raspberry Pi OUI” από μόνο του.
- Κατά τη διάρκεια ενός exercise, καταγράψτε τα assets, τοποθετήστε labels, ορίστε scope, χρησιμοποιήστε encryption, παρέχετε remote kill, θέστε deadline ανάκτησης και διασφαλίστε ότι η απώλεια δεν μπορεί να εκθέσει επαναχρησιμοποιήσιμα credentials.

## Cellular και eSIM backhaul

Ένα cellular modem αποφεύγει το Internet gateway του στόχου και μπορεί να διατηρεί ένα drop reachable πίσω από carrier NAT μέσω outbound rendezvous. Οι mobile διευθύνσεις μπορεί να αλλάζουν ή να είναι κοινόχρηστες· ο cellular operator εξακολουθεί να διαθέτει ισχυρά στοιχεία για τον συνδρομητή και το δίκτυο: ταυτότητα SIM/eSIM, IMSI, εκχωρημένες διευθύνσεις/θύρες, timing κυψέλης/τομέα, καθώς και records λογαριασμού/πληρωμών και roaming.

Από την πλευρά του enterprise, εντοπίζετε απρόσμενα modems και personal hotspots με wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring και physical inspection. Ένα drop που χρησιμοποιεί cellular για control μπορεί να εντοπιστεί από τη συμπεριφορά του σε τοπικό Ethernet/Wi-Fi και από τις radio emissions του.

Για authorized exercises, ο οργανισμός πρέπει να έχει στην κατοχή του τη subscription και το modem, να καταγράφει τα identifiers μαζί με τον controller και να επαληθεύει ότι οι όροι του carrier/provider επιτρέπουν το traffic. Μια prepaid label ή αγορά με cryptocurrency δεν διαγράφει τα tower, device ή retail records.

## MAC randomization και device fingerprinting

Τα σύγχρονα συστήματα μπορούν να χρησιμοποιούν locally administered random MAC ανά δίκτυο. Αυτό μειώνει το passive long-term tracking μέσω ενός σταθερού factory MAC· δεν αποκρύπτει:

- το probe/association timing και το σύνολο των ζητούμενων network capabilities·
- τα 802.11 information elements, τα supported rates και το vendor-specific behavior·
- τα DHCP options/hostname, τα IPv6 identifiers και το captive-portal/browser fingerprint·
- την authenticated 802.1X identity ή το certificate·
- το higher-layer account, το tunnel και το traffic pattern· ή
- την physical observation.

Οι defenders δεν πρέπει να χρησιμοποιούν MAC allowlists ως authentication. Συνδέστε την radio identity με το certificate/device posture και αντιμετωπίζετε τις μεταβαλλόμενες MACs ως φυσιολογικές, εκτός αν άλλο context είναι anomalous.

## Hijacking δορυφορικής σύνδεσης

Η Kaspersky τεκμηρίωσε ότι η Turla εκμεταλλευόταν αδυναμίες σε παλαιότερο one-way DVB-S satellite Internet. Στο μοντέλο που αναφέρθηκε, ένας legitimate remote subscriber έστελνε outbound requests μέσω terrestrial link, αλλά λάμβανε downstream data μέσω μιας unencrypted wide-area satellite broadcast. Ένας actor εντός του satellite footprint μπορούσε να παρατηρεί το downlink, να επιλέγει ένα active subscriber IP και να φροντίζει ώστε οι C2 replies να απευθύνονται σε αυτό το IP. Τόσο ο legitimate subscriber όσο και ο actor λάμβαναν το broadcast· ο actor εξήγαγε το traffic για την επιλεγμένη port, ενώ ο legitimate subscriber απέρριπτε τα unsolicited packets. Στη συνέχεια, ο C2 operator φαινόταν να χρησιμοποιεί μια διεύθυνση satellite-provider σε άλλη γεωγραφική περιοχή.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Αυτό αφορούσε συγκεκριμένο protocol/service, είχε περιορισμένο bandwidth και δεν ισοδυναμούσε με παραβίαση ενός σύγχρονου αμφίδρομου κρυπτογραφημένου δορυφορικού terminal. Επίσης, δεν έκρυβε τη διαδρομή των εξερχόμενων αιτημάτων του actor από έναν επαρκώς ικανό observer. Οι ευκαιρίες ανίχνευσης περιλαμβάνουν ασύμμετρη/αδύνατη δρομολόγηση, traffic προς subscriber που δεν ξεκίνησε το flow, ασυνήθιστες destination ports, provider telemetry, διερεύνηση της τοποθεσίας του receiver/RF και το malware configuration. Χρησιμοποιήστε αυτή την περίπτωση για να αμφισβητήσετε την υπόθεση ότι το geolocating μιας C2 IP εντοπίζει γεωγραφικά τον controller της — όχι ως οδηγό κατασκευής.

## Φύλλο εργασίας συσχέτισης από το φυσικό στο ψηφιακό

Όταν μια φαινομενικά τοπική πηγή είναι ύποπτη, δημιουργήστε ένα ενιαίο timeline:

1. κανονικοποιήστε τα ρολόγια των AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch και physical-access·
2. εντοπίστε την πρώτη radio association ή link-up, όχι μόνο το πρώτο alert·
3. αντιστοιχίστε το station με certificate, device posture, DHCP fingerprint και την τοποθεσία του switch/AP·
4. αναζητήστε ταυτόχρονη δραστηριότητα remote-control/tunnel σε κοντινά συστήματα·
5. ελέγξτε παραδόσεις, επισκέπτες, εξαιρέσεις inventory, κάμερες και RF findings σύμφωνα με την ισχύουσα policy/law·
6. διατηρήστε τη συσκευή και την volatile network state που θεωρούνται ύποπτες· μην κάνετε power-cycle χωρίς έλεγχο·
7. προσδιορίστε αν η φαινομενική πηγή είναι infrastructure που ελέγχεται από τον actor ή άλλο victim.

## References

- [1] [Volexity — Η επίθεση Nearest Neighbor: Πώς ένα ρωσικό APT weaponized κοντινά Wi-Fi networks](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: Το APT command and control στον ουρανό](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Προσθήκες hardware (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Οδηγίες για την ασφάλεια ασύρματων τοπικών δικτύων](https://csrc.nist.gov/pubs/sp/800/153/final)
