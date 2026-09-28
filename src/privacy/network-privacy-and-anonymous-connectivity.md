# Απόρρητο δικτύου & Anonymous Connectivity

{{#include ../banners/hacktricks-training.md}}

Το απόρρητο δικτύου είναι απόφαση δρομολόγησης και όχι πλήρης ταυτότητα. Επιλέξτε μια διαδρομή ρωτώντας ποιος δεν θα πρέπει να μπορεί να συνδέσει την **πηγή**, τον **προορισμό**, το **περιεχόμενο** και τον **χρονισμό**.

Για το τυποποιημένο inventory—`Pros`, `Cons`, βήμα προς βήμα `Procedure` και `Detection` για κάθε οικογένεια access-path—ξεκινήστε από τον [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Αυτή η σελίδα επεκτείνει τις συνήθεις deployable επιλογές.

## Τι μπορεί συνήθως να δει κάθε observer

| Διαδρομή | Local network / ISP | Intermediary | Destination | Κύριος περιορισμός | Σχετική ταχύτητα |
|---|---|---|---|---|---|
| Direct HTTPS | Metadata πηγής και προορισμού, χρονισμός/όγκος | Το hosting/CDN βλέπει τη σύνδεση | Source IP, δεδομένα browser/app | Δεν παρέχει source-IP privacy | Ταχύτερη |
| Commercial VPN | Η πηγή είναι συνδεδεμένη στο VPN· όχι συνήθως metadata προορισμού | Το VPN βλέπει metadata πηγής και προορισμού | VPN egress IP | Ένας provider γίνεται σημείο συσχέτισης | Συνήθως γρήγορη |
| Self-hosted VPN/VPS | Η πηγή είναι συνδεδεμένη στο VPS | Logs host/account/payment/control-plane | VPS egress IP | Είναι εύκολο να συσχετιστεί με τον rented server/account | Συνήθως γρήγορη |
| Tor Browser | Η πηγή είναι συνδεδεμένη στο Tor/bridge· χρονισμός/όγκος | Κάθε relay βλέπει περιορισμένο τμήμα | Tor exit, δεδομένα browser | Πιο αργή· risks από account/endpoint/correlation | Μέτρια/αργή |
| Tails/Whonix | Παρόμοια διαδρομή Tor, με ισχυρότερα routing boundaries | Οι ίδιοι περιορισμοί του Tor | Tor exit/application data | Τα operational λάθη και το host/hardware παραμένουν | Μέτρια/αργή |
| Public guest Wi-Fi + HTTPS | Ο χώρος βλέπει local device/timing και προορισμούς | Ο ISP του χώρου βλέπει metadata | Guest public IP | Physical/captive-portal/device correlation | Γρήγορη/μεταβλητή |
| Cellular hotspot | Ο carrier βλέπει subscriber/device/location και προορισμούς | VPN/Tor, αν χρησιμοποιείται | Carrier, VPN ή Tor egress IP | Η mobile subscription και η τοποθεσία είναι διαρκή identifiers | Γρήγορη/μεταβλητή |
| Mixnet | Το access βλέπει τη χρήση mixnet· χρονισμός/όγκος | Πολλαπλά mixing nodes | Gateway/egress | Αναδυόμενο ecosystem· κόστος σε latency και bandwidth | Η πιο αργή |

Το HTTPS προστατεύει το περιεχόμενο κατά τη μεταφορά, αλλά όχι όλα τα metadata. Η EFF επισημαίνει ότι το domain, ο χρόνος και το μέγεθος της κίνησης μπορεί να παραμένουν ορατά σε intermediaries, ακόμη και όταν τα page paths, τα credentials και τα messages είναι encrypted.<sup>[[1]](#references)</sup>

## VPNs: γρήγορο privacy με συγκεντρωμένο trust

Ένα VPN είναι χρήσιμο για την απόκρυψη destination metadata από τον access ISP, την προστασία του πρώτου hop σε untrusted network, την παρουσίαση ενός σταθερού engagement egress address ή την πρόσβαση σε private network. **Δεν** καθιστά έναν χρήστη anonymous. Το VPN βλέπει τη source connection και μπορεί να παρατηρεί destination metadata· τα accounts, τα cookies, το GPS, τα fingerprints και τα payment information παραμένουν.<sup>[[1]](#references)</sup>

### Provider evaluation checklist

1. **Ownership και jurisdiction:** εντοπίστε τη legal entity, τη parent company, τις χώρες λειτουργίας, τους infrastructure subcontractors και τη σχετική legal process.
2. **Collected data:** διακρίνετε account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries και destination logs. Το “No browsing logs” δεν σημαίνει “no data”.
3. **Retention και deletion:** βρείτε τις ακριβείς διάρκειες και αν τα backups, τα fraud systems και οι processors ακολουθούν το ίδιο schedule.
4. **Evidence:** προτιμήστε public audits με scope, date, findings και remediation· reproducible/open clients· transparency reports· και documented incidents.
5. **Protocol και client:** maintained WireGuard, OpenVPN ή άλλο reviewed protocol· automatic updates· DNS και IPv6 handling· kill switch· και per-platform leak tests.
6. **Business model:** κατανοήστε πώς χρηματοδοτείται μια free ή subsidized υπηρεσία. Η παρουσία σε app store από μόνη της δεν αποτελεί evidence αξιόπιστης λειτουργίας.
7. **Payment fit:** alternative payment μπορεί να μειώσει την αποκάλυψη billing προς το VPN, αλλά δεν διαγράφει το source IP που παρατηρείται σε κάθε connection.

### Configure και verify ένα VPN

1. Εγκαταστήστε τον signed client του provider/organization από την επίσημη πηγή του.
2. Επιλέξτε **full tunnel**, εκτός αν μια documented route πρέπει να το παρακάμπτει. Το split tunneling δημιουργεί correlation και leak paths.
3. Ενεργοποιήστε fail-closed/always-on behavior και αποκλείστε την κίνηση κατά το reconnect.
4. Στείλτε το DNS μέσω του tunnel και ελέγξτε τόσο το IPv4 όσο και το IPv6. Απενεργοποιήστε ένα protocol μόνο αν δεν μπορεί να tunnel-αριστεί με ασφάλεια και είναι αποδεκτή η απώλεια λειτουργικότητας.
5. Ελέγξτε sleep/wake, network switching, captive-portal login, tunnel crash και hotspot tethering. Το NCSC προειδοποιεί ότι οι tethered clients μπορεί να παρακάμπτουν το VPN ενός phone σε ορισμένες πλατφόρμες.<sup>[[2]](#references)</sup>
6. Χρησιμοποιήστε ένα organization-controlled test endpoint για την καταγραφή των observed IPv4, IPv6, DNS resolver και connection timing. Μην εκθέτετε ένα sensitive engagement σε τυχαία sites για “leak test”.
7. Επαναλάβετε το test μετά από αλλαγές σε client, OS, network ή policy.

### Hostile-LAN routing bypasses

Ένα VPN μπορεί να παραμένει ορατά “connected”, ενώ επιλεγμένα packets παρακάμπτουν το VPN, επειδή το operating system επιλέγει μια route **πριν** το VPN encrypt-άρει το packet. Το TunnelCrack απέδειξε δύο τρόπους abuse κοινών routing exceptions: το **LocalNet** κάνει έναν Internet destination να φαίνεται ότι βρίσκεται στο directly connected subnet, ενώ το **ServerIP** κάνει spoof τη VPN-gateway resolution, ώστε μια target address να κληρονομεί την clear-network exception που απαιτείται από το VPN transport. Πρόκειται για client/routing failures και όχι για breaks στα WireGuard, OpenVPN, IPsec ή TLS· τα HTTPS payloads παραμένουν end-to-end encrypted, αλλά ο local observer μπορεί να ανακτήσει destination/timing metadata και οποιαδήποτε cleartext protocol data.<sup>[[18]](#references)</sup>

Το TunnelVision εφαρμόζει το ίδιο pre-encryption primitive μέσω του DHCP option 121. Ένας malicious ή compromised DHCP server μπορεί να εγκαταστήσει μια classless route πιο specific από την catch-all route του VPN, επιλέγοντας το physical interface για έναν arbitrary host ή range. Το VPN control channel μπορεί να παραμένει ενεργό, επομένως ένα kill switch που ενεργοποιείται μόνο από tunnel disconnection μπορεί να μην ενεργοποιηθεί και ένας μοναδικός public “IP leak” έλεγχος μπορεί να μην εντοπίσει selective bypasses.<sup>[[19]](#references)</sup>

Ένα packet-filter kill switch που επιτρέπει μόνο DHCP και το authenticated VPN transport στο physical interface θα πρέπει να μετατρέπει αυτή την κατάσταση σε fail-closed behavior, όμως το targeted route injection μπορεί και πάλι να δημιουργήσει selective-denial side channel. Για Linux workloads υψηλών συνεπειών, προτιμήστε το ισχυρότερο [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload), όπου το application namespace δεν διαθέτει physical interface ή clear-network default route.<sup>[[19]](#references)</sup>

#### Owned-lab verification

Ελέγξτε τον ακριβή client/OS/version σε owned AP, DHCP server, VPN endpoint και destination· οι product-wide claims παλιώνουν γρήγορα, επειδή οι routing και packet-filter implementations είναι platform-specific. Κάντε capture τόσο στο ίδιο το endpoint όσο και στον test server — ένα egress-IP website από μόνο του δεν αποδεικνύει ότι κάθε destination ακολουθεί το tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Συνδεθείτε στο VPN, καταγράψτε τη διεύθυνση του VPN server και αποθηκεύστε κάθε IPv4/IPv6 routing table και policy-routing rule. Στα Windows χρησιμοποιήστε `route print`; στο macOS χρησιμοποιήστε `netstat -rn`; στο Linux χρησιμοποιήστε τις παρακάτω εντολές.
2. Κάντε query στη selected route για αρκετά owned destination IPs. Το next hop/interface πρέπει να είναι το tunnel, εκτός από το documented VPN transport endpoint.
3. Για το TunnelVision, ανανεώστε το lease στο controlled DHCP network και εγκαταστήστε μια option 121 route **μόνο για ένα owned test destination**. Pass σημαίνει ότι η κίνηση εξακολουθεί να περνά από το tunnel ή να blocked-άρεται — ποτέ να εκπέμπεται ως destination traffic στο physical interface.
4. Για το LocalNet, εκχωρήστε στον client ένα lab-only public documentation subnet, όπως `203.0.113.0/24`, και τοποθετήστε το owned test destination μέσα σε αυτό. Επιβεβαιώστε ότι η ενεργοποίηση LAN access δεν κάνει Internet-class destinations να παρακάμπτουν το tunnel.
5. Για το ServerIP, πριν από τη VPN connection κάντε το controlled DNS να επιλύει το owned VPN hostname στο owned test destination, ενώ το lab gateway προωθεί το VPN transport στο πραγματικό owned VPN endpoint. Ο client δεν πρέπει να εξαιρεί unrelated application traffic προς τη spoofed address.
6. Επαναλάβετε με το “local network access” ενεργοποιημένο και απενεργοποιημένο, μετά από reconnect, sleep/wake, network switching και VPN-process crash. Ελέγξτε ανεξάρτητα IPv4, IPv6 και DNS.
7. Επιθεωρήστε το capture του physical interface. Θα πρέπει να περιέχει DHCP και encrypted packets προς τον VPN server, όχι packets που απευθύνονται απευθείας στο owned test destination. Επιβεβαιώστε επίσης ότι ένα rejected bypass δεν μπορεί να κάνει silently fallback μετά από user prompts ή connectivity repair.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: ισχυρότερη unlinkability στον ιστό

Το Tor δημιουργεί ένα circuit μέσω πολλαπλών relays, ώστε κανένα relay κανονικά να μη γνωρίζει ταυτόχρονα την πηγή και τον προορισμό. Ο προορισμός βλέπει ένα Tor exit αντί για την IP του χρήστη· το τοπικό δίκτυο συνήθως βλέπει μια σύνδεση Tor.<sup>[[3]](#references)</sup> Το Tor έχει σχεδιαστεί για low-latency TCP εφαρμογές, επομένως είναι πιο αργό και δεν μπορεί να εγγυηθεί προστασία απέναντι σε adversary που μπορεί να συσχετίσει και τα δύο άκρα.<sup>[[4]](#references)</sup>

### Ασφαλές workflow Tor Browser

1. Κατέβαζε το Tor Browser μόνο από το Tor Project ή επίσημο mirror και επαλήθευε την υπογραφή, όταν είναι δυνατό.
2. Χρησιμοποίησε το **Tor Browser**, όχι έναν κανονικό browser που έχει ρυθμιστεί να χρησιμοποιεί μια Tor SOCKS port. Οι συνηθισμένοι browsers μπορούν να προκαλέσουν leak DNS/WebRTC και identifying state.<sup>[[5]](#references)</sup>
3. Διατήρησε το προεπιλεγμένο μέγεθος, τις γραμματοσειρές, τα extensions και τις ρυθμίσεις απορρήτου. Πρόσθετα add-ons μπορούν να κάνουν τον browser πιο μοναδικό.<sup>[[6]](#references)</sup>
4. Επίλεξε επίπεδο ασφάλειας **Safer** ή **Safest**, όταν η αυξημένη δυσλειτουργία είναι αποδεκτή.
5. Χρησιμοποίησε bridge όταν το direct Tor είναι αποκλεισμένο ή όταν οι IP των συνηθισμένων relays θα δημιουργούσαν μη αποδεκτή τοπική ορατότητα. Τα bridges μειώνουν την εύκολη αναγνώριση· δεν εξαλείφουν την traffic analysis.<sup>[[7]](#references)</sup>
6. Μην συνδέεσαι σε identifying account, μην παρέχεις identifying information και μην ανοίγεις downloaded active documents σε εξωτερική δικτυωμένη εφαρμογή.
7. Χρησιμοποίησε ξεχωριστό session/context για κάθε identity. Το “New circuit” δεν ισοδυναμεί με διαγραφή της ταυτότητας του browser/application· χρησιμοποίησε **New Identity** ή επανεκκίνησε το isolated environment, ανάλογα με την περίπτωση.
8. Προτίμησε authenticated HTTPS ή authenticated onion service. Ένα Tor exit μπορεί να παρατηρεί μη κρυπτογραφημένη HTTP κίνηση.

### Tor μαζί με VPN

Ο συνδυασμός τους δεν είναι αυτόματα ασφαλέστερος. Ένα VPN πριν από το Tor μπορεί να αποκρύψει τις direct Tor relay connections από έναν ISP, ενώ το VPN βλέπει την πηγή· το Tor πριν από ένα VPN δίνει στο VPN σταθερή εικόνα της δραστηριότητας μετά το Tor και μπορεί να μειώσει το anonymity set. Η λανθασμένη ρύθμιση μπορεί να προκαλέσει leaks. Το Tor Project συνιστά τέτοιους συνδυασμούς μόνο για advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Δημόσια και guest Wi-Fi

Το σύγχρονο HTTPS σημαίνει ότι οι παθητικοί γείτονες συνήθως δεν μπορούν να διαβάσουν σωστά κρυπτογραφημένο web content, όμως το guest Wi-Fi δεν παρέχει anonymity. Ο χώρος μπορεί να καταγράφει χρόνους σύνδεσης, device identifiers, δεδομένα captive portal, προορισμούς και λεπτομέρειες DHCP· κάμερες, αγορές, μεταφορές και φυσική παρατήρηση μπορούν να ταυτοποιήσουν τον χρήστη. Ένα fake hotspot με παρόμοιο όνομα μπορεί επίσης να συλλέξει credentials του portal ή να χειραγωγήσει μη κρυπτογραφημένη κίνηση.<sup>[[9]](#references)</sup>

### Νόμιμο workflow guest network

1. Χρησιμοποίησε μόνο δίκτυο που προσφέρεται για guests ή δίκτυο για το οποίο ο ιδιοκτήτης έχει παραχωρήσει explicit permission. Ζήτησε από το προσωπικό το ακριβές SSID και τη διαδικασία του portal.
2. Ενημέρωσε το endpoint και το travel router πριν από την άφιξη. Απενεργοποίησε το file/printer sharing, το inbound discovery, το auto-join και το probing αποθηκευμένων δικτύων.
3. Ενεργοποίησε την private/randomized Wi-Fi address του OS. Τα τρέχοντα συστήματα Apple μπορούν να χρησιμοποιούν rotating addresses σε open/weak networks· το σύγχρονο Android randomization είναι συνήθως persistent ανά SSID. Αυτό μειώνει μόνο ένα τοπικό identifier.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Προτίμησε organization-controlled travel router ή low-trust bridge device μεταξύ ενός privileged workstation και του guest network. Αυτό συγκεντρώνει την πολιτική firewall/VPN, αλλά δεν αποκρύπτει το router από τον χώρο.<sup>[[12]](#references)</sup>
5. Ολοκλήρωσε ένα captive portal μόνο μέσω της καθορισμένης low-trust συσκευής/browser. Μην εισάγεις ποτέ προσωπικά ή reused credentials για ένα supposedly anonymous context. Κλείσε τον browser του portal αφού αποκατασταθεί η συνδεσιμότητα.
6. Εκκίνησε full-tunnel VPN ή Tor πριν από sensitive activity και επιβεβαίωσε τη συμπεριφορά fail-closed.
7. Διέγραψε το δίκτυο μετά τη χρήση και έλεγξε την πολιτική του portal για account και data retention.

{% hint style="danger" %}
Το cracking του Wi-Fi γείτονα, η παράκαμψη portal, η χρήση leaked guest credentials, η κλωνοποίηση πρόσβασης άλλου guest ή η απόκρυψη Raspberry Pi σε café είναι μη εξουσιοδοτημένη δραστηριότητα — όχι τεχνική απορρήτου. Τα ασφαλή ισοδύναμα είναι ένα νόμιμο guest network, ένα client-approved site ή ένα documented drop node που τοποθετείται και ανακτάται με τη γραπτή συγκατάθεση του ιδιοκτήτη του χώρου.
{% endhint %}

## Travel routers

Ένα travel router μπορεί να απομονώσει ένα workstation από εχθρικά local broadcasts, να επιβάλει firewall, να παρέχει συνεπές εσωτερικό SSID και να επανασυνδέει αυτόματα ένα VPN. **Δεν** είναι anonymous: το upstream βλέπει τη radio identity και τον χρονισμό της κίνησης, ενώ ο VPN provider βλέπει την πηγή του tunnel.

- Χρησιμοποίησε υποστηριζόμενο OpenWrt/vendor firmware και αφαίρεσε μη χρησιμοποιούμενες υπηρεσίες.
- Κάνε administration μέσω Ethernet ή αποκλειστικού management SSID με μοναδικό password.
- Απενεργοποίησε WAN-side administration, UPnP, WPS, file sharing και unsolicited inbound traffic.
- Χρησιμοποίησε randomized/private WAN MAC μόνο όπου υποστηρίζεται και επιτρέπεται.
- Επέβαλε VPN policy στο router, συμπεριλαμβανομένων των DNS και IPv6, και απέκλεισε το egress όταν αποτυγχάνει το tunnel.
- Μην υποθέτεις ότι ένα phone hotspot διοχετεύει τις tethered συσκευές μέσω του VPN του τηλεφώνου· δοκίμασέ το.

## Cellular, SIMs και eSIMs

Το cellular είναι βολικό αλλά όχι anonymous. Οι operators διατηρούν subscriber/device identifiers και τοποθεσία που προκύπτει από τη σύνδεση στο δίκτυο· ένα eSIM εξακολουθεί να είναι mobile subscription. Το prepaid δεν σημαίνει αξιόπιστα unregistered — οι απαιτήσεις διαφέρουν ανά χώρα και αλλάζουν.<sup>[[13]](#references)</sup>

Σε επιχειρησιακό επίπεδο:

- Χρησιμοποίησε ξεχωριστή, υποστηριζόμενη συσκευή για να μειώσεις την έκθεση προσωπικών δεδομένων, όχι για να δημιουργήσεις fictional subscriber.
- Μην μεταφέρεις συνεχώς μια “separate” συσκευή παράλληλα με προσωπικό τηλέφωνο, αν το co-location περιλαμβάνεται στο threat model.
- Απενεργοποίησε αχρησιμοποίητα cellular, Wi-Fi, Bluetooth και location access· η απενεργοποίηση της συσκευής είναι ισχυρότερο radio boundary από τα UI toggles.
- Τοποθέτησε sensitive traffic μέσα στην εγκεκριμένη διαδρομή VPN/Tor, αναγνωρίζοντας ότι ο carrier εξακολουθεί να γνωρίζει τη subscription/device location και το tunnel endpoint.
- Επαλήθευσε τους τρέχοντες κανόνες registration και retention με τον εθνικό regulator ή local counsel· μην βασίζεσαι σε online λίστες με “anonymous SIM countries”.

## DNS και TLS metadata

- Το **DoH/DoT/DoQ** κρυπτογραφεί το DNS μεταξύ client και resolver, αποτρέποντας την απλή τοπική ανάγνωση ή τροποποίηση, αλλά ο resolver εξακολουθεί να βλέπει τα queries και τα transport identifiers. Μεταφέρουν την εμπιστοσύνη· δεν παρέχουν anonymity.<sup>[[14]](#references)</sup>
- Το **ODoH** προσθέτει proxy, ώστε ο resolver να μην χρειάζεται να γνωρίζει την IP του client, υπό την προϋπόθεση ότι proxy και target δεν collude. Η traffic analysis βρίσκεται ρητά εκτός scope.<sup>[[15]](#references)</sup>
- Το **TLS Encrypted Client Hello (ECH)** μπορεί να προστατεύσει το inner server name σε ένα TLS handshake, όταν το υποστηρίζουν client, DNS και server. Η destination IP, ο χρονισμός, ο όγκος και το endpoint παραμένουν ορατά.<sup>[[16]](#references)</sup>
- Σε σωστά ρυθμισμένο περιβάλλον VPN ή Tor, το DNS πρέπει να ακολουθεί την υποστηριζόμενη διαδρομή αυτού του περιβάλλοντος. Η προσθήκη ξεχωριστού resolver μπορεί να δημιουργήσει νέο observer ή fingerprint.

### Workflow επαλήθευσης Encrypted-DNS/ECH

1. Αποφάσισε αν το DNS ελέγχεται από το περιβάλλον VPN/Tor, το OS ή την εφαρμογή. Ρύθμισέ το σε **ένα** intended layer αντί να στοιβάζεις άσχετους resolvers.
2. Επίλεξε resolver βάσει της δημοσιευμένης πολιτικής privacy/retention και ενεργοποίησε strict encrypted mode, όπου το υποστηρίζει η πλατφόρμα. Το opportunistic fallback μπορεί σιωπηρά να επιστρέψει σε plaintext.
3. Κάνε query σε μοναδικό subdomain κάτω από authoritative test zone που ελέγχεις· επιβεβαίωσε ότι το authoritative log βλέπει τον intended recursive resolver.
4. Κατέγραψε μόνο την κίνηση της test device με authorization. Επιβεβαίωσε ότι το access network δεν μπορεί να διαβάσει plaintext DNS, αναγνωρίζοντας ότι μπορεί να δει το encrypted resolver/tunnel endpoint.
5. Δοκίμασε έναν blocked/unreachable encrypted resolver. Η επιτυχία είναι η επιλεγμένη fail-closed ή documented fallback συμπεριφορά — όχι ένα accidental clear query.
6. Για ECH, χρησιμοποίησε controlled ECH-enabled host και εξέτασε τα client/server diagnostics για να επιβεβαιώσεις ότι έγινε αποδεκτό το **inner** ClientHello. Η απλή προσφορά ενός HTTPS record δεν αποδεικνύει ότι το ECH πέτυχε.
7. Επανάλαβε μετά από αλλαγές δικτύου, captive portals, browser updates και VPN reconnects. Κατέγραψε ποιο component έχει την κυριότητα του DNS/ECH, ώστε οι μεταγενέστεροι administrators να μη δημιουργήσουν bypass.

## Mixnets

Τα mixnets όπως τα Nym ή Katzenpost προσθέτουν fixed-size packets, delay, reordering και cover traffic για να αντιστέκονται σε timing correlation. Αυτές οι ιδιότητες έχουν κόστος σε latency και bandwidth, ενώ τα ανεξάρτητα στοιχεία σε κλίμακα deployment είναι περιορισμένα. Αντιμετώπιζε τα τρέχοντα consumer mixnets ως **emerging/high-latency options**, όχι ως ταχύτερες ή εγγυημένες αντικαταστάσεις των Tor/VPNs.<sup>[[17]](#references)</sup>

### Workflow αξιολόγησης

1. Εντόπισε maintained client και την ακριβή supported application· μην εξαναγκάζεις αυθαίρετη browser/system traffic μέσω undocumented proxy.
2. Διάβασε το τρέχον threat model για τις υποθέσεις σχετικά με entry, mix nodes, gateway, destination και collusion.
3. Κάνε εγκατάσταση από την επίσημη signed source σε ξεχωριστό test compartment και χρησιμοποίησε μόνο benign owned endpoint.
4. Μέτρησε delivery latency, message-size limits, reliability, retransmission και τι συμβαίνει όταν το gateway δεν είναι διαθέσιμο.
5. Εξέτασε την τοπική κίνηση και το owned endpoint για να επιβεβαιώσεις την intended path και την source. Έλεγξε αν οι απαντήσεις χρησιμοποιούν το ίδιο privacy design.
6. Δοκίμασε shutdown/failure: η εφαρμογή δεν πρέπει να επιστρέφει σιωπηρά σε direct Internet access.
7. Μην απενεργοποιείς το cover traffic, μην μειώνεις τα delays και μην επιλέγεις unusual fixed routes μόνο για ταχύτητα· αυτές οι αλλαγές μπορούν να ακυρώσουν το δηλωμένο anonymity model.
8. Διατήρησέ το πειραματικό έως ότου το συγκεκριμένο deployment, η ανεξάρτητη ανάλυση και η operational reliability ανταποκρίνονται στο επίπεδο συνεπειών.

## Checklist preflight δικτύου

- [ ] Η authorization καλύπτει το access network, το target, τις ημερομηνίες και την source infrastructure.
- [ ] Το endpoint δεν περιέχει unrelated identities ή active sync sessions.
- [ ] Η συμπεριφορά IPv4, IPv6, DNS και reconnect συμφωνεί με το plan.
- [ ] Το controlled DHCP/local-subnet route injection δεν μπορεί να μετακινήσει την test traffic στη physical interface.
- [ ] Ο προορισμός βλέπει μόνο το expected egress.
- [ ] Η συμπεριφορά captive portal και hotspot έχει δοκιμαστεί χωρίς sensitive traffic.
- [ ] Το local sharing/discovery και το automatic network joining είναι απενεργοποιημένα.
- [ ] Ο observer table και ο residual traffic-correlation risk είναι αποδεκτοί.
- [ ] Η πολιτική του provider, το retention και η emergency contact είναι ενημερωμένα.

Για split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P και disposable remote browsers, συνέχισε στο [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Επιλογή του κατάλληλου VPN για εσάς](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Οδηγίες ασφάλειας συσκευών: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Οι προστασίες απορρήτου και anonymity που προσφέρει το Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Σύντομη εισαγωγή στο Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Χρήση του Tor με άλλους browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins και add-ons στο Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Άρση αποκλεισμού του Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Χρήση του Tor Browser με VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Είναι ασφαλή τα Public Wi-Fi Networks;](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Απόρρητο Wi-Fi με συσκευές Apple](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Υλοποίηση MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Αρχές για Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Υποχρεωτική εγγραφή SIM: προοπτικές πολιτικής και κανονιστικού πλαισίου](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Συστάσεις για Operators υπηρεσιών DNS Privacy](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Παράκαμψη Tunnels: Διαρροή VPN Client Traffic μέσω κατάχρησης Routing Tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Πώς οι Attackers μπορούν να αποκαλύψουν Routing-Based VPNs για Total VPN Leak](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
