# Απόρρητο δικτύου και Anonymous Connectivity

Το απόρρητο δικτύου είναι απόφαση δρομολόγησης, όχι πλήρης ταυτότητα. Επιλέξτε μια διαδρομή ρωτώντας ποιος δεν θα πρέπει να μπορεί να συσχετίσει την **πηγή**, τον **προορισμό**, το **περιεχόμενο** και τον **χρονισμό**.

Για το κανονικοποιημένο inventory—`Pros`, `Cons`, βήμα προς βήμα `Procedure` και `Detection` για κάθε οικογένεια διαδρομής πρόσβασης—ξεκινήστε από τον [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Αυτή η σελίδα επεκτείνει τις κοινές deployable επιλογές.

## Τι μπορεί συνήθως να δει κάθε observer

| Διαδρομή | Local network / ISP | Intermediary | Destination | Κύριος περιορισμός | Σχετική ταχύτητα |
|---|---|---|---|---|---|
| Direct HTTPS | Metadata πηγής, προορισμού, χρονισμού/όγκου | Το hosting/CDN βλέπει τη σύνδεση | Source IP, δεδομένα browser/app | Καμία προστασία του source IP | Η ταχύτερη |
| Commercial VPN | Η πηγή είναι συνδεδεμένη στο VPN· όχι τα συνήθη metadata προορισμού | Το VPN βλέπει metadata πηγής και προορισμού | VPN egress IP | Ένας provider γίνεται σημείο συσχέτισης | Συνήθως γρήγορη |
| Self-hosted VPN/VPS | Η πηγή είναι συνδεδεμένη στο VPS | Logs του host/account/payment/control-plane | VPS egress IP | Εύκολη απόδοση στον rented server/account | Συνήθως γρήγορη |
| Tor Browser | Η πηγή είναι συνδεδεμένη στο Tor/bridge· χρονισμός/όγκος | Κάθε relay βλέπει περιορισμένο μέρος | Tor exit, δεδομένα browser | Πιο αργό· κίνδυνοι account/endpoint/correlation | Μέτρια/αργή |
| Tails/Whonix | Παρόμοια διαδρομή Tor, με ισχυρότερα routing boundaries | Οι ίδιοι περιορισμοί του Tor | Tor exit/application data | Παραμένουν τα operational mistakes και ο host/hardware | Μέτρια/αργή |
| Public guest Wi-Fi + HTTPS | Το venue βλέπει την τοπική συσκευή/χρονισμό και τους προορισμούς | Ο ISP του venue βλέπει metadata | Guest public IP | Φυσική συσχέτιση με captive portal/συσκευή | Γρήγορη/μεταβλητή |
| Cellular hotspot | Ο carrier βλέπει subscriber/device/location και προορισμούς | VPN/Tor, αν χρησιμοποιείται | Carrier, VPN ή Tor egress IP | Η mobile subscription και η τοποθεσία είναι διαρκή identifiers | Γρήγορη/μεταβλητή |
| Mixnet | Το access βλέπει τη χρήση mixnet· χρονισμό/όγκο | Πολλαπλά mixing nodes | Gateway/egress | Αναδυόμενο ecosystem· κόστος latency και bandwidth | Η πιο αργή |

Το HTTPS προστατεύει το περιεχόμενο κατά τη μεταφορά, αλλά όχι όλα τα metadata. Το EFF σημειώνει ότι το domain, ο χρόνος και το μέγεθος της κίνησης μπορεί να παραμένουν ορατά σε intermediaries, ακόμη και όταν τα page paths, τα credentials και τα messages είναι κρυπτογραφημένα.<sup>[[1]](#references)</sup>

## VPNs: γρήγορο privacy με συγκεντρωμένη εμπιστοσύνη

Ένα VPN είναι χρήσιμο για την απόκρυψη των destination metadata από τον access ISP, την προστασία ενός first hop σε untrusted network, την εμφάνιση ενός σταθερού engagement egress address ή την πρόσβαση σε private network. Δεν καθιστά έναν χρήστη anonymous. Το VPN βλέπει τη source connection και μπορεί να παρατηρεί destination metadata· accounts, cookies, GPS, fingerprints και payment information παραμένουν.<sup>[[1]](#references)</sup>

### Checklist αξιολόγησης provider

1. **Ownership και jurisdiction:** εντοπίστε τη νομική οντότητα, τη μητρική εταιρεία, τις χώρες λειτουργίας, τους infrastructure subcontractors και τη σχετική legal process.
2. **Collected data:** διακρίνετε account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries και destination logs. Το “No browsing logs” δεν σημαίνει “no data”.
3. **Retention και deletion:** βρείτε τις ακριβείς διάρκειες και αν τα backups, τα fraud systems και οι processors ακολουθούν το ίδιο schedule.
4. **Evidence:** προτιμήστε public audits με scope, date, findings και remediation· reproducible/open clients· transparency reports· και documented incidents.
5. **Protocol και client:** maintained WireGuard, OpenVPN ή άλλο reviewed protocol· automatic updates· DNS και IPv6 handling· kill switch· και per-platform leak tests.
6. **Business model:** κατανοήστε πώς χρηματοδοτείται μια free ή subsidized υπηρεσία. Η παρουσία σε app store από μόνη της δεν αποτελεί evidence αξιόπιστης λειτουργίας.
7. **Payment fit:** η alternative payment μπορεί να μειώσει τη billing disclosure προς το VPN, αλλά δεν διαγράφει το source IP που παρατηρείται σε κάθε connection.

### Διαμόρφωση και verification VPN

1. Εγκαταστήστε τον signed client του provider/organization από την επίσημη πηγή του.
2. Επιλέξτε **full tunnel**, εκτός αν ένα documented route πρέπει να το παρακάμπτει. Το split tunneling δημιουργεί correlation και leak paths.
3. Ενεργοποιήστε fail-closed/always-on behavior και block traffic κατά το reconnect.
4. Στείλτε το DNS μέσω του tunnel και ελέγξτε IPv4 και IPv6. Απενεργοποιήστε ένα protocol μόνο αν δεν μπορεί να tunneling με ασφάλεια και έχει γίνει αποδεκτή η απώλεια λειτουργικότητας.
5. Ελέγξτε sleep/wake, network switching, captive-portal login, tunnel crash και hotspot tethering. Το NCSC προειδοποιεί ότι οι tethered clients μπορεί να παρακάμπτουν το VPN ενός τηλεφώνου σε ορισμένες πλατφόρμες.<sup>[[2]](#references)</sup>
6. Χρησιμοποιήστε organization-controlled test endpoint για την καταγραφή των observed IPv4, IPv6, DNS resolver και connection timing. Μην εκθέτετε ένα sensitive engagement σε τυχαία “leak test” sites.
7. Επαναλάβετε το test μετά από αλλαγές σε client, OS, network ή policy.

## Tor Browser: ισχυρότερο web unlinkability

Το Tor δημιουργεί circuit μέσω πολλαπλών relays, ώστε κανένα μεμονωμένο relay συνήθως να μη γνωρίζει τόσο την πηγή όσο και τον προορισμό. Ο προορισμός βλέπει ένα Tor exit αντί για το IP του χρήστη· το local network συνήθως βλέπει μια Tor connection.<sup>[[3]](#references)</sup> Το Tor έχει σχεδιαστεί για low-latency TCP applications, επομένως είναι πιο αργό και δεν μπορεί να εγγυηθεί προστασία απέναντι σε adversary που μπορεί να συσχετίσει και τα δύο άκρα.<sup>[[4]](#references)</sup>

### Ασφαλές workflow Tor Browser

1. Κατεβάστε το Tor Browser μόνο από το Tor Project ή επίσημο mirror και επαληθεύστε την υπογραφή όταν είναι δυνατό.
2. Χρησιμοποιήστε **Tor Browser**, όχι normal browser που δείχνει σε Tor SOCKS port. Οι ordinary browsers μπορούν να κάνουν leak DNS/WebRTC και identifying state.<sup>[[5]](#references)</sup>
3. Διατηρήστε το default size, fonts, extensions και privacy settings. Πρόσθετα add-ons μπορούν να κάνουν τον browser πιο unique.<sup>[[6]](#references)</sup>
4. Επιλέξτε επίπεδο ασφάλειας **Safer** ή **Safest**, όταν είναι αποδεκτό το αυξημένο breakage.
5. Χρησιμοποιήστε bridge όταν το direct Tor είναι blocked ή όταν τα ordinary relay IPs θα δημιουργούσαν unacceptable local visibility. Τα bridges μειώνουν την εύκολη αναγνώριση· δεν εξαλείφουν το traffic analysis.<sup>[[7]](#references)</sup>
6. Μην κάνετε login σε identifying account, μην παρέχετε identifying information και μην ανοίγετε downloaded active documents σε external networked application.
7. Χρησιμοποιήστε separate session/context για κάθε identity. Το “New circuit” δεν είναι το ίδιο με τη διαγραφή του browser/application identity· χρησιμοποιήστε **New Identity** ή επανεκκινήστε το isolated environment, όπως απαιτείται.
8. Προτιμήστε authenticated HTTPS ή authenticated onion service. Ένα Tor exit μπορεί να παρατηρεί unencrypted HTTP traffic.

### Tor και VPN μαζί

Ο συνδυασμός τους δεν είναι αυτομάτως ασφαλέστερος. Ένα VPN πριν από το Tor μπορεί να αποκρύψει τις direct Tor relay connections από έναν ISP, ενώ το VPN βλέπει την πηγή· το Tor πριν από ένα VPN δίνει στο VPN σταθερή εικόνα της post-Tor activity και μπορεί να μικρύνει το anonymity set. Η κακή διαμόρφωση μπορεί να εισαγάγει leaks. Το Tor Project συνιστά τέτοιους συνδυασμούς μόνο για advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Public και guest Wi-Fi

Το σύγχρονο HTTPS σημαίνει ότι οι passive neighbors συνήθως δεν μπορούν να διαβάσουν σωστά κρυπτογραφημένο web content, όμως το guest Wi-Fi δεν παρέχει anonymity. Το venue μπορεί να καταγράφει association times, device identifiers, captive-portal data, destinations και DHCP details· κάμερες, αγορές, μεταφορές και physical observation μπορούν να ταυτοποιήσουν τον χρήστη. Ένα fake hotspot με παρόμοιο όνομα μπορεί επίσης να συλλέξει portal credentials ή να τροποποιήσει unencrypted traffic.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Χρησιμοποιήστε μόνο network που προσφέρεται για guests ή για το οποίο ο owner έχει δώσει explicit permission. Ζητήστε από το staff το ακριβές SSID και τη διαδικασία του portal.
2. Ενημερώστε το endpoint και το travel router πριν από την άφιξη. Απενεργοποιήστε file/printer sharing, inbound discovery, auto-join και remembered-network probing.
3. Ενεργοποιήστε την private/randomized Wi-Fi address του OS. Τα τρέχοντα Apple systems μπορούν να χρησιμοποιούν rotating addresses σε open/weak networks· το σύγχρονο Android randomization είναι συνήθως persistent ανά SSID. Αυτό μειώνει μόνο ένα local identifier.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Προτιμήστε organization-controlled travel router ή low-trust bridge device μεταξύ privileged workstation και guest network. Αυτό συγκεντρώνει την policy του firewall/VPN, αλλά δεν κρύβει το router από το venue.<sup>[[12]](#references)</sup>
5. Ολοκληρώστε captive portal μόνο μέσω του designated low-trust device/browser. Ποτέ μην εισάγετε personal ή reused credentials για supposedly anonymous context. Κλείστε τον portal browser αφού αποκατασταθεί η connectivity.
6. Εκκινήστε full-tunnel VPN ή Tor πριν από sensitive activity και επιβεβαιώστε fail-closed behavior.
7. Κάντε forget το network μετά τη χρήση και ελέγξτε την policy του portal account/data-retention.

{% hint style="danger" %}
Το cracking του Wi-Fi ενός γείτονα, η παράκαμψη portal, η χρήση leaked guest credentials, το cloning της πρόσβασης άλλου guest ή η απόκρυψη Raspberry Pi σε café είναι unauthorized activity—not a privacy technique. Τα ασφαλή ισοδύναμα είναι ένα lawful guest network, ένα client-approved site ή ένα documented drop node που τοποθετείται και ανακτάται με written consent του property owner.
{% endhint %}

## Travel routers

Ένα travel router μπορεί να απομονώσει ένα workstation από hostile local broadcasts, να επιβάλει firewall, να παρέχει συνεπές internal SSID και να επανασυνδέει αυτόματα ένα VPN. Δεν είναι anonymous: το upstream βλέπει τη radio identity και το traffic timing του, ενώ ο VPN provider βλέπει την πηγή του tunnel.

- Χρησιμοποιήστε supported OpenWrt/vendor firmware και αφαιρέστε unused services.
- Κάντε administration μέσω Ethernet ή dedicated management SSID με unique password.
- Απενεργοποιήστε WAN-side administration, UPnP, WPS, file sharing και unsolicited inbound traffic.
- Χρησιμοποιήστε randomized/private WAN MAC μόνο όπου υποστηρίζεται και επιτρέπεται.
- Επιβάλετε VPN policy στο router, συμπεριλαμβανομένων DNS και IPv6, και κάντε block το egress όταν αποτυγχάνει το tunnel.
- Μην υποθέτετε ότι ένα phone hotspot κάνει tunnel τις tethered devices μέσω του VPN του τηλεφώνου· κάντε test.

## Cellular, SIMs και eSIMs

Το cellular είναι βολικό αλλά όχι anonymous. Οι operators διατηρούν subscriber/device identifiers και location που προκύπτει από το network attachment· ένα eSIM παραμένει mobile subscription. Το prepaid δεν σημαίνει αξιόπιστα unregistered—οι απαιτήσεις διαφέρουν ανά χώρα και αλλάζουν.<sup>[[13]](#references)</sup>

Λειτουργικά:

- Χρησιμοποιήστε separate, supported device για να μειώσετε την έκθεση personal data, όχι για να δημιουργήσετε fictional subscriber.
- Μην μεταφέρετε συνεχώς ένα “separate” device μαζί με personal phone, αν το co-location περιλαμβάνεται στο threat model.
- Απενεργοποιήστε unused cellular, Wi-Fi, Bluetooth και location access· η απενεργοποίηση της συσκευής είναι ισχυρότερο radio boundary από τα UI toggles.
- Τοποθετήστε το sensitive traffic μέσα στο approved VPN/Tor path, αναγνωρίζοντας ότι ο carrier εξακολουθεί να γνωρίζει τη subscription/device location και το tunnel endpoint.
- Επαληθεύστε τους τρέχοντες registration και retention rules με τον national regulator ή local counsel· μην βασίζεστε σε online lists με “anonymous SIM countries”.

## DNS και TLS metadata

- Το **DoH/DoT/DoQ** κρυπτογραφεί το DNS μεταξύ client και resolver, αποτρέποντας την απλή local ανάγνωση ή τροποποίηση, αλλά ο resolver εξακολουθεί να βλέπει queries και transport identifiers. Μετακινούν την εμπιστοσύνη· δεν παρέχουν anonymity.<sup>[[14]](#references)</sup>
- Το **ODoH** προσθέτει proxy, ώστε ο resolver να μην χρειάζεται να γνωρίζει το client IP, υπό την προϋπόθεση ότι proxy και target δεν collude. Το traffic analysis εξαιρείται ρητά από το scope.<sup>[[15]](#references)</sup>
- Το **TLS Encrypted Client Hello (ECH)** μπορεί να προστατεύσει το inner server name σε TLS handshake όταν το υποστηρίζουν client, DNS και server. Το destination IP, ο χρονισμός, ο όγκος και το endpoint παραμένουν ορατά.<sup>[[16]](#references)</sup>
- Σε σωστά configured VPN ή Tor environment, το DNS θα πρέπει να ακολουθεί το supported route αυτού του environment. Η προσθήκη separate resolver μπορεί να δημιουργήσει νέο observer ή fingerprint.

### Workflow verification Encrypted-DNS/ECH

1. Αποφασίστε αν το DNS ελέγχεται από το VPN/Tor environment, το OS ή την application. Ρυθμίστε το σε **ένα** intended layer αντί να στοιβάζετε unrelated resolvers.
2. Επιλέξτε resolver με βάση το published privacy/retention policy του και ενεργοποιήστε strict encrypted mode όπου το υποστηρίζει η platform. Το opportunistic fallback μπορεί σιωπηρά να επιστρέψει σε plaintext.
3. Κάντε query σε unique subdomain κάτω από authoritative test zone που ελέγχετε· επιβεβαιώστε ότι το authoritative log βλέπει τον intended recursive resolver.
4. Κάντε capture μόνο της traffic του test device με authorization. Επιβεβαιώστε ότι το access network δεν μπορεί να διαβάσει plaintext DNS, αναγνωρίζοντας ότι μπορεί να δει το encrypted resolver/tunnel endpoint.
5. Ελέγξτε έναν blocked/unreachable encrypted resolver. Η επιτυχία είναι η επιλεγμένη fail-closed ή documented fallback behavior—not an accidental clear query.
6. Για ECH, χρησιμοποιήστε controlled ECH-enabled host και ελέγξτε τα client/server diagnostics για να επιβεβαιώσετε ότι έγινε αποδεκτό το **inner** ClientHello. Η απλή προσφορά ενός HTTPS record δεν αποδεικνύει ότι το ECH πέτυχε.
7. Επαναλάβετε μετά από network changes, captive portals, browser updates και VPN reconnects. Καταγράψτε ποιο component κατέχει το DNS/ECH, ώστε μεταγενέστεροι administrators να μην δημιουργήσουν bypass.

## Mixnets

Τα mixnets όπως τα Nym ή Katzenpost προσθέτουν fixed-size packets, delay, reordering και cover traffic για την αντίσταση σε timing correlation. Αυτές οι ιδιότητες κοστίζουν σε latency και bandwidth, ενώ τα ανεξάρτητα deployment-scale evidence είναι περιορισμένα. Αντιμετωπίστε τα τρέχοντα consumer mixnets ως **emerging/high-latency options**, όχι ως ταχύτερες ή εγγυημένες replacements των Tor/VPNs.<sup>[[17]](#references)</sup>

### Workflow αξιολόγησης

1. Εντοπίστε maintained client και το ακριβές supported application· μην εξαναγκάζετε arbitrary browser/system traffic μέσω undocumented proxy.
2. Διαβάστε το current threat model για τις assumptions σχετικά με entry, mix nodes, gateway, destination και collusion.
3. Εγκαταστήστε από την official signed source σε separate test compartment και χρησιμοποιήστε μόνο benign owned endpoint.
4. Μετρήστε delivery latency, message-size limits, reliability, retransmission και τι συμβαίνει όταν το gateway δεν είναι διαθέσιμο.
5. Επιθεωρήστε την local traffic και το owned endpoint για να επιβεβαιώσετε την intended path και την πηγή. Ελέγξτε αν οι replies χρησιμοποιούν το ίδιο privacy design.
6. Ελέγξτε shutdown/failure: η application δεν πρέπει να κάνει σιωπηρά fallback σε direct Internet access.
7. Μην απενεργοποιείτε cover traffic, μην μειώνετε delays και μην επιλέγετε unusual fixed routes απλώς για ταχύτητα· αυτές οι αλλαγές μπορούν να ακυρώσουν το stated anonymity model.
8. Διατηρήστε το experimental έως ότου το συγκεκριμένο deployment, η independent analysis και η operational reliability ανταποκρίνονται στο consequence level.

## Checklist network preflight

- [ ] Η authorization καλύπτει το access network, το target, τις ημερομηνίες και το source infrastructure.
- [ ] Το endpoint δεν περιέχει unrelated identities ή active sync sessions.
- [ ] Τα IPv4, IPv6, DNS και reconnect behavior συμφωνούν με το plan.
- [ ] Το destination βλέπει μόνο το expected egress.
- [ ] Το captive portal και η συμπεριφορά του hotspot έχουν δοκιμαστεί χωρίς sensitive traffic.
- [ ] Το local sharing/discovery και το automatic network joining είναι disabled.
- [ ] Ο observer table και ο residual traffic-correlation risk έχουν γίνει αποδεκτοί.
- [ ] Η policy, το retention και το emergency contact του provider είναι current.

Για split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P και disposable remote browsers, συνεχίστε στο [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Επιλογή του κατάλληλου VPN για εσάς](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Οδηγίες ασφάλειας συσκευών: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Οι προστασίες privacy και anonymity που προσφέρει το Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Σύντομη εισαγωγή στο Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Χρήση του Tor με άλλους browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins και add-ons στο Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Άρση του αποκλεισμού του Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Χρήση του Tor Browser με VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Είναι ασφαλή τα Public Wi-Fi Networks;](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy με Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Υλοποίηση MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Αρχές για Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Υποχρεωτική SIM registration: policy και regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Συστάσεις για DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
