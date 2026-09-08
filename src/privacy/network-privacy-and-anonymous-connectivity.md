# Απόρρητο δικτύου και ανώνυμη συνδεσιμότητα

{{#include ../banners/hacktricks-training.md}}

Το απόρρητο δικτύου είναι απόφαση δρομολόγησης και όχι πλήρης ταυτότητα. Επιλέξτε μια διαδρομή ρωτώντας ποιος δεν πρέπει να μπορεί να συνδέσει την **πηγή**, τον **προορισμό**, το **περιεχόμενο** και τον **χρονισμό**.

Για το κανονικοποιημένο inventory — `Pros`, `Cons`, βήμα προς βήμα `Procedure` και `Detection` για κάθε οικογένεια διαδρομών πρόσβασης — ξεκινήστε από τον [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Αυτή η σελίδα επεκτείνει τις συνήθεις deployable επιλογές.

## Τι μπορεί συνήθως να δει κάθε παρατηρητής

| Διαδρομή | Τοπικό δίκτυο / ISP | Ενδιάμεσος | Προορισμός | Κύριος περιορισμός | Σχετική ταχύτητα |
|---|---|---|---|---|---|
| Direct HTTPS | Metadata πηγής, προορισμού, χρονισμού/όγκου | Το hosting/CDN βλέπει τη σύνδεση | Source IP, δεδομένα browser/app | Δεν παρέχει privacy για το source IP | Ταχύτερη |
| Commercial VPN | Η πηγή είναι συνδεδεμένη στο VPN· όχι τα συνήθη metadata προορισμού | Το VPN βλέπει metadata πηγής και προορισμού | VPN egress IP | Ένας provider γίνεται σημείο συσχέτισης | Συνήθως γρήγορη |
| Self-hosted VPN/VPS | Η πηγή είναι συνδεδεμένη στο VPS | Logs host/account/payment/control-plane | VPS egress IP | Εύκολη συσχέτιση με τον rented server/account | Συνήθως γρήγορη |
| Tor Browser | Η πηγή είναι συνδεδεμένη στο Tor/bridge· χρονισμός/όγκος | Κάθε relay βλέπει περιορισμένο τμήμα | Tor exit, δεδομένα browser | Πιο αργή· κίνδυνοι από accounts/endpoints/correlation | Μέτρια/αργή |
| Tails/Whonix | Παρόμοια διαδρομή Tor, με ισχυρότερα όρια δρομολόγησης | Οι ίδιοι περιορισμοί του Tor | Tor exit/δεδομένα εφαρμογής | Παραμένουν τα operational λάθη και ο host/εξοπλισμός | Μέτρια/αργή |
| Public guest Wi-Fi + HTTPS | Ο χώρος βλέπει τοπική συσκευή/χρονισμό και προορισμούς | Ο ISP του χώρου βλέπει metadata | Guest public IP | Φυσική συσχέτιση με captive portal/συσκευή | Γρήγορη/μεταβλητή |
| Cellular hotspot | Ο carrier βλέπει subscriber/device/location και προορισμούς | VPN/Tor, αν χρησιμοποιείται | Carrier, VPN ή Tor egress IP | Η mobile subscription και η τοποθεσία είναι μόνιμα identifiers | Γρήγορη/μεταβλητή |
| Mixnet | Η πρόσβαση βλέπει χρήση mixnet· χρονισμό/όγκο | Πολλαπλοί mixing nodes | Gateway/egress | Αναδυόμενο ecosystem· κόστος latency και bandwidth | Η πιο αργή |

Το HTTPS προστατεύει το περιεχόμενο κατά τη μεταφορά, αλλά όχι όλα τα metadata. Το EFF σημειώνει ότι το domain, ο χρόνος και το μέγεθος της κίνησης μπορεί να παραμένουν ορατά στους intermediaries, ακόμη και όταν τα page paths, τα credentials και τα messages είναι κρυπτογραφημένα.<sup>[[1]](#references)</sup>

## VPNs: γρήγορο privacy με συγκεντρωμένη εμπιστοσύνη

Ένα VPN είναι χρήσιμο για την απόκρυψη metadata προορισμού από τον access ISP, την προστασία του πρώτου hop σε untrusted network, την παρουσίαση ενός σταθερού engagement egress address ή την πρόσβαση σε private network. Δεν κάνει τον χρήστη **anonymous**. Το VPN βλέπει τη source connection και μπορεί να παρατηρεί metadata προορισμού· accounts, cookies, GPS, fingerprints και payment information παραμένουν.<sup>[[1]](#references)</sup>

### Checklist αξιολόγησης provider

1. **Ownership και jurisdiction:** εντοπίστε τη νομική οντότητα, τη μητρική εταιρεία, τις χώρες λειτουργίας, τους infrastructure subcontractors και τη σχετική legal process.
2. **Collected data:** διακρίνετε account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries και destination logs. Το “No browsing logs” δεν σημαίνει “no data”.
3. **Retention και deletion:** βρείτε τις ακριβείς διάρκειες και αν τα backups, τα fraud systems και οι processors ακολουθούν το ίδιο πρόγραμμα.
4. **Evidence:** προτιμήστε public audits με scope, date, findings και remediation· reproducible/open clients· transparency reports· και documented incidents.
5. **Protocol και client:** maintained WireGuard, OpenVPN ή άλλο reviewed protocol· automatic updates· DNS και IPv6 handling· kill switch· και per-platform leak tests.
6. **Business model:** κατανοήστε πώς χρηματοδοτείται μια free ή subsidized service. Η παρουσία σε app store από μόνη της δεν αποτελεί evidence αξιόπιστης λειτουργίας.
7. **Payment fit:** η alternative payment μπορεί να μειώσει την αποκάλυψη billing προς το VPN, αλλά δεν εξαλείφει το source IP που παρατηρείται σε κάθε connection.

### Διαμόρφωση και επαλήθευση VPN

1. Εγκαταστήστε τον signed client του provider/organization από την επίσημη πηγή του.
2. Επιλέξτε **full tunnel**, εκτός αν ένα documented route πρέπει να παρακάμπτει το VPN. Το split tunneling δημιουργεί paths συσχέτισης και leak.
3. Ενεργοποιήστε fail-closed/always-on behavior και αποκλείστε την κίνηση κατά το reconnect.
4. Στείλτε το DNS μέσω του tunnel και δοκιμάστε IPv4 και IPv6. Απενεργοποιήστε ένα protocol μόνο αν δεν μπορεί να διοχετευτεί με ασφάλεια και έχει γίνει αποδεκτή η απώλεια λειτουργικότητας.
5. Δοκιμάστε sleep/wake, αλλαγή δικτύου, captive-portal login, tunnel crash και hotspot tethering. Το NCSC προειδοποιεί ότι οι tethered clients μπορεί να παρακάμπτουν το VPN ενός phone σε ορισμένες πλατφόρμες.<sup>[[2]](#references)</sup>
6. Χρησιμοποιήστε ένα organization-controlled test endpoint για να καταγράψετε τα observed IPv4, IPv6, DNS resolver και connection timing. Μην εκθέτετε ένα sensitive engagement σε τυχαία “leak test” sites.
7. Επαναλάβετε το test μετά από αλλαγές σε client, OS, network ή policy.

## Tor Browser: ισχυρότερο web unlinkability

Το Tor δημιουργεί circuit μέσω πολλαπλών relays, ώστε κανένα μεμονωμένο relay συνήθως να μη γνωρίζει ταυτόχρονα source και destination. Ο προορισμός βλέπει ένα Tor exit αντί για το IP του χρήστη· το τοπικό δίκτυο συνήθως βλέπει μια Tor connection.<sup>[[3]](#references)</sup> Το Tor έχει σχεδιαστεί για low-latency TCP applications, επομένως είναι πιο αργό και δεν μπορεί να εγγυηθεί προστασία απέναντι σε adversary που μπορεί να συσχετίσει και τα δύο άκρα.<sup>[[4]](#references)</sup>

### Ασφαλές workflow Tor Browser

1. Κατεβάζετε το Tor Browser μόνο από το Tor Project ή επίσημο mirror και επαληθεύετε το signature όταν είναι δυνατό.
2. Χρησιμοποιείτε **Tor Browser**, όχι normal browser που δείχνει σε Tor SOCKS port. Οι ordinary browsers μπορούν να κάνουν leak DNS/WebRTC και identifying state.<sup>[[5]](#references)</sup>
3. Διατηρείτε το default size, fonts, extensions και privacy settings. Πρόσθετα add-ons μπορούν να κάνουν τον browser πιο μοναδικό.<sup>[[6]](#references)</sup>
4. Επιλέγετε το επίπεδο ασφάλειας **Safer** ή **Safest** όταν είναι αποδεκτό το αυξημένο breakage.
5. Χρησιμοποιείτε bridge όταν το direct Tor είναι blocked ή όταν τα ordinary relay IPs θα δημιουργούσαν μη αποδεκτή local visibility. Τα bridges μειώνουν την εύκολη αναγνώριση· δεν εξαλείφουν το traffic analysis.<sup>[[7]](#references)</sup>
6. Μην κάνετε login σε identifying account, μην παρέχετε identifying information και μην ανοίγετε downloaded active documents σε external networked application.
7. Χρησιμοποιείτε ξεχωριστό session/context για κάθε identity. Το “New circuit” δεν είναι το ίδιο με τη διαγραφή της browser/application identity· χρησιμοποιήστε **New Identity** ή κάντε restart το isolated environment, όπως απαιτείται.
8. Προτιμάτε authenticated HTTPS ή authenticated onion service. Ένα Tor exit μπορεί να παρατηρεί unencrypted HTTP traffic.

### Tor και VPN μαζί

Ο συνδυασμός τους δεν είναι αυτόματα ασφαλέστερος. Ένα VPN πριν από το Tor μπορεί να αποκρύψει τις direct Tor relay connections από έναν ISP, ενώ το VPN βλέπει την πηγή· το Tor πριν από ένα VPN δίνει στο VPN σταθερή εικόνα της post-Tor δραστηριότητας και μπορεί να μικρύνει το anonymity set. Η λανθασμένη διαμόρφωση μπορεί να εισαγάγει leaks. Το Tor Project συνιστά τέτοιους συνδυασμούς μόνο για advanced, explicit threat models.<sup>[[8]](#references)</sup>

## Δημόσια και guest Wi-Fi

Το σύγχρονο HTTPS σημαίνει ότι οι παθητικοί γείτονες συνήθως δεν μπορούν να διαβάσουν σωστά κρυπτογραφημένο web content, όμως το guest Wi-Fi δεν παρέχει anonymity. Ο χώρος μπορεί να καταγράφει association times, device identifiers, captive-portal data, destinations και DHCP details· κάμερες, αγορές, μετακινήσεις και physical observation μπορούν να ταυτοποιήσουν τον χρήστη. Ένα fake hotspot με παρόμοιο όνομα μπορεί επίσης να καταγράψει portal credentials ή να χειραγωγήσει unencrypted traffic.<sup>[[9]](#references)</sup>

### Lawful guest-network workflow

1. Χρησιμοποιείτε μόνο δίκτυο που προσφέρεται για guests ή δίκτυο για το οποίο ο owner έχει δώσει explicit permission. Ζητήστε από το staff το ακριβές SSID και τη διαδικασία του portal.
2. Ενημερώστε το endpoint και το travel router πριν από την άφιξη. Απενεργοποιήστε file/printer sharing, inbound discovery, auto-join και remembered-network probing.
3. Ενεργοποιήστε την private/randomized Wi-Fi address του OS. Τα τρέχοντα Apple systems μπορούν να χρησιμοποιούν rotating addresses σε open/weak networks· το σύγχρονο Android randomization είναι συνήθως persistent ανά SSID. Αυτό μειώνει μόνο ένα local identifier.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Προτιμήστε organization-controlled travel router ή low-trust bridge device μεταξύ privileged workstation και guest network. Αυτό συγκεντρώνει την policy firewall/VPN, αλλά δεν αποκρύπτει το router από τον χώρο.<sup>[[12]](#references)</sup>
5. Ολοκληρώστε ένα captive portal μόνο μέσω του designated low-trust device/browser. Ποτέ μην εισάγετε personal ή reused credentials για ένα supposedly anonymous context. Κλείστε τον portal browser αφού αποκατασταθεί η connectivity.
6. Ξεκινήστε full-tunnel VPN ή Tor πριν από sensitive activity και επιβεβαιώστε το fail-closed behavior.
7. Διαγράψτε το network μετά τη χρήση και ελέγξτε την policy του portal account/data-retention.

{% hint style="danger" %}
Το cracking του Wi-Fi ενός γείτονα, η παράκαμψη portal, η χρήση leaked guest credentials, η κλωνοποίηση της πρόσβασης άλλου guest ή η απόκρυψη Raspberry Pi σε café είναι unauthorized activity — όχι privacy technique. Τα ασφαλή ισοδύναμα είναι ένα lawful guest network, ένα client-approved site ή ένα documented drop node που τοποθετείται και ανακτάται με τη γραπτή συναίνεση του property owner.
{% endhint %}

## Travel routers

Ένα travel router μπορεί να απομονώσει ένα workstation από hostile local broadcasts, να επιβάλει firewall, να παρέχει συνεπές internal SSID και να επανασυνδέει αυτόματα ένα VPN. Δεν είναι **anonymous**: το upstream βλέπει το radio identity και το traffic timing, ενώ ο VPN provider βλέπει το tunnel source.

- Χρησιμοποιείτε supported OpenWrt/vendor firmware και αφαιρείτε unused services.
- Διαχειρίζεστε μέσω Ethernet ή dedicated management SSID με unique password.
- Απενεργοποιείτε WAN-side administration, UPnP, WPS, file sharing και unsolicited inbound traffic.
- Χρησιμοποιείτε randomized/private WAN MAC μόνο όπου υποστηρίζεται και επιτρέπεται.
- Επιβάλλετε VPN policy στο router, συμπεριλαμβανομένων DNS και IPv6, και αποκλείετε το egress όταν αποτυγχάνει το tunnel.
- Μην θεωρείτε δεδομένο ότι ένα phone hotspot διοχετεύει τα tethered devices μέσω του VPN του phone· δοκιμάστε το.

## Cellular, SIMs και eSIMs

Το cellular είναι βολικό αλλά όχι anonymous. Οι operators διατηρούν subscriber/device identifiers και location που προκύπτει από το network attachment· ένα eSIM παραμένει mobile subscription. Το prepaid δεν σημαίνει αξιόπιστα unregistered — οι απαιτήσεις διαφέρουν ανά χώρα και αλλάζουν.<sup>[[13]](#references)</sup>

Σε operational επίπεδο:

- Χρησιμοποιείτε ξεχωριστή, supported device για να μειώσετε την έκθεση personal data, όχι για να δημιουργήσετε fictional subscriber.
- Μην μεταφέρετε συνεχώς μια “separate” device δίπλα σε personal phone, αν το co-location βρίσκεται στο threat model.
- Απενεργοποιείτε unused cellular, Wi-Fi, Bluetooth και location access· το powering off αποτελεί ισχυρότερο radio boundary από τα UI toggles.
- Τοποθετείτε sensitive traffic μέσα στο approved VPN/Tor path, αναγνωρίζοντας ότι ο carrier εξακολουθεί να γνωρίζει τη subscription/device location και το tunnel endpoint.
- Επαληθεύετε τους τρέχοντες κανόνες registration και retention με τον national regulator ή local counsel· μην βασίζεστε σε online lists “anonymous SIM countries”.

## DNS και TLS metadata

- Το **DoH/DoT/DoQ** κρυπτογραφεί το DNS μεταξύ client και resolver, αποτρέποντας την απλή local reading ή modification, αλλά ο resolver εξακολουθεί να βλέπει queries και transport identifiers. Μετακινούν την trust· δεν παρέχουν anonymity.<sup>[[14]](#references)</sup>
- Το **ODoH** προσθέτει έναν proxy, ώστε ο resolver να μην χρειάζεται να μάθει το client IP, υπό την προϋπόθεση ότι ο proxy και ο target δεν κάνουν collusion. Το traffic analysis βρίσκεται ρητά εκτός scope.<sup>[[15]](#references)</sup>
- Το **TLS Encrypted Client Hello (ECH)** μπορεί να προστατεύσει το inner server name σε ένα TLS handshake όταν το υποστηρίζουν client, DNS και server. Τα destination IP, timing, volume και endpoint παραμένουν ορατά.<sup>[[16]](#references)</sup>
- Σε σωστά διαμορφωμένο VPN ή Tor environment, το DNS πρέπει να ακολουθεί την υποστηριζόμενη route αυτού του environment. Η προσθήκη ξεχωριστού resolver μπορεί να δημιουργήσει νέο observer ή fingerprint.

### Workflow επαλήθευσης Encrypted-DNS/ECH

1. Αποφασίστε αν το DNS ελέγχεται από το VPN/Tor environment, το OS ή την application. Διαμορφώστε το σε **ένα** intended layer αντί να στοιβάζετε unrelated resolvers.
2. Επιλέξτε resolver με βάση το published privacy/retention policy του και ενεργοποιήστε strict encrypted mode όπου το υποστηρίζει η πλατφόρμα. Το opportunistic fallback μπορεί σιωπηρά να επιστρέψει σε plaintext.
3. Κάντε query σε ένα unique subdomain κάτω από authoritative test zone που ελέγχετε· επιβεβαιώστε ότι το authoritative log βλέπει τον intended recursive resolver.
4. Κάντε capture μόνο της κίνησης της test device με authorization. Επιβεβαιώστε ότι το access network δεν μπορεί να διαβάσει plaintext DNS, αναγνωρίζοντας ότι μπορεί να δει το encrypted resolver/tunnel endpoint.
5. Δοκιμάστε έναν blocked/unreachable encrypted resolver. Η pass condition είναι η επιλεγμένη fail-closed ή documented fallback behavior — όχι ένα accidental clear query.
6. Για ECH, χρησιμοποιήστε controlled ECH-enabled host και ελέγξτε τα client/server diagnostics για να επιβεβαιώσετε ότι έγινε αποδοχή του **inner** ClientHello. Η απλή προσφορά ενός HTTPS record δεν αποδεικνύει ότι το ECH πέτυχε.
7. Επαναλάβετε μετά από network changes, captive portals, browser updates και VPN reconnects. Καταγράψτε ποιο component κατέχει το DNS/ECH, ώστε οι μεταγενέστεροι administrators να μη δημιουργήσουν bypass.

## Mixnets

Τα mixnets, όπως τα Nym ή Katzenpost, προσθέτουν fixed-size packets, delay, reordering και cover traffic για να αντιστέκονται στο timing correlation. Αυτές οι ιδιότητες κοστίζουν σε latency και bandwidth, ενώ τα ανεξάρτητα deployment-scale στοιχεία είναι περιορισμένα. Αντιμετωπίζετε τα τρέχοντα consumer mixnets ως **emerging/high-latency options**, όχι ως ταχύτερες ή εγγυημένες replacements για Tor/VPNs.<sup>[[17]](#references)</sup>

### Workflow αξιολόγησης

1. Εντοπίστε maintained client και την ακριβή supported application· μην εξαναγκάζετε arbitrary browser/system traffic μέσω undocumented proxy.
2. Διαβάστε το τρέχον threat model για τα assumptions σχετικά με entry, mix nodes, gateway, destination και collusion.
3. Εγκαταστήστε από το official signed source σε ξεχωριστό test compartment και χρησιμοποιήστε μόνο benign owned endpoint.
4. Μετρήστε delivery latency, message-size limits, reliability, retransmission και τι συμβαίνει όταν το gateway δεν είναι διαθέσιμο.
5. Επιθεωρήστε το local traffic και το owned endpoint για να επιβεβαιώσετε την intended path και την source. Ελέγξτε αν τα replies χρησιμοποιούν το ίδιο privacy design.
6. Δοκιμάστε shutdown/failure: η application δεν πρέπει να κάνει σιωπηρά fallback σε direct Internet access.
7. Μην απενεργοποιείτε cover traffic, μη μειώνετε τα delays και μην επιλέγετε unusual fixed routes μόνο για ταχύτητα· αυτές οι αλλαγές μπορούν να ακυρώσουν το stated anonymity model.
8. Διατηρήστε το experimental μέχρι το συγκεκριμένο deployment, η independent analysis και η operational reliability να ανταποκρίνονται στο επίπεδο συνεπειών.

## Checklist preflight δικτύου

- [ ] Η authorization καλύπτει το access network, τον target, τις dates και το source infrastructure.
- [ ] Το endpoint δεν περιέχει unrelated identities ή active sync sessions.
- [ ] Η συμπεριφορά IPv4, IPv6, DNS και reconnect συμφωνεί με το plan.
- [ ] Ο destination βλέπει μόνο το expected egress.
- [ ] Η συμπεριφορά captive portal και hotspot έχει δοκιμαστεί χωρίς sensitive traffic.
- [ ] Το local sharing/discovery και το automatic network joining είναι απενεργοποιημένα.
- [ ] Ο observer table και το residual traffic-correlation risk έχουν γίνει αποδεκτά.
- [ ] Η provider policy, το retention και το emergency contact είναι ενημερωμένα.

Για split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P και disposable remote browsers, συνεχίστε στο [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Επιλογή του κατάλληλου VPN για εσάς](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Οδηγίες ασφάλειας συσκευών: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Οι προστασίες privacy και anonymity που προσφέρει το Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Σύντομη εισαγωγή στο Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Χρήση του Tor με άλλους browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins και add-ons στο Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Unblocking του Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Χρήση του Tor Browser με VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Είναι ασφαλή τα Public Wi-Fi Networks;](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy με Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Υλοποίηση MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Αρχές για Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Υποχρεωτική SIM registration: προοπτικές policy και regulation](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations for DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
