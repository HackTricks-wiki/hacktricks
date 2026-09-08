# Κατάλογος Τεχνικών Anonymous Internet Access

Αυτό είναι το canonical inventory των access paths. Καλύπτει **families** πρωτοκόλλων και επιχειρησιακών πρακτικών, όχι κάθε όνομα vendor. Καμία διαδρομή στο Internet δεν εγγυάται anonymity: στοιχεία λογαριασμού, browser, endpoint, χρονισμού, πληρωμών, cloud-control-plane και φυσικά στοιχεία μπορούν να ακυρώσουν ακόμη και μια διαδρομή που φαίνεται άψογη.

Κάθε καταχώριση χρησιμοποιεί τα ίδια πεδία. Το “Procedure” σημαίνει lawful deployment ή emulation σε owned lab. Όπου η πραγματική τεχνική εξαρτάται από compromise router, κλοπή πρόσβασης ή κατάχρηση unwilling intermediary, η αναπαραγωγή χρησιμοποιεί systems που ανήκουν στην άσκηση.

## Coverage matrix

| Family | Τι βλέπει ο προορισμός | Ισχυρότερη ιδιότητα | Ταχύτητα | Αντιμετώπιση |
|---|---|---|---|---|
| Shared NAT/CGNAT | κοινή public address | ασάφεια μεταξύ subscribers | υψηλή | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | γρήγορος διαχωρισμός source-address | υψηλή | deployable |
| Multi-hop/split relay, MASQUE | final proxy | διαχωρισμός γνώσης ή πλήρες IP tunnel | υψηλή/μέτρια | deployable με trusted relays |
| Tor, bridge, onion service | exit ή onion identity | multi-party path και κοινός browser | μέτρια | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay ή αντίσταση στον χρονισμό | χαμηλή/μεταβλητή | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | διαχωρισμός source/request | υψηλή | μόνο supported applications |
| Public Wi-Fi, travel router | venue/tunnel address | αλλαγή τοποθεσίας/access-path | υψηλή | απαιτείται permission |
| Cellular/eSIM, satellite | carrier/provider address | ανεξάρτητο physical uplink | υψηλή/μεταβλητή | ο subscriber/provider παρατηρεί |
| Remote browser/jump host | remote workspace | διαχωρισμός endpoint και egress | υψηλή | deployable |
| Residential/mobile proxy | consumer/carrier address | εμφάνιση consumer network | υψηλή | κρίσιμα consent/provenance |
| ORB/compromised relay | address άλλου victim | απόκρυψη προέλευσης και borrowed reputation | υψηλή | μόνο owned-lab reproduction |
| CDN/fronting/redirector | CDN/front address | προστασία back-end infrastructure | υψηλή | απαιτείται provider/owner approval |
| Fast flux/DGA/dead drop | rotating node/service | αντίσταση στην ανακάλυψη infrastructure | μεταβλητή | μόνο owned-lab reproduction |
| Drop/nearest-neighbor | address κοντά στον target | διέλευση geographic/network boundary | υψηλή | μόνο owned-site lab |
| Store-and-forward/offline | gateway ή physical receiver | περιορισμός interactive timing linkage | χαμηλή | application-specific |
| Pluggable/refraction transport | Tor entry ή cooperating diversion proxy | censorship-resistant reachability | μεταβλητή | supported client ή research lab |
| IPFS gateway/PIR/remote fetcher | gateway ή application service | διαχωρισμός publisher/query/request | μεταβλητή | bounded application only |
| Anycast/QUIC/MPTCP | stable broker ή multiple subflows | rendezvous και session continuity | υψηλή | availability, όχι anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | υψηλή | μόνο owned workflow |
| Non-IP local first hop | organization gateway | αφαίρεση Internet stack από sensor | χαμηλή | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** Αρκετοί users μοιράζονται μία public address· ο access provider αντιστοιχίζει subscriber-side addresses και ports στο public tuple.

**Pros:** γρήγορο· δεν απαιτείται ειδικός client· το destination-side IP μπορεί να ταυτοποιεί μόνο household, venue ή carrier pool.

**Cons:** Ο provider μπορεί να διατηρεί subscriber/port/time mappings· accounts και fingerprints παραμένουν· άλλοι users μπορούν να βλάψουν τη reputation της address.

**Procedure:** (1) επιβεβαίωσε αν το authorized access χρησιμοποιεί NAT/CGNAT· (2) κατέγραψε το ακριβές public IP και source port σε owned endpoint· (3) κράτησε χωριστές τις application identities· (4) μην αντιμετωπίζεις το shared addressing ως privacy control· (5) χρησιμοποίησε ισχυρότερο path αν ο ISP δεν πρέπει να γνωρίζει τους προορισμούς.

**Detection:** Τα destinations πρέπει να διατηρούν source port και ακριβή χρόνο, όχι μόνο IP. Οι providers συσχετίζουν NAT allocation logs· οι investigators συνδυάζουν account/device/browser evidence.

## Commercial VPN

**Mechanics:** Μια encrypted full-tunnel connection τερματίζει στο VPN· τα destinations βλέπουν το egress του. Το VPN μπορεί συνήθως να συσχετίσει source, timing και destinations.

**Pros:** γρήγορο· απλό· προστατεύει από local passive observation· σταθερά ή shared exits· κατάλληλο για controlled red-team egress.

**Cons:** συγκεντρωμένη εμπιστοσύνη· billing/login telemetry· failures σε kill-switch/DNS/IPv6· τα shared exits συχνά αποκλείονται λόγω reputation.

**Procedure:** (1) ταυτοποίησε provider, owner, jurisdiction, retention και assessment policy· (2) εγκατάστησε τον signed official client· (3) ενεργοποίησε full tunnel, always-on και fail-closed behavior· (4) δρομολόγησε σκόπιμα DNS και IPv6· (5) επαλήθευσε observed IPv4/IPv6/DNS σε owned endpoint· (6) σταμάτησε/επανασύνδεσε το tunnel και επιβεβαίωσε ότι δεν υπάρχει clear fallback.<sup>[[1]](#references)</sup>

**Detection:** Τα local networks βλέπουν μακρύ encrypted flow προς VPN infrastructure· οι providers έχουν authentication/connection records· τα destinations χρησιμοποιούν ASN/reputation μαζί με account, TLS/browser και behavior correlation.

## Self-hosted VPN or rented VPS egress

**Mechanics:** Ο operator ελέγχει WireGuard/OpenVPN gateway ή προωθεί traffic μέσω rented server.

**Pros:** προβλέψιμα υψηλή ταχύτητα· fixed allowlistable address· custom logging/firewall· καλός incident control.

**Cons:** μικρό anonymity set· cloud tenant, payment, source login, API και image history συνδέουν τον operator· ένας distinctive νέος server ομαδοποιείται εύκολα.

**Procedure:** (1) δημιούργησε engagement-specific organization project· (2) κάνε provision supported image και fixed address· (3) περιόρισε το management σε MFA/key-based administration· (4) ρύθμισε full-tunnel egress και DNS· (5) επίτρεψε μόνο scoped destinations όπου είναι πρακτικό· (6) έλεγξε leak/failure behavior· (7) διατήρησε controller audit records· (8) κατέστρεψε credentials και resources στο teardown.

**Detection:** Συσχέτισε hosting ASN, first-seen address, certificate/service fingerprint και scanning behavior· οι cloud owners χρησιμοποιούν control-plane, console, billing και flow logs.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** Μια application ζητά από proxy να ανοίξει TCP stream· το SOCKS μπορεί επίσης να μεταφέρει name resolution και UDP, ανάλογα με την έκδοση· το SSH προωθεί streams μέσα σε μία encrypted session.

**Pros:** ελαφρύ· per-application· γρήγορο· χρήσιμο για chaining και πρόσβαση σε segmented networks.

**Cons:** οι applications μπορούν να το παρακάμψουν· το DNS μπορεί να leak· ο proxy βλέπει adjacent endpoints· το browser state παραμένει· τα open proxies μπορεί να είναι traps ή compromised systems.

**Procedure:** (1) κάνε deploy τον proxy σε owned host· (2) απαίτησε authentication και περιόρισε source/destination· (3) ρύθμισε ένα disposable application profile· (4) εξασφάλισε remote DNS resolution όπου απαιτείται· (5) επαλήθευσε με owned DNS/HTTP endpoint· (6) μπλόκαρε το direct egress για το workload· (7) έλεγξε και άλλαξε τα proxy credentials.

**Detection:** Εντόπισε tunnel-capable processes, CONNECT/SOCKS negotiation, μακρές SSH sessions και destinations ασύμβατα με την application· τα proxy logs ανακατασκευάζουν τα streams.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** Ένα website ανακτά destination και ξαναγράφει links/forms μέσω του origin του, ή ένα extension κατευθύνει browser requests σε proxy. Το destination βλέπει το service, ενώ το service μπορεί να δει plaintext μετά από TLS termination και να εισαγάγει ή να διατηρήσει content.

**Pros:** δεν απαιτεί system-wide client· γρήγορο για απλό browsing· λειτουργεί όπου δεν είναι δυνατή η εγκατάσταση VPN.

**Cons:** Ο proxy μπορεί να διαβάσει credentials/content, να αλλάξει downloads και να κάνει fingerprint users· scripts/WebSockets/downloads μπορεί να παρακάμπτουν το proxy· το browser extension έχει ευρείες privileges· μικρό anonymity set και συχνό blocking.

**Procedure:** (1) χρησιμοποίησε μόνο organization-operated proxy για authorized testing· (2) απομόνωσέ τον σε disposable browser χωρίς personal accounts· (3) απαγόρευσε password entry και sensitive downloads· (4) επαλήθευσε ότι κάθε subresource σε owned page περνά από τον proxy· (5) έλεγξε WebSocket, download και form behavior· (6) αφαίρεσε extension/profile μετά τη χρήση.

**Detection:** Το destination καταγράφει τον proxy· enterprise proxy/DNS και extension inventory ταυτοποιούν το service· content-security/reporting ή owned canary subresources αποκαλύπτουν direct bypass· τα proxy logs αντιστοιχίζουν user session με targets.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** Ένα entry βλέπει το source, ενώ ένα ή περισσότερα traversal relays το διαχωρίζουν από exit που βλέπει το destination.

**Pros:** κανένα συνηθισμένο relay δεν χρειάζεται να γνωρίζει και τα δύο άκρα· failure/seizure ενός node αποκαλύπτει λιγότερα· ευέλικτη γεωγραφία.

**Cons:** κοινή administration/logs ακυρώνουν τον διαχωρισμό· latency· timing correlation· περισσότερα failures και DNS routes· το ίδιο account/payment μπορεί να συνδέσει όλα τα hops.

**Procedure:** (1) καθόρισε ποιον observer αφαιρεί κάθε hop· (2) χρησιμοποίησε independently administered owned/approved relays όπου απαιτείται separation· (3) επέβαλε entry-only access από το workload· (4) εξασφάλισε ότι κάθε relay μπορεί να φτάσει μόνο στο επόμενο hop· (5) επαλήθευσε logs σε κάθε layer· (6) σταμάτησε κάθε hop και επιβεβαίωσε fail-closed behavior. Κάνε reproduction με [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** Συσχέτισε adjacent NetFlow timing/volume, επαναλαμβανόμενα proxy handshakes και common controller infrastructure· μην συμπεραίνεις τη γεωγραφία του operator από το exit.

## Split-knowledge application relay and OHTTP

**Mechanics:** Ο client κρυπτογραφεί ένα stateless HTTP message προς gateway και το στέλνει μέσω relay. Ο relay βλέπει το client IP αλλά όχι το request· ο gateway βλέπει το request αλλά συνήθως μόνο το relay IP.

**Pros:** ισχυρό, auditable privacy partition για supported requests· μικρότερο overhead από general anonymity networks.

**Cons:** όχι arbitrary browsing· cookies/authentication μπορούν να κάνουν relink· relay/gateway collusion και traffic analysis παραμένουν· η application πρέπει να το υλοποιεί.

**Procedure:** (1) επίλεξε application που δηλώνει ρητά υποστήριξη RFC 9458· (2) επαλήθευσε gateway keys μέσω official configuration path· (3) απόφυγε stable per-user fields· (4) στείλε μόνο το supported stateless request· (5) σύγκρινε relay, gateway και target logs· (6) έλεγξε key rotation/failure χωρίς direct fallback.<sup>[[2]](#references)</sup>

**Detection:** Τα enterprise endpoints αποκαλύπτουν initiating process και OHTTP relay· τα gateways εντοπίζουν malformed/replayed traffic· timing και stable payload/account fields μπορούν να συσχετίσουν requests.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** Το HTTP Extended CONNECT μέσω TLS/QUIC μεταφέρει UDP ή IP packets μέσω proxy. Μπορεί να υλοποιήσει σύγχρονο VPN-like tunnel και να αναμείξει το transport με HTTP/3, όμως ο proxy παραμένει observer.<sup>[[3]](#references)</sup>

**Pros:** αποδοτικό multiplexing/roaming· υποστήριξη UDP ή full IP· deployment μέσω modern HTTP infrastructure.

**Cons:** δεν είναι anonymity network· proxy/account βλέπει source και destinations· QUIC/HTTP fingerprints και well-known paths είναι ορατά σε endpoints/providers.

**Procedure:** (1) χρησιμοποίησε client/service που τεκμηριώνει RFC 9298/9484 support· (2) κάνε authentication του proxy certificate/configuration· (3) καθόρισε allowed target routes· (4) ενεργοποίησε encrypted DNS μέσα στο path· (5) επαλήθευσε UDP, TCP, IPv6 και failover σε owned endpoints· (6) έλεγξε proxy request και flow logs.

**Detection:** Τα endpoints βλέπουν το client process και virtual interface· τα networks μπορούν να ταξινομήσουν sustained QUIC/TLS προς proxy· τα proxy logs αποκαλύπτουν CONNECT target/path και assigned routes.

## Tor Browser

**Mechanics:** Το Tor επιλέγει guard, middle και exit relays· layered encryption περιορίζει την ορατότητα κάθε relay. Το Tor Browser προσθέτει standardized browser σχεδιασμένο να αντιστέκεται σε fingerprinting.

**Pros:** μεγάλο public anonymity set· κανένα ordinary relay δεν γνωρίζει και τα δύο άκρα· destination unlinkability χωρίς λειτουργία servers.

**Cons:** πιο αργό· κυρίως TCP-focused· exit reputation/blocks· logins και disclosures ταυτοποιούν τον user· παραμένει low-latency timing correlation.

**Procedure:** (1) κατέβασε και επαλήθευσε το Tor Browser από το project· (2) κράτησε τα defaults και απόφυγε extensions· (3) επέλεξε κατάλληλο security level· (4) δημιούργησε ξεχωριστή identity/session· (5) απόφυγε identifying accounts και external active documents· (6) χρησιμοποίησε HTTPS ή authenticated onion services· (7) επαλήθευσε το exit μόνο με owned endpoint.<sup>[[4]](#references)</sup>

**Detection:** Τα local networks μπορούν να αναγνωρίσουν known guard traffic αν δεν χρησιμοποιείται bridge/transport· τα destinations βλέπουν exits και Tor Browser behavior· end-to-end observers συσχετίζουν timing/volume.

## Tor bridges and pluggable transports

**Mechanics:** Ένα non-public bridge αντικαθιστά το public guard· τα obfs4, Snowflake ή WebTunnel αλλάζουν το first-hop transport για αντίσταση σε απλό blocking/probing.

**Pros:** παρακάμπτει censorship και κρύβει προφανή public-relay destinations· διατηρεί το Tor circuit μετά την είσοδο.

**Cons:** transport patterns/bridge discovery παραμένουν πιθανά· μεταβλητή απόδοση· δεν προσθέτει προστασία από accounts ή global timing.

**Procedure:** (1) δοκίμασε πρώτα direct Tor· (2) στις Tor Browser Connection settings επίλεξε built-in supported transport ή ζήτησε official bridge· (3) μην χρησιμοποιείς random binaries/lists· (4) συνδέσου και εκτέλεσε benign test· (5) έλεγξε reconnect και clock· (6) κράτησε όλα τα υπόλοιπα browser settings standard.<sup>[[5]](#references)</sup>

**Detection:** Οι censors χρησιμοποιούν destination discovery, protocol/flow classification και active probing· οι defenders πρέπει να διακρίνουν circumvention use από compromise και να βασίζονται σε endpoint process/context.

## VPN before Tor and Tor before VPN

**Mechanics:** Το VPN-before-Tor κρύβει direct Tor use από τον access ISP αλλά εκθέτει το source στο VPN. Το Tor-before-VPN δίνει στο VPN post-Tor traffic και συχνά stable customer/tunnel identity.

**Pros:** αφαιρεί συγκεκριμένο observer όταν σχεδιαστεί σωστά· μπορεί να φτάσει networks που μπλοκάρουν ένα layer.

**Cons:** complexity, uncommon fingerprint, leaks, μειωμένο anonymity set και false confidence· το Tor Project θεωρεί τους συνδυασμούς advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) κατέγραψε τον observer που αφαιρείται και τον νέο observer που εισάγεται· (2) χρησιμοποίησε disposable environment· (3) εγκατάστησε μόνο το intended outer path· (4) επέβαλε firewall routes· (5) επαλήθευσε DNS/IPv4/IPv6 και κάθε failure order· (6) σύγκρινε την ορατότητα και των δύο providers· (7) εγκατάλειψε το stack αν δεν έχει μετρήσιμο πλεονέκτημα.

**Detection:** Οι local/VPN/Tor observers βλέπουν διαφορετικά adjacent layers· το timing παραμένει end-to-end· unusual nested tunnel fingerprints και provider accounts μπορούν να συνδέσουν sessions.

## Onion service

**Mechanics:** Client και service δημιουργούν Tor circuits προς rendezvous, κρύβοντας το service IP και αποφεύγοντας exit.

**Pros:** προστασία τοποθεσίας source και service· end-to-end onion authentication· κανένα public inbound port· προαιρετικό client authorization.

**Cons:** origin leaks μέσω updates/analytics/errors· το onion key είναι κρίσιμο· application identity/timing και host compromise παραμένουν.

**Procedure:** (1) απομόνωσε την application και κάνε bind μόνο σε loopback/socket· (2) εγκατάστησε supported Tor· (3) ρύθμισε v3 onion service σύμφωνα με official instructions· (4) προστάτευσε/κράτησε backup του key μόνο αν απαιτείται stable identity· (5) πρόσθεσε client authorization για closed use· (6) αφαίρεσε third-party fetches· (7) επαλήθευσε externally ότι το origin δεν είναι reachable.<sup>[[7]](#references)</sup>

**Detection:** Οι host/network defenders εντοπίζουν Tor process/configuration και outbound circuits· application errors, DNS, certificates ή third-party resources μπορούν να αποκαλύψουν το origin.

## I2P internal services

**Mechanics:** Το I2P χρησιμοποιεί ξεχωριστά unidirectional inbound/outbound tunnels για destinations μέσα στο overlay· τα public-Internet outproxies προσθέτουν trust point.

**Pros:** decentralized internal publishing· καμία επίσημη εξάρτηση από exit· χωριστά inbound/outbound paths.

**Cons:** δεν είναι general web replacement· μικρότερο ecosystem· long-running peer behavior· το outproxy μπορεί να παρατηρεί public browsing.

**Procedure:** (1) εγκατάστησε από official source· (2) χρησιμοποίησε dedicated context· (3) επέτρεψε integration/bandwidth stabilization· (4) προσπέλασε owned I2P-native service· (5) απόφυγε outproxies εκτός αν απαιτούνται ρητά· (6) επαλήθευσε ότι το shutdown δεν δίνει direct fallback· (7) έλεγξε local peer και service logs.<sup>[[8]](#references)</sup>

**Detection:** Τα local networks βλέπουν long-lived peer traffic και bootstrap behavior· τα endpoints αποκαλύπτουν router/application processes· τα outproxies καταγράφουν exits.

## Mixnets

**Mechanics:** Fixed-size packets, batching, delay, reordering και cover traffic μειώνουν το timing correlation· gateways συνδέουν applications.

**Pros:** καλύτερη αντίσταση σε timing analysis από low-latency proxies· χρήσιμο για asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, μικρότερη ανάπτυξη και application limits· gateway/account metadata μπορεί να παραμένει.

**Procedure:** (1) επίλεξε maintained client και supported application· (2) διάβασε το πραγματικό threat model· (3) εγκατάστησε σε ξεχωριστό compartment· (4) στείλε benign data σε owned endpoint· (5) μέτρησε latency/reliability και reply path· (6) έλεγξε gateway failure· (7) μην απενεργοποιήσεις delays/cover traffic μόνο για ταχύτητα.<sup>[[9]](#references)</sup>

**Detection:** Τα endpoints αναγνωρίζουν τον client· τα access networks μπορούν να ταξινομήσουν gateways/packet cadence· gateways και exits παρατηρούν adjacent roles, ενώ ευρύτερη correlation απαιτεί μεγαλύτερα statistical windows.

## GNUnet anonymous file sharing

**Mechanics:** Το GNUnet μπορεί να δρομολογεί publish/search/download requests μέσω peers και να προσθέτει cover traffic σύμφωνα με anonymity level. Η documentation του προειδοποιεί ότι το default level 1 δεν απαιτεί cover traffic και ότι ισχυρή traffic analysis μπορεί να εντοπίσει την προέλευση.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing· ρυθμιζόμενη απαίτηση cover traffic.

**Cons:** όχι ordinary anonymous web access· κόστος performance/storage· peer και traffic-analysis limitations· η GNUnet VPN documentation αναφέρει ότι το IP overlay δεν παρέχει good anonymity.

**Procedure:** (1) εγκατάστησε maintained official build· (2) απομόνωσε test peer· (3) περιόρισε bandwidth/storage· (4) δημοσίευσε harmless unique test file με επιλεγμένο anonymity level· (5) ανάκτησέ το από άλλο owned peer· (6) κατέγραψε cover-traffic και latency· (7) μην ισχυριστείς ότι το IP VPN component παρέχει ισοδύναμη anonymity.

**Detection:** Peer bootstrap, overlay traffic, local datastore/process και file identifiers· broad observer μπορεί να αναλύσει traffic volume σε σχέση με cover traffic.

## Encrypted DNS, ODoH and ECH

**Mechanics:** Τα DoH/DoT/DoQ κρυπτογραφούν προς resolver· το ODoH διαχωρίζει client address και query μεταξύ proxy και resolver· το ECH κρυπτογραφεί το inner TLS ClientHello/server name.

**Pros:** αφαιρεί plaintext DNS/SNI από ορισμένους local observers· το ODoH διαχωρίζει source/query knowledge.

**Cons:** δεν είναι IP-anonymity path· resolver/proxy/server διατηρούν ρόλους· destination IP/timing/volume και endpoint παραμένουν· το fallback μπορεί να κάνει leak.

**Procedure:** (1) επίλεξε αν το OS, application ή tunnel έχει την ευθύνη του DNS· (2) ενεργοποίησε strict encrypted mode ή supported ODoH· (3) έλεγξε unique owned domain· (4) κάνε local capture για να επιβεβαιώσεις ότι δεν υπάρχει clear query· (5) σταμάτησε τον resolver και επαλήθευσε την προβλεπόμενη συμπεριφορά· (6) για ECH, επιβεβαίωσε ότι τα server diagnostics δείχνουν acceptance του inner ClientHello.<sup>[[11]](#references)</sup>

**Detection:** Endpoint/resolver logs αποκαλύπτουν queries· τα networks αναγνωρίζουν encrypted-resolver endpoints και destination flows· η κατάσταση ECH είναι ορατή σε endpoints/CDN ακόμη κι όταν κρύβεται στο path.

## Split-provider privacy relay

**Mechanics:** Products όπως το iCloud Private Relay χρησιμοποιούν ingress που γνωρίζει τον client και independently operated egress που γνωρίζει το destination, με coarse region handling.

**Pros:** low-friction split knowledge· γρήγορο· integrated DNS/web protection για supported traffic.

**Cons:** περιορισμένο product/application scope· account/platform provider εξακολουθεί να ταυτοποιεί τον customer· όχι arbitrary system anonymity· collusion/legal και timing risks.

**Procedure:** (1) επιβεβαίωσε τις ακριβείς supported applications και traffic types· (2) ενεργοποίησε τη feature σε dedicated platform context όπου είναι κατάλληλο· (3) επίλεξε region behavior· (4) έλεγξε Safari/DNS και unsupported applications χωριστά· (5) επιθεώρησε τη destination address· (6) έλεγξε network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** Το access βλέπει ingress· το destination βλέπει egress· platform/relay logs και account records καλύπτουν τα αντίστοιχα layers· unsupported applications αποκαλύπτουν normal paths.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Το browsing/tool execution γίνεται σε remote system· το destination βλέπει το egress του, ενώ ο workspace provider βλέπει τη σύνδεση του operator και το control plane.

**Pros:** γρήγορο· απομονώνει risky content· stable controlled egress· disposable state και ισχυρό organizational audit.

**Cons:** Provider/admin μπορεί να παρατηρεί session/account· screen/clipboard/file channels κάνουν leak· το remote browser fingerprint μπορεί να είναι unique· δεν υπάρχει anonymity έναντι του workspace owner.

**Procedure:** (1) δημιούργησε ένα organization-owned workspace ανά engagement· (2) απαίτησε MFA και περιόρισε administration· (3) απενεργοποίησε ή περιόρισε clipboard/upload/download· (4) δρομολόγησε μέσω approved fixed egress· (5) μη χρησιμοποίησε personal IdP/sync· (6) εξήγαγε μόνο reviewed evidence· (7) κατέστρεψε workspace και credentials σύμφωνα με το schedule.

**Detection:** Provider και IdP logs αντιστοιχίζουν user με session· τα destinations ομαδοποιούν workspace egress/browser· οι enterprise defenders αναγνωρίζουν remote-control protocols και anomalous cloud sessions.

## Public or guest Wi-Fi

**Mechanics:** Το traffic εξέρχεται μέσω venue NAT ή tunnel που ξεκινά εκεί.

**Pros:** υψηλή ταχύτητα και shared non-home address· δεν απαιτείται dedicated infrastructure.

**Cons:** venue association/DHCP/portal, camera, purchase και location evidence· hostile peers/APs· terms· physical risk.

**Procedure:** (1) απέκτησε πρόσβαση που προσφέρεται σε guests και επαλήθευσε το SSID με staff· (2) χρησιμοποίησε patched low-trust device· (3) απενεργοποίησε sharing/auto-join και ενεργοποίησε private MAC· (4) ολοκλήρωσε το portal χωρίς reused identity· (5) ξεκίνησε fail-closed VPN/Tor path· (6) επαλήθευσε tethered traffic· (7) ξέχασε το network.

**Detection:** Το venue συσχετίζει AP, MAC, DHCP, portal και χρόνο· το destination βλέπει venue/tunnel· investigators συνδυάζουν physical και device evidence. Ποτέ μην παρακάμπτεις access control.

## Travel router

**Mechanics:** Owner-operated router συνδέεται σε venue Wi-Fi/Ethernet και παρέχει isolated internal network με enforced tunnel policy.

**Pros:** απομονώνει workstations· central kill switch/DNS· consistent client network· προστατεύει privileged endpoints από local broadcasts.

**Cons:** Ο router γίνεται stable radio/DHCP fingerprint· προσθέτει attack surface· captive portals και tethering μπορούν να παρακάμψουν το tunnel.

**Procedure:** (1) ενημέρωσε supported firmware· (2) όρισε unique management credentials και απενεργοποίησε WAN admin/WPS/UPnP· (3) ρύθμισε private upstream MAC όπου επιτρέπεται· (4) δημιούργησε separate internal SSID· (5) επέβαλε full-tunnel DNS/IPv6 firewall policy· (6) έλεγξε portal, reconnect και tunnel failure.

**Detection:** Το venue βλέπει router association και traffic shape· local RF/DHCP fingerprinting τον αναγνωρίζει· ο VPN provider βλέπει venue source.

## Cellular, prepaid SIM and eSIM

**Mechanics:** Modem χρησιμοποιεί carrier radio access και συνήθως carrier NAT· VPN/Tor layer μπορεί να αλλάξει το destination-visible exit.

**Pros:** ανεξάρτητο από local wired/Wi-Fi network· mobile· υψηλή ταχύτητα· χρήσιμο backhaul για authorized drops.

**Cons:** Ο carrier γνωρίζει subscriber/eSIM, IMSI, IMEI, cells, time και assigned ports· οι registration laws διαφέρουν· co-location με personal phone συνδέει devices.

**Procedure:** (1) απέκτησε service lawfully με ακριβή required details· (2) χρησιμοποίησε ξεχωριστό organization-owned modem/device· (3) κατέγραψέ το στον exercise controller· (4) απενεργοποίησε unrelated radios/accounts· (5) εγκατάστησε approved tunnel· (6) έλεγξε αν τα tethered clients πράγματι το ακολουθούν· (7) επαλήθευσε provider και retention assumptions πριν από ταξίδι.<sup>[[13]](#references)</sup>

**Detection:** Carrier records και RF location· enterprise USB/PCI/MDM inventory και rogue-hotspot surveys· destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** Η normal service χρησιμοποιεί registered terminal/provider. Το παλαιότερο one-way DVB-S abuse επέτρεπε σε receiver μέσα σε beam να παρατηρεί unencrypted downlink traffic που απευθυνόταν σε legitimate subscriber, ενώ χρησιμοποιούσε άλλο path για outbound requests.

**Pros:** wide footprint· independent last mile· το ιστορικό one-way abuse μπορούσε να αποδώσει λανθασμένα το C2 σε subscriber geography.

**Cons:** equipment/RF/provider records· latency και coverage· τα σύγχρονα bidirectional systems διαφέρουν· outbound path και asymmetric routing παραμένουν evidence.

**Procedure:** Για lawful access, κάνε register owned terminal και κάνε tunnel το traffic όπως απαιτείται. Για emulation ιστορικού Turla behavior, κάνε replay synthetic one-way packet captures σε RF-free lab και έλεγξε αν οι analysts εντοπίζουν reply προς host που δεν έκανε request· μην κάνεις intercept live satellite traffic.<sup>[[14]](#references)</sup>

**Detection:** Provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency και malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** Backconnect gateway εκχωρεί consumer broadband/mobile exits, sticky ή rotating. Η supply μπορεί να είναι consensual, deceptively bundled ή malicious.

**Pros:** υψηλή ταχύτητα· geographic choice· consumer ASN αποφεύγει ορισμένα hosting blocks· μεγάλα pools.

**Cons:** provenance/consent και legal risk· ο broker βλέπει customer· infected exits βλάπτουν victims· rotation δημιουργεί anomalies· ακριβό και αναξιόπιστο.

**Procedure:** Χρησιμοποίησε μόνο documented, informed-consent organization-owned agents για emulation: (1) κάνε enroll test endpoints· (2) απογράφησε owners/IPs· (3) ρύθμισε gateway· (4) εναλλάσσε sticky/per-request modes· (5) στείλε μόνο σε owned target· (6) σύγκρινε gateway/exit/target logs· (7) αφαίρεσε κάθε agent.

**Detection:** Impossible travel, stable browser/account σε γρήγορες αλλαγές IP/ASN, backconnect protocols, proxyware process/network artifacts και broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased ή compromised routers/IoT/servers σχηματίζουν access, traversal και exit roles που διαχειρίζονται ως fleet. Πολλοί APT customers μπορεί να μοιράζονται το ίδιο fleet.

**Pros:** borrowed reputation/geography· short-lived exits· resilient multi-hop mesh· weak direct actor-to-IP link.

**Cons:** criminal victimization· implant/controller και fleet patterns· intermediary seizure· inconsistent performance· operator/customer service records.

**Procedure:** Ποτέ μην κάνεις compromise πραγματικών devices. Χρησιμοποίησε [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) δημιούργησε isolated entry/transit/target networks· (2) σύνδεσε owned dual-homed relay containers· (3) προώθησε μόνο ένα test port· (4) στείλε benign request· (5) επαλήθευσε ότι το target βλέπει μόνο exit· (6) άλλαξε exit· (7) κάνε teardown όλων των named assets.<sup>[[15]](#references)</sup>

**Detection:** Παρακολούθησε topology, ports/services, controller relations, implant fingerprints και node lifecycle· συγκέντρωσε edge configuration/flow/integrity telemetry· μην ταυτίζεις exit IP με actor.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Public edge προωθεί μόνο traffic που ταιριάζει σε grammar· το fronting χρησιμοποιεί benign outer SNI και διαφορετικό inner HTTP authority, ή blank SNI, όταν το επιτρέπει ο intermediary.

**Pros:** κρύβει/προστατεύει back-end· γρήγορο global edge· αναμειγνύει το destination με shared service· γρήγορο cutover.

**Cons:** Το CDN βλέπει όλο το routing και tenant· πολλοί providers απαγορεύουν cross-tenant fronting· SNI/Host/process/flow και account artifacts· configuration reuse ομαδοποιεί campaigns.

**Procedure:** Κάνε reproduction μόνο σε owned reverse proxy με [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): δημιούργησε local certificate/edge, δρομολόγησε ένα mismatched Host σε owned target, κατέγραψε SNI και Host, στείλε normal/mismatched requests και μετά αφαίρεσε τα containers.<sup>[[16]](#references)</sup>

**Detection:** Σύγκρινε SNI/ECH/Host/`:authority` σε endpoint ή terminating edge· συνδύασε initiating process, tenant/origin, request grammar και flow cadence.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** Το DDNS ενημερώνει stable name· το DGA παράγει μεταβαλλόμενα candidate names· το fast flux αλλάζει service addresses με low TTL· το double flux αλλάζει επίσης name servers.

**Pros:** resilient discovery· γρήγορη αντικατάσταση infrastructure· προστασία controller πίσω από πολλούς nodes.

**Cons:** Το DNS δημιουργεί centralized telemetry· entropy/NXDOMAIN/churn· low TTL και broad ASN patterns· registration και authoritative infrastructure παραμένουν.

**Procedure:** Χρησιμοποίησε [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): εξυπηρέτησε owned zone που επιστρέφει RFC 5737 addresses με five-second TTL, κάνε repeated queries, άλλαξε το synthetic epoch και επικύρωσε analytics. Ποτέ μην κατευθύνεις test records σε third parties.<sup>[[17]](#references)</sup>

**Detection:** Sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters και process follow-on· εξαίρεσε legitimate CDNs με context.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Public post, repository, document, object ή feed περιέχει encoded current endpoint ή task. Ο client μπορεί να επιστρέψει results από άλλο channel.

**Pros:** allowed high-reputation service· TLS· endpoint rotation χωρίς αλλαγή binary· asymmetric tasking δυσκολεύει simple flow correlation.

**Cons:** stable object/account/API identifiers· provider records· endpoint decode/follow-on sequence· το content μπορεί να κατασχεθεί ή να τροποποιηθεί.

**Procedure:** Χρησιμοποίησε [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): φιλοξένησε encoded pointer σε ένα owned container, κάνε fetch/decode από short-lived client, επικοινώνησε με δεύτερο owned service, διατήρησε και τα δύο logs και μετά κάνε teardown.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Functions/short-lived jobs εκτελούνται πίσω από provider NAT ή front· το logical service μένει stable ενώ instances και addresses αλλάζουν.

**Pros:** rapid deployment/destruction· provider-scale shared egress· λίγος local disk· elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing και front-to-origin logs είναι durable· cold-start και platform fingerprints· provider policy.

**Procedure:** (1) χρησιμοποίησε organization-owned exercise tenant· (2) κάνε deploy benign function που ζητά μόνο owned endpoint· (3) κατέγραψε project/role/image/config· (4) κάνε invoke σε αρκετά instances· (5) σύγκρινε target IPs με audit/request IDs· (6) έλεγξε log retention· (7) αφαίρεσε function, roles και secrets.

**Detection:** Cloud audit/invocation logs, unusual role creation, shared egress με stable request grammar, image/layer και secret reuse, και front-origin correlation.

## Authorized on-site drop

**Mechanics:** Inventoried small computer χρησιμοποιεί local wired/Wi-Fi και outbound VPN/cellular rendezvous, παρουσιάζοντας local source.

**Pros:** ρεαλιστικό internal-origin testing· υψηλή ταχύτητα· δυνατότητα ελέγχου NAC, physical inventory και egress controls.

**Cons:** physical discovery/theft· serial/MAC/USB/DHCP/PoE/RF και camera evidence· απώλεια μπορεί να εκθέσει credentials.

**Procedure:** Ακολούθησε [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) λάβε ακριβή γραπτή authority για placement· (2) κατέγραψε serial, MAC, photo, location και retrieval time· (3) χρησιμοποίησε signed minimal image και short-lived mutual credentials· (4) περιόρισε outbound-only destinations/capabilities· (5) πρόσθεσε server-side quarantine και bandwidth limits· (6) έλεγξε SOC visibility και loss response· (7) ανάκτησε, διατήρησε το απαιτούμενο evidence και κάνε sanitize σύμφωνα με την agreed lifecycle policy. Ποτέ μην κρύβεις συσκευή σε venue χωρίς consent.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera και physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** Actor ελέγχει host σε radio range του target και χρησιμοποιεί target Wi-Fi credentials για να περάσει remote το boundary. Το APT28 το χρησιμοποίησε μέσω nearby compromised organizations.<sup>[[18]](#references)</sup>

**Pros:** δεν απαιτείται travel του operator· το target βλέπει local radio source· παρακάμπτει controls που εφαρμόζονται μόνο στο Internet entry.

**Cons:** απαιτεί nearby compromised/owned dual-radio host και valid access· RADIUS/NAC/AP και neighbor endpoint evidence· signal/device anomalies.

**Procedure:** Κάνε reproduction μόνο με το [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): σύνδεσε owned pivot στα neighbor και target lab SSIDs, προώθησε μόνο ένα service, συνέλεξε και τα δύο AP/pivot logs και μετά ενεργοποίησε EAP-TLS/device posture για να επιβεβαιώσεις ότι η δεύτερη προσπάθεια αποτυγχάνει.

**Detection:** Συσχέτισε RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login και physical presence· αναζήτησε nearby endpoints με simultaneous radios, forwarding και tunnels.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Το traffic περνά από local peers, asynchronous gateways, removable media ή scheduled queues αντί για μία interactive Internet session.

**Pros:** λειτουργεί σε disruption/censorship· delayed/batched delivery αποδυναμώνει simple timing· δεν υπάρχει central last mile για local communication.

**Cons:** υψηλό latency· μικρό anonymity set· custody/physical metadata· malicious peers· τα data τελικά φτάνουν σε gateway που τα παρατηρεί.

**Procedure:** (1) δημιούργησε isolated owned three-node mesh ή file queue· (2) κρυπτογράφησε/authenticate content end to end· (3) αφαίρεσε direct Internet routes από origin· (4) κάνε relay benign file μετά από controlled delay· (5) επαλήθευσε ότι μόνο το gateway επικοινωνεί με owned destination· (6) σύγκρινε custody/timestamps· (7) διατήρησε το απαιτούμενο evidence και κάνε sanitize temporary media/queues στο approved closeout.

**Detection:** Endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity και content identifiers. Μεγαλύτερα correlation windows αντικαθιστούν το interactive-flow analysis.

## TURN relay and forced-relay WebRTC

**Mechanics:** Το Traversal Using Relays around NAT (TURN) εκχωρεί public relay address και μεταφέρει UDP, TCP ή TLS traffic μεταξύ client και peers. Μια ICE policy μπορεί να επιβάλει relay use αντί να εκθέτει direct candidate. Το TURN λύνει reachability, όχι general anonymity: ο server authenticates τον client και παρατηρεί allocations, peers, time και volume.<sup>[[19]](#references)</sup>

**Pros:** widely implemented· χειρίζεται restrictive NAT· υποστηρίζει mobile WebRTC· ο peer δεν λαμβάνει το direct transport address του client όταν το relay-only policy επιβάλλεται σωστά.

**Cons:** Ο TURN operator βλέπει και τις δύο adjacent πλευρές· application identity, media fingerprint και signaling παραμένουν· relay-only κοστίζει bandwidth και latency· misconfiguration μπορεί να συλλέξει host ή server-reflexive candidates.

**Procedure:** (1) κάνε deploy organization-owned TURN service με TLS και short-lived credentials· (2) περιόρισε realms, peers, ports, quotas και expiration· (3) ρύθμισε την test application σε relay-only ICE· (4) κάλεσε owned peer· (5) έλεγξε `getStats()` και packet capture ώστε να επιβεβαιώσεις ότι μόνο relay candidates μετέφεραν media· (6) σταμάτησε το relay και επιβεβαίωσε ότι δεν υπάρχει direct fallback· (7) διατήρησε allocation logs για το engagement.

**Detection:** Signaling, browser process και TURN allocations συνδέουν τη session με το relay· τα networks παρατηρούν sustained flows προς TURN ports ή TLS endpoints· ο peer βλέπει το allocated relay. **Captured node:** Application state και ephemeral TURN credentials μπορεί να αποκαλύψουν realm και rendezvous service. Ελαχιστοποίησε την έκθεση με per-device, short-lived credentials και κράτησε το operator authentication μόνο στον controller.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** Node πίσω από NAT ξεκινά authenticated connection προς organization-controlled broker. Ο operator authenticates ξεχωριστά στον broker, ο οποίος εγκρίνει narrow management channel· δεν απαιτείται inbound port forwarding ούτε direct operator-to-node route.

**Pros:** stable πίσω από NAT και captive last miles· central revocation και audit· οι αλλαγές address του field node δεν απαιτούν operator discovery· διαχωρίζει καθαρά operator identity από node credential.

**Cons:** Ο broker γίνεται high-value correlation point· periodic keepalives είναι recognizable· broad tunnel μπορεί να γίνει unsafe pivot· απώλεια broker διακόπτει management.

**Procedure:** Ακολούθησε [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): εξέδωσε ένα scoped device identity, επίτρεψε μόνο owned broker και approved management service, χρησιμοποίησε authenticated keepalive, επέβαλε fail-closed routing, έλεγξε address changes και reboot recovery και ανακάλεσε το identity στο loss drill. Το WireGuard τεκμηριώνει 25-second persistent keepalive ως broadly useful NAT interval όταν πράγματι απαιτείται.<sup>[[20]](#references)</sup>

**Detection:** Broker και identity-provider logs αντιστοιχίζουν και τις δύο πλευρές· το access network βλέπει repeated encrypted destination/cadence· endpoint inventory δείχνει overlay agent. **Captured node:** Θεώρησε εκτεθειμένα το device key, broker name, tunnel addresses και cached task data. Δεν πρέπει να περιέχει operator private key, personal account ή reusable controller token.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload κάνει polling σε authenticated mailbox για signed, pre-approved jobs και δημοσιεύει bounded results. Ο operator γράφει στο queue μέσω separate control plane· δεν υπάρχει interactive socket μεταξύ τους.

**Pros:** αντέχει intermittent links· αποσυνδέει timing και addressing· quotas και schemas περιορίζουν capability· εύκολο centralized audit και revocation.

**Cons:** Polling cadence και stable object/queue names κάνουν fingerprint το system· provider logs συνδέουν producer και consumer· delayed control· captured queued data μπορεί να εκθέσει το exercise.

**Procedure:** (1) δημιούργησε ένα engagement queue και ένα device identity· (2) καθόρισε signed schema benign, explicitly scoped jobs· (3) θέσε message TTL, maximum result size και rate· (4) επίτρεψε στο node να κάνει pull μόνο από το queue του και write μόνο στο result prefix του· (5) έλεγξε offline accumulation, duplicate delivery και revocation· (6) συγκέντρωσε immutable access logs· (7) διέγραψε το queue αφού καλυφθούν οι retention requirements.

**Detection:** Αναζήτησε periodic API calls από unusual process, stable bucket/object/queue paths, ίδιο user-agent ή TLS behavior και fetch-then-new-connection sequence. **Captured node:** Local cache μπορεί να αποκαλύψει pending jobs και object names· κράτησε το cache encrypted, bounded και disposable, διατηρώντας τα authoritative controller logs.

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node έχει δύο independent uplinks—όπως venue Ethernet/Wi-Fi και organization cellular—και διατηρεί control session μέσω overlay ή message broker καθώς αλλάζουν τα routes. Αυτό είναι availability engineering, όχι anonymity.

**Pros:** επιβιώνει από failure provider, AP ή captive portal· υποστηρίζει planned maintenance· επιτρέπει γρήγορη απομόνωση suspect path.

**Cons:** Δύο providers δημιουργούν δύο location/account records· simultaneous use διευκολύνει correlation· route και DNS leaks κατά το failover· cellular co-location evidence παραμένει.

**Procedure:** (1) κάνε register και τα δύο organization-owned interfaces/providers· (2) όρισε deterministic route priorities και health checks προς owned endpoints· (3) κάνε bind DNS και management στο overlay· (4) απέτρεψε inbound traffic από το secondary path· (5) αποσύνδεσε κάθε path και έλεγξε session recovery, source policy και απουσία direct destination access· (6) δημιούργησε alert για unplanned path change· (7) τεκμηρίωσε data use και roaming limits.

**Detection:** Συσχέτισε το ίδιο device certificate, request grammar και timing μεταξύ ASNs· local inventory βλέπει και τα δύο radios· carriers/venues διατηρούν τα δικά τους records. **Captured node:** Και τα δύο SIM/device identifiers και known SSIDs μπορεί να είναι ορατά· χρησιμοποίησε organization assets και ποτέ μην κάνεις co-location ή pairing με personal devices.

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN τοποθετεί enrolled SIMs σε private routed domain ή κάνει tunnel traffic προς enterprise gateway. Διαχωρίζει τη συσκευή από public mobile Internet, αλλά δεν την κρύβει από carrier ή contracting organization.

**Pros:** stable private addressing· carrier-level enrollment και traffic policy· αποφυγή public inbound exposure· χρήσιμο για authorized remote appliances.

**Cons:** Subscriber, IMSI/IMEI, cell και billing attribution είναι ισχυρά· procurement lead time και cost· carrier/gateway outage· όχι anonymous έναντι του operator.

**Procedure:** (1) σύναψε το APN στο όνομα του assessment organization· (2) κάνε whitelist μόνο registered SIMs και gateway prefixes· (3) πρόσθεσε application-layer mutual authentication· (4) περιόρισε το APN route σε rendezvous και update services· (5) έλεγξε SIM removal, roaming, public-Internet breakout και revocation· (6) παρακολούθησε carrier και gateway records· (7) ακύρωσε ή βάλε σε quarantine κάθε SIM στο closeout.

**Detection:** Carrier inventory και cell telemetry, APN gateway flows, SIM/IMEI mismatch και enterprise asset records. **Captured node:** Το SIM και modem ταυτοποιούν το contract ακόμη και όταν το storage είναι encrypted· capture resilience σημαίνει rapid suspension και narrow authorization, όχι deniability.

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi ή άλλο licensed/unlicensed point-to-point radio συνδέει δύο owner-approved sites, με Internet egress στο remote site. Μπορεί να μετακινήσει το apparent IP location χωρίς commercial proxy.

**Pros:** υψηλό throughput· ανεξαρτησία από intermediate wired carriers· controllable RF και routing· χρήσιμο για testing segmentation και remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord και regulatory constraints· distinctive RF emissions και hardware· και τα δύο endpoints είναι physical evidence· weather/power/alignment επηρεάζουν τη σταθερότητα.

**Procedure:** (1) λάβε γραπτή permission και για τα δύο sites και έλεγξε spectrum/power rules· (2) κάνε survey χωρίς transmission εκτός approved parameters· (3) χρησιμοποίησε authenticated encryption και management VLAN· (4) περιόρισε το bridge σε owned rendezvous ή test subnet· (5) έλεγξε failover, alignment, power recovery και RF containment· (6) κάνε label/inventory και στα δύο radios· (7) αφαίρεσέ τα και επαλήθευσε configuration reset μετά το exercise.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic και remote-site egress logs. **Captured node:** Configuration αποκαλύπτει peer και management domain· χρησιμοποίησε unique exercise credentials, χωρίς personal management accounts, και rapid peer-key revocation.

## Consented cooperative or community exit

**Mechanics:** Volunteers ή partner organizations τρέχουν relays με published policy και informed consent. Το traffic εξέρχεται από shared community pool, ενώ το coordination layer καταγράφει abuse και revocation.

**Pros:** diverse non-cloud networks· explicit consent ασφαλέστερο από proxyware· shared governance κατανέμει trust· χρήσιμο για research και censorship-resilience studies.

**Cons:** μικρά pools και membership records μειώνουν anonymity· exit operators λαμβάνουν complaints και βλέπουν traffic metadata· malicious participants, variable uptime και jurisdiction differences.

**Procedure:** (1) δημοσίευσε acceptable-use και logging policy· (2) λάβε informed opt-in από κάθε operator· (3) έκδωσε unique relay identity και περιόρισε destinations/rates· (4) παρείχε abuse handling και one-action revocation· (5) στείλε μόνο authorized traffic σε owned endpoints κατά το testing· (6) μέτρησε churn και correlation exposure· (7) αφαίρεσε καθαρά το relay όταν λήξει το consent.

**Detection:** Membership/control-plane records, relay certificates, common software fingerprint και exit behavior ταυτοποιούν το pool. **Captured node:** Relay configuration μπορεί να ταυτοποιεί το cooperative, αλλά δεν πρέπει να περιέχει client identities· αποθήκευσε client-to-session accountability στον authorized controller με access control.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** IPv6 privacy extensions δημιουργούν temporary interface identifiers ώστε stable address να μην επαναχρησιμοποιείται για κάθε outbound connection. Provider prefix changes μπορούν να προσθέσουν rotation, αλλά delegated prefix, subscriber record και upper-layer fingerprint παραμένουν.<sup>[[21]](#references)</sup>

**Pros:** μειώνει passive long-term tracking από stable interface identifier· ενσωματωμένο σε common operating systems· χωρίς relay overhead.

**Cons:** όχι source anonymity· ISP και local network γνωρίζουν prefix/device· DNS, accounts και browser state συνδέουν sessions· address churn δυσκολεύει allowlists και logging.

**Procedure:** (1) επιθεώρησε stable και temporary addresses σε owned client· (2) ενεργοποίησε OS-supported privacy-address default αντί για third-party spoofing· (3) ζήτησε owned IPv6 endpoint επανειλημμένα κατά τη διάρκεια των address lifetimes· (4) επιβεβαίωσε ότι inbound services κάνουν bind μόνο σε intended stable addresses· (5) διατήρησε DHCPv6/RA/neighbor και precise endpoint logs· (6) έλεγξε VPN/firewall behavior για κάθε IPv6 address.

**Detection:** Συσχέτισε delegated prefix, layer-2 identity, neighbor discovery, account και endpoint telemetry αντί να θεωρείς μία address ίση με μία device. **Captured node:** Network profiles και interface identifiers παραμένουν· το temporary addressing αποτρέπει ένα passive identifier, όχι forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Pluggable transport αλλάζει το πώς εμφανίζεται η πρώτη Tor connection ή πώς φτάνει σε bridge. Το Snowflake χρησιμοποιεί short-lived volunteer WebRTC proxies, το WebTunnel μοιάζει με ordinary HTTPS, το obfs4 αντιστέκεται σε simple protocol identification και active probing και το meek κάνει relay μέσω supported web infrastructure. Είναι censorship-circumvention transports προς Tor, όχι επιπλέον end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Pros:** χρήσιμο όταν direct Tor ή known relays μπλοκάρονται· το Snowflake αποφεύγει stable public bridge address· ενσωματωμένο σε maintained Tor clients· το destination εξακολουθεί να λαμβάνει ordinary Tor properties.

**Cons:** χαμηλή ή μεταβλητή απόδοση· broker/front/bridge και local network βλέπουν διαφορετικά metadata· transport fingerprints και blocking παραμένουν πιθανά· volunteer proxy δεν αντικαθιστά το Tor και δεν πρέπει να θεωρείται trusted με application plaintext.

**Procedure:** (1) εγκατάστησε και επαλήθευσε official Tor Browser ή supported Tor client· (2) επίλεξε built-in transport στο Connection/Bridges· (3) συνδέσου μόνο σε owned diagnostic page· (4) επιβεβαίωσε ότι η page βλέπει Tor exit και όχι Snowflake/WebTunnel peer· (5) σύγκρινε bootstrap και performance· (6) κάνε fail το transport και επιβεβαίωσε ότι ο client δεν συνδέεται σιωπηρά direct· (7) επέστρεψε στη standard supported configuration μετά το test.

**Detection:** Censor μπορεί να συνδυάσει destination allowlists, TLS/WebRTC behavior, broker discovery και flow analysis· endpoints αποκαλύπτουν Tor και transport configuration. **Capture-resilient OPSEC:** χρησιμοποίησε standard client, ποτέ μην αντιγράψεις personal browser state σε αυτόν και θεώρησε ότι bridge/broker history μπορεί να ανακτηθεί. **Monitoring:** Παρακολούθησε Tor bootstrap logs, unexpected direct DNS/connection attempts και controller-side owned-page observations· transport failure δεν αποτελεί απόδειξη discovery.

## Refraction networking or decoy routing

**Mechanics:** Cooperating network operator εντοπίζει covert signal σε traffic που φαίνεται να απευθύνεται σε allowed decoy και εκτρέπει το flow σε circumvention proxy. Η deployment απαιτεί infrastructure στο network path· δεν είναι κάτι που μπορεί να δημιουργήσει ο client απλώς επιλέγοντας innocent website.<sup>[[23]](#references)</sup>

**Pros:** Το apparent destination μπορεί να είναι δύσκολο να μπλοκαριστεί χωρίς collateral damage· δεν απαιτείται διανομή public bridge address· χρήσιμο research model για on-path-assisted circumvention.

**Cons:** specialized ISP/transit participation· deployability και performance εξαρτώνται από routing· client-to-decoy flow και proxy-side activity παραμένουν· global ή cooperating observer μπορεί να συσχετίσει timing.

**Procedure:** Μην κάνεις signaling μέσω uninvolved networks. Κάνε reproduction σε isolated lab: (1) δημιούργησε owned client, router, decoy και proxy namespaces· (2) χρησιμοποίησε benign tagged test request· (3) άφησε τον owned router να redirect μόνο αυτό το tag προς proxy· (4) κατέγραψε pre/post-routing tuples και request IDs· (5) σύγκρινε ordinary και signaled flows· (6) έλεγξε false positives και removal· (7) κατέστρεψε τα lab routes.

**Detection:** Authorized network operators μπορούν να επιθεωρήσουν routing divergence, unusual client hello/tag behavior και decoy-versus-back-end flow discrepancies. **Capture-resilient OPSEC:** Research client πρέπει να περιέχει μόνο test keys και documentation addresses. **Monitoring:** Σύγκρινε signed lab-router decisions με proxy arrivals· μην κάνεις probe production transit providers για να διαπιστώσεις αν εντόπισαν signaling.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway ανακτά IPFS content identifier (CID), πιθανώς από cache ή peers, και επιστρέφει verifiable content στον client. Ο original publisher μπορεί να βλέπει gateway ή άλλους peers αντί για final reader· ο gateway βλέπει reader IP και requested CID. Native peer-to-peer retrieval εκθέτει τον client σε peers και DHT/routing participants.<sup>[[24]](#references)</sup>

**Pros:** Publisher και reader μπορούν να διαχωριστούν μέσω caches· immutable content είναι hash-verifiable· replicated data επιβιώνει από έναν host· HTTP clients δεν χρειάζονται native peer stack.

**Cons:** Public CIDs και gateway logs αποκαλύπτουν interests· first retrieval timing μπορεί να συσχετίσει publisher και reader· malicious web content και path-style same-origin hazards· public gateways είναι best-effort και απαγορεύουν abuse.

**Procedure:** (1) δημοσίευσε harmless test file σε owned private IPFS swarm ή owned gateway· (2) κατέγραψε CID· (3) ανάκτησέ το μέσω separate owned HTTP gateway με subdomain isolation· (4) επαλήθευσε τα bytes έναντι του CID· (5) επανάλαβε μετά από caching· (6) σύγκρινε publisher, peer και gateway logs· (7) κάνε unpin και αφαίρεσε test content όταν λήξει το retention.

**Detection:** Gateways καταγράφουν source/CID· DHT και peer connections αποκαλύπτουν retrieval· endpoint history και file hashes ταυτοποιούν content. **Capture-resilient OPSEC:** Μην αποθηκεύεις private publishing key σε read-only field client και κρυπτογράφησε sensitive content πριν από content addressing. **Monitoring:** Alert σε unexpected pinning, αλλαγή peer-set, CID requests εκτός allowlist ή gateway account notices.

## Private information retrieval service

**Mechanics:** Το Private Information Retrieval (PIR) επιτρέπει σε client να ανακτήσει μία record από database, κρύβοντας κρυπτογραφικά το selected index από server υπό συγκεκριμένο single- ή multi-server threat model. Προστατεύει query selection για bounded dataset· δεν είναι general web access ή IP anonymity.<sup>[[25]](#references)</sup>

**Pros:** ισχυρό application-specific query privacy· measurable leakage model· χρήσιμο για key directories, blocklists ή small public databases· μπορεί να μειώσει την ανάγκη αποκάλυψης ακριβών lookup terms.

**Cons:** computation/bandwidth overhead· ο server γνωρίζει connection time/IP εκτός αν συνδυαστεί με relay· dataset version, response size και application state μπορούν να διαχωρίσουν users· η implementation maturity διαφέρει.

**Procedure:** (1) κάνε deploy audited PIR implementation έναντι synthetic owned database· (2) δημοσίευσε dataset version και parameters· (3) ανάκτησε αρκετά indices με identical request sizes· (4) επαλήθευσε correctness locally· (5) σύγκρινε server logs και επιβεβαίωσε ότι το index απουσιάζει· (6) έλεγξε malicious/truncated responses και version mismatch· (7) τεκμηρίωσε την ακριβή privacy assumption αντί να το αποκαλείς anonymous browsing.

**Detection:** Networks βλέπουν service use και volume· endpoint telemetry αποκαλύπτει client και final record use· compromised server μπορεί να χειραγωγήσει datasets ή timing. **Capture-resilient OPSEC:** Κράτησε μόνο public database parameters και bounded cache στον client. **Monitoring:** Επικύρωσε signed dataset roots, fixed request shapes, αλλαγές error-rate και server-key rotations.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service κάνει fetch ή render ένα URL και επιστρέφει screenshot, metadata ή sanitized content. Το destination βλέπει τη fetcher address· το service βλέπει requester, URL και result. Η κατάχρηση link-preview bots, security scanners ή third-party URL fetchers δεν είναι authorized proxy use.

**Pros:** απομονώνει active content από workstation· το destination λαμβάνει controlled fetcher fingerprint· μπορεί να επιβάλει file type, size, destination και rendering limits· disposable execution environment.

**Cons:** Το service έχει πλήρη γνώση request· account/API/billing records· SSRF και data-exfiltration risk· scripts, authentication και interactive sites μπορεί να μη λειτουργούν· unique URLs συσχετίζουν requester και fetch.

**Procedure:** (1) κάνε deploy organization-owned fetcher με strict allowlist owned test domains· (2) μπλόκαρε private, link-local, metadata και redirect-to-unapproved addresses· (3) περιόρισε methods, redirects, bytes και render time· (4) αφαίρεσε credentials/cookies· (5) υπέβαλε owned URL· (6) σύγκρινε requester, fetcher και target logs· (7) κατέστρεψε render instance και διατήρησε central audit σύμφωνα με policy.

**Detection:** Target βλέπει service ASN/fingerprint· provider και controller logs αντιστοιχίζουν requester με URL· endpoint process/API calls δείχνουν submission. **Capture-resilient OPSEC:** Χρησιμοποίησε ένα short-lived project token χωρίς arbitrary destination authority. **Monitoring:** Alert σε allowlist denials, redirect violations, fetches χωρίς controller job ID και provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** Πολλαπλά organization-controlled nodes διαφημίζουν ή προβάλλουν ένα stable service address και το routing επιλέγει nearby instance. Το Anycast βελτιώνει availability και κρύβει individual back-end από client, αλλά ο operator ελέγχει όλα τα instances και το service address παραμένει stable.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress· καμία field reconfiguration όταν αποτύχει instance· DDoS/load distribution· central policy μπορεί να μετακινεί sessions μεταξύ known nodes.

**Cons:** BGP/CDN και provider records ταυτοποιούν organization· path changes μπορούν να διακόψουν stateful sessions· monitoring διαφέρει ανά client location· μία stable address μπλοκάρεται ή ομαδοποιείται εύκολα λόγω reputation.

**Procedure:** Χρησιμοποίησε provider-supported organization project ή isolated routing lab: (1) κάνε deploy δύο identical authenticated health endpoints· (2) εξέθεσε ένα documented service address· (3) κράτησε session state στον broker και όχι στο edge· (4) απέσυρε έναν node και επαλήθευσε reconnection· (5) έλεγξε certificate, policy και log consistency· (6) δημιούργησε alert για unauthorized origin/region· (7) αφαίρεσε advertisements και credentials στο closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates και identical service behavior ταυτοποιούν το pool. **Capture-resilient OPSEC:** Edge κρατά μόνο regional service identity και κανένα operator ή fleet-enrollment key. **Monitoring:** Κάνε probe κάθε region από authorized monitors, σύγκρινε route origin και configuration digest και αντιμετώπισε unexpected origin ως incident.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs μπορούν να διατηρούν client session κατά NAT rebinding ή address changes· Multipath TCP μπορεί να μεταφέρει ένα reliable byte stream μέσω πολλαπλών subflows. Βελτιώνουν continuity μεταξύ Wi-Fi/cellular transitions, αλλά εκθέτουν παλιά και νέα paths στον ίδιο peer και μπορούν να κάνουν cross-path correlation ευκολότερο.<sup>[[27]](#references)</sup>

**Pros:** ταχύτερη recovery σε uplink changes· application session δεν χρειάζεται restart· MPTCP συνδυάζει resilience και throughput· χρήσιμο για approved field nodes.

**Cons:** όχι anonymity· peer βλέπει migration/subflows· connection identifiers και simultaneous traffic συνδέουν paths· middlebox/carrier support διαφέρει· duplicated provider records αυξάνουν exposure.

**Procedure:** (1) ενεργοποίησε το supported transport μόνο μεταξύ owned field client και rendezvous· (2) κάνε authentication της application ανεξάρτητα από IP· (3) ξεκίνησε bounded transfer σε approved Wi-Fi· (4) άλλαξε σε organization cellular· (5) επιβεβαίωσε path validation, data integrity και απουσία clear/direct fallback· (6) έλεγξε idle timeout και return· (7) διατήρησε broker records κάθε path transition.

**Detection:** Ο peer παρατηρεί άμεσα address migration ή MPTCP subflows· οι access providers βλέπουν το δικό τους μέρος· connection IDs, TLS identity και timing συνδέουν και τα δύο. **Capture-resilient OPSEC:** Αποθήκευσε μόνο device-scoped session material και λήξε γρήγορα το resumable state. **Monitoring:** Alert σε impossible path changes, simultaneous unapproved networks, migration storms και resumption μετά από quarantine.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow εκτελεί bounded network check σε hosted runner. Το destination βλέπει cloud runner address, ενώ η platform διατηρεί repository, actor, workflow, token, log και billing attribution. Είναι remote execution με accountable egress, όχι anonymity έναντι του provider.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment· reproducible job definition· no inbound connection· χρήσιμο για geographically distributed availability checks· strong controller audit.

**Cons:** Platform και organization ταυτοποιούν τον initiator· broad workflow tokens και untrusted pull requests είναι επικίνδυνα· shared IP reputation· logs/artifacts μπορεί να διατηρούν secrets ή target data.

**Procedure:** (1) δημιούργησε private organization repository και environment για το assessment· (2) επίτρεψε μόνο manually approved, fixed benign jobs προς owned endpoints· (3) χρησιμοποίησε minimal read-only workflow permissions και κανένα production secret· (4) εκτέλεσε το check· (5) σύγκρινε workflow, provider και target records· (6) επαλήθευσε ότι artifacts δεν περιέχουν credentials· (7) διέγραψε environment token και διατήρησε το απαιτούμενο audit.

**Detection:** Provider audit και workflow logs παρέχουν direct attribution· targets αναγνωρίζουν runner ASNs/ranges και stable request grammar. **Capture-resilient OPSEC:** Ποτέ μην τοποθετείς field-device, signing, wallet ή cloud-administrator secrets σε runner variables. **Monitoring:** Απαίτησε branch/environment approval και alert σε workflow edits, fork execution, secret reads και unexpected destinations.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio ή serial/optical link μεταφέρει bounded messages από nearby sensor σε owner-approved Internet gateway. Το field device δεν έχει Internet route· ο gateway είναι το μόνο egress. Τα όρια radio range και protocol το καθιστούν telemetry/store-and-forward design, όχι interactive anonymous Internet.

**Pros:** αφαιρεί Internet stack και credentials από το μικρότερο field device· low power· ο gateway συγκεντρώνει policy· μπορεί να γεφυρώνει προσωρινά dead zones.

**Cons:** RF/physical discovery, pairing και device identifiers· μικρό bandwidth και range· ο gateway συνδέει όλα τα messages· spectrum και encryption restrictions διαφέρουν· capture μπορεί να εκθέσει queued data.

**Procedure:** (1) λάβε site και spectrum approval· (2) κάνε pair ένα owned sensor με έναν owned gateway χρησιμοποιώντας unique keys· (3) καθόρισε signed fixed-size message types, TTL και rate· (4) δώσε στον sensor no default IP route· (5) άφησε τον gateway να προωθεί μόνο σε owned collector· (6) έλεγξε replay, range loss και gateway outage· (7) κάνε inventory και ανάκτησε και τα δύο devices.

**Detection:** RF survey, pairing database, physical inspection και gateway process/flow logs αποκαλύπτουν το path. **Capture-resilient OPSEC:** Sensor πρέπει να κρατά μόνο pairwise key και bounded encrypted queue, ποτέ operator, Wi-Fi, cellular ή controller credentials. **Monitoring:** Alert σε new peers, sequence rollback, key failure, unusual RF rate και messages από unregistered gateway.

## Capture/compromise exposure matrix

Ο πίνακας εφαρμόζει capture-resilience check σε κάθε παραπάνω family. “Minimize” σημαίνει μείωση secrets και blast radius σε authorized assets· ποτέ δεν σημαίνει διαγραφή evidence ή απόκρυψη από investigation.

| Technique family | Τι μπορεί να αποκαλύψει captured endpoint/relay | Minimum authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | γνωστά networks, DHCP/portal history, MACs, tunnel peer | ξεχωριστό organization device· private MAC όπου υποστηρίζεται· no personal accounts· controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | providers/hostnames, keys, routes, logs και adjacent hop | μία identity ανά engagement· short TTL· narrow routes· broker-side revocation· no master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers και cached requests | minimize payload identifiers· pin approved config· bounded cache· strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state και peer history | standard client· separate service keys· encrypted minimal state· rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files και remote tenant | phishing-resistant MFA at gateway· disabled transfer channels· rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider και approximate location | organization contract· no personal co-location· narrow APN/overlay policy· provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | μόνο consented/owned nodes· signed agent· per-node credential· controller-held participant mapping |
| CDN/fronting, fast flux, serverless | tenant/origin/config, API tokens, deployment και billing references | dedicated project· least-privilege role· short-lived deploy token· provider audit retained centrally |
| Dead drop, pull mailbox, store-and-forward | object names, queue, cached jobs/results και custody data | signed bounded jobs· TTL· encrypted cache· separate producer identity· immutable server logs |
| Drop, nearest-neighbor, long-range bridge | serial/radio/SSID/peer, device key, physical placement artifacts | written placement· unique device identity· no operator secret· tamper/state telemetry· revoke and recover |
| TURN, reverse overlay, dual-uplink | realm/broker, device credential, peer/route και uplink profiles | outbound-only narrow service· short-lived device credential· independent operator login· fail-closed paths |
| IPv6 temporary addressing | profiles, prefix history και endpoint/application state | treat as anti-tracking only· preserve network logs· pair with endpoint compartmentation |
| Pluggable transport/refraction lab | bridge/broker/decoy settings, Tor state και research keys | standard client ή isolated lab· no personal browser state· no production signaling |
| IPFS/PIR/fetcher | requested CID/query client, cached content, gateway ή service token | encrypted bounded cache· public-only parameters· short-lived allowlisted service token |
| Anycast/QUIC/MPTCP | service nodes, connection IDs, resumable state και every known path | regional identity only· short resumption lifetime· central route/session revocation |
| Managed CI/CD runner | repository, workflow, provider token, logs και artifacts | least-privilege workflow· no production/field/wallet secrets· environment approval |
| Non-IP local hop | radio peer, pairwise key, queued messages και gateway identity | unique pairwise key· fixed message schema· no Wi-Fi/cellular/operator credential |

## Monitoring possible discovery for every access family

Κανένα client-side test δεν αποδεικνύει ότι investigator ή defender παρακολουθεί. Παρακολούθησε αλλαγές σε systems που ανήκουν στο engagement, επιβεβαίωσέ τες με controller/client και σταμάτησε αντί να κάνεις probe σε observers. Οι παρακάτω γραμμές καλύπτουν όλες τις techniques· συνδύασέ τες με τα [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Covered techniques | Safe controller-side signals | Quarantine/stop condition |
|---|---|---|
| NAT/CGNAT, public/guest Wi-Fi, travel router, cellular/eSIM, satellite, private APN | lease/portal/carrier session, public tuple, BSSID/cell/path change, provider notice | unapproved network/SIM/device, unexplained relocation ή provider/SOC escalation |
| VPN/VPS, HTTP/SOCKS/SSH, multi-hop, residential/cooperative proxy | peer authentication, tunnel state, route/DNS leaks, new admin/API event, complaint | duplicate/stolen credential, unknown administrator, direct fallback ή out-of-scope egress |
| OHTTP/ODoH/ECH, MASQUE, split-provider relay, TURN | relay/gateway allocation, key/config version, unsupported direct connection, error/replay rate | key mismatch, direct fallback, unknown realm/peer ή provider abuse notice |
| Tor Browser, bridges, Snowflake/WebTunnel/obfs4/meek, VPN±Tor, onion service | bootstrap state, circuit failure, onion descriptor/service health και owned canary page | personal-account crossover, unexpected non-Tor connection ή compromised service key |
| I2P, mixnet, GNUnet, mesh/store-forward, non-IP local hop | peer set, queue age/sequence, gateway arrival, radio association και content hash | unknown peer/gateway, sequence rollback, unauthorized content ή missing custody record |
| Remote browser/VDI/jump host, CI/CD runner, serverless | IdP session, workflow/image/config change, new token use, artifact/export και cloud audit | unknown login/workflow edit, secret read, unexpected destination ή project-role escalation |
| ORB lab, fast flux/DGA, CDN/fronting, dead drop/pull mailbox | owned node inventory, DNS/edge/object access, controller graph, job signature και TTL | unknown node/origin/object writer, unsigned/replayed job, topology escape from lab |
| Drop/nearest-neighbor/long-range bridge/outbound overlay/dual uplink | signed heartbeat, boot/config hash, enclosure state, AP/switch context, duplicate identity | moved/opened node, unexpected boot/hash/path, sentinel use ή site report |
| IPv6 temporary addresses, QUIC migration, MPTCP | delegated prefix, connection ID/subflows, path-validation και broker session | impossible migration, simultaneous unapproved paths ή session resumption after revoke |
| IPFS/cache, PIR, constrained fetcher | CID/query-shape/root version, peer/gateway change, redirect/allowlist denial | unexpected pin/query/destination, unsigned dataset root ή provider abuse notice |
| Refraction/decoy-routing lab, anycast rendezvous | owned diversion decision, proxy arrival, BGP/RPKI origin, regional config digest | production-path signal, unknown route origin, region/config inconsistency |

## Choosing and testing a path

1. Κατονόμασε τον observer που θέλεις να αφαιρέσεις και τα data που θέλεις να κρύψεις.
2. Επίλεξε την least-complex family που τον αφαιρεί.
3. Σχεδίασε source, entry, traversal, exit, DNS, account και payment observers.
4. Χρησιμοποίησε ξεχωριστό endpoint/application identity.
5. Επαλήθευσε IPv4, IPv6, DNS, WebRTC/application bypass και destination view.
6. Διέκοψε κάθε hop και επιβεβαίωσε ότι το failure είναι closed.
7. Σύγκρινε τα logs σε κάθε component που ελέγχεις.
8. Κατέγραψε residual timing, provider, endpoint και physical links.

## References

- [1] [EFF — Choosing the VPN that is right for you](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [RFC 9298 — Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298.html) and [RFC 9484 — Proxying IP in HTTP](https://www.rfc-editor.org/rfc/rfc9484.html)
- [4] [Tor Project — Tor protections](https://support.torproject.org/about-tor/introduction/protections/) and [Tor specification introduction](https://spec.torproject.org/intro/)
- [5] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [6] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [7] [Tor Project — Onion services overview](https://community.torproject.org/onion-services/overview/)
- [8] [I2P — Threat model](https://www.i2p.net/en/docs/overview/threat-model/)
- [9] [Katzenpost — Threat model](https://katzenpost.network/docs/threat_model/)
- [10] [GNUnet — Anonymous file sharing](https://docs.gnunet.org/master/users/fs.html) and [GNUnet VPN limitations](https://docs.gnunet.org/latest/users/vpn.html)
- [11] [RFC 9230 — Oblivious DoH](https://www.rfc-editor.org/rfc/rfc9230.html) and [RFC 9849 — Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [12] [Apple Platform Security — iCloud Private Relay security](https://support.apple.com/guide/security/secad8ce3233/web)
- [13] [GSMA — Mandatory SIM registration](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [Kaspersky Securelist — Satellite Turla](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [15] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [16] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [17] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [18] [Volexity — The Nearest Neighbor Attack](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [19] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [20] [WireGuard — Quick Start: NAT and Firewall Traversal Persistence](https://www.wireguard.com/quickstart/)
- [21] [RFC 8981 — Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6](https://www.rfc-editor.org/rfc/rfc8981.html)
- [22] [Tor Project — Pluggable transports and bridges](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/) and [Using Snowflake](https://support.torproject.org/anti-censorship/how-can-i-use-snowflake/)
- [23] [Refraction Networking — project and deployment research](https://refraction.network/) and [Running Refraction Networking for Real](https://refraction.network/papers/deployment-pets20.pdf)
- [24] [IPFS — HTTP Gateway concepts and request lifecycle](https://docs.ipfs.tech/concepts/ipfs-gateway/)
- [25] [IETF PEARG — Private Information Retrieval overview](https://datatracker.ietf.org/meeting/121/materials/slides-121-pearg-call-me-by-my-name-simple-practical-private-information-retrieval-for-keyword-queries-00)
- [26] [RFC 4786 — Operation of Anycast Services](https://www.rfc-editor.org/rfc/rfc4786.html)
- [27] [RFC 9000 — QUIC connection migration](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 8684 — Multipath TCP](https://www.rfc-editor.org/rfc/rfc8684.html)
- [28] [GitHub — GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
