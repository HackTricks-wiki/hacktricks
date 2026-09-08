# Κατάλογος Τεχνικών Anonymous Internet Access

{{#include ../banners/hacktricks-training.md}}

Αυτός είναι ο canonical inventory των διαδρομών πρόσβασης. Καλύπτει **οικογένειες** πρωτοκόλλων και επιχειρησιακών πρακτικών, όχι κάθε όνομα vendor. Καμία διαδρομή Internet δεν εγγυάται anonymity: στοιχεία λογαριασμού, browser, endpoint, χρονισμού, πληρωμών, cloud-control-plane και φυσικά στοιχεία μπορούν να αποκαλύψουν τον χρήστη ακόμη και πίσω από μια φαινομενικά άψογη διαδρομή.

Κάθε καταχώριση χρησιμοποιεί τα ίδια πεδία. Το “Procedure” σημαίνει νόμιμη ανάπτυξη ή emulation σε owned lab. Όπου η πραγματική τεχνική εξαρτάται από την παραβίαση router, την κλοπή πρόσβασης ή την κατάχρηση unwilling intermediary, η αναπαραγωγή χρησιμοποιεί συστήματα που ανήκουν στην άσκηση.

## Coverage matrix

| Οικογένεια | Τι βλέπει ο προορισμός | Ισχυρότερη ιδιότητα | Ταχύτητα | Αντιμετώπιση |
|---|---|---|---|---|
| Shared NAT/CGNAT | shared public address | ασάφεια μεταξύ subscribers | υψηλή | deployable |
| VPN, VPS, SOCKS/HTTP/SSH proxy | relay address | γρήγορος διαχωρισμός source-address | υψηλή | deployable |
| Multi-hop/split relay, MASQUE | final proxy | διαχωρισμός γνώσης ή full-IP tunnel | υψηλή/μέτρια | deployable με trusted relays |
| Tor, bridge, onion service | exit ή onion identity | multi-party path και κοινός browser | μέτρια | deployable |
| I2P, GNUnet, mixnet | overlay peer/gateway | overlay ή αντίσταση σε timing analysis | χαμηλή/μεταβλητή | application-specific |
| OHTTP/ODoH, Private Relay | gateway/egress | διαχωρισμός source/request | υψηλή | μόνο σε υποστηριζόμενες εφαρμογές |
| Public Wi-Fi, travel router | venue/tunnel address | αλλαγή location/access-path | υψηλή | απαιτεί permission |
| Cellular/eSIM, satellite | carrier/provider address | ανεξάρτητο physical uplink | υψηλή/μεταβλητή | ο subscriber/provider παρατηρεί |
| Remote browser/jump host | remote workspace | διαχωρισμός endpoint και egress | υψηλή | deployable |
| Residential/mobile proxy | consumer/carrier address | εμφάνιση consumer network | υψηλή | κρίσιμα τα consent/provenance |
| ORB/compromised relay | address άλλου victim | απόκρυψη origin και borrowed reputation | υψηλή | μόνο owned-lab reproduction |
| CDN/fronting/redirector | CDN/front address | προστασία back-end infrastructure | υψηλή | απαιτεί έγκριση provider/owner |
| Fast flux/DGA/dead drop | rotating node/service | αντίσταση στην ανακάλυψη infrastructure | μεταβλητή | μόνο owned-lab reproduction |
| Drop/nearest-neighbor | local target-adjacent address | διέλευση geographic/network boundary | υψηλή | μόνο owned-site lab |
| Store-and-forward/offline | gateway ή physical receiver | μείωση interactive timing linkage | χαμηλή | application-specific |
| Pluggable/refraction transport | Tor entry ή cooperating diversion proxy | censorship-resistant reachability | μεταβλητή | supported client ή research lab |
| IPFS gateway/PIR/remote fetcher | gateway ή application service | διαχωρισμός publisher/query/request | μεταβλητή | bounded application only |
| Anycast/QUIC/MPTCP | stable broker ή multiple subflows | rendezvous και session continuity | υψηλή | availability, όχι anonymity |
| CI/CD automation runner | hosted runner address | disposable accountable egress | υψηλή | μόνο owned workflow |
| Non-IP local first hop | organization gateway | αφαίρεση Internet stack από sensor | χαμηλή | owner-approved deployment |

## Direct shared NAT and carrier-grade NAT

**Mechanics:** Πολλοί χρήστες μοιράζονται μία public address· ο access provider αντιστοιχίζει subscriber-side addresses και ports στο public tuple.

**Pros:** γρήγορο· δεν απαιτεί ειδικό client· το destination-side IP μπορεί να ταυτοποιεί μόνο household, venue ή carrier pool.

**Cons:** Ο provider μπορεί να διατηρεί subscriber/port/time mappings· accounts και fingerprints παραμένουν· άλλοι χρήστες μπορούν να βλάψουν τη reputation της address.

**Procedure:** (1) επιβεβαιώστε αν η εξουσιοδοτημένη πρόσβαση χρησιμοποιεί NAT/CGNAT· (2) καταγράψτε το ακριβές public IP και source port σε owned endpoint· (3) διατηρήστε χωριστές τις application identities· (4) μην αντιμετωπίζετε το shared addressing ως privacy control· (5) χρησιμοποιήστε ισχυρότερη διαδρομή αν ο ISP δεν πρέπει να γνωρίζει τους προορισμούς.

**Detection:** Οι προορισμοί πρέπει να διατηρούν source port και ακριβή χρόνο, όχι μόνο IP. Οι providers συσχετίζουν NAT allocation logs· οι investigators συνδέουν account/device/browser evidence.

## Commercial VPN

**Mechanics:** Μια encrypted full-tunnel connection τερματίζει στο VPN· οι προορισμοί βλέπουν το egress του. Το VPN μπορεί συνήθως να συσχετίσει source, timing και destinations.

**Pros:** γρήγορο· απλό· προστατεύει από local passive observation· stable ή shared exits· κατάλληλο για controlled red-team egress.

**Cons:** συγκεντρωμένη εμπιστοσύνη· billing/login telemetry· kill-switch/DNS/IPv6 failures· τα shared exits συχνά αποκλείονται λόγω reputation.

**Procedure:** (1) εντοπίστε provider, owner, jurisdiction, retention και assessment policy· (2) εγκαταστήστε τον signed official client· (3) ενεργοποιήστε full tunnel, always-on και fail-closed behavior· (4) ρυθμίστε σκόπιμα DNS και IPv6· (5) επαληθεύστε observed IPv4/IPv6/DNS σε owned endpoint· (6) σταματήστε/επανασυνδέστε το tunnel και επιβεβαιώστε ότι δεν υπάρχει clear fallback.<sup>[[1]](#references)</sup>

**Detection:** Τα local networks βλέπουν μακρά encrypted flow προς VPN infrastructure· οι providers διαθέτουν authentication/connection records· οι προορισμοί χρησιμοποιούν ASN/reputation μαζί με account, TLS/browser και behavior correlation.

## Self-hosted VPN or rented VPS egress

**Mechanics:** Ο operator ελέγχει WireGuard/OpenVPN gateway ή προωθεί traffic μέσω rented server.

**Pros:** προβλέψιμη υψηλή ταχύτητα· fixed allowlistable address· custom logging/firewall· καλός incident control.

**Cons:** μικρό anonymity set· cloud tenant, payment, source login, API και image history συνδέουν τον operator· ένας distinctive νέος server ομαδοποιείται εύκολα.

**Procedure:** (1) δημιουργήστε engagement-specific organization project· (2) κάντε provision supported image και fixed address· (3) περιορίστε το management σε MFA/key-based administration· (4) ρυθμίστε full-tunnel egress και DNS· (5) επιτρέψτε μόνο scoped destinations όπου είναι πρακτικό· (6) δοκιμάστε leak/failure behavior· (7) διατηρήστε controller audit records· (8) καταστρέψτε credentials και resources στο teardown.

**Detection:** Συσχετίστε hosting ASN, first-seen address, certificate/service fingerprint και scanning behavior· οι cloud owners χρησιμοποιούν control-plane, console, billing και flow logs.

## HTTP CONNECT, SOCKS and SSH forwarding

**Mechanics:** Μια εφαρμογή ζητά από proxy να ανοίξει TCP stream· το SOCKS μπορεί επίσης να μεταφέρει name resolution και UDP ανάλογα με την έκδοση· το SSH προωθεί streams μέσα σε μία encrypted session.

**Pros:** ελαφρύ· per-application· γρήγορο· χρήσιμο για chaining και πρόσβαση σε segmented networks.

**Cons:** Οι εφαρμογές μπορούν να το παρακάμψουν· το DNS μπορεί να leak· ο proxy βλέπει τα adjacent endpoints· το browser state παραμένει· τα open proxies μπορεί να είναι παγίδες ή compromised systems.

**Procedure:** (1) αναπτύξτε τον proxy σε owned host· (2) απαιτήστε authentication και περιορίστε source/destination· (3) ρυθμίστε ένα disposable application profile· (4) εξασφαλίστε remote DNS resolution όπου απαιτείται· (5) επαληθεύστε με owned DNS/HTTP endpoint· (6) αποκλείστε direct egress για το workload· (7) ελέγξτε και περιστρέψτε τα proxy credentials.

**Detection:** Εντοπίστε tunnel-capable processes, CONNECT/SOCKS negotiation, μακρές SSH sessions και destinations που δεν συμφωνούν με την εφαρμογή· τα proxy logs ανακατασκευάζουν τα streams.

## URL-rewriting web proxy and browser proxy extension

**Mechanics:** Ένα website ανακτά destination και ξαναγράφει links/forms μέσω του δικού του origin, ή ένα extension κατευθύνει τα browser requests σε proxy. Ο destination βλέπει την υπηρεσία, ενώ η υπηρεσία μπορεί να δει plaintext μετά το TLS termination και να εισαγάγει ή να διατηρήσει content.

**Pros:** δεν απαιτεί system-wide client· γρήγορο για απλό browsing· λειτουργεί όπου δεν είναι δυνατή η εγκατάσταση VPN.

**Cons:** Ο proxy μπορεί να διαβάσει credentials/content, να τροποποιήσει downloads και να κάνει fingerprinting χρηστών· scripts/WebSockets/downloads μπορεί να παρακάμπτονται· το browser extension έχει ευρείες privileges· μικρό anonymity set και συχνά blocks.

**Procedure:** (1) χρησιμοποιήστε μόνο organization-operated proxy για authorized testing· (2) απομονώστε το σε disposable browser χωρίς personal accounts· (3) απαγορεύστε password entry και sensitive downloads· (4) επαληθεύστε ότι κάθε subresource σε owned page περνά από τον proxy· (5) δοκιμάστε WebSocket, download και form behavior· (6) αφαιρέστε extension/profile μετά τη χρήση.

**Detection:** Ο destination καταγράφει τον proxy· enterprise proxy/DNS και extension inventory εντοπίζουν την υπηρεσία· content-security/reporting ή owned canary subresources αποκαλύπτουν direct bypass· τα proxy logs αντιστοιχούν user session με targets.

## Multi-hop proxy or provider multi-hop VPN

**Mechanics:** Ένα entry βλέπει το source, ενώ ένα ή περισσότερα traversal relays το διαχωρίζουν από exit που βλέπει τον destination.

**Pros:** κανένα συνηθισμένο relay δεν χρειάζεται να γνωρίζει και τα δύο άκρα· failure/seizure ενός node αποκαλύπτει λιγότερα· ευέλικτη γεωγραφία.

**Cons:** shared administration/logs καταργούν τον διαχωρισμό· latency· timing correlation· περισσότερα failures και DNS routes· το ίδιο account/payment μπορεί να ενώσει όλα τα hops.

**Procedure:** (1) καθορίστε ποιον observer αφαιρεί κάθε hop· (2) χρησιμοποιήστε independently administered owned/approved relays όπου ο διαχωρισμός έχει σημασία· (3) επιβάλετε entry-only access από το workload· (4) εξασφαλίστε ότι κάθε relay μπορεί να φτάσει μόνο στο επόμενο hop· (5) επαληθεύστε logs σε κάθε layer· (6) σταματήστε κάθε hop και επιβεβαιώστε fail-closed behavior. Αναπαραγάγετε με [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain).

**Detection:** Συσχετίστε adjacent NetFlow timing/volume, επαναλαμβανόμενα proxy handshakes και κοινή controller infrastructure· μην συμπεραίνετε τη γεωγραφία του operator από το exit.

## Split-knowledge application relay and OHTTP

**Mechanics:** Ο client κρυπτογραφεί stateless HTTP message προς gateway και το στέλνει μέσω relay. Ο relay βλέπει client IP αλλά όχι request· ο gateway βλέπει το request αλλά συνήθως μόνο το relay IP.

**Pros:** ισχυρό, auditable privacy partition για υποστηριζόμενα requests· χαμηλότερο overhead από general anonymity networks.

**Cons:** όχι arbitrary browsing· cookies/authentication μπορούν να επανασυνδέσουν τα δεδομένα· relay/gateway collusion και traffic analysis παραμένουν· η εφαρμογή πρέπει να το υλοποιεί.

**Procedure:** (1) επιλέξτε εφαρμογή που υποστηρίζει ρητά RFC 9458· (2) επαληθεύστε τα gateway keys μέσω official configuration path· (3) αποφύγετε stable per-user fields· (4) στείλτε μόνο το υποστηριζόμενο stateless request· (5) συγκρίνετε relay, gateway και target logs· (6) δοκιμάστε key rotation/failure χωρίς direct fallback.<sup>[[2]](#references)</sup>

**Detection:** Τα enterprise endpoints αποκαλύπτουν initiating process και OHTTP relay· τα gateways εντοπίζουν malformed/replayed traffic· timing και stable payload/account fields μπορούν να συσχετίσουν requests.

## MASQUE CONNECT-UDP/CONNECT-IP and HTTP privacy proxies

**Mechanics:** Το HTTP Extended CONNECT over TLS/QUIC μεταφέρει UDP ή IP packets μέσω proxy. Μπορεί να υλοποιήσει modern VPN-like tunnel και να αναμείξει το transport με HTTP/3, όμως ο proxy παραμένει observer.<sup>[[3]](#references)</sup>

**Pros:** αποδοτικό multiplexing/roaming· υποστηρίζει UDP ή full IP· αναπτύσσεται μέσω modern HTTP infrastructure.

**Cons:** δεν είναι anonymity network· ο proxy/account βλέπει source και destinations· QUIC/HTTP fingerprints και well-known paths είναι ορατά σε endpoints/providers.

**Procedure:** (1) χρησιμοποιήστε client/service που τεκμηριώνει RFC 9298/9484 support· (2) κάντε authenticate το proxy certificate/configuration· (3) καθορίστε allowed target routes· (4) ενεργοποιήστε encrypted DNS μέσα στη διαδρομή· (5) επαληθεύστε UDP, TCP, IPv6 και failover σε owned endpoints· (6) ελέγξτε proxy request και flow logs.

**Detection:** Τα endpoints βλέπουν client process και virtual interface· τα networks μπορούν να ταξινομήσουν sustained QUIC/TLS προς proxy· τα proxy logs αποκαλύπτουν CONNECT target/path και assigned routes.

## Tor Browser

**Mechanics:** Το Tor επιλέγει guard, middle και exit relays· η layered encryption περιορίζει το view κάθε relay. Το Tor Browser προσθέτει standardized browser σχεδιασμένο να αντιστέκεται στο fingerprinting.

**Pros:** μεγάλο public anonymity set· κανένα ordinary relay δεν γνωρίζει και τα δύο άκρα· destination unlinkability χωρίς operating servers.

**Cons:** πιο αργό· κυρίως TCP-focused· exit reputation/blocks· logins και disclosures ταυτοποιούν τον χρήστη· παραμένει low-latency timing correlation.

**Procedure:** (1) κατεβάστε και επαληθεύστε το Tor Browser από το project· (2) διατηρήστε τα defaults και αποφύγετε extensions· (3) επιλέξτε κατάλληλο security level· (4) δημιουργήστε separate identity/session· (5) αποφύγετε identifying accounts και external active documents· (6) χρησιμοποιήστε HTTPS ή authenticated onion services· (7) επαληθεύστε το exit μόνο με owned endpoint.<sup>[[4]](#references)</sup>

**Detection:** Τα local networks μπορούν να αναγνωρίσουν known guard traffic εκτός αν χρησιμοποιείται bridge/transport· οι destinations βλέπουν exits και Tor Browser behavior· end-to-end observers συσχετίζουν timing/volume.

## Tor bridges and pluggable transports

**Mechanics:** Ένα non-public bridge αντικαθιστά το public guard· τα obfs4, Snowflake ή WebTunnel αλλάζουν το first-hop transport ώστε να αντιστέκεται σε simple blocking/probing.

**Pros:** παρακάμπτει censorship και αποκρύπτει προφανείς public-relay destinations· διατηρεί το Tor circuit μετά την είσοδο.

**Cons:** transport patterns/bridge discovery παραμένουν πιθανά· μεταβλητή performance· δεν παρέχει προστασία απέναντι σε accounts ή global timing.

**Procedure:** (1) δοκιμάστε πρώτα direct Tor· (2) στις Connection settings του Tor Browser επιλέξτε built-in supported transport ή ζητήστε official bridge· (3) μην χρησιμοποιείτε random binaries/lists· (4) συνδεθείτε και εκτελέστε benign test· (5) δοκιμάστε reconnect και clock· (6) διατηρήστε όλα τα υπόλοιπα browser settings standard.<sup>[[5]](#references)</sup>

**Detection:** Οι censors χρησιμοποιούν destination discovery, protocol/flow classification και active probing· οι defenders πρέπει να διακρίνουν circumvention use από compromise και να βασίζονται σε endpoint process/context.

## VPN before Tor and Tor before VPN

**Mechanics:** Το VPN-before-Tor αποκρύπτει direct Tor use από τον access ISP αλλά εκθέτει το source στο VPN. Το Tor-before-VPN δίνει στο VPN post-Tor traffic και συχνά stable customer/tunnel identity.

**Pros:** αφαιρεί συγκεκριμένο observer όταν σχεδιαστεί σωστά· μπορεί να φτάσει networks που αποκλείουν το ένα layer.

**Cons:** complexity, uncommon fingerprint, leaks, μειωμένο anonymity set και false confidence· το Tor Project αντιμετωπίζει τους συνδυασμούς ως advanced.<sup>[[6]](#references)</sup>

**Procedure:** (1) γράψτε ποιον observer αφαιρείτε και ποιον νέο observer εισάγετε· (2) χρησιμοποιήστε disposable environment· (3) εγκαταστήστε μόνο την intended outer path· (4) επιβάλετε firewall routes· (5) επαληθεύστε DNS/IPv4/IPv6 και κάθε failure order· (6) συγκρίνετε την ορατότητα και των δύο providers· (7) εγκαταλείψτε το stack αν δεν έχει μετρήσιμο πλεονέκτημα.

**Detection:** Οι local/VPN/Tor observers βλέπουν διαφορετικά adjacent layers· το timing παραμένει end-to-end· ασυνήθιστα nested tunnel fingerprints και provider accounts μπορούν να συνδέσουν sessions.

## Onion service

**Mechanics:** Τόσο ο client όσο και το service δημιουργούν Tor circuits προς rendezvous, αποκρύπτοντας το service IP και αποφεύγοντας exit.

**Pros:** προστασία source και service location· end-to-end onion authentication· χωρίς public inbound port· προαιρετικό client authorization.

**Cons:** origin leaks μέσω updates/analytics/errors· το onion key είναι κρίσιμο· application identity/timing και host compromise παραμένουν.

**Procedure:** (1) απομονώστε την εφαρμογή και κάντε bind μόνο σε loopback/socket· (2) εγκαταστήστε supported Tor· (3) ρυθμίστε v3 onion service σύμφωνα με official instructions· (4) προστατέψτε/κρατήστε backup του key μόνο αν χρειάζεται stable identity· (5) προσθέστε client authorization για closed use· (6) αφαιρέστε third-party fetches· (7) επαληθεύστε externally ότι το origin δεν είναι reachable.<sup>[[7]](#references)</sup>

**Detection:** Host/network defenders εντοπίζουν Tor process/configuration και outbound circuits· application errors, DNS, certificates ή third-party resources μπορούν να αποκαλύψουν το origin.

## I2P internal services

**Mechanics:** Το I2P χρησιμοποιεί ξεχωριστά unidirectional inbound/outbound tunnels για destinations μέσα στο overlay· τα public-Internet outproxies προσθέτουν trust point.

**Pros:** decentralized internal publishing· χωρίς official exit dependency· ξεχωριστές inbound/outbound paths.

**Cons:** δεν αποτελεί general web replacement· μικρότερο ecosystem· long-running peer behavior· το outproxy μπορεί να παρατηρεί public browsing.

**Procedure:** (1) εγκαταστήστε από official source· (2) χρησιμοποιήστε dedicated context· (3) επιτρέψτε integration/bandwidth stabilization· (4) προσπελάστε owned I2P-native service· (5) αποφύγετε outproxies εκτός αν απαιτούνται ρητά· (6) επαληθεύστε ότι το shutdown δεν δίνει direct fallback· (7) ελέγξτε local peer και service logs.<sup>[[8]](#references)</sup>

**Detection:** Τα local networks βλέπουν long-lived peer traffic και bootstrap behavior· τα endpoints αποκαλύπτουν router/application processes· τα outproxies καταγράφουν exits.

## Mixnets

**Mechanics:** Fixed-size packets, batching, delay, reordering και cover traffic μειώνουν το timing correlation· gateways συνδέουν applications.

**Pros:** καλύτερη αντίσταση σε timing analysis από low-latency proxies· χρήσιμο για asynchronous messages/transactions.

**Cons:** latency, bandwidth overhead, μικρότερη deployment και application limits· gateway/account metadata μπορεί να παραμένει.

**Procedure:** (1) επιλέξτε maintained client και supported application· (2) διαβάστε το πραγματικό threat model· (3) εγκαταστήστε σε separate compartment· (4) στείλτε benign data σε owned endpoint· (5) μετρήστε latency/reliability και reply path· (6) δοκιμάστε gateway failure· (7) μην απενεργοποιείτε delays/cover traffic μόνο για ταχύτητα.<sup>[[9]](#references)</sup>

**Detection:** Τα endpoints αναγνωρίζουν τον client· τα access networks μπορούν να ταξινομήσουν gateways/packet cadence· gateways και exits παρατηρούν adjacent roles, ενώ ευρύτερη correlation απαιτεί μεγαλύτερα statistical windows.

## GNUnet anonymous file sharing

**Mechanics:** Το GNUnet μπορεί να δρομολογεί publish/search/download requests μέσω peers και να προσθέτει cover traffic ανάλογα με anonymity level. Η δική του documentation προειδοποιεί ότι το default level 1 δεν απαιτεί cover traffic και ότι ισχυρό traffic analysis μπορεί να εντοπίσει το origin.<sup>[[10]](#references)</sup>

**Pros:** decentralized, application-native anonymous sharing· ρυθμιζόμενη απαίτηση cover traffic.

**Cons:** όχι ordinary anonymous web access· performance/storage cost· peer και traffic-analysis limitations· η GNUnet VPN documentation αναφέρει ότι το IP overlay δεν παρέχει good anonymity.

**Procedure:** (1) εγκαταστήστε maintained official build· (2) απομονώστε test peer· (3) περιορίστε bandwidth/storage· (4) δημοσιεύστε harmless unique test file με επιλεγμένο anonymity level· (5) ανακτήστε το από άλλο owned peer· (6) καταγράψτε cover-traffic και latency· (7) μην ισχυριστείτε ότι το IP VPN component παρέχει ισοδύναμη anonymity.

**Detection:** Peer bootstrap, overlay traffic, local datastore/process και file identifiers· broad observer μπορεί να αναλύσει traffic volume σε σχέση με cover traffic.

## Encrypted DNS, ODoH and ECH

**Mechanics:** Τα DoH/DoT/DoQ κρυπτογραφούν προς resolver· το ODoH διαχωρίζει client address από query μεταξύ proxy και resolver· το ECH κρυπτογραφεί το inner TLS ClientHello/server name.

**Pros:** αφαιρεί plaintext DNS/SNI από ορισμένους local observers· το ODoH διαχωρίζει source/query knowledge.

**Cons:** δεν είναι IP-anonymity path· resolver/proxy/server διατηρούν roles· destination IP/timing/volume και endpoint παραμένουν· fallback μπορεί να προκαλέσει leak.

**Procedure:** (1) επιλέξτε αν το OS, η εφαρμογή ή το tunnel ελέγχει το DNS· (2) ενεργοποιήστε strict encrypted mode ή supported ODoH· (3) δοκιμάστε unique owned domain· (4) κάντε local capture για επιβεβαίωση ότι δεν υπάρχει clear query· (5) προκαλέστε failure του resolver και επαληθεύστε τη intended behavior· (6) για ECH, επιβεβαιώστε ότι τα server diagnostics δείχνουν inner ClientHello acceptance.<sup>[[11]](#references)</sup>

**Detection:** Endpoint/resolver logs αποκαλύπτουν queries· τα networks εντοπίζουν encrypted-resolver endpoints και destination flows· το ECH state είναι ορατό σε endpoints/CDN ακόμη κι όταν κρύβεται στη διαδρομή.

## Split-provider privacy relay

**Mechanics:** Products όπως το iCloud Private Relay χρησιμοποιούν ingress που γνωρίζει τον client και independently operated egress που γνωρίζει τον destination, με coarse region handling.

**Pros:** low-friction split knowledge· γρήγορο· integrated DNS/web protection για supported traffic.

**Cons:** περιορισμένο product/application scope· ο account/platform provider εξακολουθεί να ταυτοποιεί τον customer· όχι arbitrary system anonymity· collusion/legal και timing risks.

**Procedure:** (1) επιβεβαιώστε τις ακριβείς υποστηριζόμενες εφαρμογές και traffic types· (2) ενεργοποιήστε τη feature σε dedicated platform context όπου ενδείκνυται· (3) επιλέξτε region behavior· (4) δοκιμάστε Safari/DNS και unsupported applications χωριστά· (5) ελέγξτε τη destination address· (6) δοκιμάστε network switching/failure.<sup>[[12]](#references)</sup>

**Detection:** Το access βλέπει ingress· ο destination βλέπει egress· platform/relay logs και account records καλύπτουν το αντίστοιχο layer· οι unsupported applications εκθέτουν normal paths.

## Remote browser, VDI, RDP or organization jump host

**Mechanics:** Το browsing/tool execution γίνεται σε remote system· ο destination βλέπει το egress του, ενώ ο workspace provider βλέπει την operator connection και το control plane.

**Pros:** γρήγορο· απομονώνει risky content· stable controlled egress· disposable state και ισχυρό organizational audit.

**Cons:** Provider/admin μπορεί να παρατηρεί session/account· screen/clipboard/file channels κάνουν leak· το remote browser fingerprint μπορεί να είναι unique· δεν είναι anonymous προς τον workspace owner.

**Procedure:** (1) δημιουργήστε ένα organization-owned workspace ανά engagement· (2) απαιτήστε MFA και περιορίστε administration· (3) απενεργοποιήστε ή περιορίστε clipboard/upload/download· (4) δρομολογήστε μέσω approved fixed egress· (5) μην χρησιμοποιείτε personal IdP/sync· (6) εξάγετε μόνο reviewed evidence· (7) καταστρέψτε workspace και credentials σύμφωνα με schedule.

**Detection:** Provider και IdP logs αντιστοιχούν user σε session· destinations ομαδοποιούν workspace egress/browser· enterprise defenders εντοπίζουν remote-control protocols και anomalous cloud sessions.

## Public or guest Wi-Fi

**Mechanics:** Η traffic έξοδος γίνεται μέσω του venue NAT ή μέσω tunnel που ξεκινά εκεί.

**Pros:** υψηλή ταχύτητα και shared non-home address· χωρίς dedicated infrastructure.

**Cons:** venue association/DHCP/portal, κάμερες, purchase και location evidence· hostile peers/APs· όροι χρήσης· physical risk.

**Procedure:** (1) αποκτήστε την πρόσβαση που προσφέρεται σε guests και επαληθεύστε το SSID με το staff· (2) χρησιμοποιήστε patched low-trust device· (3) απενεργοποιήστε sharing/auto-join και ενεργοποιήστε private MAC· (4) ολοκληρώστε το portal χωρίς reused identity· (5) ξεκινήστε fail-closed VPN/Tor path· (6) επαληθεύστε tethered traffic· (7) κάντε forget το network.

**Detection:** Το venue συσχετίζει AP, MAC, DHCP, portal και time· ο destination βλέπει venue/tunnel· οι investigators συνδυάζουν physical και device evidence. Ποτέ μην παρακάμπτετε access control.

## Travel router

**Mechanics:** Ένα operator-owned router συνδέεται σε venue Wi-Fi/Ethernet και παρέχει isolated internal network με enforced tunnel policy.

**Pros:** απομονώνει workstations· κεντρικό kill switch/DNS· consistent client network· προστατεύει privileged endpoints από local broadcasts.

**Cons:** Ο router γίνεται stable radio/DHCP fingerprint· προσθέτει attack surface· captive portals και tethering μπορεί να παρακάμψουν το tunnel.

**Procedure:** (1) ενημερώστε supported firmware· (2) ορίστε unique management credentials και απενεργοποιήστε WAN admin/WPS/UPnP· (3) ρυθμίστε private upstream MAC όπου επιτρέπεται· (4) δημιουργήστε separate internal SSID· (5) επιβάλετε full-tunnel DNS/IPv6 firewall policy· (6) δοκιμάστε portal, reconnect και tunnel failure.

**Detection:** Το venue βλέπει router association και traffic shape· local RF/DHCP fingerprinting τον εντοπίζει· ο VPN provider βλέπει venue source.

## Cellular, prepaid SIM and eSIM

**Mechanics:** Ένα modem χρησιμοποιεί carrier radio access και συνήθως carrier NAT· ένα VPN/Tor layer μπορεί να αλλάξει το destination-visible exit.

**Pros:** ανεξάρτητο από local wired/Wi-Fi network· mobile· υψηλή ταχύτητα· χρήσιμο backhaul για authorized drops.

**Cons:** Ο carrier γνωρίζει subscriber/eSIM, IMSI, IMEI, cells, time και assigned ports· οι νόμοι registration διαφέρουν· co-location με personal phone συνδέει devices.

**Procedure:** (1) αποκτήστε την υπηρεσία νόμιμα με ακριβή απαιτούμενα στοιχεία· (2) χρησιμοποιήστε organization-owned separate modem/device· (3) καταγράψτε το με τον exercise controller· (4) απενεργοποιήστε unrelated radios/accounts· (5) εγκαταστήστε approved tunnel· (6) δοκιμάστε αν οι tethered clients πράγματι το ακολουθούν· (7) επαληθεύστε provider και retention assumptions πριν το ταξίδι.<sup>[[13]](#references)</sup>

**Detection:** Carrier records και RF location· enterprise USB/PCI/MDM inventory και rogue-hotspot surveys· destination/tunnel timing.

## Satellite Internet and satellite downlink abuse

**Mechanics:** Η κανονική υπηρεσία χρησιμοποιεί registered terminal/provider. Το παλαιότερο one-way DVB-S abuse επέτρεπε σε receiver μέσα σε beam να παρατηρεί unencrypted downlink traffic που απευθυνόταν σε legitimate subscriber, ενώ χρησιμοποιούσε άλλη διαδρομή για outbound requests.

**Pros:** wide footprint· independent last mile· historical one-way abuse μπορούσε να αποδώσει λανθασμένα το C2 στη γεωγραφία subscriber.

**Cons:** equipment/RF/provider records· latency και coverage· τα σύγχρονα bidirectional systems διαφέρουν· outbound path και asymmetric routing παραμένουν evidence.

**Procedure:** Για lawful access, καταχωρίστε owned terminal και tunnel traffic όπως απαιτείται. Για emulation ιστορικού Turla behavior, επαναλάβετε synthetic one-way packet captures μέσα σε RF-free lab και ελέγξτε αν οι analysts εντοπίζουν reply προς host που δεν έκανε request· μην αναχαιτίζετε live satellite traffic.<sup>[[14]](#references)</sup>

**Detection:** Provider/terminal telemetry, RF direction finding, impossible/asymmetric flow, RTT/routing inconsistency και malware configuration.

## Residential/mobile proxy or consented proxyware

**Mechanics:** Ένα backconnect gateway εκχωρεί consumer broadband/mobile exits, sticky ή rotating. Η supply μπορεί να είναι consensual, deceptively bundled ή malicious.

**Pros:** υψηλή ταχύτητα· geographic choice· consumer ASN αποφεύγει ορισμένα hosting blocks· μεγάλα pools.

**Cons:** provenance/consent και legal risk· ο broker βλέπει τον customer· infected exits βλάπτουν victims· rotation δημιουργεί anomalies· ακριβό και unreliable.

**Procedure:** Χρησιμοποιήστε μόνο documented, informed-consent organization-owned agents για emulation: (1) εγγράψτε test endpoints· (2) καταγράψτε owners/IPs· (3) ρυθμίστε gateway· (4) εναλλάξτε sticky/per-request modes· (5) στείλτε μόνο σε owned target· (6) συγκρίνετε gateway/exit/target logs· (7) αφαιρέστε κάθε agent.

**Detection:** Impossible travel, stable browser/account σε rapid IP/ASN changes, backconnect protocols, proxyware process/network artifacts και broker/controller relations.

## ORB, botnet and compromised edge-device relays

**Mechanics:** Leased ή compromised routers/IoT/servers σχηματίζουν access, traversal και exit roles που διαχειρίζονται ως fleet. Πολλοί APT customers μπορεί να το μοιράζονται.

**Pros:** borrowed reputation/geography· short-lived exits· resilient multi-hop mesh· weak direct actor-to-IP link.

**Cons:** criminal victimization· implant/controller και fleet patterns· intermediary seizure· inconsistent performance· operator/customer service records.

**Procedure:** Ποτέ μην παραβιάζετε πραγματικές συσκευές. Χρησιμοποιήστε [Lab 1](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain): (1) δημιουργήστε isolated entry/transit/target networks· (2) συνδέστε owned dual-homed relay containers· (3) προωθήστε μόνο ένα test port· (4) στείλτε benign request· (5) επαληθεύστε ότι ο target βλέπει μόνο το exit· (6) περιστρέψτε το exit· (7) κατεβάστε όλα τα named assets.<sup>[[15]](#references)</sup>

**Detection:** Παρακολουθήστε topology, ports/services, controller relations, implant fingerprints και node lifecycle· συγκεντρώστε edge configuration/flow/integrity telemetry· μην εξισώνετε exit IP με actor.

## CDN redirector, domain fronting and domainless fronting

**Mechanics:** Ένα public edge προωθεί μόνο traffic που ταιριάζει σε grammar· το fronting χρησιμοποιεί benign outer SNI και διαφορετικό inner HTTP authority, ή blank SNI, όταν το επιτρέπει ο intermediary.

**Pros:** κρύβει/προστατεύει back-end· fast global edge· αναμειγνύει τον destination με shared service· rapid cutover.

**Cons:** Το CDN βλέπει όλο το routing και tenant· πολλοί providers απαγορεύουν cross-tenant fronting· SNI/Host/process/flow και account artifacts· configuration reuse ομαδοποιεί campaigns.

**Procedure:** Αναπαραγάγετε μόνο σε owned reverse proxy με [Lab 2](authorized-adversary-emulation-labs.md#lab-2-snihost-mismatch-and-redirector-logging): δημιουργήστε local certificate/edge, δρομολογήστε ένα mismatched Host σε owned target, καταγράψτε SNI και Host, στείλτε normal/mismatched requests και αφαιρέστε τα containers.<sup>[[16]](#references)</sup>

**Detection:** Συγκρίνετε SNI/ECH/Host/`:authority` σε endpoint ή terminating edge· συσχετίστε initiating process, tenant/origin, request grammar και flow cadence.

## Dynamic DNS, DGA, fast flux and double flux

**Mechanics:** Το DDNS ενημερώνει stable name· το DGA παράγει μεταβαλλόμενα candidate names· το fast flux περιστρέφει service addresses με low TTL· το double flux περιστρέφει επίσης name servers.

**Pros:** resilient discovery· γρήγορη αντικατάσταση infrastructure· αποκρύπτει controller πίσω από πολλά nodes.

**Cons:** Το DNS δημιουργεί centralized telemetry· entropy/NXDOMAIN/churn· low TTL και broad ASN patterns· registration και authoritative infrastructure παραμένουν.

**Procedure:** Χρησιμοποιήστε [Lab 3](authorized-adversary-emulation-labs.md#lab-3-fast-flux-dns-telemetry): εξυπηρετήστε owned zone που επιστρέφει RFC 5737 addresses με five-second TTL, κάντε repeated queries, αλλάξτε το synthetic epoch και επικυρώστε τα analytics. Ποτέ μην κατευθύνετε test records σε τρίτους.<sup>[[17]](#references)</sup>

**Detection:** Sliding-window unique answers/ASNs, median TTL, geography, authoritative churn, DGA NXDOMAIN/lexical/temporal clusters και process follow-on· εξαιρέστε legitimate CDNs με context.

## Legitimate web service, dead-drop resolver and one-way tasking

**Mechanics:** Ένα public post, repository, document, object ή feed περιέχει encoded current endpoint ή task. Ο client μπορεί να επιστρέφει αποτελέσματα μέσω άλλου channel.

**Pros:** allowed high-reputation service· TLS· endpoint rotation χωρίς αλλαγή binary· asymmetric tasking δυσκολεύει το simple flow correlation.

**Cons:** stable object/account/API identifiers· provider records· endpoint decode/follow-on sequence· το content μπορεί να κατασχεθεί ή να αλλάξει.

**Procedure:** Χρησιμοποιήστε [Lab 5](authorized-adversary-emulation-labs.md#lab-5-dead-drop-resolver-sequence): φιλοξενήστε encoded pointer σε ένα owned container, κάντε fetch/decode από short-lived client, επικοινωνήστε με δεύτερη owned service, διατηρήστε και τα δύο logs και κάντε teardown.

## Serverless, ephemeral container and cloud-NAT egress

**Mechanics:** Functions/short-lived jobs εκτελούνται πίσω από provider NAT ή front· η logical service παραμένει stable ενώ instances και addresses περιστρέφονται.

**Pros:** rapid deployment/destruction· provider-scale shared egress· little local disk· elastic regional routing.

**Cons:** tenant, role, API, image, secret, invocation, billing και front-to-origin logs είναι durable· cold-start και platform fingerprints· provider policy.

**Procedure:** (1) χρησιμοποιήστε organization-owned exercise tenant· (2) αναπτύξτε benign function που ζητά μόνο owned endpoint· (3) καταγράψτε project/role/image/config· (4) κάντε invoke σε αρκετά instances· (5) συγκρίνετε target IPs με audit/request IDs· (6) δοκιμάστε log retention· (7) αφαιρέστε function, roles και secrets.

**Detection:** Cloud audit/invocation logs, unusual role creation, shared egress με stable request grammar, image/layer και secret reuse, και front-origin correlation.

## Authorized on-site drop

**Mechanics:** Ένας inventoried small computer χρησιμοποιεί local wired/Wi-Fi και outbound VPN/cellular rendezvous, παρουσιάζοντας local source.

**Pros:** realistic internal-origin testing· υψηλή ταχύτητα· δοκιμή NAC, physical inventory και egress controls.

**Cons:** physical discovery/theft· serial/MAC/USB/DHCP/PoE/RF και camera evidence· loss μπορεί να αποκαλύψει credentials.

**Procedure:** Ακολουθήστε το [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md): (1) λάβετε exact written placement authority· (2) καταγράψτε serial, MAC, photo, location και retrieval time· (3) χρησιμοποιήστε signed minimal image και short-lived mutual credentials· (4) περιορίστε outbound-only destinations/capabilities· (5) προσθέστε server-side quarantine και bandwidth limits· (6) δοκιμάστε SOC visibility και loss response· (7) ανακτήστε, διατηρήστε το required evidence και μετά κάντε sanitize σύμφωνα με την agreed lifecycle policy. Ποτέ μην το κρύβετε σε venue χωρίς consent.

**Detection:** NAC/802.1X, switchport/PoE/DHCP, USB inventory, RF survey, recurring tunnel, receiving/camera και physical inspection.

## Nearest-neighbor wireless pivot

**Mechanics:** Ο actor ελέγχει host σε radio range του target και χρησιμοποιεί target Wi-Fi credentials για να περάσει το boundary remotely. Το APT28 το χρησιμοποίησε έτσι.<sup>[[18]](#references)</sup>

**Pros:** no operator travel· ο target βλέπει local radio source· παρακάμπτει controls που εφαρμόζονται μόνο στην Internet entry.

**Cons:** απαιτεί nearby compromised/owned dual-radio host και valid access· RADIUS/NAC/AP και neighbor endpoint evidence· signal/device anomalies.

**Procedure:** Αναπαραγάγετε μόνο με το [two-owned-AP Lab 4](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot): συνδέστε owned pivot στα neighbor και target lab SSIDs, προωθήστε μόνο μία service, συλλέξτε και τα δύο AP/pivot logs και έπειτα ενεργοποιήστε EAP-TLS/device posture και επιβεβαιώστε ότι η δεύτερη προσπάθεια αποτυγχάνει.

**Detection:** Συσχετίστε RADIUS identity, managed certificate/posture, first-seen device, AP edge/signal, concurrent login και physical presence· αναζητήστε nearby endpoints για simultaneous radios, forwarding και tunnels.

## Community mesh, delay-tolerant and offline store-and-forward

**Mechanics:** Το traffic περνά από local peers, asynchronous gateways, removable media ή scheduled queues αντί για ένα interactive Internet session.

**Pros:** λειτουργεί σε disruption/censorship· delayed/batched delivery αποδυναμώνει το simple timing· χωρίς central last mile για local communication.

**Cons:** υψηλό latency· μικρό anonymity set· custody/physical metadata· malicious peers· τα data τελικά φτάνουν σε gateway που τα παρατηρεί.

**Procedure:** (1) δημιουργήστε isolated owned three-node mesh ή file queue· (2) κρυπτογραφήστε/authenticate content end to end· (3) αφαιρέστε direct Internet routes από το origin· (4) κάντε relay benign file μετά από controlled delay· (5) επαληθεύστε ότι μόνο gateway επικοινωνεί με owned destination· (6) συγκρίνετε custody/timestamps· (7) διατηρήστε required evidence και έπειτα κάντε sanitize temporary media/queues στο approved closeout.

**Detection:** Endpoint file/process activity, peer-radio links, removable-media audit, queue/gateway periodicity και content identifiers. Μεγαλύτερα correlation windows αντικαθιστούν το interactive-flow analysis.

## TURN relay and forced-relay WebRTC

**Mechanics:** Το Traversal Using Relays around NAT (TURN) εκχωρεί public relay address και μεταφέρει UDP, TCP ή TLS traffic μεταξύ client και peers. Μια ICE policy μπορεί να επιβάλει relay use αντί να εκθέτει direct candidate. Το TURN λύνει reachability, όχι general anonymity: ο server authenticates τον client και παρατηρεί allocations, peers, time και volume.<sup>[[19]](#references)</sup>

**Pros:** widely implemented· αντιμετωπίζει restrictive NAT· υποστηρίζει mobile WebRTC· ο peer δεν λαμβάνει το direct transport address του client όταν επιβάλλεται σωστά relay-only policy.

**Cons:** Ο TURN operator βλέπει και τις δύο adjacent sides· application identity, media fingerprint και signaling παραμένουν· relay-only κοστίζει bandwidth και latency· misconfiguration μπορεί να συλλέξει host ή server-reflexive candidates.

**Procedure:** (1) αναπτύξτε organization-owned TURN service με TLS και short-lived credentials· (2) περιορίστε realms, peers, ports, quotas και expiration· (3) ρυθμίστε την test application σε relay-only ICE· (4) καλέστε owned peer· (5) ελέγξτε `getStats()` και packet capture ώστε να επιβεβαιώσετε ότι μόνο relay candidates μετέφεραν media· (6) προκαλέστε relay failure και επιβεβαιώστε ότι δεν υπάρχει direct fallback· (7) διατηρήστε allocation logs για το engagement.

**Detection:** Signaling, browser process και TURN allocations συνδέουν το session με το relay· networks παρατηρούν sustained flows προς TURN ports ή TLS endpoints· ο peer βλέπει το allocated relay. **Captured node:** Application state και ephemeral TURN credentials μπορεί να αποκαλύψουν realm και rendezvous service. Περιορίστε την έκθεση με per-device, short-lived credentials και κρατήστε το operator authentication μόνο στον controller.

## Outbound-only rendezvous or reverse overlay

**Mechanics:** Node πίσω από NAT ξεκινά authenticated connection προς organization-controlled broker. Ο operator authenticates ξεχωριστά στον broker, ο οποίος εξουσιοδοτεί narrow management channel· δεν απαιτείται inbound port forwarding ή direct operator-to-node route.

**Pros:** stable πίσω από NAT και captive last miles· central revocation και audit· οι address changes του field node δεν απαιτούν operator discovery· καθαρός διαχωρισμός operator identity από node credential.

**Cons:** Ο broker γίνεται high-value correlation point· periodic keepalives είναι αναγνωρίσιμα· broad tunnel μπορεί να γίνει unsafe pivot· απώλεια broker τερματίζει το management.

**Procedure:** Ακολουθήστε το [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md#step-4-stable-outbound-rendezvous): εκδώστε μία scoped device identity, επιτρέψτε μόνο owned broker και approved management service, χρησιμοποιήστε authenticated keepalive, επιβάλετε fail-closed routing, δοκιμάστε address changes και reboot recovery και ανακαλέστε την identity στο loss drill. Το WireGuard τεκμηριώνει 25-second persistent keepalive ως broadly useful NAT interval όταν πράγματι απαιτείται.<sup>[[20]](#references)</sup>

**Detection:** Broker και identity-provider logs αντιστοιχούν και τις δύο πλευρές· το access network βλέπει repeated encrypted destination/cadence· endpoint inventory δείχνει overlay agent. **Captured node:** θεωρήστε exposed το device key, broker name, tunnel addresses και cached task data. Δεν πρέπει να περιέχει operator private key, personal account ή reusable controller token.

## Pull mailbox, message queue or object-store rendezvous

**Mechanics:** Field workload κάνει polling σε authenticated mailbox για signed, pre-approved jobs και δημοσιεύει bounded results. Ο operator γράφει στην queue μέσω separate control plane· δεν υπάρχει interactive socket μεταξύ τους.

**Pros:** αντέχει intermittent links· αποσυνδέει timing και addressing· quotas και schemas περιορίζουν capability· εύκολο centralized audit και revocation.

**Cons:** Polling cadence και stable object/queue names κάνουν fingerprint το system· provider logs συνδέουν producer και consumer· delayed control· captured queued data μπορεί να αποκαλύψει την άσκηση.

**Procedure:** (1) δημιουργήστε ένα engagement queue και μία device identity· (2) ορίστε signed schema benign, explicitly scoped jobs· (3) θέστε message TTL, maximum result size και rate· (4) επιτρέψτε στο node να κάνει pull μόνο από τη δική του queue και write μόνο στο δικό του result prefix· (5) δοκιμάστε offline accumulation, duplicate delivery και revocation· (6) συγκεντρώστε immutable access logs· (7) διαγράψτε την queue μετά την κάλυψη των retention requirements.

**Detection:** Αναζητήστε periodic API calls από unusual process, stable bucket/object/queue paths, identical user-agent ή TLS behavior και fetch-then-new-connection sequence. **Captured node:** Local cache μπορεί να αποκαλύψει pending jobs και object names· κρατήστε το cache encrypted, bounded και disposable, διατηρώντας authoritative controller logs.

## Dual-uplink failover and connection migration

**Mechanics:** Approved field node διαθέτει δύο independent uplinks —όπως venue Ethernet/Wi-Fi και organization cellular— και διατηρεί control session μέσω overlay ή message broker καθώς αλλάζουν οι routes. Αυτό είναι availability engineering, όχι anonymity.

**Pros:** επιβιώνει από failure provider, AP ή captive portal· υποστηρίζει planned maintenance· επιτρέπει γρήγορη απομόνωση ύποπτης path.

**Cons:** Δύο providers δημιουργούν δύο location/account records· simultaneous use διευκολύνει correlation· route και DNS leaks κατά το failover· cellular co-location evidence παραμένει.

**Procedure:** (1) καταχωρίστε και τα δύο organization-owned interfaces και providers· (2) αναθέστε deterministic route priorities και health checks προς owned endpoints· (3) κάντε bind DNS και management στο overlay· (4) εμποδίστε το secondary path να δέχεται inbound traffic· (5) αποσυνδέστε κάθε path και επαληθεύστε session recovery, source policy και απουσία direct destination access· (6) δημιουργήστε alert σε unplanned path change· (7) τεκμηριώστε data use και roaming limits.

**Detection:** Συσχετίστε το ίδιο device certificate, request grammar και timing μεταξύ ASNs· local inventory βλέπει και τα δύο radios· carriers/venues διατηρούν τα δικά τους records. **Captured node:** Και τα δύο SIM/device identifiers και γνωστά SSIDs μπορεί να είναι ορατά· χρησιμοποιήστε organization assets και ποτέ μην κάνετε co-location ή pairing με personal devices.

## Organization private APN or managed cellular tunnel

**Mechanics:** Carrier private APN τοποθετεί enrolled SIMs σε private routed domain ή διοχετεύει traffic σε enterprise gateway. Διαχωρίζει τη συσκευή από το public mobile Internet, αλλά δεν την αποκρύπτει από carrier ή contracting organization.

**Pros:** stable private addressing· carrier-level enrollment και traffic policy· αποφυγή public inbound exposure· χρήσιμο για authorized remote appliances.

**Cons:** subscriber, IMSI/IMEI, cell και billing attribution είναι ισχυρά· procurement lead time και cost· carrier/gateway outage· δεν είναι anonymous προς operator.

**Procedure:** (1) συμβληθείτε για το APN στο όνομα της assessment organization· (2) κάντε whitelist μόνο registered SIMs και gateway prefixes· (3) προσθέστε application-layer mutual authentication· (4) περιορίστε το APN route σε rendezvous και update services· (5) δοκιμάστε SIM removal, roaming, public-Internet breakout και revocation· (6) παρακολουθήστε carrier και gateway records· (7) ακυρώστε ή θέστε σε quarantine κάθε SIM στο closeout.

**Detection:** Carrier inventory και cell telemetry, APN gateway flows, SIM/IMEI mismatch και enterprise asset records. **Captured node:** Η SIM και το modem ταυτοποιούν το contract ακόμη κι όταν το storage είναι encrypted· capture resilience σημαίνει rapid suspension και narrow authorization, όχι deniability.

## Long-range point-to-point wireless bridge

**Mechanics:** Directional Wi-Fi ή άλλο licensed/unlicensed point-to-point radio συνδέει δύο owner-approved sites, με Internet egress στο remote site. Μπορεί να μετακινήσει την apparent IP location χωρίς commercial proxy.

**Pros:** υψηλό throughput· ανεξαρτησία από intermediate wired carriers· controllable RF και routing· χρήσιμο για testing segmentation και remote-site monitoring.

**Cons:** line-of-sight, spectrum, landlord και regulatory constraints· distinctive RF emissions και hardware· και τα δύο endpoints είναι physical evidence· weather/power/alignment επηρεάζουν stability.

**Procedure:** (1) λάβετε written permission και για τα δύο sites και επαληθεύστε spectrum/power rules· (2) κάντε survey χωρίς transmission έξω από approved parameters· (3) χρησιμοποιήστε authenticated encryption και management VLAN· (4) περιορίστε το bridge σε owned rendezvous ή test subnet· (5) δοκιμάστε failover, alignment, power recovery και RF containment· (6) κάντε label/inventory και στα δύο radios· (7) αφαιρέστε τα και επαληθεύστε configuration reset μετά την άσκηση.

**Detection:** RF surveys, spectrum analysis, rooftop/site inspection, bridge MAC/OUI, management traffic και remote-site egress logs. **Captured node:** Η configuration αποκαλύπτει peer και management domain· χρησιμοποιήστε unique exercise credentials, χωρίς personal management accounts και με rapid peer-key revocation.

## Consented cooperative or community exit

**Mechanics:** Volunteers ή partner organizations εκτελούν relays εν γνώσει τους, βάσει published policy. Το traffic εξέρχεται από shared community pool, ενώ το coordination layer διαχειρίζεται abuse και revocation.

**Pros:** diverse non-cloud networks· explicit consent ασφαλέστερο από proxyware· shared governance μπορεί να διανείμει την εμπιστοσύνη· χρήσιμο για research και censorship-resilience studies.

**Cons:** Small pools και membership records μειώνουν anonymity· exit operators λαμβάνουν complaints και παρατηρούν traffic metadata· malicious participants, variable uptime και jurisdiction differences.

**Procedure:** (1) δημοσιεύστε acceptable-use και logging policy· (2) λάβετε informed opt-in από κάθε operator· (3) εκδώστε unique relay identity και περιορίστε destinations/rates· (4) παρέχετε abuse handling και one-action revocation· (5) στείλτε μόνο authorized traffic σε owned endpoints κατά το testing· (6) μετρήστε churn και correlation exposure· (7) αφαιρέστε cleanly το relay όταν τερματιστεί το consent.

**Detection:** Membership/control-plane records, relay certificates, common software fingerprint και exit behavior ταυτοποιούν το pool. **Captured node:** Η relay configuration μπορεί να ταυτοποιήσει το cooperative, αλλά δεν πρέπει να περιέχει client identities· αποθηκεύστε client-to-session accountability στον authorized controller με access control.

## IPv6 temporary addresses and prefix rotation

**Mechanics:** Τα IPv6 privacy extensions δημιουργούν temporary interface identifiers ώστε stable address να μην επαναχρησιμοποιείται για κάθε outbound connection. Provider prefix changes μπορούν να προσθέσουν rotation, όμως delegated prefix, subscriber record και upper-layer fingerprint παραμένουν.<sup>[[21]](#references)</sup>

**Pros:** μειώνει passive long-term tracking από stable interface identifier· ενσωματωμένο σε common operating systems· χωρίς relay overhead.

**Cons:** όχι source anonymity· ISP και local network γνωρίζουν prefix/device· DNS, accounts και browser state συνδέουν sessions· address churn περιπλέκει allowlists και logging.

**Procedure:** (1) ελέγξτε current stable και temporary addresses σε owned client· (2) ενεργοποιήστε το OS-supported privacy-address default αντί για third-party spoofing· (3) ζητήστε repeated requests σε owned IPv6 endpoint σε διαφορετικά address lifetimes· (4) επιβεβαιώστε ότι inbound services κάνουν bind μόνο σε intended stable addresses· (5) διατηρήστε DHCPv6/RA/neighbor και precise endpoint logs· (6) δοκιμάστε VPN/firewall behavior για κάθε IPv6 address.

**Detection:** Συσχετίστε delegated prefix, layer-2 identity, neighbor discovery, account και endpoint telemetry αντί να αντιμετωπίζετε μία address ως μία συσκευή. **Captured node:** Network profiles και interface identifiers παραμένουν· το temporary addressing αποτρέπει ένα passive identifier, όχι forensic attribution.

## Tor pluggable transports: Snowflake, WebTunnel, obfs4 and meek

**Mechanics:** Ένα pluggable transport αλλάζει το πώς εμφανίζεται η πρώτη Tor connection ή το πώς φτάνει σε bridge. Το Snowflake χρησιμοποιεί short-lived volunteer WebRTC proxies, το WebTunnel μοιάζει με ordinary HTTPS, το obfs4 αντιστέκεται σε simple protocol identification και active probing, και το meek κάνει relay μέσω supported web infrastructure. Είναι censorship-circumvention transports προς Tor, όχι επιπλέον end-to-end anonymity layers.<sup>[[22]](#references)</sup>

**Pros:** χρήσιμο όταν direct Tor ή known relays αποκλείονται· το Snowflake αποφεύγει stable public bridge address· integrated σε maintained Tor clients· ο destination εξακολουθεί να λαμβάνει ordinary Tor properties.

**Cons:** χαμηλότερη ή μεταβλητή performance· broker/front/bridge και local network παρατηρούν διαφορετικά metadata· transport fingerprints και blocking παραμένουν πιθανά· volunteer proxy δεν αντικαθιστά το Tor και δεν πρέπει να εμπιστεύεται application plaintext.

**Procedure:** (1) εγκαταστήστε και επαληθεύστε official Tor Browser ή supported Tor client· (2) επιλέξτε built-in transport σε Connection/Bridges· (3) συνδεθείτε μόνο σε owned diagnostic page· (4) επιβεβαιώστε ότι η page βλέπει Tor exit, όχι Snowflake/WebTunnel peer· (5) συγκρίνετε bootstrap και performance· (6) προκαλέστε transport failure και επιβεβαιώστε ότι ο client δεν συνδέεται σιωπηρά απευθείας· (7) επιστρέψτε σε standard supported configuration μετά τη δοκιμή.

**Detection:** Censor μπορεί να συνδυάσει destination allowlists, TLS/WebRTC behavior, broker discovery και flow analysis· endpoints αποκαλύπτουν Tor και transport configuration. **Capture-resilient OPSEC:** Χρησιμοποιείτε standard client, ποτέ μην αντιγράφετε personal browser state σε αυτόν και θεωρείτε ότι bridge/broker history μπορεί να ανακτηθεί. **Monitoring:** Παρακολουθείτε Tor bootstrap logs, unexpected direct DNS/connection attempts και controller-side owned-page observations· transport failure δεν αποδεικνύει discovery.

## Refraction networking or decoy routing

**Mechanics:** Συνεργαζόμενος network operator εντοπίζει covert signal σε traffic που φαινομενικά απευθύνεται σε allowed decoy και εκτρέπει το flow σε circumvention proxy. Η ανάπτυξη απαιτεί infrastructure μέσα στο network path· δεν είναι κάτι που μπορεί να δημιουργήσει ένας client απλώς επιλέγοντας innocent website.<sup>[[23]](#references)</sup>

**Pros:** Ο apparent destination μπορεί να είναι δύσκολο να αποκλειστεί χωρίς collateral damage· δεν χρειάζεται διανομή public bridge address· χρήσιμο research model για on-path-assisted circumvention.

**Cons:** απαιτεί specialized ISP/transit participation· deployability και performance εξαρτώνται από routing· client-to-decoy flow και proxy-side activity παραμένουν· global ή cooperating observer μπορεί να συσχετίσει timing.

**Procedure:** Μην κάνετε signal μέσω uninvolved networks. Αναπαραγάγετε την architecture σε isolated lab: (1) δημιουργήστε owned client, router, decoy και proxy namespaces· (2) χρησιμοποιήστε benign tagged test request· (3) αφήστε τον owned router να ανακατευθύνει μόνο αυτό το tag στον proxy· (4) καταγράψτε pre/post-routing tuples και request IDs· (5) συγκρίνετε ordinary και signaled flows· (6) δοκιμάστε false positives και removal· (7) καταστρέψτε τα lab routes.

**Detection:** Authorized network operators μπορούν να ελέγξουν routing divergence, unusual client hello/tag behavior και decoy-versus-back-end flow discrepancies. **Capture-resilient OPSEC:** Research client πρέπει να περιέχει μόνο test keys και documentation addresses. **Monitoring:** Συγκρίνετε signed lab-router decisions με proxy arrivals· μην κάνετε probe σε production transit providers για να διαπιστώσετε αν εντόπισαν signaling.

## Content-addressed gateway or cached peer retrieval

**Mechanics:** HTTP gateway ανακτά IPFS content identifier (CID), πιθανώς από cache ή peers, και επιστρέφει verifiable content στον client. Ο original publisher μπορεί να βλέπει gateway ή άλλους peers αντί για τον final reader· ο gateway βλέπει reader IP και requested CID. Native peer-to-peer retrieval εκθέτει τον client σε peers και DHT/routing participants.<sup>[[24]](#references)</sup>

**Pros:** Publisher και reader μπορούν να διαχωριστούν μέσω caches· immutable content είναι hash-verifiable· replicated data επιβιώνει από έναν host· HTTP clients δεν απαιτούν native peer stack.

**Cons:** Public CIDs και gateway logs αποκαλύπτουν interests· first retrieval timing μπορεί να συσχετίσει publisher και reader· malicious web content και path-style same-origin hazards· public gateways είναι best-effort και απαγορεύουν abuse.

**Procedure:** (1) δημοσιεύστε harmless test file σε owned private IPFS swarm ή owned gateway· (2) καταγράψτε CID· (3) ανακτήστε το μέσω separate owned HTTP gateway με subdomain isolation· (4) επαληθεύστε τα bytes έναντι του CID· (5) επαναλάβετε μετά το caching· (6) συγκρίνετε publisher, peer και gateway logs· (7) κάντε unpin και αφαιρέστε το test content όταν λήξει το retention.

**Detection:** Gateways καταγράφουν source/CID· DHT και peer connections αποκαλύπτουν retrieval· endpoint history και file hashes ταυτοποιούν content. **Capture-resilient OPSEC:** Μην αποθηκεύετε private publishing key σε read-only field client και κρυπτογραφείτε sensitive content πριν από content addressing. **Monitoring:** Alert σε unexpected pinning, peer-set change, CID requests εκτός allowlist ή gateway account notices.

## Private information retrieval service

**Mechanics:** Το Private Information Retrieval (PIR) επιτρέπει σε client να ανακτήσει μία record από database, κρύβοντας κρυπτογραφικά το selected index από τον server υπό stated single- ή multi-server threat model. Προστατεύει query selection για bounded dataset· δεν είναι general web access ή IP anonymity.<sup>[[25]](#references)</sup>

**Pros:** strong application-specific query privacy· measurable leakage model· χρήσιμο για key directories, blocklists ή small public databases· μπορεί να μειώσει την ανάγκη αποκάλυψης exact lookup terms.

**Cons:** computation/bandwidth overhead· ο server μαθαίνει connection time/IP εκτός αν συνδυαστεί με relay· dataset version, response size και application state μπορούν να κάνουν partition users· implementation maturity ποικίλλει.

**Procedure:** (1) αναπτύξτε audited PIR implementation σε synthetic owned database· (2) δημοσιεύστε dataset version και parameters· (3) ανακτήστε αρκετά indices με identical request sizes· (4) επαληθεύστε correctness locally· (5) συγκρίνετε server logs και επιβεβαιώστε ότι το index απουσιάζει· (6) δοκιμάστε malicious/truncated responses και version mismatch· (7) τεκμηριώστε την ακριβή privacy assumption αντί να το αποκαλείτε anonymous browsing.

**Detection:** Networks βλέπουν service use και volume· endpoint telemetry αποκαλύπτει client και final record use· compromised server μπορεί να χειριστεί datasets ή timing. **Capture-resilient OPSEC:** Κρατήστε στον client μόνο public database parameters και bounded cache. **Monitoring:** Επικυρώστε signed dataset roots, fixed request shapes, error-rate changes και server-key rotations.

## Constrained server-side fetcher, preview or rendering service

**Mechanics:** Remote service κάνει fetch ή render URL και επιστρέφει screenshot, metadata ή sanitized content. Ο destination βλέπει fetcher address· η service βλέπει requester, URL και result. Η κατάχρηση link-preview bots, security scanners ή third-party URL fetchers δεν είναι authorized proxy use.

**Pros:** απομονώνει active content από workstation· ο destination λαμβάνει controlled fetcher fingerprint· μπορεί να επιβάλει file type, size, destination και rendering limits· disposable execution environment.

**Cons:** Η service έχει πλήρη γνώση request· account/API/billing records· SSRF και data-exfiltration risk· scripts, authentication και interactive sites μπορεί να μη λειτουργούν· unique URLs συσχετίζουν requester και fetch.

**Procedure:** (1) αναπτύξτε organization-owned fetcher με strict allowlist owned test domains· (2) αποκλείστε private, link-local, metadata και redirect-to-unapproved addresses· (3) περιορίστε methods, redirects, bytes και render time· (4) αφαιρέστε credentials/cookies· (5) υποβάλετε owned URL· (6) συγκρίνετε requester, fetcher και target logs· (7) καταστρέψτε render instance και διατηρήστε central audit σύμφωνα με policy.

**Detection:** Target βλέπει service ASN/fingerprint· provider και controller logs αντιστοιχούν requester με URL· endpoint process/API calls δείχνουν submission. **Capture-resilient OPSEC:** Χρησιμοποιήστε ένα short-lived project token χωρίς arbitrary destination authority. **Monitoring:** Alert σε allowlist denials, redirect violations, fetches χωρίς controller job ID και provider abuse notices.

## Anycast rendezvous pool

**Mechanics:** Πολλά organization-controlled nodes διαφημίζουν ή κάνουν front μία stable service address και το routing επιλέγει κοντινό instance. Το Anycast βελτιώνει availability και αποκρύπτει individual back-end από τον client, αλλά ο operator ελέγχει όλα τα instances και η service address είναι stable.<sup>[[26]](#references)</sup>

**Pros:** resilient regional ingress· χωρίς field reconfiguration όταν αποτυγχάνει instance· DDoS/load distribution· central policy μπορεί να μετακινεί sessions μεταξύ known nodes.

**Cons:** BGP/CDN και provider records ταυτοποιούν την organization· path changes μπορούν να διακόψουν stateful sessions· monitoring διαφέρει ανά client location· μία stable address αποκλείεται ή ομαδοποιείται εύκολα λόγω reputation.

**Procedure:** Χρησιμοποιήστε provider-supported organization project ή isolated routing lab: (1) αναπτύξτε δύο identical authenticated health endpoints· (2) εκθέστε μία documented service address· (3) κρατήστε session state στον broker αντί για edge· (4) αποσύρετε ένα node και επαληθεύστε reconnection· (5) δοκιμάστε certificate, policy και log consistency· (6) δημιουργήστε alert σε unauthorized origin/region· (7) αφαιρέστε advertisements και credentials στο closeout.

**Detection:** BGP/RPKI/history, provider tenancy, certificates και identical service behavior ταυτοποιούν το pool. **Capture-resilient OPSEC:** Edge κρατά μόνο regional service identity και κανένα operator ή fleet-enrollment key. **Monitoring:** Probe κάθε region από authorized monitors, συγκρίνετε route origin και configuration digest και αντιμετωπίστε unexpected origin ως incident.

## QUIC migration and Multipath TCP continuity

**Mechanics:** QUIC connection IDs μπορούν να διατηρούν client session ενεργό σε NAT rebinding ή address changes· το Multipath TCP μπορεί να μεταφέρει ένα reliable byte stream μέσω πολλών subflows. Βελτιώνουν continuity σε Wi-Fi/cellular transitions, αλλά εκθέτουν old και new paths στον common peer και μπορεί να διευκολύνουν cross-path correlation.<sup>[[27]](#references)</sup>

**Pros:** ταχύτερο recovery κατά uplink changes· application session δεν χρειάζεται restart· το MPTCP συνδυάζει resilience και throughput· χρήσιμο για approved field nodes.

**Cons:** όχι anonymity· peer βλέπει migration/subflows· connection identifiers και simultaneous traffic συνδέουν paths· middlebox/carrier support διαφέρει· duplicated provider records αυξάνουν exposure.

**Procedure:** (1) ενεργοποιήστε supported transport μόνο μεταξύ owned field client και rendezvous· (2) κάντε authenticate την εφαρμογή ανεξάρτητα από IP· (3) ξεκινήστε bounded transfer σε approved Wi-Fi· (4) αλλάξτε σε organization cellular· (5) επιβεβαιώστε path validation, data integrity και απουσία clear/direct fallback· (6) δοκιμάστε idle timeout και return· (7) διατηρήστε broker records κάθε path transition.

**Detection:** Ο peer παρατηρεί άμεσα address migration ή MPTCP subflows· οι access providers βλέπουν το δικό τους μέρος· connection IDs, TLS identity και timing συνδέουν και τα δύο. **Capture-resilient OPSEC:** Αποθηκεύστε μόνο device-scoped session material και λήξτε γρήγορα το resumable state. **Monitoring:** Alert σε impossible path changes, simultaneous unapproved networks, migration storms και resumption μετά από quarantine.

## Managed CI/CD or ephemeral automation runner egress

**Mechanics:** Organization-owned workflow εκτελεί bounded network check σε hosted runner. Ο destination βλέπει cloud runner address, ενώ η platform διατηρεί repository, actor, workflow, token, log και billing attribution. Αυτό είναι remote execution με accountable egress, όχι anonymity από τον provider.<sup>[[28]](#references)</sup>

**Pros:** disposable clean environment· reproducible job definition· no inbound connection· χρήσιμο για geographically distributed availability checks· ισχυρό controller audit.

**Cons:** Platform και organization ταυτοποιούν τον initiator· broad workflow tokens και untrusted pull requests είναι επικίνδυνα· shared IP reputation· logs/artifacts μπορούν να διατηρούν secrets ή target data.

**Procedure:** (1) δημιουργήστε private organization repository και environment για το assessment· (2) επιτρέψτε μόνο manually approved, fixed benign jobs προς owned endpoints· (3) χρησιμοποιήστε minimal read-only workflow permissions και production secrets· (4) εκτελέστε το check· (5) συγκρίνετε workflow, provider και target records· (6) επαληθεύστε ότι τα artifacts δεν περιέχουν credentials· (7) διαγράψτε environment token και διατηρήστε required audit.

**Detection:** Provider audit και workflow logs παρέχουν direct attribution· targets εντοπίζουν runner ASNs/ranges και stable request grammar. **Capture-resilient OPSEC:** Ποτέ μην τοποθετείτε field-device, signing, wallet ή cloud-administrator secrets σε runner variables. **Monitoring:** Απαιτήστε branch/environment approval και alert σε workflow edits, fork execution, secret reads και unexpected destinations.

## Non-IP local first hop to an owned gateway

**Mechanics:** Bluetooth mesh, Wi-Fi Aware/Direct, low-power radio ή serial/optical link μεταφέρει bounded messages από nearby sensor σε owner-approved Internet gateway. Το field device δεν έχει Internet route· ο gateway είναι το μοναδικό egress. Τα radio range και protocol limits το καθιστούν telemetry/store-and-forward design, όχι interactive anonymous Internet.

**Pros:** αφαιρεί Internet stack και credentials από το μικρότερο field device· χαμηλή κατανάλωση· gateway centralizes policy· μπορεί να γεφυρώσει προσωρινά dead zones.

**Cons:** RF/physical discovery, pairing και device identifiers· μικρό bandwidth και range· gateway εξακολουθεί να συνδέει όλα τα messages· spectrum και encryption restrictions διαφέρουν· capture μπορεί να αποκαλύψει queued data.

**Procedure:** (1) λάβετε site και spectrum approval· (2) κάντε pair ένα owned sensor με ένα owned gateway μέσω unique keys· (3) ορίστε signed fixed-size message types, TTL και rate· (4) δώστε στο sensor no default IP route· (5) επιτρέψτε στον gateway να προωθεί μόνο σε owned collector· (6) δοκιμάστε replay, range loss και gateway outage· (7) κάντε inventory και retrieve και τις δύο συσκευές.

**Detection:** RF survey, pairing database, physical inspection και gateway process/flow logs αποκαλύπτουν τη διαδρομή. **Capture-resilient OPSEC:** Το sensor κρατά μόνο pairwise key και bounded encrypted queue, ποτέ operator, Wi-Fi, cellular ή controller credentials. **Monitoring:** Alert σε new peers, sequence rollback, key failure, unusual RF rate και messages που φτάνουν μέσω unregistered gateway.

## Capture/compromise exposure matrix

Ο πίνακας εφαρμόζει capture-resilience check σε κάθε παραπάνω οικογένεια. “Minimize” σημαίνει μείωση secrets και blast radius σε authorized assets· ποτέ δεν σημαίνει διαγραφή evidence ή απόκρυψη από investigation.

| Οικογένεια τεχνικής | Τι μπορεί να αποκαλύψει captured endpoint/relay | Ελάχιστος authorized control |
|---|---|---|
| NAT/CGNAT, public Wi-Fi, travel router | γνωστά networks, DHCP/portal history, MACs, tunnel peer | separate organization device· private MAC όπου υποστηρίζεται· no personal accounts· controller inventory |
| VPN, VPS, HTTP/SOCKS/SSH, multi-hop | provider/hostnames, keys, routes, logs και adjacent hop | one identity ανά engagement· short TTL· narrow routes· broker-side revocation· no master keys |
| OHTTP/ODoH, MASQUE, split-provider relay | relay/gateway configuration, application identifiers και cached requests | minimize payload identifiers· pin approved config· bounded cache· strict no-direct fallback |
| Tor, bridge, onion service, I2P, mixnet, GNUnet | installed software, bridge/onion material, local state και peer history | standard client· separate service keys· encrypted minimal state· rotate compromised service identity |
| Remote browser/VDI/jump host | workspace token, clipboard/files και remote tenant | phishing-resistant MFA at gateway· disabled transfer channels· rapid session revocation |
| Cellular, satellite, private APN | SIM/eSIM, IMEI/terminal identity, provider και approximate location | organization contract· no personal co-location· narrow APN/overlay policy· provider suspension runbook |
| Residential/cooperative proxy, ORB lab | agent identity, controller/next hop, cached traffic | only consented/owned nodes· signed agent· per-node credential· controller-held participant mapping |
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

Κανένα client-side test δεν αποδεικνύει ότι investigator ή defender παρακολουθεί. Παρακολουθείτε αλλαγές σε systems που ανήκουν στο engagement, επιβεβαιώστε τις με controller/client και σταματήστε αντί να κάνετε probing στους observers. Οι παρακάτω γραμμές καλύπτουν κάθε παραπάνω τεχνική· συνδυάστε τις με τα [field-node alert states and response runbook](capture-resilient-authorized-field-nodes.md#monitoring-for-discovery-loss-or-compromise).

| Καλυπτόμενες τεχνικές | Safe controller-side signals | Quarantine/stop condition |
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

1. Ονομάστε τον observer που θέλετε να αφαιρέσετε και τα δεδομένα που θέλετε να κρύψετε.
2. Επιλέξτε την απλούστερη οικογένεια που τον αφαιρεί.
3. Σχεδιάστε τους observers των source, entry, traversal, exit, DNS, account και payment.
4. Χρησιμοποιήστε separate endpoint/application identity.
5. Επαληθεύστε IPv4, IPv6, DNS, WebRTC/application bypass και destination view.
6. Σπάστε κάθε hop και επιβεβαιώστε ότι η αποτυχία είναι closed.
7. Συγκρίνετε logs σε κάθε component που ελέγχετε.
8. Καταγράψτε residual timing, provider, endpoint και physical links.

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
{{#include ../banners/hacktricks-training.md}}
