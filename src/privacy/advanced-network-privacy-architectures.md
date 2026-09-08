# Προηγμένες αρχιτεκτονικές απορρήτου δικτύου

{{#include ../banners/hacktricks-training.md}}

Η πολυπλοκότητα είναι χρήσιμη μόνο όταν εξαλείφει έναν συγκεκριμένο παρατηρητή ή τρόπο αποτυχίας. Ένα μοναδικό tunnel stack, ένα custom packet shape, ένας σπάνιος user agent ή υποδομή που αλλάζει συχνά μπορεί να γίνει ισχυρότερο fingerprint από μια τυπική διαμόρφωση που χρησιμοποιούν χιλιάδες άνθρωποι.

Ο [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) παρέχει το κοινό schema `Pros`/`Cons`/`Procedure`/`Detection`. Αυτή η σελίδα επεκτείνει τις πιο σύνθετες αρχιτεκτονικές και τα όρια εμπιστοσύνης.

Ο προηγμένος στόχος είναι επομένως ο **διαχωρισμός της γνώσης**: κανένα συνηθισμένο component δεν θα πρέπει να διαθέτει ταυτόχρονα την ταυτότητα του χρήστη, τον προορισμό, το plaintext και το μακροπρόθεσμο ιστορικό δραστηριότητας. Αυτό δεν αποτελεί αορατότητα, και η συνεννόηση, η νομική διαδικασία, το endpoint compromise ή η end-to-end συσχέτιση traffic μπορούν ακόμη να ανακατασκευάσουν τη διαδρομή.

## Επιλογή αρχιτεκτονικής

| Pattern | Ιδιότητα που αποκτάται | Νέα εμπιστοσύνη/αποτυχία | Κατάλληλη χρήση |
|---|---|---|---|
| Standard Tor Browser | Κοινό browser fingerprint και διαδρομή μέσω πολλαπλών relay | Το χαμηλό latency επιτρέπει τη συσχέτιση traffic | Γενική anonymous περιήγηση στο web |
| Tor bridge + pluggable transport | Καθιστά δυσκολότερο το άμεσο blocking/classification του Tor | Το bridge/transport μπορεί ακόμη να ανιχνευθεί· το bridge μαθαίνει την πηγή | Networks με censorship |
| Onion service | Κρύβει το service IP· αποφεύγει το exit· authenticates την onion identity | Το onion key και το server endpoint γίνονται critical assets | Private publishing, intake ή administration |
| Independent ingress + egress relays | Κανένα relay συνήθως δεν βλέπει ταυτόχρονα την πηγή και τον προορισμό | Οι operators μπορεί να συνεργαστούν· το timing περνά και από τα δύο | High-performance υποστηριζόμενες εφαρμογές |
| Oblivious HTTP | Διαχωρίζει το source IP από το encrypted stateless HTTP request | Απαιτεί υποστήριξη από την εφαρμογή, το relay και το gateway | Telemetry, queries, submissions χωρίς session state |
| VPN-only workload namespace | Kernel-enforced απουσία route προς clear-network | Το VPN εξακολουθεί να βλέπει και τα δύο άκρα· το host/root παραμένει trusted | Authorized engagement tools και fixed egress |
| Disposable remote browser | Ο προορισμός απομονώνεται από το local browser/endpoint | Ο workspace provider βλέπει τη δραστηριότητα και την login identity | Untrusted sites/files και controlled research |
| I2P internal service | Ξεχωριστά inbound/outbound overlay tunnels· χωρίς official exits | Μικρότερο/διαφορετικό οικοσύστημα· συμπεριφορά peer μακράς διάρκειας | Services native στο I2P, όχι αντικατάσταση του συνηθισμένου web |
| Mixnet/asynchronous delivery | Delay, batching και cover traffic αντιστέκονται στην timing analysis | Υψηλό latency, περιορισμένες εφαρμογές και μικρότερη maturity | Messages/tasks που δεν χρειάζονται interaction |

## Relays με διαχωρισμένη γνώση

Ένα relay pattern με δύο operators μπορεί να αποδώσει καλύτερα από ένα single VPN για μια συγκεκριμένη εφαρμογή:
```text
client identity/IP
|
ingress relay -- sees client, not clear request/destination detail
|
encrypted request
|
egress gateway -- sees request/destination, not client IP
|
target service
```
Το Apple Private Relay αποτελεί υλοποιημένο παράδειγμα: η Apple διαχειρίζεται το ingress, ενώ ένας διαφορετικός πάροχος περιεχομένου διαχειρίζεται το egress, επομένως κανένα από τα δύο μέρη δεν βλέπει συνήθως τόσο την IP του client όσο και τον προορισμό περιήγησης.<sup>[[1]](#references)</sup> Πρόκειται για product-specific υπηρεσία privacy του Safari/DNS, όχι για anonymity network όλων των συσκευών, και διατηρεί σκόπιμα μια coarse region.

Το Oblivious HTTP (OHTTP) τυποποιεί ένα πιο περιορισμένο application pattern. Το relay βλέπει τον client και την κρυπτογραφημένη κίνηση προς το gateway· το gateway αποκρυπτογραφεί το HTTP message, αλλά βλέπει το relay και όχι τον client. Το RFC 9458 προειδοποιεί ότι απαιτεί πρόθυμη υποστήριξη από relay/gateway, είναι καταλληλότερο για requests χωρίς cookies/authentication/session state και εξαιρεί το traffic analysis από τις εγγυήσεις του.<sup>[[2]](#references)</sup>

### Checklist σχεδιασμού

1. Καθορίστε τα ακριβή application messages που πρέπει να προστατευτούν· μην κάνετε σιωπηρά proxy αυθαίρετων authenticated web sessions.
2. Χρησιμοποιήστε οργανισμούς ingress και egress που λειτουργούν ανεξάρτητα, με ξεχωριστή διαχείριση, credentials, logging και νομικό έλεγχο όπου είναι δυνατό.
3. Κρυπτογραφήστε το application request προς το gateway, ώστε το ingress να μην μπορεί να το διαβάσει.
4. Αφαιρέστε client-derived forwarding headers, TLS identifiers και σταθερά per-user tokens στο κατάλληλο layer.
5. Αποφύγετε unique keys, cookies ή payload fields που επιτρέπουν στο gateway να επανασυνδέει requests παρά τον διαχωρισμό μεταφοράς.
6. Κάντε aggregate, minimize και expire τα logs και στις δύο πλευρές· τεκμηριώστε τον κίνδυνο collusion και compelled disclosure.
7. Κάντε padding ή batching μόνο σύμφωνα με reviewed protocol. Το homemade traffic shaping μπορεί να δημιουργήσει unique signature χωρίς να σταματά το correlation.
8. Κάντε test με controlled canary requests και συγκρίνετε τι καταγράφουν ο client, το ingress, το gateway και το target.

Για ordinary interactive browsing, χρησιμοποιήστε Tor Browser αντί να επινοήσετε ένα private OHTTP proxy. Το OHTTP προστατεύει ένα υποστηριζόμενο application transaction, όχι μια πλήρη browser identity.

## Επιβολή του route ανά workload

Ένα kill switch που βασίζεται μόνο σε mutable host routes μπορεί να αποτύχει κατά την ανανέωση DHCP, το sleep/wake, τις αλλαγές IPv6 ή ένα tunnel crash. Ένα ισχυρότερο Linux pattern δίνει σε ένα container ή network namespace μόνο ένα loopback interface και ένα tunnel interface. Το WireGuard τεκμηριώνει ότι ένα interface μπορεί να δημιουργηθεί σε physical namespace, να μετακινηθεί σε workload namespace και να διατηρήσει το encrypted UDP socket του στο αρχικό namespace.<sup>[[3]](#references)</sup>

### Deployment pattern

1. Δημιουργήστε το αρχικά σε disposable/local-console host· λάθη στα namespaces μπορούν να αφαιρέσουν την remote access.
2. Τοποθετήστε το physical Ethernet/Wi-Fi interface και τα DHCP/supplicant σε ένα **physical** namespace.
3. Δημιουργήστε εκεί το WireGuard interface, ώστε το encrypted transport socket του να έχει πρόσβαση στο physical network.
4. Μετακινήστε μόνο το WireGuard interface στο **workload** namespace και ορίστε το ως τη μοναδική default route.
5. Δώστε στο workload έναν namespace-specific resolver που είναι προσβάσιμος μόνο μέσω του tunnel. Αντιμετωπίστε ρητά το IPv6.
6. Εκτελέστε το browser/tool container σε αυτό το namespace χωρίς host networking, privileged capability, shared browser directory ή personal credential agent.
7. Σταματήστε το tunnel και επαληθεύστε ότι το workload δεν μπορεί να κάνει resolve ή connect σε controlled IPv4 ή IPv6 endpoint.
8. Κάντε test τα endpoint roaming, DHCP renewal, suspend/resume και captive-portal handling εκτός του workload namespace.
9. Καταγράψτε το namespace/tunnel configuration hash και την approved egress address για accountability του engagement.

Αυτό παρέχει **route enforcement**, όχι anonymity από το VPN ή το engagement bastion. Ένα compromised host/root μπορεί να επιθεωρήσει ή να αλλάξει namespaces.

## Tor bridges και pluggable transports

Τα bridges είναι non-public Tor entry relays. Τα pluggable transports τροποποιούν την κίνηση του first hop, ώστε το απλό blocking ή protocol classification να γίνεται δυσκολότερο. Δεν προσθέτουν anonymous relay layers μετά την είσοδο και δεν νικούν έναν observer που μπορεί να κάνει ευρύτερο timing correlation.

| Transport | First-hop προσέγγιση | Πρακτικό tradeoff |
|---|---|---|
| **obfs4** | Κάνει την κίνηση να φαίνεται τυχαία και αντιστέκεται σε active probing | Μια γνωστή bridge address μπορεί ακόμη να γίνει block |
| **Snowflake** | Χρησιμοποιεί βραχύβια volunteer WebRTC proxies για να φτάσει σε bridge | Η απόδοση μεταβάλλεται· υπάρχουν broker/STUN/WebRTC patterns |
| **WebTunnel** | Μεταφέρει bridge traffic σε HTTPS-like WebSocket tunnel | Εξαρτάται από ένα προσβάσιμο web front και μπορεί ακόμη να ταξινομηθεί |

Το Tor Project περιγράφει τα Snowflake και WebTunnel ως censorship-circumvention transports, όχι ως τέλεια indistinguishability.<sup>[[4]](#references)</sup>

### Safe workflow

1. Ξεκινήστε με direct connection του Tor Browser. Προσθέστε bridge μόνο όταν το blocking ή η visibility στο local observer model το δικαιολογεί.
2. Χρησιμοποιήστε built-in transports ή bridge lines που αποκτήθηκαν μέσω καναλιών του Tor Project. Μην κατεβάζετε τυχαία transport binaries ή public bridge lists από forums.
3. Δοκιμάστε την λιγότερο σύνθετη υποστηριζόμενη επιλογή που συνδέεται αξιόπιστα· καταγράψτε γιατί επιλέχθηκε.
4. Διατηρήστε το Tor Browser κατά τα άλλα standard. Ένα bridge δεν καθιστά ασφαλή τα custom extensions, τα account logins ή τις unusual browser settings.
5. Κάντε test το reconnect και την ορθότητα του clock. Μην εναλλάσσετε επανειλημμένα transports με τρόπο που στέλνει distinctive sequence στον ίδιο local observer.
6. Επανεκτιμήστε την κατάσταση αν αλλάξει ο censor ή η network policy· η χρήση μπορεί να είναι ευαίσθητη ή restricted σε ορισμένες τοποθεσίες.

## Onion services ως private rendezvous

Ένα onion service δημιουργεί outbound Tor circuits προς introduction points και rendezvous relays, επομένως δεν χρειάζεται public inbound port και δεν αποκαλύπτει την IP του server μέσω του onion protocol. Η κίνηση client-to-service παραμένει εντός Tor και η onion address authenticates το service key.<sup>[[5]](#references)</sup>

Για ένα lawful intake portal, private repository, administrative interface ή engagement evidence drop:

1. Εκτελέστε την application σε dedicated host/VM και κάντε bind σε loopback ή isolated Unix socket.
2. Εγκαταστήστε το Tor από το official repository και ακολουθήστε το official v3 onion-service setup· μην χρησιμοποιείτε ποτέ obsolete v2 instructions.
3. Προστατεύστε το onion service private key όπως ένα TLS/signing key. Κάντε backup μόνο αν απαιτείται stable identity.
4. Προσθέστε onion-service client authorization για μια closed group και παραδώστε τα credentials μέσω independently authenticated channel.<sup>[[6]](#references)</sup>
5. Εμποδίστε το origin να κάνει fetch third-party fonts, analytics, updates ή webhooks που αποκαλύπτουν τη public IP ή το operator account.
6. Προσθέστε authentication και authorization και στην application· η κατοχή της onion address δεν αποτελεί access control.
7. Κάντε patch, rate-limit και monitor το service χωρίς να ενσωματώνετε third-party telemetry.
8. Από ξεχωριστό test context, επιβεβαιώστε ότι τα DNS, email, error pages, file metadata και response headers δεν αποκαλύπτουν το origin.
9. Για red-team χρήση, καταγράψτε το service, τον owner, τον σκοπό και τον χρόνο shutdown στο ROE. Μην το χρησιμοποιείτε για να αποκρύψετε out-of-scope C2.

## Remote browser και disposable workspace

Ένα remote browser μεταφέρει το rendering και το risky content μακριά από το local endpoint και μπορεί να παρέχει engagement-specific cloud egress. Προστατεύει την local device από ορισμένο content και persistence· δεν καθιστά τον operator anonymous απέναντι στον workspace provider. Η AWS, για παράδειγμα, τεκμηριώνει τη συλλογή portal, identity, policy, preference και session-log data, παρότι το disposable browser instance απορρίπτεται στο τέλος του session.<sup>[[7]](#references)</sup>

Χρησιμοποιήστε ένα organization-controlled workspace ανά engagement, περιορίστε downloads/uploads/clipboard, απενεργοποιήστε personal identity providers, στείλτε το fixed egress του μέσω του approved bastion και κάντε expire το workspace μετά το evidence export. Αντιμετωπίστε το provider console, το IdP και τον administrator ως observers.

## I2P και internal overlays

Το I2P δημιουργεί ξεχωριστά unidirectional inbound και outbound tunnels και δεν διαθέτει official network-layer exits· προορίζεται κυρίως για services μέσα στο I2P.<sup>[[8]](#references)</sup> Δεν αποτελεί drop-in γρηγορότερο τρόπο για browsing στο public Internet. Τα outproxies εισάγουν trust point και το official threat model ζητά ρητά περισσότερη έρευνα και δεν ισχυρίζεται perfect anonymity.

Χρησιμοποιήστε το I2P μόνο όταν και τα δύο άκρα το υποστηρίζουν σκόπιμα, απομονώστε τον long-lived router του από personal applications και κατανοήστε ότι peers/local networks μπορούν να παρατηρήσουν τη συμμετοχή στο I2P. Μην αυξάνετε τα hop counts ή ρυθμίζετε το peer selection χωρίς evidence: οι unusual settings μπορούν να μειώσουν την απόδοση και το anonymity set.

## Correlation-resistant operations

- Προτιμήστε ένα common, supported client configuration αντί για unique build.
- Διαχωρίστε τις identities στο endpoint· καμία routing topology δεν διορθώνει account, payment, recovery ή content reuse.
- Για non-interactive tasks, προτιμήστε ένα reviewed asynchronous protocol/mixnet αντί να προσθέτετε χειροκίνητα sleeps ή fake traffic.
- Αποφύγετε τη λειτουργία υποτιθέμενα ξεχωριστών identities σε synchronized pattern από το ίδιο physical context.
- Χρησιμοποιήστε one-way export gate: untrusted content εισέρχεται σε disposable renderer· μόνο reviewed, sanitized result εξέρχεται.
- Διατηρήστε σωστά τα clocks για protocol security, αλλά αφαιρέστε τα περιττά precise timestamps από τα published artifacts.
- Ελαχιστοποιήστε τη διάρκεια των sessions και το stale infrastructure χωρίς rapid “fast-flux” rotation, η οποία είναι conspicuous και βλάπτει την accountability.

## Techniques που δεν μπορούν να χρησιμοποιούν uninvolved third parties

Αυτές είναι πραγματικές adversary techniques, όχι φανταστικές ή ασήμαντες. Οι μηχανισμοί και η ανίχνευσή τους καλύπτονται στα [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) και [APT case studies](government-and-apt-case-studies.md). Κατά τη διάρκεια ενός authorized exercise, αναπαράγετε την observable behavior τους με owned substitutes:

- μοντελοποιήστε residential/mobile exit churn με controlled relay pools, ποτέ με markets αβέβαιης συναίνεσης·
- μοντελοποιήστε open proxies, compromised routers και botnets με owned VMs/routers·
- μοντελοποιήστε stolen cloud accounts με designated exercise tenant και synthetic victim identity·
- μοντελοποιήστε domain fronting σε owned reverse proxy αντί για unwilling CDN·
- μοντελοποιήστε third-party Wi-Fi με δύο isolated APs που ανήκουν στο lab·
- αντιμετωπίστε το custom encryption, τα multi-VPN chains και το identifier rotation ως test hypotheses, των οποίων τα flow, account και endpoint artifacts παραμένουν detectable.

Για ένα authorized red team, κάθε προσπάθεια να γίνει η κίνηση λιγότερο recognizable πρέπει να αποτελεί explicit detection objective στο ROE, να διαθέτει controller-held attribution map και να περιλαμβάνει stop/deconfliction mechanism.

## Verification matrix

| Test | Αναμενόμενο αποτέλεσμα | Το failure σημαίνει |
|---|---|---|
| Tunnel/bridge stopped | Το workload δεν έχει direct IPv4/IPv6/DNS path | Το route enforcement είναι incomplete |
| Target log inspected | Εμφανίζεται μόνο το planned egress/application identity | Header, route ή account leak |
| Ingress log inspected | Το source είναι παρόν· το clear target/request απουσιάζει | Το trust split απέτυχε στο ingress |
| Egress log inspected | Το relay/request είναι παρόν· η source identity απουσιάζει | Το trust split απέτυχε στο egress |
| Onion origin scanned externally | Δεν είναι reachable/linked καμία public origin service | Το origin leaked ή είναι dual-homed |
| Disposable session ended | Το instance state έχει εξαφανιστεί· το approved evidence διατηρείται ξεχωριστά | Το persistence boundary απέτυχε |
| Controller lookup exercised | Η activity αντιστοιχίζεται άμεσα σε engagement/operator | Η red-team accountability απέτυχε |

## References

- [1] [Apple Platform Security — Ασφάλεια του iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing και Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake και pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Πώς λειτουργούν τα Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Προηγμένες ρυθμίσεις Onion Service και client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Data encryption στο Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
{{#include ../banners/hacktricks-training.md}}
