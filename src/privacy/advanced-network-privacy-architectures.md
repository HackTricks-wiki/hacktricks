# Προηγμένες αρχιτεκτονικές ιδιωτικότητας δικτύου

Η πολυπλοκότητα είναι χρήσιμη μόνο όταν εξαλείφει έναν συγκεκριμένο παρατηρητή ή τρόπο αστοχίας. Ένα μοναδικό tunnel stack, ένα custom packet shape, ένας σπάνιος user agent ή μια υποδομή που αλλάζει συχνά μπορεί να δημιουργήσει ισχυρότερο fingerprint από μια τυπική διαμόρφωση που χρησιμοποιείται από χιλιάδες άτομα.

Ο [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) παρέχει το κοινό σχήμα `Pros`/`Cons`/`Procedure`/`Detection`. Αυτή η σελίδα επεκτείνει τις πιο σύνθετες αρχιτεκτονικές και τα trust boundaries.

Ο προηγμένος στόχος είναι επομένως ο **διαχωρισμός της γνώσης**: κανένα συνηθισμένο component δεν πρέπει να κατέχει ταυτόχρονα την ταυτότητα του χρήστη, τον προορισμό, το plaintext και το μακροπρόθεσμο ιστορικό δραστηριότητας. Αυτό δεν αποτελεί αορατότητα, ενώ η συνεννόηση μεταξύ μερών, η νομική διαδικασία, η παραβίαση του endpoint ή η end-to-end συσχέτιση traffic μπορούν ακόμη να ανακατασκευάσουν τη διαδρομή.

## Επιλογή αρχιτεκτονικής

| Pattern | Ιδιότητα που αποκτάται | Νέο trust/failure | Κατάλληλη χρήση |
|---|---|---|---|
| Standard Tor Browser | Κοινό browser fingerprint και διαδρομή μέσω πολλαπλών relay | Η χαμηλή latency επιτρέπει τη συσχέτιση traffic | Γενική ανώνυμη περιήγηση στον ιστό |
| Tor bridge + pluggable transport | Καθιστά δυσκολότερο το άμεσο blocking/classification του Tor | Το bridge/transport μπορεί ακόμη να ανιχνευθεί· το bridge μαθαίνει την πηγή | Censored networks |
| Onion service | Αποκρύπτει το service IP· αποφεύγει το exit· πιστοποιεί την onion identity | Το onion key και το server endpoint γίνονται κρίσιμα assets | Private publishing, intake ή administration |
| Independent ingress + egress relays | Κανένα μεμονωμένο relay συνήθως δεν βλέπει την πηγή και τον προορισμό | Οι operators μπορεί να συνεργαστούν· το timing διασχίζει και τα δύο | Εφαρμογές υψηλής απόδοσης με υποστήριξη |
| Oblivious HTTP | Διαχωρίζει το source IP από το κρυπτογραφημένο stateless HTTP request | Απαιτεί υποστήριξη από την εφαρμογή, το relay και το gateway | Telemetry, queries, submissions χωρίς session state |
| VPN-only workload namespace | Απουσία route προς clear-network που επιβάλλεται από τον kernel | Το VPN εξακολουθεί να βλέπει και τα δύο άκρα· το host/root παραμένει trusted | Authorized engagement tools και fixed egress |
| Disposable remote browser | Ο προορισμός απομονώνεται από το τοπικό browser/endpoint | Ο Workspace provider βλέπει τη δραστηριότητα και την ταυτότητα σύνδεσης | Untrusted sites/files και controlled research |
| I2P internal service | Ξεχωριστά inbound/outbound overlay tunnels· χωρίς official exits | Μικρότερο/διαφορετικό ecosystem· συμπεριφορά peer μακράς διάρκειας | Υπηρεσίες native στο I2P, όχι αντικατάσταση του ordinary web |
| Mixnet/asynchronous delivery | Η καθυστέρηση, το batching και το cover traffic αντιστέκονται στο timing analysis | Υψηλή latency, περιορισμένες εφαρμογές και μικρότερη ωριμότητα | Messages/tasks που δεν χρειάζονται interaction |

## Split-knowledge relays

Ένα μοτίβο relay με δύο operators μπορεί να ξεπεράσει ένα μεμονωμένο VPN για μια συγκεκριμένη εφαρμογή:
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
Το Apple Private Relay αποτελεί deployed παράδειγμα: η Apple λειτουργεί το ingress, ενώ ένας διαφορετικός πάροχος περιεχομένου λειτουργεί το egress, επομένως κανένα από τα δύο μέρη δεν βλέπει συνήθως ταυτόχρονα τόσο την IP του client όσο και τον προορισμό περιήγησης.<sup>[[1]](#references)</sup> Πρόκειται για product-specific υπηρεσία privacy του Safari/DNS, όχι για anonymity network όλων των συσκευών, και διατηρεί σκόπιμα μια γενική περιοχή.

Το Oblivious HTTP (OHTTP) τυποποιεί ένα πιο περιορισμένο application pattern. Το relay βλέπει τον client και την κρυπτογραφημένη κίνηση προς το gateway· το gateway αποκρυπτογραφεί το HTTP message, αλλά βλέπει το relay και όχι τον client. Το RFC 9458 προειδοποιεί ότι απαιτεί υποστήριξη από relay/gateway που συνεργάζονται, είναι καταλληλότερο για requests χωρίς cookies/authentication/session state και δεν περιλαμβάνει το traffic analysis στις εγγυήσεις του.<sup>[[2]](#references)</sup>

### Λίστα ελέγχου σχεδιασμού

1. Καθόρισε τα ακριβή application messages που πρέπει να προστατευτούν· μην κάνεις σιωπηρά proxy αυθαίρετα authenticated web sessions.
2. Χρησιμοποίησε οργανισμούς ingress και egress που λειτουργούν ανεξάρτητα, με ξεχωριστή διαχείριση, credentials, logging και νομικό έλεγχο όπου είναι δυνατόν.
3. Κρυπτογράφησε το application request προς το gateway, ώστε το ingress να μην μπορεί να το διαβάσει.
4. Αφαίρεσε client-derived forwarding headers, TLS identifiers και σταθερά per-user tokens στο κατάλληλο layer.
5. Απόφυγε μοναδικά keys, cookies ή payload fields που επιτρέπουν στο gateway να επανασυνδέσει requests παρά τον διαχωρισμό μεταφοράς.
6. Κάνε aggregate, minimize και expire τα logs και στις δύο πλευρές· τεκμηρίωσε τον κίνδυνο collusion και compelled disclosure.
7. Κάνε padding ή batching μόνο σύμφωνα με reviewed protocol. Το homemade traffic shaping μπορεί να δημιουργήσει μοναδικό signature χωρίς να σταματήσει το correlation.
8. Κάνε test με controlled canary requests και σύγκρινε τι καταγράφουν ο client, το ingress, το gateway και ο target.

Για συνηθισμένο interactive browsing, χρησιμοποίησε Tor Browser αντί να επινοήσεις ένα private OHTTP proxy. Το OHTTP προστατεύει ένα υποστηριζόμενο application transaction, όχι ολόκληρη την ταυτότητα του browser.

## Επιβολή του route ανά workload

Ένα kill switch που βασίζεται μόνο σε mutable host routes μπορεί να αποτύχει κατά την ανανέωση DHCP, την αναστολή/επαναφορά λειτουργίας, τις αλλαγές IPv6 ή την κατάρρευση tunnel. Ένα ισχυρότερο Linux pattern δίνει σε ένα container ή network namespace μόνο ένα loopback interface και ένα tunnel interface. Το WireGuard τεκμηριώνει ότι ένα interface μπορεί να δημιουργηθεί σε physical namespace, να μετακινηθεί σε workload namespace και να διατηρήσει το encrypted UDP socket του στο αρχικό namespace.<sup>[[3]](#references)</sup>

### Pattern ανάπτυξης

1. Δημιούργησε πρώτα αυτή τη ρύθμιση σε disposable/local-console host· λάθη στα namespaces μπορούν να αφαιρέσουν την remote πρόσβαση.
2. Τοποθέτησε το physical Ethernet/Wi-Fi interface και το DHCP/supplicant σε ένα **physical** namespace.
3. Δημιούργησε εκεί το WireGuard interface, ώστε το encrypted transport socket του να έχει πρόσβαση στο physical network.
4. Μετακίνησε μόνο το WireGuard interface στο **workload** namespace και κάν’ το sole default route.
5. Δώσε στο workload έναν namespace-specific resolver που είναι προσβάσιμος μόνο μέσω του tunnel. Υπολόγισε ρητά το IPv6.
6. Εκτέλεσε το browser/tool container σε αυτό το namespace χωρίς host networking, privileged capability, shared browser directory ή personal credential agent.
7. Σταμάτησε το tunnel και επαλήθευσε ότι το workload δεν μπορεί να κάνει resolve ή connect σε controlled IPv4 ή IPv6 endpoint.
8. Κάνε test endpoint roaming, ανανέωση DHCP, suspend/resume και captive-portal handling εκτός του workload namespace.
9. Κατέγραψε το namespace/tunnel configuration hash και την approved egress address για accountability του engagement.

Αυτό παρέχει **route enforcement**, όχι anonymity από το VPN ή το engagement bastion. Ένα compromised host/root μπορεί να επιθεωρήσει ή να αλλάξει namespaces.

## Tor bridges και pluggable transports

Τα bridges είναι μη δημόσια Tor entry relays. Τα pluggable transports τροποποιούν την κίνηση του first hop, ώστε το απλό blocking ή protocol classification να είναι δυσκολότερο. Δεν προσθέτουν anonymous relay layers μετά το entry και δεν αντιμετωπίζουν έναν observer που είναι ικανός για ευρύτερο timing correlation.

| Transport | Προσέγγιση first hop | Πρακτικός συμβιβασμός |
|---|---|---|
| **obfs4** | Κάνει την κίνηση να φαίνεται τυχαία και αντιστέκεται σε active probing | Μια γνωστή bridge address μπορεί ακόμη να αποκλειστεί |
| **Snowflake** | Χρησιμοποιεί βραχύβια εθελοντικά WebRTC proxies για να φτάσει σε bridge | Η απόδοση μεταβάλλεται· υπάρχουν broker/STUN/WebRTC patterns |
| **WebTunnel** | Μεταφέρει bridge traffic σε HTTPS-like WebSocket tunnel | Εξαρτάται από ένα προσβάσιμο web front και μπορεί ακόμη να ταξινομηθεί |

Το Tor Project περιγράφει τα Snowflake και WebTunnel ως transports για censorship circumvention, όχι ως τέλεια indistinguishability.<sup>[[4]](#references)</sup>

### Ασφαλής ροή εργασίας

1. Ξεκίνα με direct connection του Tor Browser. Πρόσθεσε bridge μόνο όταν το blocking ή η ορατότητα στο local observer model το δικαιολογεί.
2. Χρησιμοποίησε built-in transports ή bridge lines που αποκτήθηκαν μέσω καναλιών του Tor Project. Μην κατεβάζεις τυχαία transport binaries ή public bridge lists από forums.
3. Δοκίμασε την απλούστερη υποστηριζόμενη επιλογή που συνδέεται αξιόπιστα· κατέγραψε γιατί επιλέχθηκε.
4. Κράτησε τον Tor Browser κατά τα άλλα standard. Ένα bridge δεν καθιστά ασφαλή τα custom extensions, τα account logins ή τις ασυνήθιστες ρυθμίσεις browser.
5. Κάνε test το reconnect και την ορθότητα του clock. Μην εναλλάσσεις επανειλημμένα transports με τρόπο που στέλνει distinctive sequence στον ίδιο local observer.
6. Επανεκτίμησε την κατάσταση αν αλλάξει ο censor ή η network policy· η χρήση μπορεί να είναι ευαίσθητη ή restricted σε ορισμένες τοποθεσίες.

## Onion services ως private rendezvous

Ένα onion service δημιουργεί outbound Tor circuits προς introduction points και rendezvous relays, επομένως δεν χρειάζεται public inbound port και δεν αποκαλύπτει την IP του server μέσω του onion protocol. Η κίνηση client-to-service παραμένει μέσα στο Tor και η onion address authenticates το service key.<sup>[[5]](#references)</sup>

Για ένα lawful intake portal, private repository, administrative interface ή engagement evidence drop:

1. Εκτέλεσε την εφαρμογή σε dedicated host/VM και κάνε bind σε loopback ή isolated Unix socket.
2. Εγκατέστησε το Tor από το official repository και ακολούθησε το official v3 onion-service setup· μην χρησιμοποιείς ποτέ obsolete v2 instructions.
3. Προστάτευσε το private key του onion service όπως ένα TLS/signing key. Κράτησε backup μόνο αν απαιτείται stable identity.
4. Πρόσθεσε onion-service client authorization για closed group και παρέδωσε τα credentials μέσω independently authenticated channel.<sup>[[6]](#references)</sup>
5. Εμπόδισε το origin να κάνει fetch third-party fonts, analytics, updates ή webhooks που αποκαλύπτουν τη public IP ή το operator account.
6. Πρόσθεσε authentication και authorization και στην εφαρμογή· η κατοχή της onion address δεν αποτελεί access control.
7. Κάνε patch, rate-limit και monitor το service χωρίς να ενσωματώνεις third-party telemetry.
8. Από ξεχωριστό test context, επιβεβαίωσε ότι τα DNS, email, error pages, file metadata και response headers δεν αποκαλύπτουν το origin.
9. Για red-team χρήση, κατέγραψε το service, τον owner, τον σκοπό και τον χρόνο shutdown στο ROE. Μην το χρησιμοποιήσεις για να αποκρύψεις out-of-scope C2.

## Remote browser και disposable workspace

Ένα remote browser μεταφέρει το rendering και το risky content μακριά από το local endpoint και μπορεί να παρέχει engagement-specific cloud egress. Προστατεύει την local συσκευή από ορισμένο content και persistence· δεν καθιστά τον operator anonymous απέναντι στον workspace provider. Το AWS, για παράδειγμα, τεκμηριώνει τη συλλογή portal, identity, policy, preference και session-log data, παρότι το disposable browser instance απορρίπτεται στο τέλος του session.<sup>[[7]](#references)</sup>

Χρησιμοποίησε ένα organization-controlled workspace ανά engagement, περιόρισε downloads/uploads/clipboard, απενεργοποίησε personal identity providers, στείλε το fixed egress του μέσω του approved bastion και κάνε expire το workspace μετά το evidence export. Αντιμετώπισε το provider console, το IdP και τον administrator ως observers.

## I2P και internal overlays

Το I2P δημιουργεί ξεχωριστά unidirectional inbound και outbound tunnels και δεν διαθέτει official network-layer exits· προορίζεται κυρίως για services μέσα στο I2P.<sup>[[8]](#references)</sup> Δεν αποτελεί drop-in ταχύτερο τρόπο για browsing στο public Internet. Τα outproxies εισάγουν trust point, ενώ το official threat model ζητά περισσότερη έρευνα και δεν ισχυρίζεται perfect anonymity.

Χρησιμοποίησε το I2P μόνο όταν και τα δύο άκρα το υποστηρίζουν σκόπιμα, απομόνωσε τον long-lived router του από personal applications και κατανόησε ότι peers/local networks μπορούν να παρατηρούν τη συμμετοχή στο I2P. Μην αυξάνεις τα hop counts ή ρυθμίζεις το peer selection χωρίς evidence: ασυνήθιστες ρυθμίσεις μπορούν να μειώσουν την απόδοση και το anonymity set.

## Operations ανθεκτικά σε correlation

- Προτίμησε common, supported client configuration αντί για unique build.
- Διαχώρισε τις identities στο endpoint· καμία routing topology δεν διορθώνει account, payment, recovery ή content reuse.
- Για non-interactive tasks, προτίμησε reviewed asynchronous protocol/mixnet αντί να προσθέτεις χειροκίνητα sleeps ή fake traffic.
- Απόφυγε να λειτουργείς υποτίθεται ξεχωριστές identities με synchronized pattern από το ίδιο physical context.
- Χρησιμοποίησε one-way export gate: untrusted content εισέρχεται σε disposable renderer· μόνο reviewed, sanitized result εξέρχεται.
- Κράτησε τα clocks σωστά για protocol security, αλλά αφαίρεσε unnecessary precise timestamps από τα published artifacts.
- Ελαχιστοποίησε τη διάρκεια των sessions και το stale infrastructure χωρίς rapid “fast-flux” rotation, η οποία είναι conspicuous και βλάπτει το accountability.

## Techniques που δεν μπορούν να χρησιμοποιούν uninvolved third parties

Αυτές είναι πραγματικές adversary techniques, όχι φανταστικές ή ασήμαντες. Οι μηχανισμοί και η ανίχνευσή τους καλύπτονται στα [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md), [Covert Physical and Wireless Access](covert-physical-wireless-access.md) και [APT case studies](government-and-apt-case-studies.md). Κατά τη διάρκεια ενός authorized exercise, αναπαρήγαγε την observable behavior τους με owned substitutes:

- μοντελοποίησε το residential/mobile exit churn με controlled relay pools, ποτέ με αγορές ασαφούς συναίνεσης·
- μοντελοποίησε open proxies, compromised routers και botnets με owned VMs/routers·
- μοντελοποίησε stolen cloud accounts με designated exercise tenant και synthetic victim identity·
- μοντελοποίησε domain fronting σε owned reverse proxy αντί για unwilling CDN·
- μοντελοποίησε third-party Wi-Fi με δύο isolated APs που ανήκουν στο lab·
- αντιμετώπισε το custom encryption, τα multi-VPN chains και το identifier rotation ως test hypotheses, των οποίων τα flow, account και endpoint artifacts παραμένουν detectable.

Για ένα authorized red team, κάθε προσπάθεια να γίνει η κίνηση λιγότερο recognizable πρέπει να αποτελεί explicit detection objective στο ROE, να διαθέτει attribution map που κρατά ο controller και να περιλαμβάνει stop/deconfliction mechanism.

## Πίνακας επαλήθευσης

| Test | Αναμενόμενο αποτέλεσμα | Το failure σημαίνει |
|---|---|---|
| Tunnel/bridge stopped | Το workload δεν έχει direct IPv4/IPv6/DNS path | Το route enforcement είναι incomplete |
| Target log inspected | Εμφανίζεται μόνο το planned egress/application identity | Header, route ή account leak |
| Ingress log inspected | Υπάρχει source· απουσιάζει clear target/request | Το trust split απέτυχε στο ingress |
| Egress log inspected | Υπάρχει relay/request· απουσιάζει source identity | Το trust split απέτυχε στο egress |
| Onion origin scanned externally | Δεν είναι προσβάσιμο/linked κανένα public origin service | Το origin leaked ή είναι dual-homed |
| Disposable session ended | Το instance state έχει εξαφανιστεί· το approved evidence διατηρείται ξεχωριστά | Το persistence boundary απέτυχε |
| Controller lookup exercised | Η activity αντιστοιχίζεται άμεσα σε engagement/operator | Το red-team accountability απέτυχε |

## References

- [1] [Apple Platform Security — Ασφάλεια του iCloud Private Relay](https://support.apple.com/en-gb/guide/security/secad8ce3233/web)
- [2] [RFC 9458 — Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [3] [WireGuard — Routing και Network Namespaces](https://www.wireguard.com/netns/)
- [4] [Tor Project — Snowflake και pluggable transports](https://snowflake.torproject.org/) and [Arti — Pluggable Transports](https://arti.torproject.org/censorship/pluggable-transports/)
- [5] [Tor Project — Πώς λειτουργούν τα Onion Services](https://community.torproject.org/onion-services/overview/)
- [6] [Tor Project — Προηγμένες ρυθμίσεις Onion Service και client authorization](https://community.torproject.org/onion-services/advanced/)
- [7] [AWS — Κρυπτογράφηση δεδομένων στο Amazon WorkSpaces Secure Browser](https://docs.aws.amazon.com/workspaces-web/latest/adminguide/data-encryption.html)
- [8] [I2P — Threat Model](https://www.i2p.net/en/docs/overview/threat-model/) and [Garlic Routing](https://www.i2p.net/en/docs/overview/garlic-routing/)
