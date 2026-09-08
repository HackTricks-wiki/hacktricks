# Υποδομή Offensive και Αποφυγή Απόδοσης

{{#include ../banners/hacktricks-training.md}}

Ένας operator σπάνια εξασφαλίζει ουσιαστική ανωνυμία μέσω ενός μόνο proxy. Οι πραγματικές campaigns δημιουργούν ένα **separation graph**: ο operator φτάνει σε έναν access node, οι traversal nodes αποκρύπτουν αυτόν τον node από το exit, οι redirectors προστατεύουν το πραγματικό C2 και τα disposable names δείχνουν στο public edge.

Χρησιμοποίησε το [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) για μια τυποποιημένη άποψη των πλεονεκτημάτων/μειονεκτημάτων, της ανάπτυξης και του detection κάθε διαδρομής. Αυτή η σελίδα εξετάζει σε μεγαλύτερο βάθος τη σύνθεση adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Η τελευταία διεύθυνση που είδε ένας στόχος αποτελεί επομένως ένδειξη μιας διαδρομής και όχι απόδειξη για το ποιος χειριζόταν το πληκτρολόγιο. Το MITRE αντιστοιχίζει τα βασικά στοιχεία στα Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) και Web Service (T1102).<sup>[[1]](#references)</sup>

## Κατηγορίες υποδομής

| Κατηγορία | Γιατί τη χρησιμοποιεί ένας actor | Διαρκής έκθεση | Καλύτερο pivot για τον defender |
|---|---|---|---|
| Rented VPS/cloud | Γρήγορο, προβλέψιμο, δρομολογήσιμο και εύκολο στην ανακατασκευή | tenant, billing, console, source-login και ιστορικό image | συμβάντα λογαριασμού/control-plane και επαναλαμβανόμενο server fingerprint |
| Commercial VPN/Tor | Μεγάλο κοινόχρηστο σύνολο egress· χωρίς διαχείριση server | ορατότητα provider/guard και end-to-end timing | συμπεριφορά προορισμού, endpoint evidence και συσχέτιση flow |
| Residential/mobile proxy | Consumer ASN και γεωγραφική plausibility | αρχεία broker/customer· συμπεριφορά proxyware ή infected host | impossible travel, proxy protocols και αλλαγή διευθύνσεων ανά session |
| Compromised server/router/IoT | Δανείζεται τη φήμη και τη δικαιοδοσία του victim | implant, management flow και επαναλαμβανόμενος upstream controller | device telemetry και ORB topology, όχι μία exit IP |
| CDN/redirector | Διαχωρίζει το public edge από το back-end C2 | TLS/HTTP grammar, certificate, routing και artifacts λογαριασμού cloud | συσχέτιση edge-to-origin και clustering του request shape |
| Legitimate web service | Ενσωματώνεται σε επιτρεπόμενη GitHub/cloud/social κίνηση | API token, tenant/object identifiers και ασυνήθιστη process lineage | endpoint process μαζί με service/API semantics |
| Physical/cellular/satellite path | Αλλάζει τη φαινομενική φυσική προέλευση | αρχεία RF, carrier, subscriber, device και location | συνδυασμένα radio/physical και network evidence |

## Δίκτυα operational relay box

Ένα **ORB network** είναι ένας managed proxy fleet που χρησιμοποιείται ως ενδιάμεση υπηρεσία. Η Mandiant τα χωρίζει σε provisioned networks από leased servers, non-provisioned networks από compromised routers/IoT και hybrids. Μια ώριμη topology έχει τέσσερις λογικούς ρόλους:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** διατηρεί inventory, credentials, health και routing policy.
2. **Access/relay node:** πραγματοποιεί authentication πελατών ή operators· αποτελεί το σταθερό entry σε ένα μεταβαλλόμενο mesh.
3. **Traversal nodes:** ένα ή περισσότερα leased ή compromised systems μεταδίδουν opaque connections.
4. **Exit/staging node:** παρουσιάζει την τελική source address σε reconnaissance, exploitation ή C2 targets.

Το mesh μπορεί να επιλέγει exits βάσει χώρας, ASN, latency ή availability και να περιστρέφει unhealthy nodes. Πολλαπλές threat groups μπορεί να νοικιάζουν το ίδιο network. Η Mandiant παρατήρησε ότι μια IPv4 address παρέμενε συσχετισμένη με ορισμένα ORBs για μόλις 31 ημέρες· επομένως συνιστά να αντιμετωπίζεται το **network ως εξελισσόμενη οντότητα παρόμοια με actor**, αντί να γίνεται blocking μιας παρωχημένης λίστας IPs.<sup>[[2]](#references)</sup>

### Τι προσφέρει αυτό—και τι διαρρέει

- Ο στόχος βλέπει ένα exit που μπορεί να βρίσκεται γεωγραφικά κοντά και να φαίνεται residential.
- Το exit βλέπει τον στόχο και το προηγούμενο hop, όχι απαραίτητα τον operator.
- Η access service βλέπει τον customer και το route request. Ένα independently managed mesh μπορεί να κρατά τον customer διαχωρισμένο από τα exits, αλλά δημιουργεί ένα ισχυρό counterparty record.
- Επαναλαμβανόμενα ports, handshake order, server banners, certificates, uptime windows και controller relationships μπορούν να αποκαλύψουν τον fleet, ακόμη και όταν οι IPs περιστρέφονται.
- Ένας compromised router συχνά δεν διαθέτει endpoint telemetry, όμως ο ISP του εξακολουθεί να έχει subscriber και flow data· μια κατάσχεση αποκαλύπτει implant/configuration artifacts.

{% hint style="info" %}
Για ένα authorized exercise, αναπαράγετε την topology με organization-owned VMs ή routers και διατηρήστε το attribution map του controller. Μην επιστρατεύετε open proxies ή συσκευές τρίτων. Ο [οδηγός του lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) δημιουργεί την ίδια hop structure που είναι ορατή στον defender, χωρίς να θυματοποιεί έναν intermediary.
{% endhint %}

## Residential και mobile proxy networks

Οι residential proxy services εκχωρούν sessions σε consumer broadband addresses· οι mobile proxies κάνουν egress μέσω carrier NAT pools. Η προμήθεια μπορεί να προέρχεται από ρητά εγγεγραμμένες συσκευές, SDK/proxyware ενσωματωμένο σε consumer applications, resellers ή malware. Αυτές οι προελεύσεις δεν είναι ισοδύναμες: η απουσία informed consent μετατρέπει μια privacy service σε compromised infrastructure.

Τα rotation modes επηρεάζουν την ανίχνευση:

- **per-request rotation** παράγει γρήγορες ασυνέχειες σε IP και ASN/geography, ενώ η identity σε ανώτερο layer παραμένει σταθερή·
- **sticky sessions** διατηρούν ένα exit για λεπτά ή ώρες, μοιάζοντας με ordinary subscriber·
- **backconnect gateways** εκθέτουν ένα broker endpoint στον customer και επιλέγουν exits εσωτερικά·
- **mobile pools** τοποθετούν πολλούς genuine subscribers πίσω από ένα μικρό σύνολο carrier NAT addresses, καθιστώντας ένα IP block δαπανηρό.

Οι defenders θα πρέπει να συσχετίζουν την IP με authenticated session, TLS/client fingerprint, HTTP ordering, device cookie και behavior. Ένα υποτιθέμενα local residential login που ακολουθείται από άλλη χώρα, ενώ όλα τα higher-layer features παραμένουν πανομοιότυπα, αποτελεί ισχυρότερη ένδειξη από τη reputation και μόνο. Αντίθετα, η κοινή χρήση διευθύνσεων και το mobile handoff δημιουργούν legitimate churn, επομένως μην αντιμετωπίζετε ποτέ την ταξινόμηση residential/proxy ως verdict.

## Multi-hop proxy chains

Το MITRE διακρίνει τα external proxies από τα **multi-hop proxies (T1090.003)**. Η σημαντική ιδιότητα δεν είναι ο αριθμός των hops, αλλά ο διαχωρισμός της γνώσης και της διαχείρισης.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Εάν ένα μέρος διαχειρίζεται τα A και B, τα κοινόχρηστα logs ή ο χρονισμός της ροής μπορούν να ανακατασκευάσουν το circuit. Η προσθήκη διαδοχικών εμπορικών VPN από το ίδιο endpoint/account μπορεί να αυξήσει την καθυστέρηση, αφήνοντας ταυτόχρονα κοινά στοιχεία ταυτότητας, πληρωμής και χρονισμού. Το Tor μειώνει αυτό το πρόβλημα με independently selected relays και shared client design, όμως ένα low-latency interactive network δεν μπορεί να εγγυηθεί resistance απέναντι σε observer που μετρά και τα δύο άκρα.

Συνηθισμένες αστοχίες είναι το DNS ή IPv6 bypass, οι εφαρμογές που ανοίγουν τα δικά τους sockets, το management traffic που φτάνει απευθείας στα relays, η συγχρονισμένη δραστηριότητα, τα επαναχρησιμοποιημένα SSH keys και η σύνδεση σε identifying accounts. Η σωστή επαλήθευση είναι ένα failure test: σταματήστε κάθε relay διαδοχικά και δείξτε ότι το workload δεν μπορεί να μεταπέσει σε clear path.

## Επίπεδα Redirector και traffic shaping

Ένας δημόσιος **redirector** δέχεται traffic που αντιστοιχεί σε operation-specific grammar και το προωθεί σε protected team server. Οτιδήποτε άλλο μπορεί να απορρίπτεται ή να εξυπηρετεί innocuous content.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Πολλαπλά επίπεδα περιορίζουν την έκθεση: η εγκατάλειψη ενός public domain δεν χρειάζεται να εκθέσει τον team server. Τα CDN προσθέτουν anycast capacity και ένα αξιόπιστο outer domain, αλλά ο λογαριασμός του CDN και τα edge logs γίνονται σημεία απόδοσης. Τα TLS fingerprints, τα ιστορικά πιστοποιητικών, τα distinctive paths/header order, τα μεγέθη αποκρίσεων, η συμπεριφορά των redirects και οι origin allowlists μπορούν να ομαδοποιήσουν fronts που υποτίθεται ότι είναι άσχετα.

Για detection, καταγράφετε τα πεδία του reverse proxy πριν από το normalization, συγκρίνετε SNI/Host/authority, εξετάζετε σπάνιους συνδυασμούς headers, ομαδοποιείτε response bodies και TLS fingerprints και αναζητάτε επικάλυψη διαμόρφωσης στα cloud/CDN audit logs. Για authorized red teams, αποφεύγετε την αντιγραφή πραγματικού brand ή την τοποθέτηση credential collection πίσω από άσχετο third party.

## Domain fronting και domainless fronting

Με το κλασικό **domain fronting (T1090.004)**, η TLS σύνδεση διαφημίζει ένα επιτρεπόμενο front domain στο SNI, ενώ το κρυπτογραφημένο HTTP `Host` ή HTTP/2 `:authority` ζητά ένα διαφορετικό back-end domain. Ένα συνεργαζόμενο CDN πραγματοποιεί routing με βάση την εσωτερική τιμή. Ένας network observer χωρίς TLS decryption βλέπει το front· το CDN βλέπει και τις δύο τιμές και το origin. Στις domainless παραλλαγές, το SNI μπορεί να είναι κενό, ενώ ένα άλλο routing field επιλέγει τον προορισμό.<sup>[[4]](#references)</sup>

Αυτό δεν είναι μαγική impersonation: λειτουργεί μόνο όταν ο intermediary επιτρέπει σκόπιμα ή κατά λάθος την ασυμφωνία και γνωρίζει πώς να πραγματοποιήσει routing με βάση το εσωτερικό όνομα. Οι major providers έχουν περιορίσει το cross-account fronting. Το Encrypted ClientHello (ECH) αλλάζει όσα μπορεί να δει ένας on-path observer, αλλά δεν διαγράφει τα CDN, endpoint ή application records.

Τα σημεία detection περιλαμβάνουν:

- την ancestry του endpoint process και προορισμούς που δεν αναμένονται για τη συγκεκριμένη εφαρμογή·
- ασυμφωνία SNI και HTTP authority, όπου το TLS inspection είναι νόμιμο και διαθέσιμο·
- CDN logs που εμφανίζουν ένα tenant/front να πραγματοποιεί routing προς άλλο authority/origin·
- ασυνήθιστες long-lived ή περιοδικές sessions προς μια κανονικά interactive υπηρεσία·
- σταθερά encrypted flow sizes και cadence ανάμεσα σε front domains που αλλάζουν.

Το ασφαλές lab προσομοιώνει την ασυμφωνία routing σε owned reverse proxy· δεν καταχράται public CDN.

## Dynamic resolution: DDNS, DGA και fast flux

Η dynamic resolution αποσυνδέει μια λογική υπηρεσία από σταθερή υποδομή:

- **DDNS:** ένας authenticated client ενημερώνει ένα stable name αφού αλλάξει η διεύθυνσή του.
- **DGA:** τόσο το endpoint όσο και ο controller παράγουν candidate domain names από ένα time/key seed· ο operator καταχωρίζει ένα μικρό subset.
- **Fast flux:** ένα name επιστρέφει ένα σύνολο διευθύνσεων compromised/proxy που αλλάζει γρήγορα, συχνά με χαμηλά TTLs.
- **Double flux:** περιστρέφονται τόσο οι service addresses όσο και οι authoritative name-server addresses, αποκρύπτοντας και το control layer.

Το fast flux είναι ένα load-distribution pattern που χρησιμοποιείται adversarially, όχι απλώς «πολλές DNS answers». Ισχυρότερα στοιχεία συνδυάζουν χαμηλό TTL, υψηλό αριθμό unique addresses, μεγάλη διασπορά ASN/γεωγραφίας, σύντομο node lifetime, επαναλαμβανόμενη application behavior και ύποπτο registration history. Τα CDN μοιράζονται νόμιμα αρκετές από αυτές τις ιδιότητες. Το MITRE συνιστά τη συσχέτιση της DNS behavior με το process και τις subsequent connections.<sup>[[5]](#references)</sup>

Ένα DGA μπορεί να εντοπιστεί μέσω lexical entropy, μοτίβων συμφώνων/ψηφίων, bursts NXDOMAIN, synchronized first-seen domains και process context. Τα wordlist DGAs και τα generative models παρακάμπτουν απλούς κανόνες entropy, καθιστώντας σημαντικότερα το fleet-wide temporal clustering και το endpoint lineage.

## Compromised domains και domain shadowing

Ένας actor μπορεί να κάνει hijack έναν registrar/DNS account, να αναλάβει ένα dangling subdomain ή να προσθέσει records κάτω από ένα κατά τα άλλα αξιόπιστο domain. Το **domain shadowing** διατηρεί το legitimate apex, ενώ μεγάλοι αριθμοί attacker-controlled subdomains δείχνουν προς μεταβαλλόμενα delivery ή C2 hosts. Αξιοποιεί την ηλικία και τη φήμη και μπορεί να παρακάμψει το domain-wide blocking.<sup>[[6]](#references)</sup>

Οι defenders χρειάζονται registrar και authoritative-DNS audit logs, MFA, registry/registrar locks, alerts για νέα delegations/API tokens/name servers, certificate-transparency monitoring και inventory των cloud resources που αναφέρονται από το DNS. Ερευνήστε το resolution και το certificate history ενός subdomain ανεξάρτητα από τη φήμη του apex.

## Web services και dead-drop resolvers

Ένας **dead-drop resolver (T1102.001)** αποθηκεύει έναν encoded pointer προς το τρέχον C2 μέσα σε ένα legitimate post, profile, document, repository, cloud object ή blockchain field. Το malware ανακτά το public object, αποκωδικοποιεί ένα domain/IP και επικοινωνεί με το επόμενο stage. Οι bidirectional παραλλαγές ανταλλάσσουν commands ή files μέσω service APIs.<sup>[[7]](#references)</sup>

Αυτό παρέχει resilience και αποκρύπτει το back-end C2 από το static binary analysis. Δημιουργεί όμως επίσης stable object, tenant, repository, API και access-pattern identifiers. Οι defenders πρέπει να συσχετίζουν:

1. το process που επικοινώνησε με την υπηρεσία·
2. το ακριβές API path/object και το response hash·
3. τη decoding ή string-processing activity·
4. τη νέα outbound connection λίγο αργότερα· και
5. την ίδια behavior αλλού στο fleet.

Το blocking ολόκληρων των GitHub, cloud storage ή social media είναι σπάνια βιώσιμο. Το service-aware egress policy και το process-level correlation υπερτερούν του domain-only blocking.

## Personas, accounts και procurement compartments

Η infrastructure anonymity αποτυγχάνει όταν ένα persona, recovery email, phone, payment, browser ή admin IP συνδέει compartments. Operations που συνδέονται με κράτη έχουν καλλιεργήσει social profiles, email identities και cloud accounts πολύ πριν από τη χρήση τους· το ATT&CK το καταγράφει ως Establish Accounts (T1585), συμπεριλαμβανομένων social, email και cloud sub-techniques.<sup>[[8]](#references)</sup>

Ένας defender ή investigator δημιουργεί ένα graph από:

- χρόνο δημιουργίας και πρώτου login, locale, time zone και working schedule·
- recovery fields, MFA devices, identity documents και payment instruments·
- browser/TLS fingerprints και source-network history·
- avatar reuse, image provenance, writing style και social-graph growth·
- shared domain registrant, name server, certificate, analytics ID ή repository commit·
- management-plane actions που παρακάμπτουν την architecture του public relay.

Για ένα authorized red team, τα synthetic personas πρέπει να τεκμηριώνονται στον exercise controller, να χρησιμοποιούν organization-owned recovery/payment channels, να αποφεύγουν την impersonation πραγματικών, άσχετων ανθρώπων και να έχουν προγραμματισμένο retirement. Το SOC μπορεί να παραμείνει blind· η operation δεν πρέπει να καταστεί unaccountable.

## Emerging compound patterns to threat-model

Τα παρακάτω είναι **defender-driven compositions**, όχι ισχυρισμοί ότι ένας named actor έχει υλοποιήσει κάθε ακριβή σχεδιασμό. Συνδυάζουν primitives που έχουν ήδη παρατηρηθεί και είναι χρήσιμες purple-team hypotheses.

### Asymmetric one-way tasking

Τα commands φτάνουν μέσω public, broadcast ή append-only source, ενώ τα results αποστέλλονται μέσω άσχετου channel μετά από καθυστέρηση. Παραδείγματα του primitive περιλαμβάνουν web-service one-way communication και dead drops. Ο διαχωρισμός αποτρέπει ένα μόνο flow από το να φαίνεται bidirectional και δυσχεραίνει το απλό request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** διατηρείτε object-level reads και, στη συνέχεια, συσχετίζετε process state changes και μεταγενέστερες outbound transfers σε μεγαλύτερο χρονικό παράθυρο. Αναζητήστε ένα σπάνιο process που διαβάζει το ίδιο public object, ακόμη και όταν δεν ακολουθεί άμεση reply.

### Multi-stage channel promotion

Ένα ήσυχο first stage πραγματοποιεί inventory και προωθεί μόνο επιλεγμένα systems σε ένα άσχετο second-stage channel. Το δεύτερο endpoint, protocol και process μπορεί να μη μοιράζεται καμία infrastructure με το πρώτο. Αυτό περιορίζει την έκθεση της capable infrastructure και μοντελοποιείται ρητά ως ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** συσχετίστε `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`· μην κλείνετε το incident αφού κάνετε blocking το πρώτο domain.

### Cross-protocol relay translation

Διαφορετικά hops μεταφράζουν HTTPS, QUIC, WebSocket, DNS, SSH ή ένα message-queue API αντί να προωθούν διαφανώς packets. Η translation αφαιρεί ένα ενιαίο end-to-end protocol fingerprint, αλλά δημιουργεί gateways με distinctive timing, buffering και semantic conversion. Το Protocol tunneling (T1572) μπορεί να συνδυαστεί με proxies και service impersonation.<sup>[[11]](#references)</sup>

**Detection:** αναζητήστε gateway hosts που λαμβάνουν ένα protocol και ξεκινούν άλλο με tightly coupled byte/time behavior· συγκρίνετε το endpoint intent με το protocol που πραγματικά μεταφέρεται.

### Passive activation on edge devices

Αντί για beaconing, ένα implant παρακολουθεί traffic που ήδη φτάνει σε router/VPN και ενεργοποιείται μόνο με magic value, source-port pattern ή authenticated token. Η κανονική traffic συνεχίζει προς την πραγματική υπηρεσία. Το ATT&CK το αποκαλεί Traffic Signaling (T1205), με documented network-device και APT examples.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture κατά τη διάρκεια authorized hunt, απρόσμενα socket filters και differential service behavior. Η απουσία periodic beacon δεν αποδεικνύει ότι ένα edge device είναι clean.

### Serverless και ephemeral origin rotation

Ένα front διατηρεί stable logical identity, ενώ short-lived functions/containers χειρίζονται μεμονωμένα stages σε αρκετές regions/accounts. Αυτό μειώνει το disk lifetime και τα fixed origin IPs, αλλά τα control-plane creation, image/layer, role, secret, request ID και billing telemetry γίνονται το durable graph.

**Detection:** διατηρείτε cloud audit και invocation logs εκτός του workload· ομαδοποιείτε deployment templates, roles, environment keys και front-to-origin relationships.

### Privacy-layer diversity

Μια operation μπορεί σκόπιμα να αποφεύγει μία homogeneous chain: για παράδειγμα, ένα channel χρησιμοποιεί leased relay, το tasking χρησιμοποιεί public object, ένα exit προέρχεται από owned lab cellular link και η administration χρησιμοποιεί ξεχωριστό organization network. Αυτό μειώνει την αξία της παραβίασης ενός provider, αλλά αυξάνει τον κίνδυνο cross-layer timing και operational error.

**Detection:** δημιουργήστε campaign timelines σε identity, DNS, SaaS, network και cloud sensors. Αναζητήστε synchronized state transitions αντί για identical indicators.

### Decentralized ή transparency-log dead drops

Ένας actor μπορεί να τοποθετήσει έναν μικρό encrypted pointer σε οποιοδήποτε durable public append-only system, content-addressed store ή transparency-like feed. Το public object είναι resilient, αλλά το ακριβές index/content hash και η client polling behavior γίνονται stable identifiers.

**Detection:** καταγράφετε τα πλήρη API/object identifiers και response hashes· δημιουργήστε alerts για nonstandard processes που κάνουν polling immutable objects και ακολουθούνται από decoding ή νέες connections.

### Delayed store-and-forward operations

Το interactive C2 δημιουργεί ισχυρό timing correlation. Ένας store-and-forward σχεδιασμός ομαδοποιεί encrypted jobs και επιστρέφει results λεπτά ή ώρες αργότερα μέσω διαφορετικού queue ή physical transfer. Θυσιάζει responsiveness για ασθενέστερο end-to-end timing.

**Detection:** επεκτείνετε τα correlation windows, μοντελοποιήστε periodic queue access και εξετάστε το endpoint staging. Το batching μετακινεί το signal από το packet timing στη scheduled process/file behavior· δεν το εξαφανίζει.

## Design review: think in observers

Για κάθε path, συμπληρώστε αυτόν τον πίνακα πριν από το deployment και μετά τη συλλογή:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Αν ένας ordinary provider μπορεί να συμπληρώσει κάθε στήλη, η architecture παρέχει concealment από το target, αλλά όχι robust separation. Αν κανένας internal controller δεν μπορεί να αντιστοιχίσει τη δραστηριότητα σε ένα engagement, είναι ακατάλληλη για professional red teaming.

## References

- [1] [MITRE ATT&CK — Απόκτηση Infrastructure (T1583), Compromise Infrastructure (T1584) και Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actors κατασκοπείας με σύνδεση με την Κίνα χρησιμοποιούν ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
{{#include ../banners/hacktricks-training.md}}
