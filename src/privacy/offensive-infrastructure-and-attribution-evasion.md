# Υποδομή Offensive και Evasion Απόδοσης

Ένας operator σπάνια αποκτά ουσιαστική ανωνυμία από έναν μόνο proxy. Οι πραγματικές campaigns δημιουργούν ένα **γράφημα διαχωρισμού**: ο operator φτάνει σε έναν access node, οι traversal nodes αποκρύπτουν αυτόν τον node από το exit, οι redirectors προστατεύουν το πραγματικό C2 και τα disposable names δείχνουν στο public edge.

Χρησιμοποίησε τον [Κατάλογο Τεχνικών Anonymous Internet Access](anonymous-internet-access-techniques.md) για μια τυποποιημένη άποψη των πλεονεκτημάτων/μειονεκτημάτων, της ανάπτυξης και του detection κάθε διαδρομής. Αυτή η σελίδα εξετάζει σε μεγαλύτερο βάθος τη σύνθεση adversarial infrastructure.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Η τελευταία διεύθυνση που βλέπει ένας στόχος αποτελεί επομένως ένδειξη μιας διαδρομής και όχι απόδειξη του ποιος χειριζόταν το πληκτρολόγιο. Το MITRE αντιστοιχίζει τα κύρια στοιχεία στα Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) και Web Service (T1102).<sup>[[1]](#references)</sup>

## Κατηγορίες υποδομών

| Κατηγορία | Γιατί τη χρησιμοποιεί ένας actor | Ανθεκτική έκθεση | Καλύτερο pivot για τον defender |
|---|---|---|---|
| Rented VPS/cloud | Γρήγορη, προβλέψιμη, routable και εύκολη στην ανακατασκευή | tenant, billing, console, source-login και ιστορικό image | events του account/control-plane και επαναλαμβανόμενο server fingerprint |
| Commercial VPN/Tor | Μεγάλο shared egress set· χωρίς διαχείριση server | ορατότητα provider/guard και end-to-end timing | συμπεριφορά προορισμού, endpoint evidence και συσχέτιση flow |
| Residential/mobile proxy | Consumer ASN και γεωγραφική plausibility | records broker/customer· συμπεριφορά proxyware ή infected-host | impossible travel, proxy protocols και αλλαγές διευθύνσεων ανά session |
| Compromised server/router/IoT | Δανείζεται τη φήμη και τη δικαιοδοσία του θύματος | implant, management flow και επαναλαμβανόμενος upstream controller | device telemetry και ORB topology, όχι ένα exit IP |
| CDN/redirector | Διαχωρίζει το public edge από το back-end C2 | TLS/HTTP grammar, certificate, routing και cloud-account artifacts | συσχέτιση edge-to-origin και clustering βάσει request shape |
| Legitimate web service | Ενσωματώνεται σε επιτρεπόμενη GitHub/cloud/social κίνηση | API token, tenant/object identifiers και ασυνήθιστη process lineage | endpoint process και semantics του service/API |
| Physical/cellular/satellite path | Αλλάζει τη φαινομενική φυσική προέλευση | RF, carrier, subscriber, device και location records | συνδυασμένα radio/physical και network evidence |

## Δίκτυα operational relay box

Ένα **ORB network** είναι ένας managed proxy fleet που χρησιμοποιείται ως ενδιάμεση υπηρεσία. Η Mandiant τα διακρίνει σε provisioned networks από leased servers, non-provisioned networks από compromised routers/IoT και hybrids. Μια ώριμη topology διαθέτει τέσσερις λογικούς ρόλους:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** διατηρεί inventory, credentials, health και routing policy.
2. **Access/relay node:** κάνει authentication σε customers ή operators· αποτελεί το σταθερό entry point προς ένα μεταβαλλόμενο mesh.
3. **Traversal nodes:** ένα ή περισσότερα leased ή compromised systems κάνουν relay σε opaque connections.
4. **Exit/staging node:** παρουσιάζει την τελική source address σε reconnaissance, exploitation ή C2 targets.

Το mesh μπορεί να επιλέγει exits βάσει χώρας, ASN, latency ή availability και να περιστρέφει unhealthy nodes. Πολλαπλά threat groups μπορεί να νοικιάζουν το ίδιο network. Η Mandiant παρατήρησε ότι μια IPv4 address παρέμενε συσχετισμένη με ορισμένα ORBs για μόλις 31 ημέρες· επομένως συνιστά να αντιμετωπίζεται το **network ως εξελισσόμενη οντότητα που μοιάζει με actor**, αντί να γίνεται block μιας stale λίστας IPs.<sup>[[2]](#references)</sup>

### Τι προσφέρει—and τι leak

- Ο στόχος βλέπει ένα exit που μπορεί να είναι γεωγραφικά κοντινό και φαινομενικά residential.
- Το exit βλέπει τον στόχο και το προηγούμενο hop, όχι απαραίτητα τον operator.
- Το access service βλέπει τον customer και το route request. Ένα independently managed mesh μπορεί να κρατά τον customer διαχωρισμένο από τα exits, αλλά δημιουργεί ένα ισχυρό counterparty record.
- Επαναλαμβανόμενα ports, handshake order, server banners, certificates, uptime windows και controller relationships μπορούν να αποκαλύψουν τον fleet ακόμη και όταν οι IPs περιστρέφονται.
- Ένας compromised router συχνά δεν διαθέτει endpoint telemetry, αλλά ο ISP του εξακολουθεί να έχει subscriber και flow data· μια κατάσχεση αποκαλύπτει implant/configuration artifacts.

{% hint style="info" %}
Για ένα authorized exercise, αναπαράγετε την topology με organization-owned VMs ή routers και διατηρήστε το attribution map του controller. Μην επιστρατεύετε open proxies ή συσκευές τρίτων. Ο [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) δημιουργεί την ίδια defender-visible hop structure χωρίς να θυματοποιεί έναν intermediary.
{% endhint %}

## Residential και mobile proxy networks

Οι residential proxy services εκχωρούν sessions σε consumer broadband addresses· τα mobile proxies κάνουν egress μέσω carrier NAT pools. Η supply μπορεί να προέρχεται από expressly enrolled appliances, SDK/proxyware ενσωματωμένο σε consumer applications, resellers ή malware. Αυτές οι προελεύσεις δεν είναι ισοδύναμες: η απουσία informed consent μετατρέπει μια privacy service σε compromised infrastructure.

Οι τρόποι rotation επηρεάζουν το detection:

- το **per-request rotation** παράγει rapid discontinuities σε IP και ASN/geography, ενώ η identity στα higher layers παραμένει σταθερή·
- τα **sticky sessions** διατηρούν ένα exit για λεπτά ή ώρες, μοιάζοντας με ordinary subscriber·
- τα **backconnect gateways** εκθέτουν ένα broker endpoint στον customer και επιλέγουν εσωτερικά τα exits·
- τα **mobile pools** τοποθετούν πολλούς genuine subscribers πίσω από μικρό σύνολο carrier NAT addresses, καθιστώντας ένα IP block δαπανηρό.

Οι defenders θα πρέπει να συσχετίζουν την IP με authenticated session, TLS/client fingerprint, HTTP ordering, device cookie και behavior. Ένα υποτιθέμενα local residential login που ακολουθείται από άλλη χώρα, ενώ όλα τα higher-layer features παραμένουν πανομοιότυπα, αποτελεί ισχυρότερη ένδειξη από το reputation μόνο του. Αντίθετα, το address sharing και το mobile handoff δημιουργούν legitimate churn, επομένως μην αντιμετωπίζετε ποτέ την ταξινόμηση residential/proxy ως verdict.

## Multi-hop proxy chains

Το MITRE διακρίνει τα external proxies από τα **multi-hop proxies (T1090.003)**. Η σημαντική ιδιότητα δεν είναι ο αριθμός των hops αλλά ο διαχωρισμός της γνώσης και της διαχείρισης.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Αν ένα μέρος λειτουργεί τα A και B, τα κοινόχρηστα logs ή ο χρονισμός της ροής μπορούν να ανακατασκευάσουν το κύκλωμα. Η προσθήκη διαδοχικών εμπορικών VPN από το ίδιο endpoint/account μπορεί να αυξήσει την καθυστέρηση, αφήνοντας παράλληλα κοινά στοιχεία ταυτότητας, πληρωμής και χρονισμού. Το Tor περιορίζει αυτό το πρόβλημα με ανεξάρτητα επιλεγμένα relays και κοινό σχεδιασμό client, όμως ένα low-latency interactive network δεν μπορεί να εγγυηθεί αντίσταση απέναντι σε observer που μετρά και τα δύο άκρα.

Συνηθισμένες αστοχίες είναι η παράκαμψη μέσω DNS ή IPv6, οι εφαρμογές που ανοίγουν τα δικά τους sockets, η κίνηση διαχείρισης που φτάνει απευθείας στα relays, η συγχρονισμένη δραστηριότητα, η επαναχρησιμοποίηση SSH keys και η σύνδεση σε λογαριασμούς που αποκαλύπτουν την ταυτότητα. Η σωστή επαλήθευση είναι ένα failure test: σταματήστε κάθε relay διαδοχικά και δείξτε ότι το workload δεν μπορεί να στραφεί σε clear path.

## Επίπεδα redirector και διαμόρφωση traffic

Ένας δημόσιος **redirector** δέχεται traffic που αντιστοιχεί σε grammar ειδική για την επιχείρηση και το προωθεί σε έναν προστατευμένο team server. Οτιδήποτε άλλο μπορεί να απορρίπτεται ή να εξυπηρετεί innocuous content.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Πολλαπλά επίπεδα περιορίζουν την έκθεση: η απώλεια ενός public domain δεν χρειάζεται να εκθέσει τον team server. Τα CDN προσθέτουν anycast χωρητικότητα και ένα αξιόπιστο εξωτερικό domain, όμως ο λογαριασμός του CDN και τα edge logs γίνονται σημεία attribution. Τα TLS fingerprints, τα ιστορικά πιστοποιητικών, τα distinctive paths/η σειρά των headers, τα μεγέθη αποκρίσεων, η συμπεριφορά των redirects και τα origin allowlists μπορούν να ομαδοποιήσουν fronts που υποτίθεται ότι είναι άσχετα μεταξύ τους.

Για detection, καταγράψτε τα πεδία του reverse proxy πριν από το normalization, συγκρίνετε SNI/Host/authority, εξετάστε σπάνιους συνδυασμούς headers, ομαδοποιήστε response bodies και TLS fingerprints και αναζητήστε στα audit logs του cloud/CDN επικαλύψεις διαμόρφωσης. Για authorized red teams, αποφύγετε την αντιγραφή πραγματικού brand ή την τοποθέτηση credential collection πίσω από άσχετο third party.

## Domain fronting και domainless fronting

Με το κλασικό **domain fronting (T1090.004)**, η TLS σύνδεση διαφημίζει ένα επιτρεπόμενο front domain στο SNI, ενώ το κρυπτογραφημένο HTTP `Host` ή HTTP/2 `:authority` ζητά διαφορετικό back-end domain. Ένα συνεργαζόμενο CDN δρομολογεί με βάση την εσωτερική τιμή. Ένας network observer χωρίς TLS decryption βλέπει το front· το CDN βλέπει και τις δύο τιμές και το origin. Στις domainless παραλλαγές, το SNI μπορεί να είναι κενό, ενώ ένα άλλο routing field επιλέγει τον προορισμό.<sup>[[4]](#references)</sup>

Αυτό δεν αποτελεί μαγική impersonation: λειτουργεί μόνο όταν ο intermediary επιτρέπει σκόπιμα ή κατά λάθος την ασυμφωνία και γνωρίζει πώς να δρομολογήσει το εσωτερικό όνομα. Οι major providers έχουν περιορίσει το cross-account fronting. Το Encrypted ClientHello (ECH) αλλάζει όσα μπορεί να δει ένας on-path observer, αλλά δεν εξαλείφει τα records του CDN, του endpoint ή της εφαρμογής.

Τα σημεία detection περιλαμβάνουν:

- ancestry του endpoint process και destination που δεν αναμένεται για τη συγκεκριμένη εφαρμογή·
- ασυμφωνία SNI και HTTP authority όπου το TLS inspection είναι νόμιμο και διαθέσιμο·
- CDN logs που δείχνουν ένα tenant/front να δρομολογεί προς άλλο authority/origin·
- ασυνήθιστες long-lived ή περιοδικές sessions προς μια κανονικά interactive service·
- σταθερά μεγέθη και cadence κρυπτογραφημένων flows σε διαφορετικά front domains.

Το ασφαλές lab προσομοιώνει την ασυμφωνία routing σε reverse proxy που σας ανήκει· δεν κάνει abuse σε public CDN.

## Dynamic resolution: DDNS, DGA και fast flux

Το dynamic resolution αποσυνδέει μια λογική service από σταθερή υποδομή:

- **DDNS:** ένας authenticated client ενημερώνει ένα σταθερό όνομα αφού αλλάξει η διεύθυνσή του.
- **DGA:** τόσο το endpoint όσο και ο controller παράγουν candidate domain names από ένα time/key seed· ο operator καταχωρίζει ένα μικρό subset.
- **Fast flux:** ένα όνομα επιστρέφει ένα σύνολο διευθύνσεων από compromised/proxy hosts που αλλάζει γρήγορα, συχνά με χαμηλά TTLs.
- **Double flux:** περιστρέφονται τόσο οι service addresses όσο και οι authoritative name-server addresses, αποκρύπτοντας και το control layer.

Το fast flux είναι ένα μοτίβο load distribution που χρησιμοποιείται adversarially και όχι απλώς «πολλές DNS απαντήσεις». Ισχυρότερα στοιχεία συνδυάζουν χαμηλό TTL, υψηλό αριθμό unique addresses, μεγάλη διασπορά ASN/γεωγραφίας, σύντομη διάρκεια ζωής των nodes, επαναλαμβανόμενη συμπεριφορά εφαρμογής και ύποπτο registration history. Τα CDN μοιράζονται νόμιμα αρκετές από αυτές τις ιδιότητες. Το MITRE συνιστά τη συσχέτιση της συμπεριφοράς DNS με το process και τις επακόλουθες συνδέσεις.<sup>[[5]](#references)</sup>

Ένα DGA μπορεί να ανιχνευτεί μέσω lexical entropy, μοτίβων συμφώνων/ψηφίων, bursts από NXDOMAIN, συγχρονισμένων first-seen domains και process context. Τα wordlist DGAs και τα generative models παρακάμπτουν απλούς κανόνες entropy, καθιστώντας σημαντικότερο το temporal clustering σε ολόκληρο το fleet και το endpoint lineage.

## Compromised domains και domain shadowing

Ένας actor μπορεί να κάνει hijack έναν registrar/DNS account, να αναλάβει ένα dangling subdomain ή να προσθέσει records κάτω από ένα κατά τα άλλα αξιόπιστο domain. Το **domain shadowing** διατηρεί το νόμιμο apex, ενώ μεγάλος αριθμός attacker-controlled subdomains δείχνει σε μεταβαλλόμενα delivery ή C2 hosts. Δανείζεται ηλικία και reputation και μπορεί να παρακάμψει το domain-wide blocking.<sup>[[6]](#references)</sup>

Οι defenders χρειάζονται registrar και authoritative-DNS audit logs, MFA, registry/registrar locks, alerts για νέες delegations/API tokens/name servers, certificate-transparency monitoring και inventory των cloud resources που αναφέρονται από DNS. Ερευνήστε το resolution και το certificate history ενός subdomain ανεξάρτητα από το reputation του apex.

## Web services και dead-drop resolvers

Ένας **dead-drop resolver (T1102.001)** αποθηκεύει έναν encoded pointer προς το τρέχον C2 μέσα σε ένα legitimate post, profile, document, repository, cloud object ή blockchain field. Το malware κάνει fetch το public object, αποκωδικοποιεί ένα domain/IP και επικοινωνεί με το επόμενο stage. Οι bidirectional παραλλαγές ανταλλάσσουν commands ή files μέσω service APIs.<sup>[[7]](#references)</sup>

Αυτό παρέχει resilience και αποκρύπτει το back-end C2 από το static binary analysis. Δημιουργεί επίσης σταθερά object, tenant, repository, API και access-pattern identifiers. Οι defenders θα πρέπει να συσχετίζουν:

1. το process που επικοινώνησε με τη service·
2. το ακριβές API path/object και το response hash·
3. τη δραστηριότητα decoding ή string-processing·
4. τη νέα outbound connection λίγο αργότερα· και
5. την ίδια συμπεριφορά σε άλλα σημεία του fleet.

Το blocking όλου του GitHub, του cloud storage ή των social media σπάνια είναι βιώσιμο. Το service-aware egress policy και το process-level correlation υπερτερούν του domain-only blocking.

## Personas, accounts και procurement compartments

Η anonymity της υποδομής αποτυγχάνει όταν ένα persona, recovery email, τηλέφωνο, payment, browser ή admin IP συνδέει compartments. Operations που συνδέονται με state έχουν καλλιεργήσει social profiles, email identities και cloud accounts πολύ πριν από τη χρήση τους· το ATT&CK το καταγράφει ως Establish Accounts (T1585), συμπεριλαμβανομένων των social, email και cloud sub-techniques.<sup>[[8]](#references)</sup>

Ένας defender ή investigator δημιουργεί ένα graph από:

- χρόνο δημιουργίας και πρώτου login, locale, time zone και πρόγραμμα εργασίας·
- recovery fields, MFA devices, identity documents και payment instruments·
- browser/TLS fingerprints και ιστορικό source-network·
- επαναχρησιμοποίηση avatar, image provenance, writing style και ανάπτυξη του social graph·
- κοινό domain registrant, name server, certificate, analytics ID ή repository commit·
- ενέργειες στο management plane που παρακάμπτουν την αρχιτεκτονική του public relay.

Για ένα authorized red team, τα synthetic personas πρέπει να τεκμηριώνονται προς τον exercise controller, να χρησιμοποιούν organization-owned recovery/payment channels, να αποφεύγουν την impersonation πραγματικών μη εμπλεκόμενων ανθρώπων και να έχουν προγραμματισμένο retirement. Το SOC μπορεί να παραμείνει blind· η operation όμως δεν πρέπει να καταστεί unaccountable.

## Emerging compound patterns προς threat-model

Τα παρακάτω είναι **defender-driven compositions** και όχι ισχυρισμοί ότι ένας named actor έχει υλοποιήσει κάθε ακριβή σχεδιασμό. Συνδυάζουν primitives που έχουν ήδη παρατηρηθεί και είναι χρήσιμα ως purple-team hypotheses.

### Asymmetric one-way tasking

Τα commands φτάνουν μέσω μιας public, broadcast ή append-only source, ενώ τα results εξέρχονται από ένα unrelated channel μετά από καθυστέρηση. Παραδείγματα του primitive περιλαμβάνουν one-way communication μέσω web service και dead drops. Ο διαχωρισμός εμποδίζει ένα μεμονωμένο flow να εμφανίζεται ως bidirectional και δυσκολεύει το απλό request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** διατηρήστε object-level reads και στη συνέχεια συσχετίστε process state changes και μεταγενέστερες outbound transfers σε μεγαλύτερο χρονικό παράθυρο. Αναζητήστε ένα σπάνιο process που διαβάζει το ίδιο public object, ακόμη και όταν δεν ακολουθεί άμεση reply.

### Multi-stage channel promotion

Ένα ήσυχο first stage εκτελεί inventory και προωθεί μόνο επιλεγμένα systems σε ένα unrelated second-stage channel. Το δεύτερο endpoint, protocol και process μπορεί να μη μοιράζεται καμία υποδομή με το πρώτο. Αυτό περιορίζει την έκθεση της capable infrastructure και μοντελοποιείται ρητά ως ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** συνδέστε `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`· μην κλείνετε το incident μετά το blocking του πρώτου domain.

### Cross-protocol relay translation

Διαφορετικά hops μεταφράζουν HTTPS, QUIC, WebSocket, DNS, SSH ή ένα message-queue API αντί να προωθούν διαφανώς packets. Η translation αφαιρεί ένα μοναδικό end-to-end protocol fingerprint, αλλά δημιουργεί gateways με distinctive timing, buffering και semantic conversion. Το Protocol tunneling (T1572) μπορεί να συνδυαστεί με proxies και service impersonation.<sup>[[11]](#references)</sup>

**Detection:** αναζητήστε gateway hosts που λαμβάνουν ένα protocol και ξεκινούν άλλο, με στενά συνδεδεμένη συμπεριφορά σε bytes/time· συγκρίνετε το intent του endpoint με το protocol που πράγματι μεταφέρεται.

### Passive activation on edge devices

Αντί για beaconing, ένα implant παρακολουθεί traffic που ήδη φτάνει σε router/VPN και ενεργοποιείται μόνο από μια magic value, ένα source-port pattern ή ένα authenticated token. Η κανονική traffic συνεχίζει προς την πραγματική service. Το ATT&CK το ονομάζει Traffic Signaling (T1205), με τεκμηριωμένα παραδείγματα network devices και APT.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture κατά τη διάρκεια authorized hunt, απρόσμενα socket filters και differential service behavior. Η απουσία periodic beacon δεν αποδεικνύει ότι ένα edge device είναι clean.

### Serverless και ephemeral origin rotation

Ένα front διατηρεί μια σταθερή logical identity, ενώ short-lived functions/containers χειρίζονται μεμονωμένα stages σε πολλές regions/accounts. Αυτό μειώνει τη διάρκεια ζωής στο disk και τα fixed origin IPs, όμως το control-plane creation, το image/layer, το role, το secret, το request ID και το billing telemetry γίνονται το durable graph.

**Detection:** διατηρήστε τα cloud audit και invocation logs εκτός του workload· ομαδοποιήστε deployment templates, roles, environment keys και front-to-origin relationships.

### Privacy-layer diversity

Μια operation μπορεί σκόπιμα να αποφεύγει μία homogeneous chain: για παράδειγμα, ένα channel χρησιμοποιεί leased relay, το tasking χρησιμοποιεί public object, ένα exit προέρχεται από owned lab cellular link και η administration χρησιμοποιεί ξεχωριστό organization network. Αυτό μειώνει την αξία του compromise ενός provider, αλλά αυξάνει το cross-layer timing και τον κίνδυνο operational error.

**Detection:** δημιουργήστε campaign timelines σε identity, DNS, SaaS, network και cloud sensors. Αναζητήστε συγχρονισμένες state transitions αντί για identical indicators.

### Decentralized ή transparency-log dead drops

Ένας actor μπορεί να τοποθετήσει έναν μικρό encrypted pointer σε οποιοδήποτε durable public append-only system, content-addressed store ή transparency-like feed. Το public object είναι resilient, όμως το ακριβές index/content hash και η polling behavior του client γίνονται σταθερά identifiers.

**Detection:** καταγράψτε τα πλήρη API/object identifiers και response hashes· δημιουργήστε alert για nonstandard processes που κάνουν polling σε immutable objects και στη συνέχεια εκτελούν decoding ή νέες connections.

### Delayed store-and-forward operations

Το interactive C2 δημιουργεί ισχυρό timing correlation. Ένας store-and-forward σχεδιασμός ομαδοποιεί encrypted jobs και επιστρέφει results λεπτά ή ώρες αργότερα μέσω διαφορετικού queue ή physical transfer. Θυσιάζει responsiveness για ασθενέστερο end-to-end timing.

**Detection:** επεκτείνετε τα correlation windows, μοντελοποιήστε το periodic queue access και εξετάστε το endpoint staging. Το batching μετακινεί το signal από το packet timing στη scheduled process/file behavior· δεν το εξαλείφει.

## Design review: σκεφτείτε σε observers

Για κάθε path, συμπληρώστε αυτόν τον πίνακα πριν από το deployment και μετά τη συλλογή:

| Layer | Βλέπει το source; | Βλέπει το destination; | Βλέπει το content; | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

Αν ένας ordinary provider μπορεί να συμπληρώσει κάθε στήλη, η αρχιτεκτονική παρέχει concealment από το target, αλλά όχι robust separation. Αν κανένας internal controller δεν μπορεί να συσχετίσει τη δραστηριότητα με ένα engagement, είναι ακατάλληλη για professional red teaming.

## References

- [1] [MITRE ATT&CK — Απόκτηση υποδομής (T1583), Compromise Infrastructure (T1584) και Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actors espionage με nexus στην Κίνα χρησιμοποιούν ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
