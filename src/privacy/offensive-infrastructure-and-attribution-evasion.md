# Υποδομή Offensive και Αποφυγή Attribution

{{#include ../banners/hacktricks-training.md}}

Ένας operator σπάνια επιτυγχάνει ουσιαστική ανωνυμία μέσω ενός και μόνο proxy. Οι πραγματικές εκστρατείες δημιουργούν ένα **separation graph**: ο operator φτάνει σε έναν access node, οι traversal nodes αποκρύπτουν αυτόν τον node από το exit, οι redirectors προστατεύουν το πραγματικό C2 και τα disposable names δείχνουν στο public edge.

Χρησιμοποίησε το [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) για μια τυποποιημένη άποψη των πλεονεκτημάτων/μειονεκτημάτων, της ανάπτυξης και του detection κάθε διαδρομής. Αυτή η σελίδα εμβαθύνει στη σύνθεση adversarial υποδομής.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Η τελευταία διεύθυνση που βλέπει ένας στόχος αποτελεί επομένως ένδειξη μιας διαδρομής και όχι απόδειξη του ποιος έλεγχε το πληκτρολόγιο. Το MITRE αντιστοιχίζει τα κύρια στοιχεία στα Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) και Web Service (T1102).<sup>[[1]](#references)</sup>

## Κατηγορίες υποδομής

| Κατηγορία | Γιατί τη χρησιμοποιεί ένας actor | Διαρκής έκθεση | Καλύτερο pivot για τον defender |
|---|---|---|---|
| Rented VPS/cloud | Γρήγορο, προβλέψιμο, δρομολογήσιμο και εύκολο στην αναδημιουργία | tenant, billing, console, source-login και ιστορικό image | events του account/control-plane και επαναλαμβανόμενο server fingerprint |
| Commercial VPN/Tor | Μεγάλο κοινόχρηστο σύνολο egress· χωρίς διαχείριση server | ορατότητα provider/guard και end-to-end timing | συμπεριφορά προορισμού, endpoint evidence και flow correlation |
| Residential/mobile proxy | Consumer ASN και γεωγραφική αληθοφάνεια | αρχεία broker/customer· συμπεριφορά proxyware ή infected host | impossible travel, πρωτόκολλα proxy και αλλαγή διευθύνσεων ανά session |
| Compromised server/router/IoT | Δανείζεται τη φήμη και τη δικαιοδοσία του θύματος | implant, management flow και επαναλαμβανόμενος upstream controller | telemetry της συσκευής και ORB topology, όχι μία exit IP |
| CDN/redirector | Διαχωρίζει το public edge από το back-end C2 | TLS/HTTP grammar, certificate, routing και artifacts του cloud account | edge-to-origin correlation και clustering βάσει request shape |
| Legitimate web service | Ενσωματώνεται σε επιτρεπόμενη GitHub/cloud/social traffic | API token, tenant/object identifiers και ασυνήθιστη process lineage | endpoint process μαζί με τα semantics του service/API |
| Physical/cellular/satellite path | Αλλάζει τη φαινομενική φυσική προέλευση | RF, carrier, subscriber, device και location records | συνδυασμός radio/physical και network evidence |

## Δίκτυα operational relay box

Ένα **ORB network** είναι ένας managed proxy fleet που χρησιμοποιείται ως ενδιάμεση υπηρεσία. Η Mandiant τα διαχωρίζει σε provisioned networks από leased servers, non-provisioned networks από compromised routers/IoT και hybrids. Μια ώριμη topology έχει τέσσερις λογικούς ρόλους:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** διατηρεί inventory, credentials, health και routing policy.
2. **Access/relay node:** αυθεντικοποιεί customers ή operators· αποτελεί το σταθερό entry σε ένα μεταβαλλόμενο mesh.
3. **Traversal nodes:** ένα ή περισσότερα leased ή compromised systems προωθούν opaque connections.
4. **Exit/staging node:** παρουσιάζει την τελική source address σε reconnaissance, exploitation ή C2 targets.

Το mesh μπορεί να επιλέγει exits με βάση τη χώρα, το ASN, το latency ή τη διαθεσιμότητα και να αντικαθιστά unhealthy nodes. Πολλαπλές threat groups μπορεί να νοικιάζουν το ίδιο network. Η Mandiant παρατήρησε ότι μια IPv4 address παρέμενε συνδεδεμένη με ορισμένα ORBs για μόλις 31 ημέρες· επομένως συνιστά να αντιμετωπίζεται το **network ως μια εξελισσόμενη οντότητα που μοιάζει με actor**, αντί να γίνεται block μιας παρωχημένης λίστας IPs.<sup>[[2]](#references)</sup>

### Τι προσφέρει—and τι leaks

- Ο στόχος βλέπει ένα exit που μπορεί να βρίσκεται γεωγραφικά κοντά και να φαίνεται residential.
- Το exit βλέπει τον στόχο και το προηγούμενο hop, όχι απαραίτητα τον operator.
- Η access service βλέπει τον customer και το route request. Ένα ανεξάρτητα διαχειριζόμενο mesh μπορεί να διατηρεί τον customer διαχωρισμένο από τα exits, αλλά δημιουργεί ένα ισχυρό counterparty record.
- Επαναλαμβανόμενα ports, handshake order, server banners, certificates, uptime windows και controller relationships μπορούν να αποκαλύψουν το fleet ακόμη και όταν οι IPs αλλάζουν.
- Ένας compromised router συχνά δεν διαθέτει endpoint telemetry, όμως ο ISP του εξακολουθεί να έχει subscriber και flow data· μια κατάσχεση αποκαλύπτει artifacts του implant/configuration.

{% hint style="info" %}
Για ένα authorized exercise, αναπαράγετε την topology με VMs ή routers που ανήκουν στον οργανισμό και διατηρήστε το attribution map του controller. Μην στρατολογείτε open proxies ή συσκευές τρίτων. Ο [οδηγός του lab](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) δημιουργεί την ίδια hop structure που είναι ορατή στον defender χωρίς να θυματοποιεί έναν intermediary.
{% endhint %}

## Residential και mobile proxy networks

Οι residential proxy services αντιστοιχίζουν sessions σε consumer broadband addresses· τα mobile proxies κάνουν egress μέσω carrier NAT pools. Η προμήθεια μπορεί να προέρχεται από συσκευές που έχουν εγγραφεί ρητά, SDK/proxyware ενσωματωμένα σε consumer applications, resellers ή malware. Αυτές οι προελεύσεις δεν είναι ισοδύναμες: η έλλειψη informed consent μετατρέπει μια privacy service σε compromised infrastructure.

Οι τρόποι rotation επηρεάζουν το detection:

- **per-request rotation** δημιουργεί γρήγορες ασυνέχειες σε IP, ASN και γεωγραφία, ενώ η ταυτότητα στα υψηλότερα layers παραμένει σταθερή·
- **sticky sessions** διατηρούν ένα exit για λεπτά ή ώρες, μοιάζοντας με ordinary subscriber·
- **backconnect gateways** εκθέτουν ένα broker endpoint στον customer και επιλέγουν εσωτερικά τα exits·
- **mobile pools** τοποθετούν πολλούς πραγματικούς subscribers πίσω από ένα μικρό σύνολο carrier NAT addresses, καθιστώντας ένα IP block δαπανηρό.

Οι defenders θα πρέπει να συσχετίζουν την IP με το authenticated session, το TLS/client fingerprint, το HTTP ordering, το device cookie και τη συμπεριφορά. Ένα υποτιθέμενα local residential login που ακολουθείται από άλλη χώρα, ενώ όλα τα χαρακτηριστικά στα υψηλότερα layers παραμένουν πανομοιότυπα, αποτελεί ισχυρότερη ένδειξη από το reputation μόνο του. Αντίστροφα, το address sharing και το mobile handoff δημιουργούν legitimate churn, επομένως μην αντιμετωπίζετε ποτέ την ταξινόμηση residential/proxy ως verdict.

### Proxyware control planes και reseller overlap

Μην μοντελοποιείτε ένα residential pool ως επίπεδη λίστα exits. Η ανάλυση του IPIDEA ecosystem αποκάλυψε ένα επαναχρησιμοποιήσιμο **two-tier control plane**: ένα embedded SDK αναφέρει αρχικά device/enrollment metadata σε ένα Tier One domain και λαμβάνει scheduling καθώς και ζεύγη Tier Two `connect`/`proxy` IP:port. Ο node κάνει περιοδικά poll στο Tier Two connect port για ένα encoded task, ανοίγει δεύτερη connection στο αντίστοιχο proxy port και προωθεί τα παρεχόμενα bytes στον ζητούμενο προορισμό. SDKs και proxy brands που ονομαστικά διέφεραν είχαν ξεχωριστά discovery domains, αλλά συνέκλιναν σε κοινόχρηστο Tier Two infrastructure και επικαλυπτόμενα exit pools μέσω κοινής ιδιοκτησίας και reseller relationships.<sup>[[13]](#references)</sup>
```text
enrolled node -> Tier One domain        -> Tier Two IP:port pairs
enrolled node -> Tier Two connect port  -> destination + connection ID
enrolled node -> Tier Two proxy port   <-> customer bytes -> destination
```
Αυτό παράγει πιο ανθεκτικά hunting pivots από ένα residential IP block:<sup>[[13]](#references)</sup>

- μια απρόσμενη διεργασία utility, VPN, game ή embedded-device στέλνει ένα σταθερό device ID/customer key και λαμβάνει μια μεταβαλλόμενη λίστα server·
- το endpoint κάνει polling σε ένα direct IP σε ασυνήθιστη θύρα και, αμέσως πριν ανοίξει ένα νέο destination socket, συνδέεται σε άλλη θύρα στην ίδια διεύθυνση·
- πολλές φαινομενικά διαφορετικές μάρκες μοιράζονται Tier Two διευθύνσεις, protocol grammar, κώδικα SDK ή επικάλυψη exit-node·
- διαφορετικές εφαρμογές που επικοινωνούν με διαφορετικά Tier One domains λαμβάνουν διευθύνσεις από το ίδιο Tier Two pool.

Η επικάλυψη περιορίζει επίσης την απόδοση: το να εντοπιστεί μια IP στο advertised pool ενός vendor δεν αποδεικνύει ποιος reseller, customer ή threat actor τη χρησιμοποίησε κατά τον σχετικό χρόνο. Διατηρήστε timestamps των flows, process lineage, τα σώματα των αποκρίσεων Tier One και τα Tier Two task identifiers.<sup>[[13]](#references)</sup> Σε ένα authorized exercise, προσομοιώστε αυτή την ιεραρχία μόνο με endpoints που ανήκουν στον οργανισμό· μην εγγράφετε ποτέ consumer devices ή third-party proxyware.

## Multi-hop proxy chains

Το MITRE διακρίνει τα external proxies από τα **multi-hop proxies (T1090.003)**. Η σημαντική ιδιότητα δεν είναι ο αριθμός των hops, αλλά ο διαχωρισμός της γνώσης και της διαχείρισης.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
Εάν ένα μέρος χειρίζεται τα A και B, τα κοινόχρηστα logs ή ο χρονισμός της ροής μπορούν να ανακατασκευάσουν το circuit. Η προσθήκη διαδοχικών commercial VPNs από το ίδιο endpoint/account μπορεί να αυξήσει το latency, αφήνοντας παράλληλα κοινά στοιχεία ταυτότητας, πληρωμών και χρονισμού. Το Tor μειώνει αυτό το πρόβλημα με independently selected relays και shared client design, όμως ένα low-latency interactive network δεν μπορεί να εγγυηθεί αντίσταση απέναντι σε observer που μετρά και τα δύο άκρα.

Συνηθισμένες αστοχίες είναι το DNS ή IPv6 bypass, οι εφαρμογές που ανοίγουν τα δικά τους sockets, η απευθείας προσέγγιση των relays από management traffic, η συγχρονισμένη δραστηριότητα, η επαναχρησιμοποίηση SSH keys και η σύνδεση σε identifying accounts. Η σωστή επαλήθευση είναι ένα failure test: σταματήστε κάθε relay διαδοχικά και δείξτε ότι το workload δεν μπορεί να κάνει fallback σε clear path.

### Κατάρρευση tunnel και upstream leakage

Μια relay architecture είναι συχνά πιο attributable όταν αποτυγχάνει. Το Unit 42 τεκμηρίωσε ένα multi-tier espionage path που χρησιμοποιούσε victim-facing VPSs, relay VPSs, residential proxies, Tor και άλλες proxy services· όταν ένα tunnel παραλειπόταν ή κατέρρεε, κρυφή upstream infrastructure συνδεόταν απευθείας με relay και victim-facing systems. Η ίδια έρευνα χρησιμοποίησε επίσης ένα X.509 certificate, το οποίο εκτέθηκε για σύντομο χρονικό διάστημα σε upstream infrastructure, ως cross-tier pivot.<sup>[[14]](#references)</sup>

Διατηρήστε το **data plane** (`victim <-> exit`) ξεχωριστά από το **control plane** (`operator/upstream -> relay administration`). Διατηρήστε ingress και authentication logs σε κάθε owned tier, certificate histories και σύντομες failed connections—όχι μόνο επιτυχημένα C2 sessions. Μια source που εμφανίζεται μόνο κατά τη διάρκεια relay outages ή διαχειρίζεται απευθείας πολλαπλά victim-facing nodes αποτελεί ισχυρότερο upstream candidate από ένα συνηθισμένο exit, όμως το ASN/geolocation της παραμένει hypothesis και όχι απόδειξη της ταυτότητας ενός operator.

Ένα authorized lab πρέπει να κάνει το workload fail closed. Για ένα workload απομονωμένο σε Linux network namespace, η πρώτη route πρέπει να χρησιμοποιεί το tunnel· μετά την αφαίρεσή του, τόσο το request όσο και το route lookup πρέπει να αποτυγχάνουν αντί να επιλέγουν το physical uplink:
```bash
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: dev wg0
ip -n workload link set wg0 down
ip netns exec workload curl --fail --connect-timeout 3 \
--resolve "$OWNED_TEST_HOST:443:$OWNED_TEST_IP" "https://$OWNED_TEST_HOST/health"
ip netns exec workload ip route get "$OWNED_TEST_IP"  # expect: unreachable
```
Επανάλαβε τη δοκιμή για DNS και IPv6, καθώς και σε κάθε όριο relay. Αν οποιοδήποτε probe πετύχει, κατέγραψε την πραγματική διεύθυνση interface/source πριν διορθώσεις το policy routing ή το firewall· αυτή η παρατήρηση είναι το attribution leak που θα έβλεπε ένας investigator.

## Redirector tiers και traffic shaping

Ένας δημόσιος **redirector** δέχεται traffic που ταιριάζει με μια operation-specific grammar και το προωθεί σε έναν προστατευμένο team server. Οτιδήποτε άλλο μπορεί να απορρίπτεται ή να εξυπηρετεί innocuous περιεχόμενο.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Πολλαπλά επίπεδα περιορίζουν την έκθεση: η απώλεια ενός public domain δεν χρειάζεται να εκθέσει τον team server. Τα CDN προσθέτουν anycast capacity και ένα αξιόπιστο outer domain, αλλά το CDN account και τα edge logs γίνονται σημεία attribution. Τα TLS fingerprints, τα certificate histories, τα distinctive paths/header order, τα response sizes, η redirect behavior και τα origin allowlists μπορούν να ομαδοποιήσουν fronts που υποτίθεται ότι είναι άσχετα.

Για detection, καταγράψτε τα reverse-proxy fields πριν από το normalization, συγκρίνετε SNI/Host/authority, εξετάστε σπάνιους συνδυασμούς headers, ομαδοποιήστε response bodies και TLS fingerprints και αναζητήστε στα cloud/CDN audit logs επικαλύψεις configuration. Για authorized red teams, αποφύγετε την αντιγραφή πραγματικού brand ή την τοποθέτηση credential collection πίσω από άσχετο third party.

## Domain fronting και domainless fronting

Με το κλασικό **domain fronting (T1090.004)**, η TLS connection διαφημίζει ένα επιτρεπόμενο front domain στο SNI, ενώ το κρυπτογραφημένο HTTP `Host` ή HTTP/2 `:authority` ζητά διαφορετικό back-end domain. Ένα cooperating CDN κάνει routing με βάση την εσωτερική τιμή. Ένας network observer χωρίς TLS decryption βλέπει το front· το CDN βλέπει και τις δύο τιμές, καθώς και το origin. Στις domainless παραλλαγές, το SNI μπορεί να είναι κενό, ενώ ένα άλλο routing field επιλέγει τον προορισμό.<sup>[[4]](#references)</sup>

Αυτό δεν είναι μαγική impersonation: λειτουργεί μόνο όταν ο intermediary επιτρέπει σκόπιμα ή κατά λάθος την ασυμφωνία και γνωρίζει πώς να κάνει routing στο εσωτερικό όνομα. Οι major providers έχουν περιορίσει το cross-account fronting. Το Encrypted ClientHello (ECH) αλλάζει όσα μπορεί να δει ένας on-path observer, αλλά δεν διαγράφει τα CDN, endpoint ή application records.

Τα detection points περιλαμβάνουν:

- endpoint process ancestry και destination που δεν αναμένονται για τη συγκεκριμένη application·
- ασυμφωνία μεταξύ SNI και HTTP authority, όπου το TLS inspection είναι νόμιμο και διαθέσιμο·
- CDN logs που δείχνουν ένα tenant/front να κάνει routing προς άλλο authority/origin·
- ασυνήθιστες long-lived ή περιοδικές sessions προς μια κανονικά interactive service·
- σταθερά encrypted flow sizes και cadence μεταξύ front domains που αλλάζουν.

Το ασφαλές lab προσομοιώνει το routing mismatch σε owned reverse proxy· δεν κάνει abuse ενός public CDN.

## Dynamic resolution: DDNS, DGA και fast flux

Το dynamic resolution αποσυνδέει μια logical service από fixed infrastructure:

- **DDNS:** ένας authenticated client ενημερώνει ένα stable name μετά την αλλαγή της address του.
- **DGA:** τόσο το endpoint όσο και το controller παράγουν candidate domain names από ένα time/key seed· ο operator κάνει register μόνο ένα μικρό subset.
- **Fast flux:** ένα name επιστρέφει ένα σύνολο από rapidly changing compromised/proxy addresses, συχνά με low TTLs.
- **Double flux:** περιστρέφονται τόσο οι service addresses όσο και οι authoritative name-server addresses, αποκρύπτοντας και το control layer.

Το fast flux είναι ένα load-distribution pattern που χρησιμοποιείται adversarially, όχι απλώς «πολλές DNS answers». Ισχυρότερα στοιχεία συνδυάζουν low TTL, μεγάλο αριθμό unique addresses, ευρεία διασπορά ASN/geography, σύντομο node lifetime, επαναλαμβανόμενη application behavior και ύποπτο registration history. Τα CDN μοιράζονται νόμιμα αρκετές από αυτές τις ιδιότητες. Το MITRE συνιστά τη συσχέτιση της DNS behavior με το process και τις subsequent connections.<sup>[[5]](#references)</sup>

Ένα DGA μπορεί να ανιχνευθεί μέσω lexical entropy, consonant/digit patterns, bursts από NXDOMAIN, synchronized first-seen domains και process context. Τα wordlist DGAs και τα generative models παρακάμπτουν απλούς entropy rules, καθιστώντας σημαντικότερο το fleet-wide temporal clustering και το endpoint lineage.

## Compromised domains και domain shadowing

Ένας actor μπορεί να κάνει hijack σε registrar/DNS account, να αναλάβει ένα dangling subdomain ή να προσθέσει records κάτω από ένα κατά τα άλλα reputable domain. Το **domain shadowing** διατηρεί το νόμιμο apex, ενώ μεγάλοι αριθμοί attacker-controlled subdomains δείχνουν σε μεταβαλλόμενα delivery ή C2 hosts. Δανείζεται age και reputation και μπορεί να παρακάμψει το domain-wide blocking.<sup>[[6]](#references)</sup>

Οι defenders χρειάζονται registrar και authoritative-DNS audit logs, MFA, registry/registrar locks, alerts για νέα delegations/API tokens/name servers, certificate-transparency monitoring και inventory των cloud resources που αναφέρονται από το DNS. Ερευνήστε το resolution και το certificate history ενός subdomain ανεξάρτητα από το reputation του apex.

## Web services και dead-drop resolvers

Ένας **dead-drop resolver (T1102.001)** αποθηκεύει έναν encoded pointer προς το τρέχον C2 μέσα σε ένα legitimate post, profile, document, repository, cloud object ή blockchain field. Το malware κάνει fetch το public object, αποκωδικοποιεί ένα domain/IP και επικοινωνεί με το επόμενο stage. Bidirectional variants ανταλλάσσουν commands ή files μέσω service APIs.<sup>[[7]](#references)</sup>

Αυτό παρέχει resilience και αποκρύπτει το back-end C2 από static binary analysis. Δημιουργεί επίσης stable object, tenant, repository, API και access-pattern identifiers. Οι defenders πρέπει να συσχετίζουν:

1. το process που επικοινώνησε με τη service·
2. το ακριβές API path/object και το response hash·
3. τη decoding ή string-processing activity·
4. τη νέα outbound connection λίγο αργότερα· και
5. την ίδια behavior αλλού στο fleet.

Το blocking όλων των GitHub, cloud storage ή social media σπάνια είναι βιώσιμο. Το service-aware egress policy και το process-level correlation αποδίδουν καλύτερα από το domain-only blocking.

## Personas, accounts και procurement compartments

Η υποδομή anonymity αποτυγχάνει όταν ένα persona, recovery email, phone, payment, browser ή admin IP συνδέει compartments. State-linked operations έχουν καλλιεργήσει social profiles, email identities και cloud accounts πολύ πριν από τη χρήση τους· το ATT&CK το καταγράφει ως Establish Accounts (T1585), συμπεριλαμβανομένων social, email και cloud sub-techniques.<sup>[[8]](#references)</sup>

Ένας defender ή investigator δημιουργεί ένα graph από:

- creation και first-login time, locale, time zone και working schedule·
- recovery fields, MFA devices, identity documents και payment instruments·
- browser/TLS fingerprints και source-network history·
- avatar reuse, image provenance, writing style και social-graph growth·
- shared domain registrant, name server, certificate, analytics ID ή repository commit·
- management-plane actions που παρακάμπτουν την architecture του public relay.

Για ένα authorized red team, τα synthetic personas πρέπει να τεκμηριώνονται προς τον exercise controller, να χρησιμοποιούν organization-owned recovery/payment channels, να αποφεύγουν την impersonation πραγματικών μη εμπλεκόμενων ατόμων και να έχουν προγραμματισμένο retirement. Το SOC μπορεί να παραμείνει blind· η operation δεν πρέπει να γίνει unaccountable.

## Emerging compound patterns προς threat-model

Τα παρακάτω είναι **defender-driven compositions**, όχι ισχυρισμοί ότι κάποιος named actor έχει αναπτύξει κάθε ακριβή design. Συνδυάζουν primitives που έχουν ήδη παρατηρηθεί και είναι χρήσιμα ως purple-team hypotheses.

### Asymmetric one-way tasking

Τα commands φτάνουν μέσω μιας public, broadcast ή append-only source, ενώ τα results εξέρχονται μέσω ενός unrelated channel μετά από καθυστέρηση. Παραδείγματα του primitive περιλαμβάνουν web-service one-way communication και dead drops. Ο διαχωρισμός εμποδίζει ένα single flow να φαίνεται bidirectional και δυσκολεύει το απλό request/response correlation.<sup>[[9]](#references)</sup>

**Detection:** διατηρήστε object-level reads και στη συνέχεια συσχετίστε process state changes και μεταγενέστερα outbound transfers σε μεγαλύτερο χρονικό παράθυρο. Αναζητήστε ένα σπάνιο process που διαβάζει το ίδιο public object, ακόμη και όταν δεν ακολουθεί άμεση reply.

### Multi-stage channel promotion

Ένα ήσυχο first stage πραγματοποιεί inventory και προωθεί μόνο επιλεγμένα systems σε ένα unrelated second-stage channel. Το δεύτερο endpoint, protocol και process μπορεί να μη μοιράζεται καμία infrastructure με το πρώτο. Αυτό περιορίζει την έκθεση capable infrastructure και μοντελοποιείται ρητά ως ATT&CK T1104.<sup>[[10]](#references)</sup>

**Detection:** συσχετίστε `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`· μην κλείνετε το incident μετά το blocking του πρώτου domain.

### Cross-protocol relay translation

Διαφορετικά hops μεταφράζουν HTTPS, QUIC, WebSocket, DNS, SSH ή ένα message-queue API, αντί να προωθούν διαφανώς packets. Η μετάφραση αφαιρεί ένα single end-to-end protocol fingerprint, αλλά δημιουργεί gateways με distinctive timing, buffering και semantic conversion. Το protocol tunneling (T1572) μπορεί να συνδυαστεί με proxies και service impersonation.<sup>[[11]](#references)</sup>

**Detection:** αναζητήστε gateway hosts που λαμβάνουν ένα protocol και ξεκινούν ένα άλλο, με tightly coupled byte/time behavior· συγκρίνετε το endpoint intent με το protocol που πραγματικά μεταφέρεται.

### Passive activation on edge devices

Αντί να κάνει beaconing, ένα implant παρακολουθεί traffic που ήδη φτάνει σε router/VPN και ενεργοποιείται μόνο από μια magic value, source-port pattern ή authenticated token. Η κανονική traffic συνεχίζει προς την πραγματική service. Το ATT&CK το ονομάζει Traffic Signaling (T1205), με documented network-device και APT examples.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture κατά τη διάρκεια authorized hunt, unexpected socket filters και differential service behavior. Η απουσία periodic beacon δεν αποδεικνύει ότι ένα edge device είναι clean.

### Serverless και ephemeral origin rotation

Ένα front διατηρεί stable logical identity, ενώ short-lived functions/containers χειρίζονται μεμονωμένα stages σε αρκετές regions/accounts. Αυτό μειώνει το disk lifetime και τα fixed origin IPs, αλλά τα control-plane creation, image/layer, role, secret, request ID και billing telemetry γίνονται το durable graph.

**Detection:** διατηρήστε τα cloud audit και invocation logs εκτός του workload· ομαδοποιήστε deployment templates, roles, environment keys και front-to-origin relationships.

### Privacy-layer diversity

Μια operation μπορεί σκόπιμα να αποφεύγει ένα homogeneous chain: για παράδειγμα, ένα channel χρησιμοποιεί leased relay, το tasking χρησιμοποιεί public object, ένα exit προέρχεται από owned lab cellular link και η administration χρησιμοποιεί ξεχωριστό organization network. Αυτό μειώνει την αξία του compromising ενός provider, αλλά αυξάνει το cross-layer timing και το operational-error risk.

**Detection:** δημιουργήστε campaign timelines σε identity, DNS, SaaS, network και cloud sensors. Αναζητήστε synchronized state transitions αντί για identical indicators.

### Decentralized ή transparency-log dead drops

Ένας actor μπορεί να τοποθετήσει έναν μικρό encrypted pointer σε οποιοδήποτε durable public append-only system, content-addressed store ή transparency-like feed. Το public object είναι resilient, αλλά το ακριβές index/content hash και το client polling behavior γίνονται stable identifiers.

**Detection:** καταγράψτε πλήρη API/object identifiers και response hashes· δημιουργήστε alerts για nonstandard processes που κάνουν polling immutable objects και ακολουθούνται από decoding ή νέες connections.

### Delayed store-and-forward operations

Το interactive C2 δημιουργεί ισχυρό timing correlation. Ένα store-and-forward design κάνει batching σε encrypted jobs και επιστρέφει results λεπτά ή ώρες αργότερα μέσω διαφορετικού queue ή physical transfer. Θυσιάζει responsiveness για ασθενέστερο end-to-end timing.

**Detection:** διευρύνετε τα correlation windows, μοντελοποιήστε το periodic queue access και εξετάστε το endpoint staging. Το batching μετακινεί το signal από το packet timing στη scheduled process/file behavior· δεν το εξαφανίζει.

## Design review: σκεφτείτε με βάση τους observers

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

Αν ένας ordinary provider μπορεί να συμπληρώσει κάθε στήλη, η architecture παρέχει concealment από το target, αλλά όχι robust separation. Αν κανένας internal controller δεν μπορεί να αντιστοιχίσει τη δραστηριότητα σε ένα engagement, είναι ακατάλληλη για professional red teaming.

## References

- [1] [MITRE ATT&CK — Απόκτηση Infrastructure (T1583), Compromise Infrastructure (T1584) και Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — Actors espionage με nexus την Κίνα χρησιμοποιούν ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
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
- [13] [Google Threat Intelligence Group — Disrupting the World's Largest Residential Proxy Network](https://cloud.google.com/blog/topics/threat-intelligence/disrupting-largest-residential-proxy-network)
- [14] [Unit 42 — The Shadow Campaigns: Uncovering Global Espionage](https://unit42.paloaltonetworks.com/shadow-campaigns-uncovering-global-espionage/)
{{#include ../banners/hacktricks-training.md}}
