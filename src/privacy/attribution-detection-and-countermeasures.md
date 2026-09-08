# Υποδομή Attribution, Detection και Countermeasures

Η υποδομή αποφυγής attribution έχει σχεδιαστεί ώστε οι individual indicators να είναι αναλώσιμοι. Οι defenders θα πρέπει να διατηρούν τα raw evidence, να μοντελοποιούν τις σχέσεις και να αναζητούν behavior που επιβιώνει από την αλλαγή IP, domain ή persona.

## Ιεραρχία evidence

| Evidence | Χρήσιμο για | Κύριο caveat |
|---|---|---|
| Source IP/ASN/geolocation | εντοπισμό του ορατού exit και του provider | το exit μπορεί να είναι relay, NAT ή victim· η geolocation είναι κατά προσέγγιση |
| Passive DNS/registration | ιστορικό infrastructure και co-hosting | το privacy/redaction και το shared hosting δημιουργούν κενά |
| Certificate/TLS/HTTP fingerprint | ομαδοποίηση επαναλαμβανόμενων deployments | το common software και το mimicry δημιουργούν false positives |
| Flow timing και byte shape | συσχέτιση relay stages και επαναλαμβανόμενων beacons | τα CDNs/NAT και η περιορισμένη ορατότητα μειώνουν τη βεβαιότητα |
| Endpoint process/identity | εξήγηση του λόγου για τον οποίο πραγματοποιήθηκε μια σύνδεση | δεν υπάρχει σε edge/IoT· ο attacker μπορεί να χρησιμοποιεί native tools |
| Cloud/CDN/API audit | αναγνώριση του tenant και του infrastructure control | η διατήρηση δεδομένων και η πρόσβαση μέσω provider/legal διαδικασιών διαφέρουν |
| Payment/account/device | σύνδεση του procurement με ένα άτομο/οντότητα | πρέπει να εξετάζονται nominee, compromise και shared devices |
| Seized implant/configuration | αποκάλυψη keys, peers, controllers και build links | η ακεραιότητα της συλλογής και ο χρόνος της κατάσχεσης έχουν σημασία |
| Human/physical evidence | σύνδεση του digital event με τοποθεσία/operator | παρεμβατικό, εξαρτάται από τη jurisdiction και απαιτεί αυστηρό χειρισμό |

Καμία μεμονωμένη γραμμή δεν θα πρέπει να υποστηρίζει attribution κρατικής προέλευσης με υψηλή βεβαιότητα. Χρησιμοποιήστε competing hypotheses και δηλώστε ποια παρατήρηση θα διέψευδε καθεμία.

## Ελάχιστη telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver και timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags και sensor location.
3. **TLS/HTTP:** SNI όταν είναι ορατό, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status και byte count. Προστατεύστε τα ευαίσθητα full URLs.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID και risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash και destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface και flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token και result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP και posture.

Συγχρονίστε τα clocks, διατηρήστε τα original time zones, τεκμηριώστε τα όρια NAT/proxy και διατηρήστε αρκετό ιστορικό ώστε να ξεπερνά τη διάρκεια ζωής ενός 31-day ORB node.

## Δημιουργία attribution graph

Αναπαραστήστε τις παρατηρήσεις ως typed nodes και edges:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Χρήσιμοι κόμβοι περιλαμβάνουν IP, prefix, ASN, domain, DNS account, certificate/key, fingerprint τύπου JA3/JA4, HTTP grammar, hash αρχείου/config, cloud tenant, API token, email, persona, payment instrument και physical device. Κάθε ακμή χρειάζεται `first_seen`, `last_seen`, sensor/source, confidence και ένδειξη για το αν είναι observed ή inferred.

Η πυκνότητα του graph από μόνη της είναι παραπλανητική: ένα CDN ή certificate authority συνδέει πολλούς άσχετους actors. Δώστε μεγαλύτερο βάρος σε σπάνιες σχέσεις που ελέγχονται από τον operator—το ίδιο API account, SSH key, origin allowlist, μοναδικό response body ή control protocol—και μικρότερο βάρος στο κοινό hosting.

## ORB και hunting παραβιασμένων routers

### Από ένα observed exit

1. Προσδιορίστε αν η διεύθυνση αφορά hosting, residential, mobile, education ή business· μην απορρίπτετε residential sources.
2. Συλλέξτε historical DNS, services/certificates, open ports και observed scan/exploitation behavior για μια καθορισμένη χρονική περίοδο.
3. Αναζητήστε peers που μοιράζονται rare service fingerprints, controller destinations, certificate material ή rotation timing.
4. Κατηγοριοποιήστε τους πιθανούς ρόλους: access, traversal, exit/staging ή administration.
5. Ελέγξτε αν πολλά unrelated intrusion clusters χρησιμοποίησαν το ίδιο pool· το multi-tenancy αποδυναμώνει το direct actor attribution, αλλά ενισχύει την υπόθεση ORB.
6. Παρακολουθήστε νέα nodes που ταιριάζουν στο role profile μετά την εξαφάνιση των παλιών IPs.

### Στον network owner

- Ενεργοποιήστε alerts για νέα Internet-exposed management interfaces και default/legacy authentication.
- Στέλνετε τις αλλαγές σε router/firewall/VPN configuration και τα admin authentication events εκτός συσκευής.
- Δημιουργήστε baseline για outbound connections από infrastructure που κανονικά ξεκινά λίγες sessions.
- Εντοπίζετε νέα proxy/listener processes, tunnels, scheduled tasks, firmware changes και μη αναμενόμενο DNS.
- Αντικαταστήστε end-of-life devices· ένα reboot που αφαιρεί volatile malware δεν διορθώνει την έκθεση.
- Περιορίστε το management σε authenticated administration plane και γνωστές sources.

Η Mandiant συνιστά την παρακολούθηση του ORB infrastructure ως evolving entity, επειδή το short-lived IP blocking δεν αποτυπώνει την topology και το lifecycle.<sup>[[1]](#references)</sup>

## Fast-flux και dynamic-DNS analytics

Κάντε aggregate ανά registered domain και sliding window. Ένα πρακτικό score μπορεί να συνδυάζει:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Ερευνήστε domains με αρκετά ανεξάρτητα χαρακτηριστικά, όχι βάσει ενός μόνο threshold. Συγκρίνετε με ένα CDN/anti-DDoS allow-model και ελέγξτε την εναλλαγή authoritative name-server για να διακρίνετε το single από το double flux. Για DGAs, προσθέστε bursts από NXDOMAIN ανά client, την κατανομή μήκους/χαρακτήρων, συγχρονισμένα queries μεταξύ hosts και τη διαδικασία που τα δημιουργεί. Η τρέχουσα καθοδήγηση του MITRE δίνει επίσης έμφαση σε αλλαγές υψηλής συχνότητας, χαμηλό TTL και συσχέτιση process/network.<sup>[[2]](#references)</sup>

## Ανίχνευση domain-fronting

Όπου το enterprise endpoint ή ένα authorized inspection point διαθέτει και τις δύο ταυτότητες, συγκρίνετε:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Αυξήστε την εμπιστοσύνη όταν το SNI και το authority ανήκουν σε μη σχετιζόμενους tenants, η διεργασία δεν είναι εγκεκριμένος client, το session είναι περιοδικό/μακρόβιο και το inner origin είναι σπάνιο. Το κενό SNI είναι ένα χαρακτηριστικό που πρέπει να καταγράφεται και δεν είναι αυτόματα κακόβουλο. Το ECH ενδέχεται να αποκρύπτει το SNI στο wire, επομένως τα logs του endpoint, του DNS και του provider/CDN γίνονται σημαντικότερα. Το MITRE τεκμηριώνει τόσο τις παραλλαγές με mismatch όσο και τις παραλλαγές με blank-SNI.<sup>[[3]](#references)</sup>

## Ανίχνευση ακολουθιών dead-drop resolver

Η συμπεριφορά υψηλού σήματος είναι μια ακολουθία και όχι ένα blocked domain:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Αναζητήστε σε ολόκληρο τον στόλο identical object paths, response hashes, API identifiers και follow-on destinations. Διατηρήστε το περιεχόμενο που ανακτήθηκε, επειδή ο actor μπορεί να το επεξεργαστεί ή να το διαγράψει. Περιορίστε τα μη απαραίτητα service APIs και απαιτήστε από τις εγκεκριμένες εφαρμογές να χρησιμοποιούν enterprise proxies, λαμβάνοντας όμως υπόψη τα developer tools και το automation. Το MITRE παραθέτει GitHub, forums, documents και social/web services σε πραγματικές διαδικασίες.<sup>[[4]](#references)</sup>

## Clustering Redirector και reusable-deployment

Ακόμη και όταν αλλάζουν τα domains και οι addresses, οι operators συχνά κάνουν redeploy το ίδιο automation. Δημιουργήστε clusters με βάση συνδυασμούς των εξής:

- πεδία certificates/key reuse και χρόνος έκδοσης·
- έκδοση TLS/cipher/σειρά extensions και συμπεριφορά server·
- identical HTTP status, σειρά headers, συμπεριφορά cache, icon/body και error page·
- ασυνήθιστες ζεύξεις ports και redirect chains·
- μοτίβο DNS provider/name-server και πρόγραμμα TTL·
- χρόνος deployment, uptime και maintenance window·
- έκθεση back-end origin ή identical allowlists.

Μία μεμονωμένη generic σελίδα Nginx αποτελεί αδύναμο στοιχείο. Αρκετές σπάνιες, ανεξάρτητες συμπτώσεις, σε συνδυασμό με temporal continuity, μπορούν να τεκμηριώσουν μια υπόθεση infrastructure cluster.

## Ανίχνευση Residential Proxy και impossible-session

Διατηρήστε την ταυτότητα της session πάνω από το επίπεδο της IP. Επισημάνετε συνδυασμούς όπως:

- το fingerprint μίας session/device αλλάζει χώρες/ASNs ταχύτερα από όσο επιτρέπει η φυσιολογική μετακίνηση·
- μία consumer IP αλλάζει σε κάθε request, ενώ τα cookies και η ταυτότητα TLS/browser παραμένουν σταθερά·
- η δηλωμένη τοπική συσκευή έχει latency/time-zone/language που δεν συμφωνεί με το exit·
- μία address εναλλάσσει άσχετους πληθυσμούς accounts ή παρουσιάζει συμπεριφορά backconnect proxy·
- μία privileged session εμφανίζεται από residential access χωρίς το device certificate του οργανισμού.

Το Carrier NAT, τα accessibility tools, τα corporate VPNs και τα ταξίδια δημιουργούν καλοπροαίρετες ανωμαλίες. Απαιτήστε step-up authentication ή investigation αντί για μη αναστρέψιμο blocking που βασίζεται αποκλειστικά σε labels “residential proxy”.

## Ανίχνευση Wireless και covert-device

Συνδυάστε το RADIUS/NAC με το AP και το φυσικό πλαίσιο:

1. εντοπίστε συνδυασμούς account–device–AP που εμφανίζονται για πρώτη φορά·
2. εντοπίστε credentials που χρησιμοποιούνται χωρίς managed EAP certificate/posture·
3. συγκρίνετε concurrent sessions και παρουσία σε badge/building·
4. εξετάστε ασυνήθιστα ασθενές/οριακό signal και μετακίνηση μεταξύ APs·
5. αναζητήστε σε κοντινά managed endpoints wireless scanning, newly enabled interface bridge/NAT, virtual adapters ή tunnels·
6. καταγράψτε νέα δραστηριότητα σε switchport, DHCP, USB network και PoE·
7. πραγματοποιήστε εξουσιοδοτημένο RF/physical sweep όταν τα στοιχεία το υποστηρίζουν.

Αυτό εντοπίζει τόσο ένα nearest-neighbor path τύπου APT28 όσο και ένα exercise drop. Το MAC randomization δεν πρέπει να αντιμετωπίζεται ως ταυτότητα ή ενοχή.

## Ανίχνευση Financial-attribution

- Διατηρήστε την ακριβή chain, token, address, transaction και block identifiers.
- Παρακολουθήστε την αξία μέσω change, peel chains, fan-out/in, mixers, bridges και service deposits, επισημαίνοντας τα heuristics.
- Συσχετίστε χρόνο, ποσό μείον fees, contract event, liquidity και withdrawal στο destination-chain.
- Αποκτήστε ή διατηρήστε νόμιμα exchange, bridge, merchant, account, device και delivery records.
- Ελέγχετε τις τρέχουσες sanctioned entities/addresses και τα derivatives στο πλαίσιο του ισχύοντος προγράμματος· μην βασίζεστε σε παλιά static list.
- Αντιμετωπίστε τη χρήση privacy-protocol ως input του risk context και όχι ως απόδειξη wrongdoing.

Τα red flags του FATF είναι ρητά contextual: unusual pattern, amount/frequency, geography, source of funds και anonymity-enhancing services αποκτούν σημασία όταν εξετάζονται μαζί.<sup>[[5]](#references)</sup>

## Deception και canaries

Οι defenders μπορούν να δημιουργήσουν signals υψηλής αξιοπιστίας χωρίς να προσπαθούν να deanonymize ordinary users:

- μοναδικά credentials ή documents που δεν θα έπρεπε ποτέ να εγκαταλείψουν ένα σύστημα·
- fake administrative endpoints και decoy shares·
- instrumented DNS names ενσωματωμένα μόνο σε controlled artifacts·
- canary cloud keys χωρίς legitimate use·
- decoy Wi-Fi identity που δεν διαθέτει καμία managed device.

Οριοθετήστε και διαχειριστείτε προσεκτικά το deception. Ένα canary πρέπει να εντοπίζει misuse ενός asset του ίδιου του defender και όχι να συλλέγει άσχετη κίνηση τρίτων.

## Προτεραιότητες Countermeasure

1. Αφαιρέστε routers, VPNs και appliances που εκτίθενται στο Internet χωρίς υποστήριξη.
2. Απαιτήστε phishing-resistant MFA και device-bound certificates, συμπεριλαμβανομένης της internal/wireless access.
3. Συγκεντρώστε immutable-enough identity, endpoint, DNS, flow, proxy, cloud και network-device logs.
4. Περιορίστε το management και το egress· καταγράψτε κάθε externally reachable service.
5. Παρακολουθείτε DNS, certificate transparency και cloud configuration για unauthorized assets.
6. Διατηρήστε process-to-network και object-level SaaS visibility.
7. Ασκηθείτε σε cross-layer investigations και neighboring-provider coordination.
8. Παρακολουθείτε infrastructure clusters και behaviors, όχι μόνο IP blocklists.

## Analytical discipline

Χρησιμοποιείτε γλώσσα confidence:

- **Observed:** το record του sensor/provider εμφανίζει άμεσα τη σχέση.
- **Strongly supported:** πολλαπλές ανεξάρτητες παρατηρήσεις την υποστηρίζουν περισσότερο από τις εναλλακτικές.
- **Assessed:** inference που βασίζεται σε δηλωμένες assumptions και evidence.
- **Unknown:** η ελλιπής visibility δεν επιτρέπει συμπέρασμα.

Διατηρείτε πάντα τουλάχιστον δύο hypotheses: actor-operated infrastructure έναντι compromised/shared intermediary· ένας actor έναντι multi-tenant service· deliberate evasion έναντι legitimate privacy/CDN behavior. Η ικανότητα εξήγησης της αβεβαιότητας αποτελεί μέρος μιας ορθής detection.

## References

- [1] [Google Cloud/Mandiant — Actors κατασκοπείας με σύνδεση με την Κίνα χρησιμοποιούν ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Red flag indicators για Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Actors της ΛΔΚ παραβιάζουν και διατηρούν persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Guidance για enhanced visibility και hardening των communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
