# Attribution, Detection and Countermeasures

{{#include ../banners/hacktricks-training.md}}

Η υποδομή αποφυγής attribution έχει σχεδιαστεί ώστε οι επιμέρους indicators να μπορούν να απορρίπτονται. Οι defenders πρέπει να διατηρούν τα raw evidence, να μοντελοποιούν τις σχέσεις και να αναζητούν behavior που επιβιώνει μετά την αλλαγή IP, domain ή persona.

## Ιεραρχία evidence

| Evidence | Χρήσιμο για | Κύρια επιφύλαξη |
|---|---|---|
| Source IP/ASN/geolocation | εντοπισμό του ορατού exit και του provider | το exit μπορεί να είναι relay, NAT ή victim· η geolocation είναι κατά προσέγγιση |
| Passive DNS/registration | ιστορικό υποδομής και co-hosting | το privacy/redaction και το shared hosting δημιουργούν κενά |
| Certificate/TLS/HTTP fingerprint | ομαδοποίηση επαναλαμβανόμενων deployments | το κοινό software και το mimicry δημιουργούν false positives |
| Flow timing και byte shape | σύνδεση σταδίων relay και επαναλαμβανόμενων beacons | τα CDN/NAT και η περιορισμένη ορατότητα μειώνουν τη βεβαιότητα |
| Endpoint process/identity | εξήγηση του λόγου για τον οποίο πραγματοποιήθηκε μια σύνδεση | δεν υπάρχει σε edge/IoT· ο attacker μπορεί να χρησιμοποιεί native tools |
| Cloud/CDN/API audit | αναγνώριση του tenant και του ελέγχου της υποδομής | η διατήρηση δεδομένων και η πρόσβαση μέσω provider/legal διαδικασιών διαφέρουν |
| Payment/account/device | σύνδεση της προμήθειας με ένα άτομο/οντότητα | πρέπει να λαμβάνονται υπόψη nominee, compromise και shared devices |
| Seized implant/configuration | αποκάλυψη keys, peers, controllers και build links | η ακεραιότητα της συλλογής και ο χρόνος κατάσχεσης έχουν σημασία |
| Human/physical evidence | σύνδεση ενός digital event με τόπο/operator | είναι intrusive, εξαρτάται από τη δικαιοδοσία και απαιτεί αυστηρό χειρισμό |

Καμία μεμονωμένη γραμμή δεν πρέπει να υποστηρίζει attribution κρατικού actor με υψηλή βεβαιότητα. Χρησιμοποιήστε ανταγωνιστικές υποθέσεις και δηλώστε ποια παρατήρηση θα διέψευδε καθεμία.

## Ελάχιστη τηλεμετρία

1. **DNS:** client, question, type, answers, TTL, response code, resolver και timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags και sensor location.
3. **TLS/HTTP:** SNI όταν είναι ορατό, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status και byte count. Προστατέψτε τα ευαίσθητα full URLs.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID και risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash και destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface και flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token και result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP και posture.

Συγχρονίστε τα clocks, διατηρήστε τα original time zones, τεκμηριώστε τα όρια NAT/proxy και διατηρήστε αρκετό ιστορικό ώστε να ξεπερνά τη διάρκεια ζωής ενός ORB node 31 ημερών.

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

Η πυκνότητα του graph από μόνη της είναι παραπλανητική: ένα CDN ή certificate authority συνδέει πολλούς άσχετους actors. Δώστε μεγαλύτερο βάρος σε σπάνιες σχέσεις που ελέγχονται από τον operator—το ίδιο API account, SSH key, origin allowlist, μοναδικό response body ή control protocol—και μικρότερο σε συνηθισμένο hosting.

## ORB και hunting παραβιασμένων router

### Από ένα observed exit

1. Προσδιορίστε αν η διεύθυνση αφορά hosting, residential, mobile, education ή business· μην απορρίπτετε residential sources.
2. Συλλέξτε historical DNS, services/certificates, open ports και observed scan/exploitation behavior για μια οριοθετημένη περίοδο.
3. Αναζητήστε peers που μοιράζονται rare service fingerprints, controller destinations, certificate material ή rotation timing.
4. Κατηγοριοποιήστε τους πιθανούς ρόλους: access, traversal, exit/staging ή administration.
5. Ελέγξτε αν πολλά unrelated intrusion clusters χρησιμοποίησαν το ίδιο pool· η multi-tenancy αποδυναμώνει την άμεση attribution σε actor, αλλά ενισχύει την υπόθεση ORB.
6. Παρακολουθήστε νέα nodes που ταιριάζουν στο role profile αφού εξαφανιστούν τα παλιά IPs.

### Στον network owner

- Δημιουργήστε alert για νέο Internet-exposed management και default/legacy authentication.
- Στέλνετε τις αλλαγές configuration του router/firewall/VPN και το admin authentication εκτός συσκευής.
- Δημιουργήστε baseline για outbound connections από infrastructure που κανονικά ξεκινά λίγα sessions.
- Εντοπίζετε νέα proxy/listener processes, tunnels, scheduled tasks, firmware changes και unexpected DNS.
- Αντικαταστήστε end-of-life devices· ένα reboot που αφαιρεί volatile malware δεν διορθώνει το exposure.
- Περιορίστε το management σε authenticated administration plane και known sources.

Η Mandiant συνιστά την παρακολούθηση της ORB infrastructure ως evolving entity, επειδή το βραχυπρόθεσμο IP blocking δεν αποτυπώνει την topology και τον κύκλο ζωής.<sup>[[1]](#references)</sup>

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
Διερευνήστε domains με αρκετά ανεξάρτητα χαρακτηριστικά, όχι με βάση ένα μόνο threshold. Συγκρίνετε με ένα allow-model CDN/anti-DDoS και ελέγξτε την εναλλαγή των authoritative name servers για να διακρίνετε το single από το double flux. Για τα DGA, προσθέστε bursts από NXDOMAIN ανά client, κατανομή μήκους/χαρακτήρων, συγχρονισμένα queries μεταξύ hosts και τη διεργασία που τα δημιουργεί. Η τρέχουσα καθοδήγηση του MITRE δίνει επίσης έμφαση σε αλλαγές υψηλής συχνότητας, χαμηλό TTL και συσχέτιση διεργασίας/δικτύου.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Όπου το enterprise endpoint ή ένα εξουσιοδοτημένο σημείο επιθεώρησης έχει και τις δύο ταυτότητες, συγκρίνετε:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Αυξήστε την εμπιστοσύνη όταν τα SNI και authority ανήκουν σε μη σχετιζόμενους tenants, η διεργασία δεν είναι εγκεκριμένος client, η συνεδρία είναι περιοδική/μακράς διάρκειας και το εσωτερικό origin είναι σπάνιο. Το κενό SNI είναι στοιχείο προς καταγραφή και όχι αυτόματα κακόβουλο. Το ECH μπορεί να αποκρύπτει το SNI στο wire, επομένως τα logs των endpoints, του DNS και του provider/CDN γίνονται σημαντικότερα. Το MITRE τεκμηριώνει τόσο τις παραλλαγές με mismatched όσο και με blank-SNI.<sup>[[3]](#references)</sup>

## Ανίχνευση ακολουθίας dead-drop resolver

Η συμπεριφορά υψηλού σήματος είναι μια ακολουθία και όχι ένα blocked domain:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Αναζητήστε σε ολόκληρο τον στόλο identical object paths, response hashes, API identifiers και follow-on destinations. Διατηρήστε το περιεχόμενο που ανακτήθηκε, επειδή ο actor μπορεί να το επεξεργαστεί ή να το διαγράψει. Περιορίστε τα μη απαραίτητα service APIs και απαιτήστε από τις εγκεκριμένες εφαρμογές να χρησιμοποιούν enterprise proxies, λαμβάνοντας όμως υπόψη τα developer tools και το automation. Το MITRE αναφέρει GitHub, forums, documents και social/web services σε πραγματικές διαδικασίες.<sup>[[4]](#references)</sup>

## Ομαδοποίηση Redirector και επαναχρησιμοποιήσιμων deployments

Ακόμη και όταν αλλάζουν τα domains και οι διευθύνσεις, οι operators συχνά επαναχρησιμοποιούν το ίδιο automation. Κάντε clustering με βάση συνδυασμούς των εξής:

- πεδία certificate/key reuse και χρόνος έκδοσης·
- έκδοση TLS/cipher/σειρά extension και συμπεριφορά server·
- identical HTTP status, σειρά headers, συμπεριφορά cache, icon/body και error page·
- ασυνήθιστα ζεύγη ports και redirect chains·
- μοτίβο DNS provider/name-server και πρόγραμμα TTL·
- χρόνος deployment, uptime και παράθυρο maintenance·
- έκθεση back-end origin ή identical allowlists.

Μία γενική σελίδα Nginx αποτελεί ασθενές evidence. Αρκετές σπάνιες, ανεξάρτητες συμπτώσεις, σε συνδυασμό με temporal continuity, μπορούν να δικαιολογήσουν μια υπόθεση infrastructure cluster.

## Εντοπισμός Residential proxy και impossible session

Διατηρήστε την ταυτότητα του session πάνω από το επίπεδο της IP. Επισημάνετε συνδυασμούς όπως:

- ένα session/device fingerprint αλλάζει χώρες/ASNs γρηγορότερα από όσο επιτρέπει η μετακίνηση·
- μια consumer IP αλλάζει σε κάθε request, ενώ τα cookies και η ταυτότητα TLS/browser παραμένουν σταθερά·
- η δηλωμένη local συσκευή έχει latency/time-zone/language που δεν συμφωνούν με το exit·
- μια διεύθυνση εναλλάσσει άσχετους πληθυσμούς accounts ή παρουσιάζει συμπεριφορά backconnect proxy·
- ένα privileged session εμφανίζεται από residential access χωρίς το device certificate του οργανισμού.

Το Carrier NAT, τα accessibility tools, τα corporate VPNs και τα ταξίδια δημιουργούν καλοήθεις ανωμαλίες. Απαιτήστε step-up authentication ή investigation αντί για μη αναστρέψιμο blocking που βασίζεται αποκλειστικά σε labels «residential proxy».

## Εντοπισμός Wireless και covert devices

Συνδυάστε RADIUS/NAC με το πλαίσιο των AP και του φυσικού χώρου:

1. εντοπίστε τους συνδυασμούς account–device–AP που εμφανίζονται για πρώτη φορά·
2. εντοπίστε credentials που χρησιμοποιούνται χωρίς managed EAP certificate/posture·
3. συγκρίνετε concurrent sessions και παρουσία badge/building·
4. εξετάστε ασυνήθιστα ασθενές/οριακό signal και τη μετακίνηση μεταξύ APs·
5. αναζητήστε σε κοντινά managed endpoints wireless scanning, newly enabled interface bridge/NAT, virtual adapters ή tunnels·
6. καταγράψτε νέα δραστηριότητα σε switchport, DHCP, USB network και PoE·
7. εκτελέστε εξουσιοδοτημένο RF/physical sweep όταν τα στοιχεία το υποστηρίζουν.

Αυτό εντοπίζει τόσο μια διαδρομή τύπου APT28 μέσω του πλησιέστερου neighbor όσο και ένα exercise drop. Το MAC randomization δεν πρέπει να αντιμετωπίζεται ως identity ή guilt.

## Εντοπισμός Financial attribution

- Διατηρήστε την ακριβή chain, token, address, transaction και block identifiers.
- Παρακολουθήστε την αξία μέσω change, peel chains, fan-out/in, mixers, bridges και service deposits, επισημαίνοντας τα heuristics.
- Συσχετίστε τον χρόνο, το ποσό μείον τα fees, το contract event, τη liquidity και το withdrawal στο destination chain.
- Αποκτήστε ή διατηρήστε lawful exchange, bridge, merchant, account, device και delivery records.
- Ελέγξτε τις τρέχουσες sanctioned entities/addresses και τα derivatives βάσει του ισχύοντος προγράμματος· μην βασίζεστε σε παλιά static list.
- Αντιμετωπίστε τη χρήση privacy protocols ως input για το risk context και όχι ως απόδειξη wrongdoing.

Τα red flags του FATF είναι ρητά contextual: ασυνήθιστο pattern, amount/frequency, geography, source of funds και anonymity-enhancing services αποκτούν σημασία όταν συνυπάρχουν.<sup>[[5]](#references)</sup>

## Deception και canaries

Οι defenders μπορούν να δημιουργήσουν high-confidence signals χωρίς να προσπαθούν να deanonymize ordinary users:

- μοναδικά credentials ή documents που δεν θα έπρεπε ποτέ να εγκαταλείψουν ένα σύστημα·
- fake administrative endpoints και decoy shares·
- instrumented DNS names ενσωματωμένα μόνο σε controlled artifacts·
- canary cloud keys χωρίς legitimate use·
- ένα decoy Wi-Fi identity που δεν κατέχει καμία managed device.

Ορίστε και διαχειριστείτε προσεκτικά το scope του deception. Ένα canary πρέπει να εντοπίζει misuse του asset του ίδιου του defender και όχι να συλλέγει άσχετη traffic τρίτων.

## Προτεραιότητες Countermeasure

1. Αφαιρέστε routers, VPNs και appliances που εκτίθενται στο Internet χωρίς υποστήριξη.
2. Απαιτήστε phishing-resistant MFA και device-bound certificates, συμπεριλαμβανομένης της internal/wireless access.
3. Συγκεντρώστε immutable-enough identity, endpoint, DNS, flow, proxy, cloud και network-device logs.
4. Περιορίστε το management και το egress· καταγράψτε κάθε externally reachable service.
5. Παρακολουθήστε DNS, certificate transparency και cloud configuration για unauthorized assets.
6. Διατηρήστε process-to-network και object-level SaaS visibility.
7. Ασκηθείτε σε cross-layer investigations και coordination με neighboring providers.
8. Παρακολουθείτε infrastructure clusters και behaviors, όχι μόνο IP blocklists.

## Analytical discipline

Χρησιμοποιήστε γλώσσα confidence:

- **Observed:** η εγγραφή sensor/provider εμφανίζει άμεσα τη σχέση.
- **Strongly supported:** πολλαπλές ανεξάρτητες παρατηρήσεις την υποστηρίζουν έναντι των εναλλακτικών.
- **Assessed:** inference που βασίζεται σε δηλωμένες assumptions και evidence.
- **Unknown:** η ελλιπής visibility δεν επιτρέπει συμπέρασμα.

Διατηρείτε πάντα τουλάχιστον δύο hypotheses: actor-operated infrastructure έναντι compromised/shared intermediary· ένας actor έναντι multi-tenant service· deliberate evasion έναντι legitimate privacy/CDN behavior. Η δυνατότητα εξήγησης της αβεβαιότητας αποτελεί μέρος ενός correct detection.

## References

- [1] [Google Cloud/Mandiant — Actors κατασκοπείας με nexus την Κίνα χρησιμοποιούν δίκτυα ORB](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Ενδείξεις κινδύνου για Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — Actors της ΛΔΚ παραβιάζουν και διατηρούν επίμονη πρόσβαση](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Καθοδήγηση για ενισχυμένη visibility και hardening σε communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
