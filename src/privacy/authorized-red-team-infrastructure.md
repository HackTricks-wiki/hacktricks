# Υποδομή Authorized Red-Team

{{#include ../banners/hacktricks-training.md}}

Για ανθεκτικές επιτόπιες συσκευές, χρησιμοποιήστε τον σχεδιασμό [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) και το runbook για τον εντοπισμό πιθανής ανακάλυψης.

Για ένα επαγγελματικό red team, ο στόχος είναι η **ελεγχόμενη απόδοση ευθύνης**, όχι η απαλλαγή από τη λογοδοσία. Ο στόχος δεν πρέπει να βλέπει εύκολα την οικιακή IP ή τους προσωπικούς λογαριασμούς ενός operator, ενώ ο υπεύθυνος του engagement πρέπει να μπορεί να ταυτοποιήσει την προέλευση, να διακόψει την επιχείρηση, να διαχειριστεί αναφορές abuse, να διατηρήσει τα αποδεικτικά στοιχεία και να αποδείξει την authorization.

Αυτή η σελίδα αποτελεί τη βασική γραμμή ανάπτυξης για ένα lawful engagement. Για το adversary tradecraft που προορίζεται να προσομοιώσει—συμπεριλαμβανομένων των compromised ORBs, residential relays, fronting, dead drops και nearby wireless pivots—ξεκινήστε από τα [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) και [Government and APT Case Studies](government-and-apt-case-studies.md) και, στη συνέχεια, αναπαραγάγετε τα απαιτούμενα telemetry στα [authorized labs](authorized-adversary-emulation-labs.md).

Το NIST ορίζει τους κανόνες εμπλοκής (ROE) ως προκαθορισμένους περιορισμούς που παρέχουν authority για συγκεκριμένες δραστηριότητες testing.<sup>[[1]](#references)</sup> Η αρχιτεκτονική privacy δεν μπορεί να διευρύνει αυτή την authority.

## Επιλέξτε ένα μοτίβο egress

| Μοτίβο | Καλύτερη χρήση | Τι βλέπει ο στόχος | Τι βλέπει ο provider/local observer | Accountability |
|---|---|---|---|---|
| VPN/jump host που παρέχεται από τον client | Οι περισσότερες αξιολογήσεις | Εύρος διευθύνσεων του client | Ταυτότητα του client και πρόσβαση του operator | Ισχυρότερη |
| Bastion του οργανισμού red team | Επαναλήψιμο controlled egress | Εύρος διευθύνσεων του οργανισμού | Hosting provider και οργανισμός | Ισχυρό |
| VPS ειδικού engagement | Απομόνωση clients/campaigns | Διεύθυνση VPS | Λογαριασμός host, billing, control-plane και access logs | Ισχυρό, εφόσον τεκμηριώνεται |
| Εγκεκριμένο commercial VPN | Research/scanning που επιτρέπεται από τον provider και το ROE | Shared/dedicated VPN egress | Λογαριασμός VPN και source connection | Μεσαίο |
| Tor Browser | Web research που απαιτεί unlinkability από τον προορισμό | Έξοδος Tor | Το local network βλέπει Tor/bridge· ο προορισμός βλέπει Tor | Ακατάλληλο για allowlisted source attribution |
| Client-approved on-site drop | Εσωτερική simulation | On-site συσκευή/διεύθυνση | Site network και remote tunnel provider | Ισχυρό, εφόσον είναι καταγεγραμμένο |
| Lawful guest Wi-Fi | Διοικητική/research χρήση χαμηλού κινδύνου | Public IP του χώρου ή tunnel egress | Χώρος, ISP, VPN/Tor | Αδύναμο και φυσικά παρατηρήσιμο |

Για τις περισσότερες εργασίες, ένα fixed egress που παρέχεται από τον client ή ελέγχεται από τον οργανισμό είναι ασφαλέστερο και ταχύτερο από consumer anonymity services. Επιτρέπει επίσης στους defenders να κάνουν allowlist, να παρακολουθούν ή σκόπιμα να **μην** κάνουν allowlist γνωστά source ranges, σύμφωνα με τον σχεδιασμό του exercise.

## Παράρτημα υποδομής ROE

Καταγράψτε πριν από το deployment:

- τις νομικές οντότητες που παρέχουν και λαμβάνουν authorization·
- τους ακριβείς στόχους και τις ρητές εξαιρέσεις·
- τις ώρες έναρξης/λήξης, τη ζώνη ώρας και τις επιτρεπόμενες techniques·
- τα source IPs, τα ονόματα autonomous-system/provider, τα domains, τα redirectors, την mail infrastructure και τα identifiers των on-site συσκευών·
- αν επιτρέπονται phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence ή third-party services·
- τις εγκρίσεις του client και του provider, συμπεριλαμβανομένης τυχόν αναφοράς pre-notification·
- τη φράση emergency stop, τα 24/7 abuse contacts του client και του provider και τον μέγιστο χρόνο απόκρισης·
- τις data classes που επιτρέπεται να συλλεχθούν, την encryption, την access, τη retention και τη deletion·
- τις απαιτήσεις για evidence και logging, συμπεριλαμβανομένου του ποιος διατηρεί το mapping από τη public infrastructure στον operator·
- το teardown, τη λήξη των domains, την ανάκληση certificates, το credential rotation, την ανάκτηση συσκευών και την τελική attestation.

Επαληθεύστε ότι τα public IPs και τα domains ελέγχονται πράγματι από το authorizing party ή περιλαμβάνονται ρητά στο scope. Το NIST SP 800-115 συνιστά να επιβεβαιώνεται ότι οι public target addresses υπάγονται στη δικαιοδοσία του οργανισμού πριν από το testing.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Δημιουργήστε έναν engagement account/project** υπό τον οργανισμό red team, χρησιμοποιώντας ακριβή στοιχεία billing και ownership. Διαχωρίστε τα roles, τα API keys, τα budgets και τα audit logs από άλλους clients.
2. **Ελέγξτε την policy κάθε provider.** Οι cloud, VPS, CDN, domain, email και VPN providers έχουν διαφορετικούς κανόνες. Η AWS, για παράδειγμα, επιτρέπει συγκεκριμένα assessments, αλλά απαιτεί prior approval για hosted C2/covert simulations και απαγορεύει τις αναφερόμενες δραστηριότητες.<sup>[[3]](#references)</sup>
3. **Κατανείμετε fixed egress addresses** και καταγράψτε τις στο ROE annex. Αποφύγετε το rapid IP/resource cycling· περιπλέκει το incident response και ενδέχεται να παραβιάζει την policy του provider.
4. **Σκληρύνετε το management:** SSH μόνο με keys ή identity-aware management plane, phishing-resistant MFA, ξεχωριστό admin network, least privilege, patched images, χωρίς public admin ports και με encrypted secret storage.
5. **Δημιουργήστε διαδρομή full-tunnel** από το operator endpoint προς το bastion. Δρομολογήστε σκόπιμα τα DNS και IPv6 και επιβάλετε firewall deny όταν το tunnel είναι εκτός λειτουργίας.
6. **Περιορίστε τους outbound destinations και ports** στο authorized scope, όπου είναι εφικτό. Εφαρμόστε rate limiting στους scanners και τοποθετήστε τις irreversible/destructive techniques πίσω από ξεχωριστό approval gate.
7. **Καταγράφετε για accountability, όχι για surveillance:** authentication του operator, configuration changes, start/stop, source address, scoped destination και tool/job identifiers. Αποφύγετε το payload/credential capture, εκτός αν απαιτείται από το exercise και προστατεύεται από το data plan.
8. **Επικυρώστε μέσω ενός controlled endpoint** που ανήκει στον οργανισμό: observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect και abuse contact του provider.
9. **Μοιραστείτε με ασφαλή τρόπο το attribution map** με τον exercise controller ή ένα συμφωνημένο escrow contact. Μην το δημοσιεύσετε στην ομάδα του στόχου, αν το blind detection αποτελεί μέρος του test.

### Architecture
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
Ένα VPS είναι ψευδωνυμικό μόνο ως προς τον προορισμό. Ο host μπορεί να διαθέτει αρχεία επικοινωνίας, χρέωσης, ταυτότητας, source-IP, API, συσκευής, τοποθεσίας και χρήσης· ακόμη και το ιστορικό AWS CloudTrail που είναι ορατό στον πελάτη μπορεί από μόνο του να αποκαλύψει δραστηριότητα διαχείρισης.<sup>[[4]](#references)</sup> Η πληρωμή hosting με cryptocurrency δεν διαγράφει αυτά τα αρχεία.

## Domains και certificates

- Χρησιμοποιήστε λογαριασμό registrar ειδικά για το engagement, ιδιοκτησίας του οργανισμού.
- Ενεργοποιήστε registrar lock, DNSSEC όπου υποστηρίζεται, MFA/security keys και auto-renew μόνο για την εγκεκριμένη περίοδο.
- Χρησιμοποιήστε registration privacy για να μειώσετε τη δημόσια έκθεση, όχι για να παραποιήσετε τα στοιχεία του registrant. Η πολιτική του ICANN απαιτεί από τους registrars να συλλέγουν registration data ακόμη και όταν η δημόσια εμφάνιση είναι redacted ή proxied.<sup>[[5]](#references)</sup>
- Αποφύγετε ονόματα που μιμούνται παράνομα άσχετα μέρη. Τα typosquatting/lookalike domains απαιτούν ρητή έγκριση του client και του provider.
- Καταγράψτε τα DNS, certificates, τη ρύθμιση CDN/redirector και τα third-party analytics που θα μπορούσαν να κάνουν leak operators ή clients.
- Κατά το teardown, αφαιρέστε records, ανακαλέστε certificates/tokens, διατηρήστε τα συμφωνημένα evidence και αποφασίστε αν το domain πρέπει να διατηρηθεί αμυντικά.

## Εξουσιοδοτημένα on-site drop nodes

Ένα Raspberry Pi ή παρόμοιο appliance είναι αποδεκτό μόνο όταν ο ιδιοκτήτης του χώρου/δικτύου και ο client έχουν εξουσιοδοτήσει ρητά την ακριβή τοποθέτηση και συμπεριφορά του. Ένα ασφαλές σχέδιο:

1. Καταγράψτε το serial της συσκευής, το MAC/private-MAC policy, φωτογραφία, τον ιδιοκτήτη, την ακριβή εγκεκριμένη τοποθεσία, την πηγή τροφοδοσίας, την προθεσμία ανάκτησης και την επαφή για tampering.
2. Χρησιμοποιήστε minimal signed image, encrypted secrets, read-only ή recoverable storage, host firewall, automatic security updates όπου είναι πρακτικό και χωρίς default credentials.
3. Ρυθμίστε επικοινωνία μόνο εξερχόμενη προς ένα named engagement endpoint. Μην εκθέτετε unauthenticated listener.
4. Επιτρέψτε μόνο εγκεκριμένους προορισμούς και capabilities. Τα packet capture, credential collection, wireless impersonation και lateral movement πρέπει να έχουν εξουσιοδοτηθεί ρητά το καθένα.
5. Χρησιμοποιήστε mutual authentication, short-lived keys, remote kill, health reporting και bandwidth limits.
6. Βεβαιωθείτε ότι η απώλεια/κλοπή δεν αποκαλύπτει επαναχρησιμοποιήσιμα credentials ή δεδομένα του client.
7. Προγραμματίστε την ανάκτηση και το secure wipe/decommission· λάβετε υπογεγραμμένο recovery record.

Μην κρύβετε hardware σε café, ξενοδοχείο, κοινόχρηστο γραφείο, ιδιοκτησία γείτονα ή δημόσιο χώρο χωρίς τη γραπτή άδεια του ιδιοκτήτη/operator.

## Guest networks και travel routers

Αν ένα εξουσιοδοτημένο σενάριο απαιτεί guest access:

- επαληθεύστε το SSID και την acceptable-use policy με τον χώρο/client·
- χρησιμοποιήστε travel router ιδιοκτησίας του οργανισμού ή low-trust bridge device για να απομονώσετε το privileged workstation·
- ολοκληρώστε τα captive portals εκτός του privileged workstation·
- ξεκινήστε το εγκεκριμένο tunnel πριν από την assessment traffic·
- επιβεβαιώστε ότι οι tethered devices χρησιμοποιούν πράγματι αυτό το tunnel·
- θεωρήστε ότι ο χώρος μπορεί να συσχετίσει radio association, portal, φυσική παρουσία και αρχεία από κάμερες/πληρωμές·
- μην παρακάμπτετε access control, μην κλωνοποιείτε άλλη συσκευή, μην επιτίθεστε σε Wi-Fi και μην αφήνετε εξοπλισμό πίσω.

## Operational separation

- Ένα client/engagement ανά endpoint compartment, cloud project, secrets set, domain group, redirector set και evidence store.
- Κανένα personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity ή payment reimbursement εκτός των εγκεκριμένων συστημάτων του οργανισμού.
- Μην επαναχρησιμοποιείτε distinctive payload configuration, callback paths, certificates ή public repositories μεταξύ clients, εκτός αν ο σχεδιασμός της άσκησης αποδέχεται το fingerprinting.
- Ορίστε kill date και budget alert για την infrastructure. Τα orphaned systems αποτελούν κίνδυνο τόσο για τον client όσο και για το Internet.
- Διατηρήστε αρκετή εσωτερική attribution ώστε να διερευνώνται ατυχήματα. Το “No logs” είναι συνήθως ασύμβατο με τις επαγγελματικές υποχρεώσεις για evidence και ασφάλεια.

## Blind to defenders, attributable to the controller

Όταν ο στόχος της άσκησης είναι η μέτρηση της detection και όχι ο έλεγχος ενός allowlist, το target SOC μπορεί να παραμείνει blind χωρίς η επιχείρηση να γίνει μη accountable:

1. Ο exercise controller εγκρίνει κάθε public source, domain, certificate και on-site device, αλλά αποκρύπτει τη λίστα από το SOC.
2. Ο controller αποθηκεύει το source-to-engagement/operator map σε ξεχωριστό encrypted vault με emergency access δύο ατόμων.
3. Κάθε operator job λαμβάνει signed manifest που περιέχει scope, time window, source compartment και irreversible job identifier. Το target δεν χρειάζεται να δει το manifest κατά την κανονική λειτουργία.
4. Τα bastion audit events συνδέονται σε chain ή αποστέλλονται append-only σε controller storage, ώστε ένας operator να μην μπορεί να τροποποιήσει κρυφά την attribution μετά από incident.
5. Μια 24/7 provider-abuse contact διατηρεί verification phrase/reference που επιβεβαιώνει την εξουσιοδότηση χωρίς να αποκαλύπτει δημόσια τον client.
6. Κάθε path υλοποιεί out-of-band stop channel που δεν εξαρτάται από το assessment C2, το target network ή τον λογαριασμό ενός operator.
7. Πριν από το live testing, στείλτε benign canaries από κάθε source. Επιβεβαιώστε ότι ο controller μπορεί να τα εντοπίσει και να τα σταματήσει εντός του ROE response time.
8. Μετά την άσκηση, συγκρίνετε το SOC telemetry με το controller ledger, αποκαλύψτε τη source list και εξηγήστε τις detections που χάθηκαν ή ήταν λανθασμένες.

Μην προσθέτετε anti-forensics, καταστροφή logs, compromised relays ή false subscriber identities. Αυτά υπονομεύουν το accountable testing αντί να το βελτιώνουν.

## Teardown checklist

- [ ] Ο exercise controller επιβεβαιώνει το stop.
- [ ] Τα C2, tunnels, redirectors, mail, VPN και scheduled jobs έχουν απενεργοποιηθεί.
- [ ] Οι on-site devices έχουν ανακτηθεί φυσικά και έχουν συμφωνηθεί με τα αρχεία.
- [ ] Τα tokens, API keys, SSH keys, certificates και captured credentials έχουν ανακληθεί/περιστραφεί.
- [ ] Τα DNS και cloud resources έχουν αφαιρεθεί ή μεταβιβαστεί για defensive retention.
- [ ] Τα δεδομένα του client έχουν επιστραφεί, διατηρηθεί ή καταστραφεί σύμφωνα με το contract.
- [ ] Τα απαιτούμενα financial, audit και authorization records παραμένουν encrypted και access-controlled.
- [ ] Τα provider abuse cases έχουν κλείσει και ο client έχει λάβει τα τελικά source indicators.
- [ ] Ένας δεύτερος operator επαληθεύει ότι δεν παραμένει ενεργή infrastructure.

## References

- [1] [NIST CSRC — Κανόνες Εμπλοκής](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Τεχνικός Οδηγός για Testing και Assessment Ασφάλειας Πληροφοριών](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Πολιτική Υποστήριξης Πελατών για Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Δήλωση Απορρήτου](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Πολιτική Registration Data](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
