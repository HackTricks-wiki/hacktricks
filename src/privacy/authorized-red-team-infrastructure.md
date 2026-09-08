# Υποδομή Authorized Red-Team

Για ανθεκτικές επιτόπιες συσκευές, χρησιμοποιήστε τον σχεδιασμό και το runbook suspected-discovery [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Για ένα professional red team, ο στόχος είναι η **ελεγχόμενη απόδοση ευθύνης**, όχι η απαλλαγή από τη λογοδοσία. Ο στόχος δεν πρέπει να μπορεί να δει άμεσα την οικιακή IP ή τους προσωπικούς λογαριασμούς ενός operator, ενώ ο owner του engagement πρέπει να μπορεί να αναγνωρίσει την πηγή, να διακόψει την operation, να διαχειριστεί reports κατάχρησης, να διατηρήσει evidence και να αποδείξει την authorization.

Αυτή η σελίδα αποτελεί το deployment baseline για ένα lawful engagement. Για το adversary tradecraft που προορίζεται να προσομοιώσει—συμπεριλαμβανομένων compromised ORBs, residential relays, fronting, dead drops και nearby wireless pivots—ξεκινήστε με τα [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) και [Government and APT Case Studies](government-and-apt-case-studies.md) και, στη συνέχεια, αναπαραγάγετε το απαιτούμενο telemetry στα [authorized labs](authorized-adversary-emulation-labs.md).

Το NIST ορίζει τους rules of engagement (ROE) ως προκαθορισμένους περιορισμούς που παρέχουν authority για συγκεκριμένες testing activities.<sup>[[1]](#references)</sup> Η privacy architecture δεν μπορεί να διευρύνει αυτή την authority.

## Επιλέξτε ένα egress pattern

| Pattern | Βέλτιστη χρήση | Τι βλέπει ο στόχος | Τι βλέπει ο provider/local observer | Accountability |
|---|---|---|---|---|
| Client-provided VPN/jump host | Τα περισσότερα assessments | Το address range του client | Την ταυτότητα του client και την πρόσβαση του operator | Ισχυρότερη |
| Red-team organization bastion | Επαναλαμβανόμενο controlled egress | Το range του organization | Τον hosting provider και το organization | Ισχυρή |
| Engagement-specific VPS | Απομόνωση clients/campaigns | Τη διεύθυνση του VPS | Το host account, τα billing, control-plane και access logs | Ισχυρή εάν έχει τεκμηριωθεί |
| Approved commercial VPN | Research/scanning που επιτρέπεται από τον provider και τα ROE | Το shared/dedicated VPN egress | Το VPN account και τη source connection | Μεσαία |
| Tor Browser | Web research που απαιτεί destination unlinkability | Το Tor exit | Το local network βλέπει Tor/bridge· ο προορισμός βλέπει Tor | Ακατάλληλο για allowlisted source attribution |
| Client-approved on-site drop | Internal simulation | Την on-site συσκευή/διεύθυνση | Το site network και τον remote tunnel provider | Ισχυρή εάν έχει καταγραφεί στο inventory |
| Lawful guest Wi-Fi | Low-risk administrative/research χρήση | Το public IP του venue ή το tunnel egress | Το venue, τον ISP, το VPN/Tor | Αδύναμη και φυσικά παρατηρήσιμη |

Για τις περισσότερες εργασίες, ένα client-provided ή organization-controlled fixed egress είναι ασφαλέστερο και ταχύτερο από consumer anonymity services. Επιτρέπει επίσης στους defenders να κάνουν allowlist, να παρακολουθούν ή σκόπιμα **να μην κάνουν allowlist** γνωστά source ranges, σύμφωνα με τον σχεδιασμό του exercise.

## ROE infrastructure annex

Καταγράψτε πριν από το deployment:

- τις legal entities που παρέχουν και λαμβάνουν authorization·
- τους ακριβείς στόχους και τις ρητές εξαιρέσεις·
- τις ώρες έναρξης/λήξης, τη ζώνη ώρας και τις επιτρεπόμενες techniques·
- τις source IPs, τα autonomous-system/provider names, τα domains, τους redirectors, το mail infrastructure και τα on-site device identifiers·
- εάν επιτρέπονται phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence ή third-party services·
- τις εγκρίσεις του client και του provider, συμπεριλαμβανομένου οποιουδήποτε pre-notification reference·
- τη emergency stop phrase, τα 24/7 abuse contacts του client και του provider και τον μέγιστο χρόνο απόκρισης·
- τις data classes που επιτρέπεται να συλλεχθούν, την encryption, την access, τη retention και τη deletion·
- τις απαιτήσεις για evidence και logging, συμπεριλαμβανομένου του ποιος διατηρεί το mapping από τη public infrastructure στον operator·
- το teardown, τη λήξη domain, την ανάκληση certificate, τη rotation credentials, την ανάκτηση συσκευών και την τελική attestation.

Επαληθεύστε ότι τα public IPs και τα domains ελέγχονται πράγματι από το authorizing party ή περιλαμβάνονται ρητά στο scope. Το NIST SP 800-115 συνιστά να επιβεβαιώνεται ότι οι public target addresses βρίσκονται υπό τον έλεγχο του organization πριν από το testing.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Δημιουργήστε ένα engagement account/project** υπό το red-team organization, χρησιμοποιώντας ακριβή στοιχεία billing και ownership. Διαχωρίστε roles, API keys, budgets και audit logs από άλλους clients.
2. **Ελέγξτε την policy κάθε provider.** Οι cloud, VPS, CDN, domain, email και VPN providers έχουν διαφορετικούς κανόνες. Το AWS, για παράδειγμα, επιτρέπει συγκεκριμένα assessments, αλλά απαιτεί prior approval για hosted C2/covert simulations και απαγορεύει τις αναφερόμενες activities.<sup>[[3]](#references)</sup>
3. **Κατανείμετε fixed egress addresses** και προσθέστε τις στο ROE annex. Αποφύγετε το rapid IP/resource cycling· περιπλέκει το incident response και ενδέχεται να παραβιάζει την policy του provider.
4. **Σκληρύνετε το management:** key-only SSH ή identity-aware management plane, phishing-resistant MFA, ξεχωριστό admin network, least privilege, patched images, χωρίς public admin ports και με encrypted secret storage.
5. **Δημιουργήστε full-tunnel path** από το operator endpoint προς το bastion. Κατευθύνετε σκόπιμα το DNS και το IPv6 και επιβάλετε firewall deny όταν το tunnel είναι εκτός λειτουργίας.
6. **Περιορίστε τα outbound destinations και ports** στο authorized scope όπου είναι εφικτό. Εφαρμόστε rate limits στους scanners και θέστε τις irreversible/destructive techniques πίσω από ξεχωριστό approval gate.
7. **Καταγράψτε για accountability, όχι για surveillance:** operator authentication, configuration changes, start/stop, source address, scoped destination και tool/job identifiers. Αποφύγετε payload/credential capture εκτός εάν απαιτείται από το exercise και προστατεύεται από το data plan.
8. **Επικυρώστε μέσω ενός controlled endpoint** που ανήκει στο organization: observed IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect και provider abuse contact.
9. **Μοιραστείτε με ασφάλεια το attribution map** με τον exercise controller ή έναν συμφωνημένο escrow contact. Μην το δημοσιεύσετε στην target team εάν το blind detection αποτελεί μέρος του test.

### Αρχιτεκτονική
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
Ένα VPS είναι ψευδωνυμικό μόνο ως προς τον προορισμό. Ο host μπορεί να διατηρεί αρχεία επικοινωνίας, χρέωσης, ταυτότητας, source-IP, API, συσκευής, τοποθεσίας και χρήσης· μόνο το ιστορικό AWS CloudTrail που είναι ορατό στον πελάτη μπορεί να αποκαλύψει δραστηριότητα διαχείρισης.<sup>[[4]](#references)</sup> Η πληρωμή hosting με cryptocurrency δεν διαγράφει αυτά τα αρχεία.

## Domains και certificates

- Χρησιμοποιήστε λογαριασμό registrar ειδικό για το engagement, τον οποίο κατέχει ο οργανισμός.
- Ενεργοποιήστε registrar lock, DNSSEC όπου υποστηρίζεται, MFA/security keys και auto-renew μόνο για την εγκεκριμένη περίοδο.
- Χρησιμοποιήστε registration privacy για να περιορίσετε τη δημόσια έκθεση, όχι για να παραποιήσετε τα στοιχεία του registrant. Η πολιτική της ICANN απαιτεί από τους registrars να συλλέγουν registration data ακόμη και όταν η δημόσια εμφάνιση είναι redacted ή proxied.<sup>[[5]](#references)</sup>
- Αποφύγετε ονόματα που impersonate παράνομα άσχετα μέρη. Τα typosquatting/lookalike domains απαιτούν ρητή έγκριση από τον πελάτη και τον provider.
- Καταγράψτε το DNS, τα certificates, τη ρύθμιση CDN/redirector και τα third-party analytics που θα μπορούσαν να leak operators ή clients.
- Κατά το teardown, αφαιρέστε τα records, ανακαλέστε certificates/tokens, διατηρήστε τα συμφωνημένα evidence και αποφασίστε αν το domain πρέπει να διατηρηθεί αμυντικά.

## Authorized on-site drop nodes

Ένα Raspberry Pi ή παρόμοιο appliance είναι αποδεκτό μόνο όταν ο ιδιοκτήτης του χώρου/δικτύου και ο πελάτης έχουν εγκρίνει ρητά την ακριβή τοποθέτηση και συμπεριφορά του. Ένα ασφαλές σχέδιο:

1. Καταγράψτε το serial της συσκευής, το MAC/private-MAC policy, φωτογραφία, ιδιοκτήτη, ακριβή εγκεκριμένη τοποθεσία, πηγή τροφοδοσίας, προθεσμία ανάκτησης και contact για tampering.
2. Χρησιμοποιήστε minimal signed image, encrypted secrets, read-only ή recoverable storage, host firewall, automatic security updates όπου είναι πρακτικό και χωρίς default credentials.
3. Ρυθμίστε outbound-only communication προς ένα κατονομασμένο engagement endpoint. Μην εκθέτετε unauthenticated listener.
4. Κάντε allowlist τους προορισμούς και τις δυνατότητες. Τα packet capture, credential collection, wireless impersonation και lateral movement πρέπει να έχουν εγκριθεί ρητά το καθένα.
5. Χρησιμοποιήστε mutual authentication, short-lived keys, remote kill, health reporting και bandwidth limits.
6. Βεβαιωθείτε ότι η απώλεια ή κλοπή δεν αποκαλύπτει reusable credentials ή client data.
7. Προγραμματίστε την ανάκτηση και το secure wipe/decommission· λάβετε signed recovery record.

Μην κρύβετε hardware σε café, ξενοδοχείο, shared office, ιδιοκτησία γείτονα ή δημόσιο χώρο χωρίς τη γραπτή άδεια του ιδιοκτήτη/operator.

## Guest networks και travel routers

Αν ένα authorized scenario απαιτεί guest access:

- επαληθεύστε το SSID και το acceptable-use policy με τον χώρο/client·
- χρησιμοποιήστε travel router ιδιοκτησίας του οργανισμού ή low-trust bridge device για να απομονώσετε το privileged workstation·
- ολοκληρώστε τα captive portals εκτός του privileged workstation·
- ξεκινήστε το approved tunnel πριν από assessment traffic·
- επιβεβαιώστε ότι οι tethered devices χρησιμοποιούν πράγματι αυτό το tunnel·
- θεωρήστε ότι ο χώρος μπορεί να συσχετίσει το radio association, το portal, τη φυσική παρουσία και τα camera/payment records·
- ποτέ μην παρακάμπτετε access control, μην κάνετε clone άλλης συσκευής, μην επιτίθεστε σε Wi-Fi και μην αφήνετε εξοπλισμό πίσω.

## Operational separation

- Ένας client/engagement ανά endpoint compartment, cloud project, secrets set, domain group, redirector set και evidence store.
- Κανένα personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity ή payment reimbursement εκτός των εγκεκριμένων συστημάτων του οργανισμού.
- Μην επαναχρησιμοποιείτε distinctive payload configuration, callback paths, certificates ή public repositories μεταξύ clients, εκτός αν ο σχεδιασμός του exercise αποδέχεται το fingerprinting.
- Ορίστε kill date και budget alert για την υποδομή. Τα orphaned systems αποτελούν κίνδυνο τόσο για τον client όσο και για το Internet.
- Διατηρήστε αρκετό internal attribution ώστε να διερευνώνται ατυχήματα. Το “No logs” συνήθως δεν συμβαδίζει με τις επαγγελματικές υποχρεώσεις για evidence και safety.

## Blind to defenders, attributable to the controller

Όταν ο στόχος του exercise είναι η μέτρηση του detection και όχι ο έλεγχος allowlist, το target SOC μπορεί να παραμείνει blind χωρίς η επιχείρηση να καταστεί μη accountable:

1. Ο exercise controller εγκρίνει κάθε public source, domain, certificate και on-site device, αλλά αποκρύπτει τη λίστα από το SOC.
2. Ο controller αποθηκεύει το source-to-engagement/operator map σε ξεχωριστό encrypted vault με emergency access δύο ατόμων.
3. Κάθε operator job λαμβάνει signed manifest που περιέχει scope, time window, source compartment και irreversible job identifier. Το target δεν χρειάζεται να δει το manifest κατά την κανονική λειτουργία.
4. Τα bastion audit events συνδέονται μεταξύ τους ή αποστέλλονται append-only σε controller storage, ώστε ένας operator να μην μπορεί να τροποποιήσει σιωπηλά το attribution μετά από incident.
5. Ένα 24/7 provider-abuse contact διαθέτει verification phrase/reference που επιβεβαιώνει την authorization χωρίς να αποκαλύπτει δημόσια τον client.
6. Κάθε path υλοποιεί out-of-band stop channel που δεν εξαρτάται από το assessment C2, το target network ή τον λογαριασμό ενός operator.
7. Πριν από το live testing, στείλτε benign canaries από κάθε source. Επιβεβαιώστε ότι ο controller μπορεί να τα εντοπίσει και να τα σταματήσει εντός του response time του ROE.
8. Μετά το exercise, συγκρίνετε το SOC telemetry με το controller ledger, αποκαλύψτε τη source list και εξηγήστε τα missed/incorrect detections.

Μην προσθέτετε anti-forensics, log destruction, compromised relays ή false subscriber identities. Αυτά υπονομεύουν το accountable testing αντί να το βελτιώνουν.

## Teardown checklist

- [ ] Ο exercise controller επιβεβαιώνει το stop.
- [ ] Τα C2, tunnels, redirectors, mail, VPN και scheduled jobs έχουν απενεργοποιηθεί.
- [ ] Οι on-site devices έχουν ανακτηθεί φυσικά και έχει γίνει reconciliation.
- [ ] Τα tokens, API keys, SSH keys, certificates και captured credentials έχουν ανακληθεί/περιστραφεί.
- [ ] Τα DNS και cloud resources έχουν αφαιρεθεί ή μεταβιβαστεί για defensive retention.
- [ ] Τα client data έχουν επιστραφεί, διατηρηθεί ή καταστραφεί σύμφωνα με το contract.
- [ ] Τα απαιτούμενα financial, audit και authorization records παραμένουν encrypted και access-controlled.
- [ ] Τα provider abuse cases έχουν κλείσει και ο client έχει λάβει τα τελικά source indicators.
- [ ] Ένας δεύτερος operator επαληθεύει ότι δεν παραμένει ενεργή infrastructure.

## References

- [1] [NIST CSRC — Κανόνες Εμπλοκής](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Τεχνικός Οδηγός για Testing και Assessment Ασφάλειας Πληροφοριών](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Πολιτική Υποστήριξης Πελατών για Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Πολιτική Registration Data](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
