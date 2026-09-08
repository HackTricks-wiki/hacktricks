# Ιδιωτικές ψηφιακές πληρωμές

{{#include ../banners/hacktricks-training.md}}

Η ιδιωτικότητα των πληρωμών είναι η ελεγχόμενη αποκάλυψη δεδομένων συναλλαγών. Δεν αποτελεί τρόπο νομιμοποίησης παράνομων κεφαλαίων, αποφυγής φόρων ή κυρώσεων, παράκαμψης του KYC, χρήσης ψευδών ταυτοτήτων ή απόκρυψης μη εξουσιοδοτημένης ενέργειας. Μια πληρωμή μπορεί να είναι ιδιωτική απέναντι σε έναν έμπορο, ενώ παραμένει πλήρως ορατή στον εκδότη, στο δίκτυο, στον εργοδότη, στη φορολογική αρχή ή σε έναν ερευνητή.

Ο [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) είναι η κανονικοποιημένη καταγραφή με `Pros`, `Cons`, νόμιμη `Procedure` βήμα προς βήμα και `Detection` για κάθε οικογένεια. Αυτή η σελίδα επεκτείνει τις συμβατικές μεθόδους πληρωμής.

{% hint style="danger" %}
Μην χρησιμοποιείτε ποτέ κλεμμένους λογαριασμούς, συνθετικές ταυτότητες, money mules, πλασματικές δηλώσεις κατοικίας ή προέλευσης κεφαλαίων, τεμαχισμό συναλλαγών («structuring») ή αδιαφανείς μεσίτες «no-KYC card». Ελέγχετε την ισχύουσα νομοθεσία και τους όρους του παρόχου σε κάθε σχετική δικαιοδοσία.
{% endhint %}

## Καθορισμός της ιδιότητας ιδιωτικότητας

Ονομάστε τον παρατηρητή πριν επιλέξετε rail:

| Παρατηρητής | Τυπικά δεδομένα | Χρήσιμος έλεγχος | Τι παραμένει |
|---|---|---|---|
| Έμπορος | Όνομα, email, διεύθυνση, card token, IP/device, καλάθι | Guest checkout, ελάχιστα προαιρετικά δεδομένα, merchant-specific virtual card | Δεδομένα παράδοσης, λογαριασμού και fraud telemetry |
| Εκδότης/processor πληρωμών | Νομική ταυτότητα, πηγή χρηματοδότησης, έμπορος, ποσό, ώρα, device | Επιλογή regulated provider με καλούς όρους ιδιωτικότητας/ασφάλειας | Ο πάροχος εξακολουθεί να επεξεργάζεται και μπορεί να διατηρεί/γνωστοποιεί αρχεία |
| Εργοδότης/ιδιοκτήτης engagement | Δαπάνη, operator και σκοπός | Ξεχωριστός προϋπολογισμός engagement και access-controlled ledger | Η νόμιμη διακυβέρνηση απαιτεί εσωτερική απόδοση ευθύνης |
| Δημόσιος παρατηρητής blockchain | Διευθύνσεις, ροές, ποσά και χρόνος, ανάλογα με το chain | Κατάλληλο protocol και wallet discipline | Η απόκτηση, τα endpoints και οι μεταγενέστερες δαπάνες μπορεί να επανασυνδέσουν τη δραστηριότητα |
| Network/RPC/node operator | IP, wallet queries, transaction broadcasts | Local node ή κατάλληλο privacy network | Η χρονική συσχέτιση και η συμπεριφορά των endpoints μπορεί να παραμένουν ανιχνεύσιμες |
| Φυσικός παρατηρητής | Πρόσωπο, τοποθεσία, όχημα, CCTV, απόδειξη | Συνήθης situational privacy | Τα μετρητά δεν καθιστούν ένα άτομο αόρατο στον φυσικό χώρο |

Το CFPB περιγράφει τις payment apps ως ικανές να συλλέγουν δεδομένα ταυτότητας, συσκευής, τοποθεσίας, επαφών, συναλλαγών και συμπεριφοράς· οι πολιτειακοί κανόνες ιδιωτικότητας δεν εμποδίζουν απαραίτητα τη monetization ή κάθε δευτερεύουσα χρήση.<sup>[[1]](#references)</sup> Διαβάστε την πραγματική ειδοποίηση του παρόχου αντί να συμπεραίνετε την ιδιωτικότητα από το όνομα ενός προϊόντος.

## Σύγκριση μεθόδων πληρωμής

| Μέθοδος | Όφελος ιδιωτικότητας | Κύριοι παρατηρητές/συσχετίσεις | Κατάλληλη χρήση |
|---|---|---|---|
| Μετρητά | Χωρίς ledger του payment network | Παραλήπτης, κάμερες, μάρτυρες, κανόνες αναφοράς μετρητών | Νόμιμες τοπικές αγορές όπου γίνονται δεκτά |
| Open-loop prepaid/gift card | Διαχωρίζει τον αριθμό της κάρτας από μια κύρια κάρτα | Πωλητής, πάροχος ενεργοποίησης/εγγραφής, πηγή χρηματοδότησης, έμπορος | Budgeting ή περιορισμένη compartmentalization μεταξύ εμπόρων |
| Virtual/one-time card number | Αποκρύπτει το επαναχρησιμοποιήσιμο PAN από τον έμπορο· εύκολη ανάκληση | Ο εκδότης εξακολουθεί να γνωρίζει την ταυτότητα και τη συναλλαγή | Compartmentalization online εμπόρων |
| Mobile-wallet token | Η συσκευή/ο έμπορος λαμβάνει token αντί για το υποκείμενο PAN | Wallet provider, εκδότης, payment network και έμπορος | Ασφάλεια credential, όχι ανωνυμία |
| Bank transfer/app | Βολικό audit trail | Τράπεζα/app, αντισυμβαλλόμενος και συνδεδεμένη ταυτότητα | Accountable οργανωτικές πληρωμές |
| Cryptocurrency | Διαφέρει ανά protocol· το self-custody μπορεί να μειώσει την έκθεση σε custodian | Public ledger ή privacy protocol, exchange, endpoint, αντισυμβαλλόμενος | Νόμιμες μεταφορές μετά από protocol-specific ανάλυση |

## Μετρητά

Τα μετρητά εξακολουθούν να θεωρούνται σημαντικά για την ιδιωτικότητα και την οικονομική ένταξη και αποφεύγουν την καταγραφή σε payment network.<sup>[[2]](#references)</sup> Δεν παρακάμπτουν το CCTV, τους μάρτυρες, την τοποθεσία της συσκευής, τις αποδείξεις, την ιχνηλάτηση σειριακών αριθμών σε ειδικές περιπτώσεις ή τη νόμιμη αναφορά.

### Νόμιμη ροή εργασίας

1. Ελέγξτε την αποδοχή και τα τοπικά όρια μετρητών πριν από τη συναλλαγή. Τα όρια διαφέρουν ανά χώρα και τύπο αντισυμβαλλομένου και αλλάζουν με την πάροδο του χρόνου.
2. Πραγματοποιήστε την κανονική αγορά σε μία ειλικρινή συναλλαγή. **Μην την τεμαχίσετε ποτέ** για να αποφύγετε ένα όριο ή μια αναφορά.
3. Απορρίψτε την προαιρετική παρακολούθηση loyalty ή τη συλλογή δεδομένων marketing. Παρέχετε με ειλικρίνεια τα δεδομένα που απαιτούνται για εγγύηση, ασφάλεια, παράδοση, φορολογία ή βάσει νόμου.
4. Διατηρήστε την αναγκαία απόδειξη αγοράς και τα απαιτούμενα λογιστικά αρχεία σε κρυπτογραφημένο storage με ημερομηνία διατήρησης.
5. Για έναν οργανισμό, ζητήστε αποζημίωση μέσω της εγκεκριμένης διαδικασίας και καταγράψτε operator, authorization, σκοπό, ποσό, ημερομηνία και απόδειξη.

Στις Ηνωμένες Πολιτείες, ορισμένες επιχειρήσεις υποβάλλουν το Form 8300 για εισπράξεις μετρητών άνω των $10.000, συμπεριλαμβανομένων σχετιζόμενων συναλλαγών· η σκόπιμη διάσπαση συναλλαγών μπορεί να αποτελεί από μόνη της παράνομο structuring.<sup>[[3]](#references)</sup> Άλλες δικαιοδοσίες διαφέρουν—για παράδειγμα, η Ισπανία δημοσιεύει τον δικό της νόμιμο περιορισμό πληρωμών με μετρητά.<sup>[[4]](#references)</sup>

## Prepaid και gift cards

Το «prepaid» δεν σημαίνει ανώνυμο. Ένα κατάστημα, εκδότης, program manager, funding bank και έμπορος μπορεί να συσχετίσουν αγορά, ενεργοποίηση, device, IP, τοποθεσία και δαπάνη. Οι reloads, η πρόσβαση σε ATM, η διεθνής χρήση, τα υψηλότερα όρια ή η προστασία απώλειας απαιτούν συνήθως εγγραφή.

Οι οδηγίες για καταναλωτές στις ΗΠΑ εξηγούν ότι οι εκδότες μπορεί να ζητήσουν δεδομένα ταυτότητας για νομική επαλήθευση και να απορρίψουν μια εγγεγραμμένη κάρτα όταν η επαλήθευση αποτυγχάνει.<sup>[[5]](#references)</sup> Οι κανόνες της FinCEN καθορίζουν ποια prepaid programs και participants έχουν υποχρεώσεις AML.<sup>[[6]](#references)</sup> Στην ΕΕ, οι περιορισμένες εξαιρέσεις για anonymous e-money μειώθηκαν με την Directive (EU) 2018/843· ο Regulation (EU) 2024/1624 αλλάζει ξανά το πλαίσιο, αλλά εφαρμόζεται γενικά από τις **10 July 2027**, επομένως μην τον περιγράφετε ως ήδη ενεργό το 2026.<sup>[[7]](#references)</sup>

Χρησιμοποιείτε prepaid value μόνο όταν έχει αποκτηθεί νόμιμα από identifiable issuer, οι όροι του επιτρέπουν την προβλεπόμενη χρήση και το όφελος είναι το budgeting ή ο διαχωρισμός από ένα primary payment credential. Αποφεύγετε resale markets και brokers που διαφημίζουν μη επαληθεύσιμες «no-name» κάρτες: η αξία μπορεί να είναι κλεμμένη, να έχει ήδη εξαργυρωθεί, να υπόκειται σε γεωγραφικούς περιορισμούς ή σε κατάσχεση.

## Virtual cards και wallet tokens

Ένας virtual card number (VCN) εκδίδεται συνήθως πίσω από έναν πραγματικό, επαληθευμένο λογαριασμό. Οι merchant-specific ή single-use αριθμοί μειώνουν τον κίνδυνο breach και τη συσχέτιση του PAN μεταξύ εμπόρων· **δεν** αποκρύπτουν τη συναλλαγή από τον εκδότη. Αντίστοιχα, το network tokenization αντικαθιστά ένα card credential με ένα περιορισμένο token.<sup>[[8]](#references)</sup>

### Merchant-compartmentalized workflow

1. Ανοίξτε λογαριασμό σε regulated issuer χρησιμοποιώντας ακριβή στοιχεία ταυτότητας, κατοικίας και χρηματοδότησης.
2. Ασφαλίστε τον με μοναδικό password, phishing-resistant MFA όπου είναι διαθέσιμο, login alerts και recovery codes αποθηκευμένα offline.
3. Δημιουργήστε merchant-locked ή one-time VCN. Ορίστε εύλογο όριο ποσού/χρόνου, εφόσον υποστηρίζεται.
4. Χρησιμοποιήστε guest checkout και παραλείψτε μόνο **προαιρετικά** πεδία profile, loyalty και marketing. Παρέχετε ακριβή στοιχεία billing, delivery και tax όταν απαιτούνται.
5. Αποφύγετε τη σύνδεση σε unrelated identity providers· χρησιμοποιήστε engagement/account browser compartment και το εγκεκριμένο network path.
6. Αποθηκεύστε την απόδειξη και την αντιστοίχιση VCN-to-purpose σε κρυπτογραφημένο internal ledger.
7. Κλειδώστε ή ανακαλέστε τον αριθμό μετά το refund/chargeback window· παρακολουθείτε το parent account για μη αναμενόμενες authorizations.

Η Capital One και η Google τεκμηριώνουν ότι οι virtual numbers παραμένουν συνδεδεμένοι με τον underlying account, ενώ οι EMVCo/Visa περιγράφουν το tokenization ως αντικατάσταση credential και domain restriction, όχι ως ανωνυμία του payer.<sup>[[8]](#references)</sup>

## Παράδοση, λογαριασμοί και επιστροφές χρημάτων

Η πληρωμή είναι μόνο μία ακμή στο linkage graph:

- Μια μοναδική κάρτα ακυρώνεται ως μέτρο ιδιωτικότητας αν επαναχρησιμοποιούνται προσωπικό email, τηλέφωνο, browser profile, IP address ή loyalty account.
- Η φυσική παράδοση συνήθως απαιτεί νόμιμο παραλήπτη και τοποθεσία. Μην χρησιμοποιείτε τη διεύθυνση μη εμπλεκόμενου ατόμου και μην υποδύεστε έναν κάτοικο. Οι εγκεκριμένες business receiving services είναι ασφαλέστερες από τα κατασκευασμένα στοιχεία.
- Τα digital goods μπορεί να καταγράφουν account identity, IP, device fingerprint, license activation και downloads.
- Οι επιστροφές χρημάτων συνήθως επιστρέφουν στο αρχικό rail. Αιτήματα λήψης χρημάτων και προώθησης/επιστροφής τους αλλού αποτελούν προειδοποίηση για fraud και money mule.
- Τα merchant descriptors, το κείμενο invoice και οι ειδοποιήσεις αποστολής μπορεί να αποκαλύψουν μια ευαίσθητη αγορά σε account delegates· ρυθμίστε σκόπιμα την πρόσβαση και τις ειδοποιήσεις.

## Authorized red-team αγορές

Ένα engagement πρέπει να είναι διακριτικό εξωτερικά και accountable εσωτερικά:

1. Λάβετε γραπτό scope, σκοπό, spending ceiling, approver, επιτρεπόμενους merchants/assets και κανόνα reimbursement.
2. Χρησιμοποιήστε organization-controlled payment account και ξεχωριστό VCN ή sub-account ανά engagement ή merchant.
3. Διατηρήστε ακριβή στοιχεία billing και registrant στους providers. Η privacy προστασία δημόσιας εγγραφής μπορεί να μειώσει την έκθεση, αλλά δεν αποτελεί άδεια για ψέματα.
4. Διατηρήστε κρυπτογραφημένο ledger με operator, approval, σκοπό, ημερομηνία, ποσό, αντισυμβαλλόμενο, asset identifier και απόδειξη.
5. Ελέγξτε τους αντισυμβαλλομένους όπως απαιτείται και ακολουθήστε τις υποχρεώσεις του provider, τις κυρώσεις, τη φορολογία και την αναφορά.
6. Δώστε στο finance μόνο την πρόσβαση που χρειάζεται· δώστε στους operators μόνο την περιορισμένη δυνατότητα δαπανών που χρειάζονται.
7. Κλείστε ή παγώστε τα payment credentials κατά το teardown, κάντε reconcile των pending charges/refunds και διατηρήστε τα αρχεία σύμφωνα με την policy.

Για επιλογές ειδικά για crypto, συνεχίστε στο [Cryptocurrency Privacy](cryptocurrency-privacy.md). Για την υποδομή που υποστηρίζουν αυτές οι αγορές, δείτε το [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md).

## Λίστα ελέγχου επαλήθευσης

- [ ] Η επιθυμητή ιδιότητα ιδιωτικότητας και οι παρατηρητές έχουν καταγραφεί.
- [ ] Οι κανόνες του provider, του merchant και της δικαιοδοσίας ελέγχθηκαν πρόσφατα.
- [ ] Οι δηλώσεις ταυτότητας και προέλευσης κεφαλαίων είναι αληθείς.
- [ ] Τα προαιρετικά δεδομένα του merchant έχουν ελαχιστοποιηθεί χωρίς να παρακάμπτεται η απαιτούμενη επαλήθευση.
- [ ] Οι συσχετίσεις funding, device, network, account, delivery και refund είναι κατανοητές.
- [ ] Δεν εμπλέκονται αποφυγή ορίου, απαγορευμένος αντισυμβαλλόμενος, mule, κλεμμένο credential ή ταυτότητα τρίτου.
- [ ] Οι απαιτούμενες αποδείξεις, εγκρίσεις, φορολογικά αρχεία και recovery information είναι κρυπτογραφημένα και access-controlled.

## References

- [1] [US CFPB — Αίτημα για πληροφορίες σχετικά με τη συλλογή, χρήση και monetization των δεδομένων πληρωμών καταναλωτών και άλλων προσωπικών οικονομικών δεδομένων](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf) and [State Consumer Privacy Laws and the Monetization of Consumer Financial Data](https://www.consumerfinance.gov/data-research/research-reports/state-consumer-privacy-laws-and-the-monetization-of-consumer-financial-data/)
- [2] [European Central Bank — Μελέτη για τις στάσεις των καταναλωτών απέναντι στις πληρωμές στη ζώνη του ευρώ (SPACE) 2024](https://www.ecb.europa.eu/stats/ecb_surveys/space/html/ecb.space2024~19d46f0f17.en.html)
- [3] [US IRS — Οδηγίες για το Form 8300](https://www.irs.gov/instructions/i8300) and [FinCEN — Currency Transaction Reporting Requirement](https://www.fincen.gov/fincen-educational-pamphlet-currency-transaction-reporting-requirement)
- [4] [Spanish Tax Agency — Αναφορά πληρωμών με μετρητά](https://sede.agenciatributaria.gob.es/Sede/colaborar-agencia-tributaria/denuncias/denuncia-pagos-efectivo.html)
- [5] US CFPB — [Γιατί μου ζητούν προσωπικές πληροφορίες για την ενεργοποίηση ή εγγραφή prepaid card;](https://www.consumerfinance.gov/ask-cfpb/why-am-i-being-asked-for-personal-information-to-activate-or-register-a-prepaid-card-en-443/) και [Μπορεί να απορριφθώ για prepaid card;](https://www.consumerfinance.gov/ask-cfpb/can-i-be-declined-for-a-prepaid-card-en-437/)
- [6] [FinCEN — Τελικός κανόνας για Prepaid Access](https://www.fincen.gov/resources/statutes-regulations/guidance/final-rule-definitions-and-other-regulations-relating)
- [7] [Directive (EU) 2018/843](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32018L0843) and [Regulation (EU) 2024/1624](https://eur-lex.europa.eu/eli/reg/2024/1624)
- [8] [Capital One — Χρήση virtual credit cards](https://www.capitalone.com/help-center/credit-cards/using-virtual-credit-cards/), [Google Pay — Virtual cards](https://support.google.com/googlepay/answer/7643925?hl=en), [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/), and [Visa — Token Service Provisioning](https://developer.visa.com/capabilities/token-service-provisioning)
{{#include ../banners/hacktricks-training.md}}
