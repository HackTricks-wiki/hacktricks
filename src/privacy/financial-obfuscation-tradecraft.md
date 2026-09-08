# Τεχνικές χρηματοοικονομικής συσκότισης

Η ιδιωτικότητα των πληρωμών είναι πρόβλημα απόδοσης ευθύνης και όχι πρόβλημα της μάρκας πληρωμών. Μια επιχείρηση αφήνει στοιχεία όταν η αξία αποκτάται, μετακινείται, μετατρέπεται, δαπανάται και παραδίδεται. Μια διεύθυνση σε public-chain μπορεί να είναι ψευδωνυμική, ενώ ένα ανταλλακτήριο, ένας εκδότης κάρτας, ένας έμπορος, μια mobile συσκευή ή μια κάμερα αποστολών μπορεί να ταυτοποιήσει το άτομο που βρίσκεται πίσω από αυτήν.

Αυτή η σελίδα εξηγεί μοτίβα χρηματοοικονομικής συσκότισης που χρησιμοποιούνται σε cybercrime και από επιχειρήσεις συνδεδεμένες με κράτη, ώστε οι defenders να μπορούν να τα αναγνωρίζουν. **Δεν** παρέχει διαδικασία ξεπλύματος χρήματος, αποφυγής κυρώσεων, χρήσης ψευδούς ταυτότητας ή παράκαμψης KYC.

## Το end-to-end γράφημα αξίας
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Ένας actor προσπαθεί να εμποδίσει οποιονδήποτε observer να δει και τα δύο άκρα. Οι investigators κάνουν το αντίστροφο: διατηρούν records σε κάθε boundary, κανονικοποιούν τον χρόνο/την αξία/τα fees και εντοπίζουν το **σημείο επανασύγκλισης** όπου διαφορετικές personas επαναχρησιμοποιούν έναν facilitator, device, account, merchant ή destination.

## Instruments και οι πραγματικοί observers τους

| Instrument | Κρυφό από merchant/κοινό | Εξακολουθεί να είναι ορατό σε |
|---|---|---|
| Issuer virtual card/token | τον underlying card number | issuer, network/token provider, wallet, merchant account και delivery systems |
| Prepaid/gift value | μερικές φορές το legal name σε μια συνηθισμένη αγορά | retailer/payment rail, activation/redemption service, cameras, device και delivery |
| Cash | το public ledger και τον remote issuer | counterparties, cameras, withdrawal/serial controls όπου εφαρμόζεται, physical search |
| Bitcoin/new address | το direct legal name | κάθε blockchain observer, wallet/network peers, acquisition/off-ramp services |
| CoinJoin/PayJoin | τις απλές common-input/payment heuristics | public transaction, coordinator/peer/network metadata και μεταγενέστερη spending behavior |
| Privacy coin | τον public sender/receiver/amount, ανάλογα με το protocol | acquisition/off-ramp, wallet endpoint, network observer και counterparty |
| Centralized mixer | το direct deposit-to-withdraw link | mixer operator/logs, blockchain entry/exit sets και counterparties |
| Cross-chain bridge/swap | τη continuity σε ένα chain | και τα δύο chains, bridge/swap service, timing/value και liquidity constraints |
| OTC/P2P broker | το direct exchange account σε ορισμένες περιπτώσεις | broker, communications, bank/cash movement, counterparties και devices |

## Cards, prepaid value, nominees και mules

### Virtual και masked cards

Ένας issuer μπορεί να δημιουργήσει έναν merchant-locked ή disposable card number. Αυτό μειώνει την έκθεση του merchant και την επαναχρησιμοποίηση του αριθμού μεταξύ merchants. Ο issuer εξακολουθεί να τον αντιστοιχίζει στον customer, στο funding account, στο device, στην IP και στη transaction. Τα billing descriptors, το merchant account, η shipping address και τα browser data εξακολουθούν να μπορούν να συνδεθούν.

Το marketing για “No-name” cards δεν συνεπάγεται anonymous settlement. Οι regulated issuers και distributors μπορεί να πραγματοποιούν identity checks, να διατηρούν records, να επιβάλλουν geography/amount limits και να ανταποκρίνονται σε legal process. Μια card που αποκτήθηκε μέσω stolen identity προσθέτει identity theft· δεν αφαιρεί τα issuer/device/merchant telemetry.

### Prepaid και gift value

Οι prepaid cards και τα gift codes διαχωρίζουν μια μεταγενέστερη redemption από το αρχικό payment instrument, αλλά δημιουργούν ένα αριθμημένο object με events αγοράς, activation, balance-query και redemption. Patterns που έχουν σημασία περιλαμβάνουν bulk purchases, επαναλαμβανόμενες denominations λίγο κάτω από τα controls, distant rapid redemption, ένα device που ελέγχει πολλά balances ή πολλές cards που συγκλίνουν σε έναν merchant/account.

### Nominees, money mules και merchant fronts

Ένας nominee ή mule παρέχει ένα account και legal identity που παρεμβάλλεται μεταξύ του operator και μιας service. Τα networks μπορεί να περιλαμβάνουν recruiters, account holders, payment processors, shell merchants και cash-out brokers σε layers. Αυτό δημιουργεί απόσταση, αλλά κάθε participant προσθέτει communications, fees, behavioral inconsistency και έναν πιθανό cooperating witness. Οι front companies προσθέτουν records για incorporation, tax, banking, director, invoice, hosting και shipment.

Οι defenders θα πρέπει να διερευνούν shared devices/IPs, beneficiary reuse, geolocation contradictions, velocity που δεν συνάδει με το account history, circular transfers, πολλαπλούς άσχετους senders που συγκλίνουν και άμεση onward movement. Μην θεωρείτε ότι ο named account holder είναι ο controlling actor· αντιμετωπίστε τον ως node του οποίου ο ρόλος πρέπει να προσδιοριστεί.

## Patterns obfuscation συναλλαγών σε public-chain

### Address rotation και coin control

Η δημιουργία νέου address για κάθε receipt αποτρέπει την trivial address reuse, αλλά οι transactions μπορούν ακόμη να συνδεθούν μέσω common inputs, change detection, exact value/time και μεταγενέστερου consolidation. Το **Coin control** επιτρέπει σε ένα wallet να επιλέγει ποια outputs θα ξοδέψει και να αποφεύγει τη σύνδεση compartments. Βελτιώνει την hygiene· δεν μπορεί να αφαιρέσει έναν σύνδεσμο που είναι ήδη public.

### Peel chains

Μια peel chain ξοδεύει επανειλημμένα ένα μεγάλο balance, στέλνοντας ένα μικρότερο amount προς τα έξω και επιστρέφοντας το υπόλοιπο σε ένα νέο address:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Η διεύθυνση αλλάζει σε κάθε βήμα, όμως η συνέχεια της αξίας, ο ρυθμός και η δομή των συναλλαγών συχνά σχηματίζουν μια αναγνωρίσιμη αλυσίδα. Τα νόμιμα exchange hot wallets μπορεί να συμπεριφέρονται παρόμοια, επομένως η απόδοση απαιτεί evidence από την υπηρεσία και το context. Το DOJ έχει χρησιμοποιήσει ανάλυση peel-chain σε υποθέσεις κατάσχεσης που συνδέονται με τη DPRK.<sup>[[1]](#references)</sup>

### Structuring και fan-out/fan-in

- **Fan-out:** μία πηγή διαμοιράζεται σε πολλές διευθύνσεις, ώστε να αυξηθεί ο φόρτος της έρευνας ή να προετοιμαστεί παράλληλη μετατροπή.
- **Fan-in:** πολλές πηγές ενοποιούνται σε έναν collector, αποκαλύπτοντας κοινό έλεγχο ή μια υπηρεσία.
- **Structuring:** επαναλαμβανόμενες μικρότερες μεταφορές επιδιώκουν την αποφυγή ορίων ελέγχου ή την ανάμειξη με τον συνηθισμένο όγκο.
- **Commingling:** παράνομα και άσχετα κεφάλαια μοιράζονται wallets, pools ή services, με αποτέλεσμα οι απλοϊκοί αναλογικοί ισχυρισμοί να μην είναι ασφαλείς.

Το σχήμα του graph αποτελεί ένδειξη και όχι απόδειξη. Οι analysts πρέπει να λαμβάνουν υπόψη τα fees, το UTXO/account model, τη συμπεριφορά του service και τις συμβάσεις change.

### CoinJoin και PayJoin

Σε ένα τυπικό CoinJoin, αρκετοί συμμετέχοντες συνεισφέρουν inputs και λαμβάνουν outputs σε μία collaborative transaction, συχνά με ίσες denominations εξόδων. Αυτό καταρρίπτει την υπόθεση ότι κάθε input και output μιας συναλλαγής ανήκει σε έναν μόνο owner. Το anonymity set περιορίζεται από τον αριθμό των συμμετεχόντων και τη μεταγενέστερη συμπεριφορά: unequal change, toxic change, consolidation ή διέλευση από ένα γνωστό service μπορούν να επαναφέρουν τις συνδέσεις.

Το PayJoin τροποποιεί μια συνηθισμένη πληρωμή, ώστε τόσο ο payer όσο και ο payee να συνεισφέρουν inputs, ακυρώνοντας άμεσα το common-input ownership heuristic για τη συγκεκριμένη συναλλαγή. Πρόκειται κυρίως για payment privacy protocol και όχι για bulk laundering service. Η ανίχνευση πρέπει να αποφεύγει να δηλώνει ότι όλα τα inputs ανήκουν στον ίδιο owner και να εκφράζει την αβεβαιότητα, αντί να επιβάλλει ένα εσφαλμένο cluster.

### Centralized mixers και tumblers

Ένα centralized mixer δέχεται deposits και αργότερα καταβάλλει διαφορετικά coins από ένα pooled reserve, συχνά μετά από fees και delays. Η privacy του εξαρτάται από το μέγεθος του pool, την πολιτική withdrawal, τα logs, την εντιμότητα του operator και την ανθεκτικότητα σε seizure. Η ανάλυση του timing/value εισόδου και εξόδου, των deposit addresses, του clustering των service wallets και των records μπορεί να περιορίσει το σύνολο. Οι operators μπορούν να κλέψουν τα funds ή να διατηρούν πλήρη αντιστοίχιση.

Η νομική έκθεση είναι σημαντική και εξαρτάται από τη δικαιοδοσία. Οι υποθέσεις του DOJ κατά των developers/operators των ChipMixer, Samourai Wallet και Tornado Cash, καθώς και η μεταβαλλόμενη litigation σχετικά με sanctions, δείχνουν ότι τα πραγματικά περιστατικά γύρω από το protocol, την custody, τον control και τη money transmission έχουν σημασία· μια ετικέτα όπως «decentralized» δεν αποτελεί νομικό συμπέρασμα.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps και bridges

Το chain hopping μετατρέπει ένα asset ή το μετακινεί μέσω ενός bridge, διακόπτοντας ένα query σε ένα μόνο ledger, αλλά όχι την οικονομική συνέχεια:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Οι αναλυτές συσχετίζουν smart contracts γεφυρών/διευθύνσεις καταθέσεων υπηρεσιών, σειρά συναλλαγών, χρονικό παράθυρο, συναλλαγματική ισοτιμία, χρεώσεις, ρευστότητα και μοναδικό ποσό. Οι επαναλαμβανόμενες swaps μπορεί να αυξήσουν την αμφισημία, προσθέτοντας ταυτόχρονα telemetry από provider/API/wallet. Η FATF αναγνωρίζει συγκεκριμένα το chain hopping, τους mixers, τις peer-to-peer υπηρεσίες και τα anonymity-enhanced currencies ως δείκτες κινδύνου όταν συνδυάζονται με ύποπτο πλαίσιο.<sup>[[3]](#references)</sup>

### NFTs, gambling και αγορές από merchants

Οι συναλλαγές NFT με αυτοσυναλλαγή ή συμπαιγνία μπορούν να προσδώσουν στα funds μια φαινομενική αφήγηση πώλησης· το gambling μπορεί να ανταλλάσσει καταθέσεις με αναλήψεις· τα αγαθά μπορούν να μετατρέπουν ψηφιακή αξία σε αποθέματα που μεταπωλούνται. Αυτές οι διαδρομές αφήνουν λογαριασμούς marketplace, συνδέσεις δημιουργού/royalty, γραφήματα wash-trading, ιστορικό αποδόσεων/παιχνιδιού, device logs, στοιχεία παράδοσης και μεταπώλησης. Μια απώλεια ή χρέωση δεν αποδεικνύει ότι η προέλευση εξαφανίστηκε.

## Κρυπτονομίσματα που διατηρούν την ιδιωτικότητα

Τα privacy protocols διαφέρουν τεχνικά:

- **Monero** χρησιμοποιεί one-time addresses, ring signatures και confidential amounts, μειώνοντας την ορατότητα του αποστολέα/παραλήπτη/ποσού στο public ledger. Η παρατήρηση του δικτύου, η παραβίαση wallet, η απόκτηση/off-ramp και τα αρχεία αντισυμβαλλομένων παραμένουν εκτός αυτών των on-chain προστασιών.
- Τα **Zcash shielded pools** μπορούν να αποκρύψουν τον αποστολέα, τον παραλήπτη και το ποσό όταν χρησιμοποιούνται shielded transactions· οι transparent addresses και οι μεταβάσεις μεταξύ pools παραμένουν δημόσιες, ενώ τα πρότυπα χρήσης επηρεάζουν το πραγματικό anonymity set.
- Το **Bitcoin** είναι transparent by default. Οι νέες διευθύνσεις, το CoinJoin, το PayJoin και το Lightning αλλάζουν συγκεκριμένες παραδοχές σύνδεσης, αλλά δεν καθιστούν όλα τα layers private.

Η privacy technology έχει νόμιμες χρήσεις για την ασφάλεια και το εμπόριο. Από investigative perspective, όταν το ledger παρέχει λιγότερες πληροφορίες, τα endpoint, service, network και human evidence γίνονται σημαντικότερα. Ποτέ μην συμπεραίνεις εγκληματικότητα μόνο από την επιλογή ενός privacy-preserving protocol.

## Μοντέλο υπόθεσης πολλαπλών layers της DPRK

Οι δημόσιες κατηγορίες του DOJ και οι ενέργειες forfeiture περιγράφουν μια συνδυασμένη διαδικασία, όχι ένα μόνο trick:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. εργαζόμενοι χρησιμοποίησαν πλαστό/κλεμμένο υλικό ταυτότητας και VPNs για να εξασφαλίσουν remote employment·
2. οι εργοδότες πλήρωσαν σε cryptocurrency, συμπεριλαμβανομένων stablecoins·
3. τα funds μετακινήθηκαν σε μικρότερα ποσά, πέρασαν από chains ή tokens, χρησιμοποιήθηκαν για αγορές NFTs ή αναμείχθηκαν·
4. άλλα κλεμμένα funds εισήλθαν σε mixers·
5. OTC traders και front companies μετέτρεψαν την αξία σε πληρωμές ή αγαθά σε fiat·
6. επαναλαμβανόμενοι facilitators, accounts και blockchain paths επέτρεψαν στους investigators να επανασυνδέσουν τα layers.

Το Treasury δήλωσε ότι το Lazarus χρησιμοποίησε το Blender.io για να επεξεργαστεί μέρος της κλοπής Axie Infinity/Ronin, ενώ το FBI έχει δημοσιεύσει addresses και παρότρυνε bridges, exchanges, RPC operators και analytics firms να μπλοκάρουν funds που συνδέονται με μεταγενέστερες κλοπές TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Το μάθημα είναι αμφίδρομο: οι state actors χρησιμοποιούν συνηθισμένες εμπορικές/εγκληματικές υπηρεσίες και τα public blockchains επιτρέπουν στους defenders να ακολουθούν την αξία, ακόμη και όταν τα ονόματα είναι αρχικά άγνωστα.

## Ροή εργασίας detection

1. **Διατήρησε τα raw transaction identifiers και records.** Τα screenshots και οι στρογγυλοποιημένες αξίες σε fiat είναι ανεπαρκή.
2. **Κανονικοποίησε τα assets και τον χρόνο.** Κατέγραψε chain, token contract, units, block time, service time zone, fees και exchange-rate source.
3. **Σήμανε το evidence confidence.** Διέκρινε μια address που δημοσιεύτηκε από service, ένα deterministic contract event, ένα clustering heuristic και external intelligence.
4. **Κάνε trace και προς τις δύο κατευθύνσεις.** Εντόπισε την προέλευση χρηματοδότησης, το immediate dispersal, το reconvergence, τα bridge exits, τα service deposits και το spend/delivery.
5. **Σύνδεσε off-chain evidence.** Τα account KYC, device, IP, support tickets, API keys, bank/payment, shipping και communication records συχνά επιλύουν την αμφισημία.
6. **Έλεγξε εναλλακτικές εξηγήσεις.** Exchanges, custodians, payroll και privacy protocols μπορούν να δημιουργήσουν fan-in/out ή co-spends χωρίς κοινή beneficial ownership.
7. **Κάνε monitoring αντί να κλείσεις πρόωρα την υπόθεση.** Ένα dormant output μπορεί αργότερα να καταστεί attributable όταν φτάσει σε service.
8. **Εφάρμοσε τις ισχύουσες υποχρεώσεις sanctions/AML με νομικό σύμβουλο.** Οι κανόνες και οι designations αλλάζουν· η ιστορική συσχέτιση δεν υποκαθιστά την τρέχουσα legal analysis.

## Ασφαλές red-team procurement model

Μια εξουσιοδοτημένη ομάδα μπορεί να χρειαστεί το SOC του στόχου να μην αναγνωρίσει την πληρωμή hosting, ενώ ο engagement controller διατηρεί την accountability:

- χρησιμοποίησε engagement-specific organization card ή documented corporate wallet·
- διατήρησε ακριβή billing, tax και provider records·
- διαχώρισε τον operator από τα procurement duties και περιόρισε την πρόσβαση στο attribution map·
- ποτέ μη χρησιμοποιήσεις mule, false identity, stolen card, sanctions workaround ή unlicensed exchanger·
- κατέγραψε asset, amount, owner, service, date, refund path και teardown evidence·
- αποκάλυψε τους σχετικούς payment/provider indicators στον controller μετά την άσκηση.

Αυτό δημιουργεί **blindness ως προς τον participant της άσκησης**, όχι blindness ως προς τον νόμο, τον provider ή τη διακυβέρνηση.

## References

- [1] [US DOJ — Πλαίσιο επιβολής για τα Cryptocurrency (παράδειγμα peel-chain και έρευνες DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Κατάργηση του ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Δείκτες κόκκινων σημαιών για Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Εκπρόσωπος της Foreign Trade Bank της DPRK κατηγορείται για συνωμοσίες laundering μέσω crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Complaint κατάσχεσης σχετικά με $7,74 εκατομμύρια που φέρεται να ξεπλύθηκαν για την DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Κυρώσεις κατά του Blender.io και funds του Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Η Βόρεια Κορέα ευθύνεται για την κλοπή από το Bybit το 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Εφαρμογή των regulations σε users, administrators και exchangers virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
