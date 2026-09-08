# Tradecraft Χρηματοοικονομικής Απόκρυψης

{{#include ../banners/hacktricks-training.md}}

Η ιδιωτικότητα των πληρωμών είναι πρόβλημα απόδοσης ταυτότητας και όχι πρόβλημα της επωνυμίας πληρωμών. Μια επιχείρηση αφήνει στοιχεία όταν η αξία αποκτάται, μετακινείται, μετατρέπεται, δαπανάται και παραδίδεται. Μια διεύθυνση σε public-chain μπορεί να είναι ψευδωνυμική, ενώ ένα ανταλλακτήριο, ένας εκδότης κάρτας, ένας έμπορος, μια mobile συσκευή ή μια κάμερα αποστολών μπορεί να ταυτοποιήσει το άτομο που κρύβεται πίσω από αυτήν.

Αυτή η σελίδα εξηγεί μοτίβα financial-obfuscation που χρησιμοποιούνται στο cybercrime και σε επιχειρήσεις συνδεδεμένες με κρατικούς φορείς, ώστε οι defenders να μπορούν να τα αναγνωρίζουν. **Δεν** παρέχει διαδικασία laundering, sanctions-evasion, false-identity ή KYC-bypass.

## Το γράφημα αξίας από άκρο σε άκρο
```text
funding source -> acquisition -> transfer/layering -> conversion -> merchant/host -> delivery/use
|              |                |                 |             |
bank/account     KYC/P2P          blockchain         VASP/OTC    service + device
```
Ένας actor προσπαθεί να εμποδίσει οποιονδήποτε observer να δει και τα δύο άκρα. Οι investigators κάνουν το αντίστροφο: διατηρούν records σε κάθε boundary, κανονικοποιούν τον χρόνο/την αξία/τα fees και εντοπίζουν το **σημείο επανασύγκλισης** όπου διαφορετικές personas επαναχρησιμοποιούν έναν facilitator, device, account, merchant ή destination.

## Instruments και οι πραγματικοί observers τους

| Instrument | Κρυφό από τον merchant/το public | Εξακολουθεί να είναι ορατό σε |
|---|---|---|
| Issuer virtual card/token | ο underlying card number | τον issuer, το network/token provider, το wallet, το merchant account και τα delivery systems |
| Prepaid/gift value | μερικές φορές το legal name σε μια συνηθισμένη αγορά | το retailer/payment rail, την activation/redemption service, τις cameras, το device και το delivery |
| Cash | το public ledger και τον remote issuer | τους counterparties, τις cameras, τους withdrawal/serial controls όπου εφαρμόζονται, τη physical search |
| Bitcoin/new address | το direct legal name | κάθε blockchain observer, τους wallet/network peers, τις acquisition/off-ramp services |
| CoinJoin/PayJoin | τα απλά common-input/payment heuristics | το public transaction, τα coordinator/peer/network metadata και τη μεταγενέστερη spending behavior |
| Privacy coin | τον public sender/receiver/amount, ανάλογα με το protocol | την acquisition/off-ramp, το wallet endpoint, τον network observer και τον counterparty |
| Centralized mixer | το direct deposit-to-withdraw link | τον mixer operator/logs, τα blockchain entry/exit sets και τους counterparties |
| Cross-chain bridge/swap | τη continuity σε ένα chain | και τα δύο chains, το bridge/swap service, το timing/value και τους liquidity constraints |
| OTC/P2P broker | το direct exchange account σε ορισμένες περιπτώσεις | τον broker, τις communications, την bank/cash movement, τους counterparties και τα devices |

## Cards, prepaid value, nominees και mules

### Virtual και masked cards

Ένας issuer μπορεί να δημιουργήσει έναν merchant-locked ή disposable card number. Αυτό μειώνει την έκθεση του merchant και την επαναχρησιμοποίηση του number μεταξύ merchants. Ο issuer εξακολουθεί να το αντιστοιχίζει στον customer, το funding account, το device, την IP και το transaction. Τα billing descriptors, το merchant account, η shipping address και τα browser data παραμένουν δυνατό να συσχετιστούν.

Το marketing για “No-name” cards δεν συνεπάγεται anonymous settlement. Οι regulated issuers και distributors μπορεί να πραγματοποιούν identity checks, να διατηρούν records, να επιβάλλουν geography/amount limits και να ανταποκρίνονται σε legal process. Μια card που αποκτήθηκε μέσω stolen identity προσθέτει identity theft· δεν αφαιρεί το issuer/device/merchant telemetry.

### Prepaid και gift value

Οι prepaid cards και τα gift codes διαχωρίζουν ένα μεταγενέστερο redemption από το αρχικό payment instrument, αλλά δημιουργούν ένα αριθμημένο object με purchase, activation, balance-query και redemption events. Σημασία έχουν patterns όπως bulk purchases, επαναλαμβανόμενες denominations λίγο κάτω από τα controls, distant rapid redemption, ένα device που ελέγχει πολλά balances ή πολλές cards που συγκλίνουν σε ένα merchant/account.

### Nominees, money mules και merchant fronts

Ένας nominee ή mule παρέχει ένα account και legal identity που βρίσκεται μεταξύ του operator και μιας service. Τα networks μπορεί να τοποθετούν διαδοχικά recruiters, account holders, payment processors, shell merchants και cash-out brokers. Αυτό δημιουργεί απόσταση, αλλά κάθε participant προσθέτει communications, fees, behavioral inconsistency και έναν πιθανό cooperating witness. Οι front companies προσθέτουν records για incorporation, tax, banking, director, invoice, hosting και shipment.

Οι defenders θα πρέπει να ερευνούν shared devices/IPs, beneficiary reuse, geolocation contradictions, velocity που δεν συνάδει με το account history, circular transfers, πολλούς άσχετους senders που συγκλίνουν και immediate onward movement. Μην υποθέτετε ότι ο named account holder είναι ο controlling actor· αντιμετωπίστε τον ως node που απαιτεί role determination.

## Public-chain transaction-obfuscation patterns

### Address rotation και coin control

Η δημιουργία νέου address για κάθε receipt εμποδίζει την trivial address reuse, αλλά τα transactions μπορούν ακόμη να ενωθούν ως προς την ownership μέσω common inputs, change detection, exact value/time και later consolidation. Το **Coin control** επιτρέπει σε ένα wallet να επιλέγει ποια outputs θα δαπανήσει και να αποφεύγει τη συνένωση compartments. Βελτιώνει το hygiene· δεν μπορεί να αφαιρέσει ένα link που είναι ήδη public.

### Peel chains

Μια peel chain δαπανά επανειλημμένα ένα μεγάλο balance, στέλνοντας ένα μικρότερο amount προς τα έξω και επιστρέφοντας το remainder σε ένα νέο address:
```text
100 -> payment 3 + change 97
97 -> payment 4 + change 93
93 -> payment 2 + change 91 -> ...
```
Η διεύθυνση αλλάζει σε κάθε βήμα, όμως η συνέχεια της αξίας, ο ρυθμός και η δομή των συναλλαγών συχνά σχηματίζουν μια αναγνωρίσιμη αλυσίδα. Τα hot wallets νόμιμων ανταλλακτηρίων μπορούν να συμπεριφέρονται με παρόμοιο τρόπο, επομένως η απόδοση απαιτεί στοιχεία σχετικά με την υπηρεσία/το πλαίσιο. Το DOJ έχει χρησιμοποιήσει ανάλυση peel-chain σε υποθέσεις κατάσχεσης περιουσιακών στοιχείων που συνδέονται με τη DPRK.<sup>[[1]](#references)</sup>

### Structuring and fan-out/fan-in

- **Fan-out:** μία πηγή διαμοιράζει τα κεφάλαια σε πολλές διευθύνσεις, ώστε να αυξήσει τον φόρτο της έρευνας ή να προετοιμάσει παράλληλη μετατροπή.
- **Fan-in:** πολλές πηγές συγκεντρώνονται σε έναν συλλέκτη, αποκαλύπτοντας κοινό έλεγχο ή μια υπηρεσία.
- **Structuring:** επαναλαμβανόμενες μικρότερες μεταφορές επιδιώκουν την αποφυγή ορίων ελέγχου ή την ενσωμάτωση στον συνήθη όγκο.
- **Commingling:** παράνομα και άσχετα κεφάλαια μοιράζονται wallets, pools ή υπηρεσίες, καθιστώντας μη ασφαλείς τις απλουστευμένες αναλογικές εκτιμήσεις.

Το σχήμα του γράφου αποτελεί ένδειξη, όχι απόδειξη. Οι αναλυτές πρέπει να λαμβάνουν υπόψη τις προμήθειες, το μοντέλο UTXO/account, τη συμπεριφορά της υπηρεσίας και τις συμβάσεις επιστροφής ρέστων.

### CoinJoin and PayJoin

Σε ένα τυπικό CoinJoin, αρκετοί συμμετέχοντες συνεισφέρουν inputs και λαμβάνουν outputs σε μία συνεργατική συναλλαγή, συχνά με ίσες ονομαστικές αξίες output. Αυτό καταρρίπτει την υπόθεση ότι κάθε input και output μιας συναλλαγής έχει έναν ιδιοκτήτη. Το anonymity set περιορίζεται από τον αριθμό των συμμετεχόντων και τη μετέπειτα συμπεριφορά: άνισα change, toxic change, consolidation ή διέλευση από γνωστή υπηρεσία μπορούν να επαναφέρουν τις συνδέσεις.

Το PayJoin τροποποιεί μια συνηθισμένη πληρωμή, έτσι ώστε τόσο ο πληρωτής όσο και ο δικαιούχος να συνεισφέρουν inputs, ακυρώνοντας άμεσα το common-input ownership heuristic για τη συγκεκριμένη συναλλαγή. Πρόκειται κυρίως για πρωτόκολλο privacy πληρωμών και όχι για υπηρεσία μαζικού laundering. Η ανίχνευση θα πρέπει να αποφεύγει να δηλώνει ότι όλα τα inputs ανήκουν στον ίδιο ιδιοκτήτη και να εκφράζει την αβεβαιότητα, αντί να επιβάλλει ένα ψευδές cluster.

### Centralized mixers and tumblers

Ένας centralized mixer δέχεται καταθέσεις και αργότερα καταβάλλει διαφορετικά coins από ένα pooled reserve, συχνά μετά από προμήθειες και καθυστερήσεις. Η privacy του εξαρτάται από το μέγεθος του pool, την πολιτική αναλήψεων, τα logs, την ειλικρίνεια του operator και την ανθεκτικότητα σε seizure. Η ανάλυση χρονισμού/αξίας εισόδου και εξόδου, οι διευθύνσεις καταθέσεων, το clustering των service wallets και τα αρχεία μπορούν να περιορίσουν το σύνολο. Οι operators μπορούν να κλέψουν τα κεφάλαια ή να διατηρούν πλήρη αντιστοίχιση.

Η νομική έκθεση είναι σημαντική και εξαρτάται από τη δικαιοδοσία. Οι υποθέσεις του DOJ κατά των ChipMixer, Samourai Wallet και των developers/operators του Tornado Cash, καθώς και η μεταβαλλόμενη δικαστική διαμάχη για τις κυρώσεις, δείχνουν ότι τα πραγματικά περιστατικά σχετικά με το πρωτόκολλο, την custody, τον έλεγχο και τη μετάδοση χρημάτων έχουν σημασία· ένας χαρακτηρισμός όπως «decentralized» δεν αποτελεί νομικό συμπέρασμα.<sup>[[2]](#references)</sup>

### Cross-chain hopping, swaps and bridges

Το chain hopping μετατρέπει ένα asset ή το μεταφέρει μέσω bridge, διακόπτοντας ένα query σε ένα ledger, αλλά όχι την οικονομική συνέχεια:
```text
chain A deposit -> bridge/swap event -> chain B issuance/withdrawal
t0, amount A                    t1, amount B - fees
```
Οι αναλυτές συσχετίζουν τα bridge contracts/service deposit addresses, τη σειρά των συναλλαγών, το χρονικό παράθυρο, την ισοτιμία, τις προμήθειες, τη ρευστότητα και το μοναδικό ποσό. Οι επαναλαμβανόμενες swaps μπορεί να αυξήσουν την αμφισημία, ενώ παράλληλα προσθέτουν telemetry από provider/API/wallet. Το FATF αναγνωρίζει ειδικά το chain hopping, τα mixers, τις peer-to-peer υπηρεσίες και τα anonymity-enhanced currencies ως δείκτες κινδύνου όταν συνδυάζονται με ύποπτο πλαίσιο.<sup>[[3]](#references)</sup>

### NFTs, gambling και αγορές από εμπόρους

Οι συναλλαγές NFT με αυτοσυναλλαγή ή συμπαιγνία μπορούν να προσδώσουν στα funds μια φαινομενική αφήγηση πώλησης· το gambling μπορεί να ανταλλάσσει καταθέσεις με αναλήψεις· τα αγαθά μπορούν να μετατρέπουν ψηφιακή αξία σε μεταπωλήσιμο απόθεμα. Αυτές οι διαδρομές αφήνουν marketplace accounts, creator/royalty links, wash-trading graphs, odds/play history, device logs, καθώς και στοιχεία παράδοσης και μεταπώλησης. Μια απώλεια ή προμήθεια δεν αποτελεί απόδειξη ότι η προέλευση εξαφανίστηκε.

## Κρυπτονομίσματα που διατηρούν την ιδιωτικότητα

Τα privacy protocols διαφέρουν τεχνικά:

- Το **Monero** χρησιμοποιεί one-time addresses, ring signatures και confidential amounts, μειώνοντας την ορατότητα του public sender/receiver/amount. Η παρατήρηση του δικτύου, η παραβίαση wallet, η απόκτηση/off-ramp και τα αρχεία counterparty παραμένουν εκτός αυτών των on-chain protections.
- Τα **Zcash shielded pools** μπορούν να αποκρύψουν sender, receiver και amount όταν χρησιμοποιούνται shielded transactions· οι transparent addresses και οι μεταβάσεις μεταξύ pools παραμένουν public, ενώ τα usage patterns επηρεάζουν το effective anonymity set.
- Το **Bitcoin** είναι transparent by default. Τα new addresses, το CoinJoin, το PayJoin και το Lightning αλλάζουν συγκεκριμένες παραδοχές linkage, αλλά δεν καθιστούν όλα τα layers private.

Η privacy technology έχει νόμιμες χρήσεις ασφάλειας και εμπορικές χρήσεις. Από investigative perspective, όταν το ledger παρέχει λιγότερες πληροφορίες, τα endpoint, service, network και human evidence γίνονται σημαντικότερα. Ποτέ μην συμπεραίνετε εγκληματικότητα μόνο από την επιλογή ενός privacy-preserving protocol.

## DPRK multi-layer case model

Οι δημόσιες καταγγελίες και οι ενέργειες forfeiture του DOJ περιγράφουν μια σύνθετη διαδικασία και όχι ένα μόνο τέχνασμα:<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

1. εργαζόμενοι χρησιμοποίησαν πλαστό/κλεμμένο υλικό ταυτότητας και VPNs για να εξασφαλίσουν remote employment·
2. οι εργοδότες πλήρωσαν cryptocurrency, συμπεριλαμβανομένων stablecoins·
3. τα funds μετακινήθηκαν σε μικρότερα ποσά, διέσχισαν chains ή tokens, αγόρασαν NFTs ή αναμίχθηκαν με άλλα funds·
4. άλλα stolen funds εισήλθαν σε mixers·
5. OTC traders και front companies μετέτρεψαν την αξία σε fiat payments ή αγαθά·
6. οι επαναλαμβανόμενοι facilitators, οι λογαριασμοί και τα blockchain paths επέτρεψαν στους investigators να επανασυνδέσουν τα layers.

Το Treasury δήλωσε ότι το Lazarus χρησιμοποίησε το Blender.io για να επεξεργαστεί μέρος της κλοπής Axie Infinity/Ronin, ενώ το FBI έχει δημοσιεύσει addresses και έχει καλέσει bridges, exchanges, RPC operators και analytics firms να μπλοκάρουν funds που συνδέονται με μεταγενέστερες κλοπές TraderTraitor.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

Το δίδαγμα είναι αμφίδρομο: οι κρατικοί actors χρησιμοποιούν συνηθισμένες commercial/criminal services και τα public blockchains επιτρέπουν στους defenders να ακολουθούν την αξία, ακόμη και όταν τα ονόματα είναι αρχικά άγνωστα.

## Detection workflow

1. **Διατηρήστε τα raw transaction identifiers και records.** Τα screenshots και οι στρογγυλοποιημένες fiat values είναι ανεπαρκή.
2. **Κανονικοποιήστε τα assets και τον χρόνο.** Καταγράψτε chain, token contract, units, block time, service time zone, fees και exchange-rate source.
3. **Επισημάνετε το evidence confidence.** Διακρίνετε ένα service-published address, ένα deterministic contract event, ένα clustering heuristic και external intelligence.
4. **Ακολουθήστε και τις δύο κατευθύνσεις.** Εντοπίστε funding origin, immediate dispersal, reconvergence, bridge exits, service deposits και spend/delivery.
5. **Συνδέστε off-chain evidence.** Τα account KYC, device, IP, support tickets, API keys, bank/payment, shipping και communication records συχνά επιλύουν την αμφισημία.
6. **Ελέγξτε alternative explanations.** Τα exchanges, custodians, payroll και privacy protocols μπορούν να δημιουργήσουν fan-in/out ή co-spends χωρίς κοινή beneficial ownership.
7. **Παρακολουθείτε αντί να κλείσετε πρόωρα την υπόθεση.** Ένα dormant output μπορεί αργότερα να καταστεί attributable όταν φτάσει σε service.
8. **Εφαρμόστε τις τρέχουσες sanctions/AML obligations με νομικό σύμβουλο.** Οι κανόνες και οι designations αλλάζουν· η ιστορική συσχέτιση δεν υποκαθιστά την τρέχουσα νομική ανάλυση.

## Safe red-team procurement model

Μια authorized team μπορεί να χρειάζεται το target SOC να μην αναγνωρίσει το hosting payment, ενώ ο engagement controller διατηρεί την accountability:

- χρησιμοποιήστε μια engagement-specific organization card ή ένα documented corporate wallet·
- διατηρήστε ακριβή billing, tax και provider records·
- διαχωρίστε τον operator από τα procurement duties και περιορίστε την πρόσβαση στο attribution map·
- μην χρησιμοποιήσετε mule, false identity, stolen card, sanctions workaround ή unlicensed exchanger·
- καταγράψτε asset, amount, owner, service, date, refund path και teardown evidence·
- γνωστοποιήστε τους σχετικούς payment/provider indicators στον controller μετά την άσκηση.

Αυτό δημιουργεί **blindness ως προς τον participant της άσκησης**, όχι blindness ως προς τον νόμο, τον provider ή το governance.

## References

- [1] [US DOJ — Πλαίσιο επιβολής για τα Cryptocurrency (παράδειγμα peel-chain και έρευνες DPRK)](https://www.justice.gov/archives/ag/page/file/1326061/dl?inline=)
- [2] [US DOJ — Κατάργηση του ChipMixer](https://www.justice.gov/archives/opa/pr/justice-department-investigation-leads-takedown-darknet-cryptocurrency-mixer-processed-over-3)
- [3] [FATF — Δείκτες κόκκινων σημαιών για τα Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [4] [US DOJ — Εκπρόσωπος της Foreign Trade Bank της DPRK κατηγορείται για συνωμοσίες ξεπλύματος μέσω crypto](https://www.justice.gov/archives/opa/pr/north-korean-foreign-trade-bank-representative-charged-crypto-laundering-conspiracies)
- [5] [US DOJ — Καταγγελία forfeiture σχετικά με $7.74 εκατομμύρια που φέρεται να ξεπλύθηκαν για την DPRK](https://www.justice.gov/usao-dc/pr/department-files-civil-forfeiture-complaint-against-more-774-million-laundered-behalf-0)
- [6] [US Treasury — Κυρώσεις στο Blender.io και funds του Lazarus](https://home.treasury.gov/news/press-releases/jy0768)
- [7] [FBI — Η Βόρεια Κορέα ευθύνεται για την κλοπή από το Bybit το 2025](https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack)
- [8] [FinCEN — Εφαρμογή των regulations σε users, administrators και exchangers virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
{{#include ../banners/hacktricks-training.md}}
