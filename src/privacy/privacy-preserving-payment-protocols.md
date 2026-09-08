# Πρωτόκολλα πληρωμών που διατηρούν την ιδιωτικότητα

Τα προηγμένα συστήματα πληρωμών μπορούν να αποκρύπτουν τον πληρωτή από τον έμπορο, να αποκρύπτουν τον παραλήπτη ή το ποσό από ένα δημόσιο ledger ή να εμποδίζουν ένα mint να συνδέσει την ανάληψη με την εξαργύρωση. Αυτές είναι διαφορετικές ιδιότητες. Καμία δεν εξαλείφει τα αρχεία απόκτησης, συσκευής, δικτύου, παράδοσης, λογιστικής, κυρώσεων ή endpoint.

Ο [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) παρέχει τυποποιημένη καταχώριση `Pros`, `Cons`, βήμα-προς-βήμα `Procedure` και `Detection` για κάθε οικογένεια πληρωμών. Αυτή η σελίδα επεκτείνει τα προηγμένα πρωτόκολλα.

{% hint style="danger" %}
Χρησιμοποιείτε μόνο νόμιμα κεφάλαια και αντισυμβαλλόμενους. Μην χρησιμοποιείτε privacy protocols για να παρακάμψετε απαιτούμενη ταυτοποίηση, κυρώσεις, φορολογία, ελέγχους προέλευσης κεφαλαίων ή αναφορά συναλλαγών. Μην λειτουργείτε exchange, mint ή υπηρεσία μεταφοράς χωρίς να κατανοείτε τις υποχρεώσεις αδειοδότησης, custody, AML και προστασίας καταναλωτών.
{% endhint %}

## Σύγκριση των προηγμένων επιλογών

| Protocol | Τι αποκρύπτει από το public/merchant | Trusted ή observing party | Ωριμότητα/διαθεσιμότητα |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Οι εξωτερικοί παρατηρητές δεν μπορούν να συνδέσουν έναν επαναχρησιμοποιήσιμο payment code με τα one-time outputs του | Το public Bitcoin graph παραμένει· ο wallet/index server μπορεί να βλέπει τα scans | Η προδιαγραφή έχει ολοκληρωθεί· η υποστήριξη wallet διαφέρει |
| Zcash fully shielded Orchard | Ο αποστολέας, ο παραλήπτης και το ποσό είναι κρυπτογραφημένα on-chain | Το wallet backend/network και το acquisition/off-ramp παραμένουν | Deployed· η shielded υποστήριξη διαφέρει ανά wallet/exchange |
| GNU Taler | Ο merchant δεν χρειάζεται να γνωρίζει την ταυτότητα του payer· το εισόδημα του merchant παραμένει accountable | Το Taler exchange/bank βλέπει τη χρηματοδότηση· ο merchant βλέπει την παραγγελία | Τα deployments είναι γεωγραφικά περιορισμένα |
| Federated Chaumian e-cash | Η federation δεν θα πρέπει να συνδέει τα issued notes με τα internal transfers/redemption | Το guardian quorum έχει custody των reserves· τα gateways βλέπουν boundary activity | Αναδυόμενα community deployments |
| Lightning BOLT 12/route blinding | Μειώνει την αποκάλυψη του receiver/node και της διαδρομής | Τα endpoints, τα επιλεγμένα hops, το funding chain και οι wallet services | Η υποστήριξη εξαρτάται από το wallet |
| Virtual card/token | Ο merchant λαμβάνει περιορισμένο credential και όχι επαναχρησιμοποιήσιμο PAN | Ο issuer/network διατηρεί τον payer και τη συναλλαγή | Ώριμο και ευρέως διαθέσιμο |

## Bitcoin Silent Payments (BIP 352)

Τα Silent Payments επιτρέπουν σε έναν receiver να δημοσιεύει έναν στατικό payment code, ενώ κάθε sender παράγει ένα μοναδικό Taproot output. Ένας εξωτερικός παρατηρητής του chain δεν μπορεί να συνδέσει άμεσα αυτά τα outputs με τον δημοσιευμένο code, ενώ δεν απαιτείται interactive address request ή on-chain notification output. Το BIP 352 χαρακτηρίζεται **Ολοκληρωμένο**, αλλά εισάγει κόστος scanning και δεν είναι συμβατό με wallets που δεν το έχουν υλοποιήσει.<sup>[[1]](#references)</sup>

### Ροή εργασίας receiver

1. Επιλέξτε ένα maintained wallet που υποστηρίζει ρητά λήψη μέσω BIP 352· επαληθεύστε τη δυνατότητα με βάση την τρέχουσα τεκμηρίωση του wallet και όχι έναν ισχυρισμό στα social media.
2. Δημιουργήστε αντίγραφο ασφαλείας του wallet seed και του Silent Payment descriptor/key material, χρησιμοποιώντας τη documented recovery method του wallet. Δοκιμάστε την ανακάλυψη με μικρό ποσό σε testnet/mainnet πριν δημοσιεύσετε τον code.
3. Δημιουργήστε ξεχωριστά **labels** για campaigns, invoices ή counterparties όπου το wallet υποστηρίζει BIP 352 labels. Τα labels βοηθούν την τοπική λογιστική χωρίς να δημοσιεύουν διευθύνσεις που μπορούν να συνδεθούν.
4. Δημοσιεύστε τον static Silent Payment code μέσω authenticated channel. Είναι επαναχρησιμοποιήσιμος, αλλά ένας impostor μπορεί να αντικαταστήσει τον code με δικό του.
5. Κάντε scan μέσω local full node όταν είναι πρακτικό. Ένας third-party index/scanning server μπορεί να μάθει τον χρόνο των requests ή τα filter data, ακόμη και αν δεν μπορεί να κάνει spend.
6. Διατηρήστε τα discovered UTXOs με labels και εφαρμόστε τους ίδιους κανόνες coin-control όπως στο συνηθισμένο Bitcoin. Η δαπάνη ή η ενοποίησή τους μπορεί να αποκαλύψει σχέσεις ιδιοκτησίας.
7. Επιβεβαιώστε ότι το recovery ανακαλύπτει τις πληρωμές χωρίς να βασίζεται σε external index που δεν έχει υποστεί backup.

### Ροή εργασίας sender

1. Επιβεβαιώστε ότι το wallet υποστηρίζει αποστολή στη συγκεκριμένη address version και authenticated τον στατικό κωδικό του receiver.
2. Αφήστε το wallet να κατασκευάσει το output· ποτέ μην μετατρέπετε ή περικόπτετε τον code χειροκίνητα.
3. Ελέγξτε προσεκτικά τα επιλεγμένα inputs. Τα Silent Payments βελτιώνουν την privacy της διεύθυνσης του recipient, αλλά τα inputs του sender παραμένουν στο public graph.
4. Χρησιμοποιήστε τη wallet-supported συμπεριφορά fee bumping/PSBT. Το BIP 352 απαιτεί εκ νέου derivation του output αν αλλάξουν τα inputs, ενώ ορισμένες signing modes δεν είναι ασφαλείς.
5. Διατηρήστε ένα κρυπτογραφημένο receipt ή proof που απαιτείται για disputes/accounting.

Τα Silent Payments επιλύουν τη repeated publication διευθύνσεων του recipient. Δεν αποκρύπτουν το ποσό, τον χρόνο της συναλλαγής, το sender cluster, το acquisition history ή το μεταγενέστερο co-spending.

## Zcash fully shielded payments

Το Zcash υποστηρίζει transparent και shielded value pools. Οι Orchard shielded transactions χρησιμοποιούν zero-knowledge proofs, ώστε οι nodes να μπορούν να επαληθεύουν την εγκυρότητα ενώ οι λεπτομέρειες της συναλλαγής είναι κρυπτογραφημένες· τα Unified Addresses μπορούν να περιέχουν πολλαπλούς τύπους receivers.<sup>[[2]](#references)</sup> Η privacy εξαρτάται από την πραγματική διαδρομή που επιλέγει το wallet και όχι από τον πρώτο χαρακτήρα μιας εμφανιζόμενης διεύθυνσης.

### Shielded workflow

1. Επιλέξτε ένα maintained wallet που προσδιορίζει ξεκάθαρα τη συμπεριφορά **shielded-by-default** και την τρέχουσα υποστήριξη Orchard. Επαληθεύστε το download και δημιουργήστε/δοκιμάστε backup του seed.
2. Αποκτήστε ZEC νόμιμα και καταγράψτε τη βάση/πηγή. Ένα exchange εξακολουθεί να γνωρίζει την απόκτηση και την ανάληψη.
3. Λάβετε σε Unified Address που υποστηρίζεται από το wallet και στη συνέχεια ελέγξτε αν η συναλλαγή κατέληξε σε shielded pool. Μην υποθέτετε automatic shielding χωρίς να επιβεβαιώσετε τη συμπεριφορά του wallet.
4. Προτιμήστε **shielded-to-shielded** transfers. Οι κινήσεις transparent-to-shielded και shielded-to-transparent στα boundaries εκθέτουν public values/timing και μπορούν να επιτρέψουν amount correlation· η Orchard specification αναφέρει ότι η αποστολή σε non-Orchard address αποκαλύπτει την αξία της συναλλαγής.<sup>[[3]](#references)</sup>
5. Αποφύγετε distinctive exact-amount round trips και άμεσες boundary crossings. Πρόκειται για privacy hygiene και όχι για άδεια απόκρυψης ιδιοκτησίας ή reporting.
6. Χρησιμοποιήστε το υποστηριζόμενο network-privacy path του wallet. Η shielded cryptography δεν αποκρύπτει το IP/timing από wallet servers ή peers.
7. Διατηρήστε εσωτερικά compliance records και χρησιμοποιήστε viewing keys μόνο για σκόπιμο audit/disclosure, αφού κατανοήσετε το scope τους.
8. Επιβεβαιώστε την υποστήριξη του recipient wallet/exchange πριν την αποστολή· ένας forced transparent receiver αλλάζει την ιδιότητα privacy.

## GNU Taler: anonymous payer, accountable merchant

Το GNU Taler είναι ένα open electronic-payment protocol που χρησιμοποιεί παραδοσιακά νομίσματα, blind signatures και regulated exchange/bank integration. Ο σχεδιασμός του στοχεύει στο να παραμένουν οι customers anonymous προς τους merchants, ενώ οι merchants παραμένουν identifiable και taxable.<sup>[[4]](#references)</sup> Δεν είναι cryptocurrency και η διαθεσιμότητα εξαρτάται από compatible regional exchange, bank, wallet και merchant.

### User workflow όπου έχει αναπτυχθεί

1. Εντοπίστε ένα operating Taler exchange και merchant στο σχετικό currency/jurisdiction· διαβάστε τους τρέχοντες όρους, fees, KYC και privacy notices.
2. Εγκαταστήστε το official wallet και επαληθεύστε την πηγή του. Προστατεύστε τα wallet backup/recovery data όπως τα μετρητά, επειδή η αξία του wallet μπορεί να είναι bearer asset.
3. Κάντε withdraw value μέσω του υποστηριζόμενου bank/exchange flow χρησιμοποιώντας truthful information. Το funding institution/exchange μπορεί να γνωρίζει την ανάληψη, παρότι οι blind signatures διακόπτουν την άμεση σύνδεση coin-to-withdrawal.
4. Ελέγξτε το merchant contract στο wallet: ταυτότητα merchant, item/summary, ποσό, fees, refund και delivery terms.
5. Πληρώστε και διατηρήστε τα receipt data που απαιτούνται για refund, warranty, accounting ή tax.
6. Μην επαναχρησιμοποιείτε προαιρετικά merchant session/account identifiers, αν απαιτείται merchant unlinkability.
7. Συμπεριλάβετε στο threat model τα wallet, network και delivery metadata· η payment cryptography του Taler δεν αποκρύπτει μια shipping address ή ένα compromised endpoint.

Ο merchant και το exchange παραμένουν accountable, ενώ η λειτουργία οποιουδήποτε από τα δύο μπορεί να αποτελεί regulated payment-service activity.

## Federated Chaumian e-cash

Το Chaumian e-cash χρησιμοποιεί blind signatures, ώστε ένα mint να υπογράφει ένα token χωρίς να βλέπει το unblinded token που δαπανάται αργότερα. Το Fedimint κατανέμει το reserve custody και το signing σε μια guardian federation· η τεκμηρίωσή του αναφέρει ότι οι guardians βλέπουν aggregate reserves/outstanding notes, αλλά δεν θα πρέπει να βλέπουν το individual balance ή ποιος πλήρωσε ποιον μέσα στη federation.<sup>[[5]](#references)</sup>

Πρόκειται για **custodial bearer value**. Ένα επαρκές guardian quorum ελέγχει τα reserves· αποτυχία της federation, dishonest guardians, software bugs ή απώλεια client state μπορούν να προκαλέσουν απώλεια. Οι deposits, withdrawals και Lightning gateways είναι ορατά boundary events και μπορούν να συσχετίσουν timing/amount.

### Workflow περιορισμένου κινδύνου

1. Χρησιμοποιήστε μόνο μικρό ποσό που μπορείτε να χάσετε. Θεωρήστε τις public/unknown federations υψηλότερου κινδύνου από guardians με πραγματική λογοδοσία.
2. Επαληθεύστε το federation invite μέσω authenticated channel και καταγράψτε τις ταυτότητες των guardians, το quorum, τη δικαιοδοσία, τα fees, το recovery και την shutdown policy.
3. Εγκαταστήστε ένα maintained compatible wallet, επαληθεύστε το και κατανοήστε το backup scheme πριν κάνετε deposit.
4. Κάντε deposit νόμιμα αποκτημένου Bitcoin μέσω του documented path. Καταγράψτε το peg-in για accounting και θεωρήστε ότι το timing/amount είναι public ή γνωστό στο boundary.
5. Μέσα στη federation, χρησιμοποιείτε fresh payment requests και αποφύγετε την προσθήκη account/chat/delivery identifiers που επαναδημιουργούν τη σύνδεση την οποία αφαίρεσε η blind signature.
6. Για Lightning payments, θεωρήστε το gateway πρόσθετο observer των invoices και του boundary timing.
7. Κάντε redeem/withdraw σύμφωνα με την policy, αναμένοντας ότι ένα distinctive amount και άμεσο timing μπορούν να συσχετιστούν με deposit ή external payment.
8. Διατηρήστε ιδιωτικά τα tax/source/authorization records· μην ζητάτε από guardians ή gateways να παρουσιάσουν ανακριβώς τη δραστηριότητα.

Μην περιγράφετε το federated e-cash ως trustless, self-custodial ή εγγυημένα anonymous.

## BOLT 12 offers και route blinding

Τα BOLT 12 offers μπορούν να είναι reusable χωρίς δημοσίευση σταθερής on-chain address και μπορούν να χρησιμοποιούν blinded paths, ώστε ο payer να μη χρειάζεται να γνωρίζει το clear node identity/path του receiver. Αυτό συμπληρώνει, αλλά δεν αντικαθιστά, το υπάρχον onion routing του Lightning.

Πριν από τη χρήση:

1. Επιβεβαιώστε ότι τα sender και receiver wallets υποστηρίζουν τα ίδια τρέχοντα BOLT 12 features· μην συμπεραίνετε υποστήριξη από γενικό branding “Lightning”.
2. Κάντε authenticate το offer out of band και ελέγξτε το ποσό, τον issuer/description και τους recurrence rules.
3. Χρησιμοποιήστε fresh invoice/payment context που δημιουργείται από το offer.
4. Περιορίστε στο ελάχιστο τα node aliases, τις public contact information και τα stable network endpoints.
5. Θεωρήστε ότι ο sender/receiver, το first/last hop, η wallet service, το channel graph και το on-chain funding/closure εξακολουθούν να αποκαλύπτουν τμήματα της σχέσης.

## Auditability χωρίς public disclosure

Η privacy και το audit μπορούν να συνυπάρχουν:

- Διατηρείτε labels, invoices, authorization, cost basis και ownership mapping κρυπτογραφημένα εκτός του public protocol.
- Διαχωρίστε ένα **view/audit key** από ένα spending key όταν το protocol παρέχει τέτοια δυνατότητα· δοκιμάστε πρώτα το ακριβές disclosure του σε sample wallet.
- Δώστε σε auditor το ελάχιστο scoped proof αντί για seed ή unrestricted spending credential.
- Καταγράψτε την έκδοση software, το protocol/pool, το transaction ID ή proof, τον σκοπό του counterparty και την πηγή exchange-rate κατά τον χρόνο της συναλλαγής.
- Ορίστε retention και deletion αντί να συσσωρεύετε ένα μόνιμο, μη κρυπτογραφημένο identity graph.

## Checklist επιλογής

- [ ] Το hidden field και ο observer έχουν προσδιοριστεί με ακρίβεια.
- [ ] Η υποστήριξη wallet/protocol επαληθεύτηκε κατά την ημερομηνία της συναλλαγής.
- [ ] Τα acquisition, network, node/RPC, counterparty, delivery και later-spend links έχουν τεκμηριωθεί.
- [ ] Οι κίνδυνοι custody, recovery, liquidity, issuer/federation solvency και refund έχουν γίνει αποδεκτοί.
- [ ] Τα απαιτούμενα identity, tax, sanctions, source και organizational records παραμένουν ακριβή.
- [ ] Ένα μικρό end-to-end test, συμπεριλαμβανομένων των recovery και audit proof, ολοκληρώθηκε επιτυχώς.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Unified Addresses](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [Τεκμηρίωση GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Πώς λειτουργεί](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
