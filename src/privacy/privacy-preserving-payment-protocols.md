# Privacy-Preserving Payment Protocols

{{#include ../banners/hacktricks-training.md}}

Τα προηγμένα συστήματα πληρωμών μπορούν να αποκρύψουν τον πληρωτή από τον έμπορο, να αποκρύψουν τον παραλήπτη ή το ποσό από ένα δημόσιο ledger ή να εμποδίσουν ένα mint να συνδέσει την ανάληψη με την εξαργύρωση. Πρόκειται για διαφορετικές ιδιότητες. Καμία δεν εξαλείφει τα records απόκτησης, συσκευής, δικτύου, παράδοσης, λογιστικής, κυρώσεων ή endpoint.

Ο [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) παρέχει τυποποιημένη καταχώριση `Pros`, `Cons`, βήμα-βήμα `Procedure` και `Detection` για κάθε οικογένεια πληρωμών. Αυτή η σελίδα επεκτείνει τα προηγμένα πρωτόκολλα.

{% hint style="danger" %}
Χρησιμοποιείτε μόνο νόμιμα κεφάλαια και αντισυμβαλλομένους. Μην χρησιμοποιείτε privacy protocols για να παρακάμψετε απαιτούμενη ταυτοποίηση, κυρώσεις, φορολογία, ελέγχους προέλευσης κεφαλαίων ή αναφορά συναλλαγών. Μην λειτουργείτε exchange, mint ή υπηρεσία μεταφοράς χωρίς να κατανοείτε τις υποχρεώσεις αδειοδότησης, custody, AML και προστασίας καταναλωτή.
{% endhint %}

## Σύγκριση των προηγμένων επιλογών

| Πρωτόκολλο | Τι αποκρύπτει από το public/merchant | Έμπιστο ή παρατηρούν μέρος | Ωριμότητα/διαθεσιμότητα |
|---|---|---|---|
| Bitcoin Silent Payments (BIP 352) | Οι εξωτερικοί παρατηρητές δεν μπορούν να συνδέσουν έναν επαναχρησιμοποιήσιμο payment code με τα one-time outputs του | Το δημόσιο Bitcoin graph παραμένει· το wallet/index server μπορεί να βλέπει τα scans | Η προδιαγραφή έχει ολοκληρωθεί· η υποστήριξη wallet διαφέρει |
| Zcash fully shielded Orchard | Ο αποστολέας, ο παραλήπτης και το ποσό είναι κρυπτογραφημένα on-chain | Το wallet backend/network και το acquisition/off-ramp παραμένουν | Σε ανάπτυξη· η υποστήριξη shielded διαφέρει ανά wallet/exchange |
| GNU Taler | Ο έμπορος δεν χρειάζεται να γνωρίζει την ταυτότητα του πληρωτή· τα έσοδα του εμπόρου παραμένουν accountable | Το Taler exchange/bank βλέπει τη χρηματοδότηση· ο έμπορος βλέπει την παραγγελία | Οι deployments είναι γεωγραφικά περιορισμένες |
| Federated Chaumian e-cash | Η federation δεν θα πρέπει να συνδέει τα εκδοθέντα notes με τις εσωτερικές transfers/redemption | Το guardian quorum έχει custody των reserves· τα gateways βλέπουν boundary activity | Αναδυόμενες community deployments |
| Lightning BOLT 12/route blinding | Μειώνει την αποκάλυψη receiver/node και route | Τα endpoints, τα επιλεγμένα hops, το funding chain και οι wallet services | Η υποστήριξη εξαρτάται από το wallet |
| Virtual card/token | Ο έμπορος λαμβάνει constrained credential και όχι reusable PAN | Ο issuer/network διατηρεί τον πληρωτή και τη συναλλαγή | Ώριμο και ευρέως διαθέσιμο |

## Bitcoin Silent Payments (BIP 352)

Τα Silent Payments επιτρέπουν σε έναν παραλήπτη να δημοσιεύσει έναν static payment code, ενώ κάθε αποστολέας παράγει ένα μοναδικό Taproot output. Ένας εξωτερικός παρατηρητής του chain δεν μπορεί να συνδέσει άμεσα αυτά τα outputs με τον δημοσιευμένο code, ενώ δεν απαιτείται interactive address request ή on-chain notification output. Το BIP 352 έχει την ένδειξη **Complete**, αλλά εισάγει κόστος scanning και δεν είναι συμβατό με wallets που δεν το έχουν υλοποιήσει.<sup>[[1]](#references)</sup>

### Workflow παραλήπτη

1. Επιλέξτε ένα maintained wallet που υποστηρίζει ρητά BIP 352 receiving· επαληθεύστε τη λειτουργία στην τρέχουσα τεκμηρίωση του wallet και όχι σε ισχυρισμό social media.
2. Δημιουργήστε backup του wallet seed και του Silent Payment descriptor/key material χρησιμοποιώντας τη documented recovery method του wallet. Δοκιμάστε την ανακάλυψη με μικρό ποσό σε testnet/mainnet πριν δημοσιεύσετε τον code.
3. Δημιουργήστε ξεχωριστά **labels** για campaigns, invoices ή counterparties όπου το wallet υποστηρίζει BIP 352 labels. Τα labels βοηθούν την τοπική λογιστική χωρίς να δημοσιεύουν linkable addresses.
4. Δημοσιεύστε τον static Silent Payment code μέσω authenticated channel. Είναι επαναχρησιμοποιήσιμος, αλλά ένας impostor μπορεί να αντικαταστήσει τον code με δικό του.
5. Εκτελείτε scanning μέσω local full node όταν είναι πρακτικό. Ένας third-party index/scanning server μπορεί να μάθει το request timing ή filter data, ακόμη και αν δεν μπορεί να κάνει spend.
6. Διατηρείτε τα discovered UTXOs με labels και εφαρμόζετε τους ίδιους κανόνες coin-control όπως στο συνηθισμένο Bitcoin. Το spending ή η consolidation τους μπορεί να αποκαλύψει σχέσεις ιδιοκτησίας.
7. Επιβεβαιώστε ότι το recovery εντοπίζει τις πληρωμές χωρίς να βασίζεστε σε external index χωρίς backup.

### Workflow αποστολέα

1. Επιβεβαιώστε ότι το wallet υποστηρίζει αποστολές στη συγκεκριμένη address version και authenticated τον static code του παραλήπτη.
2. Αφήστε το wallet να κατασκευάσει το output· μην μετατρέπετε ή περικόπτετε τον code χειροκίνητα.
3. Ελέγξτε προσεκτικά τα επιλεγμένα inputs. Τα Silent Payments βελτιώνουν το recipient-address privacy, αλλά τα sender inputs παραμένουν στο public graph.
4. Χρησιμοποιήστε wallet-supported fee bumping/PSBT behavior. Το BIP 352 απαιτεί output re-derivation αν αλλάξουν τα inputs, ενώ ορισμένα signing modes δεν είναι ασφαλή.
5. Διατηρήστε encrypted receipt ή proof που απαιτείται για disputes/accounting.

Τα Silent Payments επιλύουν το πρόβλημα της επαναλαμβανόμενης δημοσίευσης recipient addresses. Δεν αποκρύπτουν το ποσό, το transaction timing, το sender cluster, το acquisition history ή το μεταγενέστερο co-spending.

## Zcash fully shielded payments

Το Zcash υποστηρίζει transparent και shielded value pools. Οι Orchard shielded transactions χρησιμοποιούν zero-knowledge proofs, ώστε τα nodes να επαληθεύουν την εγκυρότητα ενώ οι λεπτομέρειες της συναλλαγής είναι κρυπτογραφημένες· τα Unified Addresses μπορούν να περιέχουν πολλαπλούς τύπους receiver.<sup>[[2]](#references)</sup> Το privacy εξαρτάται από το πραγματικό path που επιλέγει το wallet και όχι από τον πρώτο χαρακτήρα μιας εμφανιζόμενης address.

### Shielded workflow

1. Επιλέξτε ένα maintained wallet που προσδιορίζει ξεκάθαρα τη συμπεριφορά **shielded-by-default** και την τρέχουσα υποστήριξη Orchard. Επαληθεύστε το download και δημιουργήστε backup/test του seed.
2. Αποκτήστε ZEC νόμιμα και καταγράψτε τη basis/source. Ένα exchange εξακολουθεί να γνωρίζει την απόκτηση και την ανάληψη.
3. Λάβετε funds σε Unified Address που υποστηρίζεται από το wallet και, στη συνέχεια, ελέγξτε αν η συναλλαγή κατέληξε σε shielded pool. Μην θεωρείτε δεδομένο το automatic shielding χωρίς να επιβεβαιώσετε τη συμπεριφορά του wallet.
4. Προτιμάτε **shielded-to-shielded** transfers. Οι transparent-to-shielded και shielded-to-transparent boundary movements αποκαλύπτουν public values/timing και μπορούν να επιτρέψουν amount correlation· η Orchard specification σημειώνει ότι το spending σε non-Orchard address αποκαλύπτει την αξία της συναλλαγής.<sup>[[3]](#references)</sup>
5. Αποφεύγετε distinctive exact-amount round trips και άμεσες boundary crossings. Αυτό αποτελεί privacy hygiene και όχι άδεια απόκρυψης ιδιοκτησίας ή reporting.
6. Χρησιμοποιήστε το network-privacy path που υποστηρίζει το wallet. Η shielded cryptography δεν αποκρύπτει το IP/timing από wallet servers ή peers.
7. Διατηρείτε internal compliance records και χρησιμοποιείτε viewing keys μόνο για σκόπιμο audit/disclosure, αφού κατανοήσετε το scope τους.
8. Επιβεβαιώστε την υποστήριξη του recipient wallet/exchange πριν την αποστολή· ένας forced transparent receiver αλλάζει την ιδιότητα privacy.

## GNU Taler: anonymous payer, accountable merchant

Το GNU Taler είναι ένα open electronic-payment protocol που χρησιμοποιεί traditional currencies, blind signatures και regulated exchange/bank integration. Ο σχεδιασμός του αποσκοπεί στο να παραμένουν οι πελάτες anonymous στους merchants, ενώ οι merchants παραμένουν identifiable και taxable.<sup>[[4]](#references)</sup> Δεν είναι cryptocurrency και η διαθεσιμότητα εξαρτάται από compatible regional exchange, bank, wallet και merchant.

### User workflow όπου είναι deployed

1. Εντοπίστε ένα operating Taler exchange και merchant στο σχετικό currency/jurisdiction· διαβάστε τους τρέχοντες όρους, τα fees, το KYC και τις privacy notices.
2. Εγκαταστήστε το official wallet και επαληθεύστε την προέλευσή του. Προστατεύστε τα wallet backup/recovery data όπως τα μετρητά, επειδή η αξία του wallet μπορεί να είναι bearer asset.
3. Κάντε withdraw value μέσω του supported bank/exchange flow χρησιμοποιώντας truthful information. Το funding institution/exchange μπορεί να γνωρίζει την ανάληψη, παρότι οι blind signatures διασπούν το direct coin-to-withdrawal link.
4. Ελέγξτε το merchant contract στο wallet: merchant identity, item/summary, amount, fees, refund και delivery terms.
5. Πληρώστε και διατηρήστε τα receipt data που απαιτούνται για refund, warranty, accounting ή tax.
6. Μην επαναχρησιμοποιείτε optional merchant session/account identifiers αν απαιτείται merchant unlinkability.
7. Συμπεριλάβετε στο threat model τα wallet, network και delivery metadata· η payment cryptography του Taler δεν αποκρύπτει shipping address ή compromised endpoint.

Ο merchant και το exchange παραμένουν accountable, ενώ η λειτουργία οποιουδήποτε από τα δύο components μπορεί να αποτελεί regulated payment-service activity.

## Federated Chaumian e-cash

Το Chaumian e-cash χρησιμοποιεί blind signatures, ώστε ένα mint να υπογράφει ένα token χωρίς να βλέπει το unblinded token που δαπανάται αργότερα. Το Fedimint κατανέμει το reserve custody και το signing σε guardian federation· η τεκμηρίωσή του αναφέρει ότι οι guardians βλέπουν aggregate reserves/outstanding notes, αλλά δεν θα πρέπει να βλέπουν το individual balance ή ποιος πλήρωσε ποιον στο εσωτερικό της federation.<sup>[[5]](#references)</sup>

Αυτή είναι **custodial bearer value**. Ένα sufficient guardian quorum ελέγχει τα reserves· failure της federation, dishonest guardians, software bugs ή απώλεια client state μπορούν να προκαλέσουν απώλεια. Τα deposits, withdrawals και Lightning gateways είναι ορατά boundary events και μπορούν να συσχετίσουν timing/amount.

### Workflow περιορισμένου ρίσκου

1. Χρησιμοποιείτε μόνο μικρό ποσό που μπορείτε να χάσετε. Θεωρείτε τις public/unknown federations υψηλότερου ρίσκου από guardians με πραγματική accountability.
2. Επαληθεύστε το federation invite μέσω authenticated channel και καταγράψτε guardian identities, quorum, jurisdiction, fees, recovery και shutdown policy.
3. Εγκαταστήστε maintained compatible wallet, επαληθεύστε το και κατανοήστε το backup scheme πριν από την κατάθεση.
4. Καταθέστε Bitcoin που αποκτήθηκε νόμιμα μέσω του documented path. Καταγράψτε το peg-in για accounting και θεωρήστε ότι το timing/amount είναι public ή γνωστό στο boundary.
5. Μέσα στη federation, χρησιμοποιείτε fresh payment requests και αποφεύγετε την προσθήκη account/chat/delivery identifiers που επαναδημιουργούν τον σύνδεσμο τον οποίο αφαίρεσε η blind signature.
6. Για Lightning payments, θεωρείτε το gateway πρόσθετο observer των invoices και του boundary timing.
7. Κάντε redeem/withdraw σύμφωνα με την policy, αναμένοντας ότι distinctive amount και immediate timing μπορούν να συσχετιστούν με deposit ή external payment.
8. Διατηρείτε ιδιωτικά tax/source/authorization records· μην ζητάτε από guardians ή gateways να παρουσιάσουν ανακριβώς τη δραστηριότητα.

Μην περιγράφετε το federated e-cash ως trustless, self-custodial ή εγγυημένα anonymous.

## BOLT 12 offers και route blinding

Τα BOLT 12 offers μπορούν να είναι επαναχρησιμοποιήσιμα χωρίς δημοσίευση stable on-chain address και μπορούν να χρησιμοποιούν blinded paths, ώστε ο payer να μην χρειάζεται να μάθει το clear node identity/path του receiver. Αυτό συμπληρώνει, αλλά δεν αντικαθιστά, το υπάρχον onion routing του Lightning.

Πριν από τη χρήση:

1. Επιβεβαιώστε ότι τα sender και receiver wallets υποστηρίζουν τα ίδια τρέχοντα BOLT 12 features· μην συμπεραίνετε την υποστήριξη από το γενικό branding “Lightning”.
2. Κάντε authenticate το offer out of band και ελέγξτε amount, issuer/description και recurrence rules.
3. Χρησιμοποιήστε fresh invoice/payment context που δημιουργήθηκε από το offer.
4. Διατηρήστε στο ελάχιστο τα node aliases, τις public contact information και τα stable network endpoints.
5. Θεωρήστε ότι sender/receiver, first/last hop, wallet service, channel graph και on-chain funding/closure εξακολουθούν να αποκαλύπτουν τμήματα της σχέσης.

## Auditability χωρίς δημόσια αποκάλυψη

Το privacy και το audit μπορούν να συνυπάρξουν:

- Διατηρείτε labels, invoices, authorization, cost basis και ownership mapping κρυπτογραφημένα εκτός του public protocol.
- Διαχωρίζετε ένα **view/audit key** από ένα spending key όταν το protocol παρέχει τέτοια δυνατότητα· δοκιμάστε πρώτα το ακριβές disclosure του σε sample wallet.
- Παρέχετε σε auditor το ελάχιστο scoped proof αντί για seed ή unrestricted spending credential.
- Καταγράφετε κατά τον χρόνο της συναλλαγής την έκδοση software, το protocol/pool, το transaction ID ή proof, τον σκοπό του counterparty και την πηγή της exchange rate.
- Ορίστε retention και deletion αντί να συσσωρεύετε ένα μόνιμο unencrypted identity graph.

## Checklist επιλογής

- [ ] Το hidden field και ο observer έχουν προσδιοριστεί με ακρίβεια.
- [ ] Η υποστήριξη wallet/protocol επαληθεύτηκε κατά την ημερομηνία της συναλλαγής.
- [ ] Τα acquisition, network, node/RPC, counterparty, delivery και later-spend links έχουν τεκμηριωθεί.
- [ ] Τα custody, recovery, liquidity, issuer/federation solvency και refund risks έχουν γίνει αποδεκτά.
- [ ] Τα απαιτούμενα identity, tax, sanctions, source και organizational records παραμένουν ακριβή.
- [ ] Ένα μικρό end-to-end test, συμπεριλαμβανομένων recovery και audit proof, ολοκληρώθηκε με επιτυχία.

## References

- [1] [BIP 352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [2] [Zcash — Ενοποιημένες διευθύνσεις](https://z.cash/learn/what-are-zcash-unified-addresses/) and [The Orchard Book — Keys and addresses](https://zcash.github.io/orchard/design/keys.html)
- [3] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [4] [Τεκμηρίωση GNU Taler](https://docs.taler.net/) and [Merchant Manual — About GNU Taler](https://docs.taler.net/taler-merchant-manual.html)
- [5] [Fedimint — Πώς λειτουργεί](https://fedimint.org/users/how-it-works), [How federations work](https://fedimint.org/guardians/how-federations-work), and [Threshold blind signatures](https://docs.fedimint.org/crypto/index.html)
- [6] [BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
{{#include ../banners/hacktricks-training.md}}
