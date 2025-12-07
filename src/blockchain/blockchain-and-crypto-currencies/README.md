# Blockchain και Κρυπτονομίσματα

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται στα smart contracts, διαθέτοντας φιλικό προς τον χρήστη front-end και διαφανές, ελεγχόμενο back-end.
- **Tokens & Coins** διακρίνονται ως εξής: τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, και **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακού στοιχείου.
- **DeFi** σημαίνει Αποκεντρωμένα Χρηματοοικονομικά, προσφέροντας χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Πλατφόρμες Αποκεντρωμένης Ανταλλαγής (Decentralized Exchange Platforms) και Αποκεντρωμένες Αυτόνομες Οργανώσεις (Decentralized Autonomous Organizations).

## Μηχανισμοί Συμφωνίας (Consensus Mechanisms)

Οι μηχανισμοί συμφωνίας εξασφαλίζουν ασφαλή και συμφωνημένη επαλήθευση συναλλαγών στο blockchain:

- **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν συγκεκριμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Βασικά για το Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών υπογραφών, εξασφαλίζοντας ότι μόνο ο κάτοχος του ιδιωτικού κλειδιού μπορεί να ξεκινήσει μεταφορές.

#### Κύρια Στοιχεία:

- **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (πληρωτέα στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Σκοπός του είναι να αυξήσει την κλιμακωσιμότητα του Bitcoin επιτρέποντας πολλαπλές συναλλαγές εντός ενός καναλιού, μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Θέματα Ιδιωτικότητας του Bitcoin

Οι επιθέσεις κατά της ιδιωτικότητας, όπως **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται πρότυπα συναλλαγών. Στρατηγικές όπως **Mixers** και **CoinJoin** βελτιώνουν την ανωνυμία θολώνοντας τους συνδέσμους συναλλαγών μεταξύ χρηστών.

## Απόκτηση Bitcoins Ανώνυμα

Μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να περιπλέξει την ανιχνευσιμότητα, ενώ το **PayJoin** μεταμφιέζει CoinJoins ως κανονικές συναλλαγές για αυξημένη ιδιωτικότητα.

# Επιθέσεις στην Ιδιωτικότητα του Bitcoin

# Σύνοψη Επιθέσεων στην Ιδιωτικότητα του Bitcoin

Στον κόσμο του Bitcoin, η ιδιωτικότητα των συναλλαγών και η ανωνυμία των χρηστών συχνά προκαλούν ανησυχία. Ακολουθεί μια απλουστευμένη επισκόπηση αρκετών κοινών μεθόδων μέσω των οποίων οι επιτιθέμενοι μπορούν να υπονομεύσουν την ιδιωτικότητα στο Bitcoin.

## **Υπόθεση Κοινού Κατόχου Εισόδων (Common Input Ownership Assumption)**

Σε γενικές γραμμές είναι σπάνιο οι inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία συναλλαγή λόγω της πολυπλοκότητας. Επομένως, **δύο διευθύνσεις εισόδων στην ίδια συναλλαγή συχνά θεωρείται ότι ανήκουν στον ίδιο κάτοχο**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί ολόκληρο σε μια συναλλαγή. Αν μόνο μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα διεύθυνση αλλαγής (change address). Οι παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, θέτοντας σε κίνδυνο την ιδιωτικότητα.

### Παράδειγμα

Για να μετριαστεί αυτό, υπηρεσίες mixing ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στο να θολώσει η ιδιοκτησία.

## **Έκθεση σε Social Networks & Forums**

Οι χρήστες μερικές φορές μοιράζονται τις διευθύνσεις Bitcoin τους online, καθιστώντας **εύκολο να συνδεθεί η διεύθυνση με τον κάτοχό της**.

## **Ανάλυση Γραφήματος Συναλλαγών**

Οι συναλλαγές μπορούν να απεικονιστούν ως γράφοι, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών βάσει της ροής των κεφαλαίων.

## **Ευριστική του Μη Αναγκαίου Input (Optimal Change Heuristic)**

Αυτό το ευριστικό βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το υπόλοιπο που επιστρέφει στον αποστολέα.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Wallets should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions without change are likely between two addresses owned by the same user.
- **Round Numbers:** A round number in a transaction suggests it's a payment, with the non-round output likely being the change.
- **Wallet Fingerprinting:** Different wallets have unique transaction creation patterns, allowing analysts to identify the software used and potentially the change address.
- **Amount & Timing Correlations:** Disclosing transaction times or amounts can make transactions traceable.

## **Traffic Analysis**

By monitoring network traffic, attackers can potentially link transactions or blocks to IP addresses, compromising user privacy. This is especially true if an entity operates many Bitcoin nodes, enhancing their ability to monitor transactions.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

By using a mixing service, a user can **send bitcoins** and receive **different bitcoins in return**, which makes tracing the original owner difficult. Yet, this requires trust in the service not to keep logs and to actually return the bitcoins. Alternative mixing options include Bitcoin casinos.

## CoinJoin

**CoinJoin** merges multiple transactions from different users into one, complicating the process for anyone trying to match inputs with outputs. Despite its effectiveness, transactions with unique input and output sizes can still potentially be traced.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, ενισχύοντας το απόρρητο ενώ παραμένουν αδιάκριτες σε σχέση με τις κανονικές bitcoin συναλλαγές.

**Η χρήση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας το μια υποσχόμενη εξέλιξη στην επιδίωξη του συναλλακτικού απορρήτου.

# Καλές πρακτικές για το απόρρητο στα κρυπτονομίσματα

## **Τεχνικές συγχρονισμού πορτοφολιών**

Για να διατηρηθεί το απόρρητο και η ασφάλεια, ο συγχρονισμός των wallets με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Κατεβάζοντας ολόκληρο το blockchain, ένας full node εξασφαλίζει μέγιστο απόρρητο. Όλες οι συναλλαγές που έγιναν αποθηκεύονται τοπικά, καθιστώντας αδύνατο για αντιπάλους να προσδιορίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα πορτοφόλια να εντοπίζουν σχετικές συναλλαγές χωρίς να εκθέτουν συγκεκριμένα ενδιαφέροντα σε παρατηρητές του δικτύου. Τα lightweight wallets κατεβάζουν αυτά τα φίλτρα, τραβώντας πλήρη blocks μόνο όταν υπάρχει ταύτιση με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για ανωνυμία**

Δεδομένου ότι το Bitcoin λειτουργεί σε ένα peer-to-peer δίκτυο, προτείνεται η χρήση του Tor για να κρύψετε τη διεύθυνση IP σας, βελτιώνοντας το απόρρητο κατά την αλληλεπίδραση με το δίκτυο.

## **Αποφυγή επαναχρησιμοποίησης διευθύνσεων**

Για την προστασία του απορρήτου, είναι ζωτικής σημασίας η χρήση μιας νέας διεύθυνσης για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το απόρρητο συνδέοντας συναλλαγές στο ίδιο ον. Τα σύγχρονα πορτοφόλια αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για το απόρρητο των συναλλαγών**

- **Πολλαπλές συναλλαγές**: Το διαχωρισμό μιας πληρωμής σε αρκετές συναλλαγές μπορεί να συγκαλύψει το ποσό της συναλλαγής, παρεμποδίζοντας επιθέσεις κατά του απορρήτου.
- **Αποφυγή change**: Η επιλογή για συναλλαγές που δεν απαιτούν change outputs βελτιώνει το απόρρητο διαταράσσοντας τις μεθόδους ανίχνευσης change.
- **Πολλαπλά change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλαπλών change outputs μπορεί ακόμα να βελτιώσει το απόρρητο.

# **Monero: Ένα φάρος ανωνυμίας**

Το Monero καλύπτει την ανάγκη για απόλυτη ανωνυμία στις ψηφιακές συναλλαγές, θέτοντας υψηλό πρότυπο για το απόρρητο.

# **Ethereum: Gas και Συναλλαγές**

## **Κατανόηση του Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση λειτουργιών στο Ethereum, τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για να παρακινηθούν οι miners. Οι χρήστες μπορούν να ορίσουν ένα max fee για να εξασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, με την περίσσεια να επιστρέφεται.

## **Εκτέλεση Συναλλαγών**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, που μπορούν να είναι είτε διευθύνσεις χρηστών είτε smart contract. Απαιτούν αμοιβή και πρέπει να εξορυχθούν. Βασικές πληροφορίες σε μια συναλλαγή περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά δεδομένα, το gas limit και τις αμοιβές. Σημειωτέον, η διεύθυνση του αποστολέα προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη για αυτή στα δεδομένα της συναλλαγής.

Αυτές οι πρακτικές και μηχανισμοί είναι θεμελιώδεις για οποιονδήποτε επιθυμεί να ασχοληθεί με κρυπτονομίσματα δίνοντας προτεραιότητα στο απόρρητο και την ασφάλεια.

## Smart Contract Security

- Mutation testing για τον εντοπισμό τυφλών σημείων σε test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Αναφορές

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

For multi-asset weighted pools that cache virtual balances and can be poisoned when `supply == 0`, study:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
