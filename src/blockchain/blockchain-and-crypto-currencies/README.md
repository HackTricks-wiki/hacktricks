# Blockchain και Κρυπτονομίσματα

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- Τα **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς μεσάζοντες.
- Οι **Decentralized Applications (dApps)** βασίζονται στα smart contracts, διαθέτοντας ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελέγξιμο back-end.
- Τα **Tokens & Coins** διαφέρουν ως προς το ότι τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- Τα **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, ενώ τα **Security Tokens** υποδηλώνουν την ιδιοκτησία περιουσιακών στοιχείων.
- Το **DeFi** σημαίνει Decentralized Finance και προσφέρει χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- Τα **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Μηχανισμοί Συναίνεσης

Οι μηχανισμοί συναίνεσης διασφαλίζουν την ασφαλή και κοινά αποδεκτή επικύρωση συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν συγκεκριμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.<sup>[[1]](#references)</sup>

## Βασικά στοιχεία του Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω digital signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.<sup>[[2]](#references)</sup>

#### Βασικά στοιχεία:

- Οι **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.<sup>[[3]](#references)</sup>
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (καταβάλλονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα channel και μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Ζητήματα ιδιωτικότητας του Bitcoin

Επιθέσεις ιδιωτικότητας, όπως οι **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα συναλλαγών. Στρατηγικές όπως οι **Mixers** και το **CoinJoin** βελτιώνουν την ανωνυμία αποκρύπτοντας τις συνδέσεις συναλλαγών μεταξύ χρηστών.

## Ανώνυμη απόκτηση Bitcoins

Οι μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και τη χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να περιπλέξει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές συναλλαγές για αυξημένη ιδιωτικότητα.

# Περίληψη των επιθέσεων ιδιωτικότητας στο Bitcoin

Στον κόσμο του Bitcoin, η ιδιωτικότητα των συναλλαγών και η ανωνυμία των χρηστών αποτελούν συχνά αντικείμενα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων μέσω των οποίων οι attackers μπορούν να παραβιάσουν την ιδιωτικότητα του Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Γενικά, είναι σπάνιο να συνδυάζονται inputs από διαφορετικούς χρήστες σε μία συναλλαγή λόγω της πολυπλοκότητας που απαιτείται. Επομένως, **δύο input addresses στην ίδια συναλλαγή θεωρείται συχνά ότι ανήκουν στον ίδιο κάτοχο**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί εξ ολοκλήρου σε μια συναλλαγή. Αν μόνο ένα μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο μεταφέρεται σε μια νέα change address. Οι παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, θέτοντας σε κίνδυνο την ιδιωτικότητα.

### Παράδειγμα

Για τον περιορισμό αυτού του κινδύνου, οι mixing services ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές κοινοποιούν τις Bitcoin addresses τους online, καθιστώντας **εύκολη τη σύνδεση της διεύθυνσης με τον κάτοχό της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να απεικονιστούν ως graphs, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή των κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs, προκειμένου να γίνει εικασία σχετικά με το ποιο output αποτελεί το change που επιστρέφει στον αποστολέα.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το change output μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να προκαλέσει σύγχυση στο heuristic.

## **Forced Address Reuse**

Οι επιτιθέμενοι μπορεί να στέλνουν μικρά ποσά σε διευθύνσεις που έχουν ήδη χρησιμοποιηθεί, ελπίζοντας ότι ο παραλήπτης θα τις συνδυάσει με άλλα inputs σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Σωστή συμπεριφορά Wallet

Τα Wallets θα πρέπει να αποφεύγουν τη χρήση coins που λαμβάνονται σε ήδη χρησιμοποιημένες, άδειες διευθύνσεις, ώστε να αποτρέπεται αυτό το privacy leak.

## **Άλλες τεχνικές Blockchain Analysis**

- **Ακριβή ποσά πληρωμών:** Οι συναλλαγές χωρίς change είναι πιθανό να πραγματοποιούνται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Στρογγυλοποιημένοι αριθμοί:** Ένας στρογγυλοποιημένος αριθμός σε μια συναλλαγή υποδηλώνει ότι πρόκειται για πληρωμή, ενώ το output που δεν είναι στρογγυλοποιημένο είναι πιθανότατα το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά μοτίβα δημιουργίας συναλλαγών, επιτρέποντας στους analysts να αναγνωρίζουν το software που χρησιμοποιήθηκε και ενδεχομένως τη change address.
- **Συσχετίσεις ποσού και χρόνου:** Η αποκάλυψη των χρόνων ή των ποσών των συναλλαγών μπορεί να καταστήσει τις συναλλαγές ανιχνεύσιμες.

## **Traffic Analysis**

Παρακολουθώντας την κίνηση του δικτύου, οι επιτιθέμενοι μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με IP addresses, θέτοντας σε κίνδυνο το privacy των χρηστών. Αυτό ισχύει ιδιαίτερα όταν μια οντότητα λειτουργεί πολλά Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί συναλλαγές.

## Περισσότερα

Για μια ολοκληρωμένη λίστα privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Τρόποι απόκτησης Bitcoins ανώνυμα

- **Συναλλαγές με μετρητά:** Απόκτηση bitcoin μέσω μετρητών.
- **Εναλλακτικές μετρητών:** Αγορά gift cards και ανταλλαγή τους online με bitcoin.
- **Mining:** Η πιο private μέθοδος απόκτησης bitcoins είναι μέσω mining, ειδικά όταν γίνεται μεμονωμένα, επειδή τα mining pools μπορεί να γνωρίζουν την IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Κλοπή:** Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι μια ακόμη μέθοδος ανώνυμης απόκτησής του, αν και είναι παράνομη και δεν συνιστάται.

## Mixing Services

Με τη χρήση μιας mixing service, ένας χρήστης μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins ως αντάλλαγμα**, γεγονός που δυσκολεύει την ανίχνευση του αρχικού ιδιοκτήτη. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι η service δεν θα διατηρεί logs και ότι πράγματι θα επιστρέψει τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συγχωνεύει πολλές συναλλαγές από διαφορετικούς χρήστες σε μία, περιπλέκοντας τη διαδικασία για όποιον προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, συναλλαγές με μοναδικά μεγέθη input και output μπορούν ακόμη δυνητικά να ανιχνευθούν.

Παραδείγματα συναλλαγών που μπορεί να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τις `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για ένα Ethereum smart-contract mixer που διαχωρίζει τις καταθέσεις από τις μεταγενέστερες αναλήψεις, δείτε το [Tornado Cash](https://tornado.cash).

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), συγκαλύπτει τη συναλλαγή μεταξύ δύο μερών (π.χ. ενός πελάτη και ενός merchant) ως κανονική συναλλαγή, χωρίς το χαρακτηριστικό των ίσων outputs που συναντάται στο CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιείται από οντότητες επιτήρησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, ενισχύοντας το privacy ενώ παραμένουν μη διακριτές από τις τυπικές συναλλαγές bitcoin.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας την μια πολλά υποσχόμενη εξέλιξη στην προσπάθεια για transactional privacy.

# Βέλτιστες πρακτικές για το Privacy στα Cryptocurrencies

## **Τεχνικές συγχρονισμού Wallet**

Για τη διατήρηση του privacy και της ασφάλειας, ο συγχρονισμός των wallets με το blockchain είναι κρίσιμος. Ξεχωρίζουν δύο μέθοδοι:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node εξασφαλίζει μέγιστο privacy. Όλες οι συναλλαγές που έχουν πραγματοποιηθεί ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για τους adversaries να εντοπίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα wallets να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα στους network observers. Τα lightweight wallets κατεβάζουν αυτά τα φίλτρα και λαμβάνουν πλήρη blocks μόνο όταν εντοπίζεται αντιστοίχιση με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer network, συνιστάται η χρήση του Tor για την απόκρυψη της IP address, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Αποτροπή επαναχρησιμοποίησης διευθύνσεων**

Για την προστασία του privacy, είναι ζωτικής σημασίας να χρησιμοποιείται μια νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το privacy, συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallets αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για το Transaction Privacy**

- **Πολλαπλές συναλλαγές**: Η διάσπαση μιας πληρωμής σε πολλές συναλλαγές μπορεί να αποκρύψει το ποσό της συναλλαγής, αποτρέποντας privacy attacks.
- **Αποφυγή ρέστων**: Η επιλογή συναλλαγών που δεν απαιτούν outputs ρέστων ενισχύει το privacy, διαταράσσοντας τις μεθόδους εντοπισμού ρέστων.
- **Πολλαπλά outputs ρέστων**: Αν η αποφυγή ρέστων δεν είναι εφικτή, η δημιουργία πολλαπλών outputs ρέστων μπορεί και πάλι να βελτιώσει το privacy.

# **Monero: Ένας φάρος Anonymity**

Το Monero έχει σχεδιαστεί ώστε να δίνει προτεραιότητα στο transaction privacy.

# **Ethereum: Gas και συναλλαγές**

## **Κατανόηση του Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum και τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, μαζί με ένα priority fee για να παρέχει κίνητρο στους validators να τη συμπεριλάβουν. Οι χρήστες μπορούν να ορίσουν ένα max fee ώστε να διασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, ενώ το πλεόνασμα επιστρέφεται.<sup>[[5]](#references)</sup>

## **Εκτέλεση συναλλαγών**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, οι οποίοι μπορεί να είναι διευθύνσεις χρηστών ή smart contracts. Απαιτούν fee και πρέπει να συμπεριληφθούν σε ένα block. Οι βασικές πληροφορίες μιας συναλλαγής περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά δεδομένα, το gas limit και τα fees. Σημειωτέον ότι η διεύθυνση του αποστολέα συνάγεται από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα δεδομένα της συναλλαγής.<sup>[[4]](#references)</sup>

Αυτές οι πρακτικές και οι μηχανισμοί αποτελούν θεμελιώδη στοιχεία για όποιον θέλει να ασχοληθεί με cryptocurrencies, δίνοντας προτεραιότητα στο privacy και την ασφάλεια.

## Red Teaming με επίκεντρο την αξία στο Web3

- Καταγράψτε τα components που διαθέτουν αξία (signers, oracles, bridges, automation), ώστε να κατανοήσετε ποιος μπορεί να μετακινήσει funds και με ποιον τρόπο.
- Αντιστοιχίστε κάθε component στις σχετικές MITRE AADAPT tactics, ώστε να αποκαλυφθούν διαδρομές privilege escalation.
- Εξασκηθείτε σε flash-loan/oracle/credential/cross-chain attack chains, ώστε να επικυρώσετε τον αντίκτυπο και να τεκμηριώσετε τις εκμεταλλεύσιμες προϋποθέσεις.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromise της ροής υπογραφής στο Web3

- Η παραποίηση στο supply chain των wallet UIs μπορεί να τροποποιήσει EIP-712 payloads ακριβώς πριν από την υπογραφή, συλλέγοντας έγκυρες υπογραφές για takeovers proxies βασισμένα σε delegatecall (π.χ. overwrite του slot-0 του Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Οι συνήθεις τρόποι αποτυχίας των smart accounts περιλαμβάνουν την παράκαμψη του access control του `EntryPoint`, unsigned gas fields, stateful validation, ERC-1271 replay και fee-drain μέσω revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Ασφάλεια Smart Contracts

- Mutation testing για τον εντοπισμό blind spots στις test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Ακεραιότητα ZK Proof / zkVM Guest

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να πιστοποιήσει έναν ισχυρισμό, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως έχει γραφτεί**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας malicious prover μπορεί να δημιουργήσει ένα proof που επαληθεύεται, ενώ τα **public metrics ή το claimed invariant είναι ψευδή**.<sup>[[7]](#references)</sup>

### Unsafe deserialization μέσα σε proof guests

- Αντιμετωπίζετε τα private witness/circuit bytes ως **untrusted attacker input**, ακόμη και αν αποκρύπτονται από το proof.
- Αποφεύγετε την αποσειριοποίησή τους με unchecked helpers όπως το `rkyv::access_unchecked`, εκτός αν τα bytes έχουν ήδη επικυρωθεί out-of-band.
- Τα enum discriminants, οι relative pointers, τα lengths και τα indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Πρακτικό μοτίβο ελέγχου:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Εάν ένα πεδίο όπως το `op.kind` είναι enum και ένας attacker μπορεί να εισαγάγει έναν **out-of-range discriminant**, κάθε downstream `match` πάνω σε αυτή την τιμή γίνεται ύποπτο.

### Παράκαμψη counter με jump-table / UB

Εάν η Rust μετατρέπει ένα μεγάλο `match` σε **jump table**, ένας μη έγκυρος enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο pattern είναι:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί την **πραγματική σημασιολογία της instruction**.
3. Ένας out-of-range discriminant κάνει index πέρα από το πρώτο jump table και καταλήγει σε κώδικα που σχετίζεται με το δεύτερο.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παρακάμπτεται. Σε ένα zkVM αυτό μπορεί να πλαστογραφήσει proofs που αναφέρουν αδύνατες μετρικές, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους πλαστογραφημένους bounded resources.

Checklist ελέγχου:

- Αναζητήστε attacker-controlled enums που γίνονται deserialize από witness/private input.
- Ελέγξτε επαναλαμβανόμενες εντολές `match` πάνω στο ίδιο opcode/kind field.
- Αντιμετωπίστε τον συνδυασμό `unsafe` + unchecked deserialization + large opcode dispatch ως υψηλού κινδύνου.
- Κάντε reverse engineer το emitted binary όταν χρειάζεται· η διάταξη των jump tables μπορεί να είναι σημαντικότερη από τον source code.

### Απουσία semantic constraints σε reversible/specialized interpreters

Μην επικυρώνετε μόνο την ασφάλεια μνήμης· επικυρώστε επίσης τους **semantic rules** που πρέπει να επιβάλλει το proof.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι τα operands που πρέπει να είναι distinct πράγματι περιορίζονται ώστε να είναι distinct. Μια operation τύπου Toffoli/CCX που υλοποιείται ως:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
καθίσταται μη ασφαλές αν ο guest δεν το απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση καταρρέει σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, καταρρίπτοντας τις παραδοχές αντιστρεψιμότητας και επιτρέποντας φθηνότερους μη προβλεπόμενους υπολογισμούς. Σε proof systems που πιστοποιούν τη χρήση πόρων, αυτό μπορεί να επιτρέψει στους attackers να ικανοποιούν τους functional checks, παρακάμπτοντας παράλληλα το cost model που ο verifier θεωρεί ότι εφαρμόζεται.

### Τι να ελέγχετε σε ZK systems

- Κάντε fuzzing σε όλους τους guest parsers με malformed witness/private-input encodings.
- Επιβεβαιώστε το enum range validation πριν από το opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες μη έγκυρες μορφές instructions.
- Συγκρίνετε τους reported/public counters με μια ανεξάρτητη reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί να αποδεικνύει τη **λάθος statement** αν το guest program είναι buggy.

## Εκμετάλλευση DeFi/AMM

Αν ερευνάτε πρακτική exploitation των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που αποθηκεύουν virtual balances σε cache και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Επεξήγηση δημόσιου και ιδιωτικού κλειδιού - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Τι είναι οι multi-signature transactions; - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas και fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Νικήσαμε το zero-knowledge proof της Google για την κρυπτανάλυση μέσω quantum](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Ασφάλιση Elliptic Curve Cryptocurrencies έναντι Quantum Vulnerabilities: Resource Estimates και Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-concept repository της Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
