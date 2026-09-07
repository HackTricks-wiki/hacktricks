# Blockchain και Κρυπτο-νομίσματα

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- Τα **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς μεσάζοντες.
- Οι **Decentralized Applications (dApps)** βασίζονται σε smart contracts, διαθέτοντας ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, auditable back-end.
- Τα **Tokens & Coins** διαφέρουν ως προς το ότι τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- Τα **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, ενώ τα **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακών στοιχείων.
- Το **DeFi** σημαίνει Decentralized Finance και προσφέρει χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- Τα **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Μηχανισμοί Συναίνεσης

Οι μηχανισμοί συναίνεσης διασφαλίζουν την ασφαλή και συμφωνημένη επικύρωση συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν συγκεκριμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.<sup>[[1]](#references)</sup>

## Βασικά στοιχεία του Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω digital signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.<sup>[[2]](#references)</sup>

#### Βασικά στοιχεία:

- Οι **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.<sup>[[3]](#references)</sup>
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (καταβάλλονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin, επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα channel και μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Ανησυχίες σχετικά με το Privacy του Bitcoin

Επιθέσεις privacy, όπως τα **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα συναλλαγών. Στρατηγικές όπως τα **Mixers** και το **CoinJoin** βελτιώνουν την ανωνυμία αποκρύπτοντας τις συνδέσεις συναλλαγών μεταξύ χρηστών.

## Ανώνυμη απόκτηση Bitcoins

Οι μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να περιπλέξει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές συναλλαγές για ενισχυμένο privacy.

# Σύνοψη των επιθέσεων Privacy στο Bitcoin

Στον κόσμο του Bitcoin, το privacy των συναλλαγών και η ανωνυμία των χρηστών αποτελούν συχνά αντικείμενα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων μέσω των οποίων οι attackers μπορούν να παραβιάσουν το privacy του Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Γενικά, είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία συναλλαγή, λόγω της πολυπλοκότητας που απαιτείται. Επομένως, **δύο input addresses στην ίδια συναλλαγή θεωρείται συχνά ότι ανήκουν στον ίδιο κάτοχο**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί εξ ολοκλήρου σε μία συναλλαγή. Αν μόνο ένα μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα change address. Οι παρατηρητές μπορούν να θεωρήσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, παραβιάζοντας το privacy.

### Παράδειγμα

Για τον μετριασμό αυτού του κινδύνου, οι mixing services ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες κοινοποιούν μερικές φορές τις Bitcoin addresses τους online, καθιστώντας **εύκολη τη σύνδεση της διεύθυνσης με τον κάτοχό της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να απεικονιστούν ως γραφήματα, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs, ώστε να γίνει εκτίμηση για το ποιο output αποτελεί το change που επιστρέφει στον αποστολέα.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το output της συναλλαγής μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να προκαλέσει σύγχυση στο heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στέλνουν μικρά ποσά σε διευθύνσεις που έχουν χρησιμοποιηθεί στο παρελθόν, ελπίζοντας ότι ο παραλήπτης θα τα συνδυάσει με άλλα inputs σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Σωστή συμπεριφορά Wallet

Τα wallets θα πρέπει να αποφεύγουν τη χρήση coins που λαμβάνονται σε ήδη χρησιμοποιημένες, κενές διευθύνσεις, ώστε να αποτρέπεται αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Ακριβή ποσά πληρωμής:** Οι συναλλαγές χωρίς change είναι πιθανό να πραγματοποιούνται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Στρογγυλοποιημένοι αριθμοί:** Ένας στρογγυλοποιημένος αριθμός σε μια συναλλαγή υποδηλώνει ότι πρόκειται για πληρωμή, ενώ το output που δεν είναι στρογγυλοποιημένο είναι πιθανότατα το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά patterns δημιουργίας συναλλαγών, επιτρέποντας στους analysts να αναγνωρίζουν το λογισμικό που χρησιμοποιείται και, ενδεχομένως, τη διεύθυνση change.
- **Συσχετίσεις ποσού και χρόνου:** Η αποκάλυψη των χρόνων ή των ποσών των συναλλαγών μπορεί να κάνει τις συναλλαγές traceable.

## **Traffic Analysis**

Με την παρακολούθηση της κίνησης του δικτύου, οι attackers μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με διευθύνσεις IP, θέτοντας σε κίνδυνο το privacy των χρηστών. Αυτό ισχύει ιδιαίτερα όταν μια οντότητα λειτουργεί πολλά Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί συναλλαγές.

## Περισσότερα

Για μια ολοκληρωμένη λίστα privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy στο Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Τρόποι απόκτησης Bitcoins ανώνυμα

- **Συναλλαγές με μετρητά**: Απόκτηση bitcoin μέσω μετρητών.
- **Εναλλακτικές μετρητών**: Αγορά gift cards και ανταλλαγή τους online με bitcoin.
- **Mining**: Η πιο ιδιωτική μέθοδος απόκτησης bitcoins είναι μέσω mining, ειδικά όταν γίνεται ανεξάρτητα, επειδή τα mining pools μπορεί να γνωρίζουν τη διεύθυνση IP του miner. [Πληροφορίες για Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Κλοπή**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι μια ακόμη μέθοδος ανώνυμης απόκτησής του, αν και είναι παράνομη και δεν συνιστάται.

## Mixing Services

Με τη χρήση μιας mixing service, ένας χρήστης μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins ως αντάλλαγμα**, γεγονός που δυσκολεύει την ανίχνευση του αρχικού ιδιοκτήτη. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι η service δεν θα διατηρεί logs και ότι πράγματι θα επιστρέψει τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συγχωνεύει πολλές συναλλαγές από διαφορετικούς χρήστες σε μία, περιπλέκοντας τη διαδικασία για οποιονδήποτε προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, συναλλαγές με μοναδικά μεγέθη input και output μπορεί να είναι ακόμη traceable.

Παραδείγματα συναλλαγών που ενδέχεται να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για ένα Ethereum smart-contract mixer που διαχωρίζει τις καταθέσεις από τις μεταγενέστερες αναλήψεις, δείτε το [Tornado Cash](https://tornado.cash).

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), συγκαλύπτει τη συναλλαγή μεταξύ δύο μερών (π.χ. ενός πελάτη και ενός εμπόρου) ως κανονική συναλλαγή, χωρίς το χαρακτηριστικό των ίσων outputs του CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιούν οι οντότητες παρακολούθησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, ενισχύοντας το privacy ενώ παραμένουν μη διακριτές από τις τυπικές συναλλαγές bitcoin.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας την μια πολλά υποσχόμενη εξέλιξη στην προσπάθεια επίτευξης privacy στις συναλλαγές.

# Βέλτιστες πρακτικές για privacy στα κρυπτονομίσματα

## **Τεχνικές συγχρονισμού wallet**

Για τη διατήρηση του privacy και της ασφάλειας, ο συγχρονισμός των wallet με το blockchain είναι κρίσιμος. Ξεχωρίζουν δύο μέθοδοι:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node εξασφαλίζει μέγιστο privacy. Όλες οι συναλλαγές που έχουν πραγματοποιηθεί ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για τους adversaries να εντοπίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία filters για κάθε block του blockchain, επιτρέποντας στα wallet να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα στους network observers. Τα lightweight wallet κατεβάζουν αυτά τα filters και ανακτούν ολόκληρα blocks μόνο όταν εντοπίζεται αντιστοίχιση με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer network, συνιστάται η χρήση του Tor για την απόκρυψη της IP address, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Αποτροπή επαναχρησιμοποίησης διευθύνσεων**

Για την προστασία του privacy, είναι απαραίτητο να χρησιμοποιείται νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το privacy, συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallet αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για privacy στις συναλλαγές**

- **Multiple transactions**: Ο διαχωρισμός μιας πληρωμής σε πολλές συναλλαγές μπορεί να αποκρύψει το ποσό της συναλλαγής, αποτρέποντας privacy attacks.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν outputs επιστροφής ενισχύει το privacy, διαταράσσοντας τις μεθόδους εντοπισμού change.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλών change outputs μπορεί και πάλι να βελτιώσει το privacy.

# **Monero: Φάρος anonymity**

Το Monero έχει σχεδιαστεί με προτεραιότητα στο privacy των συναλλαγών.

# **Ethereum: Gas και συναλλαγές**

## **Κατανόηση του Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum και τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει gas limit και base fee, μαζί με priority fee για να ενθαρρύνει την ένταξη από τους validators. Οι χρήστες μπορούν να ορίσουν max fee ώστε να διασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, ενώ το πλεόνασμα επιστρέφεται.<sup>[[5]](#references)</sup>

## **Εκτέλεση συναλλαγών**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, οι οποίοι μπορεί να είναι διευθύνσεις χρηστών ή smart contract. Απαιτούν fee και πρέπει να συμπεριληφθούν σε block. Οι βασικές πληροφορίες μιας συναλλαγής περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά data, το gas limit και τα fees. Συγκεκριμένα, η διεύθυνση του αποστολέα συνάγεται από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα δεδομένα της συναλλαγής.<sup>[[4]](#references)</sup>

Αυτές οι πρακτικές και οι μηχανισμοί αποτελούν τη βάση για οποιονδήποτε θέλει να ασχοληθεί με τα κρυπτονομίσματα, δίνοντας προτεραιότητα στο privacy και την ασφάλεια.

## Red Teaming του Web3 με επίκεντρο την αξία

- Καταγράψτε τα components που περιέχουν αξία (signers, oracles, bridges, automation), ώστε να κατανοήσετε ποιος μπορεί να μετακινήσει funds και με ποιον τρόπο.
- Αντιστοιχίστε κάθε component στις σχετικές MITRE AADAPT tactics, ώστε να αποκαλύψετε paths για privilege escalation.
- Κάντε πρόβα σε αλυσίδες επιθέσεων flash-loan/oracle/credential/cross-chain, για να επικυρώσετε τον αντίκτυπο και να τεκμηριώσετε τις exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromise στη ροή υπογραφής του Web3

- Η παραποίηση στο supply chain των wallet UIs μπορεί να τροποποιήσει EIP-712 payloads ακριβώς πριν από την υπογραφή, συλλέγοντας έγκυρες υπογραφές για takeovers proxy βασισμένα σε delegatecall (π.χ. overwrite του slot-0 του Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Συνήθεις τρόποι αποτυχίας των smart accounts περιλαμβάνουν παράκαμψη του access control του `EntryPoint`, unsigned gas fields, stateful validation, replay στο ERC-1271 και fee-drain μέσω revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Ασφάλεια Smart Contract

- Mutation testing για τον εντοπισμό blind spots στις test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Ακεραιότητα ZK Proof / zkVM Guest

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να επιβεβαιώσει έναν ισχυρισμό, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως είχε γραφτεί**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας κακόβουλος prover μπορεί να δημιουργήσει proof που επαληθεύεται, ενώ τα **public metrics ή το claimed invariant είναι ψευδή**.<sup>[[7]](#references)</sup>

### Unsafe deserialization μέσα σε proof guests

- Αντιμετωπίζετε τα private witness/circuit bytes ως **untrusted attacker input**, ακόμη και αν αποκρύπτονται από το proof.
- Αποφύγετε την αποσειριοποίησή τους με unchecked helpers όπως το `rkyv::access_unchecked`, εκτός αν τα bytes έχουν ήδη επικυρωθεί out-of-band.
- Τα enum discriminants, οι relative pointers, τα lengths και τα indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Πρακτικό μοτίβο ελέγχου:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Αν ένα πεδίο όπως το `op.kind` είναι enum και ένας attacker μπορεί να εισαγάγει έναν **out-of-range discriminant**, κάθε downstream `match` πάνω σε αυτή την τιμή γίνεται ύποπτο.

### Παράκαμψη με Jump-table / UB

Αν η Rust μετατρέψει ένα μεγάλο `match` σε **jump table**, ένας μη έγκυρος enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο pattern είναι το εξής:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί τα **πραγματικά semantics της instruction**.
3. Ένας out-of-range discriminant κάνει index μετά το πρώτο jump table και καταλήγει σε κώδικα που σχετίζεται με το δεύτερο.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παρακάμπτεται. Σε ένα zkVM αυτό μπορεί να πλαστογραφήσει proofs που αναφέρουν αδύνατες μετρικές, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους παραποιημένους bounded resources.

Λίστα ελέγχου:

- Αναζητήστε attacker-controlled enums που γίνονται deserialize από witness/private input.
- Ελέγξτε επαναλαμβανόμενες δηλώσεις `match` πάνω στο ίδιο opcode/kind field.
- Αντιμετωπίστε τον συνδυασμό `unsafe` + unchecked deserialization + large opcode dispatch ως υψηλού κινδύνου.
- Κάντε reverse engineering του emitted binary όταν χρειάζεται· η διάταξη του jump table μπορεί να είναι σημαντικότερη από τον πηγαίο κώδικα.

### Ελλείποντες semantic constraints σε reversible/specialized interpreters

Μην επικυρώνετε μόνο την ασφάλεια μνήμης· επικυρώστε επίσης τους **semantic rules** που το proof προορίζεται να επιβάλλει.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι τα operands που πρέπει να είναι διαφορετικά περιορίζονται πράγματι ώστε να είναι διαφορετικά. Μια operation τύπου Toffoli/CCX που υλοποιείται ως:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται μη ασφαλές αν ο guest δεν απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση συμπτύσσεται σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, καταρρίπτοντας τις παραδοχές αντιστρεψιμότητας και επιτρέποντας φθηνότερους μη προβλεπόμενους υπολογισμούς. Σε proof systems που πιστοποιούν τη χρήση πόρων, αυτό μπορεί να επιτρέψει στους attackers να ικανοποιούν τους functional ελέγχους, παρακάμπτοντας παράλληλα το cost model που ο verifier θεωρεί ότι επιβάλλεται.

### Τι να ελέγχετε σε ZK systems

- Κάντε fuzzing σε όλους τους guest parsers με malformed witness/private-input encodings.
- Επιβεβαιώστε το enum range validation πριν από το opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες μη έγκυρες μορφές instructions.
- Συγκρίνετε τους reported/public counters με μια ανεξάρτητη reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί να αποδεικνύει τη **λάθος statement** αν το guest program είναι buggy.

## Authorization που εξαρτάται από το State

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploitation σε DeFi/AMM

Αν ερευνάτε πρακτικό exploitation των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), ελέγξτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που αποθηκεύουν virtual balances και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Επεξήγηση Public Key και Private Key - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Τι είναι οι multi-signature transactions; - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas και fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Νικήσαμε το zero-knowledge proof της Google για την quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Ασφάλιση Elliptic Curve Cryptocurrencies έναντι Quantum Vulnerabilities: Resource Estimates και Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-concept repository του Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
