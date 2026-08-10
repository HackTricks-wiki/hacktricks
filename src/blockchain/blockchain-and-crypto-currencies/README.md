# Blockchain και Κρυπτονομίσματα

## Βασικές Έννοιες

- Τα **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς μεσάζοντες.
- Οι **Decentralized Applications (dApps)** βασίζονται σε smart contracts και διαθέτουν user-friendly front-end και διαφανές, ελέγξιμο back-end.
- Τα **Tokens & Coins** διαφέρουν ως προς το ότι τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- Τα **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, ενώ τα **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακών στοιχείων.
- Το **DeFi** σημαίνει Decentralized Finance και προσφέρει χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- Τα **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Μηχανισμοί Συναίνεσης

Οι μηχανισμοί συναίνεσης διασφαλίζουν την ασφαλή και συμφωνημένη επικύρωση συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν μια συγκεκριμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.<sup>[[1]](#references)</sup>

## Βασικά στοιχεία του Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά χρημάτων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω digital signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.<sup>[[2]](#references)</sup>

#### Βασικά στοιχεία:

- Οι **Multisignature Transactions** απαιτούν multiple signatures για την εξουσιοδότηση μιας συναλλαγής.<sup>[[3]](#references)</sup>
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή χρημάτων), **outputs** (προορισμός), **fees** (καταβάλλονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα channel και μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Ανησυχίες σχετικά με το Bitcoin Privacy

Επιθέσεις privacy, όπως οι **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα συναλλαγών. Στρατηγικές όπως οι **Mixers** και το **CoinJoin** βελτιώνουν την anonymity αποκρύπτοντας τις συνδέσεις συναλλαγών μεταξύ χρηστών.

## Απόκτηση Bitcoins ανώνυμα

Οι μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει multiple transactions για να περιπλέξει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές συναλλαγές για αυξημένο privacy.

# Σύνοψη των Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, το privacy των συναλλαγών και η anonymity των χρηστών αποτελούν συχνά αντικείμενα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων μέσω των οποίων οι attackers μπορούν να παραβιάσουν το Bitcoin privacy.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Γενικά, είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία συναλλαγή λόγω της πολυπλοκότητας που απαιτείται. Επομένως, **δύο input addresses στην ίδια συναλλαγή θεωρείται συχνά ότι ανήκουν στον ίδιο owner**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί εξ ολοκλήρου σε μια συναλλαγή. Αν μόνο ένα μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο μεταφέρεται σε μια νέα change address. Οι observers μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον sender, θέτοντας σε κίνδυνο το privacy.

### Παράδειγμα

Για τον περιορισμό αυτού του κινδύνου, οι mixing services ή η χρήση multiple addresses μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές κοινοποιούν τις Bitcoin addresses τους online, καθιστώντας **εύκολη τη σύνδεση της διεύθυνσης με τον owner της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να οπτικοποιηθούν ως graphs, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή των χρημάτων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με multiple inputs και outputs, ώστε να γίνει εικασία για το ποιο output αποτελεί το change που επιστρέφεται στον sender.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το output της συναλλαγής μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να προκαλέσει σύγχυση στο heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στείλουν μικρά ποσά σε διευθύνσεις που έχουν χρησιμοποιηθεί στο παρελθόν, ελπίζοντας ότι ο παραλήπτης θα τις συνδυάσει με άλλα inputs σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Correct Wallet Behavior

Τα Wallets θα πρέπει να αποφεύγουν τη χρήση coins που λαμβάνονται σε ήδη χρησιμοποιημένες, κενές διευθύνσεις, ώστε να αποτρέπεται αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Οι συναλλαγές χωρίς change πιθανότατα πραγματοποιούνται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Round Numbers:** Ένας στρογγυλός αριθμός σε μια συναλλαγή υποδηλώνει ότι πρόκειται για πληρωμή, ενώ το output που δεν είναι στρογγυλό πιθανότατα είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά Wallets έχουν μοναδικά μοτίβα δημιουργίας συναλλαγών, επιτρέποντας στους analysts να εντοπίζουν το software που χρησιμοποιείται και, ενδεχομένως, τη διεύθυνση change.
- **Amount & Timing Correlations:** Η αποκάλυψη των χρόνων ή των ποσών των συναλλαγών μπορεί να καταστήσει τις συναλλαγές traceable.

## **Traffic Analysis**

Με την παρακολούθηση της κίνησης του δικτύου, οι attackers μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με διευθύνσεις IP, θέτοντας σε κίνδυνο το privacy των χρηστών. Αυτό ισχύει ιδιαίτερα αν μια οντότητα λειτουργεί πολλά Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί συναλλαγές.

## More

Για μια ολοκληρωμένη λίστα privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online με bitcoin.
- **Mining**: Η πιο private μέθοδος απόκτησης bitcoins είναι το mining, ειδικά όταν γίνεται μεμονωμένα, επειδή τα mining pools ενδέχεται να γνωρίζουν τη διεύθυνση IP του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι μια ακόμη μέθοδος ανώνυμης απόκτησής του, αν και είναι παράνομη και δεν συνιστάται.

## Mixing Services

Με τη χρήση μιας mixing service, ένας χρήστης μπορεί να **send bitcoins** και να λάβει **different bitcoins in return**, γεγονός που καθιστά δύσκολη την ανίχνευση του αρχικού κατόχου. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι η service δεν θα διατηρεί logs και ότι θα επιστρέψει πράγματι τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συγχωνεύει πολλές συναλλαγές από διαφορετικούς χρήστες σε μία, περιπλέκοντας τη διαδικασία για οποιονδήποτε προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, συναλλαγές με μοναδικά μεγέθη input και output μπορούν ακόμη να εντοπιστούν.

Παραδείγματα συναλλαγών που ενδέχεται να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για ένα Ethereum smart-contract mixer που διαχωρίζει τις καταθέσεις από τις μεταγενέστερες αναλήψεις, δείτε το [Tornado Cash](https://tornado.cash).

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), αποκρύπτει τη συναλλαγή μεταξύ δύο μερών (π.χ. ενός πελάτη και ενός merchant) ως μια κανονική συναλλαγή, χωρίς το χαρακτηριστικό των ίσων outputs του CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιούν entities επιτήρησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Τέτοιες συναλλαγές θα μπορούσαν να είναι PayJoin, ενισχύοντας το privacy ενώ παραμένουν μη διακριτές από τις τυπικές συναλλαγές bitcoin.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους surveillance**, καθιστώντας την μια πολλά υποσχόμενη εξέλιξη στην επιδίωξη του transactional privacy.

# Βέλτιστες πρακτικές για το Privacy στα Cryptocurrencies

## **Τεχνικές συγχρονισμού Wallet**

Για τη διατήρηση του privacy και της ασφάλειας, ο συγχρονισμός των wallet με το blockchain είναι κρίσιμος. Ξεχωρίζουν δύο μέθοδοι:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node διασφαλίζει το μέγιστο privacy. Όλες οι συναλλαγές που έχουν πραγματοποιηθεί ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για τους adversaries να εντοπίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα wallet να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα στους network observers. Τα lightweight wallet κατεβάζουν αυτά τα φίλτρα και λαμβάνουν ολόκληρα τα block μόνο όταν εντοπίζεται match με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer network, συνιστάται η χρήση του Tor για την απόκρυψη της IP address, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Αποτροπή Address Reuse**

Για την προστασία του privacy, είναι ζωτικής σημασίας να χρησιμοποιείται νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το privacy, συνδέοντας τις συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallet αποθαρρύνουν την address reuse μέσω του σχεδιασμού τους.

## **Στρατηγικές για Transaction Privacy**

- **Multiple transactions**: Ο διαχωρισμός μιας πληρωμής σε πολλές συναλλαγές μπορεί να αποκρύψει το ποσό της συναλλαγής, αποτρέποντας privacy attacks.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει το privacy, διαταράσσοντας τις μεθόδους change detection.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλαπλών change outputs μπορεί και πάλι να βελτιώσει το privacy.

# **Monero: Ένας Φάρος Anonymity**

Το Monero έχει σχεδιαστεί ώστε να δίνει προτεραιότητα στο transaction privacy.

# **Ethereum: Gas και Transactions**

## **Κατανόηση του Gas**

Το gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum και τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, καθώς και ένα priority fee για να δοθεί κίνητρο στους validators να την συμπεριλάβουν. Οι χρήστες μπορούν να ορίσουν ένα max fee ώστε να διασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, με το επιπλέον ποσό να επιστρέφεται.<sup>[[5]](#references)</sup>

## **Εκτέλεση Transactions**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν sender και έναν recipient, οι οποίοι μπορεί να είναι είτε user είτε smart contract addresses. Απαιτούν fee και πρέπει να συμπεριληφθούν σε ένα block. Οι βασικές πληροφορίες μιας συναλλαγής περιλαμβάνουν τον recipient, την υπογραφή του sender, την value, προαιρετικά data, το gas limit και τα fees. Αξιοσημείωτα, η διεύθυνση του sender συνάγεται από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα δεδομένα της συναλλαγής.<sup>[[4]](#references)</sup>

Αυτές οι πρακτικές και οι μηχανισμοί αποτελούν θεμελιώδη στοιχεία για οποιονδήποτε θέλει να ασχοληθεί με cryptocurrencies, δίνοντας προτεραιότητα στο privacy και την ασφάλεια.

## Red Teaming του Web3 με επίκεντρο την αξία

- Καταγράψτε τα components που διαχειρίζονται value (signers, oracles, bridges, automation), ώστε να κατανοήσετε ποιος μπορεί να μετακινήσει funds και με ποιον τρόπο.
- Αντιστοιχίστε κάθε component στις σχετικές MITRE AADAPT tactics, ώστε να αποκαλύψετε paths για privilege escalation.
- Κάντε rehearse attack chains με flash-loan/oracle/credential/cross-chain, ώστε να επικυρώσετε το impact και να τεκμηριώσετε τις exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromise του Web3 Signing Workflow

- Supply-chain tampering των wallet UI μπορεί να τροποποιήσει EIP-712 payloads ακριβώς πριν από το signing, συλλέγοντας valid signatures για delegatecall-based proxy takeovers (π.χ. slot-0 overwrite του Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Τα συνήθη failure modes των smart-account περιλαμβάνουν bypass του `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay και fee-drain μέσω revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Ασφάλεια Smart Contract

- Mutation testing για τον εντοπισμό blind spots στα test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να πιστοποιήσει έναν ισχυρισμό, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως είχε γραφτεί**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας malicious prover μπορεί να δημιουργήσει proof που επαληθεύεται, ενώ τα **public metrics ή το claimed invariant είναι false**.<sup>[[7]](#references)</sup>

### Unsafe deserialization μέσα σε proof guests

- Αντιμετωπίζετε τα private witness/circuit bytes ως **untrusted attacker input**, ακόμη και αν αποκρύπτονται από το proof.
- Αποφεύγετε την αποσειριοποίησή τους με unchecked helpers όπως το `rkyv::access_unchecked`, εκτός αν τα bytes έχουν ήδη validated out-of-band.
- Τα enum discriminants, relative pointers, lengths και indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Πρακτικό audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Εάν ένα πεδίο όπως το `op.kind` είναι enum και ένας attacker μπορεί να εισαγάγει έναν **out-of-range discriminant**, κάθε downstream `match` σε αυτή την τιμή γίνεται ύποπτο.

### Jump-table / UB counter bypass

Εάν η Rust μετατρέπει ένα μεγάλο `match` σε **jump table**, ένας μη έγκυρος enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο pattern είναι το εξής:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί τα **πραγματικά semantics της instruction**.
3. Ένας out-of-range discriminant προσπελαύνει θέση μετά το πρώτο jump table και καταλήγει σε κώδικα που σχετίζεται με το δεύτερο.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παρακάμπτεται. Σε ένα zkVM αυτό μπορεί να πλαστογραφήσει proofs που αναφέρουν αδύνατα metrics, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους παραποιημένους bounded resources.

Checklist ελέγχου:

- Αναζητήστε attacker-controlled enums που γίνονται deserialize από witness/private input.
- Ελέγξτε επαναλαμβανόμενες εντολές `match` πάνω στο ίδιο opcode/kind field.
- Αντιμετωπίστε τον συνδυασμό `unsafe` + unchecked deserialization + large opcode dispatch ως υψηλού κινδύνου.
- Κάντε reverse engineering του emitted binary όταν χρειάζεται· η διάταξη του jump table μπορεί να είναι σημαντικότερη από τον source code.

### Missing semantic constraints in reversible/specialized interpreters

Μην επικυρώνετε μόνο την ασφάλεια μνήμης· επικυρώστε επίσης τους **semantic rules** που το proof πρέπει να επιβάλλει.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι τα operands που πρέπει να είναι διαφορετικά πράγματι περιορίζονται ώστε να είναι διαφορετικά. Μια operation τύπου Toffoli/CCX που υλοποιείται ως:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται μη ασφαλές αν ο guest δεν το απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση συμπτύσσεται σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, καταρρίπτοντας τις παραδοχές αντιστρεψιμότητας και επιτρέποντας φθηνότερους υπολογισμούς που δεν προβλέπονται από τον σχεδιασμό. Σε proof systems που πιστοποιούν τη χρήση πόρων, αυτό μπορεί να επιτρέψει σε attackers να ικανοποιούν τους λειτουργικούς ελέγχους, παρακάμπτοντας παράλληλα το cost model που ο verifier θεωρεί ότι επιβάλλεται.

### Τι να ελέγχετε σε ZK systems

- Κάντε fuzzing σε όλους τους guest parsers με malformed witness/private-input encodings.
- Επιβεβαιώστε το enum range validation πριν από το opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες μη έγκυρες μορφές instructions.
- Συγκρίνετε τους reported/public counters με μια ανεξάρτητη reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί ακόμη να αποδεικνύει τη **λάθος statement** αν το guest program είναι buggy.

## Εκμετάλλευση DeFi/AMM

Αν ερευνάτε πρακτική exploitation των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), ελέγξτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που κάνουν cache τα virtual balances και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Επεξήγηση δημόσιου κλειδιού και ιδιωτικού κλειδιού - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Τι είναι οι συναλλαγές πολλαπλών υπογραφών; - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Συναλλαγές | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas και fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Νικήσαμε το zero-knowledge proof της Google για την κβαντική κρυπτανάλυση](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Ασφάλιση κρυπτονομισμάτων ελλειπτικών καμπυλών απέναντι σε κβαντικές ευπάθειες: εκτιμήσεις πόρων και μετριασμοί (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Proof-of-concept repository του Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
