# Blockchain και Κρυπτονομίσματα

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- Τα **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται συγκεκριμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς μεσάζοντες.
- Οι **Decentralized Applications (dApps)** βασίζονται σε smart contracts και διαθέτουν ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελέγξιμο back-end.
- Τα **Tokens & Coins** διαφέρουν ως προς το ότι τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- Τα **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, ενώ τα **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακών στοιχείων.
- Το **DeFi** σημαίνει Decentralized Finance και προσφέρει χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- Τα **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Μηχανισμοί Συναίνεσης

Οι μηχανισμοί συναίνεσης διασφαλίζουν την ασφαλή και συμφωνημένη επικύρωση συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να διατηρούν μια συγκεκριμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.<sup>[[1]](#references)</sup>

## Βασικά στοιχεία του Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω digital signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.<sup>[[2]](#references)</sup>

#### Βασικά στοιχεία:

- Οι **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.<sup>[[3]](#references)</sup>
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (καταβάλλονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin, επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα channel και μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Ανησυχίες για το Privacy του Bitcoin

Επιθέσεις privacy, όπως οι **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα συναλλαγών. Στρατηγικές όπως τα **Mixers** και το **CoinJoin** βελτιώνουν το anonymity αποκρύπτοντας τις συνδέσεις συναλλαγών μεταξύ χρηστών.

## Ανώνυμη απόκτηση Bitcoins

Οι μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να δυσκολέψει την ιχνηλασιμότητα, ενώ το **PayJoin** συγκαλύπτει τα CoinJoins ως κανονικές συναλλαγές για αυξημένο privacy.

# Επιθέσεις Privacy του Bitcoin

# Περίληψη των Επιθέσεων Privacy του Bitcoin

Στον κόσμο του Bitcoin, το privacy των συναλλαγών και το anonymity των χρηστών αποτελούν συχνά αντικείμενα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών συνηθισμένων μεθόδων μέσω των οποίων οι attackers μπορούν να παραβιάσουν το privacy του Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Γενικά, είναι σπάνιο να συνδυάζονται inputs από διαφορετικούς χρήστες σε μία συναλλαγή λόγω της πολυπλοκότητας που απαιτείται. Επομένως, **δύο input addresses στην ίδια συναλλαγή θεωρείται συχνά ότι ανήκουν στον ίδιο κάτοχο**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί εξ ολοκλήρου σε μια συναλλαγή. Αν σταλεί μόνο ένα μέρος του σε άλλη διεύθυνση, το υπόλοιπο μεταφέρεται σε μια νέα change address. Οι παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, θέτοντας σε κίνδυνο το privacy.

### Παράδειγμα

Για τον περιορισμό αυτού του κινδύνου, οι υπηρεσίες mixing ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές κοινοποιούν τις Bitcoin addresses τους online, καθιστώντας **εύκολη τη σύνδεση της διεύθυνσης με τον κάτοχό της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να οπτικοποιηθούν ως γραφήματα, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs, ώστε να γίνει πρόβλεψη για το ποιο output αποτελεί τα ρέστα που επιστρέφουν στον αποστολέα.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Εάν η προσθήκη περισσότερων inputs κάνει το change output μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να μπερδέψει το heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στέλνουν μικρά ποσά σε διευθύνσεις που έχουν ήδη χρησιμοποιηθεί, ελπίζοντας ότι ο παραλήπτης θα τα συνδυάσει με άλλα inputs σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Σωστή συμπεριφορά Wallet

Τα Wallets θα πρέπει να αποφεύγουν τη χρήση coins που λαμβάνονται σε ήδη χρησιμοποιημένες, κενές διευθύνσεις, ώστε να αποτρέπεται αυτό το privacy leak.

## **Άλλες τεχνικές Blockchain Analysis**

- **Ακριβή ποσά πληρωμής:** Οι συναλλαγές χωρίς change είναι πιθανό να πραγματοποιούνται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Στρογγυλοί αριθμοί:** Ένας στρογγυλός αριθμός σε μια συναλλαγή υποδηλώνει ότι πρόκειται για πληρωμή, ενώ το output που δεν είναι στρογγυλό πιθανότατα είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά μοτίβα δημιουργίας συναλλαγών, επιτρέποντας στους analysts να αναγνωρίζουν το software που χρησιμοποιείται και, ενδεχομένως, τη διεύθυνση change.
- **Συσχετίσεις ποσού και χρόνου:** Η αποκάλυψη των χρόνων ή των ποσών των συναλλαγών μπορεί να κάνει τις συναλλαγές ανιχνεύσιμες.

## **Traffic Analysis**

Με την παρακολούθηση της κίνησης του δικτύου, οι attackers μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με IP addresses, θέτοντας σε κίνδυνο το privacy των χρηστών. Αυτό ισχύει ιδιαίτερα όταν μια οντότητα λειτουργεί πολλά Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί συναλλαγές.

## Περισσότερα

Για μια ολοκληρωμένη λίστα privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Τρόποι απόκτησης Bitcoins Anonymous

- **Cash Transactions:** Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives:** Αγορά gift cards και online ανταλλαγή τους με bitcoin.
- **Mining:** Η πιο privacy-friendly μέθοδος απόκτησης bitcoins είναι το mining, ιδιαίτερα όταν πραγματοποιείται μεμονωμένα, επειδή τα mining pools μπορεί να γνωρίζουν την IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft:** Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι ένας ακόμη τρόπος anonymous απόκτησής του, αν και είναι παράνομη και δεν συνιστάται.

## Mixing Services

Με τη χρήση ενός mixing service, ένας χρήστης μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins ως αντάλλαγμα**, γεγονός που δυσκολεύει την ανίχνευση του αρχικού κατόχου. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι το service δεν θα κρατήσει logs και ότι πράγματι θα επιστρέψει τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συγχωνεύει πολλές συναλλαγές από διαφορετικούς χρήστες σε μία, περιπλέκοντας τη διαδικασία για όποιον προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, συναλλαγές με μοναδικά μεγέθη input και output μπορούν ακόμη να ανιχνευθούν.

Παραδείγματα συναλλαγών που μπορεί να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για παρόμοιο service στο Ethereum, δείτε το [Tornado Cash](https://tornado.cash), το οποίο anonymizes συναλλαγές με funds από miners.

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), μεταμφιέζει τη συναλλαγή μεταξύ δύο μερών (π.χ. ενός πελάτη και ενός merchant) ως κανονική συναλλαγή, χωρίς το χαρακτηριστικό των ίσων outputs του CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να ανιχνευθεί και θα μπορούσε να καταστήσει άκυρο το common-input-ownership heuristic που χρησιμοποιείται από entities επιτήρησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, ενισχύοντας το privacy ενώ παραμένουν δυσδιάκριτες από τις τυπικές bitcoin συναλλαγές.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους surveillance**, καθιστώντας την μια πολλά υποσχόμενη εξέλιξη στην προσπάθεια για transactional privacy.

# Βέλτιστες πρακτικές για privacy στα cryptocurrencies

## **Τεχνικές συγχρονισμού wallet**

Για τη διατήρηση του privacy και της ασφάλειας, ο συγχρονισμός των wallet με το blockchain είναι κρίσιμος. Ξεχωρίζουν δύο μέθοδοι:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node εξασφαλίζει μέγιστο privacy. Όλες οι συναλλαγές που έχουν πραγματοποιηθεί αποθηκεύονται τοπικά, καθιστώντας αδύνατο για τους adversaries να αναγνωρίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία filters για κάθε block του blockchain, επιτρέποντας στα wallet να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα σε network observers. Τα lightweight wallet κατεβάζουν αυτά τα filters και ανακτούν ολόκληρα blocks μόνο όταν εντοπιστεί αντιστοίχιση με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για ανωνυμία**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer network, συνιστάται η χρήση του Tor για την απόκρυψη της IP address σας, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Αποτροπή επαναχρησιμοποίησης διευθύνσεων**

Για την προστασία του privacy, είναι ζωτικής σημασίας να χρησιμοποιείται μια νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το privacy, συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallet αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για transactional privacy**

- **Multiple transactions**: Ο διαχωρισμός μιας πληρωμής σε πολλές συναλλαγές μπορεί να αποκρύψει το ποσό της συναλλαγής, αποτρέποντας privacy attacks.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει το privacy, διαταράσσοντας τις μεθόδους ανίχνευσης change.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλών change outputs μπορεί και πάλι να βελτιώσει το privacy.

# **Monero: Φάρος ανωνυμίας**

Το Monero ανταποκρίνεται στην ανάγκη για απόλυτη ανωνυμία στις digital συναλλαγές, θέτοντας υψηλά standards για το privacy.

# **Ethereum: Gas και συναλλαγές**

## **Κατανόηση του Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum και τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, καθώς και ένα tip για την παροχή κινήτρου στους miners. Οι χρήστες μπορούν να ορίσουν ένα max fee ώστε να διασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, με το πλεόνασμα να επιστρέφεται.<sup>[[5]](#references)</sup>

## **Εκτέλεση συναλλαγών**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν sender και έναν recipient, οι οποίοι μπορεί να είναι είτε user είτε smart contract addresses. Απαιτούν fee και πρέπει να γίνουν mined. Οι βασικές πληροφορίες μιας συναλλαγής περιλαμβάνουν τον recipient, την υπογραφή του sender, την αξία, προαιρετικά data, το gas limit και τα fees. Αξίζει να σημειωθεί ότι η address του sender συνάγεται από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα transaction data.<sup>[[4]](#references)</sup>

Αυτές οι πρακτικές και οι μηχανισμοί αποτελούν τη βάση για όποιον επιθυμεί να ασχοληθεί με cryptocurrencies, δίνοντας προτεραιότητα στο privacy και την ασφάλεια.

## Red Teaming στο Web3 με επίκεντρο την αξία

- Καταγράψτε τα components που μεταφέρουν αξία (signers, oracles, bridges, automation), ώστε να κατανοήσετε ποιος μπορεί να μετακινήσει funds και με ποιον τρόπο.
- Αντιστοιχίστε κάθε component με τα σχετικά MITRE AADAPT tactics, ώστε να αποκαλύψετε paths για privilege escalation.
- Κάντε rehearse flash-loan/oracle/credential/cross-chain attack chains για να επικυρώσετε τον αντίκτυπο και να τεκμηριώσετε τις exploitable προϋποθέσεις.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromise του Web3 Signing Workflow

- Η παραποίηση στο supply chain των wallet UIs μπορεί να μεταβάλει τα EIP-712 payloads ακριβώς πριν από το signing, συλλέγοντας valid signatures για delegatecall-based proxy takeovers (π.χ. slot-0 overwrite του Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Οι συνήθεις smart-account failure modes περιλαμβάνουν bypass του access control του `EntryPoint`, unsigned gas fields, stateful validation, ERC-1271 replay και fee-drain μέσω revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Ασφάλεια Smart Contract

- Mutation testing για την εύρεση blind spots στις test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Ακεραιότητα ZK Proof / zkVM Guest

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να επιβεβαιώσει έναν ισχυρισμό, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως έχει γραφτεί**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας κακόβουλος prover μπορεί να δημιουργήσει ένα proof που επαληθεύεται, ενώ τα **public metrics ή το claimed invariant είναι false**.<sup>[[7]](#references)</sup>

### Unsafe deserialization μέσα σε proof guests

- Αντιμετωπίζετε τα private witness/circuit bytes ως **untrusted attacker input**, ακόμη και αν κρύβονται από το proof.
- Αποφύγετε την αποσειριοποίησή τους με unchecked helpers όπως το `rkyv::access_unchecked`, εκτός αν τα bytes έχουν ήδη επικυρωθεί out-of-band.
- Τα enum discriminants, relative pointers, lengths και indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Πρακτικό audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Αν ένα πεδίο όπως το `op.kind` είναι enum και ένας attacker μπορεί να εισαγάγει έναν **out-of-range discriminant**, κάθε downstream `match` πάνω σε αυτή την τιμή γίνεται ύποπτο.

### Παράκαμψη counter μέσω Jump-table / UB

Αν η Rust μετατρέπει ένα μεγάλο `match` σε **jump table**, ένα μη έγκυρο enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο μοτίβο είναι το εξής:<sup>[[7]](#references)[[9]](#references)</sup>

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί τα **πραγματικά semantics της instruction**.
3. Ένας out-of-range discriminant προσπελαύνει θέση μετά το πρώτο jump table και καταλήγει σε κώδικα που σχετίζεται με το δεύτερο.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παρακάμπτεται. Σε ένα zkVM, αυτό μπορεί να forge proofs που αναφέρουν αδύνατες μετρικές, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους falsified bounded resources.

Checklist ελέγχου:

- Αναζητήστε attacker-controlled enums που γίνονται deserialize από witness/private input.
- Ελέγξτε επαναλαμβανόμενες εντολές `match` πάνω στο ίδιο opcode/kind field.
- Θεωρήστε τον συνδυασμό `unsafe` + unchecked deserialization + large opcode dispatch υψηλού ρίσκου.
- Κάντε reverse engineer το emitted binary όταν χρειάζεται· η διάταξη του jump table μπορεί να είναι σημαντικότερη από τον source code.

### Missing semantic constraints σε reversible/specialized interpreters

Μην επικυρώνετε μόνο την ασφάλεια μνήμης· επικυρώστε επίσης τους **semantic rules** που υποτίθεται ότι επιβάλλει το proof.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι τα operands που πρέπει να είναι distinct πράγματι constrained ώστε να είναι distinct. Μια operation τύπου Toffoli/CCX που υλοποιείται ως:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται μη ασφαλές αν το guest δεν απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση συμπτύσσεται σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **ντετερμινιστικό primitive επαναφοράς**, παραβιάζοντας τις παραδοχές αντιστρεψιμότητας και επιτρέποντας φθηνότερους μη προβλεπόμενους υπολογισμούς. Σε proof systems που πιστοποιούν τη χρήση πόρων, αυτό μπορεί να επιτρέψει στους επιτιθέμενους να ικανοποιούν τους λειτουργικούς ελέγχους, παρακάμπτοντας παράλληλα το μοντέλο κόστους που ο verifier θεωρεί ότι επιβάλλεται.

### Τι να δοκιμάσετε σε ZK systems

- Εφαρμόστε fuzzing σε όλους τους guest parsers με κακοσχηματισμένες κωδικοποιήσεις witness/private-input.
- Επιβεβαιώστε το enum range validation πριν από το opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες μη έγκυρες μορφές instructions.
- Συγκρίνετε τους reported/public counters με μια ανεξάρτητη reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί και πάλι να αποδεικνύει τη **λάθος statement** αν το guest program έχει σφάλματα.

## DeFi/AMM Exploitation

Αν ερευνάτε πρακτική exploitation των DEXes και των AMMs (Uniswap v4 hooks, rounding/precision abuse, flash-loan amplified threshold-crossing swaps), ελέγξτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που αποθηκεύουν virtual balances σε cache και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Αναφορές

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Επεξήγηση Public Key και Private Key - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [Τι είναι οι multi-signature transactions; - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas και fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Νικήσαμε το zero-knowledge proof της Google για την κβαντική cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Ασφάλιση των Elliptic Curve Cryptocurrencies απέναντι σε Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
