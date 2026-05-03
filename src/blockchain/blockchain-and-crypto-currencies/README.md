# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες συνθήκες, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, με ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελέγξιμο back-end.
- **Tokens & Coins** διαφοροποιούν το πού τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα contexts.
- Τα **Utility Tokens** παρέχουν πρόσβαση σε services, ενώ τα **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακών στοιχείων.
- Το **DeFi** σημαίνει Decentralized Finance, προσφέροντας financial services χωρίς κεντρικές αρχές.
- Τα **DEX** και **DAOs** αναφέρονται σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations, αντίστοιχα.

## Consensus Mechanisms

Οι consensus mechanisms εξασφαλίζουν ασφαλείς και συμφωνημένες επικυρώσεις συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν μια ορισμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Bitcoin Essentials

### Transactions

Οι Bitcoin transactions περιλαμβάνουν μεταφορά κεφαλαίων μεταξύ addresses. Οι transactions επικυρώνονται μέσω ψηφιακών signatures, διασφαλίζοντας ότι μόνο ο owner του private key μπορεί να ξεκινήσει μεταφορές.

#### Key Components:

- Οι **Multisignature Transactions** απαιτούν πολλαπλές signatures για την εξουσιοδότηση μιας transaction.
- Οι transactions αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (πληρώνονται στους miners) και **scripts** (κανόνες transaction).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin επιτρέποντας πολλαπλές transactions μέσα σε ένα channel, δημοσιεύοντας μόνο την τελική κατάσταση στο blockchain.

## Bitcoin Privacy Concerns

Τα privacy attacks, όπως τα **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα transactions. Στρατηγικές όπως τα **Mixers** και το **CoinJoin** βελτιώνουν την ανωνυμία αποκρύπτοντας τους δεσμούς μεταξύ transactions των users.

## Acquiring Bitcoins Anonymously

Οι μέθοδοι περιλαμβάνουν cash trades, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές transactions για να δυσκολέψει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές transactions για αυξημένο privacy.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, το privacy των transactions και η ανωνυμία των users αποτελούν συχνά αντικείμενα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών συνηθισμένων μεθόδων μέσω των οποίων attackers μπορούν να παραβιάσουν το Bitcoin privacy.

## **Common Input Ownership Assumption**

Γενικά, είναι σπάνιο inputs από διαφορετικούς users να συνδυάζονται σε μία μόνο transaction λόγω της πολυπλοκότητας που απαιτείται. Έτσι, **δύο input addresses στην ίδια transaction συχνά θεωρείται ότι ανήκουν στον ίδιο owner**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανάται εξ ολοκλήρου σε μια transaction. Αν μόνο ένα μέρος του σταλεί σε άλλο address, το υπόλοιπο πηγαίνει σε ένα νέο change address. Οι observers μπορούν να υποθέσουν ότι αυτό το νέο address ανήκει στον sender, θέτοντας σε κίνδυνο το privacy.

### Example

Για τον μετριασμό αυτού, services mixing ή η χρήση πολλαπλών addresses μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι users μερικές φορές μοιράζονται online τα Bitcoin addresses τους, καθιστώντας εύκολο να συνδεθεί το address με τον owner του.

## **Transaction Graph Analysis**

Οι transactions μπορούν να οπτικοποιηθούν ως graphs, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ users με βάση τη ροή των funds.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση transactions με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το change output μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να μπερδέψει το heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στείλουν μικρά ποσά σε διευθύνσεις που έχουν χρησιμοποιηθεί προηγουμένως, ελπίζοντας ότι ο recipient θα τα συνδυάσει με άλλα inputs σε μελλοντικές transactions, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Correct Wallet Behavior

Τα wallets θα πρέπει να αποφεύγουν τη χρήση coins που ελήφθησαν σε ήδη χρησιμοποιημένες, κενές διευθύνσεις, για να αποτρέψουν αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions χωρίς change είναι πιθανό να γίνονται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο user.
- **Round Numbers:** Ένα στρογγυλό ποσό σε μια transaction υποδηλώνει ότι είναι payment, με το μη στρογγυλό output πιθανότατα να είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά patterns δημιουργίας transactions, επιτρέποντας στους analysts να αναγνωρίσουν το software που χρησιμοποιήθηκε και πιθανώς τη διεύθυνση change.
- **Amount & Timing Correlations:** Η αποκάλυψη των χρόνων ή των ποσών μιας transaction μπορεί να την κάνει traceable.

## **Traffic Analysis**

Παρακολουθώντας network traffic, οι attackers μπορούν δυνητικά να συνδέσουν transactions ή blocks με IP addresses, θέτοντας σε κίνδυνο το privacy των users. Αυτό είναι ιδιαίτερα αληθινό αν μια οντότητα λειτουργεί πολλούς Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί transactions.

## More

Για μια ολοκληρωμένη λίστα με privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online για bitcoin.
- **Mining**: Η πιο private μέθοδος για να κερδίσει κανείς bitcoins είναι μέσω mining, ειδικά όταν γίνεται μόνος, επειδή mining pools μπορεί να γνωρίζουν τη IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, το να κλέψει κανείς bitcoin θα μπορούσε να είναι ένας άλλος τρόπος απόκτησής του anonymously, αν και είναι παράνομο και δεν συνιστάται.

## Mixing Services

Χρησιμοποιώντας ένα mixing service, ένας user μπορεί να **send bitcoins** και να λάβει **different bitcoins in return**, κάτι που κάνει το tracing του αρχικού owner δύσκολο. Παρ' όλα αυτά, αυτό απαιτεί εμπιστοσύνη στο service ότι δεν θα κρατήσει logs και ότι θα επιστρέψει πράγματι τα bitcoins. Εναλλακτικές mixing επιλογές περιλαμβάνουν Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συνδυάζει πολλές transactions από διαφορετικούς users σε μία, περιπλέκοντας τη διαδικασία για οποιονδήποτε προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, transactions με μοναδικά μεγέθη input και output μπορούν ακόμα δυνητικά να εντοπιστούν.

Παραδείγματα transactions που μπορεί να χρησιμοποίησαν CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για μια παρόμοια υπηρεσία στο Ethereum, δείτε το [Tornado Cash](https://tornado.cash), το οποίο anonymizes transactions με funds από miners.

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), μεταμφιέζει τη transaction ανάμεσα σε δύο parties (π.χ. έναν customer και έναν merchant) ως κανονική transaction, χωρίς τα χαρακτηριστικά ίσα outputs του CoinJoin. Αυτό το κάνει εξαιρετικά δύσκολο να ανιχνευθεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιείται από transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, ενισχύοντας την ιδιωτικότητα ενώ παραμένουν μη διακρίσιμες από standard bitcoin transactions.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας το μια πολλά υποσχόμενη εξέλιξη στην επιδίωξη της ιδιωτικότητας των συναλλαγών.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Για τη διατήρηση της ιδιωτικότητας και της ασφάλειας, ο συγχρονισμός των wallets με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node διασφαλίζει μέγιστη ιδιωτικότητα. Όλες οι συναλλαγές που έχουν γίνει ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για αντιπάλους να εντοπίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα wallets να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα σε παρατηρητές του δικτύου. Τα lightweight wallets κατεβάζουν αυτά τα φίλτρα, ανακτώντας ολόκληρα blocks μόνο όταν βρεθεί αντιστοίχιση με τις διευθύνσεις του χρήστη.

## **Utilizing Tor for Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer network, συνιστάται η χρήση του Tor για να καλύψετε τη διεύθυνση IP σας, ενισχύοντας την ιδιωτικότητα κατά την αλληλεπίδραση με το δίκτυο.

## **Preventing Address Reuse**

Για να προστατεύσετε την ιδιωτικότητα, είναι ζωτικής σημασίας να χρησιμοποιείτε νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο την ιδιωτικότητα συνδέοντας τις συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallets αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Η διαίρεση μιας πληρωμής σε πολλές συναλλαγές μπορεί να συγκαλύψει το ποσό της συναλλαγής, αποτρέποντας privacy attacks.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει την ιδιωτικότητα διαταράσσοντας τις μεθόδους ανίχνευσης change.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλών change outputs μπορεί να βελτιώσει την ιδιωτικότητα.

# **Monero: A Beacon of Anonymity**

Το Monero αντιμετωπίζει την ανάγκη για απόλυτη ανωνυμία σε ψηφιακές συναλλαγές, θέτοντας υψηλό standard για την ιδιωτικότητα.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum, με τιμολόγηση σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει gas limit και base fee, με ένα tip για να δοθεί κίνητρο στους miners. Οι χρήστες μπορούν να ορίσουν max fee ώστε να μην πληρώσουν παραπάνω, με το επιπλέον ποσό να επιστρέφεται.

## **Executing Transactions**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν sender και έναν recipient, οι οποίοι μπορεί να είναι είτε user είτε smart contract διευθύνσεις. Απαιτούν fee και πρέπει να γίνουν mined. Οι βασικές πληροφορίες σε μια συναλλαγή περιλαμβάνουν τον recipient, την υπογραφή του sender, το value, προαιρετικά data, gas limit και fees. Αξιοσημείωτο είναι ότι η διεύθυνση του sender προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα δεδομένα της συναλλαγής.

Αυτές οι πρακτικές και οι μηχανισμοί είναι θεμελιώδεις για όποιον θέλει να ασχοληθεί με cryptocurrencies, δίνοντας προτεραιότητα στην ιδιωτικότητα και την ασφάλεια.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να πιστοποιήσει ένα claim, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως γράφτηκε**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας κακόβουλος prover μπορεί να δημιουργήσει μια proof που επαληθεύεται ενώ οι **public metrics ή το claimed invariant είναι false**.

### Unsafe deserialization inside proof guests

- Αντιμετωπίζετε τα private witness/circuit bytes ως **untrusted attacker input** ακόμη κι αν είναι κρυμμένα από την proof.
- Αποφύγετε την αποσειριοποίησή τους με unchecked helpers όπως `rkyv::access_unchecked` εκτός αν τα bytes έχουν ήδη επικυρωθεί out-of-band.
- Enum discriminants, relative pointers, lengths και indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Αν ένα πεδίο όπως το `op.kind` είναι enum και ένας επιτιθέμενος μπορεί να εισάγει ένα **out-of-range discriminant**, κάθε downstream `match` πάνω σε αυτή την τιμή γίνεται ύποπτο.

### Jump-table / UB counter bypass

Αν το Rust κάνει lowering ένα μεγάλο `match` σε μια **jump table**, ένα άκυρο enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο μοτίβο είναι:

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί την **real instruction semantics**.
3. Ένα out-of-range discriminant κάνει index πέρα από την πρώτη jump table και προσγειώνεται σε code που σχετίζεται με τη δεύτερη.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παραλείπεται. Σε ένα zkVM αυτό μπορεί να πλαστογραφήσει proofs που αναφέρουν αδύνατα metrics όπως fewer gates, fewer expensive operations, ή άλλα falsified bounded resources.

Review checklist:

- Look for attacker-controlled enums deserialized from witness/private input.
- Inspect repeated `match` statements over the same opcode/kind field.
- Treat `unsafe` + unchecked deserialization + large opcode dispatch as a high-risk combination.
- Reverse engineer the emitted binary when needed; jump-table layout can matter more than the source.

### Missing semantic constraints in reversible/specialized interpreters

Μην επικυρώνετε μόνο την memory safety· επικυρώστε επίσης τους **semantic rules** που το proof προορίζεται να επιβάλλει.

Για reversible/quantum-like instruction sets, ensure operands that must be distinct are actually constrained to be distinct. A Toffoli/CCX-like operation implemented as:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται μη ασφαλές αν ο guest δεν απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση καταρρέει σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, σπάζοντας τις υποθέσεις αναστρεψιμότητας και επιτρέποντας φθηνότερους μη-προοριζόμενους υπολογισμούς. Σε proof systems που πιστοποιούν χρήση πόρων, αυτό μπορεί να επιτρέψει σε attackers να ικανοποιήσουν λειτουργικούς ελέγχους ενώ παρακάμπτουν το cost model που ο verifier πιστεύει ότι επιβάλλεται.

### Τι να ελέγξετε σε ZK systems

- Fuzz όλα τα guest parsers με malformed witness/private-input encodings.
- Βεβαιωθείτε ότι γίνεται enum range validation πριν από opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες invalid instruction forms.
- Συγκρίνετε τους reported/public counters με μια ανεξάρτητη reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί ακόμα να αποδεικνύει τη **λάθος πρόταση** αν το guest program είναι buggy.

## DeFi/AMM Exploitation

Αν ερευνάτε πρακτική exploitation DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{endref}}

Για multi-asset weighted pools που κάνουν cache virtual balances και μπορούν να poisoned όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
