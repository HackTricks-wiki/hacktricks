# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες συνθήκες, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, με ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελέγξιμο back-end.
- **Tokens & Coins** διαφοροποιούν το πού τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- Οι **Utility Tokens** δίνουν πρόσβαση σε υπηρεσίες, και οι **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακού στοιχείου.
- Το **DeFi** σημαίνει Decentralized Finance, προσφέροντας χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- Οι **DEX** και οι **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Μηχανισμοί Συναίνεσης

Οι μηχανισμοί συναίνεσης διασφαλίζουν ασφαλείς και συμφωνημένες επικυρώσεις συναλλαγών στο blockchain:

- Το **Proof of Work (PoW)** βασίζεται σε υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- Το **Proof of Stake (PoS)** απαιτεί από τους validators να διατηρούν μια ορισμένη ποσότητα tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Bitcoin Essentials

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.

#### Key Components:

- Οι **Multisignature Transactions** απαιτούν πολλαπλά signatures για να εγκριθεί μια συναλλαγή.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (πληρώνονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στόχος είναι η βελτίωση της κλιμακωσιμότητας του Bitcoin επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα channel, μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Θέματα Απορρήτου Bitcoin

Επιθέσεις απορρήτου, όπως οι **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται μοτίβα συναλλαγών. Στρατηγικές όπως οι **Mixers** και το **CoinJoin** βελτιώνουν την ανωνυμία αποκρύπτοντας τα links συναλλαγών μεταξύ χρηστών.

## Απόκτηση Bitcoins Ανώνυμα

Οι μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να δυσκολέψει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές συναλλαγές για αυξημένο απόρρητο.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, το απόρρητο των συναλλαγών και η ανωνυμία των χρηστών συχνά αποτελούν θέματα ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών συνηθισμένων μεθόδων μέσω των οποίων οι attackers μπορούν να παραβιάσουν το απόρρητο του Bitcoin.

## **Common Input Ownership Assumption**

Γενικά είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μια ενιαία συναλλαγή λόγω της πολυπλοκότητας που απαιτείται. Έτσι, **two input addresses in the same transaction are often assumed to belong to the same owner**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί εξ ολοκλήρου σε μια συναλλαγή. Αν μόνο ένα μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα change address. Οι παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, θέτοντας σε κίνδυνο το απόρρητο.

### Example

Για να μετριαστεί αυτό, τα mixing services ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές μοιράζονται δημόσια τις διευθύνσεις Bitcoin τους, καθιστώντας το **easy to link the address to its owner**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να οπτικοποιηθούν ως graphs, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών βάσει της ροής των κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον αποστολέα.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το change output μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να μπερδέψει το heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στείλουν μικρά ποσά σε addresses που έχουν χρησιμοποιηθεί πριν, ελπίζοντας ότι ο recipient θα τα συνδυάσει με άλλα inputs σε μελλοντικές transactions, συνδέοντας έτσι τα addresses μεταξύ τους.

### Correct Wallet Behavior

Τα wallets θα πρέπει να αποφεύγουν τη χρήση coins που ελήφθησαν σε ήδη χρησιμοποιημένες, κενές addresses για να αποτρέψουν αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions χωρίς change είναι πιθανό να γίνονται μεταξύ δύο addresses που ανήκουν στον ίδιο user.
- **Round Numbers:** Ένας round number σε μια transaction υποδηλώνει ότι πρόκειται για payment, με το μη round output πιθανότατα να είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά patterns δημιουργίας transactions, επιτρέποντας στους analysts να εντοπίσουν το software που χρησιμοποιήθηκε και πιθανόν τη change address.
- **Amount & Timing Correlations:** Η αποκάλυψη χρόνων ή ποσών transactions μπορεί να τις καταστήσει traceable.

## **Traffic Analysis**

Παρακολουθώντας network traffic, οι attackers μπορούν δυνητικά να συνδέσουν transactions ή blocks με IP addresses, θέτοντας σε κίνδυνο το user privacy. Αυτό ισχύει ιδιαίτερα αν μια οντότητα λειτουργεί πολλούς Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί transactions.

## More

Για μια πλήρη λίστα από privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online για bitcoin.
- **Mining**: Ο πιο private τρόπος να κερδίσει κανείς bitcoins είναι μέσω mining, ειδικά όταν γίνεται μόνος του επειδή τα mining pools μπορεί να γνωρίζουν το IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι ένας ακόμη τρόπος για να τα αποκτήσει κανείς anonymously, αν και είναι παράνομο και δεν συνιστάται.

## Mixing Services

Χρησιμοποιώντας ένα mixing service, ένας user μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins σε αντάλλαγμα**, κάτι που δυσκολεύει το tracing του αρχικού owner. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι το service δεν θα κρατήσει logs και ότι θα επιστρέψει πράγματι τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συγχωνεύει πολλαπλές transactions από διαφορετικούς users σε μία, περιπλέκοντας τη διαδικασία για όποιον προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, transactions με μοναδικά input και output sizes μπορούν ακόμα δυνητικά να εντοπιστούν.

Παραδείγματα transactions που μπορεί να χρησιμοποίησαν CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για μια παρόμοια υπηρεσία στο Ethereum, δείτε το [Tornado Cash](https://tornado.cash), το οποίο anonymizes transactions με funds από miners.

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), μεταμφιέζει τη transaction ανάμεσα σε δύο parties (π.χ. έναν customer και έναν merchant) ως κανονική transaction, χωρίς τα χαρακτηριστικά ίσα outputs του CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιούν οι transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, ενισχύοντας το απόρρητο ενώ παραμένουν αδιάκριτες από τις standard bitcoin transactions.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας το μια πολλά υποσχόμενη εξέλιξη στην επιδίωξη του transactional privacy.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Για να διατηρηθούν το privacy και η security, ο συγχρονισμός των wallets με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node διασφαλίζει μέγιστο privacy. Όλες οι συναλλαγές που έχουν γίνει ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για adversaries να εντοπίσουν ποιες συναλλαγές ή addresses ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία filters για κάθε block στο blockchain, επιτρέποντας στα wallets να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα σε network observers. Τα lightweight wallets κατεβάζουν αυτά τα filters, ανακτώντας πλήρη blocks μόνο όταν βρεθεί match με τις addresses του χρήστη.

## **Utilizing Tor for Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε ένα peer-to-peer network, η χρήση του Tor συνιστάται για να κρύψει το IP address σας, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Preventing Address Reuse**

Για να προστατευτεί το privacy, είναι ζωτικής σημασίας να χρησιμοποιείται μια νέα address για κάθε transaction. Η επαναχρησιμοποίηση addresses μπορεί να θέσει σε κίνδυνο το privacy συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallets αποθαρρύνουν την επαναχρησιμοποίηση addresses μέσω του σχεδιασμού τους.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Η διαίρεση μιας πληρωμής σε several transactions μπορεί να αποκρύψει το transaction amount, ματαιώνοντας privacy attacks.
- **Change avoidance**: Η επιλογή transactions που δεν απαιτούν change outputs ενισχύει το privacy διαταράσσοντας τις change detection methods.
- **Multiple change outputs**: Αν η αποφυγή του change δεν είναι εφικτή, η δημιουργία multiple change outputs μπορεί να βελτιώσει το privacy.

# **Monero: A Beacon of Anonymity**

Το Monero αντιμετωπίζει την ανάγκη για απόλυτο anonymity στις ψηφιακές συναλλαγές, θέτοντας υψηλό standard για το privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum, με τιμολόγηση σε **gwei**. Για παράδειγμα, μια transaction με κόστος 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για να δοθεί κίνητρο στους miners. Οι users μπορούν να ορίσουν ένα max fee ώστε να μην πληρώσουν υπερβολικά, με το επιπλέον ποσό να επιστρέφεται.

## **Executing Transactions**

Οι transactions στο Ethereum περιλαμβάνουν έναν sender και έναν recipient, οι οποίοι μπορεί να είναι είτε user είτε smart contract addresses. Απαιτούν ένα fee και πρέπει να mined. Οι βασικές πληροφορίες σε μια transaction περιλαμβάνουν τον recipient, το sender's signature, το value, προαιρετικό data, gas limit και fees. Αξίζει να σημειωθεί ότι το sender's address προκύπτει από την signature, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα transaction data.

Αυτές οι πρακτικές και μηχανισμοί αποτελούν τη βάση για όποιον θέλει να ασχοληθεί με cryptocurrencies δίνοντας προτεραιότητα στο privacy και το security.

## Value-Centric Web3 Red Teaming

- Inventory τα value-bearing components (signers, oracles, bridges, automation) για να κατανοήσετε ποιος μπορεί να μετακινήσει funds και πώς.
- Χαρτογραφήστε κάθε component στις σχετικές MITRE AADAPT tactics για να αποκαλύψετε privilege escalation paths.
- Εξασκηθείτε σε flash-loan/oracle/credential/cross-chain attack chains για να επαληθεύσετε το impact και να τεκμηριώσετε exploitable preconditions.

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

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να επιβεβαιώσει ένα claim, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως γράφτηκε**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior**, ή **missing semantic constraints**, ένας malicious prover μπορεί να δημιουργήσει ένα proof που επαληθεύεται ενώ τα **public metrics ή το claimed invariant είναι false**.

### Unsafe deserialization inside proof guests

- Αντιμετωπίστε τα private witness/circuit bytes ως **untrusted attacker input** ακόμη κι αν είναι κρυμμένα από το proof.
- Αποφύγετε το deserializing τους με unchecked helpers όπως `rkyv::access_unchecked` εκτός αν τα bytes έχουν ήδη validated out-of-band.
- Enum discriminants, relative pointers, lengths, και indexes που φορτώνονται από untrusted serialized data πρέπει να validated πριν επηρεάσουν control flow ή memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Εάν ένα πεδίο όπως το `op.kind` είναι enum και ένας επιτιθέμενος μπορεί να εισάγει ένα **discriminant εκτός εύρους**, κάθε downstream `match` πάνω σε αυτή την τιμή γίνεται ύποπτο.

### Jump-table / UB counter bypass

Αν το Rust μεταγλωττίσει ένα μεγάλο `match` σε **jump table**, ένα άκυρο enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο pattern είναι:

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί τη **real instruction semantics**.
3. Ένα out-of-range discriminant κάνει index πέρα από την πρώτη jump table και καταλήγει σε code που σχετίζεται με τη δεύτερη.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παραλείπεται. Σε ένα zkVM αυτό μπορεί να forge proofs που αναφέρουν αδύνατες μετρικές, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους falsified bounded resources.

Review checklist:

- Ψάξτε για attacker-controlled enums που deserialized από witness/private input.
- Εξετάστε επαναλαμβανόμενα `match` statements πάνω στο ίδιο opcode/kind field.
- Θεωρήστε τον συνδυασμό `unsafe` + unchecked deserialization + μεγάλο opcode dispatch ως υψηλού κινδύνου.
- Reverse engineer το emitted binary όταν χρειάζεται· το jump-table layout μπορεί να έχει μεγαλύτερη σημασία από το source.

### Missing semantic constraints in reversible/specialized interpreters

Μην περιορίζεστε στην επαλήθευση της memory safety· επαληθεύστε επίσης τους **semantic rules** που το proof προορίζεται να επιβάλει.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι operands που πρέπει να είναι distinct είναι πράγματι constrained ώστε να είναι distinct. Μια Toffoli/CCX-like operation υλοποιημένη ως:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται μη ασφαλές αν το guest δεν απορρίπτει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτήν την περίπτωση η μετάβαση καταρρέει σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, σπάζοντας τις υποθέσεις αναστρεψιμότητας και επιτρέποντας φθηνότερους μη επιδιωκόμενους υπολογισμούς. Σε proof systems που πιστοποιούν τη χρήση πόρων, αυτό μπορεί να επιτρέψει σε attackers να ικανοποιούν functional checks ενώ παρακάμπτουν το cost model που ο verifier πιστεύει ότι επιβάλλεται.

### Τι να δοκιμάσετε σε ZK systems

- Κάντε fuzz όλους τους guest parsers με malformed witness/private-input encodings.
- Επαληθεύστε το enum range validation πριν από το opcode dispatch.
- Προσθέστε semantic checks για operand aliasing και άλλες invalid instruction forms.
- Συγκρίνετε reported/public counters με ένα ανεξάρτητο reference implementation.
- Να θυμάστε ότι ένα valid proof μπορεί ακόμα να αποδεικνύει τη **λάθος δήλωση** αν το guest program είναι buggy.

## DeFi/AMM Exploitation

Αν ερευνάτε πρακτικό exploitation των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που cache virtual balances και μπορούν να poisoned όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

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
