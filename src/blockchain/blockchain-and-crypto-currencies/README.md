# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες συνθήκες, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, με ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελέγξιμο back-end.
- **Tokens & Coins** διαφοροποιούν το πού τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, και τα **Security Tokens** δηλώνουν ιδιοκτησία περιουσιακών στοιχείων.
- **DeFi** σημαίνει Decentralized Finance, προσφέροντας χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- **DEX** και **DAOs** αναφέρονται σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations, αντίστοιχα.

## Consensus Mechanisms

Οι consensus mechanisms διασφαλίζουν ασφαλείς και συμφωνημένες επικυρώσεις συναλλαγών στο blockchain:

- **Proof of Work (PoW)** βασίζεται σε υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν ένα συγκεκριμένο ποσό tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Bitcoin Essentials

### Transactions

Οι Bitcoin transactions περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ addresses. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών signatures, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει transfers.

#### Key Components:

- **Multisignature Transactions** απαιτούν πολλαπλές signatures για να εγκριθεί μια συναλλαγή.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (πληρώνονται στους miners), και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει να βελτιώσει το scalability του Bitcoin επιτρέποντας πολλαπλές transactions μέσα σε ένα channel, δημοσιεύοντας μόνο την τελική κατάσταση στο blockchain.

## Bitcoin Privacy Concerns

Οι privacy attacks, όπως οι **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται patterns συναλλαγών. Στρατηγικές όπως τα **Mixers** και το **CoinJoin** βελτιώνουν την ανωνυμία αποκρύπτοντας τα links συναλλαγών μεταξύ χρηστών.

## Acquiring Bitcoins Anonymously

Οι μέθοδοι περιλαμβάνουν cash trades, mining, και τη χρήση mixers. Το **CoinJoin** αναμειγνύει πολλαπλές transactions για να δυσκολέψει την ιχνηλασιμότητα, ενώ το **PayJoin** μεταμφιέζει τα CoinJoins ως κανονικές συναλλαγές για αυξημένο privacy.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, το privacy των transactions και η ανωνυμία των χρηστών συχνά αποτελούν αντικείμενο ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων μέσω των οποίων attackers μπορούν να παραβιάσουν το privacy του Bitcoin.

## **Common Input Ownership Assumption**

Γενικά είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία μόνο συναλλαγή λόγω της πολυπλοκότητας που απαιτείται. Έτσι, **δύο addresses input στην ίδια συναλλαγή συχνά θεωρείται ότι ανήκουν στον ίδιο owner**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να ξοδευτεί εξ ολοκλήρου σε μια συναλλαγή. Αν μόνο ένα μέρος του σταλεί σε άλλο address, το υπόλοιπο πηγαίνει σε ένα νέο change address. Οι observers μπορούν να υποθέσουν ότι αυτό το νέο address ανήκει στον sender, θέτοντας σε κίνδυνο το privacy.

### Example

Για να μετριαστεί αυτό, υπηρεσίες mixing ή η χρήση πολλαπλών addresses μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές μοιράζονται τα Bitcoin addresses τους online, καθιστώντας το **εύκολο να συνδεθεί το address με τον owner του**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να οπτικοποιηθούν ως graphs, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτό το heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Αν η προσθήκη περισσότερων inputs κάνει το change output μεγαλύτερο από οποιοδήποτε μεμονωμένο input, μπορεί να μπερδέψει το heuristic.

## **Forced Address Reuse**

Οι attackers μπορεί να στείλουν μικρά ποσά σε προηγουμένως χρησιμοποιημένες addresses, ελπίζοντας ότι ο παραλήπτης θα τα συνδυάσει με άλλα inputs σε μελλοντικές transactions, συνδέοντας έτσι τις addresses μεταξύ τους.

### Correct Wallet Behavior

Τα wallets θα πρέπει να αποφεύγουν τη χρήση coins που ελήφθησαν σε ήδη χρησιμοποιημένες, κενές addresses, ώστε να αποτρέπεται αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transactions χωρίς change είναι πιθανό να γίνονται μεταξύ δύο addresses που ανήκουν στον ίδιο user.
- **Round Numbers:** Ένας στρογγυλός αριθμός σε μια transaction υποδηλώνει ότι πρόκειται για payment, με το μη στρογγυλό output πιθανότατα να είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά transaction creation patterns, επιτρέποντας στους analysts να αναγνωρίσουν το software που χρησιμοποιήθηκε και πιθανώς το change address.
- **Amount & Timing Correlations:** Η αποκάλυψη των times ή των amounts των transactions μπορεί να τις κάνει traceable.

## **Traffic Analysis**

Με την παρακολούθηση του network traffic, οι attackers μπορούν δυνητικά να συνδέσουν transactions ή blocks με IP addresses, θέτοντας σε κίνδυνο το user privacy. Αυτό ισχύει ιδιαίτερα αν μια οντότητα λειτουργεί πολλούς Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί transactions.

## More

Για μια ολοκληρωμένη λίστα από privacy attacks και defenses, επισκεφθείτε το [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online για bitcoin.
- **Mining**: Η πιο private μέθοδος για να κερδίσει κανείς bitcoins είναι μέσω mining, ειδικά όταν γίνεται solo, επειδή τα mining pools μπορεί να γνωρίζουν το IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι μια άλλη μέθοδος απόκτησής του anonymously, αν και είναι παράνομη και δεν συνιστάται.

## Mixing Services

Χρησιμοποιώντας ένα mixing service, ένας user μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins σε αντάλλαγμα**, κάτι που καθιστά δύσκολη την ανίχνευση του αρχικού owner. Ωστόσο, αυτό απαιτεί εμπιστοσύνη ότι το service δεν θα κρατήσει logs και ότι πράγματι θα επιστρέψει τα bitcoins. Εναλλακτικές mixing options περιλαμβάνουν Bitcoin casinos.

## CoinJoin

Το **CoinJoin** συνδυάζει multiple transactions από διαφορετικούς users σε μία, περιπλέκοντας τη διαδικασία για οποιονδήποτε προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, transactions με μοναδικά input και output sizes μπορούν ακόμη δυνητικά να εντοπιστούν.

Παραδείγματα transactions που μπορεί να χρησιμοποίησαν CoinJoin περιλαμβάνουν τα `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε το [CoinJoin](https://coinjoin.io/en). Για μια παρόμοια υπηρεσία στο Ethereum, δείτε το [Tornado Cash](https://tornado.cash), το οποίο anonymizes transactions με funds από miners.

## PayJoin

Μια παραλλαγή του CoinJoin, το **PayJoin** (ή P2EP), συγκαλύπτει τη transaction μεταξύ δύο μερών (π.χ. ενός customer και ενός merchant) ως κανονική transaction, χωρίς τα χαρακτηριστικά ίσα outputs που είναι χαρακτηριστικά του CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και θα μπορούσε να ακυρώσει το common-input-ownership heuristic που χρησιμοποιείται από transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Οι συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, ενισχύοντας το privacy ενώ παραμένουν αδιαχώριστες από standard bitcoin transactions.

**Η αξιοποίηση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους surveillance**, καθιστώντας το μια πολλά υποσχόμενη εξέλιξη στην επιδίωξη του transactional privacy.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Για να διατηρηθούν το privacy και η security, ο συγχρονισμός των wallets με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Με τη λήψη ολόκληρου του blockchain, ένα full node εξασφαλίζει μέγιστο privacy. Όλες οι συναλλαγές που έχουν γίνει ποτέ αποθηκεύονται τοπικά, καθιστώντας αδύνατο για adversaries να εντοπίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία filters για κάθε block στο blockchain, επιτρέποντας στα wallets να εντοπίζουν σχετικές συναλλαγές χωρίς να εκθέτουν συγκεκριμένα ενδιαφέροντα σε network observers. Τα lightweight wallets κατεβάζουν αυτά τα filters, ανακτώντας πλήρη blocks μόνο όταν βρεθεί αντιστοιχία με τις διευθύνσεις του χρήστη.

## **Utilizing Tor for Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε ένα peer-to-peer network, συνιστάται η χρήση Tor για να καλύψετε τη διεύθυνση IP σας, ενισχύοντας το privacy κατά την αλληλεπίδραση με το network.

## **Preventing Address Reuse**

Για την προστασία του privacy, είναι ζωτικής σημασίας να χρησιμοποιείται νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το privacy, συνδέοντας συναλλαγές με την ίδια οντότητα. Τα modern wallets αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Η διαίρεση μιας πληρωμής σε πολλές συναλλαγές μπορεί να αποκρύψει το ποσό της συναλλαγής, ματαιώνοντας privacy attacks.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει το privacy διαταράσσοντας τις μεθόδους change detection.
- **Multiple change outputs**: Αν δεν είναι εφικτή η αποφυγή του change, η δημιουργία πολλαπλών change outputs μπορεί παρ' όλα αυτά να βελτιώσει το privacy.

# **Monero: A Beacon of Anonymity**

Το Monero αντιμετωπίζει την ανάγκη για απόλυτη anonymity στις digital transactions, θέτοντας ένα υψηλό standard για το privacy.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση operations στο Ethereum, με τιμολόγηση σε **gwei**. Για παράδειγμα, μια transaction που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για να δοθεί κίνητρο στους miners. Οι users μπορούν να ορίσουν ένα max fee ώστε να μην υπερπληρώσουν, με την περίσσεια να επιστρέφεται.

## **Executing Transactions**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν sender και έναν recipient, που μπορεί να είναι είτε user είτε smart contract addresses. Απαιτούν ένα fee και πρέπει να γίνει mining. Τα βασικά στοιχεία σε μια transaction περιλαμβάνουν τον recipient, την υπογραφή του sender, το value, προαιρετικά data, gas limit και fees. Αξίζει να σημειωθεί ότι η διεύθυνση του sender προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη να περιλαμβάνεται στα δεδομένα της transaction.

Αυτές οι πρακτικές και οι μηχανισμοί αποτελούν θεμέλια για όποιον θέλει να ασχοληθεί με cryptocurrencies δίνοντας προτεραιότητα στο privacy και την security.

## Value-Centric Web3 Red Teaming

- Καταγράψτε τα components που φέρουν value (signers, oracles, bridges, automation) για να κατανοήσετε ποιος μπορεί να μετακινήσει funds και πώς.
- Χαρτογραφήστε κάθε component στις σχετικές MITRE AADAPT tactics για να αποκαλύψετε privilege escalation paths.
- Εξασκηθείτε σε flash-loan/oracle/credential/cross-chain attack chains για να επαληθεύσετε το impact και να τεκμηριώσετε τα εκμεταλλεύσιμα preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Το tampering της supply chain των wallet UIs μπορεί να μεταβάλλει EIP-712 payloads ακριβώς πριν από το signing, συλλέγοντας έγκυρες signatures για delegatecall-based proxy takeovers (π.χ. slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Συνήθεις failure modes σε smart accounts περιλαμβάνουν bypassing του `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay και fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing για τον εντοπισμό blind spots στα test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Όταν ένας prover χρησιμοποιεί ένα **zkVM** ή ένα application-specific proof circuit για να πιστοποιήσει μια claim, ο verifier μαθαίνει μόνο ότι το **guest program εκτελέστηκε όπως γράφτηκε**. Αν το guest περιέχει **unsafe deserialization**, **undefined behavior** ή **missing semantic constraints**, ένας κακόβουλος prover μπορεί να δημιουργήσει μια proof που επαληθεύεται ενώ τα **public metrics ή το claimed invariant είναι ψευδή**.

### Unsafe deserialization inside proof guests

- Αντιμετωπίστε τα private witness/circuit bytes ως **untrusted attacker input** ακόμη κι αν είναι κρυμμένα από την proof.
- Αποφύγετε την αποσειριοποίησή τους με unchecked helpers όπως `rkyv::access_unchecked` εκτός αν τα bytes έχουν ήδη επικυρωθεί out-of-band.
- Enum discriminants, relative pointers, lengths και indexes που φορτώνονται από untrusted serialized data πρέπει να επικυρώνονται πριν επηρεάσουν το control flow ή την πρόσβαση στη μνήμη.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Αν ένα πεδίο όπως το `op.kind` είναι enum και ένας επιτιθέμενος μπορεί να εισαγάγει ένα **discriminant εκτός εύρους**, κάθε downstream `match` σε αυτή την τιμή γίνεται ύποπτο.

### Jump-table / UB counter bypass

Αν το Rust μεταγλωττίσει ένα μεγάλο `match` σε μια **jump table**, ένα άκυρο enum discriminant μπορεί να προκαλέσει **undefined control flow**. Ένα επικίνδυνο pattern είναι:

1. Ένα `match` ενημερώνει **security-critical counters/constraints**.
2. Ένα δεύτερο `match` εκτελεί την **πραγματική semantics της instruction**.
3. Ένα discriminant εκτός εύρους κάνει index πέρα από την πρώτη jump table και καταλήγει σε code που σχετίζεται με τη δεύτερη.

Αποτέλεσμα: η operation εξακολουθεί να εκτελείται, αλλά το accounting path παραλείπεται. Σε ένα zkVM αυτό μπορεί να πλαστογραφήσει proofs που αναφέρουν αδύνατα metrics, όπως λιγότερα gates, λιγότερες expensive operations ή άλλους ψευδείς bounded resources.

Review checklist:

- Αναζητήστε enums που ελέγχονται από attacker και deserialized από witness/private input.
- Ελέγξτε επαναλαμβανόμενα `match` statements πάνω στο ίδιο opcode/kind field.
- Αντιμετωπίστε το `unsafe` + unchecked deserialization + μεγάλο opcode dispatch ως συνδυασμό υψηλού κινδύνου.
- Reverse engineer το emitted binary όταν χρειάζεται· η διάταξη της jump table μπορεί να έχει μεγαλύτερη σημασία από το source.

### Missing semantic constraints in reversible/specialized interpreters

Μην επαληθεύετε μόνο τη memory safety· επαληθεύστε επίσης τους **semantic κανόνες** που υποτίθεται ότι επιβάλλει το proof.

Για reversible/quantum-like instruction sets, βεβαιωθείτε ότι τα operands που πρέπει να είναι distinct είναι πράγματι constrained ώστε να είναι distinct. Μια Toffoli/CCX-like operation implemented ως:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
γίνεται ανασφαλές αν ο guest δεν απορρίψει:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Σε αυτή την περίπτωση, η μετάβαση καταρρέει σε:
```text
q = q ^ (q & q) = 0
```
Αυτό δημιουργεί ένα **deterministic reset primitive**, σπάζοντας τις υποθέσεις αντιστρεψιμότητας και επιτρέποντας φθηνότερους μη-προοριζόμενους υπολογισμούς. Σε proof systems που πιστοποιούν χρήση πόρων, αυτό μπορεί να επιτρέψει σε attackers να ικανοποιούν functional checks ενώ παρακάμπτουν το cost model που ο verifier πιστεύει ότι επιβάλλεται.

### Τι να δοκιμάσεις σε ZK systems

- Fuzz όλα τα guest parsers με malformed witness/private-input encodings.
- Έλεγξε enum range validation πριν από opcode dispatch.
- Πρόσθεσε semantic checks για operand aliasing και άλλες invalid instruction forms.
- Σύγκρινε reported/public counters με ένα ανεξάρτητο reference implementation.
- Θυμήσου ότι ένα valid proof μπορεί ακόμα να αποδείξει τη **λάθος δήλωση** αν το guest program είναι buggy.

## DeFi/AMM Exploitation

Αν ερευνάς πρακτικό exploitation των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δες:

{{#ref}}
defi-amm-hook-precision.md
{{endref}}

Για multi-asset weighted pools που cache virtual balances και μπορούν να poisoned όταν `supply == 0`, μελέτησε:

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
