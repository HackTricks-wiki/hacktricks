# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν ικανοποιούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, διαθέτοντας ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελεγχόμενο back-end.
- **Tokens & Coins** διακρίνουν όπου τα coins λειτουργούν ως ψηφιακά χρήματα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, και **Security Tokens** δηλώνουν ιδιοκτησία περιουσιακού στοιχείου.
- **DeFi** σημαίνει Decentralized Finance και προσφέρει χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- **DEX** και **DAOs** αναφέρονται αντίστοιχα σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations.

## Consensus Mechanisms

Οι μηχανισμοί συναίνεσης διασφαλίζουν ασφαλείς και συμφωνημένες επικυρώσεις συναλλαγών στο blockchain:

- **Proof of Work (PoW)** βασίζεται σε υπολογιστική ισχύ για επαλήθευση συναλλαγών.
- **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν ένα ορισμένο ποσό tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Bitcoin Essentials

### Transactions

Οι συναλλαγές Bitcoin αφορούν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών υπογραφών, διασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.

#### Key Components:

- **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή των κεφαλαίων), **outputs** (προορισμός), **fees** (πληρωτέα στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της επεκτασιμότητας του Bitcoin επιτρέποντας πολλαπλές συναλλαγές εντός ενός channel, μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Bitcoin Privacy Concerns

Επιθέσεις στην ιδιωτικότητα, όπως **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται πρότυπα συναλλαγών. Στρατηγικές όπως **Mixers** και **CoinJoin** βελτιώνουν την ανωνυμία, θολώνοντας τους δεσμούς συναλλαγών μεταξύ χρηστών.

## Acquiring Bitcoins Anonymously

Μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining και χρήση mixers. **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να περιπλέξει την ιχνηλασιμότητα, ενώ **PayJoin** αποκρύπτει CoinJoins ως κανονικές συναλλαγές για αυξημένη ιδιωτικότητα.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, το απόρρητο των συναλλαγών και η ανωνυμία των χρηστών αποτελούν συχνά αντικείμενο ανησυχίας. Ακολουθεί μια απλουστευμένη επισκόπηση αρκετών κοινών μεθόδων με τις οποίες επιτιθέμενοι μπορούν να υπονομεύσουν το απόρρητο του Bitcoin.

## **Common Input Ownership Assumption**

Γενικά είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία συναλλαγή λόγω της πολυπλοκότητας που συνεπάγεται. Επομένως, **δύο input addresses στην ίδια συναλλαγή συχνά υποτίθενται ότι ανήκουν στον ίδιο ιδιοκτήτη**.

## **UTXO Change Address Detection**

Ένα UTXO, ή Unspent Transaction Output, πρέπει να δαπανηθεί ολόκληρο σε μια συναλλαγή. Αν μόνο ένα μέρος του αποσταλεί σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα change address. Παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον sender, υπονομεύοντας το απόρρητο.

### Example

Για να μετριαστεί αυτό, υπηρεσίες mixing ή η χρήση πολλαπλών διευθύνσεων μπορεί να βοηθήσει να θολωθεί η ιδιοκτησία.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές κοινοποιούν τις Bitcoin διευθύνσεις τους online, καθιστώντας εύκολο να συνδεθεί η διεύθυνση με τον ιδιοκτήτη.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να οπτικοποιηθούν ως γράφοι, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή των κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτός ο κανόνας βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον αποστολέα.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Εάν η προσθήκη περισσότερων εισροών κάνει την έξοδο αλλαγής μεγαλύτερη από οποιαδήποτε μεμονωμένη εισροή, αυτό μπορεί να μπερδέψει την ευρετική.

## **Forced Address Reuse**

Οι επιτιθέμενοι μπορεί να στείλουν μικρά ποσά σε προηγουμένως χρησιμοποιημένες διευθύνσεις, ελπίζοντας ότι ο παραλήπτης θα τα συνδυάσει με άλλες εισροές σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Σωστή Συμπεριφορά Πορτοφολιού

Τα πορτοφόλια πρέπει να αποφεύγουν τη χρήση νομισμάτων που ελήφθησαν σε ήδη χρησιμοποιημένες, κενές διευθύνσεις για να αποτρέψουν αυτή τη privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Συναλλαγές χωρίς αλλαγή είναι πιθανό να γίνονται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Round Numbers:** Ένας στρογγυλός αριθμός σε μια συναλλαγή υποδηλώνει ότι είναι πληρωμή, με την μη στρογγυλή έξοδο να είναι πιθανότατα η αλλαγή.
- **Wallet Fingerprinting:** Διαφορετικά πορτοφόλια έχουν μοναδικά μοτίβα δημιουργίας συναλλαγών, επιτρέποντας στους αναλυτές να προσδιορίσουν το χρησιμοποιούμενο λογισμικό και πιθανώς τη διεύθυνση αλλαγής.
- **Amount & Timing Correlations:** Η αποκάλυψη χρόνων ή ποσών συναλλαγών μπορεί να κάνει τις συναλλαγές ανιχνεύσιμες.

## **Traffic Analysis**

Παρακολουθώντας την κίνηση δικτύου, οι επιτιθέμενοι μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με διευθύνσεις IP, υπονομεύοντας το απόρρητο των χρηστών. Αυτό ισχύει ιδιαίτερα αν ένας φορέας λειτουργεί πολλούς Bitcoin nodes, αυξάνοντας την ικανότητά του να παρακολουθεί συναλλαγές.

## Περισσότερα

Για μια ολοκληρωμένη λίστα με επιθέσεις και άμυνες για την ιδιωτικότητα, επισκεφθείτε [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Ανώνυμες Συναλλαγές Bitcoin

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin με μετρητά.
- **Cash Alternatives**: Αγορά δωροκάρτων και ανταλλαγή τους online για bitcoin.
- **Mining**: Ο πιο ιδιωτικός τρόπος για να κερδίσει κάποιος bitcoins είναι μέσω mining, ιδιαίτερα όταν γίνεται μόνος, διότι τα mining pools μπορεί να γνωρίζουν τη διεύθυνση IP του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι ένας άλλος τρόπος απόκτησης ανώνυμα, αλλά είναι παράνομο και δεν συνιστάται.

## Mixing Services

Χρησιμοποιώντας μια υπηρεσία mixing, ένας χρήστης μπορεί να **send bitcoins** και να λάβει **different bitcoins in return**, γεγονός που δυσκολεύει τον εντοπισμό του αρχικού ιδιοκτήτη. Ωστόσο, αυτό απαιτεί εμπιστοσύνη στην υπηρεσία να μην κρατήσει logs και να επιστρέψει πραγματικά τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το CoinJoin συγχωνεύει πολλαπλές συναλλαγές από διαφορετικούς χρήστες σε μία, δυσκολεύοντας την αντιστοίχιση inputs με outputs. Παρά την αποτελεσματικότητά του, συναλλαγές με μοναδικά μεγέθη εισροών και εκροών μπορούν ακόμη να εντοπιστούν.

Παραδείγματα συναλλαγών που ενδέχεται να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τις `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Για περισσότερες πληροφορίες, επισκεφθείτε [CoinJoin](https://coinjoin.io/en). Για μια παρόμοια υπηρεσία στο Ethereum, δείτε [Tornado Cash](https://tornado.cash), που ανωνυμοποιεί συναλλαγές με κεφάλαια από miners.

## PayJoin

Μια παραλλαγή του CoinJoin, η **PayJoin** (ή P2EP), συγκαλύπτει τη συναλλαγή ανάμεσα σε δύο μέρη (π.χ. έναν πελάτη και έναν έμπορο) ως κανονική συναλλαγή, χωρίς τα χαρακτηριστικά ίσα outputs του CoinJoin. Αυτό την καθιστά εξαιρετικά δύσκολη στην ανίχνευση και μπορεί να ακυρώσει την ευρετική common-input-ownership που χρησιμοποιούν οι οντότητες παρακολούθησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω μπορεί να είναι PayJoin, ενισχύοντας το απόρρητο ενώ παραμένουν αδιάκριτες από τις τυπικές bitcoin συναλλαγές.

**Η χρήση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους επιτήρησης**, καθιστώντας το μια πολλά υποσχόμενη εξέλιξη στην επιδίωξη του απορρήτου στις συναλλαγές.

# Βέλτιστες Πρακτικές για το Απόρρητο στα Κρυπτονομίσματα

## **Wallet Synchronization Techniques**

Για να διατηρηθεί το απόρρητο και η ασφάλεια, ο συγχρονισμός των πορτοφολιών με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Κατεβάζοντας ολόκληρο το blockchain, ένα Full node εξασφαλίζει το μέγιστο απόρρητο. Όλες οι συναλλαγές που έχουν γίνει αποθηκεύονται τοπικά, καθιστώντας αδύνατο για αντιπάλους να αναγνωρίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα πορτοφόλια να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα σε παρατηρητές του δικτύου. Τα lightweight wallets κατεβάζουν αυτά τα φίλτρα, ανακτώντας πλήρη blocks μόνο όταν υπάρξει ταύτιση με τις διευθύνσεις του χρήστη.

## **Utilizing Tor for Anonymity**

Δεδομένου ότι το Bitcoin λειτουργεί σε ένα peer-to-peer δίκτυο, συνιστάται η χρήση Tor για να καλυφθεί η διεύθυνση IP σας, ενισχύοντας το απόρρητο κατά την αλληλεπίδραση με το δίκτυο.

## **Preventing Address Reuse**

Για να προστατευθεί το απόρρητο, είναι ζωτικής σημασίας να χρησιμοποιείτε μια νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να θέσει σε κίνδυνο το απόρρητο συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα πορτοφόλια αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Η διάσπαση μιας πληρωμής σε πολλές συναλλαγές μπορεί να συγκαλύψει το ποσό της συναλλαγής, αποτρέποντας επιθέσεις κατά του απορρήτου.
- **Change avoidance**: Επιλέγοντας συναλλαγές που δεν απαιτούν change outputs ενισχύεται το απόρρητο διαταράσσοντας τις μεθόδους ανίχνευσης αλλαγής.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλαπλών change outputs μπορεί ακόμη να βελτιώσει το απόρρητο.

# **Monero: A Beacon of Anonymity**

Monero καλύπτει την ανάγκη για απόλυτη ανωνυμία στις ψηφιακές συναλλαγές, θέτοντας υψηλό πρότυπο για το απόρρητο.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Το Gas μετράει την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση λειτουργιών στο Ethereum, τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για να κινητροδοτηθούν οι miners. Οι χρήστες μπορούν να ορίσουν ένα max fee για να εξασφαλίσουν ότι δεν θα πληρώσουν υπερβολικά, με το πλεόνασμα να επιστρέφεται.

## **Executing Transactions**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, οι οποίοι μπορούν να είναι είτε διευθύνσεις χρήστη είτε smart contract διευθύνσεις. Απαιτούν μια αμοιβή και πρέπει να εξορυχθούν. Βασικές πληροφορίες σε μια συναλλαγή περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά δεδομένα, gas limit και τέλη. Σημειωτέον, η διεύθυνση του αποστολέα προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη για την παρουσία της στα δεδομένα της συναλλαγής.

Αυτές οι πρακτικές και μηχανισμοί είναι θεμελιώδεις για οποιονδήποτε θέλει να εμπλακεί με κρυπτονομίσματα ενώ δίνει προτεραιότητα στο απόρρητο και την ασφάλεια.

## Value-Centric Web3 Red Teaming

- Κατάλογος των components που φέρουν αξία (signers, oracles, bridges, automation) για να κατανοήσετε ποιος μπορεί να μετακινήσει κεφάλαια και πώς.
- Χαρτογράφησε κάθε component σε σχετικά MITRE AADAPT tactics για να αποκαλύψεις μονοπάτια eskalation προνομίων.
- Εξασκηθείτε σε αλυσίδες επιθέσεων flash-loan/oracle/credential/cross-chain για να επαληθεύσετε τον αντίκτυπο και να τεκμηριώσετε τις εκμεταλλεύσιμες προϋποθέσεις.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering του wallet UI μπορεί να μεταβάλει EIP-712 payloads ακριβώς πριν από την υπογραφή, συλλέγοντας έγκυρες υπογραφές για delegatecall-based proxy takeovers (π.χ., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Κοινές failure modes σε smart-accounts περιλαμβάνουν παράκαμψη access control του `EntryPoint`, unsigned gas fields, stateful validation, ERC-1271 replay, και fee-drain μέσω revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing για να βρείτε τυφλά σημεία στις test suites:

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

Εάν ερευνάτε πρακτική εκμετάλλευση των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που cacheάρουν virtual balances και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
