# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς μεσάζοντες.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, με φιλικό προς τον χρήστη front-end και έναν διαφανή, ελεγχόμενο back-end.
- **Tokens & Coins** διαχωρίζονται ως προς τη χρήση: τα coins χρησιμεύουν ως ψηφιακό χρήμα, ενώ τα tokens αναπαριστούν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, και τα **Security Tokens** υποδηλώνουν ιδιοκτησία περιουσιακού στοιχείου.
- **DeFi** σημαίνει Decentralized Finance, προσφέροντας χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- **DEX** και **DAOs** αναφέρονται σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations, αντίστοιχα.

## Consensus Mechanisms

Οι μηχανισμοί συναίνεσης εξασφαλίζουν ασφαλή και συμφωνημένο validation των συναλλαγών στο blockchain:

- **Proof of Work (PoW)** βασίζεται σε υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν ένα συγκεκριμένο ποσό tokens, μειώνοντας την κατανάλωση ενέργειας σε σύγκριση με το PoW.

## Bitcoin Essentials

### Transactions

Οι συναλλαγές Bitcoin περιλαμβάνουν μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών υπογραφών, εξασφαλίζοντας ότι μόνο ο κάτοχος του private key μπορεί να ξεκινήσει μεταφορές.

#### Key Components:

- **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (πληρωτέα στους miners), και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Στοχεύει στη βελτίωση της scalability του Bitcoin επιτρέποντας πολλαπλές συναλλαγές εντός ενός channel, δημοσιοποιώντας μόνο την τελική κατάσταση στο blockchain.

## Bitcoin Privacy Concerns

Επιθέσεις στην ιδιωτικότητα, όπως **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται τα μοτίβα των συναλλαγών. Στρατηγικές όπως **Mixers** και **CoinJoin** βελτιώνουν την ανωνυμία θολώνοντας τους συνδέσμους συναλλαγών μεταξύ χρηστών.

## Acquiring Bitcoins Anonymously

Μέθοδοι περιλαμβάνουν συναλλαγές με μετρητά, mining, και χρήση mixers. **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να δυσχεράνει την ανιχνευσιμότητα, ενώ **PayJoin** συγκαλύπτει CoinJoins ως κανονικές συναλλαγές για αυξημένη ιδιωτικότητα.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

Στον κόσμο του Bitcoin, η ιδιωτικότητα των συναλλαγών και η ανωνυμία των χρηστών συχνά αποτελούν αντικείμενο ανησυχίας. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων με τις οποίες οι επιτιθέμενοι μπορούν να υπονομεύσουν την ιδιωτικότητα του Bitcoin.

## **Common Input Ownership Assumption**

Συνήθως είναι σπάνιο inputs από διαφορετικούς χρήστες να συνδυάζονται σε μια ενιαία συναλλαγή λόγω της πολυπλοκότητας που αυτό συνεπάγεται. Επομένως, **δύο input διευθύνσεις στην ίδια συναλλαγή συχνά θεωρούνται ότι ανήκουν στον ίδιο ιδιοκτήτη**.

## **UTXO Change Address Detection**

UTXO, ή **Unspent Transaction Output**, πρέπει να δαπανηθεί ολόκληρο σε μια συναλλαγή. Αν μόνο μέρος του σταλεί σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα change address. Παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, υπονομεύοντας την ιδιωτικότητα.

### Example

Για να μετριαστεί αυτό, υπηρεσίες mixing ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στη θόλωση της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Χρήστες μερικές φορές μοιράζονται τις Bitcoin διευθύνσεις τους online, καθιστώντας εύκολο το **σύνδεσμο της διεύθυνσης με τον κάτοχό της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να απεικονιστούν ως γράφοι, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών βάσει της ροής κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτή η ευριστική βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον αποστολέα.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Εξαναγκασμένη Επαναχρησιμοποίηση Διεύθυνσης**

Οι επιτιθέμενοι μπορεί να στέλνουν μικρά ποσά σε διευθύνσεις που έχουν χρησιμοποιηθεί προηγουμένως, ελπίζοντας ότι ο παραλήπτης θα τα συνδυάσει με άλλα inputs σε μελλοντικές συναλλαγές, συνδέοντας έτσι τις διευθύνσεις μεταξύ τους.

### Σωστή Συμπεριφορά Πορτοφολιού

Τα πορτοφόλια θα πρέπει να αποφεύγουν τη χρήση νομισμάτων που λήφθηκαν σε ήδη χρησιμοποιημένες, κενές διευθύνσεις για να αποτρέψουν αυτό το privacy leak.

## **Άλλες Τεχνικές Ανάλυσης Blockchain**

- **Exact Payment Amounts:** Οι συναλλαγές χωρίς change είναι πιθανό να γίνονται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Round Numbers:** Ένας στρογγυλός αριθμός σε μια συναλλαγή υποδηλώνει ότι είναι πληρωμή, με το μη στρογγυλό output να είναι πιθανότατα το change.
- **Wallet Fingerprinting:** Διαφορετικά πορτοφόλια έχουν μοναδικά πρότυπα δημιουργίας συναλλαγών, επιτρέποντας σε αναλυτές να αναγνωρίσουν το χρησιμοποιούμενο λογισμικό και ενδεχομένως τη change address.
- **Amount & Timing Correlations:** Η αποκάλυψη των χρόνων ή των ποσοτήτων συναλλαγών μπορεί να κάνει τις συναλλαγές ιχνηλάσιμες.

## **Ανάλυση Κυκλοφορίας**

Με την παρακολούθηση της δικτυακής κίνησης, οι επιτιθέμενοι μπορούν ενδεχομένως να συνδέσουν συναλλαγές ή blocks με IP διευθύνσεις, υπονομεύοντας το απόρρητο των χρηστών. Αυτό ισχύει ιδιαίτερα εάν μια οντότητα λειτουργεί πολλούς Bitcoin nodes, ενισχύοντας την ικανότητά της να παρακολουθεί συναλλαγές.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Ανώνυμες Συναλλαγές Bitcoin

## Τρόποι Απόκτησης Bitcoins Ανώνυμα

- **Cash Transactions**: Απόκτηση bitcoin μέσω μετρητών.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online για bitcoin.
- **Mining**: Η πιο ιδιωτική μέθοδος για να κερδίσετε bitcoins είναι το mining, ειδικά όταν γίνεται solo, γιατί τα mining pools μπορεί να γνωρίζουν την IP διεύθυνση του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι ένας άλλος τρόπος απόκτησής τους ανώνυμα, αν και είναι παράνομο και δεν συνιστάται.

## Mixing Services

Με τη χρήση μιας mixing service, ένας χρήστης μπορεί να **στείλει bitcoins** και να λάβει **διαφορετικά bitcoins σε αντάλλαγμα**, κάνοντας δύσκολη την ανίχνευση του αρχικού ιδιοκτήτη. Ωστόσο, αυτό απαιτεί εμπιστοσύνη στην υπηρεσία ότι δεν θα κρατήσει logs και ότι θα επιστρέψει πραγματικά τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το CoinJoin συγχωνεύει πολλαπλές συναλλαγές από διαφορετικούς χρήστες σε μία, περιπλέκοντας τη διαδικασία για όποιον προσπαθεί να αντιστοιχίσει inputs με outputs. Παρ’ όλο που είναι αποτελεσματικό, συναλλαγές με μοναδικά μεγέθη εισόδων και εξόδων μπορούν ακόμα ενδεχομένως να ανιχνευθούν.

Παραδείγματα συναλλαγών που μπορεί να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν τις `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), masks the transaction between two parties (π.χ. πελάτης και έμπορος) ως μια κανονική συναλλαγή, χωρίς τα ξεχωριστά ίσα outputs που χαρακτηρίζουν το CoinJoin. Αυτό το καθιστά εξαιρετικά δύσκολο να εντοπιστεί και μπορεί να ακυρώσει την common-input-ownership heuristic που χρησιμοποιούν οι οντότητες επιτήρησης συναλλαγών.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Οι συναλλαγές όπως η παραπάνω θα μπορούσαν να είναι PayJoin, βελτιώνοντας την ιδιωτικότητα ενώ παραμένουν αδιάκριτες από τις τυπικές bitcoin συναλλαγές.

**Η χρήση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους παρακολούθησης**, καθιστώντας το μια υποσχόμενη εξέλιξη στην επιδίωξη της ιδιωτικότητας των συναλλαγών.

# Καλές Πρακτικές για Ιδιωτικότητα στα Κρυπτονομίσματα

## **Wallet Synchronization Techniques**

Για να διατηρηθεί η ιδιωτικότητα και η ασφάλεια, η συγχρονισμός των wallets με το blockchain είναι κρίσιμη. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Με το να κατεβάζει ολόκληρο το blockchain, ένα full node εξασφαλίζει μέγιστη ιδιωτικότητα. Όλες οι συναλλαγές που έγιναν αποθηκεύονται τοπικά, καθιστώντας αδύνατο για τους αντιπάλους να προσδιορίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε block στο blockchain, επιτρέποντας στα wallets να εντοπίζουν σχετικές συναλλαγές χωρίς να εκθέτουν συγκεκριμένα ενδιαφέροντα σε παρατηρητές του δικτύου. Lightweight wallets κατεβάζουν αυτά τα φίλτρα, ανακτώντας πλήρη blocks μόνο όταν υπάρχει ταύτιση με τις διευθύνσεις του χρήστη.

## **Χρήση Tor για Ανωνυμία**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer δίκτυο, συνιστάται η χρήση Tor για την απόκρυψη της IP διεύθυνσής σας, ενισχύοντας την ιδιωτικότητα κατά την αλληλεπίδραση με το δίκτυο.

## **Αποφυγή Επαναχρησιμοποίησης Διευθύνσεων**

Για την προστασία της ιδιωτικότητας, είναι ζωτικής σημασίας να χρησιμοποιείται μια νέα διεύθυνση για κάθε συναλλαγή. Η επαναχρησιμοποίηση διευθύνσεων μπορεί να υπονομεύσει την ιδιωτικότητα συνδέοντας συναλλαγές με την ίδια οντότητα. Τα σύγχρονα wallets αποθαρρύνουν την επαναχρησιμοποίηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για Ιδιωτικότητα Συναλλαγών**

- **Multiple transactions**: Διάσπαση μιας πληρωμής σε πολλές συναλλαγές μπορεί να συγκαλύψει το ποσό της συναλλαγής, ματαιώνοντας επιθέσεις που στοχεύουν την ιδιωτικότητα.
- **Change avoidance**: Επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει την ιδιωτικότητα διαταράσσοντας τις μεθόδους ανίχνευσης change.
- **Multiple change outputs**: Αν η αποφυγή change δεν είναι εφικτή, η δημιουργία πολλαπλών change outputs μπορεί να βελτιώσει την ιδιωτικότητα.

# **Monero: Φάρος Ανωνυμίας**

Monero καλύπτει την ανάγκη για απόλυτη ανωνυμία στις ψηφιακές συναλλαγές, θέτοντας υψηλά στάνταρ ιδιωτικότητας.

# **Ethereum: Gas και Συναλλαγές**

## **Κατανόηση του Gas**

Gas μετράει τον υπολογιστικό κόπο που απαιτείται για την εκτέλεση λειτουργιών στο Ethereum, τιμολογούμενο σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για την παρότρυνση των miners. Οι χρήστες μπορούν να ορίσουν ένα max fee για να διασφαλίσουν ότι δεν θα πληρώσουν παραπάνω, με την πλεονάζουσα διαφορά να επιστρέφεται.

## **Εκτέλεση Συναλλαγών**

Συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, που μπορεί να είναι είτε διευθύνσεις χρηστών είτε smart contract. Απαιτούν μια αμοιβή και πρέπει να γίνουν mined. Βασικές πληροφορίες σε μια συναλλαγή περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά δεδομένα, gas limit και τέλη. Σημειωτέον, η διεύθυνση του αποστολέα προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη για την συμπερίληψή της στα δεδομένα της συναλλαγής.

Αυτές οι πρακτικές και μηχανισμοί είναι θεμελιώδεις για όποιον επιθυμεί να ασχοληθεί με κρυπτονομίσματα δίνοντας προτεραιότητα στην ιδιωτικότητα και την ασφάλεια.

## Value-Centric Web3 Red Teaming

- Κάντε inventory των value-bearing components (signers, oracles, bridges, automation) για να κατανοήσετε ποιος μπορεί να μετακινήσει funds και με ποιον τρόπο.
- Χαρτογραφήστε κάθε component σε σχετικά MITRE AADAPT tactics για να αποκαλύψετε μονοπάτια privilege escalation.
- Επαναλάβετε flash-loan/oracle/credential/cross-chain attack chains για να επικυρώσετε τον αντίκτυπο και να τεκμηριώσετε εκμεταλλεύσιμες προϋποθέσεις.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs μπορεί να μεταμορφώσει EIP-712 payloads ακριβώς πριν το signing, συλλέγοντας έγκυρες υπογραφές για delegatecall-based proxy takeovers (π.χ., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing για να βρεθούν blind spots σε test suites:

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

Αν ερευνάτε πρακτική εκμετάλλευση DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Για multi-asset weighted pools που κάνουν cache virtual balances και μπορούν να δηλητηριαστούν όταν `supply == 0`, μελετήστε:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
