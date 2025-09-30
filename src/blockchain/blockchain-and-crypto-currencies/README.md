# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Έννοιες

- **Smart Contracts** ορίζονται ως προγράμματα που εκτελούνται σε ένα blockchain όταν πληρούνται ορισμένες προϋποθέσεις, αυτοματοποιώντας την εκτέλεση συμφωνιών χωρίς ενδιάμεσους.
- **Decentralized Applications (dApps)** βασίζονται σε smart contracts, διαθέτοντας ένα φιλικό προς τον χρήστη front-end και ένα διαφανές, ελεγχόμενο back-end.
- **Tokens & Coins** διαφοροποιούνται, όπου τα coins λειτουργούν ως ψηφιακό χρήμα, ενώ τα tokens αντιπροσωπεύουν αξία ή ιδιοκτησία σε συγκεκριμένα πλαίσια.
- **Utility Tokens** παρέχουν πρόσβαση σε υπηρεσίες, και **Security Tokens** δηλώνουν ιδιοκτησία σε περιουσιακό στοιχείο.
- **DeFi** σημαίνει Decentralized Finance, προσφέροντας χρηματοοικονομικές υπηρεσίες χωρίς κεντρικές αρχές.
- **DEX** και **DAOs** αναφέρονται σε Decentralized Exchange Platforms και Decentralized Autonomous Organizations, αντίστοιχα.

## Μηχανισμοί Συμφωνίας

Οι μηχανισμοί συμφωνίας εξασφαλίζουν την ασφαλή και συμφωνημένη επικύρωση συναλλαγών στο blockchain:

- **Proof of Work (PoW)** βασίζεται στην υπολογιστική ισχύ για την επαλήθευση συναλλαγών.
- **Proof of Stake (PoS)** απαιτεί από τους validators να κατέχουν ένα συγκεκριμένο ποσό tokens, μειώνοντας την κατανάλωση ενέργειας σε σχέση με το PoW.

## Βασικά Στοιχεία του Bitcoin

### Συναλλαγές

Οι συναλλαγές Bitcoin περιλαμβάνουν τη μεταφορά κεφαλαίων μεταξύ διευθύνσεων. Οι συναλλαγές επικυρώνονται μέσω ψηφιακών υπογραφών, διασφαλίζοντας ότι μόνο ο κάτοχος του ιδιωτικού κλειδιού μπορεί να ξεκινήσει μεταφορές.

#### Κύρια Συστατικά:

- **Multisignature Transactions** απαιτούν πολλαπλές υπογραφές για την εξουσιοδότηση μιας συναλλαγής.
- Οι συναλλαγές αποτελούνται από **inputs** (πηγή κεφαλαίων), **outputs** (προορισμός), **fees** (καταβάλλονται στους miners) και **scripts** (κανόνες συναλλαγής).

### Lightning Network

Σκοπός του είναι να βελτιώσει την κλιμάκωση του Bitcoin επιτρέποντας πολλαπλές συναλλαγές μέσα σε ένα κανάλι, μεταδίδοντας στο blockchain μόνο την τελική κατάσταση.

## Προβλήματα Ιδιωτικότητας στο Bitcoin

Επιθέσεις στην ιδιωτικότητα, όπως **Common Input Ownership** και **UTXO Change Address Detection**, εκμεταλλεύονται πρότυπα συναλλαγών. Στρατηγικές όπως **Mixers** και **CoinJoin** βελτιώνουν την ανωνυμία καλύπτοντας τους δεσμούς συναλλαγών μεταξύ χρηστών.

## Απόκτηση Bitcoins Ανώνυμα

Μέθοδοι περιλαμβάνουν ανταλλαγές με μετρητά, mining και χρήση mixers. **CoinJoin** αναμειγνύει πολλαπλές συναλλαγές για να περιπλέξει την ανιχνευσιμότητα, ενώ **PayJoin** εξαντλεί CoinJoins ως κανονικές συναλλαγές για αυξημένη ιδιωτικότητα.

# Bitcoin Privacy Atacks

# Περίληψη των Επιθέσεων στην Ιδιωτικότητα του Bitcoin

Στον κόσμο του Bitcoin, η ιδιωτικότητα των συναλλαγών και η ανωνυμία των χρηστών συχνά απασχολούν. Ακολουθεί μια απλοποιημένη επισκόπηση αρκετών κοινών μεθόδων με τις οποίες οι επιτιθέμενοι μπορούν να υπονομεύσουν την ιδιωτικότητα του Bitcoin.

## **Common Input Ownership Assumption**

Είναι γενικά σπάνιο τα inputs από διαφορετικούς χρήστες να συνδυάζονται σε μία συναλλαγή λόγω της πολυπλοκότητας που εμπλέκεται. Έτσι, **δύο input διευθύνσεις στην ίδια συναλλαγή συχνά υποτίθεται ότι ανήκουν στον ίδιο κάτοχο**.

## **UTXO Change Address Detection**

Ένα UTXO, ή **Unspent Transaction Output**, πρέπει να ξοδευτεί ολόκληρο σε μια συναλλαγή. Αν μόνο ένα μέρος του αποστέλλεται σε άλλη διεύθυνση, το υπόλοιπο πηγαίνει σε μια νέα change address. Οι παρατηρητές μπορούν να υποθέσουν ότι αυτή η νέα διεύθυνση ανήκει στον αποστολέα, υπονομεύοντας την ιδιωτικότητα.

### Παράδειγμα

Για να μετριαστεί αυτό, υπηρεσίες mixing ή η χρήση πολλαπλών διευθύνσεων μπορούν να βοηθήσουν στην απόκρυψη της ιδιοκτησίας.

## **Social Networks & Forums Exposure**

Οι χρήστες μερικές φορές μοιράζονται τις Bitcoin διευθύνσεις τους online, καθιστώντας **εύκολο να συνδεθεί η διεύθυνση με τον κάτοχό της**.

## **Transaction Graph Analysis**

Οι συναλλαγές μπορούν να απεικονιστούν ως γράφοι, αποκαλύπτοντας πιθανές συνδέσεις μεταξύ χρηστών με βάση τη ροή κεφαλαίων.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Αυτός ο heuristic βασίζεται στην ανάλυση συναλλαγών με πολλαπλά inputs και outputs για να μαντέψει ποιο output είναι το change που επιστρέφει στον αποστολέα.

### Παράδειγμα
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

Τα πορτοφόλια πρέπει να αποφεύγουν τη χρήση coins που έχουν ληφθεί σε ήδη χρησιμοποιημένες, άδειες διευθύνσεις, για να αποτρέπουν αυτό το privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Οι transactions χωρίς change είναι πιθανό να γίνονται μεταξύ δύο διευθύνσεων που ανήκουν στον ίδιο χρήστη.
- **Round Numbers:** Ένας round αριθμός σε μια transaction υποδηλώνει ότι είναι μια πληρωμή, με το μη-round output πιθανότατα να είναι το change.
- **Wallet Fingerprinting:** Διαφορετικά wallets έχουν μοναδικά μοτίβα δημιουργίας transactions, επιτρέποντας σε analysts να αναγνωρίσουν το χρησιμοποιούμενο software και πιθανώς τη change address.
- **Amount & Timing Correlations:** Η αποκάλυψη των χρόνων ή των ποσών των transactions μπορεί να κάνει τις transactions ιχνηλάσιμες.

## **Traffic Analysis**

Παρακολουθώντας το network traffic, attackers μπορούν ενδεχομένως να συνδέσουν transactions ή blocks με IP addresses, υπονομεύοντας την ιδιωτικότητα του χρήστη. Αυτό ισχύει ιδιαίτερα αν ένας φορέας λειτουργεί πολλούς Bitcoin nodes, βελτιώνοντας την ικανότητά του να παρακολουθεί transactions.

## More

Για μια ολοκληρωμένη λίστα επιθέσεων και αμυνών για την ιδιωτικότητα, επισκεφθείτε [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Απόκτηση bitcoin με μετρητά.
- **Cash Alternatives**: Αγορά gift cards και ανταλλαγή τους online για bitcoin.
- **Mining**: Η πιο ιδιωτική μέθοδος απόκτησης bitcoins είναι μέσω mining, ειδικά όταν γίνεται solo, επειδή τα mining pools μπορεί να γνωρίζουν το IP address του miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Θεωρητικά, η κλοπή bitcoin θα μπορούσε να είναι άλλη μια μέθοδος για να τα αποκτήσει κανείς ανώνυμα, αν και είναι παράνομη και δεν συστήνεται.

## Mixing Services

Χρησιμοποιώντας ένα mixing service, ένας χρήστης μπορεί **send bitcoins** και να λάβει **different bitcoins in return**, κάτι που δυσκολεύει την ανίχνευση του αρχικού ιδιοκτήτη. Ωστόσο, αυτό απαιτεί εμπιστοσύνη στην υπηρεσία να μην κρατά logs και να επιστρέψει όντως τα bitcoins. Εναλλακτικές επιλογές mixing περιλαμβάνουν τα Bitcoin casinos.

## CoinJoin

Το CoinJoin συγχωνεύει πολλαπλές transactions από διαφορετικούς users σε μία, δυσκολεύοντας τη διαδικασία για οποιονδήποτε προσπαθεί να αντιστοιχίσει inputs με outputs. Παρά την αποτελεσματικότητά του, transactions με μοναδικά μεγέθη inputs και outputs μπορούν ακόμη να ιχνηλατηθούν.

Παραδείγματα transactions που μπορεί να έχουν χρησιμοποιήσει CoinJoin περιλαμβάνουν `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` και `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disguises the transaction among two parties (e.g., a customer and a merchant) as a regular transaction, without the distinctive equal outputs characteristic of CoinJoin. This makes it extremely hard to detect and could invalidate the common-input-ownership heuristic used by transaction surveillance entities.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Συναλλαγές όπως η παραπάνω μπορεί να είναι PayJoin, ενισχύοντας την ιδιωτικότητα ενώ παραμένουν αδιαχώριστες από standard bitcoin συναλλαγές.

**Η χρήση του PayJoin θα μπορούσε να διαταράξει σημαντικά τις παραδοσιακές μεθόδους επιτήρησης**, καθιστώντας το μια ελπιδοφόρα εξέλιξη για την επιδίωξη της ιδιωτικότητας στις συναλλαγές.

# Καλύτερες Πρακτικές για την Ιδιωτικότητα στα Κρυπτονομίσματα

## **Τεχνικές Συγχρονισμού Πορτοφολιών**

Για τη διατήρηση της ιδιωτικότητας και της ασφάλειας, ο συγχρονισμός των πορτοφολιών με το blockchain είναι κρίσιμος. Δύο μέθοδοι ξεχωρίζουν:

- **Full node**: Κατεβάζοντας ολόκληρο το blockchain, ένα Full node διασφαλίζει μέγιστη ιδιωτικότητα. Όλες οι συναλλαγές που έχουν γίνει αποθηκεύονται τοπικά, καθιστώντας αδύνατο για αντιπάλους να προσδιορίσουν ποιες συναλλαγές ή διευθύνσεις ενδιαφέρουν τον χρήστη.
- **Client-side block filtering**: Αυτή η μέθοδος περιλαμβάνει τη δημιουργία φίλτρων για κάθε μπλοκ στο blockchain, επιτρέποντας στα πορτοφόλια να εντοπίζουν σχετικές συναλλαγές χωρίς να αποκαλύπτουν συγκεκριμένα ενδιαφέροντα σε παρατηρητές του δικτύου. Τα lightweight wallets κατεβάζουν αυτά τα φίλτρα, ανακτώντας πλήρη μπλοκ μόνο όταν βρεθεί ταύτιση με τις διευθύνσεις του χρήστη.

## **Χρήση του Tor για Ανωνυμία**

Δεδομένου ότι το Bitcoin λειτουργεί σε peer-to-peer δίκτυο, συνιστάται η χρήση του Tor για απόκρυψη της διεύθυνσης IP, βελτιώνοντας την ιδιωτικότητα κατά την αλληλεπίδραση με το δίκτυο.

## **Αποφυγή Επανάχρησης Διευθύνσεων**

Για την προστασία της ιδιωτικότητας, είναι ζωτικής σημασίας να χρησιμοποιείται μια νέα διεύθυνση για κάθε συναλλαγή. Η επανάχρηση διευθύνσεων μπορεί να θέσει σε κίνδυνο την ιδιωτικότητα συνδέοντας συναλλαγές με το ίδιο πρόσωπο. Τα σύγχρονα πορτοφόλια αποθαρρύνουν την επανάχρηση διευθύνσεων μέσω του σχεδιασμού τους.

## **Στρατηγικές για την Ιδιωτικότητα Συναλλαγών**

- **Multiple transactions**: Η διάσπαση μιας πληρωμής σε πολλές συναλλαγές μπορεί να συγκαλύψει το ποσό της συναλλαγής, αποτρέποντας επιθέσεις στην ιδιωτικότητα.
- **Change avoidance**: Η επιλογή συναλλαγών που δεν απαιτούν change outputs ενισχύει την ιδιωτικότητα διαταράσσοντας τις μεθόδους ανίχνευσης αλλαγής.
- **Multiple change outputs**: Εάν η αποφυγή αλλαγής δεν είναι εφικτή, η δημιουργία πολλαπλών change outputs μπορεί ακόμα να βελτιώσει την ιδιωτικότητα.

# **Monero: Φάρος Ανωνυμίας**

Το Monero ανταποκρίνεται στην ανάγκη για απόλυτη ανωνυμία στις ψηφιακές συναλλαγές, θέτοντας υψηλό πρότυπο για την ιδιωτικότητα.

# **Ethereum: Gas και Συναλλαγές**

## **Κατανόηση του Gas**

Το Gas μετρά την υπολογιστική προσπάθεια που απαιτείται για την εκτέλεση λειτουργιών στο Ethereum, τιμολογείται σε **gwei**. Για παράδειγμα, μια συναλλαγή που κοστίζει 2,310,000 gwei (ή 0.00231 ETH) περιλαμβάνει ένα gas limit και ένα base fee, με ένα tip για να παρακινήσει τους miners. Οι χρήστες μπορούν να ορίσουν ένα max fee για να μην πληρώσουν υπερβολικά, με την περίσσεια να επιστρέφεται.

## **Εκτέλεση Συναλλαγών**

Οι συναλλαγές στο Ethereum περιλαμβάνουν έναν αποστολέα και έναν παραλήπτη, που μπορεί να είναι είτε διευθύνσεις χρηστών είτε smart contract. Απαιτούν αμοιβή και πρέπει να γίνουν mined. Βασικές πληροφορίες σε μια συναλλαγή περιλαμβάνουν τον παραλήπτη, την υπογραφή του αποστολέα, την αξία, προαιρετικά δεδομένα, το gas limit και τα fees. Σημειωτέον, η διεύθυνση του αποστολέα προκύπτει από την υπογραφή, εξαλείφοντας την ανάγκη να συμπεριληφθεί στα δεδομένα της συναλλαγής.

Αυτές οι πρακτικές και μηχανισμοί είναι θεμελιώδεις για όποιον επιθυμεί να ασχοληθεί με κρυπτονομίσματα δίνοντας προτεραιότητα στην ιδιωτικότητα και την ασφάλεια.

## Ασφάλεια Smart Contract

- Mutation testing to find blind spots in test suites:

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

## Εκμετάλλευση DeFi/AMM

Αν ερευνάτε πρακτική εκμετάλλευση των DEXes και AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), δείτε:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
