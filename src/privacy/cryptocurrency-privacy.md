# Απόρρητο κρυπτονομισμάτων

{{#include ../banners/hacktricks-training.md}}

Το απόρρητο των κρυπτονομισμάτων είναι ζήτημα πρωτοκόλλου και λειτουργιών, όχι συνώνυμο της μυστικότητας ή της ασυλίας. Τα δημόσια καθολικά, τα ανταλλακτήρια, οι servers πορτοφολιών, οι network peers, οι έμποροι και οι μεταγενέστερες συναλλαγές εκθέτουν διαφορετικά τμήματα του γραφήματος.

Ξεκινήστε από τον [Κατάλογο Anonymous Payment Technique](anonymous-payment-techniques.md) για τη μορφή pros/cons/procedure/detection ανά τεχνική. Αυτή η σελίδα επεκτείνει τους ειδικούς μηχανισμούς και τους λειτουργικούς περιορισμούς των κρυπτονομισμάτων.

{% hint style="danger" %}
Αυτό το κεφάλαιο αφορά τη νόμιμη self-custody και την ελαχιστοποίηση δεδομένων. Μην το χρησιμοποιείτε για νομιμοποίηση εσόδων, αποφυγή κυρώσεων/φόρων/υποχρεώσεων αναφοράς, συναλλαγές με απαγορευμένα μέρη, παραπλάνηση ρυθμιζόμενου παρόχου ή λειτουργία μη αδειοδοτημένης υπηρεσίας μεταφοράς. Η τεχνολογία απορρήτου δεν αλλάζει τη νόμιμη προέλευση ή ιδιοκτησία των κεφαλαίων.
{% endhint %}

## Μοντέλο απειλών ανά επίπεδο

| Επίπεδο | Παρατηρητής | Συνήθης αποκάλυψη |
|---|---|---|
| Acquisition/off-ramp | Ανταλλακτήριο, τράπεζα, broker, P2P counterparty | Ταυτότητα, λογαριασμός χρηματοδότησης, προορισμός, συσκευή, IP, χρόνος |
| Ledger | Οποιοσδήποτε εκτελεί analytics | Διευθύνσεις/outputs, ποσά και χρόνος σε transparent chains· metadata ειδικά για το πρωτόκολλο αλλού |
| Wallet backend | RPC provider, explorer, remote node | Ερωτήματα διευθύνσεων, υπόλοιπα, IP, broadcast συναλλαγών |
| Network | ISP, peers, είσοδος anonymity-network | IP, χρονισμός, όγκος και χρήση πρωτοκόλλου |
| Counterparty | Payer/payee | Invoice/διεύθυνση, παράδοση, συνομιλία, λογαριασμός και χρονισμός |
| Endpoint | Malware, cloud backup, φυσική κατάσχεση | Seed, keys, labels, ιστορικό, screenshots και clipboard |

Η self-custody μπορεί να αφαιρέσει έναν custodian από τη διαδρομή ελέγχου, αλλά δεν διαγράφει το ledger, το αρχείο απόκτησης, τα network metadata ή τα στοιχεία του endpoint.

## Σύγκριση πρωτοκόλλων

| Μέθοδος | Χρήσιμη ιδιότητα απορρήτου | Σημαντικοί περιορισμοί |
|---|---|---|
| Bitcoin on-chain | Self-custody· οι fresh addresses αποφεύγουν την απλή επαναχρησιμοποίηση διεύθυνσης | Δημόσιο και μόνιμο γράφημα συναλλαγών· heuristics ποσού/χρονισμού και spending |
| Bitcoin PayJoin | Το input του receiver μπορεί να καταρρίψει το common-input-ownership heuristic | Απαιτεί υποστήριξη και από τα δύο wallets· η συναλλαγή παραμένει δημόσια· άνιση υποστήριξη |
| Bitcoin CoinJoin | Δημιουργεί αμφισημία μεταξύ συντονισμένων συμμετεχόντων | Αναγνωρίσιμα patterns, pre/post links, consolidation, κίνδυνος πολιτικής/νομικού πλαισίου/provider |
| Lightning | Οι onion-routed payments δεν δημοσιεύονται παγκοσμίως ως συνηθισμένες transfers | Τα channels ανοίγουν/κλείνουν on-chain· endpoints, peers, probes ή custodian μπορούν να συμπεράνουν δεδομένα |
| Monero | Ισχυρότερη προεπιλεγμένη on-chain εμπιστευτικότητα για receiver, ποσό και sender set | Οι συνδέσεις με exchange, node, χρονισμό, endpoint και counterparty παραμένουν |
| Ethereum/stablecoins | Ευρεία διαθεσιμότητα και smart-contract interoperability | Δημόσιο state/actions· RPC metadata· centralized issuers μπορούν να κάνουν block/freeze/report |

## Bitcoin: baseline προστασίας απορρήτου

Το Bitcoin είναι pseudonymous, όχι anonymous. Οι επιβεβαιωμένες συναλλαγές είναι δημόσιες και διαρκείς· η επαναχρησιμοποίηση διευθύνσεων, το common-input ownership, η ανίχνευση change και οι δημόσια αναγνωρισμένες διευθύνσεις μπορούν να δημιουργήσουν clusters.<sup>[[1]](#references)</sup>

### Ροή εργασίας

1. **Επιλέξτε ένα maintained self-custody wallet.** Κατεβάστε το από το επίσημο project, επαληθεύστε signatures/hashes όταν προσφέρονται και εφαρμόστε security updates.
2. **Δημιουργήστε το wallet σε trusted endpoint.** Καταγράψτε το recovery seed offline· μην το τοποθετείτε ποτέ σε email, chat, screenshots ή συνηθισμένες cloud notes. Δοκιμάστε την ανάκτηση πριν από σημαντική αξία.
3. **Διατηρείτε hot μόνο την operational value.** Χρησιμοποιήστε κατάλληλη offline/hardware custody για μακροπρόθεσμη αξία, με recovery plan που δεν εκθέτει το seed σε μία μόνο εύθραυστη τοποθεσία.
4. **Δημιουργείτε fresh receive address/invoice για κάθε συναλλαγή.** Μην δημοσιεύετε static address όταν είναι δυνατή η χρήση invoice server ή authenticated private delivery.
5. **Χρησιμοποιήστε το δικό σας full node όταν είναι εφικτό.** Ένας third-party explorer/electrum server μπορεί να μάθει τις queried addresses και IP metadata. Ρυθμίστε μόνο behavior Tor/proxy που υποστηρίζεται από το wallet· το Tor αποκρύπτει ένα network edge, όχι το blockchain graph.
6. **Κάντε ιδιωτικό label σε κάθε UTXO** με source, owner, purpose και compliance state. Ενεργοποιήστε το coin control ώστε άσχετα identity contexts να μη γίνονται co-spent.
7. **Κάντε preview της συναλλαγής:** selected inputs, change destination, amount, fee, counterparty και αν το spend συγχωνεύει compartments. Αποφύγετε το περιττό consolidation.
8. **Διατηρείτε τα νόμιμα αρχεία ξεχωριστά και encrypted.** Διαφυλάξτε acquisition basis, invoices, authorization και tax/reporting information χωρίς να δημοσιεύετε τη συσχέτιση.
9. **Αντιμετωπίστε το later spending ως μέρος της ίδιας απόφασης απορρήτου.** Μια καλά διαχωρισμένη receipt μπορεί να επανασυσχετιστεί όταν το output της γίνει co-spent με identified funds.

Η τεκμηρίωση απορρήτου του Bitcoin Core εξηγεί ότι ένα full node αποφεύγει την αποκάλυψη wallet queries σε third-party servers, αλλά ότι το transaction broadcast και το public history εξακολουθούν να χρειάζονται ανάλυση.<sup>[[2]](#references)</sup>

## PayJoin

Το PayJoin είναι μια collaborative payment στην οποία ο receiver προσθέτει ένα input. Αυτό καταρρίπτει την απλοϊκή υπόθεση ότι όλα τα inputs ανήκουν στον sender. Το BIP 78 περιγράφει το αρχικό interactive protocol· το draft BIP 77 ορίζει έναν asynchronous v2 design που χρησιμοποιεί encrypted mailbox/OHTTP.<sup>[[3]](#references)</sup>

Ασφαλής χρήση:

1. Επιβεβαιώστε ότι και τα δύο maintained wallets υποστηρίζουν την ίδια έκδοση PayJoin.
2. Αποκτήστε το PayJoin-capable invoice μέσω authenticated channel· προστατέψτε το όπως κάθε payment request.
3. Ελέγξτε το αρχικό ποσό και τον προορισμό και, στη συνέχεια, αφήστε το wallet να επικυρώσει την πρόταση/PSBT, τη fee contribution και τις prohibited substitutions.
4. Επιβεβαιώστε το τελικό wallet summary. Μην εγκρίνετε χειροκίνητα απρόσμενο output, ποσό ή υπερβολικό fee.
5. Αν η διαπραγμάτευση αποτύχει, κατανοήστε αν το wallet κάνει με ασφάλεια fallback σε ordinary payment ή απαιτεί νέο invoice.
6. Διατηρήστε τα private receipts/records που απαιτούνται για ownership, accounting και disputes.

Το PayJoin βελτιώνει ένα chain-analysis heuristic· δεν αποκρύπτει την πληρωμή από τα μέρη, την acquisition platform, τα endpoints ή το public ledger.

## CoinJoin: οφέλη και περιορισμοί

Το CoinJoin συντονίζει πολλούς χρήστες σε μία συναλλαγή, ώστε η αντιστοίχιση input-output να είναι λιγότερο βέβαιη. Έρευνα σε συγκεκριμένα ιστορικά designs των Wasabi και Samourai εντόπισε εξαιρετικά αναγνωρίσιμες συναλλαγές και έδειξε ότι η συμπεριφορά pre/post-mix μπορεί να περιορίσει σημαντικά την anonymity.<sup>[[4]](#references)</sup> Το αποτέλεσμα αυτό δεν πρέπει να γενικεύεται σε κάθε implementation ή μελλοντική έκδοση, αλλά καταδεικνύει γιατί ένας αριθμός “anonymity-set” δεν αποτελεί εγγύηση.

Πριν από οποιαδήποτε νόμιμη χρήση:

- ελέγξτε την ισχύουσα τοπική νομοθεσία, το sanctions status, την πολιτική exchange/custodian και τις φορολογικές/υποχρεώσεις αναφοράς·
- χρησιμοποιήστε maintained, non-custodial software που αποκτήθηκε από το επίσημο project·
- κατανοήστε το coordinator model, τα fees, τα denial-of-service controls και αν η τρέχουσα υπηρεσία εξακολουθεί να λειτουργεί—το zkSNACKs τερμάτισε τον coordinator του το 2024, αν και ενδέχεται να υπάρχουν άλλοι Wasabi coordinators·
- διατηρήστε ιδιωτικά τα source-of-funds και transaction records·
- μην αποδέχεστε ποτέ unknown funds για λογαριασμό κάποιου άλλου και μην χρησιμοποιείτε custodial “mixer” που υπόσχεται untraceable withdrawals·
- διατηρείτε τα outputs διαχωρισμένα ανά source/context και αποφεύγετε μεταγενέστερο consolidation που καταστρέφει την επιδιωκόμενη αμφισημία.

Οι νομικές συνέπειες εξαρτώνται από τα γεγονότα και τη δικαιοδοσία. Οι guilty pleas του Samourai το 2025 αφορούσαν εν γνώσει λειτουργία μη αδειοδοτημένου money transmitter που μετέφερε criminal proceeds· δεν αποδεικνύουν ότι κάθε collaborative transaction ή χρήστης που επιδιώκει privacy είναι εγκληματίας.<sup>[[5]](#references)</sup>

## Lightning Network

Το Sphinx onion routing του Lightning έχει σχεδιαστεί έτσι ώστε ένα intermediate hop να μαθαίνει τον predecessor και τον successor του, αντί για ολόκληρη τη διαδρομή.<sup>[[6]](#references)</sup> Δεν αποτελεί blanket anonymity: το channel funding/closure είναι δημόσιο, οι nodes διαφημίζουν topology, οι counterparties γνωρίζουν τα endpoints, το routing/probing μπορεί να αποκαλύψει balances ή parties και ένα custodial wallet βλέπει τη δραστηριότητα του λογαριασμού του χρήστη.

Για καλύτερο privacy:

1. Προτιμήστε maintained non-custodial wallet αν έχει σημασία το intermediary privacy· σχεδιάστε πρώτα το channel backup/recovery.
2. Χρησιμοποιείτε fresh invoice ή offer για κάθε πληρωμή. Επαληθεύστε αν το συγκεκριμένο wallet υποστηρίζει ακριβώς BOLT 12/route blinding, αντί να υποθέτετε ότι το κάνει.
3. Αποφύγετε τη δημοσίευση περιττών node aliases, contact details και stable network endpoints.
4. Συνδεθείτε μέσω υποστηριζόμενου privacy network όταν είναι κατάλληλο, κατανοώντας ότι τα patterns διαθεσιμότητας/χρονισμού μπορούν ακόμη να συσχετιστούν.
5. Μην συμπεραίνετε ότι μια off-chain payment δεν αφήνει αρχεία: sender, receiver, peers, watchtowers, liquidity providers και wallet services μπορεί να διατηρούν observations.

Δημοσιευμένη έρευνα έχει αποδείξει sender/recipient και channel-balance inference από δημόσια δεδομένα και active probing, αν και οι επιθέσεις και τα mitigations εξελίσσονται.<sup>[[7]](#references)</sup>

## Monero

Το Monero χρησιμοποιεί one-time stealth addresses για outputs, RingCT για την απόκρυψη ποσών και ring signatures για την παροχή πιθανοτικής sender ambiguity· οι τρέχουσες technical specifications τεκμηριώνουν ring size 16 (15 decoys).<sup>[[8]](#references)</sup> Αυτές είναι ισχυρότερες προεπιλογές για on-chain confidentiality από τα transparent ledgers, όχι μαγική προστασία από endpoint ή operational mistakes.

### Νόμιμη ροή εργασίας

1. **Αποκτήστε το νόμιμα.** Ένα regulated exchange μπορεί να γνωρίζει την αγορά και την ανάληψη ακόμη και όταν οι μεταγενέστερες on-chain λεπτομέρειες είναι confidential. Διατηρήστε source, basis και reporting records.
2. **Εγκαταστήστε το επίσημο maintained wallet** και επαληθεύστε τη λήψη σύμφωνα με τις οδηγίες του project. Δημιουργήστε backup του seed offline και δοκιμάστε την αποκατάσταση με μικρό ποσό.
3. **Προτιμήστε local node** για μέγιστο wallet-query privacy. Αν αυτό δεν είναι πρακτικό, επιλέξτε trusted remote node προσβάσιμο μέσω officially supported onion/I2P configuration. Ένα remote node μπορεί να καταγράφει IP, requests, timing και transaction IDs· ορισμένα lightweight designs αποκαλύπτουν ένα view key.
4. **Χρησιμοποιείτε νέο subaddress ανά payer, campaign ή invoice.** Ένας payer μπορεί να συσχετίσει την επαναλαμβανόμενη χρήση του ίδιου subaddress.<sup>[[9]](#references)</sup>
5. **Κάντε local label στα incoming contexts.** Αποφύγετε operationally merging separated receipts όταν ένας ενημερωμένος payer θα μπορούσε να αναγνωρίσει τη μετέπειτα συμπεριφορά.
6. **Προστατεύστε τα network metadata.** Ακολουθήστε την επίσημη anonymity-network configuration· αναγνωρίστε τα documented leaks από timestamps, intermittent synchronization, bandwidth shape και stream reuse.<sup>[[10]](#references)</sup>
7. **Διατηρήστε ιδιωτικά τα compliance/audit data.** Αποκαλύψτε view key ή transaction proof μόνο σκόπιμα, στον προβλεπόμενο auditor/party, και κατανοήστε ακριβώς τι αποκαλύπτει.

Οι ιστορικές μελέτες traceability περιλαμβάνουν bugs και εποχές decoy-selection που έχουν έκτοτε αλλάξει· μην εφαρμόζετε παλιά success percentages σε τρέχουσες συναλλαγές. Ομοίως, το FCMP++ παραμένει roadmap work κατά το research cutoff του Σεπτεμβρίου 2026 αυτού του κεφαλαίου και δεν αποτελεί deployed protection.<sup>[[11]](#references)</sup>

## Ethereum και stablecoins

Το ίδιο το privacy material του Ethereum σημειώνει ότι οι on-chain actions είναι ορατές και ότι η wallet/RPC infrastructure προσθέτει έκθεση IP και metadata.<sup>[[12]](#references)</sup> Τα token transfers, approvals, smart-contract interactions, name services και gas funding μπορούν όλα να συνδέσουν ταυτότητες.

Τα centralized stablecoins προσθέτουν issuer control. Οι τρέχοντες όροι των USDC και Tether διατηρούν εξουσίες για block/freeze addresses ή assets και συμμόρφωση με νομικές/διαδικαστικές υποχρεώσεις.<sup>[[13]](#references)</sup> Μπορεί να είναι χρήσιμα payment instruments, αλλά αποτελούν κακές επιλογές όταν η απαίτηση είναι censorship resistance ή on-chain anonymity.

## Όρια συμμόρφωσης

- Οι συστάσεις του FATF εφαρμόζονται μέσω εθνικής νομοθεσίας και αλλάζουν με τον χρόνο· η ενημέρωση του 2026 δίνει έμφαση σε VASP licensing/registration και στην εφαρμογή του Travel Rule.<sup>[[14]](#references)</sup>
- Στις ΗΠΑ, το FinCEN διακρίνει ένα άτομο που χρησιμοποιεί convertible virtual currency για τα δικά του αγαθά/υπηρεσίες από μια επιχείρηση που την αποδέχεται και τη μεταφέρει ή ανταλλάσσει· σημασία έχουν τα πραγματικά περιστατικά και οι μεταγενέστεροι κανόνες.<sup>[[15]](#references)</sup>
- Ο κανονισμός της ΕΕ για τη μεταφορά κεφαλαίων απαιτεί πληροφορίες originator/beneficiary όταν εμπλέκεται crypto-asset service provider και προσθέτει κανόνες επαλήθευσης για ορισμένες transfers προς/από self-hosted addresses.<sup>[[16]](#references)</sup>
- Οι κυρώσεις και οι φορολογικές υποχρεώσεις εξακολουθούν να ισχύουν. Κάντε screening όπως απαιτείται, αρνηθείτε prohibited parties και διατηρήστε records· οι λίστες και το νομικό καθεστώς μπορούν να αλλάξουν γρήγορα.<sup>[[17]](#references)</sup>

Πριν από σημαντική αξία, cross-border activity, privacy-enhancing coordination ή exchange/transmission σε επιχειρηματική βάση, λάβετε τρέχουσα επαγγελματική συμβουλή για τις σχετικές δικαιοδοσίες.

Για Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash και BOLT 12, συνεχίστε στο [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Προστατέψτε το απόρρητό σας](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Λειτουργίες απορρήτου](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Μια απλή πρόταση Payjoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Υιοθέτηση και πραγματικό απόρρητο των decentralized CoinJoin implementations στο Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Οι ιδρυτές του Samourai Wallet δηλώνουν ένοχοι (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Εμπειρική ανάλυση του απορρήτου στο Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) και [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Εξέλιξη του απορρήτου του Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Απόρρητο στο Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Όροι USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Ενημέρωση του 2026 για Virtual Assets και VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Εφαρμογή των κανονισμών του FinCEN σε άτομα που διαχειρίζονται, ανταλλάσσουν ή χρησιμοποιούν Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Κανονισμός (ΕΕ) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Οδηγίες συμμόρφωσης με κυρώσεις για τον κλάδο Virtual Currency](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
{{#include ../banners/hacktricks-training.md}}
