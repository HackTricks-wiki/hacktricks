# Απόρρητο κρυπτονομισμάτων

Το απόρρητο των κρυπτονομισμάτων είναι ζήτημα πρωτοκόλλου και λειτουργιών, όχι συνώνυμο της μυστικότητας ή της ασυλίας. Τα δημόσια ledger, τα exchanges, οι servers των wallets, οι network peers, οι έμποροι και οι μεταγενέστερες συναλλαγές αποκαλύπτουν διαφορετικά τμήματα του γράφου.

Ξεκινήστε από τον [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) για τη μορφή pros/cons/procedure/detection ανά technique. Αυτή η σελίδα επεκτείνει τους ειδικούς μηχανισμούς και τους λειτουργικούς περιορισμούς των κρυπτονομισμάτων.

{% hint style="danger" %}
Αυτό το κεφάλαιο αφορά τη lawful self-custody και την ελαχιστοποίηση δεδομένων. Μην το χρησιμοποιείτε για ξέπλυμα εσόδων, αποφυγή κυρώσεων/φόρων/υποχρεώσεων αναφοράς, συναλλαγές με απαγορευμένα μέρη, παραπλάνηση regulated provider ή λειτουργία μη αδειοδοτημένης υπηρεσίας μεταφοράς. Η privacy technology δεν αλλάζει τη νόμιμη προέλευση ή ιδιοκτησία των κεφαλαίων.
{% endhint %}

## Μοντέλο απειλών ανά layer

| Layer | Observer | Common disclosure |
|---|---|---|
| Acquisition/off-ramp | Exchange, bank, broker, P2P counterparty | Identity, funding account, destination, device, IP, time |
| Ledger | Anyone running analytics | Addresses/outputs, amounts and time on transparent chains; protocol-specific metadata elsewhere |
| Wallet backend | RPC provider, explorer, remote node | Address queries, balances, IP, transaction broadcast |
| Network | ISP, peers, anonymity-network entry | IP, timing, volume and protocol use |
| Counterparty | Payer/payee | Invoice/address, delivery, conversation, account and timing |
| Endpoint | Malware, cloud backup, physical seizure | Seed, keys, labels, history, screenshots and clipboard |

Η self-custody μπορεί να αφαιρέσει έναν custodian από το control path, αλλά δεν διαγράφει το ledger, το acquisition record, τα network metadata ή τα στοιχεία του endpoint.

## Σύγκριση πρωτοκόλλων

| Method | Useful privacy property | Important limits |
|---|---|---|
| Bitcoin on-chain | Self-custody; fresh addresses avoid simple address reuse | Public permanent transaction graph; amount/timing and spending heuristics |
| Bitcoin PayJoin | Receiver input can break the common-input-ownership heuristic | Both wallets need support; transaction remains public; support is uneven |
| Bitcoin CoinJoin | Creates ambiguity among coordinated participants | Recognizable patterns, pre/post links, consolidation, policy/legal/provider risk |
| Lightning | Onion-routed payments are not globally published as ordinary transfers | Channels open/close on-chain; endpoints, peers, probes or custodian may infer data |
| Monero | Stronger default on-chain confidentiality for receiver, amount and sender set | Exchange, node, timing, endpoint and counterparty links remain |
| Ethereum/stablecoins | Broad availability and smart-contract interoperability | Public state/actions; RPC metadata; centralized issuers may block/freeze/report |

## Bitcoin: baseline προστασίας απορρήτου

Το Bitcoin είναι pseudonymous, όχι anonymous. Οι confirmed transactions είναι δημόσιες και διαρκείς· η address reuse, η common-input ownership, η change detection και οι publicly identified addresses μπορούν να δημιουργήσουν clusters.<sup>[[1]](#references)</sup>

### Workflow

1. **Επιλέξτε ένα maintained self-custody wallet.** Κατεβάστε το από το επίσημο project, επαληθεύστε signatures/hashes όταν προσφέρονται και εφαρμόστε security updates.
2. **Δημιουργήστε το wallet σε trusted endpoint.** Καταγράψτε το recovery seed offline· μην το τοποθετείτε ποτέ σε email, chat, screenshots ή συνηθισμένες cloud notes. Δοκιμάστε το recovery πριν αποθηκεύσετε σημαντική αξία.
3. **Διατηρείτε hot μόνο την operational value.** Χρησιμοποιήστε κατάλληλο offline/hardware custody για μακροπρόθεσμη αξία, με recovery plan που δεν εκθέτει το seed σε μία μοναδική ευάλωτη τοποθεσία.
4. **Δημιουργείτε fresh receive address/invoice για κάθε συναλλαγή.** Μην δημοσιεύετε static address όταν είναι δυνατός ένας invoice server ή authenticated private delivery.
5. **Χρησιμοποιήστε το δικό σας full node όταν είναι εφικτό.** Ένα third-party explorer/electrum server μπορεί να μάθει τις addresses που αναζητάτε και τα IP metadata. Ρυθμίστε μόνο wallet-supported συμπεριφορά Tor/proxy· το Tor αποκρύπτει ένα network edge, όχι τον blockchain graph.
6. **Κάντε ιδιωτική επισήμανση σε κάθε UTXO** με source, owner, purpose και compliance state. Ενεργοποιήστε το coin control, ώστε άσχετα identity contexts να μην καταναλώνονται στην ίδια συναλλαγή.
7. **Κάντε preview της συναλλαγής:** selected inputs, change destination, amount, fee, counterparty και αν το spend συγχωνεύει compartments. Αποφύγετε την περιττή consolidation.
8. **Διατηρείτε τα lawful records χωριστά και κρυπτογραφημένα.** Διατηρήστε acquisition basis, invoices, authorization και tax/reporting information χωρίς να δημοσιεύετε τη συσχέτιση.
9. **Αντιμετωπίστε το μεταγενέστερο spending ως μέρος της ίδιας απόφασης privacy.** Μια καλά διαχωρισμένη receipt μπορεί να επανασυσχετιστεί όταν το output της καταναλωθεί μαζί με identified funds.

Η τεκμηρίωση privacy του Bitcoin Core εξηγεί ότι ένα full node αποφεύγει την αποκάλυψη wallet queries σε third-party servers, αλλά ότι το transaction broadcast και το public history εξακολουθούν να χρειάζονται ανάλυση.<sup>[[2]](#references)</sup>

## PayJoin

Το PayJoin είναι μια collaborative payment στην οποία ο receiver προσθέτει ένα input. Αυτό αναιρεί την απλοϊκή υπόθεση ότι όλα τα inputs ανήκουν στον sender. Το BIP 78 περιγράφει το αρχικό interactive protocol· το draft BIP 77 ορίζει έναν asynchronous v2 design που χρησιμοποιεί encrypted mailbox/OHTTP.<sup>[[3]](#references)</sup>

Ασφαλής χρήση:

1. Επιβεβαιώστε ότι και τα δύο maintained wallets υποστηρίζουν την ίδια έκδοση PayJoin.
2. Λάβετε το PayJoin-capable invoice μέσω authenticated channel· προστατέψτε το όπως κάθε payment request.
3. Ελέγξτε το αρχικό amount και destination και, στη συνέχεια, αφήστε το wallet να επικυρώσει το proposal/PSBT, τη fee contribution και τις prohibited substitutions.
4. Επιβεβαιώστε το τελικό wallet summary. Μην εγκρίνετε χειροκίνητα μη αναμενόμενο output, amount ή excessive fee.
5. Αν η negotiation αποτύχει, κατανοήστε αν το wallet κάνει με ασφάλεια fallback σε ordinary payment ή αν απαιτεί νέο invoice.
6. Διατηρήστε τις private receipts/records που απαιτούνται για ownership, accounting και disputes.

Το PayJoin βελτιώνει ένα heuristic του chain analysis· δεν αποκρύπτει την payment από τα parties, την acquisition platform, τα endpoints ή το public ledger.

## CoinJoin: οφέλη και περιορισμοί

Το CoinJoin συντονίζει πολλούς users σε μία transaction, ώστε η αντιστοίχιση input-output να είναι λιγότερο βέβαιη. Έρευνα σε συγκεκριμένα ιστορικά designs των Wasabi και Samourai βρήκε highly recognizable transactions και έδειξε ότι η συμπεριφορά pre/post-mix μπορεί να περιορίσει σημαντικά το anonymity.<sup>[[4]](#references)</sup> Αυτό δεν πρέπει να γενικεύεται σε κάθε implementation ή future version, αλλά δείχνει γιατί ένας αριθμός “anonymity-set” δεν αποτελεί εγγύηση.

Πριν από οποιαδήποτε lawful χρήση:

- ελέγξτε την τρέχουσα local law, το sanctions status, την exchange/custodian policy και τις tax/reporting duties·
- χρησιμοποιήστε maintained, non-custodial software που αποκτήθηκε από το official project·
- κατανοήστε το coordinator model, τα fees, τα denial-of-service controls και αν η τρέχουσα service εξακολουθεί να λειτουργεί—το zkSNACKs τερμάτισε τον coordinator του το 2024, αν και μπορεί να υπάρχουν άλλοι Wasabi coordinators·
- διατηρήστε ιδιωτικά τα source-of-funds και transaction records·
- μην αποδέχεστε ποτέ άγνωστα funds για λογαριασμό κάποιου άλλου και μην χρησιμοποιείτε custodial “mixer” που υπόσχεται untraceable withdrawals·
- διατηρείτε τα outputs χωρισμένα ανά source/context και αποφύγετε μεταγενέστερη consolidation που καταστρέφει την επιδιωκόμενη ambiguity.

Τα νομικά αποτελέσματα εξαρτώνται από τα πραγματικά περιστατικά και τη jurisdiction. Οι guilty pleas του Samourai το 2025 αφορούσαν την εν γνώσει λειτουργία μη αδειοδοτημένου money transmitter που μετακινούσε criminal proceeds· δεν καθορίζουν ότι κάθε collaborative transaction ή privacy-seeking user είναι εγκληματική.<sup>[[5]](#references)</sup>

## Lightning Network

Το Sphinx onion routing του Lightning έχει σχεδιαστεί έτσι ώστε ένας intermediate hop να μαθαίνει τον predecessor και τον successor του, αντί για ολόκληρο το route.<sup>[[6]](#references)</sup> Δεν αποτελεί blanket anonymity: το channel funding/closure είναι δημόσιο, οι nodes διαφημίζουν topology, οι counterparties γνωρίζουν τα endpoints, το routing/probing μπορεί να αποκαλύψει balances ή parties και ένα custodial wallet βλέπει τη δραστηριότητα του account του user.

Για καλύτερο privacy:

1. Προτιμήστε maintained non-custodial wallet αν έχει σημασία το intermediary privacy· σχεδιάστε πρώτα το channel backup/recovery.
2. Χρησιμοποιήστε fresh invoice ή offer για κάθε payment. Επαληθεύστε αν το συγκεκριμένο wallet υποστηρίζει BOLT 12/route blinding, αντί να το θεωρείτε δεδομένο.
3. Αποφύγετε τη δημοσίευση περιττών node aliases, contact details και stable network endpoints.
4. Συνδεθείτε μέσω supported privacy network, εφόσον είναι κατάλληλο, κατανοώντας ότι τα uptime/timing patterns μπορούν ακόμη να συσχετιστούν.
5. Μην συμπεραίνετε ότι μια off-chain payment δεν αφήνει records: sender, receiver, peers, watchtowers, liquidity providers και wallet services μπορεί να διατηρούν observations.

Δημοσιευμένη έρευνα έχει αποδείξει inference sender/recipient και channel-balance από public data και active probing, αν και οι attacks και οι mitigations εξελίσσονται.<sup>[[7]](#references)</sup>

## Monero

Το Monero χρησιμοποιεί one-time stealth addresses για outputs, RingCT για την απόκρυψη amounts και ring signatures για την παροχή probabilistic sender ambiguity· οι τρέχουσες technical specifications τεκμηριώνουν ring size 16 (15 decoys).<sup>[[8]](#references)</sup> Αυτά είναι ισχυρότερα defaults για on-chain confidentiality από τα transparent ledgers, όχι μαγική προστασία από endpoint ή operational mistakes.

### Lawful workflow

1. **Κάντε lawful acquisition.** Ένα regulated exchange μπορεί να γνωρίζει την purchase και withdrawal ακόμη και όταν οι μεταγενέστερες on-chain details είναι confidential. Διατηρήστε source, basis και reporting records.
2. **Εγκαταστήστε το official maintained wallet** και επαληθεύστε το download σύμφωνα με τις οδηγίες του project. Κάντε backup το seed offline και δοκιμάστε restoration με μικρό amount.
3. **Προτιμήστε local node** για μέγιστο wallet-query privacy. Αν αυτό δεν είναι πρακτικό, επιλέξτε trusted remote node προσβάσιμο μέσω officially supported onion/I2P configuration. Ένα remote node μπορεί να καταγράφει IP, requests, timing και transaction IDs· ορισμένα lightweight designs αποκαλύπτουν ένα view key.
4. **Χρησιμοποιήστε νέο subaddress ανά payer, campaign ή invoice.** Ένας payer μπορεί να συσχετίσει την επαναλαμβανόμενη χρήση του ίδιου subaddress.<sup>[[9]](#references)</sup>
5. **Κάντε local labeling στα incoming contexts.** Αποφύγετε την operational συγχώνευση χωριστών receipts όταν ένας ενημερωμένος payer θα μπορούσε να αναγνωρίσει τη μεταγενέστερη συμπεριφορά.
6. **Προστατέψτε τα network metadata.** Ακολουθήστε την επίσημη anonymity-network configuration· αναγνωρίστε τα documented leaks από timestamps, intermittent synchronization, bandwidth shape και stream reuse.<sup>[[10]](#references)</sup>
7. **Διατηρήστε ιδιωτικά τα compliance/audit data.** Αποκαλύψτε ένα view key ή transaction proof μόνο σκόπιμα, στον intended auditor/party, και κατανοήστε ακριβώς τι αποκαλύπτει.

Οι historical traceability studies περιλαμβάνουν bugs και eras επιλογής decoys που έχουν έκτοτε αλλάξει· μην εφαρμόζετε παλιά success percentages σε current transactions. Παρομοίως, το FCMP++ παραμένει roadmap work κατά το research cutoff του παρόντος κεφαλαίου τον Σεπτέμβριο του 2026 και δεν αποτελεί deployed protection.<sup>[[11]](#references)</sup>

## Ethereum και stablecoins

Το ίδιο το privacy material του Ethereum σημειώνει ότι οι on-chain actions είναι ορατές και ότι η wallet/RPC infrastructure προσθέτει IP και metadata exposure.<sup>[[12]](#references)</sup> Οι token transfers, approvals, smart-contract interactions, name services και gas funding μπορούν όλα να συνδέσουν identities.

Τα centralized stablecoins προσθέτουν issuer control. Οι τρέχοντες όροι των USDC και Tether διατηρούν εξουσίες για block/freeze addresses ή assets και για συμμόρφωση με legal/process obligations.<sup>[[13]](#references)</sup> Μπορεί να είναι χρήσιμα payment instruments, αλλά αποτελούν κακές επιλογές όταν η απαίτηση είναι censorship resistance ή on-chain anonymity.

## Όρια συμμόρφωσης

- Οι recommendations του FATF εφαρμόζονται μέσω national law και αλλάζουν με την πάροδο του χρόνου· το update του 2026 δίνει έμφαση στο VASP licensing/registration και στην εφαρμογή του Travel Rule.<sup>[[14]](#references)</sup>
- Στις ΗΠΑ, το FinCEN διακρίνει ένα πρόσωπο που χρησιμοποιεί convertible virtual currency για τα δικά του goods/services από μια business που αποδέχεται και μεταδίδει ή ανταλλάσσει virtual currency· τα πραγματικά περιστατικά και οι μεταγενέστεροι κανόνες έχουν σημασία.<sup>[[15]](#references)</sup>
- Ο EU Transfer of Funds Regulation απαιτεί originator/beneficiary information όταν εμπλέκεται crypto-asset service provider και προσθέτει verification rules για ορισμένες transfers από/προς self-hosted addresses.<sup>[[16]](#references)</sup>
- Οι sanctions και οι tax duties εξακολουθούν να εφαρμόζονται. Κάντε screening όπου απαιτείται, αρνηθείτε prohibited parties και διατηρήστε records· οι λίστες και το legal status μπορούν να αλλάξουν γρήγορα.<sup>[[17]](#references)</sup>

Πριν από material value, cross-border activity, privacy-enhancing coordination ή business-like exchange/transmission, λάβετε current professional advice για τις σχετικές jurisdictions.

Για Bitcoin Silent Payments, fully shielded Zcash, GNU Taler, federated Chaumian e-cash και BOLT 12, συνεχίστε στο [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md).

## References

- [1] [Bitcoin.org — Προστατέψτε το privacy σας](https://bitcoin.org/en/protect-your-privacy) and [Bitcoin Developer Guide — Transactions](https://developer.bitcoin.org/devguide/transactions.html)
- [2] [Bitcoin Core — Privacy features](https://bitcoin.org/en/bitcoin-core/features/privacy) and [Bitcoin.org — Secure your wallet](https://bitcoin.org/en/secure-your-wallet)
- [3] [BIP 78 — Μια απλή πρόταση PayJoin](https://bips.dev/78/) and [Draft BIP 77 — Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
- [4] [Stütz et al. — Υιοθέτηση και πραγματικό privacy των Decentralized CoinJoin Implementations στο Bitcoin (AFT 2022)](https://arxiv.org/abs/2109.10229) and [Wasabi Wallet — Coin consolidation warning](https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html)
- [5] [US DOJ — Οι ιδρυτές του Samourai Wallet δηλώνουν ένοχοι (2025)](https://www.justice.gov/usao-sdny/pr/founders-samourai-wallet-cryptocurrency-mixing-service-plead-guilty) and [Wasabi — coordinator status](https://docs.wasabiwallet.io/FAQ/FAQ-Introduction.html)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Kappos et al. — Εμπειρική ανάλυση του privacy στο Lightning Network](https://arxiv.org/abs/2003.12470)
- [8] Monero Project — [Stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [Ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html) και [Technical specifications](https://docs.getmonero.org/technical-specs/)
- [9] [Monero Docs — Subaddress](https://docs.getmonero.org/public-address/subaddress/)
- [10] [Monero Docs — Networks](https://docs.getmonero.org/infrastructure/networks/), [Running a node with Tor/I2P](https://docs.getmonero.org/running-node/monerod-tori2p/), and [Monero Project — Anonymity networks](https://github.com/monero-project/monero/blob/master/docs/ANONYMITY_NETWORKS.md)
- [11] [Hammad and Victor — Εξερευνώντας την εξέλιξη του privacy του Monero (2024)](https://arxiv.org/abs/2408.05332) and [Monero Roadmap](https://beta.getmonero.org/resources/roadmap/)
- [12] [Ethereum.org — Privacy στο Ethereum](https://ethereum.org/privacy/ethereum)
- [13] [Circle — Όροι USDC](https://www.circle.com/legal/usdc-terms) and [Tether — Legal](https://tether.to/en/legal/)
- [14] [FATF — Targeted Update 2026 για Virtual Assets και VASPs](https://www.fatf-gafi.org/en/publications/Fatfrecommendations/targeted-updated-virtualassets-vasps-2026.html)
- [15] [FinCEN — Εφαρμογή των κανονισμών του FinCEN σε πρόσωπα που διαχειρίζονται, ανταλλάσσουν ή χρησιμοποιούν Virtual Currencies](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [16] [Regulation (EU) 2023/1113](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [17] [US OFAC — Οδηγίες συμμόρφωσης με τις κυρώσεις για τον κλάδο Virtual Currency](https://ofac.treasury.gov/system/files/126/virtual_currency_guidance_brochure.pdf) and [US IRS — Digital asset transaction FAQs](https://www.irs.gov/individuals/international-taxpayers/frequently-asked-questions-on-digital-asset-transactions)
