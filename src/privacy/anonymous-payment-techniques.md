# Κατάλογος Τεχνικών Anonymous Payment

{{#include ../banners/hacktricks-training.md}}

Ο κατάλογος καλύπτει **οικογένειες** πληρωμών, από τα συνηθισμένα μετρητά έως το blind-signature e-cash και το public-chain obfuscation. Το «anonymous» σημαίνει πάντοτε anonymous από έναν κατονομασμένο παρατηρητή. Ο merchant, ο issuer, το mint, το exchange, ο blockchain analyst, ο network provider, ο εργοδότης και ο φυσικός παρατηρητής βλέπουν διαφορετικά στοιχεία.

Οι παρακάτω διαδικασίες αφορούν νόμιμα κεφάλαια, αληθείς λογαριασμούς και εξουσιοδοτημένες προμήθειες. Techniques των οποίων ο σκοπός στις αναφερόμενες περιπτώσεις ήταν το laundering, η αποφυγή κυρώσεων ή η identity fraud εξηγούνται και ανιχνεύονται, αλλά η διαδικασία τους αποτελεί συνθετική forensic άσκηση και όχι οδηγίες για τη διάπραξη του εγκλήματος.

## Coverage matrix

| Οικογένεια | Κύρια ιδιότητα privacy | Κύριος παρατηρητής/εμπιστοσύνη | Αντιμετώπιση |
|---|---|---|---|
| Μετρητά και ισοδύναμα μετρητών | καμία απομακρυσμένη εγγραφή σε payment network | recipient και φυσικό περιβάλλον | lawful workflow |
| Prepaid/gift/voucher value | διαχωρίζει το redemption από την κύρια card | seller, issuer και redemption service | lawful workflow, διαφέρει ανά δικαιοδοσία |
| Virtual/tokenized card | κρύβει το reusable PAN ή διαχωρίζει τους merchants | issuer/network/wallet εξακολουθεί να αναγνωρίζει τον payer | lawful workflow |
| Payment app/intermediary | ο merchant μπορεί να βλέπει alias/intermediary | το app συλλέγει identity/device/transaction | comparison baseline |
| Bitcoin hygiene/Silent Payments | pseudonyms και unlinkability του recipient | public graph και wallet/network boundary | deployable |
| PayJoin/CoinJoin | αποδυναμώνει heuristics κοινής ιδιοκτησίας/linkage | participants/coordinator/network/public graph | deployable όπου υποστηρίζεται· legal review |
| Lightning/BOLT 12 | off-chain routing και μείωση του receiver-path | endpoints, hops, services και channel graph | deployable όπου υποστηρίζεται |
| Monero/Zcash/MWEB | on-chain confidentiality σε επίπεδο protocol | acquisition, endpoint, network και boundary παραμένουν | deployable όπου είναι lawful/supported |
| Ethereum ZK application | κρύβει συγκεκριμένη σχέση statement/action | public inputs, RPC, relayer και app | application-specific |
| Cashu/Fedimint/Taler | payer privacy μέσω blind signatures | mint/federation/exchange custody και boundaries | emerging/deployment-specific |
| Stablecoins | εύκολο digital settlement | transparent chain και issuer freeze/control | όχι anonymous baseline |
| Swaps/bridges/DEX | μεταφέρει value μεταξύ asset/chain | και τα δύο graphs, contracts και providers | forensic mechanics· μόνο ordinary lawful swaps |
| Mixers/peel/structuring | αυξάνει την ασάφεια/work του graph | entry/exit graph και service records | μόνο synthetic detection exercise |
| Nominees/mules/OTC/fronts | εισάγει ανθρώπινους/επιχειρηματικούς intermediaries | facilitators, banks, communications | μόνο criminal-abuse analysis |
| Reusable/stealth payment addresses | νέα διεύθυνση recipient ανά πληρωμή | public announcement/notification και wallet boundaries | deployable όπου υποστηρίζεται |
| Confidential sidechain/state channel | κρύβει amount/asset ή ενδιάμεσες ενημερώσεις | peers, bridge/federation και lifecycle settlement | protocol-specific |
| Carrier/open-banking/platform billing | κρύβει την κύρια card από τον merchant | carrier, bank/PISP ή platform αναγνωρίζει τον customer | ordinary identified payment |
| Mutual credit/net settlement | λιγότερες εξωτερικές εγγραφές settlement | ο private ledger operator έχει πλήρες mapping | μόνο identified participants |

## Cash

**Mechanics:** physical bearer value αλλάζει χέρια χωρίς online issuer authorization ή public ledger.

**Pros:** ο merchant δεν χρειάζεται να μάθει την ταυτότητα bank/card· κανένα remote transaction graph· ευρέως κατανοητό και final.

**Cons:** μόνο face-to-face· κλοπή/απώλεια· change/receipt/serial ή reporting controls· withdrawal, κάμερες, μάρτυρες και τοποθεσία εξακολουθούν να συνδέουν τον payer.

**Procedure:** (1) επιβεβαίωσε ότι τα μετρητά είναι lawful/accepted και έλεγξε τυχόν όριο ή reporting rule· (2) κάνε lawful withdrawal ή λάβε τα νόμιμα και κράτησε private accounting records· (3) πλήρωσε ordinary merchant χωρίς περιττά loyalty/account identifiers· (4) ζήτησε μόνο την απαιτούμενη receipt· (5) απόφυγε shipping/account data αν η αγορά δεν τα χρειάζεται· (6) κατέγραψε εσωτερικά τον legitimate business purpose.

**Detection:** κάνε reconcile till/receipt/inventory, καμερών και access logs σύμφωνα με την applicable policy· διερεύνησε ασυνήθιστα cash refunds ή επαναλαμβανόμενα ποσά λίγο κάτω από control limits, χωρίς να θεωρείς από μόνη της ύποπτη τη συνήθη χρήση μετρητών.

## Money order, postal order, cashier instrument και cash on delivery

**Mechanics:** ένας regulated issuer μετατρέπει cash/account funds σε αριθμημένο instrument payable σε named recipient· το COD μεταθέτει την είσπραξη για την παράδοση.

**Pros:** ο recipient μπορεί να μη λάβει τον primary bank/card number του payer· χρήσιμο όπου τα μετρητά δεν μπορούν να μεταφερθούν remotely· σαφής receipt.

**Cons:** issuer/retailer διατηρεί purchase/identity data όπως απαιτείται· serial tracking· recipient/delivery address· κίνδυνος απώλειας/fraud και regional restrictions· γενικά όχι anonymous.

**Procedure:** (1) έλεγξε issuer rules, limits, identification και acceptance από τον recipient· (2) αγόρασε με truthful information και lawful funds· (3) συμπλήρωσε αμέσως payee/amount· (4) κράτησε serial/receipt· (5) χρησιμοποίησε tracked delivery ανάλογη της αξίας· (6) κάνε reconcile redemption/refund.

**Detection:** issuer purchase/redemption record, instrument serial, retailer/camera, shipping και recipient account· επισήμανε alteration, duplicate serials και γρήγορο geographically inconsistent redemption.

## Open-loop prepaid card

**Mechanics:** network-branded stored-value credential κάνει authorization έναντι prepaid balance αντί για primary credit account.

**Pros:** περιορίζει merchant exposure και loss· διαχωρίζει τον merchant από το main PAN· χρησιμοποιείται online όπου γίνεται δεκτή.

**Cons:** purchase/activation/reload/registration και device records· KYC και limits διαφέρουν· αποτυχίες billing-address· περιορισμοί cash-out/refund· το “no name” δεν σημαίνει απουσία issuer record.

**Procedure:** (1) επαλήθευσε current issuer identity, fees, KYC, geography και online/recurring support· (2) απέκτησέ την από authorized seller με lawful funds· (3) δήλωσε truthful required data· (4) χρησιμοποίησέ την για μία compartment/purpose· (5) μην κάνεις structure loads και μην κατασκευάζεις residency· (6) κράτησε purchase/expense evidence και κλείσε/απόρριψέ την σύμφωνα με τους issuer terms.

**Detection:** συσχέτισε seller/activation, funding, device/IP, merchant authorization, balance checks και redemption/refund. Τα patterns έχουν μεγαλύτερη σημασία από την prepaid label.

## Closed-loop gift card, voucher και transferable service credit

**Mechanics:** numbered value που εξαργυρώνεται μόνο σε έναν merchant/service ή ecosystem. Airtime/game/store credits είναι παραλλαγές.

**Pros:** ο recipient merchant μπορεί να βλέπει μόνο code/balance· περιορισμένο blast radius· εύκολο gifting και budget separation.

**Cons:** seller και service καταγράφουν purchase/activation/redemption· account/device/delivery εξακολουθούν να συνδέουν τη δραστηριότητα· scams, resale discounts και expiry/region limits· αδύναμα refund rights.

**Procedure:** (1) αγόραζε μόνο από authorized channels· (2) κατέγραφε την αξία του code χωρίς να εκθέτεις το secret· (3) μην το συνδέεις με identifying loyalty account αν δεν είναι απαραίτητο· (4) κάνε redeem μέσω separate legitimate merchant account/context· (5) κράτησε τη receipt μέχρι να γίνει accepted· (6) μην αγοράζεις ποτέ codes για unsolicited “tax/support/ransom” demand.

**Detection:** code issuance/redemption time, device/account convergence, bulk/threshold-pattern purchase, μία συσκευή που ελέγχει πολλά balances και distant rapid redemption.

## Cryptocurrency-funded card ή gift-code broker

**Mechanics:** intermediary δέχεται cryptocurrency και εκδίδει card, voucher ή merchant code. Πρόκειται για cross-rail conversion: ο merchant βλέπει ordinary card/gift value, ενώ ο broker συνδέει το on-chain deposit με issuance και delivery.

**Pros:** ο merchant δεν λαμβάνει το funding wallet· χρήσιμο για legitimate merchants που δεν δέχονται crypto· bounded stored value.

**Cons:** όχι anonymous από broker/issuer· KYC, sanctions, exchange και card-program rules· public deposit graph· account/device/email και code redemption επανασυνδέουν τις δύο πλευρές· scam/insolvency risk.

**Procedure:** (1) επαλήθευσε legal entity, card issuer, supported jurisdiction, KYC, fees και refund policy· (2) χρησιμοποίησε μόνο lawful documented funds· (3) δοκίμασε τη μικρότερη denomination· (4) επιβεβαίωσε network/merchant restrictions πριν από την αγορά· (5) κράτησε τόσο το blockchain transaction όσο και το broker receipt για accounting· (6) μην χρησιμοποιείς broker που υπόσχεται identity fraud, sanctions bypass ή “untraceable” cash-out.

**Detection:** συσχέτισε broker deposit addresses, unique amount/time, account/device και issued-card authorization ή gift-code redemption· τα issuer και broker records γεφυρώνουν το public chain με τον merchant.

## Virtual ή merchant-locked card

**Mechanics:** ο issuer αντιστοιχίζει generated PAN/token στον πραγματικό account, συχνά με περιορισμό merchant, amount ή expiration.

**Pros:** αποτρέπει την έκθεση reusable PAN· merchant compartmentation· spend limits και εύκολη revocation· ώριμο fraud control.

**Cons:** ο issuer εξακολουθεί να γνωρίζει payer, funding, merchant, device/IP και time· ο merchant βλέπει account/delivery· ορισμένα refunds/recurring charges αποτυγχάνουν· δεν είναι anonymous.

**Procedure:** (1) χρησιμοποίησε το official feature του regulated issuer· (2) δημιούργησε card για έναν merchant/engagement· (3) όρισε το μικρότερο χρήσιμο limit και expiry· (4) χρησιμοποίησε accurate billing όπου απαιτείται· (5) επιβεβαίωσε statement descriptor/refund behavior· (6) κάνε freeze/delete μετά το final settlement, διατηρώντας audit evidence.

**Detection:** issuer token-to-account mapping, merchant authorization, device και delivery. Οι defenders χρησιμοποιούν merchant-specific reuse, velocity και account-takeover signals.

## Mobile-wallet network token

**Mechanics:** το EMV payment tokenization αντικαθιστά το PAN με constrained credential, συνήθως δεμένο με device, merchant ή payment scenario.<sup>[[1]](#references)</sup>

**Pros:** ο merchant δεν λαμβάνει το reusable PAN· device cryptography/dynamic data μειώνουν το cloning· μπορεί να γίνει revoke χωρίς αντικατάσταση της card.

**Cons:** issuer, token service, wallet platform και network διατηρούν mappings/transactions· device/platform account και location μπορεί να αναγνωρίσουν τον payer.

**Procedure:** (1) κάνε enroll legitimate card στο official wallet· (2) προστάτευσε platform account/device με strong authentication· (3) επιβεβαίωσε device token/last digits κατά την αγορά· (4) απενεργοποίησε περιττό location/analytics όπου υποστηρίζεται· (5) αφαίρεσε αμέσως lost devices/token· (6) έλεγξε issuer και wallet records.

**Detection:** token requestor/device cryptogram και issuer mapping, wallet/account telemetry, merchant terminal και physical evidence.

## Payment app, marketplace wallet και centralized intermediary

**Mechanics:** η service διατηρεί accounts και κάνει transfers εσωτερικά ή μέσω bank/card rails· ο merchant μπορεί να βλέπει alias, ενώ η service βλέπει και τα δύο μέρη.

**Pros:** convenience, dispute/refund mechanisms· ο recipient δεν χρειάζεται να βλέπει bank/card details.

**Cons:** centralized identity/social/transaction/device graph· freezes και legal process· counterparties μπορούν να εκθέσουν το profile· η χρήση data μπορεί να υπερβαίνει την ανάγκη της πληρωμής.<sup>[[2]](#references)</sup>

**Procedure:** (1) διάβασε identity, privacy, retention και buyer-protection terms· (2) περιόρισε optional profile/contact synchronization· (3) χρησιμοποίησε separate truthful account μόνο όταν το επιτρέπουν οι terms· (4) ενεργοποίησε MFA/alerts· (5) επιβεβαίωσε recipient και privacy του memo/profile· (6) εξήγαγε records και κλείσε unused links.

**Detection:** provider account, device/IP, contact graph, funding/withdrawal, memo και merchant records. Ένα alias είναι pseudonymity από τον counterparty, όχι anonymity από την platform.

## Bank transfer, ACH, wire και instant-account payment

**Mechanics:** regulated institutions μετακινούν value μεταξύ identified accounts και ανταλλάσσουν τα απαιτούμενα payment data.

**Pros:** γρήγορο, accountable, περιορισμένα reversible cases, ισχυρά records· virtual account numbers μπορεί να μειώσουν την disclosure στον merchant.

**Cons:** οι banks/processors γνωρίζουν και τις δύο πλευρές· statements και references· όχι anonymous· cross-border και Travel Rule/AML data.

**Procedure:** χρησιμοποίησέ το μόνο όταν η accountability είναι αποδεκτή: επαλήθευσε ανεξάρτητα τον beneficiary, περιόρισε optional memo data, χρησιμοποίησε bank-provided virtual account/reference όπου υπάρχει, ενεργοποίησε alerts, κράτησε invoice και κάνε reconcile.

**Detection:** deterministic bank/payment records, beneficiary/account ownership, device/session και fraud controls. Αυτό είναι baseline και όχι anonymity technique.

## Account και merchant compartmentation

**Mechanics:** ξεχωριστές lawful identities/accounts, email aliases, cards και delivery contexts εμποδίζουν άσχετους merchants να ενώσουν εύκολα τη δραστηριότητα, ενώ issuer/controller διατηρεί το mapping.

**Pros:** μειώνει breach και cross-merchant linkage· εύκολο audit· συμβατό με regulated payments.

**Cons:** ο provider εξακολουθεί να ενώνει τα compartments· recovery phone/device/IP και shipping μπορεί να τα επανασυνδέσουν· policy μπορεί να απαγορεύει πολλαπλούς accounts.

**Procedure:** (1) καθόρισε ένα purpose· (2) δημιούργησε μόνο terms-compliant aliases/subaccounts· (3) χρησιμοποίησε merchant-specific token/card· (4) απενεργοποίησε cross-account contact/ad personalization· (5) κράτησε encrypted controller ledger· (6) απόσυρε identifiers μετά το τέλος των refund/retention requirements.

**Detection:** οι providers ενώνουν recovery, device, funding και IP· οι merchants ενώνουν delivery, browser και account behavior. Οι defenders πρέπει να διακρίνουν legitimate compartmentation από synthetic identity fraud.

## Controlled red-team procurement

**Mechanics:** το SOC δεν γνωρίζει μια αγορά, ενώ ένας exercise controller διατηρεί legal entity, operator και infrastructure mapping.

**Pros:** ρεαλιστικό detection exercise· καμία προσωπική έκθεση· άμεσο deconfliction και audit.

**Cons:** όχι anonymous από organization/provider· governance overhead· leaks αν γίνει κακή διαχείριση του controller ledger.

**Procedure:** (1) διέθεσε engagement-specific organization card/wallet/budget· (2) διαχώρισε purchaser/operator roles· (3) κατέγραψε asset, amount, service, purpose και kill date· (4) αποθήκευσε το attribution mapping με περιορισμένη πρόσβαση controller· (5) μην χρησιμοποιήσεις false identity/mule/stolen funds· (6) αποκάλυψε και κάνε reconcile indicators και refunds στο closeout.

**Detection:** ο controller αντιστοιχίζει provider invoice και asset· το SOC δοκιμάζει independent discovery μέσω domain, certificate, hosting και traffic αντί για cardholder data.

## Bitcoin address hygiene και coin control

**Mechanics:** fresh receive addresses, local labeling και selective UTXO spending μειώνουν address reuse και accidental compartment merging σε public ledger.

**Pros:** ευρέως supported· self-custodial· αποφεύγει το απλούστερο public linkage.

**Cons:** όλες οι transactions/amounts παραμένουν public· common-input/change/timing και μεταγενέστερο consolidation συνδέουν τη δραστηριότητα· παραμένουν acquisition/RPC/network records.

**Procedure:** (1) εγκατέστησε/επαλήθευσε maintained wallet· (2) κάνε backup και test seed recovery· (3) χρησιμοποίησε νέα address ανά invoice· (4) βάλε label source/purpose locally· (5) χρησιμοποίησε coin control για να μη συγχωνεύεις contexts· (6) προτίμησε local node ή privacy-aware connection· (7) κάνε preview change/fees και κράτησε lawful accounting.<sup>[[3]](#references)</sup>

**Detection:** address graph, common-input/change heuristics με uncertainty, exact amount/time, consolidation, service deposits, node/RPC broadcast timing και off-chain records.

## Bitcoin Silent Payments

**Mechanics:** το BIP 352 επιτρέπει στον receiver να δημοσιεύει static code, ενώ οι senders παράγουν unique Taproot outputs μέσω ECDH· οι εξωτερικοί observers δεν μπορούν να συνδέσουν άμεσα τα outputs με το code.<sup>[[4]](#references)</sup>

**Pros:** reusable public identifier χωρίς address reuse· δεν απαιτεί interactive address request ή notification output· ενσωματώνεται σε Taproot outputs.

**Cons:** scanning cost για τον receiver· μεταβλητό wallet support· amount/sender graph και spending παραμένουν public· index server μπορεί να βλέπει τα scans.

**Procedure:** (1) επίλεξε current BIP 352 wallet· (2) κάνε backup/test descriptor και scanning recovery· (3) δημιούργησε labeled code όπου υποστηρίζεται· (4) κάνε authenticate το published code· (5) ο sender ελέγχει inputs και στέλνει small test· (6) ο receiver κάνει scan κατά προτίμηση μέσω δικού του node· (7) κράτησε τα received UTXOs separated.

**Detection:** από το output μόνο δεν είναι αξιόπιστα identifiable by design· οι analysts χρησιμοποιούν sender inputs, amount/time, later spending, wallet/network/index και counterparty records.

## PayJoin

**Mechanics:** payer και payee συνεισφέρουν inputs σε μία payment transaction, καταρρίπτοντας την υπόθεση ότι όλα τα inputs έχουν έναν owner.<sup>[[5]](#references)</sup>

**Pros:** ordinary payment με βελτιωμένο privacy· ωφελεί το ευρύτερο graph αποδυναμώνοντας common heuristic· δεν απαιτεί equal-output crowd.

**Cons:** interactive/support requirement· receiver endpoint availability· amount και final transaction είναι public· implementation και fallback metadata.

**Procedure:** (1) επιβεβαίωσε ότι και τα δύο maintained wallets υποστηρίζουν την ίδια PayJoin version· (2) κάνε authenticate invoice/endpoint· (3) ξεκίνα από το wallet’s PayJoin-enabled payment URI· (4) έλεγξε final amount/fee και υπέγραψε μόνο expected inputs· (5) απόφυγε manual transaction surgery· (6) επιβεβαίωσε broadcast και receipt· (7) κατέγραψε fallback αν αποτύχει η negotiation.

**Detection:** οι blockchain analysts δεν πρέπει να επιβάλλουν common-input clustering· endpoint/provider μπορεί να καταγράφει τη negotiation· χρησιμοποίησε wallet/network και later-spend evidence αντί για transaction shape μόνο.

## CoinJoin

**Mechanics:** πολλοί participants δημιουργούν συνεργατικά transaction με πολλά inputs/outputs, συνήθως equal denominations, αυξάνοντας την ambiguity της αντιστοίχισης input-output.

**Pros:** μεγαλύτερο on-chain ambiguity set· υπάρχουν self-custodial designs· μετρήσιμη round structure.

**Cons:** coordinator/peer/network metadata· fees/liquidity· identifiable transaction shape· toxic change και later consolidation καταστρέφουν τα οφέλη· legal/provider availability διαφέρει.

**Procedure:** (1) επαλήθευσε current wallet/coordinator availability και legality· (2) εγκατέστησε official wallet και κάνε backup· (3) χρησιμοποίησε μόνο lawful UTXOs· (4) κατανόησε denomination, fee και coordinator model· (5) κράτησε change και mixed outputs labeled/separate· (6) μην τα κάνεις ποτέ consolidate μαζί· (7) δρομολόγησε network traffic όπως υποστηρίζεται επίσημα και κράτησε accounting.

**Detection:** εντόπισε collaborative structure χωρίς να υποθέτεις crime· υπολόγισε possible mappings/anonymity set και στη συνέχεια παρακολούθησε change/consolidation, service boundaries και network/coordinator records.

## Lightning Network

**Mechanics:** HTLC payments διασχίζουν onion-routed channels· τα περισσότερα payment details δεν δημοσιεύονται on chain, ενώ τα funding/closing και οι public channel information παραμένουν.

**Pros:** γρήγορο, χαμηλό fee· οι intermediaries συνήθως βλέπουν adjacent hops· routine payment details παραμένουν off chain.

**Cons:** sender/receiver και first/last hop γνωρίζουν περισσότερα· probing, timing, channel graph, liquidity/wallet/LSP records· custodial wallets αναγνωρίζουν users.

**Procedure:** (1) επίλεξε συνειδητά self-custodial ή custodial· (2) επαλήθευσε wallet/seed/channel recovery· (3) χρησιμοποίησε invoice για το exact payment· (4) προτίμησε private channels/LSP features μόνο αφού διαβάσεις τα tradeoffs· (5) προστάτευσε node IP με supported Tor όπου χρειάζεται· (6) απόφυγε identifying invoice reuse· (7) κράτησε channel και payment accounting.<sup>[[6]](#references)</sup>

**Detection:** node/LSP/custodian logs, channel graph/probes, payment failure/timing και on-chain funding/closure· η απουσία public transaction δεν σημαίνει απουσία records.

## BOLT 12 offers και route blinding

**Mechanics:** reusable offer παράγει fresh invoices και μπορεί να διαφημίζει blinded paths, ώστε ο payer να μη χρειάζεται να μάθει το clear node/path του receiver.

**Pros:** receiver privacy· reusable donation/payment endpoint χωρίς static invoice· ενσωμάτωση στο Lightning onion routing.

**Cons:** μεταβλητό wallet support· endpoints, selected hops και funding παραμένουν· public contact ή network endpoint μπορεί να επαναπροσδιορίσει τον receiver.

**Procedure:** (1) επιβεβαίωσε matching BOLT 12 support· (2) κάνε authenticate το offer· (3) ζήτησε fresh invoice· (4) έλεγξε amount/issuer/recurrence· (5) πλήρωσε μέσω του wallet· (6) επιβεβαίωσε receipt/refund behavior· (7) ελαχιστοποίησε node alias/contact και κράτησε accounting.<sup>[[7]](#references)</sup>

**Detection:** wallet/LSP και first/last-hop telemetry, offer distribution account, timing/value και funding graph· το route blinding περιορίζει σκόπιμα την ορατότητα του payer.

## Monero

**Mechanics:** one-time stealth addresses κρύβουν το recipient linkage, το RingCT κρύβει amounts και τα ring signatures παρέχουν sender ambiguity.

**Pros:** privacy by default on chain· confidentiality sender/receiver/amount· ώριμο dedicated wallet/node ecosystem.

**Cons:** acquisition/off-ramp και endpoint/network/counterparty records· remote node βλέπει queries/IP· exchange support/legal treatment διαφέρουν· μικρά operational mistakes εξακολουθούν να συνδέουν contexts.

**Procedure:** (1) απέκτησέ το νόμιμα και κράτησε basis/source· (2) εγκατέστησε/επαλήθευσε official maintained wallet· (3) κάνε backup/test seed· (4) χρησιμοποίησε local node ή documented Tor/I2P remote-node path· (5) χρησιμοποίησε νέα subaddress ανά payer/invoice· (6) βάλε local labels στα contexts· (7) αποκάλυψε transaction proof/view access μόνο σκόπιμα.<sup>[[8]](#references)</sup>

**Detection:** εστίασε σε exchange/merchant/device/network και seized-wallet evidence· η χρήση του protocol από μόνη της δεν είναι ύποπτη και το public chain σκόπιμα εκθέτει λιγότερα.

## Zcash fully shielded Orchard

**Mechanics:** zero-knowledge proofs επικυρώνουν shielded transfers, ενώ sender, receiver και amount είναι encrypted· transparent pools και pool transitions παραμένουν public.

**Pros:** ισχυρό shielded on-chain confidentiality· viewing keys για scoped audit· protocol-enforced validity.

**Cons:** wallet/exchange support και πραγματική επιλογή pool διαφέρουν· transparent boundary timing/value correlation· network/RPC και endpoint παραμένουν.

**Procedure:** (1) επίλεξε maintained Orchard shielded-by-default wallet· (2) επαλήθευσε/κάνε backup· (3) απέκτησε ZEC νόμιμα· (4) λάβε σε supported Unified Address και επιβεβαίωσε pool· (5) προτίμησε shielded-to-shielded· (6) χρησιμοποίησε supported network privacy· (7) δοκίμασε viewing-key disclosure σε μικρό wallet πριν από audit.<sup>[[9]](#references)</sup>

**Detection:** transparent boundary και service records, wallet/network metadata και viewing keys όπου παρέχονται νόμιμα· μην υποθέτεις ότι όλες οι Unified Address payments ήταν shielded.

## Mimblewimble και Litecoin MWEB

**Mechanics:** confidential transactions κρύβουν amounts και το Mimblewimble-style aggregation αφαιρεί conventional address-rich history· το Litecoin υλοποιεί optional extension block παράλληλα με το transparent chain.

**Pros:** confidential amounts και βελτιωμένο fungibility στο private domain· efficient pruning/aggregation.

**Cons:** opt-in boundary peg-in/out είναι public και correlatable· wallet/exchange support· interactive/address model differences· network και acquisition records.

**Procedure:** (1) επίλεξε maintained wallet με explicit MWEB support· (2) επαλήθευσε/κάνε backup και δοκίμασε small amount· (3) απέκτησέ το νόμιμα· (4) κάνε peg into MWEB και επιβεβαίωσε balance domain· (5) κάνε transact μόνο με compatible receiver· (6) απόφυγε immediate distinctive peg-out· (7) κράτησε private audit records.<sup>[[10]](#references)</sup>

**Detection:** public peg-in/out timing/value, exchange/wallet/node data και later transparent spends· οι εσωτερικές confidential transfer details μειώνονται σκόπιμα.

## Ethereum zero-knowledge privacy applications

**Mechanics:** ένα circuit αποδεικνύει statement—membership, valid note ownership ή authorization—χωρίς να αποκαλύπτει το secret· verifier contract το ελέγχει. Deposits, withdrawals, public inputs, events και gas μπορούν ακόμη να αποκαλύψουν links.

**Pros:** programmable selective disclosure· anonymous-set applications· verifiable rules χωρίς αποκάλυψη όλων των data.

**Cons:** contract/circuit bugs· μικρό anonymity set· public boundaries· RPC/IP/session/analytics/gas funding· application και sanctions/legal risk.

**Procedure:** (1) όρισε ακριβώς τι κρύβει το proof· (2) χρησιμοποίησε audited maintained application όπου είναι lawful· (3) έλεγξε public inputs/events και deposit/withdraw rules· (4) διαχώρισε action wallet και gas sponsorship όπως προβλέπει το protocol· (5) χρησιμοποίησε privacy-aware RPC/network path· (6) δοκίμασε με μικρή αξία· (7) διατήρησε compliance records.<sup>[[11]](#references)</sup>

**Detection:** contract events, deposit/withdraw timing/value, relayer/paymaster, RPC/session, frontend storage/analytics και eventual exchange/merchant boundary. Μην ισχυρίζεσαι ότι το ZK proof κρύβει fields που έχουν δηλωθεί public.

## Stablecoins

**Mechanics:** tokens μεταφέρονται σε public chain· centralized issuers μπορεί να κάνουν freeze/blacklist ή redeem έναντι identified accounts.

**Pros:** price stability, liquidity και merchant support· fast settlement· εύκολο accounting.

**Cons:** transparent address/amount/contract graph· gas funding· issuer και exchange identity/control· sanctions screening· γενικά poor anonymity.

**Procedure:** αντιμετώπισέ τα ως identified payment: χρησιμοποίησε fresh business address μόνο για compartmentation, επαλήθευσε token contract/network, κάνε small test, προστάτευσε το wallet, χρησιμοποίησε trusted RPC/local node, κράτησε basis/source και κάνε screen τα απαιτούμενα parties.

**Detection:** πλήρες token event graph, issuer freeze list/actions, exchange/RPC/device και gas-funding relationships.

## Cashu Chaumian e-cash

**Mechanics:** ένα mint υπογράφει blind client-generated bearer secrets, backed by mint Bitcoin/Lightning reserves· μπορεί να αποτρέπει double-spend χωρίς να συνδέει άμεσα το issuance με το μεταγενέστερο redemption.

**Pros:** accountless bearer tokens· instant peer transfer· το mint δεν μπορεί να συνδέσει άμεσα blinded withdrawal με spend· τα tokens μετακινούνται ως data/QR.

**Cons:** mint custody/solvency/censorship· bearer data loss/theft· denomination/timing και Lightning boundaries· network metadata· early software ecosystem.<sup>[[12]](#references)</sup>

**Procedure:** (1) χρησιμοποίησε official test mint ή tiny disposable value πρώτα· (2) εγκατέστησε maintained wallet και δοκίμασε backup/restore limitations· (3) κάνε authenticate mint και έλεγξε custody/fees· (4) κάνε mint μικρό amount· (5) στείλε token μέσω authenticated private channel/QR· (6) ο receiver κάνει swap το token πριν το θεωρήσει final· (7) κάνε redeem και reconcile. Μην αποθηκεύεις meaningful value σε untrusted mint.

**Detection:** το mint βλέπει network, issue/redeem/Lightning boundaries και spent-token set, αλλά το blinding αφαιρεί το direct token linkage· endpoints/messages και distinctive amount/timing μπορούν να επαναφέρουν links.

## Fedimint federated e-cash

**Mechanics:** threshold guardians διατηρούν reserves και κάνουν blind-sign e-cash· τα internal bearer transfers είναι private από τους guardians, ενώ Lightning gateways γεφυρώνουν external payments.

**Pros:** distributed custody· private internal transfer· community governance· κανένας guardian δεν ελέγχει μόνος του το reserve κάτω από το threshold.

**Cons:** guardian quorum/custody/software risk· gateway παρατηρεί invoices/timing· deposit/withdraw boundaries· complexity στην ανάκτηση client state.

**Procedure:** (1) επαλήθευσε federation invite/guardians/quorum/jurisdiction· (2) εγκατέστησε maintained client και δοκίμασε recovery· (3) κάνε deposit small lawful amount· (4) χρησιμοποίησε fresh internal payment requests· (5) αντιμετώπισε το gateway ως observer για Lightning· (6) δοκίμασε redemption· (7) κράτησε source/tax records εκτός public payment data.<sup>[[13]](#references)</sup>

**Detection:** η federation βλέπει aggregate issuance/redemption, τα gateways βλέπουν external invoices, Bitcoin/Lightning δείχνουν boundaries και endpoint/communication evidence μπορεί να συνδέσει internal transfers.

## GNU Taler

**Mechanics:** bank-integrated blind-signature e-cash που στοχεύει να κρατά τον payer anonymous από τους merchants, ενώ οι merchants και το income παραμένουν accountable.

**Pros:** payer privacy by design· ordinary currency· merchant accountability/refunds· δεν απαιτείται speculative token.

**Cons:** limited deployments· exchange/bank βλέπει funding· merchant βλέπει order/delivery· wallet bearer/recovery risk· regulated operators.

**Procedure:** (1) βρες current exchange/merchant για τη jurisdiction/currency· (2) διάβασε KYC/fees/privacy· (3) εγκατέστησε official wallet· (4) κάνε lawful withdrawal από supported bank/exchange· (5) έλεγξε merchant contract· (6) πλήρωσε και κράτησε receipt/refund data· (7) απόφυγε περιττά merchant session identifiers.<sup>[[14]](#references)</sup>

**Detection:** bank/exchange withdrawal και merchant deposit είναι accountable boundaries· merchant order/device/delivery και timing μπορεί να συσχετιστούν ακόμη και όταν τα coins είναι blinded.

## Cross-chain bridge, atomic swap και decentralized exchange

**Mechanics:** contract/service κλειδώνει/καίει ένα asset και απελευθερώνει/κάνει mint άλλο, ή counterparties κάνουν atomic exchange. Αυτό διασπά την single-ledger view, όχι την οικονομική συνέχεια.

**Pros:** asset/network interoperability· μπορεί να αποφύγει έναν centralized custodian· ordinary portfolio/liquidity use.

**Cons:** και τα δύο chains είναι public· time/value/fees/liquidity και contracts συσχετίζονται· bridge/relayer/frontend/RPC records· smart-contract/counterparty και regulatory risk.

**Procedure for lawful swaps:** (1) επαλήθευσε official contract/service και legal availability· (2) έλεγξε custody/audit/fees/slippage· (3) κάνε small test· (4) κατέγραψε και τα δύο transaction IDs και rate· (5) προστάτευσε approvals· (6) κάνε reconcile το destination asset και revoke unnecessary approval. Μην χρησιμοποιείς swaps για να συγκαλύψεις την προέλευση funds.

**Detection:** bridge deposit/withdraw events, unique amount minus fees, time order, liquidity, relayer/RPC/frontend και later service deposits.

## Centralized mixer ή tumbler

**Mechanics:** service λαμβάνει deposits σε pool και επιστρέφει διαφορετικές units αργότερα, προσπαθώντας να αποκρύψει το direct input-output mapping.

**Pros:** θεωρητικά μπορεί να διευρύνει transaction ambiguity.

**Cons:** operator μπορεί να κλέψει/καταγράψει· entry/exit timing/value analysis· sanctions/money-transmission και criminal exposure· seizures αποκαλύπτουν mappings· taint/rejection risk.

**Procedure:** δεν παρέχεται operational mixing guide. Αναπαρήγαγε με ασφάλεια το graph επεκτείνοντας το [Lab 6](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph): δημιούργησε synthetic deposits, pooled outputs, fees και delays· δώσε στους analysts incomplete mappings· μέτρησε ποια heuristics λειτουργούν· έπειτα αποκάλυψε το ground truth.

**Detection:** service wallet/contract identification, entry/exit candidate sets, amount/fee/timing, deposit address reuse, seized/provider logs και downstream consolidation. Σήμανε την attribution ως probabilistic.

## Peel chains, fan-out/fan-in και structuring

**Mechanics:** repeated transactions αποσπούν μικρές πληρωμές από change, διαμοιράζουν value σε πολλές addresses, επανασυγκλίνουν σε collectors ή διαιρούν amounts για να αποφύγουν review.

**Pros:** αυξάνει το workload και τον αριθμό addresses για naive analysts.

**Cons:** recognizable value/cadence/transaction continuity· consolidation και service endpoints· το structuring μπορεί να είναι παράνομο· fees και operational errors.

**Procedure:** χρησιμοποίησε μόνο synthetic CSV/testnet data: δημιούργησε μεγάλο source, repeated payment/change edges, parallel branches και έναν collector· πρόσθεσε benign exchange-like examples· ρύθμισε detection και τεκμηρίωσε false positives.

**Detection:** graph continuity, repeated change pattern, cadence, just-below-control amounts, common service endpoint και off-chain records. Τα exchange hot wallets μπορεί να μοιάζουν με αυτά τα patterns, επομένως το context είναι υποχρεωτικό.<sup>[[15]](#references)</sup>

## Nominee, money mule, OTC broker και front company

**Mechanics:** άλλο πρόσωπο/account/company λαμβάνει, μετατρέπει ή δαπανά funds, εισάγοντας legal και operational layers μεταξύ controller και transaction.

**Pros to an adversary:** ο named account δεν ταυτοποιεί αμέσως τον controller· μπορεί να γεφυρώνει cash, crypto, goods και jurisdictions.

**Cons:** identity fraud/money-laundering exposure· κάθε participant προσθέτει communications, bank/company/tax/shipping records, fees, inconsistencies και witnesses· facilitator reuse δημιουργεί hubs.

**Procedure:** μην το προσομοιώνεις με πραγματικούς ανθρώπους/accounts. Δημιούργησε synthetic graph με controller, recruiter, mule, OTC, shell merchant και beneficiary· πρόσθεσε device/IP/message/bank edges· ζήτησε από investigators να διακρίνουν account holder από controller και να καταγράψουν evidence confidence.

**Detection:** shared device/IP/recovery, unusual beneficiary/velocity, πολλοί unrelated senders, immediate onward movement, company/director/invoice inconsistency, communications και cash/commodity delivery.

## NFTs, gambling, merchant goods και refund loops

**Mechanics:** το value μετατρέπεται σε self-priced asset, wagering balance, resalable goods ή refunds για να δημιουργηθεί διαφορετικό transaction narrative.

**Pros to an adversary:** αλλάζει τη μορφή του asset και εισάγει marketplace/merchant intermediaries.

**Cons:** marketplace/account/device και wash-trade graph· odds/play και refund records· delivery/resale evidence· fees/losses· fraud/laundering liability.

**Procedure:** δεν παρέχεται concealment workflow. Χρησιμοποίησε synthetic marketplace data με related-wallet self-trades, implausible pricing, minimal play, mismatched refund instrument και common shipping· επικύρωσε το detection έναντι legitimate collectors/customers.

**Detection:** circular/self-funded trades, common ownership/funding, price outliers, immediate resale/refund, minimal economic activity, shared device/delivery και proceeds reconvergence.

## Physical bearer wallet ή offline token transfer

**Mechanics:** device, paper/QR, hardware bearer instrument ή e-cash token μεταφέρει τον έλεγχο ενός secret αντί να κάνει broadcast payment κατά την παράδοση.

**Pros:** κανένα live network event κατά την exchange· χρήσιμο offline· physical cash-like custody.

**Cons:** copy/theft/loss και αβέβαιο exclusivity· later redemption/broadcast links· physical meeting/shipping· counterfeit/tamper risk.

**Procedure:** (1) χρησιμοποίησε μόνο reviewed instrument/protocol· (2) αρχικοποίησε/επαλήθευσε authenticity privately· (3) φόρτωσε μόνο small lawful value· (4) κάνε transfer σε documented authorized context· (5) ο receiver επαληθεύει ή κάνει sweep promptly όπως απαιτεί το protocol· (6) μην υποθέτεις ότι ο sender δεν κράτησε αντίγραφο· (7) κράτησε ownership/tax evidence privately.

**Detection:** purchase/funding και eventual sweep/redemption, device serial/tamper evidence, delivery/meeting και endpoint records.

## Merchant-scoped invoice ή one-time payment request

**Mechanics:** ο merchant δημιουργεί single-use request με amount, expiry και order reference. Ο payer το εξοφλεί μέσω supported rail χωρίς να εκθέτει reusable credential απευθείας στον merchant· ο issuer ή payment processor μπορεί να ταυτοποιεί και τις δύο πλευρές.

**Pros:** περιορίζει credential reuse και accidental cross-merchant identifiers· exact amount/expiry μειώνουν errors· συμβατό με ordinary accounting και refunds.

**Cons:** invoice, delivery, browser, processor και issuer εξακολουθούν να συνδέουν το order· unique amount/time μπορεί να ενισχύσει το correlation· malicious payment links είναι συνηθισμένα.

**Procedure:** (1) κάνε authenticate τον merchant independently· (2) ζήτησε fresh invoice με exact amount, asset/network και expiry· (3) έλεγξε destination και refund rules· (4) πλήρωσε από το approved engagement compartment· (5) επιβεβαίωσε ότι ο merchant αναγνωρίζει το ίδιο invoice· (6) κράτησε receipt και transaction reference· (7) άφησε το request να λήξει αντί να το επαναχρησιμοποιήσεις.

**Detection:** merchant και processor ενώνουν invoice, session και settlement· unique amounts/timing και delivery ταυτοποιούν τον payer. **Captured wallet/device:** το invoice history αποκαλύπτει counterparties και purpose· ελαχιστοποίησε unnecessary memo data, κρυπτογράφησε τη συσκευή και κράτησε το authoritative accounting στο controlled finance system.

## Prepaid service credit και capability token

**Mechanics:** service μετατρέπει conventional payment σε bounded internal credits ή bearer capability. Η subsequent API/resource use μπορεί να αποφεύγει την παρουσίαση της original card σε κάθε request, αλλά η service συχνά μπορεί να αντιστοιχίσει issuance με redemption.

**Pros:** περιορίζει spend και compromise loss· διαχωρίζει day-to-day workers από το funding credential· υποστηρίζει per-project budgets και revocation.

**Cons:** συνήθως pseudonymous, όχι anonymous· service database, redemption IP και unique usage pattern συνδέουν τη δραστηριότητα· bearer tokens μπορεί να κλαπούν· refunds μπορεί να απαιτούν τον original payer.

**Procedure:** (1) αγόρασε credits μέσω organization account· (2) δημιούργησε ένα project και budget· (3) έκδωσε narrow token με service, amount και expiry constraints· (4) αποθήκευσέ το μόνο σε approved secret manager ή workload identity path· (5) δοκίμασε rejection εκτός scope και μετά το expiry· (6) παρακολούθησε consumption· (7) κάνε revoke και reconcile unused value.

**Detection:** provider ενώνει funding account, project, token issuance και usage· defenders κάνουν alert σε geographic/process changes και anomalous consumption. **Captured node:** υπέθεσε ότι το remaining capability μπορεί να δαπανηθεί· χρησιμοποίησε short expiry, low balance, audience binding και immediate server-side revocation.

## Privacy Pass ή blinded authorization token

**Mechanics:** issuer παράγει privacy-preserving authorization token που το origin μπορεί να επικυρώσει χωρίς να συνδέει redemption με issuance. Μπορεί να αντιπροσωπεύει paid entitlement ή rate-limited access, αλλά δεν είναι general currency. Η architecture διαχωρίζει client, attester, issuer και origin roles και προειδοποιεί ότι IP/timing ή collusion μπορούν να ακυρώσουν το unlinkability.<sup>[[18]](#references)</sup>

**Pros:** unlinkable redemption για supported services· κανένα reusable account cookie στο origin· cached tokens μπορούν να διαχωρίζουν issuance και use χρονικά.

**Cons:** application-specific· issuer/attester trust και anonymity-set partitioning· IP και browser metadata παραμένουν· token theft ή distinctive issuance timing μπορεί να συσχετίσει τη χρήση.

**Procedure:** (1) χρησιμοποίησε implementation συμβατό με το relevant Privacy Pass token type· (2) όρισε ακριβώς ποιο entitlement αποδεικνύει το token· (3) διαχώρισε issuer και origin administration όπου το απαιτεί το threat model· (4) ελαχιστοποίησε challenge metadata· (5) έκδωσε αρκετά test tokens και κάνε redeem από μία φορά σε owned origins· (6) σύγκρινε logs για απαγορευμένα stable identifiers· (7) δοκίμασε replay, expiry και revocation/abuse controls.

**Detection:** origins βλέπουν redemption IP/time και token validity· issuers/attesters βλέπουν issuance context· οι analysts δοκιμάζουν timing και metadata partitions χωρίς να υποθέτουν cryptographic break. **Captured client:** unspent bearer tokens μπορεί να χρησιμοποιηθούν· περιόρισε value, lifetime και audience και μην αποθηκεύεις ποτέ το funding credential μαζί τους.

## Delegated organization procurement ή fiscal sponsor

**Mechanics:** authorized procurement team, reseller ή fiscal sponsor συνάπτει contract και πληρώνει, ενώ η operational team λαμβάνει bounded service. Πρόκειται για role separation με truthful records, όχι nominee ή false identity.

**Pros:** οι vendors δεν χρειάζεται να λάβουν την identity ή personal payment details κάθε operator· central compliance, tax και refund handling· σαφές budget και offboarding.

**Cons:** ο sponsor γνωρίζει beneficiary και purpose· contracts, approvals, delivery και accounts παραμένουν· πρόσθετη καθυστέρηση/fees· αδύναμος διαχωρισμός αν το ίδιο άτομο διαχειρίζεται κάθε layer.

**Procedure:** (1) τεκμηρίωσε business purpose, beneficiary και approving authority· (2) επίλεξε organization-approved intermediary· (3) σύναψε contract με truthful details· (4) provision project-scoped subaccount χωρίς personal billing credential· (5) διαχώρισε finance administrators από operators· (6) κάνε reconcile invoices και access· (7) τερμάτισε service και delegated access στο closeout.

**Detection:** procurement, identity-provider, vendor και delivery records ενώνουν την αλυσίδα. **Captured operational device:** πρέπει να αποκαλύπτει το service project αλλά όχι finance credentials· κράτησε invoices και payer identities στο finance system, όχι σε field nodes.

## Escrow ή conditional settlement

**Mechanics:** trusted escrow agent ή smart contract κρατά value μέχρι να ικανοποιηθούν documented conditions. Μπορεί να μειώσει την άμεση disclosure μεταξύ payer και payee, ενώ το escrow και τα underlying payment rails διατηρούν τη σχέση.

**Pros:** dispute και delivery protection· payer και merchant μπορούν να εκθέσουν λιγότερα reusable credentials ο ένας στον άλλον· auditable release conditions.

**Cons:** escrow custody/contract risk, fees και identity obligations· on-chain contracts είναι public· order, shipping και dispute data παραμένουν· όχι anonymous από τον intermediary.

**Procedure:** (1) επαλήθευσε legal entity, custody, fees, dispute forum και supported assets· (2) δημιούργησε ακριβές γραπτό milestone και refund path· (3) χρηματοδότησε από approved organization account· (4) επαλήθευσε receipt και release authorization independently· (5) κάνε release μόνο μετά από evidence· (6) κράτησε complete audit record· (7) κλείσε unused permissions ή contract approvals.

**Detection:** escrow account/contract events, funding και release time, beneficiary και dispute records αποκαλύπτουν τη transaction. **Captured device:** session tokens ή contract approvals μπορεί να επιτρέψουν release· απαίτησε separate approver/MFA και κάνε revoke active sessions σε περίπτωση απώλειας.

## Batched ή pooled organization settlement

**Mechanics:** πολλές approved obligations συγκεντρώνονται και εξοφλούνται σε λιγότερες bank ή blockchain transactions, με private internal ledger που αντιστοιχίζει κάθε share. Το batching μπορεί να μειώσει public per-purchase detail, αλλά ο coordinator διατηρεί complete attribution.

**Pros:** lower fees· λιγότερα public graph edges· κρύβει individual line items από public observer όταν τα amounts aggregating· straightforward internal accounting.

**Cons:** ο coordinator είναι complete observer και high-value target· distinctive totals/timing μπορεί να συσχετιστούν· custody και reconciliation risk· μπορεί να μοιάζει με structuring αν γίνει abuse.

**Procedure:** (1) όρισε participants και lawful obligations στο accounting system· (2) θέσε regular business-justified batch window αντί για thresholds σχεδιασμένα να αποφεύγουν controls· (3) απαίτησε dual approval του aggregate· (4) κάνε settle σε authenticated recipients· (5) κάνε reconcile κάθε internal line με το batch· (6) χειρίσου refunds ως linked corrections· (7) προστάτευσε ledger access και διατήρησέ το σύμφωνα με policy.

**Detection:** coordinator ledger, approval και beneficiary records παρέχουν ground truth· public analysts χρησιμοποιούν input/output/value/time clustering cautiously. **Captured payer device:** πρέπει να περιέχει μόνο το requisition του, όχι το pool signing key ή participant ledger.

## Account-abstraction paymaster ή sponsored gas

**Mechanics:** relayer/bundler υποβάλλει smart-account operation και paymaster πληρώνει transaction fees, αποφεύγοντας direct native-gas funding edge από το user wallet. Βελτιώνει μία ιδιότητα του graph· operation, contract και service telemetry παραμένουν public ή observable.<sup>[[19]](#references)</sup>

**Pros:** αφαιρεί common gas-funding link· υποστηρίζει scoped sponsorship και rate limits· καλύτερο onboarding για legitimate privacy applications.

**Cons:** paymaster/bundler/RPC/front end μπορεί να συσχετίζει requests· contract events και public inputs παραμένουν· sponsorship policy fingerprinting μιας cohort· malicious contracts ή approvals μπορούν να κλέψουν assets.

**Procedure:** (1) χρησιμοποίησε audited maintained smart account και paymaster στο σωστό network· (2) έλεγξε ποια fields είναι public και τι logs κρατά ο sponsor· (3) περιόρισε sponsorship ανά contract, function, amount, nonce και expiry· (4) δοκίμασε με low value· (5) κάνε submit μέσω του intended privacy-aware path της εφαρμογής· (6) επαλήθευσε operation και fee payer on chain· (7) κάνε revoke allowances/session keys και κράτησε compliance records.

**Detection:** ένωσε UserOperation, EntryPoint, paymaster, bundler/RPC και application logs· κάνε cautious clustering identical sponsorship policy. **Captured wallet:** session keys και pending approvals μπορεί να είναι usable ακόμη και χωρίς gas· περιόρισέ τα αυστηρά και κάνε revoke μέσω του account recovery policy.

## Threshold ή multisignature payment authorization

**Mechanics:** η δαπάνη απαιτεί threshold ανεξάρτητων signers. Δεν κρύβει τη transaction, αλλά επιτρέπει τον διαχωρισμό payment authority από οποιοδήποτε captured laptop, field node ή single operator.

**Pros:** ισχυρή αντίσταση σε compromise και insider· accountable approval· κανένα field device δεν έχει πλήρη signing authority· υποστηρίζει recovery.

**Cons:** coordination και availability· signer/device/account metadata μπορεί να συσχετίσει participants· κακό backup design προκαλεί loss· public multisig patterns μπορεί να είναι identifiable.

**Procedure:** (1) όρισε signers, threshold, limits και recovery πριν από το funding· (2) κάνε initialize σε separate supported hardware/accounts· (3) επαλήθευσε addresses και backups independently· (4) δώσε στα field workloads μόνο unsigned requisition capability· (5) απαίτησε out-of-band review recipient, amount και purpose· (6) δοκίμασε recovery και one-signer loss με small value· (7) κάνε rotate signer μετά από compromise.

**Detection:** approval system, signer device και public script/contract παρέχουν evidence· defenders κάνουν alert σε policy ή signer-set changes. **Captured node:** πρέπει να αποκαλύπτει το πολύ ένα low-authority session key ή unsigned request· μην αποθηκεύεις quorum material μαζί.

## Closed-loop community ή event currency

**Mechanics:** cooperative, conference ή private test environment εκδίδει credits που εξαργυρώνονται μόνο μεταξύ enrolled participants. Το internal transfer μπορεί να εκθέτει λιγότερα στοιχεία στα global payment networks, ενώ ο operator ελέγχει issuance και redemption.

**Pros:** bounded economic domain· μπορεί να δοκιμάσει offline ή privacy-preserving payment UX· περιορίζει external card exposure· σαφή experimental controls.

**Cons:** small anonymity set· operator και merchants παρατηρούν activity· limited acceptance/redemption· licensing, consumer-protection και tax rules μπορεί να ισχύουν ακόμη και για local value.

**Procedure:** (1) λάβε legal/compliance review και δημοσίευσε issuer terms· (2) κάνε enroll consenting test participants· (3) περιόρισε issuance και απαγόρευσε cash-like misuse· (4) χρησιμοποίησε fresh payment requests και ελαχιστοποίησε public participant identifiers· (5) κατέγραψε aggregate reserves και private individual receipts· (6) δοκίμασε loss/refund/redemption· (7) κλείσε το ledger και επέστρεψε residual value όπως υποσχέθηκες.

**Detection:** issuer ledger, enrollment, merchant και redemption records ανακατασκευάζουν τις flows· unusual circular transfers ή rapid cash-out απαιτούν review. **Captured wallet:** local balance και counterparties μπορεί να εκτεθούν· περιόρισε value, κρυπτογράφησε state και υποστήριξε issuer-side freeze/reissue με auditable record.

## Bitcoin reusable payment codes και private payment instructions

**Mechanics:** τα BIP 47 payment codes χρησιμοποιούν reusable public identifier και ECDH-derived one-time deposit addresses· το BIP 351 καθορίζει νεότερο private-payment instruction design. Μειώνουν public address reuse ενώ επιτρέπουν στον recipient να δημοσιεύει stable payment instructions. Notification, wallet support, funding και subsequent coin selection εξακολουθούν να επηρεάζουν το privacy.<sup>[[20]](#references)</sup>

**Pros:** μία public instruction μπορεί να παράγει distinct addresses· ο recipient δεν χρειάζεται να δημοσιεύει κάθε invoice address· compatible wallets μπορούν να παρακολουθούν derived payments· χρήσιμο για repeated lawful donors/customers.

**Cons:** wallet interoperability διαφέρει· notification transactions ή published payment code συνδέουν relationship context· sender, recipient και public graph εξακολουθούν να βλέπουν transactions· careless consolidation ή change handling ακυρώνουν το όφελος.

**Procedure:** (1) επιβεβαίωσε ότι και τα δύο maintained wallets υποστηρίζουν ακριβώς την ίδια specification/version· (2) κάνε backup και test recovery σε low-value wallet· (3) κάνε authenticate το recipient payment code out of band· (4) στείλε small lawful test· (5) επιβεβαίωσε ότι χρησιμοποιήθηκε fresh derived address· (6) βάλε local label στη σχέση και εφάρμοσε coin control· (7) δοκίμασε recovery και refund behavior πριν βασιστείς σε αυτό.

**Detection:** οι analysts εξετάζουν notification patterns, funding/change, later consolidation και service boundaries· η δημοσίευση public code αναγνωρίζει το recipient context ακόμη και όταν οι deposit addresses διαφέρουν. **Capture-resilient OPSEC:** κράτα spend keys εκτός field devices και εξέθεσε το πολύ watch-only relationship view. **Monitoring:** κάνε alert σε unexpected notification transactions, reused derived addresses, wallet gap-limit/recovery errors και unplanned consolidation.

## EVM stealth addresses (ERC-5564)

**Mechanics:** sender παράγει one-time stealth account από το stealth meta-address του recipient και δημοσιεύει announcement με ephemeral public key και view tag. Ο recipient κάνει scan announcements με viewing key και παράγει το αντίστοιχο spend key. Η recipient linkage βελτιώνεται, αλλά sender, amount/token, gas, announcement και later spending παραμένουν visible.<sup>[[21]](#references)</sup>

**Pros:** non-interactive fresh receiver address· reusable meta-address· separate viewing και spending roles· λειτουργεί σε supported EVM assets/applications.

**Cons:** announcement scanning και spam· funding gas για τη νέα address μπορεί να την επανασυνδέσει· ο sender γνωρίζει τον recipient· public token/amount και eventual consolidation παραμένουν· implementation και wallet support διαφέρουν.

**Procedure:** (1) χρησιμοποίησε audited maintained implementation πρώτα σε test network· (2) δημιούργησε separate viewing και spending material και κάνε backup· (3) κάνε authenticate το meta-address· (4) στείλε low-value test και announcement· (5) κάνε scan και derive το stealth account· (6) δοκίμασε supported gas sponsorship χωρίς personal funding edge· (7) κατέγραψε public fields και κράτησε lawful accounting.

**Detection:** ακολούθησε announcement caller, token/amount, timing, gas sponsor, spending και consolidation· ένα view key μπορεί να αποδείξει receipt χωρίς να επιτρέπει spend. **Capture-resilient OPSEC:** networked scanner πρέπει να έχει μόνο viewing role όπου υποστηρίζεται· κράτα spend και recovery keys αλλού. **Monitoring:** κάνε alert σε malformed/spam announcements, view-key access, unexpected spend derivation και stealth outputs που μετακινήθηκαν χωρίς approval.

## Liquid Confidential Transactions

**Mechanics:** το Liquid κάνει default blind τα output amounts και asset types μέσω commitments και proofs, ενώ αφήνει visible το transaction graph, input/output count, fee και block time. Peg-in/peg-out και service boundaries παραμένουν linkable και οι users μπορούν να κάνουν selective disclosure blinding data.<sup>[[22]](#references)</sup>

**Pros:** confidential amount και asset type by default· fast sidechain settlement· selective audit μέσω blinding keys/descriptors· κρύβει commercially sensitive values από public observers.

**Cons:** graph structure και timing παραμένουν· federation/bridge και exchange trust· peg boundaries και unconfidential outputs· wallet/node/network records· receiver και sender γνωρίζουν τη transaction τους.

**Procedure:** (1) επίλεξε maintained Liquid wallet και επαλήθευσε το backup model· (2) χρησιμοποίησε testnet ή small lawful amount· (3) λάβε σε confidential address και επιβεβαίωσε ότι το wallet χαρακτηρίζει το output ως blinded· (4) στείλε test confidential transaction· (5) έλεγξε ποια explorer fields παραμένουν public· (6) εξήγαγε μόνο το scoped blinding proof που απαιτείται για audit· (7) τεκμηρίωσε peg/exchange boundaries και κάνε reconcile funds.

**Detection:** ανάλυσε visible graph/fee/time, peg και exchange records, network metadata και later unblinding evidence· μην συμπεραίνεις hidden amount ή asset. **Capture-resilient OPSEC:** διαχώρισε spend seed, blinding/view data και watch-only operations. **Monitoring:** κάνε alert σε accidental unconfidential addresses, unknown peg requests, descriptor changes και unapproved unblinding-key export.

## General payment ή state channel

**Mechanics:** participants κλειδώνουν funds, ανταλλάσσουν signed off-chain state updates και δημοσιεύουν on chain μόνο opening, closing ή disputed state. Τα intermediate payments δεν γίνονται globally broadcast, αλλά peers και routing/intermediary services βλέπουν το τμήμα τους και τα endpoints πρέπει να διατηρούν το latest enforceable state.<sup>[[23]](#references)</sup>

**Pros:** πολλές fast low-fee interactions private-to-public-ledger· λιγότερο global transaction detail· bounded channel balance· χρήσιμο για metered services και repeated counterparties.

**Cons:** channel peers γνωρίζουν ο ένας τον άλλον και μπορούν να κρατούν updates· opening/closing/value/timing συσχετίζονται· μπορεί να απαιτείται online monitoring κατά τα challenge windows· implementation και liquidity risk· από μόνο του δεν είναι μεγάλο anonymity set.

**Procedure:** (1) επίλεξε maintained audited implementation και κατανόησε το dispute window· (2) άνοιξε low-value test channel μεταξύ owned parties· (3) αντάλλαξε signed state updates με unique nonces· (4) κάνε backup το latest enforceable state· (5) κλείσε cooperatively· (6) κάνε rehearse stale-state rejection στο testnet· (7) κράτησε accounting και channel-peer records.

**Detection:** public chain αποκαλύπτει lifecycle/disputes· peers, watch services και application transport αποκαλύπτουν off-chain timing και parties. **Capture-resilient OPSEC:** περιόρισε hot balance και κράτησε το latest signed state σε encrypted recoverable store ξεχωριστά από field nodes. **Monitoring:** παρακολούθησε συνεχώς stale-state publication, missed backup, peer-key change και approaching challenge deadline.

## Mobile carrier billing

**Mechanics:** online service χρεώνει purchase σε mobile subscription ή prepaid balance μέσω carrier billing system. Ο merchant μπορεί να λάβει carrier authorization αντί για card/bank details, ενώ ο carrier γνωρίζει subscriber/line, device/network context, merchant, amount και time.<sup>[[24]](#references)</sup>

**Pros:** κανένα card number στον merchant· ευρεία phone availability· χρήσιμο για low-value digital goods· ο carrier μπορεί να κάνει cap και reverse charges.

**Cons:** strongly identified από SIM/account και συχνά device· μικρά limits και υψηλά fees· merchant category restrictions· account takeover/SIM-swap risk· carrier και aggregator δημιουργούν πλήρες transaction trail.

**Procedure:** (1) επιβεβαίωσε availability, limit, fee και refund terms με το organization carrier account· (2) ενεργοποίησέ το μόνο σε dedicated organization line όταν δικαιολογείται· (3) όρισε το χαμηλότερο χρήσιμο spend cap· (4) αγόρασε benign test item· (5) επιβεβαίωσε merchant και carrier receipts· (6) απενεργοποίησε recurring authorization· (7) κάνε reconcile και απενεργοποίησε τη λειτουργία μετά την assessment.

**Detection:** carrier, aggregator και merchant records ενώνουν line, subscriber, IP/device και charge· enterprise telecom invoices το αποκαλύπτουν. **Capture-resilient OPSEC:** μην χρησιμοποιείς personal number και απαίτησε carrier-account MFA εκτός field device. **Monitoring:** ενεργοποίησε instant charge/SIM-change alerts και σταμάτησε σε unexpected premium-service enrollment, forwarding ή account recovery.

## Open-banking payment initiation

**Mechanics:** με explicit user consent, regulated payment-initiation service provider (PISP) ζητά από την account-servicing bank να ξεκινήσει transfer. Ο merchant μπορεί να μη λάβει card credentials, αλλά ο PISP και οι banks διατηρούν regulated payer, payee, consent, device και transaction records.<sup>[[25]](#references)</sup>

**Pros:** κανένα reusable card number στο checkout· ισχυρό bank authentication· exact account-to-account settlement· consent και status APIs· σαφές reconciliation.

**Cons:** όχι anonymous από banks/PISP· ο payee συχνά βλέπει legal account details ή reference· phishing/redirect risk· jurisdiction και refund protections διαφέρουν· consent metadata προσθέτει observer.

**Procedure:** (1) επαλήθευσε ότι ο PISP είναι currently regulated και ότι το merchant callback domain είναι authentic· (2) ξεκίνα από το merchant request· (3) έλεγξε payee, amount, reference και requested consent στην bank· (4) ενέκρινε μόνο τη single payment· (5) επαλήθευσε independently το final status· (6) κάνε revoke residual consent αν υπάρχει· (7) κράτησε receipt και κάνε reconcile.

**Detection:** bank/PISP/merchant logs και transfer references παρέχουν ισχυρό attribution. **Capture-resilient OPSEC:** κράτα banking authentication και recovery εκτός operational/field devices· η συσκευή πρέπει να διατηρεί μόνο paid-service entitlement. **Monitoring:** χρησιμοποίησε bank transaction/consent alerts και διερεύνησε νέα PISP grants, changed payee ή status callbacks εκτός expected session.

## Platform wallet, app-store balance ή in-app credit

**Mechanics:** platform χρεώνει τον user ή κάνει redeem account credit και έπειτα εκδίδει signed receipt ή entitlement σε application. Ο app developer μπορεί να μη λάβει το original funding instrument, ενώ η platform συνδέει account, device, funding, product και redemption.<sup>[[26]](#references)</sup>

**Pros:** merchant/developer δεν λαμβάνει primary PAN· fraud/refund και family/business controls· μικρό prepaid balance μπορεί να περιορίσει exposure· signed receipts απλοποιούν entitlement verification.

**Cons:** platform account είναι ισχυρό identity και behavior hub· device και storefront geography· gift-balance purchase/redemption trail· limited cash-out· fraud controls μπορεί να παγώσουν funds· δεν είναι cross-platform money.

**Procedure:** (1) χρησιμοποίησε organization-managed platform account όπου επιτρέπει η policy· (2) έλεγξε funding, region, refund και transferable-value rules· (3) πρόσθεσε μόνο το approved budget· (4) αγόρασε benign product μέσω official store· (5) επιβεβαίωσε ότι η application λαμβάνει μόνο τα expected receipt fields· (6) απενεργοποίησε recurring purchase· (7) κάνε reconcile και αφαίρεσε το account από operational hardware.

**Detection:** platform receipts/server notifications, account/device login και funding records ανακατασκευάζουν την purchase. **Capture-resilient OPSEC:** μην κάνεις ποτέ sign-in field node σε personal store account· παρείχε μόνο scoped app entitlement όπου είναι δυνατό. **Monitoring:** ενεργοποίησε new-device/purchase alerts και διερεύνησε receipt replay, family/account changes ή unexpected restore events.

## Mutual credit, clearing ή periodic net settlement

**Mechanics:** participants καταγράφουν obligations σε private ledger και περιοδικά εξοφλούν μόνο κάθε net position. Individual service events δεν χρειάζεται να δημιουργούν ξεχωριστές public payments, αλλά ο ledger operator και οι counterparties διατηρούν λεπτομερές attribution.

**Pros:** λιγότερες external transactions και fees· public observers βλέπουν μόνο net settlement· λειτουργεί για repeated organizations· explicit credit limits περιορίζουν exposure.

**Cons:** centralized ledger είναι πλήρες evidence και στόχος fraud· counterparty/default risk· legal/accounting/tax duties· μικρή membership set· unusual net transfers μπορεί να αποκαλύψουν σχέσεις.

**Procedure:** (1) χρησιμοποίησε μόνο identified consenting organizations με legal/accounting approval· (2) όρισε unit, credit limit, settlement interval και dispute rules· (3) κατέγραψε κάθε obligation με immutable approval· (4) ξεχωριστοί finance roles υπολογίζουν και εγκρίνουν net positions· (5) κάνε settle μέσω ordinary lawful rail· (6) κάνε reconcile individual lines με το settlement· (7) κλείσε access και κράτησε records σύμφωνα με policy.

**Detection:** ledger, invoices, approvals και final bank/chain settlement παρέχουν ground truth· οι analysts δεν πρέπει να συμπεραίνουν missing gross activity μόνο από το net transfer. **Capture-resilient OPSEC:** operational devices μπορούν να υποβάλλουν bounded requisitions αλλά δεν μπορούν να επεξεργαστούν balances ή να εγκρίνουν settlement. **Monitoring:** κάνε alert σε credit-limit breach, backdated entries, administrator changes, reconciliation mismatch και settlement σε νέο beneficiary.

## Capture/compromise exposure matrix

Αυτό εφαρμόζει seizure/loss test σε κάθε family. Στόχος είναι ο περιορισμός spend authority και unrelated identity disclosure, με διατήρηση lawful accounting, όχι η διαγραφή transactions ή η παρεμπόδιση investigation.

| Οικογένεια technique | Τι μπορεί να αποκαλύψει captured wallet/device/account | Ελάχιστος authorized control |
|---|---|---|
| Cash, money order, COD, physical bearer value | receipts, serials, notes, remaining bearer value και physical contacts | μόνο approved amount· separate private accounting· prompt loss report· no false records |
| Prepaid, gift, voucher, service credits | balance, issuer, activation, redemption και account/session tokens | low balance· one purpose· truthful registration· issuer freeze/revocation όπου υπάρχει |
| Virtual/tokenized card, wallet token, payment app | issuer account, device token, transactions, recovery και merchant history | device lock· transaction alerts· merchant scope· remote issuer suspension· no shared recovery account |
| Bank compartment, delegated procurement, red-team procurement | organization, approvers, vendor, invoices και project | role separation· least-privilege subaccount· finance credentials ποτέ σε operational/field nodes |
| Invoice, escrow, batch settlement | counterparty, purpose, pending approval, coordinator ή dispute trail | single-use request· separate approver· limited session· central authoritative ledger |
| Bitcoin, Silent Payments, PayJoin/CoinJoin | seed/keys, labels, addresses, transaction graph και network configuration | hardware/offline signing· encrypted wallet· passphrase limits· watch-only field view· documented recovery |
| Lightning/BOLT 12 | seed, channels, invoices, peers/LSP και payment database | minimal hot balance· encrypted backup· separate node identity· close/recover per documented plan |
| Monero, Zcash, MWEB, ZK applications | spend/view keys, local wallet history, RPC και boundary transactions | separate spend/view roles· hardware support όπου υπάρχει· no exchange session on field node |
| Stablecoins, swaps, bridges και DEX | transparent graph, approvals, RPC/front-end state και destination assets | revoke allowances· verified contracts· low-value test· complete reconciliation |
| Cashu, Fedimint, Taler, Privacy Pass | bearer tokens, mint/federation/exchange, issuance/redemption cache | small balance· encrypted backup όπως υποστηρίζει το protocol· redeem/reissue· never colocate funding credential |
| Paymaster, multisig/threshold | session key, one signer, pending operations και sponsor policy | narrow session key· independent quorum· signer rotation· field device cannot reach threshold |
| Mixer/peel/structuring, nominees/fronts, refund/gambling abuse | incriminating provider, communications, graph και participant records | no operational use· emulate μόνο με synthetic/testnet evidence |
| Community/event currency | enrollment, local balance, counterparties και redemption | capped value· issuer freeze/reissue· consent και private auditable ledger |
| Reusable Bitcoin/EVM stealth address | payment/view/spend keys, relationship metadata, announcements και derived outputs | watch/view-only network role· offline/hardware spend role· no personal funding session |
| Liquid confidential/state channels | seed, blinding data/latest state, peers, boundaries και disputes | separate spend/view/state backup· low hot balance· independent dispute monitor |
| Carrier/open-banking/platform billing | phone/bank/store account, consent, receipt, device και funding source | organization account· external MFA· low limit· no personal account on field hardware |
| Mutual-credit clearing | members, obligations, limits, approvals και settlement ledger | operational requisition only· separate immutable ledger και dual finance approval |

## Monitoring possible discovery ή payment compromise

Payment denial, compliance review ή wallet που τίθεται offline δεν αποδεικνύουν investigation. Παρακολούθησε μόνο accounts, ledgers και infrastructure που ο οργανισμός δικαιούται να παρατηρεί· μην κάνεις probe σε providers ή counterparties για να ελέγξεις αν συνεργάζονται με investigators.

| Covered techniques | Safe monitoring signals | Freeze/stop condition |
|---|---|---|
| Cash, money order/COD, prepaid/gift/voucher, physical bearer value | inventory/receipt mismatch, duplicate serial, unexpected redemption/refund ή loss report | missing instrument, redemption εκτός approved order, altered receipt ή custody break |
| Virtual/tokenized card, payment app, bank/ACH/wire, open banking, carrier/platform billing | issuer/bank/platform alerts, new device/consent/payee, token reuse, SIM/account recovery | unknown authorization, payee change, new recovery factor, SIM swap ή recurring charge |
| Account/merchant compartment, controlled/delegated procurement, service credits | IdP/vendor project, role/token/budget change, invoice και consumption | cross-project token, unknown admin, limit breach, invoice mismatch ή unsupported destination |
| Invoice, escrow, pooled settlement, mutual credit | request expiry, approval/release, ledger integrity, reconciliation και beneficiary change | altered amount/payee, backdated ledger, unilateral release ή unreconciled batch |
| Bitcoin address/coin control, Silent Payments, BIP47/BIP351 | watch-only transactions, notification/scan state, address reuse, UTXO labels και consolidation | unknown spend, reused recipient output, wallet gap/recovery failure ή unapproved merge |
| PayJoin/CoinJoin | proposal inputs/outputs/fees, coordinator availability, final transaction equality | substituted output, excessive fee, unexpected input disclosure ή coordinator policy change |
| Lightning/BOLT12/general channels | channel backup, invoice/offer use, liquidity, peer/LSP και chain dispute | unknown invoice payment, peer-key change, stale close ή approaching dispute deadline |
| Monero/Zcash/MWEB/Liquid CT | view/watch events, pool/domain/address type, descriptor και boundary transaction | spend without approval, transparent/unconfidential downgrade, key export ή unknown boundary |
| Ethereum ZK, stealth addresses, paymaster, stablecoin | contract/announcement, RPC/bundler, gas sponsor, allowance/session key και issuer action | wrong contract/public field, unknown approval/spend, paymaster change ή issuer freeze |
| Cashu/Fedimint/Taler/Privacy Pass | mint/federation/exchange health, token double-spend/replay, gateway και bearer balance | unknown redemption, mint key/terms change, restore failure ή balance inconsistency |
| Swaps/bridges/DEX | verified contract, allowance, both-chain confirmations, rate και destination | contract/route mismatch, unlimited approval, missing destination ή bridge incident |
| Multisig/threshold | signer-set/policy change, pending proposal, quorum και recovery audit | unknown proposal/signer, threshold reduction, recovery activation ή policy bypass |
| Mixer/peel/structuring, nominees/fronts, NFT/gambling/refund abuse | μόνο synthetic lab ground truth και detection output | οποιοσδήποτε real account, person ή value μπει στην emulation: stop immediately |

## Selection και verification workflow

1. Καθόρισε ποιο party δεν πρέπει να μάθει ποιο field.
2. Εντόπισε issuer/mint/custodian, public ledger, network/RPC, merchant και physical observers.
3. Επαλήθευσε current support, legality, limits, custody, recovery και refund behavior.
4. Κάνε small lawful end-to-end test.
5. Έλεγξε merchant receipt, provider statement, public chain και wallet/node logs.
6. Δοκίμασε backup/recovery και deliberate audit disclosure.
7. Κράτησε τα απαιτούμενα source, ownership, tax, sanctions και engagement records accurate αλλά access-controlled.

## References

- [1] [EMVCo — Payment Tokenisation](https://www.emvco.com/emv-technologies/payment-tokenisation/)
- [2] [US CFPB — Observations on data collection by large payment platforms](https://files.consumerfinance.gov/f/documents/cfpb_privacy-rfi-2025-01.pdf)
- [3] [Bitcoin.org — Protect your privacy](https://bitcoin.org/en/protect-your-privacy)
- [4] [BIP 352 — Silent Payments](https://bips.dev/352/)
- [5] [BIP 78 — A Simple Payjoin Proposal](https://bips.dev/78/)
- [6] [Lightning BOLT 4 — Onion Routing Protocol](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)
- [7] [Lightning BOLT 12 — Offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md)
- [8] [Monero Documentation — Technical specifications and network privacy](https://docs.getmonero.org/technical-specs/)
- [9] [ZIP 224 — Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [10] [Litecoin — Mimblewimble Extension Blocks](https://litecoin.com/projects/mweb)
- [11] [Ethereum.org — Building privacy applications with zero-knowledge proofs](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [12] [Cashu — Protocol and privacy limitations](https://docs.cashu.space/faq)
- [13] [Fedimint — How it works](https://fedimint.org/users/how-it-works)
- [14] [GNU Taler documentation](https://docs.taler.net/)
- [15] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [16] [US FinCEN — Administrators, exchangers and users of virtual currency](https://www.fincen.gov/resources/statutes-regulations/guidance/application-fincens-regulations-persons-administering)
- [17] [EU Regulation 2023/1113 — transfer information and crypto-assets](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32023R1113)
- [18] [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html) and [RFC 9577 — Privacy Pass HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html)
- [19] [ERC-4337 — Account Abstraction Using an Alternative Mempool](https://eips.ethereum.org/EIPS/eip-4337) and [Ethereum.org — Privacy application architecture](https://ethereum.org/latest/privacy-apps-on-ethereum/)
- [20] [BIP 47 — Reusable Payment Codes](https://bips.dev/47/) and [BIP 351 — Private Payments](https://bips.dev/351/)
- [21] [ERC-5564 — Stealth Addresses](https://eips.ethereum.org/EIPS/eip-5564)
- [22] [Liquid — Confidential Transactions](https://docs.liquid.net/docs/confidential-transactions)
- [23] [Ethereum.org — State and payment channels](https://ethereum.org/developers/docs/scaling/state-channels/)
- [24] [GSMA Open Gateway — Carrier Billing API](https://open-gateway.gsma.com/docs/carrier-billing/api-reference)
- [25] [Open Banking Standards — Payment Initiation Services](https://standards.openbanking.org.uk/customer-experience-guidelines/payment-initiation-services/v4-0/)
- [26] [Apple Developer — StoreKit](https://developer.apple.com/documentation/storekit/)
{{#include ../banners/hacktricks-training.md}}
