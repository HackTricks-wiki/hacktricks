# Side-Channel Attacks μέσω Delivery Receipts σε E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Τα delivery receipts είναι υποχρεωτικά στα σύγχρονα end-to-end encrypted (E2EE) messengers, επειδή οι clients πρέπει να γνωρίζουν πότε έγινε decrypt ένα ciphertext, ώστε να μπορούν να απορρίψουν την κατάσταση του ratchet και τα ephemeral keys. Ο server προωθεί opaque blobs, επομένως τα acknowledgements των συσκευών (διπλά checkmarks) αποστέλλονται από τον recipient μετά από επιτυχημένο decryption. Η μέτρηση του round-trip time (RTT) μεταξύ μιας ενέργειας που προκαλεί ο attacker και του αντίστοιχου delivery receipt αποκαλύπτει ένα timing channel υψηλής ανάλυσης που κάνει leak την κατάσταση της συσκευής και την online παρουσία, ενώ μπορεί να χρησιμοποιηθεί για covert DoS. Οι deployments πολλαπλών συσκευών με "client-fanout" ενισχύουν το leak, επειδή κάθε registered device κάνει decrypt το probe και επιστρέφει το δικό του receipt.<sup>[[1]](#references)</sup>

## Πηγές delivery receipts έναντι signals που βλέπει ο user

Επίλεξε message types που εκδίδουν πάντα delivery receipt, αλλά δεν εμφανίζουν UI artifacts στο victim. Ο παρακάτω πίνακας συνοψίζει τη συμπεριφορά που επιβεβαιώθηκε εμπειρικά:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Πάντα noisy → χρήσιμο μόνο για bootstrap του state. |
| | Reaction | ● | ◐ (μόνο αν γίνεται reaction σε μήνυμα του victim) | Τα self-reactions και οι removals παραμένουν silent. |
| | Edit | ● | Silent push, ανάλογα με την πλατφόρμα | Edit window ≈20 min· εξακολουθεί να γίνεται ack μετά τη λήξη. |
| | Delete for everyone | ● | ○ | Το UI επιτρέπει περίπου ~60 h, αλλά τα μεταγενέστερα packets εξακολουθούν να λαμβάνουν ack. |
| **Signal** | Text message | ● | ● | Ίδιοι περιορισμοί με το WhatsApp. |
| | Reaction | ● | ◐ | Τα self-reactions είναι αόρατα στον victim. |
| | Edit/Delete | ● | ○ | Ο server επιβάλλει window ~48 h και επιτρέπει έως 10 edits, αλλά τα late packets εξακολουθούν να λαμβάνουν ack. |
| **Threema** | Text message | ● | ● | Τα multi-device receipts γίνονται aggregate, επομένως είναι ορατό μόνο ένα RTT ανά probe. |

Legend: ● = πάντα, ◐ = υπό προϋποθέσεις, ○ = ποτέ. Η συμπεριφορά του UI που εξαρτάται από την πλατφόρμα σημειώνεται inline. Απενεργοποίησε τα read receipts αν χρειάζεται, αλλά τα delivery receipts δεν μπορούν να απενεργοποιηθούν στο WhatsApp ή στο Signal.<sup>[[1]](#references)</sup>

## Στόχοι και μοντέλα του attacker

* **G1 – Device fingerprinting:** Μέτρησε πόσα receipts φτάνουν ανά probe, ομαδοποίησε τα RTTs για να συμπεράνεις OS/client (Android έναντι iOS ή desktop) και παρακολούθησε τις μεταβάσεις online/offline.
* **G2 – Behavioural monitoring:** Αντιμετώπισε τη high-frequency σειρά RTT (≈1 Hz είναι σταθερό) ως time-series και συμπέρανε screen on/off, app foreground/background, ώρες μετακίνησης έναντι εργασίας κ.λπ.
* **G3 – Resource exhaustion:** Διατήρησε τα radios/CPUs κάθε victim device ενεργά στέλνοντας endless silent probes, εξαντλώντας battery/data και υποβαθμίζοντας την ποιότητα VoIP/RTC.<sup>[[1]](#references)</sup>

Δύο threat actors αρκούν για την περιγραφή του abuse surface:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Ήδη μοιράζεται ένα chat με τον victim και κάνει abuse σε self-reactions, reaction removals ή repeated edits/deletes που συνδέονται με υπάρχοντα message IDs.
2. **Spooky stranger:** Κάνει register έναν burner account και στέλνει reactions που αναφέρονται σε message IDs τα οποία δεν υπήρξαν ποτέ στην τοπική συνομιλία. Το WhatsApp και το Signal εξακολουθούν να κάνουν decrypt και acknowledge, παρότι το UI απορρίπτει την αλλαγή του state, επομένως δεν απαιτείται προηγούμενη συνομιλία.

## Tooling για raw protocol access

Βασίσου σε clients που εκθέτουν το underlying E2EE protocol, ώστε να μπορείς να δημιουργείς packets εκτός των περιορισμών του UI, να καθορίζεις αυθαίρετα `message_id`s και να καταγράφεις ακριβή timestamps:

* **WhatsApp:** Τα [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ή [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) επιτρέπουν την αποστολή raw `ReactionMessage`, `ProtocolMessage` (edit/delete) και `Receipt` frames, διατηρώντας συγχρονισμένο το double-ratchet state.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** Το [signal-cli](https://github.com/AsamK/signal-cli), σε συνδυασμό με το [libsignal-service-java](https://github.com/signalapp/libsignal-service-java), εκθέτει κάθε message type μέσω CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> Η τρέχουσα σύνταξη του `signal-cli` χρησιμοποιεί `sendReaction RECIPIENT --target-author --target-timestamp`· διατήρησε το `receive` ή το `daemon` σε λειτουργία, ώστε να συλλέγονται πράγματι τα delivery receipts.<sup>[[6]](#references)</sup> Παράδειγμα self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Ο source code του Android client τεκμηριώνει τον τρόπο με τον οποίο τα delivery receipts ενοποιούνται πριν φύγουν από τη συσκευή, εξηγώντας γιατί το side channel έχει negligible bandwidth εκεί.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** Το [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) περιλαμβάνει WhatsApp/Signal backends, χρησιμοποιεί ως default silent delete probes και χαρακτηρίζει τις καταστάσεις `active` έναντι `standby` με rolling-median threshold (`RTT < 0.9 * median`). Το [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) είναι ένα ελαφρύτερο WhatsApp-first CLI με `--delay`, `--concurrent`, CSV/Prometheus exporters και Grafana-friendly output.<sup>[[8]](#references)</sup> Αντιμετώπισε και τα δύο ως reconnaissance helpers και όχι ως protocol references· το σημαντικό συμπέρασμα είναι πόσο λίγος code απαιτείται όταν υπάρχει raw client access.

Όταν δεν είναι διαθέσιμο custom tooling, μπορείς ακόμη να προκαλέσεις silent actions από το WhatsApp Web ή το Signal Desktop και να κάνεις sniff το encrypted websocket/WebRTC channel, αλλά τα raw APIs αφαιρούν τις καθυστερήσεις του UI και επιτρέπουν invalid operations.

## Creepy companion: silent sampling loop

1. Επίλεξε οποιοδήποτε historical message που έχεις γράψει εσύ στο chat, ώστε ο victim να μη δει ποτέ να αλλάζουν τα "reaction" balloons.
2. Κάνε εναλλαγή μεταξύ ενός visible emoji και ενός empty reaction payload (κωδικοποιημένου ως `""` στα WhatsApp protobufs ή ως `--remove` στο signal-cli). Κάθε transmission αποδίδει device ack, παρότι δεν υπάρχει UI delta για τον victim.
3. Κατέγραψε timestamp για τον χρόνο αποστολής και για κάθε άφιξη delivery receipt. Ένα loop 1 Hz όπως το παρακάτω παρέχει per-device RTT traces επ' αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή τα WhatsApp/Signal δέχονται unlimited reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο chat content ούτε να ανησυχεί για edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing αυθαίρετων phone numbers

1. Κάνε register έναν νέο WhatsApp/Signal account και ανάκτησε τα public identity keys για τον target number (αυτό γίνεται αυτόματα κατά το session setup).
2. Δημιούργησε ένα reaction/edit/delete packet που αναφέρεται σε ένα τυχαίο `message_id` το οποίο δεν έχει δει κανένα από τα δύο μέρη (το WhatsApp δέχεται αυθαίρετα `key.id` GUIDs· το Signal χρησιμοποιεί timestamps σε milliseconds).
3. Στείλε το packet παρότι δεν υπάρχει thread. Οι victim devices κάνουν decrypt, αποτυγχάνουν να αντιστοιχίσουν το base message, απορρίπτουν την αλλαγή του state, αλλά εξακολουθούν να κάνουν acknowledge το incoming ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επανάλαβε συνεχώς για να δημιουργήσεις RTT series χωρίς να εμφανιστείς ποτέ στη chat list του victim.<sup>[[1]](#references)</sup>

Αν πρώτα χρειάζεται να ανακαλύψεις ποιοι αριθμοί είναι registered ή θέλεις να κάνεις pre-seed inventories συσκευών σε scale, σύνδεσέ το με [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), αντί να μαντεύεις χειροκίνητα τυχαίες περιοχές E.164.

Δημοσιευμένη εργασία contact-discovery έδειξε γιατί αυτό έχει επιχειρησιακή σημασία: με ακριβείς phone-prefix tables και μέτριους πόρους, οι researchers μπόρεσαν να query περίπου το `10%` των US mobile numbers στο WhatsApp και το `100%` στο Signal, πριν προχωρήσουν σε targeted probing.<sup>[[11]](#references)</sup> Στην πράξη, το pre-filtering των live accounts διατηρεί το budget των silent probes εστιασμένο σε αριθμούς που πράγματι θα κάνουν decrypt τα packets.

Τα πρόσφατα WhatsApp builds εκθέτουν επίσης το `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Αντιμετώπισέ το ως throughput limiter και όχι ως fix: επηρεάζει κυρίως το sustained stranger-only flooding και είναι irrelevant όταν είσαι ήδη known contact.

## Recycling edits και deletes ως covert triggers

* **Repeated deletes:** Αφού ένα message διαγραφεί μία φορά με delete-for-everyone, επιπλέον delete packets που αναφέρονται στο ίδιο `message_id` δεν έχουν UI effect, αλλά κάθε device εξακολουθεί να κάνει decrypt και acknowledge.
* **Out-of-window operations:** Το WhatsApp επιβάλλει windows ~60 h για delete και ~20 min για edit στο UI· το Signal επιβάλλει ~48 h. Crafted protocol messages εκτός αυτών των windows αγνοούνται silent στη συσκευή του victim, όμως τα receipts μεταδίδονται, επομένως οι attackers μπορούν να κάνουν probe επ' αόριστον, πολύ μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Malformed edit bodies ή deletes που αναφέρονται σε ήδη purged messages προκαλούν την ίδια συμπεριφορά—decryption συν receipt, χωρίς user-visible artefacts.<sup>[[1]](#references)</sup>

## Multi-device amplification και fingerprinting

* Κάθε associated device (phone, desktop app, browser companion) κάνει decrypt το probe ανεξάρτητα και επιστρέφει το δικό του ack. Η καταμέτρηση των receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.
* Αν ένα device είναι offline, το receipt του μπαίνει σε queue και αποστέλλεται κατά την επανασύνδεση. Επομένως, τα κενά κάνουν leak τους online/offline κύκλους και ακόμη και τα commuting schedules (π.χ. τα desktop receipts σταματούν κατά τη διάρκεια μετακίνησης).
* Οι κατανομές RTT διαφέρουν ανά platform λόγω του OS power management και των push wakeups. Κάνε cluster τα RTTs (π.χ. k-means σε median/variance features) για να χαρακτηρίσεις “Android handset", “iOS handset", “Electron desktop" κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το key inventory του recipient πριν από το encryption, ο attacker μπορεί επίσης να παρακολουθεί πότε γίνεται pair νέων συσκευών· μια απότομη αύξηση στον αριθμό συσκευών ή ένα νέο RTT cluster αποτελεί ισχυρή ένδειξη.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing και stacked receipts

* **WhatsApp burst tolerance:** Δημοσιευμένες μετρήσεις ανέφεραν ότι το WhatsApp δεχόταν silent-reaction bursts με ρυθμό έως και ένα probe κάθε `50 ms`, χωρίς εμφανές server-side queueing. Αυτό είναι χρήσιμο για σύντομα calibration bursts, γρήγορο device counting ή γρήγορη αύξηση ενός drain attack.
* **Signal long-run queueing:** Το Signal ανεχόταν σύντομα bursts, αλλά άρχιζε να κάνει queue sustained traffic πολλαπλών probes ανά δευτερόλεπτο. Για long-lived monitoring, διατήρησε το cadence περίπου στο `1 Hz` (ή χαμηλότερα), ώστε κάθε receipt να εξακολουθεί να αντικατοπτρίζει το τρέχον device state και όχι την εκκένωση backlog.
* **Reconnect artefacts:** Όταν ένα device επανέρχεται online, ορισμένοι clients κάνουν batch ή rapidly flush πολλαπλά delayed receipts. Αντιμετώπισε αυτά τα receipt bursts ως marker μετάβασης state και όχι ως ανεξάρτητα RTT samples, διαφορετικά ο classifier σου για clustering / `active` έναντι `idle` θα κάνει overfit στον θόρυβο της επανασύνδεσης.<sup>[[1]](#references)</sup>

## Behaviour inference από RTT traces

1. Κάνε sampling σε ≥1 Hz για να καταγράψεις τις επιδράσεις του OS scheduling. Στο WhatsApp σε iOS, RTTs <1 s συσχετίζονται έντονα με screen-on/foreground, ενώ RTTs >1 s με screen-off/background throttling.
2. Δημιούργησε απλούς classifiers (thresholding ή two-cluster k-means) που χαρακτηρίζουν κάθε RTT ως "active" ή "idle". Κάνε aggregate τα labels σε streaks για να εξαγάγεις ώρες ύπνου, μετακινήσεις, ώρες εργασίας ή πότε είναι active το desktop companion.
3. Συσχέτισε ταυτόχρονα probes προς κάθε device για να δεις πότε οι users μεταβαίνουν από mobile σε desktop, πότε τα companions πηγαίνουν offline και αν το app περιορίζεται από rate limiting μέσω push ή persistent socket.
4. Σε πραγματικά networks, απόφυγε ένα μοναδικό hardcoded threshold `1 s`. Κάνε bootstrap κάθε device με ένα σύντομο warm-up window και διατήρησε rolling baseline (για παράδειγμα, `threshold = 0.9 * median RTT`), ώστε το Wi-Fi/cellular drift να μην καταρρεύσει τον classifier σου.<sup>[[1]](#references)</sup>

## Location inference από delivery RTT

Το ίδιο timing primitive μπορεί να επαναχρησιμοποιηθεί για να εξαχθεί η τοποθεσία του recipient και όχι μόνο αν είναι active. Η εργασία `Hope of Delivery` έδειξε ότι η εκπαίδευση σε RTT distributions για γνωστές τοποθεσίες του receiver επιτρέπει στον attacker να ταξινομήσει αργότερα την τοποθεσία του victim μόνο από delivery confirmations:<sup>[[2]](#references)</sup>

* Δημιούργησε baseline για τον ίδιο target ενώ βρίσκεται σε αρκετές γνωστές τοποθεσίες (home, office, campus, country A έναντι country B κ.λπ.).
* Για κάθε τοποθεσία, συνέλεξε πολλά normal message RTTs και εξήγαγε απλά features, όπως median, variance ή percentile buckets.
* Κατά τη διάρκεια του πραγματικού attack, σύγκρινε τη νέα probe series με τα trained clusters. Το paper αναφέρει ότι ακόμη και τοποθεσίες μέσα στην ίδια πόλη μπορούν συχνά να διαχωριστούν, με accuracy `>80%` σε setting 3 τοποθεσιών.
* Αυτό λειτουργεί καλύτερα όταν ο attacker ελέγχει το sender environment και κάνει probes υπό παρόμοιες network conditions, επειδή η measured path περιλαμβάνει το access network του recipient, το wake-up latency και το messenger infrastructure.<sup>[[2]](#references)</sup>

Σε αντίθεση με τα παραπάνω silent reaction/edit/delete attacks, το location inference δεν απαιτεί invalid message IDs ή stealthy state-changing packets. Αρκούν plain messages με normal delivery confirmations, επομένως το tradeoff είναι χαμηλότερο stealth αλλά ευρύτερη applicability σε messengers.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να γίνει decrypt και acknowledge, η συνεχής αποστολή reaction toggles, invalid edits ή delete-for-everyone packets δημιουργεί application-layer DoS:<sup>[[1]](#references)</sup>

* Αναγκάζει το radio/modem να κάνει transmit/receive κάθε δευτερόλεπτο → noticeable battery drain, ειδικά σε idle handsets.
* Δημιουργεί unmetered upstream/downstream traffic που καταναλώνει mobile data plans, ενώ αναμειγνύεται με TLS/WebSocket noise.
* Απασχολεί crypto threads και εισάγει jitter σε latency-sensitive features (VoIP, video calls), παρότι ο user δεν βλέπει notifications.
* Στο WhatsApp, τα invalid reactions δέχονται πολύ περισσότερα data από όσα υποδηλώνει ένα normal emoji: δημοσιευμένες μετρήσεις βρήκαν server-side acceptance έως περίπου `1 MB` ανά reaction.
* Τα oversized reactions παύουν να παράγουν αξιόπιστα delivery receipts όταν το body ξεπεράσει περίπου τα `30 bytes`, αλλά εξακολουθούν να προωθούνται και να υποβάλλονται σε processing πριν απορριφθούν. Διατήρησε τα reaction bodies μικρά όταν χρειάζεσαι ACKs· κάνε τα μεγαλύτερα μόνο όταν ο στόχος είναι καθαρό drain ή covert one-way transport.
* Δημόσιες μετρήσεις έφτασαν περίπου τα `3.7 MB/s` (`~13.3 GB/h`) traffic του victim σε αυτό το mode.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
