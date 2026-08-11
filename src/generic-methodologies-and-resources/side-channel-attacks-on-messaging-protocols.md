# Side-Channel Attacks μέσω Delivery Receipts σε E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Τα delivery receipts είναι υποχρεωτικά στα σύγχρονα end-to-end encrypted (E2EE) messengers, επειδή οι clients πρέπει να γνωρίζουν πότε έγινε decrypt ένα ciphertext, ώστε να απορρίπτουν την κατάσταση ratcheting και τα ephemeral keys. Ο server προωθεί opaque blobs, επομένως τα acknowledgements των συσκευών (διπλά σημάδια ελέγχου) αποστέλλονται από τον recipient μετά από επιτυχημένο decryption. Η μέτρηση του round-trip time (RTT) μεταξύ μιας ενέργειας που προκαλεί ο attacker και του αντίστοιχου delivery receipt εκθέτει ένα κανάλι χρονισμού υψηλής ανάλυσης, το οποίο κάνει leak την κατάσταση της συσκευής και την online παρουσία και μπορεί να χρησιμοποιηθεί για covert DoS. Οι deployments πολλαπλών συσκευών τύπου "client-fanout" ενισχύουν το leak, επειδή κάθε registered device κάνει decrypt το probe και επιστρέφει το δικό της receipt.<sup>[[1]](#references)</sup>

## Πηγές delivery receipts vs. signals που βλέπει ο user

Επίλεξε message types που εκδίδουν πάντα delivery receipt, αλλά δεν εμφανίζουν UI artifacts στο victim. Ο παρακάτω πίνακας συνοψίζει τη συμπεριφορά που έχει επιβεβαιωθεί εμπειρικά:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Πάντα noisy → χρήσιμο μόνο για bootstrap του state. |
| | Reaction | ● | ◐ (μόνο αν γίνεται reaction σε μήνυμα του victim) | Τα self-reactions και οι removals παραμένουν silent. |
| | Edit | ● | Platform-dependent silent push | Το edit window είναι ≈20 min· εξακολουθεί να γίνεται ack μετά τη λήξη. |
| | Delete for everyone | ● | ○ | Το UI επιτρέπει ~60 h, αλλά τα μεταγενέστερα packets εξακολουθούν να γίνονται ack. |
| **Signal** | Text message | ● | ● | Ίδιοι περιορισμοί με το WhatsApp. |
| | Reaction | ● | ◐ | Τα self-reactions είναι αόρατα στον victim. |
| | Edit/Delete | ● | ○ | Ο server επιβάλλει window ~48 h, επιτρέπει έως 10 edits, αλλά τα late packets εξακολουθούν να γίνονται ack. |
| **Threema** | Text message | ● | ● | Τα multi-device receipts γίνονται aggregated, επομένως γίνεται ορατό μόνο ένα RTT ανά probe. |

Legend: ● = πάντα, ◐ = conditional, ○ = ποτέ. Η platform-dependent συμπεριφορά του UI σημειώνεται inline. Απενεργοποίησε τα read receipts αν χρειάζεται, αλλά τα delivery receipts δεν μπορούν να απενεργοποιηθούν στο WhatsApp ή στο Signal.<sup>[[1]](#references)</sup>

## Στόχοι και μοντέλα attacker

* **G1 – Device fingerprinting:** Μέτρησε πόσα receipts φτάνουν ανά probe, κάνε cluster στα RTTs για να συμπεράνεις το OS/client (Android vs iOS vs desktop) και παρακολούθησε τις μεταβάσεις online/offline.
* **G2 – Behavioural monitoring:** Αντιμετώπισε τη σειρά RTT υψηλής συχνότητας (≈1 Hz είναι σταθερό) ως time-series και συμπέρανε screen on/off, app foreground/background, ώρες μετακίνησης έναντι εργασίας κ.λπ.
* **G3 – Resource exhaustion:** Κράτησε τα radios/CPUs κάθε victim device ενεργά στέλνοντας αδιάκοπα silent probes, εξαντλώντας battery/data και υποβαθμίζοντας την ποιότητα των video calls.<sup>[[1]](#references)</sup>

Δύο threat actors αρκούν για την περιγραφή της επιφάνειας abuse:<sup>[[1]](#references)</sup>

1. **Creepy companion:** Ήδη συμμετέχει σε chat με τον victim και κάνει abuse στα self-reactions, στα reaction removals ή σε επαναλαμβανόμενα edits/deletes που συνδέονται με υπάρχοντα message IDs.
2. **Spooky stranger:** Κάνει register έναν burner account και στέλνει reactions που αναφέρουν message IDs τα οποία δεν υπήρξαν ποτέ στο local conversation· το WhatsApp και το Signal εξακολουθούν να κάνουν decrypt και acknowledge, παρότι το UI απορρίπτει το state change, επομένως δεν απαιτείται προηγούμενη συνομιλία.

## Tooling για raw protocol access

Βασίσου σε clients που εκθέτουν αρκετό από το underlying E2EE protocol ώστε να δημιουργούν supported packets εκτός των περιορισμών του UI και να καταγράφουν ακριβή timestamps· για arbitrary message IDs απαιτείται έλεγχος κάθε implementation:

* **WhatsApp:** Το [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) τεκμηριώνει την αποστολή και λήψη delivery receipts· το [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web και mobile API) τεκμηριώνει message operations όπως reacting, editing και deleting. Χρησιμοποίησε τα documented APIs αντί να θεωρείς ότι εκτίθεται κάθε internal frame.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** Το [signal-cli](https://github.com/AsamK/signal-cli) εκθέτει interfaces CLI, JSON-RPC και D-Bus, ενώ το [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) είναι Java library για επικοινωνία με το Signal.<sup>[[5]](#references)[[7]](#references)</sup> Η τρέχουσα σύνταξη του `signal-cli` χρησιμοποιεί `sendReaction RECIPIENT --target-author --target-timestamp`· κράτησε το `receive` ή το `daemon` σε λειτουργία ώστε να συνεχίσουν να γίνονται process τα protocol updates.<sup>[[6]](#references)</sup> Παράδειγμα self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Οι μετρήσεις στην εργασία Careless Whisper έδειξαν ότι τα delivery receipts συγχρονίζονται μεταξύ συσκευών, επομένως εκτίθεται μόνο ένα receipt ανά message, ακόμη και σε multi-device setup.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** Το [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) περιλαμβάνει WhatsApp/Signal backends, έχει ως default τα silent delete probes και επισημαίνει `active` έναντι `standby` με rolling-median threshold (`RTT < 0.9 * median`). Το [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) είναι ένα ελαφρύτερο WhatsApp-first CLI με `--delay`, `--concurrent`, CSV/Prometheus exporters και Grafana-friendly output.<sup>[[8]](#references)</sup> <sup>[[9]](#references)</sup> Αντιμετώπισέ τα ως reconnaissance helpers και όχι ως protocol references· το σημαντικό συμπέρασμα είναι πόσο λίγος κώδικας απαιτείται όταν υπάρχει raw client access.

Όταν δεν είναι διαθέσιμο custom tooling, τα official clients ή τα browser developer tools μπορούν ακόμη να trigger-άρουν silent actions και να εκθέσουν τον χρονισμό encrypted traffic· τα raw APIs αφαιρούν τα UI delays και επιτρέπουν invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Επίλεξε οποιοδήποτε historical message που έγραψες εσύ στο chat, ώστε ο victim να μη δει ποτέ να αλλάζουν τα "reaction" balloons.
2. Κάνε alternate μεταξύ ενός visible emoji και ενός empty reaction payload (κωδικοποιημένου ως `""` στα WhatsApp protobufs ή ως `--remove` στο signal-cli). Κάθε transmission δημιουργεί device ack, παρότι δεν υπάρχει UI delta για τον victim.
3. Κατέγραψε το send time και κάθε άφιξη delivery receipt. Ένα loop 1 Hz όπως το παρακάτω παρέχει per-device RTT traces επ' αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή το WhatsApp/Signal αποδέχεται unlimited reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο chat content ούτε να ανησυχεί για edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. Κάνε register έναν fresh WhatsApp/Signal account και κάνε fetch τα public identity keys για τον target number (αυτό γίνεται αυτόματα κατά το session setup).
2. Δημιούργησε ένα reaction packet που αναφέρει ένα τυχαίο `message_id` το οποίο δεν έχει δει κανένα από τα δύο μέρη· η εργασία αναφέρει ότι τόσο το WhatsApp όσο και το Signal αποδέχονται τέτοια reactions και εξακολουθούν να δημιουργούν delivery receipts.<sup>[[1]](#references)</sup>
3. Στείλε το packet παρότι δεν υπάρχει thread. Οι συσκευές του victim κάνουν decrypt, αποτυγχάνουν να αντιστοιχίσουν το base message, απορρίπτουν το state change, αλλά εξακολουθούν να κάνουν acknowledge το incoming ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επανάλαβε συνεχώς για να δημιουργήσεις RTT series χωρίς προηγούμενη συνομιλία ή visible notification.<sup>[[1]](#references)</sup>

Αν χρειάζεται πρώτα να ανακαλύψεις ποιοι αριθμοί είναι registered ή θέλεις να κάνεις pre-seed inventories συσκευών σε κλίμακα, σύνδεσέ το με [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) αντί να μαντεύεις χειροκίνητα τυχαίες περιοχές E.164.

Η δημοσιευμένη εργασία contact-discovery έδειξε γιατί αυτό έχει operational σημασία: με ακριβείς phone-prefix tables και μέτριους πόρους, οι ερευνητές μπόρεσαν να κάνουν query περίπου στο `10%` των US mobile numbers στο WhatsApp και στο `100%` στο Signal, πριν προχωρήσουν σε targeted probing.<sup>[[11]](#references)</sup> Στην πράξη, το pre-filtering των live accounts διατηρεί το silent-probe budget εστιασμένο σε αριθμούς που πράγματι θα κάνουν decrypt τα packets.

Τα πρόσφατα WhatsApp builds εκθέτουν επίσης το `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Αντιμετώπισέ το ως throughput limiter: η τεκμηρίωση του tracker αναφέρει ότι το WhatsApp μπλοκάρει high-volume messages από unknown accounts, αλλά δεν αποκαλύπτει το threshold, επομένως δεν αποτρέπει πλήρως τα probe reactions.<sup>[[8]](#references)</sup>

## Ανακύκλωση edits και deletes ως covert triggers

* **Repeated deletes:** Μετά τη διαγραφή ενός message ως delete-for-everyone, τα επόμενα delete packets που αναφέρουν το ίδιο `message_id` δεν έχουν UI effect, αλλά κάθε συσκευή εξακολουθεί να κάνει decrypt και acknowledge.
* **Out-of-window operations:** Το WhatsApp επιβάλλει ~60 h delete / ~20 min edit windows στο UI· το Signal επιβάλλει ~48 h. Crafted protocol messages εκτός αυτών των windows αγνοούνται silent στη συσκευή του victim, ωστόσο τα receipts μεταδίδονται, επομένως οι attackers μπορούν να κάνουν probe επ' αόριστον, πολύ μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Η εργασία αναφέρει ότι ακόμη και invalid messages μπορεί να γίνουν acknowledge· η ακριβής συμπεριφορά για malformed bodies ή purged IDs εξαρτάται από το implementation, επομένως κάνε test πριν βασιστείς σε αυτήν.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Στο WhatsApp και στο Signal, κάθε associated device (phone, desktop app, browser companion) κάνει decrypt το probe ανεξάρτητα και επιστρέφει το δικό της ack. Η καταμέτρηση των receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.<sup>[[1]](#references)</sup>
* Αν μια συσκευή είναι offline, το receipt της μπαίνει σε queue και εκπέμπεται κατά την επανασύνδεση. Επομένως τα gaps κάνουν leak τους online/offline cycles και ακόμη και τα commuting schedules (π.χ. τα desktop receipts σταματούν κατά τη μετακίνηση).
* Οι κατανομές RTT διαφέρουν ανά platform και environment, επειδή το OS, το model, ο client και οι network conditions επηρεάζουν τον χρονισμό. Κάνε cluster στα RTTs (π.χ. k-means σε median/variance features) για να επισημάνεις “Android handset", “iOS handset", “Electron desktop" κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το key inventory του recipient πριν από το encryption, ο attacker μπορεί επίσης να παρακολουθεί πότε γίνεται pairing νέων συσκευών· μια ξαφνική αύξηση του device count ή ένα νέο RTT cluster αποτελεί ισχυρή ένδειξη.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing και stacked receipts

* **WhatsApp burst tolerance:** Δημοσιευμένες μετρήσεις ανέφεραν ότι το WhatsApp αποδεχόταν silent-reaction bursts τόσο γρήγορα όσο ένα probe κάθε `50 ms`, χωρίς εμφανές server-side queueing. Αυτό είναι χρήσιμο για σύντομα calibration bursts, γρήγορο device counting ή γρήγορη κλιμάκωση ενός drain attack.
* **Signal long-run queueing:** Το Signal ανεχόταν σύντομα bursts, αλλά άρχιζε να κάνει queue sustained traffic πολλαπλών probes ανά δευτερόλεπτο. Για long-lived monitoring, κράτησε το cadence περίπου στο `1 Hz` (ή χαμηλότερα), ώστε κάθε receipt να εξακολουθεί να αντικατοπτρίζει την τρέχουσα κατάσταση της συσκευής αντί για την εκκένωση backlog.
* **Reconnect artefacts:** Όταν μια συσκευή επιστρέφει online, ορισμένοι clients κάνουν batch ή rapid flush πολλαπλών delayed receipts. Αντιμετώπισε αυτά τα receipt bursts ως state-transition marker και όχι ως ανεξάρτητα RTT samples, διαφορετικά ο classifier σου για clustering / `active` έναντι `idle` θα κάνει overfit στον θόρυβο της επανασύνδεσης.<sup>[[1]](#references)</sup>

## Συμπερασμός συμπεριφοράς από RTT traces

1. Κάνε sampling στα ≥1 Hz για να καταγράψεις OS scheduling effects. Στο WhatsApp σε iOS, RTTs <1 s συσχετίζονται έντονα με screen-on/foreground, ενώ RTTs >1 s με screen-off/background throttling.
2. Δημιούργησε απλούς classifiers (thresholding ή two-cluster k-means) που επισημαίνουν κάθε RTT ως "active" ή "idle". Κάνε aggregate τα labels σε streaks για να εξάγεις ώρες ύπνου, μετακινήσεις, ώρες εργασίας ή πότε είναι active το desktop companion.
3. Συσχέτισε simultaneous probes προς κάθε συσκευή για να δεις πότε οι users μεταβαίνουν από mobile σε desktop, πότε οι companions γίνονται offline και αν το app υφίσταται rate limiting από push έναντι persistent socket.
4. Σε πραγματικά networks, απόφυγε ένα μόνο hardcoded `1 s` threshold. Κάνε bootstrap κάθε συσκευής με ένα σύντομο warm-up window και διατήρησε rolling baseline (για παράδειγμα, το device-activity-tracker PoC χρησιμοποιεί `threshold = 0.9 * median RTT`), ώστε το Wi-Fi/cellular drift να μην καταρρεύσει τον classifier σου.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference από delivery RTT

Το ίδιο timing primitive μπορεί να επαναχρησιμοποιηθεί για να εξαχθεί η τοποθεσία του recipient και όχι μόνο αν είναι active. Η εργασία `Hope of Delivery` έδειξε ότι η εκπαίδευση σε RTT distributions για γνωστές τοποθεσίες receiver επιτρέπει στον attacker να ταξινομήσει αργότερα την τοποθεσία του victim μόνο από τις delivery confirmations:<sup>[[2]](#references)</sup>

* Δημιούργησε baseline για τον ίδιο target ενώ βρίσκεται σε αρκετές γνωστές τοποθεσίες (home, office, campus, country A έναντι country B κ.λπ.).
* Για κάθε τοποθεσία, συνέλεξε πολλά normal message RTTs και εξήγαγε απλά features όπως median, variance ή percentile buckets.
* Κατά τη διάρκεια του πραγματικού attack, σύγκρινε τη νέα probe series με τα trained clusters. Η εργασία αναφέρει ότι ακόμη και τοποθεσίες στην ίδια πόλη μπορούν συχνά να διαχωριστούν, με ακρίβεια `>80%` σε ρύθμιση 3 τοποθεσιών.
* Αυτό λειτουργεί καλύτερα όταν ο attacker ελέγχει το sender environment και κάνει probes υπό παρόμοιες network conditions, επειδή το measured path περιλαμβάνει το access network του recipient, το wake-up latency και το messenger infrastructure.<sup>[[2]](#references)</sup>

Σε αντίθεση με τα silent reaction/edit/delete attacks παραπάνω, το location inference δεν απαιτεί invalid message IDs ή stealthy state-changing packets. Αρκούν plain messages με normal delivery confirmations, επομένως το tradeoff είναι χαμηλότερο stealth αλλά ευρύτερη εφαρμογή μεταξύ messengers.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να γίνει decrypt και acknowledge, η συνεχής αποστολή reaction toggles, invalid edits ή delete-for-everyone packets δημιουργεί application-layer DoS:<sup>[[1]](#references)</sup>

* Αναγκάζει το radio/modem να κάνει transmit/receive κάθε δευτερόλεπτο → αισθητή battery drain, ειδικά σε idle handsets.
* Δημιουργεί upstream/downstream traffic που καταναλώνει mobile data plans και μπορεί να ανταγωνιστεί latency-sensitive features όπως τα video calls.<sup>[[1]](#references)</sup>
* Τα large invalid payloads προσθέτουν processing work, αλλά η εργασία αναφέρει ότι η cryptography αποτελεί αμελητέο μέρος του battery cost.<sup>[[1]](#references)</sup>
* Στο WhatsApp, τα invalid reactions αποδέχονται πολύ περισσότερα δεδομένα απ' όσα υποδηλώνει ένα normal emoji: δημοσιευμένες μετρήσεις βρήκαν server-side acceptance έως περίπου `1 MB` ανά reaction.
* Τα oversized reactions παύουν να παράγουν reliable delivery receipts όταν το body ξεπεράσει περίπου τα `30 bytes`, αλλά εξακολουθούν να προωθούνται και να γίνονται process πριν απορριφθούν. Κράτησε τα reaction bodies μικρά όταν χρειάζεσαι ACKs· κάνε τα μεγαλύτερα μόνο όταν ο στόχος είναι pure drain ή covert one-way transport.
* Public measurements έφτασαν περίπου τα `3.7 MB/s` (`~13.3 GB/h`) traffic του victim σε αυτό το mode.

## References

- [1] [Careless Whisper: Εκμετάλλευση Silent Delivery Receipts για την Παρακολούθηση Users σε Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Εξαγωγή User Locations από Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Πώς να μπλοκάρετε μεγάλους όγκους άγνωστων messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Όλοι οι Numbers είναι US: Abuse μεγάλης κλίμακας του Contact Discovery σε Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
