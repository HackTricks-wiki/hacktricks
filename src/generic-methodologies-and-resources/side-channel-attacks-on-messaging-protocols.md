# Επιθέσεις side-channel σε Delivery Receipt σε E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Τα delivery receipts είναι υποχρεωτικά σε σύγχρονους end-to-end encrypted (E2EE) messengers επειδή οι clients χρειάζονται να ξέρουν πότε ένα ciphertext αποκρυπτογραφήθηκε ώστε να μπορούν να απορρίψουν το ratcheting state και τα ephemeral keys. Ο server προωθεί opaque blobs, οπότε οι επιβεβαιώσεις συσκευής (double checkmarks) εκπέμπονται από τον παραλήπτη μετά από επιτυχημένη αποκρυπτογράφηση. Η μέτρηση του round-trip time (RTT) μεταξύ μιας ενέργειας που ενεργοποιεί ο attacker και του αντίστοιχου delivery receipt αποκαλύπτει ένα timing channel υψηλής ανάλυσης που leak device state, online presence, και μπορεί να χρησιμοποιηθεί για covert DoS. Τα multi-device "client-fanout" deployments ενισχύουν το leak επειδή κάθε registered device αποκρυπτογραφεί το probe και επιστρέφει το δικό του receipt.

## Πηγές delivery receipt vs. signals ορατά στον χρήστη

Επίλεξε message types που πάντα εκπέμπουν delivery receipt αλλά δεν εμφανίζουν UI artifacts στο victim. Ο παρακάτω πίνακας συνοψίζει την empirically confirmed συμπεριφορά:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Πάντα noisy → μόνο χρήσιμο για bootstrap state. |
| | Reaction | ● | ◐ (μόνο αν reacting σε message του victim) | Οι self-reactions και οι removals μένουν αθόρυβες. |
| | Edit | ● | Platform-dependent silent push | Το edit window ≈20 min· παραμένει ack’d και μετά τη λήξη. |
| | Delete for everyone | ● | ○ | Το UI επιτρέπει ~60 h, αλλά τα μεταγενέστερα packets παραμένουν ack’d. |
| **Signal** | Text message | ● | ● | Ίδιοι περιορισμοί με το WhatsApp. |
| | Reaction | ● | ◐ | Οι self-reactions είναι αόρατες για το victim. |
| | Edit/Delete | ● | ○ | Ο server επιβάλλει παράθυρο ~48 h, επιτρέπει έως 10 edits, αλλά τα καθυστερημένα packets παραμένουν ack’d. |
| **Threema** | Text message | ● | ● | Τα multi-device receipts συγκεντρώνονται, οπότε μόνο ένα RTT ανά probe γίνεται ορατό. |

Legend: ● = πάντα, ◐ = υπό προϋποθέσεις, ○ = ποτέ. Η platform-dependent συμπεριφορά του UI σημειώνεται inline. Απενεργοποίησε τα read receipts αν χρειάζεται, αλλά τα delivery receipts δεν μπορούν να απενεργοποιηθούν σε WhatsApp ή Signal.

## Στόχοι και μοντέλα attacker

* **G1 – Device fingerprinting:** Μετρά πόσα receipts φτάνουν ανά probe, κάνε cluster τα RTTs για να εξαγάγεις OS/client (Android vs iOS vs desktop), και παρατήρησε online/offline transitions.
* **G2 – Behavioural monitoring:** Αντιμετώπισε τη σειρά υψηλής συχνότητας RTT (≈1 Hz είναι σταθερό) ως time-series και εξήγαγε screen on/off, app foreground/background, commuting vs working hours, κ.λπ.
* **G3 – Resource exhaustion:** Κράτησε radios/CPUs κάθε victim device ξύπνια στέλνοντας ατελείωτα silent probes, αδειάζοντας μπαταρία/data και υποβαθμίζοντας την ποιότητα VoIP/RTC.

Δύο threat actors αρκούν για να περιγράψουν το πεδίο κατάχρησης:

1. **Creepy companion:** ήδη μοιράζεται ένα chat με το victim και καταχράται self-reactions, reaction removals, ή επαναλαμβανόμενα edits/deletes που συνδέονται με υπάρχοντα message IDs.
2. **Spooky stranger:** εγγράφει έναν burner account και στέλνει reactions που αναφέρονται σε message IDs που δεν υπήρξαν ποτέ στο τοπικό conversation· το WhatsApp και το Signal εξακολουθούν να τα αποκρυπτογραφούν και να τα επιβεβαιώνουν παρότι το UI απορρίπτει την αλλαγή κατάστασης, οπότε δεν απαιτείται προηγούμενο conversation.

## Tooling για raw protocol access

Στηρίξου σε clients που εκθέτουν το underlying E2EE protocol ώστε να μπορείς να φτιάχνεις packets έξω από τους περιορισμούς του UI, να καθορίζεις arbitrary `message_id`s και να καταγράφεις ακριβείς timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ή [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) επιτρέπουν να στέλνεις raw `ReactionMessage`, `ProtocolMessage` (edit/delete), και `Receipt` frames ενώ διατηρούν το double-ratchet state σε sync.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) σε συνδυασμό με [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) εκθέτει κάθε message type μέσω CLI/API. Η τρέχουσα σύνταξη του `signal-cli` χρησιμοποιεί `sendReaction RECIPIENT --target-author --target-timestamp`; κράτα το `receive` ή `daemon` σε λειτουργία ώστε τα delivery receipts να συλλέγονται πραγματικά. Παράδειγμα toggle self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Ο source του Android client τεκμηριώνει πώς τα delivery receipts συγκεντρώνονται πριν φύγουν από τη συσκευή, εξηγώντας γιατί το side channel έχει αμελητέο bandwidth εκεί.
* **Turnkey PoCs:** Το [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) περιλαμβάνει backends για WhatsApp/Signal, προεπιλέγει silent delete probes, και επισημαίνει `active` vs `standby` με rolling-median threshold (`RTT < 0.9 * median`). Το [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) είναι ένα ελαφρύτερο WhatsApp-first CLI με `--delay`, `--concurrent`, CSV/Prometheus exporters, και έξοδο φιλική προς Grafana. Θεώρησε και τα δύο ως reconnaissance helpers και όχι ως protocol references· το σημαντικό συμπέρασμα είναι πόσο λίγο code χρειάζεται όταν υπάρχει raw client access.

Όταν δεν υπάρχει custom tooling, μπορείς ακόμη να ενεργοποιήσεις silent actions από WhatsApp Web ή Signal Desktop και να sniffάρεις το encrypted websocket/WebRTC channel, αλλά τα raw APIs αφαιρούν τις καθυστερήσεις του UI και επιτρέπουν invalid operations.

## Creepy companion: silent sampling loop

1. Επίλεξε οποιοδήποτε ιστορικό μήνυμα που έστειλες στο chat ώστε το victim να μην βλέπει ποτέ τις φούσκες "reaction" να αλλάζουν.
2. Εναλλάξτε μεταξύ ενός ορατού emoji και ενός κενού reaction payload (κωδικοποιημένο ως `""` στα WhatsApp protobufs ή `--remove` στο signal-cli). Κάθε μετάδοση δίνει ένα device ack παρότι δεν υπάρχει UI delta για το victim.
3. Καταχώρισε τον χρόνο αποστολής και κάθε άφιξη delivery receipt. Ένα 1 Hz loop όπως το παρακάτω δίνει per-device RTT traces επ' αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή το WhatsApp/Signal δέχονται απεριόριστα reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο chat content ούτε να ανησυχεί για edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Εγγράψου με έναν νέο WhatsApp/Signal account και πάρε τα public identity keys για τον στόχο-αριθμό (γίνεται αυτόματα κατά το session setup).
2. Φτιάξε ένα reaction/edit/delete packet που αναφέρεται σε ένα τυχαίο `message_id` που δεν είδε ποτέ κανένα από τα δύο μέρη (το WhatsApp δέχεται arbitrary `key.id` GUIDs· το Signal χρησιμοποιεί millisecond timestamps).
3. Στείλε το packet παρότι δεν υπάρχει thread. Οι συσκευές του victim το αποκρυπτογραφούν, αποτυγχάνουν να ταιριάξουν το base message, απορρίπτουν την αλλαγή κατάστασης, αλλά εξακολουθούν να επιβεβαιώνουν το εισερχόμενο ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επανάλαβέ το συνεχώς για να χτίσεις σειρές RTT χωρίς ποτέ να εμφανιστείς στη λίστα chats του victim.

Αν πρώτα χρειάζεται να ανακαλύψεις ποιοι αριθμοί είναι registered ή θέλεις να προ-γεμίσεις inventories συσκευών σε κλίμακα, σύνδεσε αυτό με [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) αντί να μαντεύεις τυχαία E.164 ranges με το χέρι.

Δημοσιευμένη έρευνα για contact-discovery έδειξε γιατί αυτό έχει επιχειρησιακή σημασία: με ακριβείς πίνακες phone-prefix και περιορισμένους πόρους, οι ερευνητές κατάφεραν να κάνουν query περίπου `10%` των US mobile numbers στο WhatsApp και `100%` στο Signal πριν προχωρήσουν σε targeted probing. Στην πράξη, το pre-filtering των live accounts πρώτα κρατά τον silent-probe budget επικεντρωμένο σε αριθμούς που όντως θα αποκρυπτογραφήσουν packets.

Νεότερα WhatsApp builds εκθέτουν επίσης `Settings -> Privacy -> Advanced -> Block unknown account messages`. Αντιμετώπισέ το ως throughput limiter, όχι ως λύση: κυρίως δυσκολεύει το sustained stranger-only flooding και είναι άσχετο μόλις είσαι ήδη γνωστή επαφή.

## Επαναχρησιμοποίηση edits και deletes ως covert triggers

* **Repeated deletes:** Αφού ένα μήνυμα διαγραφεί-for-everyone μία φορά, τα περαιτέρω delete packets που αναφέρονται στο ίδιο `message_id` δεν έχουν UI effect, αλλά κάθε device εξακολουθεί να τα αποκρυπτογραφεί και να τα επιβεβαιώνει.
* **Out-of-window operations:** Το WhatsApp επιβάλλει ~60 h delete / ~20 min edit windows στο UI· το Signal επιβάλλει ~48 h. Crafted protocol messages έξω από αυτά τα windows αγνοούνται σιωπηλά στη συσκευή του victim, όμως τα receipts μεταδίδονται, οπότε οι attackers μπορούν να probeάρουν επ' αόριστον πολύ μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Malformed edit bodies ή deletes που αναφέρονται σε ήδη purged messages προκαλούν την ίδια συμπεριφορά—αποκρυπτογράφηση συν receipt, μηδενικά user-visible artefacts.

## Multi-device amplification & fingerprinting

* Κάθε συνδεδεμένη συσκευή (phone, desktop app, browser companion) αποκρυπτογραφεί το probe ανεξάρτητα και επιστρέφει το δικό της ack. Η καταμέτρηση των receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.
* Αν μια συσκευή είναι offline, το receipt της μπαίνει σε ουρά και εκπέμπεται μόλις επανασυνδεθεί. Τα κενά επομένως leak online/offline κύκλους και ακόμη και προγράμματα μετακίνησης (π.χ. τα desktop receipts σταματούν κατά τη διάρκεια του ταξιδιού).
* Οι κατανομές RTT διαφέρουν ανά platform λόγω OS power management και push wakeups. Κάνε cluster τα RTTs (π.χ. k-means σε features median/variance) για να επισημάνεις “Android handset", “iOS handset", “Electron desktop", κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το key inventory του παραλήπτη πριν κρυπτογραφήσει, ο attacker μπορεί επίσης να παρατηρήσει πότε ζευγαρώνονται νέες συσκευές· μια ξαφνική αύξηση στον αριθμό συσκευών ή ένα νέο RTT cluster είναι ισχυρή ένδειξη.

## Sampling cadence, queueing, και stacked receipts

* **WhatsApp burst tolerance:** Δημοσιευμένες μετρήσεις ανέφεραν ότι το WhatsApp δεχόταν silent-reaction bursts όσο γρήγορα όσο ένα probe κάθε `50 ms` χωρίς προφανές server-side queueing. Αυτό είναι χρήσιμο για σύντομα calibration bursts, γρήγορη καταμέτρηση συσκευών ή ταχεία εκκίνηση μιας drain επίθεσης.
* **Signal long-run queueing:** Το Signal ανεχόταν σύντομα bursts αλλά άρχισε να βάζει σε ουρά sustained multi-probe-per-second traffic. Για monitoring μεγάλης διάρκειας, κράτα το cadence γύρω στο `1 Hz` (ή χαμηλότερα) ώστε κάθε receipt να αντικατοπτρίζει ακόμα την τρέχουσα κατάσταση της συσκευής αντί για drain backlog.
* **Reconnect artefacts:** Όταν μια συσκευή επανέρχεται online, ορισμένοι clients κάνουν batch ή φιλτράρουν γρήγορα πολλαπλά καθυστερημένα receipts. Αντιμετώπισε αυτά τα receipt bursts ως marker μετάβασης κατάστασης και όχι ως ανεξάρτητα RTT samples, αλλιώς το clustering / `active` vs `idle` classifier θα υπερπροσαρμοστεί στο reconnect noise.

## Εξαγωγή συμπερασμάτων συμπεριφοράς από RTT traces

1. Sample σε ≥1 Hz για να καταγράψεις effects scheduling του OS. Με WhatsApp σε iOS, RTTs < 1 s συσχετίζονται έντονα με screen-on/foreground, ενώ > 1 s με screen-off/background throttling.
2. Φτιάξε απλούς classifiers (thresholding ή two-cluster k-means) που επισημαίνουν κάθε RTT ως "active" ή "idle". Συγκέντρωσε τις ετικέτες σε streaks για να εξάγεις bedtimes, commutes, work hours, ή πότε το desktop companion είναι ενεργό.
3. Συσχέτισε ταυτόχρονα probes προς κάθε device για να δεις πότε οι χρήστες περνούν από mobile σε desktop, πότε τα companions πάνε offline, και αν η app περιορίζεται από push ή persistent socket.
4. Σε πραγματικά networks, απόφυγε ένα μοναδικό hardcoded `1 s` threshold. Κάνε bootstrap κάθε συσκευή με ένα σύντομο warm-up window και κράτα ένα rolling baseline (για παράδειγμα, `threshold = 0.9 * median RTT`) ώστε η μετατόπιση Wi-Fi/cellular να μη διαλύσει τον classifier.

## Εξαγωγή τοποθεσίας από delivery RTT

Το ίδιο timing primitive μπορεί να επαναχρησιμοποιηθεί για να εξαχθεί πού βρίσκεται ο παραλήπτης, όχι μόνο αν είναι ενεργός. Το έργο `Hope of Delivery` έδειξε ότι η εκπαίδευση πάνω σε RTT distributions για γνωστές τοποθεσίες παραλήπτη επιτρέπει σε έναν attacker αργότερα να ταξινομήσει την τοποθεσία του victim μόνο από τις delivery confirmations:

* Φτιάξε ένα baseline για τον ίδιο στόχο ενώ βρίσκεται σε μερικά γνωστά μέρη (σπίτι, γραφείο, campus, country A vs country B, κ.λπ.).
* Για κάθε τοποθεσία, μάζεψε πολλά normal message RTTs και εξήγαγε απλά features όπως median, variance, ή percentile buckets.
* Κατά την πραγματική επίθεση, σύγκρινε τη νέα σειρά probes με τα trained clusters. Η paper αναφέρει ότι ακόμη και τοποθεσίες μέσα στην ίδια πόλη μπορούν συχνά να διαχωριστούν, με ακρίβεια `>80%` σε σενάριο 3 τοποθεσιών.
* Αυτό δουλεύει καλύτερα όταν ο attacker ελέγχει το sender environment και κάνει probes κάτω από παρόμοιες network συνθήκες, επειδή η μετρημένη διαδρομή περιλαμβάνει το access network του παραλήπτη, το wake-up latency, και την υποδομή του messenger.

Σε αντίθεση με τα silent reaction/edit/delete attacks παραπάνω, η εξαγωγή τοποθεσίας δεν απαιτεί invalid message IDs ή stealthy state-changing packets. Απλά μηνύματα με κανονικές delivery confirmations αρκούν, οπότε το tradeoff είναι λιγότερο stealth αλλά ευρύτερη εφαρμογή σε messengers.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να αποκρυπτογραφηθεί και να επιβεβαιωθεί, η συνεχής αποστολή reaction toggles, invalid edits, ή delete-for-everyone packets δημιουργεί application-layer DoS:

* Αναγκάζει το radio/modem να στέλνει/λαμβάνει κάθε δευτερόλεπτο → αισθητή εξάντληση μπαταρίας, ειδικά σε idle handsets.
* Δημιουργεί unmetered upstream/downstream traffic που καταναλώνει mobile data plans ενώ χάνεται μέσα στο TLS/WebSocket noise.
* Καταλαμβάνει crypto threads και εισάγει jitter σε latency-sensitive features (VoIP, video calls) παρότι ο χρήστης δεν βλέπει ποτέ notifications.
* Στο WhatsApp, τα invalid reactions δέχονται πολύ περισσότερα data από όσα υπονοεί ένα κανονικό emoji: δημοσιευμένες μετρήσεις βρήκαν server-side acceptance έως περίπου `1 MB` ανά reaction.
* Τα oversized reactions σταματούν να παράγουν αξιόπιστα delivery receipts μόλις το body μεγαλώσει πάνω από περίπου `30 bytes`, αλλά εξακολουθούν να προωθούνται και να επεξεργάζονται πριν απορριφθούν. Κράτα τα reaction bodies μικρά όταν χρειάζεσαι ACKs· φούσκωσέ τα μόνο όταν ο στόχος είναι καθαρό drain ή covert one-way transport.
* Δημοσιευμένες μετρήσεις έφτασαν περίπου `3.7 MB/s` (`~13.3 GB/h`) victim traffic σε αυτό το mode.

## Αναφορές

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
