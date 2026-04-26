# Επιθέσεις Side-Channel μέσω Delivery Receipt σε E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Τα delivery receipts είναι υποχρεωτικά σε σύγχρονους end-to-end encrypted (E2EE) messengers επειδή οι clients χρειάζονται να ξέρουν πότε ένα ciphertext αποκρυπτογραφήθηκε ώστε να μπορούν να απορρίψουν ratcheting state και ephemeral keys. Ο server προωθεί opaque blobs, οπότε οι επιβεβαιώσεις συσκευής (double checkmarks) εκδίδονται από τον παραλήπτη μετά από επιτυχή αποκρυπτογράφηση. Η μέτρηση του round-trip time (RTT) ανάμεσα σε μια ενέργεια που ενεργοποιεί ο attacker και στο αντίστοιχο delivery receipt αποκαλύπτει ένα timing channel υψηλής ανάλυσης που leak device state, online presence, και μπορεί να χρησιμοποιηθεί για covert DoS. Τα multi-device "client-fanout" deployments ενισχύουν το leak επειδή κάθε καταγεγραμμένη συσκευή αποκρυπτογραφεί το probe και επιστρέφει το δικό της receipt.

## Delivery receipt sources vs. user-visible signals

Επίλεξε τύπους μηνυμάτων που πάντα εκδίδουν ένα delivery receipt αλλά δεν εμφανίζουν UI artifacts στο θύμα. Ο παρακάτω πίνακας συνοψίζει την εμπειρικά επιβεβαιωμένη συμπεριφορά:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Πάντα noisy → χρήσιμο μόνο για bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | Το UI επιτρέπει ~60 h, αλλά τα μεταγενέστερα packets still ack’d. |
| **Signal** | Text message | ● | ● | Ίδιοι περιορισμοί με το WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Ο server επιβάλλει παράθυρο ~48 h, επιτρέπει έως 10 edits, αλλά τα late packets still ack’d. |
| **Threema** | Text message | ● | ● | Τα multi-device receipts συγκεντρώνονται, οπότε μόνο ένα RTT ανά probe γίνεται ορατό. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour is noted inline. Disable read receipts if needed, but delivery receipts cannot be turned off in WhatsApp or Signal.

## Attacker goals and models

* **G1 – Device fingerprinting:** Μέτρα πόσα receipts φτάνουν ανά probe, cluster RTTs για να συμπεράνεις OS/client (Android vs iOS vs desktop), και παρακολούθησε online/offline transitions.
* **G2 – Behavioural monitoring:** Αντιμετώπισε τη σειρά RTT υψηλής συχνότητας (≈1 Hz είναι σταθερό) ως time-series και συμπέρανε screen on/off, app foreground/background, commuting vs working hours, κ.λπ.
* **G3 – Resource exhaustion:** Κράτα radios/CPUs κάθε συσκευής του θύματος ενεργά στέλνοντας ατελείωτα silent probes, αδειάζοντας battery/data και υποβαθμίζοντας την ποιότητα VoIP/RTC.

Δύο threat actors αρκούν για να περιγράψουν την επιφάνεια κατάχρησης:

1. **Creepy companion:** ήδη μοιράζεται ένα chat με το θύμα και καταχράται self-reactions, reaction removals, ή repeated edits/deletes συνδεδεμένα με υπάρχοντα message IDs.
2. **Spooky stranger:** καταχωρεί έναν burner account και στέλνει reactions που αναφέρονται σε message IDs που δεν υπήρξαν ποτέ στην τοπική συνομιλία· WhatsApp και Signal εξακολουθούν να τα αποκρυπτογραφούν και να τα επιβεβαιώνουν παρότι το UI απορρίπτει την αλλαγή κατάστασης, οπότε δεν απαιτείται προηγούμενη συνομιλία.

## Tooling for raw protocol access

Βασίσου σε clients που εκθέτουν το υποκείμενο E2EE protocol ώστε να μπορείς να συνθέτεις packets έξω από τους περιορισμούς του UI, να ορίζεις αυθαίρετα `message_id`s, και να καταγράφεις ακριβή timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ή [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) σου επιτρέπουν να εκπέμπεις raw `ReactionMessage`, `ProtocolMessage` (edit/delete), και `Receipt` frames ενώ κρατάς το double-ratchet state συγχρονισμένο.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) σε συνδυασμό με [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) εκθέτει κάθε τύπο μηνύματος μέσω CLI/API. Παράδειγμα self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Η πηγή του Android client τεκμηριώνει πώς τα delivery receipts συγκεντρώνονται πριν φύγουν από τη συσκευή, εξηγώντας γιατί το side channel εκεί έχει αμελητέο bandwidth.
* **Turnkey PoCs:** δημόσια projects όπως `device-activity-tracker` και `careless-whisper-python` ήδη αυτοματοποιούν silent delete/reaction probes και RTT classification. Αντιμετώπισέ τα ως έτοιμα reconnaissance helpers και όχι ως protocol references· το ενδιαφέρον είναι ότι επιβεβαιώνουν πως η επίθεση είναι λειτουργικά απλή μόλις υπάρχει raw client access.

Όταν δεν υπάρχει custom tooling, μπορείς ακόμα να ενεργοποιείς silent actions από WhatsApp Web ή Signal Desktop και να sniffάρεις το κρυπτογραφημένο websocket/WebRTC channel, αλλά τα raw APIs αφαιρούν UI delays και επιτρέπουν invalid operations.

## Creepy companion: silent sampling loop

1. Επίλεξε οποιοδήποτε historical message που έγραψες στο chat ώστε το θύμα να μην βλέπει ποτέ τα "reaction" balloons να αλλάζουν.
2. Εναλλάσσεσαι ανάμεσα σε ένα visible emoji και ένα empty reaction payload (encoded ως `""` σε WhatsApp protobufs ή `--remove` στο signal-cli). Κάθε μετάδοση δίνει device ack παρότι δεν υπάρχει UI delta για το θύμα.
3. Χρονοσφράγισε τον send time και κάθε arrival του delivery receipt. Ένα 1 Hz loop όπως το παρακάτω δίνει per-device RTT traces επ’ αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή WhatsApp/Signal δέχονται απεριόριστα reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο chat content ή να ανησυχεί για edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Καταχώρησε έναν φρέσκο WhatsApp/Signal account και ανέκτησε τα public identity keys για τον target number (γίνεται αυτόματα κατά το session setup).
2. Σύνθεσε ένα reaction/edit/delete packet που αναφέρεται σε ένα τυχαίο `message_id` που δεν είδε ποτέ κανένα από τα δύο μέρη (το WhatsApp δέχεται αυθαίρετα `key.id` GUIDs· το Signal χρησιμοποιεί millisecond timestamps).
3. Στείλε το packet παρότι δεν υπάρχει thread. Οι συσκευές του θύματος το αποκρυπτογραφούν, αποτυγχάνουν να ταιριάξουν το base message, απορρίπτουν την αλλαγή κατάστασης, αλλά εξακολουθούν να επιβεβαιώνουν το εισερχόμενο ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επανάλαβε συνεχώς για να χτίσεις RTT series χωρίς ποτέ να εμφανίζεσαι στη λίστα chat του θύματος.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Αφού ένα μήνυμα διαγραφεί-for-everyone μία φορά, τα επόμενα delete packets που αναφέρονται στο ίδιο `message_id` δεν έχουν UI effect αλλά κάθε συσκευή εξακολουθεί να τα αποκρυπτογραφεί και να τα επιβεβαιώνει.
* **Out-of-window operations:** Το WhatsApp επιβάλλει παράθυρα ~60 h για delete / ~20 min για edit στο UI· το Signal επιβάλλει ~48 h. Crafted protocol messages έξω από αυτά τα παράθυρα αγνοούνται σιωπηλά στη συσκευή του θύματος, όμως τα receipts εξακολουθούν να μεταδίδονται, οπότε οι attackers μπορούν να probeάρουν επ’ αόριστον πολύ μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Malformed edit bodies ή deletes που αναφέρονται σε ήδη purged messages προκαλούν την ίδια συμπεριφορά—αποκρυπτογράφηση plus receipt, μηδενικά user-visible artefacts.

## Multi-device amplification & fingerprinting

* Κάθε συσχετισμένη συσκευή (phone, desktop app, browser companion) αποκρυπτογραφεί το probe ανεξάρτητα και επιστρέφει το δικό της ack. Η καταμέτρηση των receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.
* Αν μια συσκευή είναι offline, το receipt της μπαίνει σε ουρά και εκπέμπεται με τη reconnection. Τα κενά επομένως leak online/offline cycles και ακόμη και commuting schedules (π.χ. τα desktop receipts σταματούν κατά τη μετακίνηση).
* Οι RTT distributions διαφέρουν ανά platform λόγω OS power management και push wakeups. Cluster RTTs (π.χ. k-means πάνω σε median/variance features) για να επισημάνεις “Android handset", “iOS handset", “Electron desktop", κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το key inventory του παραλήπτη πριν κρυπτογραφήσει, ο attacker μπορεί επίσης να παρακολουθεί πότε γίνονται pair νέα devices· μια ξαφνική αύξηση στον αριθμό συσκευών ή ένα νέο RTT cluster είναι ισχυρή ένδειξη.

## Behaviour inference from RTT traces

1. Κάνε sample σε ≥1 Hz για να πιάσεις OS scheduling effects. Με WhatsApp σε iOS, RTTs <1 s συσχετίζονται έντονα με screen-on/foreground, ενώ RTTs >1 s με screen-off/background throttling.
2. Χτίσε απλούς classifiers (thresholding ή two-cluster k-means) που επισημαίνουν κάθε RTT ως "active" ή "idle". Συνόψισε τα labels σε streaks για να εξαγάγεις bedtimes, commutes, work hours, ή πότε είναι ενεργός ο desktop companion.
3. Συσχέτισε ταυτόχρονες probes προς κάθε συσκευή για να δεις πότε οι χρήστες αλλάζουν από mobile σε desktop, πότε οι companions βγαίνουν offline, και αν το app περιορίζεται από push ή persistent socket.

## Location inference from delivery RTT

Η ίδια timing primitive μπορεί να επαναχρησιμοποιηθεί για να συμπεράνει πού βρίσκεται ο παραλήπτης, όχι μόνο αν είναι ενεργός. Το έργο `Hope of Delivery` έδειξε ότι η εκπαίδευση πάνω σε RTT distributions για γνωστές τοποθεσίες παραλήπτη επιτρέπει σε έναν attacker αργότερα να ταξινομήσει την τοποθεσία του θύματος μόνο από delivery confirmations:

* Χτίσε ένα baseline για τον ίδιο target ενώ βρίσκεται σε αρκετά γνωστά μέρη (σπίτι, γραφείο, campus, χώρα A vs χώρα B, κ.λπ.).
* Για κάθε τοποθεσία, συλλέξε πολλά normal message RTTs και εξήγαγε απλά features όπως median, variance, ή percentile buckets.
* Κατά το πραγματικό attack, σύγκρινε τη νέα probe series με τα εκπαιδευμένα clusters. Η paper αναφέρει ότι ακόμη και τοποθεσίες μέσα στην ίδια πόλη μπορούν συχνά να διαχωριστούν, με `>80%` accuracy σε σενάριο 3 τοποθεσιών.
* Αυτό λειτουργεί καλύτερα όταν ο attacker ελέγχει το περιβάλλον του sender και κάνει probes υπό παρόμοιες network conditions, επειδή η μετρούμενη διαδρομή περιλαμβάνει το recipient access network, wake-up latency, και την υποδομή του messenger.

Σε αντίθεση με τις silent reaction/edit/delete επιθέσεις παραπάνω, το location inference δεν απαιτεί invalid message IDs ή stealthy state-changing packets. Απλά μηνύματα με κανονικές delivery confirmations αρκούν, οπότε το tradeoff είναι μικρότερο stealth αλλά ευρύτερη εφαρμοσιμότητα σε messengers.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να αποκρυπτογραφηθεί και να επιβεβαιωθεί, η συνεχής αποστολή reaction toggles, invalid edits, ή delete-for-everyone packets δημιουργεί application-layer DoS:

* Αναγκάζει το radio/modem να μεταδίδει/λαμβάνει κάθε δευτερόλεπτο → αισθητή battery drain, ειδικά σε idle handsets.
* Παράγει unmetered upstream/downstream traffic που καταναλώνει mobile data plans ενώ αναμειγνύεται με TLS/WebSocket noise.
* Καταλαμβάνει crypto threads και εισάγει jitter σε latency-sensitive features (VoIP, video calls) παρότι ο χρήστης δεν βλέπει ποτέ notifications.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
