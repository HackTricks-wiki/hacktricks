# Side-Channel Attacks στις αποδείξεις παράδοσης σε E2EE messengers

{{#include ../banners/hacktricks-training.md}}

Οι αποδείξεις παράδοσης (delivery receipts) είναι υποχρεωτικές στους σύγχρονους end-to-end encrypted (E2EE) messengers επειδή οι clients πρέπει να ξέρουν πότε ένα ciphertext αποκρυπτογραφήθηκε ώστε να απορρίψουν το ratcheting state και τα ephemeral keys. Ο server προωθεί αδιαφανή blobs, οπότε οι συσκευές αποστολέα (διπλά τσεκ) εκπέμπουν acknowledgements από τον παραλήπτη μετά από επιτυχή αποκρυπτογράφηση. Η μέτρηση του round-trip time (RTT) μεταξύ μιας ενέργειας που προκαλεί ο attacker και της αντίστοιχης delivery receipt αποκαλύπτει ένα high-resolution timing channel που leak device state, online presence, και μπορεί να καταχραστεί για covert DoS. Οι multi-device "client-fanout" αναπτύξεις πολλαπλασιάζουν το leak επειδή κάθε καταχωρημένη συσκευή αποκρυπτογραφεί το probe και επιστρέφει τη δική της receipt.

## Πηγές delivery receipts vs. εμφανή UI σήματα

Επιλέξτε τύπους μηνυμάτων που πάντα εκπέμπουν delivery receipt αλλά δεν εμφανίζουν UI artifacts στο θύμα. Ο παρακάτω πίνακας συνοψίζει το εμπειρικά επιβεβαιωμένο behaviour:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → only useful to bootstrap state. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions and removals stay silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; still ack’d after expiry. |
| | Delete for everyone | ● | ○ | UI allows ~60 h, but later packets still ack’d. |
| **Signal** | Text message | ● | ● | Same limitations as WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions invisible to victim. |
| | Edit/Delete | ● | ○ | Server enforces ~48 h window, allows up to 10 edits, but late packets still ack’d. |
| **Threema** | Text message | ● | ● | Multi-device receipts are aggregated, so only one RTT per probe becomes visible. |

Legend: ● = πάντα, ◐ = υπό όρους, ○ = ποτέ. Το platform-dependent UI behaviour σημειώνεται inline. Απενεργοποιήστε τα read receipts αν χρειάζεται, αλλά τα delivery receipts δεν μπορούν να απενεργοποιηθούν σε WhatsApp ή Signal.

## Στόχοι και μοντέλα επιτιθέμενου

* **G1 – Device fingerprinting:** Μετρήστε πόσες receipts έρχονται ανά probe, κάντε clustering στα RTT για να συμπεράνετε OS/client (Android vs iOS vs desktop), και παρακολουθήστε μεταβάσεις online/offline.
* **G2 – Behavioural monitoring:** Θεωρήστε τη high-frequency σειρά RTT (≈1 Hz είναι σταθερή) ως time-series και εξαγάγετε screen on/off, app foreground/background, commuting vs working hours, κ.λπ.
* **G3 – Resource exhaustion:** Κρατήστε τα radios/CPUs κάθε θύματος ξυπνημένα στέλνοντας ατελείωτα silent probes, στραγγίζοντας μπαταρία/δεδομένα και υποβαθμίζοντας την ποιότητα VoIP/RTC.

Δύο threat actors αρκούν για να περιγράψουν την επιφάνεια κατάχρησης:

1. **Creepy companion:** ήδη μοιράζεται chat με το θύμα και καταχράται self-reactions, reaction removals, ή επαναλαμβανόμενα edits/deletes συνδεδεμένα με υπάρχοντα message IDs.
2. **Spooky stranger:** εγγράφει ένα burner account και στέλνει reactions που αναφέρονται σε message IDs που δεν υπήρξαν ποτέ στην τοπική συνομιλία· WhatsApp και Signal αποκρυπτογραφούν και ack’άρουν αυτά ακόμα κι αν το UI απορρίψει την αλλαγή κατάστασης, οπότε δεν απαιτείται προηγούμενη συνομιλία.

## Εργαλεία για raw πρόσβαση στο protocol

Βασιστείτε σε clients που εκθέτουν το underlying E2EE protocol ώστε να μπορείτε να κατασκευάσετε πακέτα εκτός των UI περιορισμών, να ορίσετε αυθαίρετα `message_id`s, και να καταγράψετε ακριβή timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ή [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) σας επιτρέπουν να εκπέμψετε raw `ReactionMessage`, `ProtocolMessage` (edit/delete), και `Receipt` frames ενώ διατηρούν το double-ratchet state σε συγχρονισμό.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) combined with [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) εκθέτουν κάθε message type μέσω CLI/API. Παράδειγμα toggle self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Το source του Android client τεκμηριώνει πώς τα delivery receipts κονσολιδεύονται πριν φύγουν από τη συσκευή, εξηγώντας γιατί το side channel έχει ασήμαντο bandwidth εκεί.

Όταν δεν υπάρχει custom tooling, μπορείτε να ενεργοποιήσετε silent actions από WhatsApp Web ή Signal Desktop και να sniffάρετε το encrypted websocket/WebRTC κανάλι, αλλά τα raw APIs αφαιρούν UI delays και επιτρέπουν invalid operations.

## Creepy companion: silent sampling loop

1. Επιλέξτε οποιοδήποτε ιστορικό μήνυμα που έχετε γράψει στο chat ώστε το θύμα να μην βλέπει αλλαγές στα "reaction" balloons.
2. Εναλλάξτε μεταξύ ενός εμφανούς emoji και ενός empty reaction payload (encoded ως `""` στα WhatsApp protobufs ή `--remove` στο signal-cli). Κάθε μετάδοση παράγει device ack παρότι δεν υπάρχει UI delta για το θύμα.
3. Timestamp το send time και κάθε arrival της delivery receipt. Ένας 1 Hz loop όπως ο παρακάτω δίνει per-device RTT traces επ’ αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή WhatsApp/Signal αποδέχονται unlimited reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο περιεχόμενο chat ούτε να ανησυχεί για παράθυρα επεξεργασίας.

## Spooky stranger: probing arbitrary phone numbers

1. Εγγραφείτε ένα νέο WhatsApp/Signal account και φέρετε τα public identity keys για τον target αριθμό (γίνεται αυτόματα κατά το session setup).
2. Κατασκευάστε ένα reaction/edit/delete πακέτο που αναφέρεται σε ένα τυχαίο `message_id` που δεν έχει δει ποτέ κανένα μέρος (WhatsApp αποδέχεται αυθαίρετα `key.id` GUIDs· Signal χρησιμοποιεί millisecond timestamps).
3. Στείλτε το πακέτο παρότι δεν υπάρχει thread. Οι συσκευές του θύματος το αποκρυπτογραφούν, δεν βρίσκουν το base message, απορρίπτουν την αλλαγή state, αλλά εξακολουθούν να ack’άρουν το εισερχόμενο ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επαναλάβετε συνεχώς για να χτίσετε σειρά RTT χωρίς ποτέ να εμφανιστείτε στη λίστα chat του θύματος.

## Ανακύκλωση edits και deletes ως covert triggers

* **Repeated deletes:** Μετά από ένα delete-for-everyone, περαιτέρω delete πακέτα που αναφέρονται στο ίδιο `message_id` δεν έχουν UI effect αλλά κάθε συσκευή εξακολουθεί να τα αποκρυπτογραφεί και να τα ack’άρει.
* **Out-of-window operations:** Το WhatsApp επιβάλλει ~60 h για delete / ~20 min για edit στα UI· το Signal ~48 h. Τα crafted protocol messages έξω από αυτά τα παράθυρα αγνοούνται σιωπηλά στη συσκευή του θύματος, αλλά οι receipts μεταδίδονται, οπότε οι attackers μπορούν να probe επ’ αόριστον και πολύ μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Κατεστραμμένα edit bodies ή deletes που αναφέρονται σε ήδη purged μηνύματα προκαλούν την ίδια συμπεριφορά — αποκρυπτογράφηση συν receipt, μηδέν ορατά artifacts για τον χρήστη.

## Multi-device amplification & fingerprinting

* Κάθε συσχετισμένη συσκευή (phone, desktop app, browser companion) αποκρυπτογραφεί το probe ανεξάρτητα και επιστρέφει το δικό της ack. Η καταμέτρηση receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.
* Αν μια συσκευή είναι offline, η receipt της μπαίνει σε queue και εκπέμπεται κατά την επανασύνδεση. Τα gaps επομένως leak online/offline cycles και ακόμη και commuting schedules (π.χ. οι desktop receipts σταματούν κατά τη διάρκεια ταξιδιών).
* Οι κατανομές RTT διαφέρουν ανά πλατφόρμα λόγω OS power management και push wakeups. Κάντε cluster στα RTT (π.χ. k-means σε median/variance features) για να επισημάνετε “Android handset”, “iOS handset”, “Electron desktop”, κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το recipient’s key inventory πριν κρυπτογραφήσει, ο attacker μπορεί επίσης να παρατηρεί πότε προστίθενται νέες συσκευές· μια απότομη αύξηση στον αριθμό συσκευών ή νέο RTT cluster είναι ισχυρός δείκτης.

## Σύνθεση συμπερασμάτων από RTT traces

1. Sampλε στο ≥1 Hz για να συλλάβετε effects του OS scheduling. Με WhatsApp σε iOS, <1 s RTTs συσχετίζονται ισχυρά με screen-on/foreground, >1 s με screen-off/background throttling.
2. Χτίστε απλούς classifiers (thresholding ή two-cluster k-means) που επισημαίνουν κάθε RTT ως "active" ή "idle". Συγκεκρίνετε τις ετικέτες σε streaks για να εξαχθούν bedtimes, commutes, εργάσιμες ώρες, ή πότε το desktop companion είναι ενεργό.
3. Correlate simultaneous probes προς κάθε συσκευή για να δείτε πότε οι χρήστες μεταβαίνουν από mobile σε desktop, πότε companions αποσυνδέονται, και αν η εφαρμογή rate limited από push vs persistent socket.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να αποκρυπτογραφηθεί και να ack’αριστεί, το συνεχές στέλσιμο reaction toggles, invalid edits, ή delete-for-everyone πακέτων δημιουργεί application-layer DoS:

* Αναγκάζει το radio/modem να στέλνει/λαμβάνει κάθε δευτερόλεπτο → αισθητή drain μπαταρίας, ειδικά σε idle handsets.
* Γεννά αχρεώστη upstream/downstream traffic που καταναλώνει mobile data plans ενώ συγχωνεύεται στο TLS/WebSocket noise.
* Καταλαμβάνει crypto threads και εισάγει jitter σε latency-sensitive λειτουργίες (VoIP, video calls) παρότι ο χρήστης δεν βλέπει ποτέ notifications.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
