# Επιθέσεις Side-Channel από Delivery Receipt σε E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Τα delivery receipts είναι υποχρεωτικά σε σύγχρονους end-to-end encrypted (E2EE) messengers επειδή οι clients χρειάζονται να ξέρουν πότε ένα ciphertext αποκρυπτογραφήθηκε, ώστε να μπορούν να απορρίψουν το ratcheting state και τα ephemeral keys. Ο server προωθεί opaque blobs, άρα οι επιβεβαιώσεις συσκευής (double checkmarks) εκπέμπονται από τον παραλήπτη μετά από επιτυχή αποκρυπτογράφηση. Η μέτρηση του round-trip time (RTT) μεταξύ μιας ενέργειας που πυροδοτεί ο attacker και του αντίστοιχου delivery receipt αποκαλύπτει ένα timing channel υψηλής ανάλυσης που leakάρει device state, online presence, και μπορεί να αξιοποιηθεί για covert DoS. Τα multi-device "client-fanout" deployments ενισχύουν το leak επειδή κάθε καταχωρημένη συσκευή αποκρυπτογραφεί το probe και επιστρέφει το δικό της receipt.

## Πηγές delivery receipt vs. ορατά από τον χρήστη σήματα

Επίλεξε τύπους μηνυμάτων που πάντα εκπέμπουν delivery receipt αλλά δεν εμφανίζουν UI artifacts στο θύμα. Ο παρακάτω πίνακας συνοψίζει την empirically confirmed συμπεριφορά:

| Messenger | Ενέργεια | Delivery receipt | Ειδοποίηση θύματος | Σημειώσεις |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Μήνυμα κειμένου | ● | ● | Πάντα noisy → χρήσιμο μόνο για bootstrap state. |
| | Reaction | ● | ◐ (μόνο αν γίνεται reaction σε μήνυμα του θύματος) | Τα self-reactions και οι αφαιρέσεις μένουν silent. |
| | Edit | ● | Platform-dependent silent push | Το edit window ≈20 min; εξακολουθεί να ack’άρεται μετά τη λήξη. |
| | Delete for everyone | ● | ○ | Το UI επιτρέπει ~60 h, αλλά και τα μεταγενέστερα packets εξακολουθούν να ack’άρονται. |
| **Signal** | Μήνυμα κειμένου | ● | ● | Οι ίδιοι περιορισμοί με το WhatsApp. |
| | Reaction | ● | ◐ | Τα self-reactions είναι αόρατα στο θύμα. |
| | Edit/Delete | ● | ○ | Ο server επιβάλλει window ~48 h, επιτρέπει έως 10 edits, αλλά τα late packets εξακολουθούν να ack’άρονται. |
| **Threema** | Μήνυμα κειμένου | ● | ● | Τα multi-device receipts συγκεντρώνονται, άρα μόνο ένα RTT ανά probe γίνεται ορατό. |

Υπόμνημα: ● = πάντα, ◐ = υπό συνθήκη, ○ = ποτέ. Η platform-dependent συμπεριφορά του UI σημειώνεται inline. Απενεργοποίησε τα read receipts αν χρειάζεται, αλλά τα delivery receipts δεν μπορούν να απενεργοποιηθούν στο WhatsApp ή στο Signal.

## Στόχοι και μοντέλα επιτιθέμενου

* **G1 – Device fingerprinting:** Μέτρησε πόσα receipts φτάνουν ανά probe, ομαδοποίησε RTTs για να συμπεράνεις OS/client (Android vs iOS vs desktop), και παρακολούθησε μεταβάσεις online/offline.
* **G2 – Behavioral monitoring:** Αντιμετώπισε τη σειρά RTT υψηλής συχνότητας (≈1 Hz είναι σταθερό) ως time-series και συμπέρανε screen on/off, app foreground/background, commute vs working hours, κ.λπ.
* **G3 – Resource exhaustion:** Κράτα radios/CPUs κάθε συσκευής του θύματος awake στέλνοντας ατελείωτα silent probes, αδειάζοντας μπαταρία/data και υποβαθμίζοντας την ποιότητα VoIP/RTC.

Αρκούν δύο threat actors για να περιγράψουν την επιφάνεια κατάχρησης:

1. **Creepy companion:** ήδη μοιράζεται ένα chat με το θύμα και καταχράται self-reactions, reaction removals ή επαναλαμβανόμενα edits/deletes συνδεδεμένα με υπάρχοντα message IDs.
2. **Spooky stranger:** καταχωρεί έναν burner account και στέλνει reactions που αναφέρονται σε message IDs που δεν υπήρξαν ποτέ στο τοπικό conversation· το WhatsApp και το Signal εξακολουθούν να τα αποκρυπτογραφούν και να τα acknowledge’άρουν ακόμη κι αν το UI απορρίπτει την αλλαγή κατάστασης, άρα δεν απαιτείται προηγούμενη συνομιλία.

## Εργαλεία για raw protocol access

Βασίσου σε clients που εκθέτουν το υποκείμενο E2EE protocol ώστε να μπορείς να κατασκευάζεις packets έξω από τους UI περιορισμούς, να ορίζεις αυθαίρετα `message_id`s και να καταγράφεις ακριβή timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ή [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) σου επιτρέπουν να εκπέμπεις raw `ReactionMessage`, `ProtocolMessage` (edit/delete) και `Receipt` frames διατηρώντας το double-ratchet state συγχρονισμένο.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) σε συνδυασμό με [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) εκθέτει κάθε message type μέσω CLI/API. Η τρέχουσα σύνταξη του `signal-cli` χρησιμοποιεί `sendReaction RECIPIENT --target-author --target-timestamp`; κράτα το `receive` ή `daemon` σε λειτουργία ώστε να συλλέγονται πραγματικά τα delivery receipts. Παράδειγμα self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Ο πηγαίος κώδικας του Android client τεκμηριώνει πώς τα delivery receipts συγκεντρώνονται πριν φύγουν από τη συσκευή, εξηγώντας γιατί το side channel έχει αμελητέο bandwidth εκεί.
* **Turnkey PoCs:** Το [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) περιλαμβάνει WhatsApp/Signal backends, χρησιμοποιεί ως προεπιλογή silent delete probes, και επισημαίνει `active` vs `standby` με rolling-median threshold (`RTT < 0.9 * median`). Το [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) είναι ένα πιο ελαφρύ WhatsApp-first CLI με `--delay`, `--concurrent`, CSV/Prometheus exporters και output φιλικό προς Grafana. Αντιμετώπισε και τα δύο ως reconnaissance helpers και όχι ως protocol references· το σημαντικό συμπέρασμα είναι πόσο λίγο code χρειάζεται μόλις υπάρχει raw client access.

Όταν δεν υπάρχει custom tooling, μπορείς ακόμα να πυροδοτήσεις silent actions από WhatsApp Web ή Signal Desktop και να sniffάρεις το encrypted websocket/WebRTC channel, αλλά τα raw APIs αφαιρούν τα UI delays και επιτρέπουν invalid operations.

## Creepy companion: silent sampling loop

1. Επίλεξε οποιοδήποτε historical message έγραψες εσύ στο chat ώστε το θύμα να μην βλέπει ποτέ τα "reaction" balloons να αλλάζουν.
2. Εναλλάσσε ανάμεσα σε ένα ορατό emoji και σε ένα empty reaction payload (encoded ως `""` στα WhatsApp protobufs ή `--remove` στο signal-cli). Κάθε μετάδοση δίνει device ack παρότι δεν υπάρχει UI delta για το θύμα.
3. Χρονοσήμανε το send time και κάθε άφιξη delivery receipt. Ένα 1 Hz loop όπως το παρακάτω δίνει per-device RTT traces επ' αόριστον:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Επειδή το WhatsApp/Signal δέχονται απεριόριστα reaction updates, ο attacker δεν χρειάζεται ποτέ να δημοσιεύσει νέο chat content ούτε να ανησυχεί για edit windows.

## Spooky stranger: probing αυθαίρετων αριθμών τηλεφώνου

1. Καταχώρησε έναν φρέσκο WhatsApp/Signal account και λάβε τα δημόσια identity keys για τον αριθμό-στόχο (αυτό γίνεται αυτόματα κατά το session setup).
2. Κατασκεύασε ένα reaction/edit/delete packet που αναφέρεται σε ένα τυχαίο `message_id` που δεν είδε ποτέ κανένα από τα δύο μέρη (το WhatsApp δέχεται αυθαίρετα `key.id` GUIDs· το Signal χρησιμοποιεί millisecond timestamps).
3. Στείλε το packet παρότι δεν υπάρχει thread. Οι συσκευές του θύματος το αποκρυπτογραφούν, αποτυγχάνουν να ταιριάξουν το base message, απορρίπτουν την αλλαγή κατάστασης, αλλά εξακολουθούν να acknowledge’άρουν το εισερχόμενο ciphertext, στέλνοντας device receipts πίσω στον attacker.
4. Επανάλαβε συνεχώς για να χτίσεις σειρές RTT χωρίς ποτέ να εμφανιστείς στη λίστα chats του θύματος.

Αν πρώτα χρειάζεται να ανακαλύψεις ποιοι αριθμοί είναι registered ή θέλεις να pre-seed device inventories σε κλίμακα, σύνδεσε αυτό με [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) αντί να μαντεύεις τυχαία E.164 ranges με το χέρι.

Οι πρόσφατες εκδόσεις του WhatsApp επίσης εκθέτουν `Settings -> Privacy -> Advanced -> Block unknown account messages`. Αντιμετώπισέ το ως throughput limiter, όχι ως λύση: κυρίως δυσκολεύει το sustained stranger-only flooding και είναι άσχετο μόλις είσαι ήδη γνωστή επαφή.

## Επαναχρησιμοποίηση edits και deletes ως covert triggers

* **Repeated deletes:** Αφού ένα μήνυμα διαγραφεί-for-everyone μία φορά, περαιτέρω delete packets που αναφέρονται στο ίδιο `message_id` δεν έχουν UI effect, αλλά κάθε συσκευή εξακολουθεί να τα αποκρυπτογραφεί και να τα acknowledge’άρει.
* **Out-of-window operations:** Το WhatsApp επιβάλλει window ~60 h για delete / ~20 min για edit στο UI· το Signal επιβάλλει ~48 h. Τα crafted protocol messages έξω από αυτά τα windows αγνοούνται silent στη συσκευή του θύματος, όμως τα receipts μεταδίδονται, άρα οι attackers μπορούν να κάνουν probe για πολύ μεγάλο διάστημα μετά το τέλος της συνομιλίας.
* **Invalid payloads:** Malformed edit bodies ή deletes που αναφέρονται σε ήδη purged messages προκαλούν την ίδια συμπεριφορά—αποκρυπτογράφηση συν receipt, μηδενικά user-visible artefacts.

## Ενίσχυση multi-device & fingerprinting

* Κάθε συνδεδεμένη συσκευή (phone, desktop app, browser companion) αποκρυπτογραφεί το probe ανεξάρτητα και επιστρέφει το δικό της ack. Η μέτρηση των receipts ανά probe αποκαλύπτει τον ακριβή αριθμό συσκευών.
* Αν μια συσκευή είναι offline, το receipt της μπαίνει σε ουρά και εκπέμπεται κατά την επανασύνδεση. Τα κενά, επομένως, leakάρουν κύκλους online/offline και ακόμη και προγράμματα μετακίνησης (π.χ. τα desktop receipts σταματούν κατά τη διάρκεια του ταξιδιού).
* Οι κατανομές RTT διαφέρουν ανά platform λόγω OS power management και push wakeups. Ομαδοποίησε RTTs (π.χ. k-means σε features median/variance) για να επισημάνεις “Android handset", “iOS handset", “Electron desktop", κ.λπ.
* Επειδή ο sender πρέπει να ανακτήσει το key inventory του παραλήπτη πριν από την κρυπτογράφηση, ο attacker μπορεί επίσης να παρακολουθεί πότε γίνονται pair νέα devices· μια απότομη αύξηση στον αριθμό συσκευών ή ένα νέο RTT cluster είναι ισχυρή ένδειξη.

## Συμπεράσματα συμπεριφοράς από RTT traces

1. Δειγμάτισε σε ≥1 Hz για να συλλάβεις OS scheduling effects. Με WhatsApp σε iOS, RTTs <1 s συσχετίζονται έντονα με screen-on/foreground, ενώ >1 s με screen-off/background throttling.
2. Κατασκεύασε απλούς classifiers (thresholding ή two-cluster k-means) που επισημαίνουν κάθε RTT ως "active" ή "idle". Συνόψισε τις ετικέτες σε streaks για να προκύψουν bedtimes, commutes, work hours ή το πότε είναι ενεργό το desktop companion.
3. Συσχέτισε ταυτόχρονες probes προς κάθε συσκευή για να δεις πότε οι χρήστες αλλάζουν από mobile σε desktop, πότε τα companions βγαίνουν offline και αν το app rate-limited από push ή persistent socket.
4. Σε πραγματικά δίκτυα, απόφυγε ένα μονό hardcoded `1 s` threshold. Κάνε bootstrap σε κάθε συσκευή με ένα σύντομο warm-up window και κράτα ένα rolling baseline (για παράδειγμα, `threshold = 0.9 * median RTT`) ώστε η μεταβολή Wi-Fi/cellular να μην καταρρίψει τον classifier σου.

## Συμπεράσματα τοποθεσίας από delivery RTT

Ο ίδιος timing primitive μπορεί να επαναχρησιμοποιηθεί για να συμπεράνει όχι μόνο αν ο παραλήπτης είναι active, αλλά και πού βρίσκεται. Το έργο `Hope of Delivery` έδειξε ότι η εκπαίδευση σε RTT distributions για γνωστές τοποθεσίες παραλήπτη επιτρέπει σε έναν attacker να ταξινομήσει αργότερα τη θέση του θύματος μόνο από delivery confirmations:

* Χτίσε ένα baseline για τον ίδιο στόχο ενώ βρίσκεται σε αρκετές γνωστές τοποθεσίες (σπίτι, γραφείο, campus, country A vs country B, κ.λπ.).
* Για κάθε τοποθεσία, μάζεψε πολλά normal message RTTs και εξήγαγε απλά features όπως median, variance ή percentile buckets.
* Κατά την πραγματική επίθεση, σύγκρινε τη νέα σειρά probes με τα εκπαιδευμένα clusters. Η εργασία αναφέρει ότι ακόμη και τοποθεσίες μέσα στην ίδια πόλη συχνά μπορούν να διαχωριστούν, με ακρίβεια `>80%` σε σενάριο 3 τοποθεσιών.
* Αυτό λειτουργεί καλύτερα όταν ο attacker ελέγχει το sender environment και κάνει probes κάτω από παρόμοιες network conditions, επειδή η μετρημένη διαδρομή περιλαμβάνει το recipient access network, wake-up latency και messenger infrastructure.

Σε αντίθεση με τις silent reaction/edit/delete επιθέσεις παραπάνω, η συμπερασματολογία τοποθεσίας δεν απαιτεί invalid message IDs ή stealthy state-changing packets. Απλά μηνύματα με κανονικές delivery confirmations αρκούν, άρα το tradeoff είναι χαμηλότερη stealth αλλά ευρύτερη εφαρμοσιμότητα σε messengers.

## Stealthy resource exhaustion

Επειδή κάθε silent probe πρέπει να αποκρυπτογραφηθεί και να acknowledge’αριστεί, η συνεχής αποστολή reaction toggles, invalid edits ή delete-for-everyone packets δημιουργεί ένα application-layer DoS:

* Αναγκάζει το radio/modem να στέλνει/λαμβάνει κάθε δευτερόλεπτο → αισθητή αποστράγγιση μπαταρίας, ειδικά σε idle handsets.
* Παράγει unmetered upstream/downstream traffic που καταναλώνει mobile data plans ενώ αναμειγνύεται στο TLS/WebSocket noise.
* Καταλαμβάνει crypto threads και εισάγει jitter σε latency-sensitive features (VoIP, video calls) παρότι ο χρήστης δεν βλέπει ποτέ ειδοποιήσεις.
* Στο WhatsApp, τα invalid reactions δέχονται πολύ περισσότερα data απ' ό,τι υπονοεί ένα κανονικό emoji: δημοσιευμένες μετρήσεις βρήκαν server-side acceptance έως περίπου `1 MB` ανά reaction.
* Τα oversized reactions σταματούν να παράγουν αξιόπιστα delivery receipts όταν το body μεγαλώσει πάνω από περίπου `30 bytes`, αλλά εξακολουθούν να προωθούνται και να επεξεργάζονται πριν απορριφθούν. Κράτα τα reaction bodies μικρά όταν χρειάζεσαι ACKs· φούσκωσέ τα μόνο όταν ο στόχος είναι καθαρή αποστράγγιση ή covert one-way transport.
* Δημοσιευμένες μετρήσεις έφτασαν περίπου `3.7 MB/s` (`~13.3 GB/h`) traffic του θύματος σε αυτό το mode.

## Αναφορές

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
