# Παράκαμψη KYC με χρήση AI

{{#include ../banners/hacktricks-training.md}}

Τα Generative models μπορούν να χρησιμοποιηθούν για **παράκαμψη KYC μέσω browser, επαλήθευσης ηλικίας και ροών βιομετρικής ανίχνευσης ζωντανής παρουσίας**. Το αδύναμο σημείο συχνά **δεν** είναι η μεταφορά ή ο cloud πάροχος liveness, αλλά το **όριο εμπιστοσύνης της κάμερας**: ένας desktop browser συνήθως εμπιστεύεται οποιαδήποτε συσκευή εκθέτει το `getUserMedia()` ως webcam.<sup>[[1]](#references)</sup>

## Πρακτική αλυσίδα επίθεσης

1. **Δημιουργία media που συμμορφώνονται με τα challenges** με ένα video-to-video model, χρησιμοποιώντας έναν source actor και μια εικόνα αναφοράς του θύματος.<sup>[[1]](#references)</sup>
2. **Εισαγωγή του forged stream πριν από την υπογραφή ή το upload**, για παράδειγμα μέσω μιας Linux virtual camera που δημιουργήθηκε με `v4l2loopback` και τροφοδοτείται από OBS ή FFmpeg.<sup>[[3]](#references)</sup>
3. Αφήστε τον browser και το vendor SDK (WebRTC, AWS κ.λπ.) να **συλλάβουν, υπογράψουν και ανεβάσουν τα frames που ελέγχει ο attacker, σαν να προέρχονταν από πραγματική webcam**.<sup>[[2]](#references)</sup>

Αυτό είναι σημαντικό κατά τις αξιολογήσεις, επειδή τα υπογεγραμμένα WebSocket chunks ή το proprietary SDK framing μπορεί να καθιστούν το **network-layer tampering** μη πρακτικό, ενώ το **camera-layer injection** εξακολουθεί να λειτουργεί.<sup>[[1]](#references)</sup>

## Πολύτιμες κατευθύνσεις testing

- **Αποδοχή virtual webcam**: αν η ροή λειτουργεί από desktop browser, ελέγξτε αν τα OBS, `v4l2loopback` ή οι virtual cameras του vendor γίνονται αποδεκτά ως κανονικά peripherals.<sup>[[1]](#references)</sup>
- **Ανακατεύθυνση Camera API σε mobile**: οι native mobile ροές μπορεί να παραμένουν ευάλωτες όταν τα Frida hooks στις camera APIs αντικαθιστούν τα sensor buffers με frames από ένα MP4 ή από virtual camera που υποστηρίζεται από emulator.
- **Αποδυνάμωση constraints**: σελίδες που απαιτούν ακριβή `deviceId`, `frameRate`, `width`, `height` ή `facingMode` μπορούν μερικές φορές να παρακαμφθούν με monkeypatching του `navigator.mediaDevices.getUserMedia` και αντικατάσταση των strict constraints με ευρύτερα ranges.<sup>[[4]](#references)</sup>
- **Generation χαμηλής ποιότητας και post-processing**: δημιουργήστε το φθηνότερο video που μπορεί να αποδώσει αξιόπιστα το model και, στη συνέχεια, χρησιμοποιήστε FFmpeg upscaling ή frame interpolation για να ικανοποιήσετε τις απαιτήσεις capture.
- **Προβλέψιμα active challenges**: επαναλαμβανόμενες ακολουθίες κίνησης του κεφαλιού ή αναλαμπών φωτός αξίζει να καταγράφονται και να αναπαράγονται μέσω generative workflow.
- **Αδύναμη ανίχνευση replay**: απλές μεταβολές της σκηνής, όπως αλλαγές crop ή θέσης, αλλαγές overlay ή ελαφριά κίνηση, μπορεί να επαρκούν όταν η anti-replay λογική ελέγχει μόνο επιφανειακή ομοιότητα frames.<sup>[[1]](#references)</sup>

## Διαφορές εμπιστοσύνης μεταξύ Mobile και Desktop

Οι native mobile εφαρμογές μπορούν να αυξήσουν το κόστος για τον attacker μέσω:<sup>[[1]](#references)</sup>

- **attestation αισθητήρων ή Secure Element** για camera buffers·
- σημάτων **execution-integrity**, όπως τα **Play Integrity** ή **App Attest**·
- **συσχέτισης κίνησης** μεταξύ video και telemetry από accelerometer ή gyroscope.

Οι desktop web ροές συνήθως δεν διαθέτουν αντίστοιχη chain of trust για την κάμερα, επομένως αποτελούν γενικά τη διαδρομή με τη μικρότερη αντίσταση.<sup>[[1]](#references)</sup>

## Σημειώσεις αμυντικού ελέγχου

Κατά την αξιολόγηση μιας ενσωμάτωσης KYC ή liveness, επαληθεύστε αν:<sup>[[1]](#references)</sup>

- επιτρέπει **desktop-browser fallback** για μια ροή που είχε μοντελοποιηθεί ως προς τις απειλές μόνο για mobile capture·
- βασίζεται κυρίως σε **algorithmic liveness** χωρίς ισχυρή ανθρώπινη κλιμάκωση για ύποπτα sessions·
- χρησιμοποιεί **σταθερά ή προβλέψιμα challenges** που μπορούν να προ-καταγραφούν και να τροφοδοτηθούν σε generation pipeline·
- ανιχνεύει **`getUserMedia` monkeypatching**, virtual cameras, ασυνεπή telemetry hardware του browser ή απουσία device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
