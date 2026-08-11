# Παράκαμψη KYC με χρήση AI

{{#include ../banners/hacktricks-training.md}}

Τα Generative models μπορούν να χρησιμοποιηθούν για **παράκαμψη browser-based KYC, age-verification και biometric liveness workflows**. Το αδύναμο σημείο συχνά **δεν είναι το transport ή ο cloud liveness provider**, αλλά το **camera trust boundary**: ένας desktop browser συνήθως εμπιστεύεται οποιαδήποτε συσκευή εκθέτει το `getUserMedia()` ως webcam.<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **Δημιουργία challenge-compliant media** με video-to-video model, χρησιμοποιώντας έναν source actor και μια reference image του victim.<sup>[[1]](#references)</sup>
2. **Injection του forged stream πριν από το signing ή το upload**, για παράδειγμα μέσω μιας Linux virtual camera που δημιουργήθηκε με `v4l2loopback` και τροφοδοτείται από OBS ή FFmpeg.<sup>[[3]](#references)</sup>
3. Άφησε τον browser και το vendor SDK (WebRTC, AWS κ.λπ.) να **κάνουν capture, sign και upload τα attacker-controlled frames σαν να προέρχονταν από πραγματική webcam**.<sup>[[2]](#references)</sup>

Αυτό είναι σημαντικό κατά τη διάρκεια assessments, επειδή τα signed WebSocket chunks ή το proprietary SDK framing μπορεί να κάνουν το **network-layer tampering** μη πρακτικό, ενώ το **camera-layer injection** εξακολουθεί να λειτουργεί.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Αποδοχή virtual webcam**: αν το flow λειτουργεί από desktop browser, έλεγξε αν τα OBS, `v4l2loopback` ή vendor virtual cameras γίνονται αποδεκτά ως κανονικά peripherals.<sup>[[1]](#references)</sup>
- **Camera API redirection σε mobile**: τα native flows μπορεί να παραμένουν ευάλωτα όταν runtime instrumentation, όπως το Frida, κάνει hooks στα camera APIs και αντικαθιστά τα sensor buffers με frames από αρχείο MP4 ή emulator-backed virtual camera. Αυτό απαιτεί έλεγχο του client execution environment και πρέπει να αξιολογείται μαζί με root/jailbreak και application-integrity signals.<sup>[[1]](#references)</sup>
- **Constraint weakening**: σελίδες που απαιτούν ακριβή `deviceId`, `frameRate`, `width`, `height` ή `facingMode` μπορούν μερικές φορές να παρακαμφθούν με monkeypatching του `navigator.mediaDevices.getUserMedia` και αντικατάσταση των strict constraints με ευρύτερα ranges.<sup>[[4]](#references)</sup>
- **Low-quality generation και post-processing**: έλεγξε αν ένα φθηνό generated video μπορεί να γίνει upscale ή frame-interpolated με FFmpeg, ώστε να πληροί επαρκώς τα capture constraints.<sup>[[1]](#references)</sup>
- **Predictable active challenges**: επαναλαμβανόμενες ακολουθίες head-movement ή light-flash αξίζει να καταγράφονται και να αναπαράγονται μέσω generative workflow.
- **Weak replay detection**: απλές scene perturbations, όπως αλλαγές σε crop ή position, αλλαγές σε overlays ή μικρή κίνηση, μπορεί να αρκούν όταν η anti-replay λογική ελέγχει μόνο superficial frame similarity.<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Τα native mobile apps μπορούν να αυξήσουν το κόστος για τον attacker με:<sup>[[1]](#references)</sup>

- **hardware-backed provenance ή attestation signals**, συμπεριλαμβανομένων evidence backed by Secure Element, όταν η platform και το capture stack τα εκθέτουν πράγματι·
- **execution-integrity** signals όπως **Play Integrity** ή **App Attest**·<sup>[[5]](#references)[[6]](#references)</sup>
- **motion correlation** μεταξύ video και telemetry από accelerometer ή gyroscope.

Τα desktop web flows συνήθως δεν διαθέτουν ισοδύναμο camera chain of trust, επομένως αποτελούν γενικά το path of least resistance.<sup>[[1]](#references)</sup>

## Defensive Review Notes

Κατά την αξιολόγηση ενός KYC ή liveness integration, επιβεβαίωσε αν:<sup>[[1]](#references)</sup>

- επιτρέπει **desktop-browser fallback** για workflow που είχε γίνει threat-modeling μόνο για mobile capture·
- βασίζεται κυρίως σε **algorithmic liveness** χωρίς ισχυρό human escalation για ύποπτα sessions·
- χρησιμοποιεί **stable ή predictable challenges** που μπορούν να προ-καταγραφούν και να τροφοδοτηθούν σε generation pipeline·
- ανιχνεύει **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry ή missing device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Παράκαμψη age verification με χρήση generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
