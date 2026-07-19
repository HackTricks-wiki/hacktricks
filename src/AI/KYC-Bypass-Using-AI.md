# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Τα Generative models μπορούν να χρησιμοποιηθούν για **bypass browser-based KYC, age-verification και biometric liveness workflows**. Το αδύναμο σημείο συχνά **δεν** είναι το transport ή ο cloud liveness provider, αλλά το **camera trust boundary**: ένας desktop browser συνήθως εμπιστεύεται οποιαδήποτε συσκευή εκθέτει το `getUserMedia()` ως webcam.

## Practical Attack Chain

1. **Παραγωγή challenge-compliant media** με ένα video-to-video model, χρησιμοποιώντας έναν source actor και μια victim reference image.
2. **Injection του forged stream πριν από το signing ή το upload**, για παράδειγμα μέσω μιας Linux virtual camera που δημιουργείται με `v4l2loopback` και τροφοδοτείται από OBS ή FFmpeg.
3. Επιτρέψτε στον browser και στο vendor SDK (WebRTC, AWS κ.λπ.) να **κάνουν capture, sign και upload τα attacker-controlled frames σαν να προέρχονται από πραγματική webcam**.

Αυτό είναι σημαντικό κατά τη διάρκεια assessments, επειδή τα signed WebSocket chunks ή το proprietary SDK framing μπορεί να κάνουν το **network-layer tampering** μη πρακτικό, ενώ το **camera-layer injection** εξακολουθεί να λειτουργεί.

## High-Value Testing Angles

- **Virtual webcam acceptance**: αν το flow λειτουργεί από desktop browser, ελέγξτε αν τα OBS, `v4l2loopback` ή vendor virtual cameras γίνονται αποδεκτά ως κανονικά peripherals.
- **Camera API redirection on mobile**: τα native mobile flows μπορεί να παραμένουν vulnerable όταν το Frida κάνει hooks στα camera APIs και αντικαθιστά τα sensor buffers με frames από ένα MP4 ή από emulator-backed virtual camera.
- **Constraint weakening**: σελίδες που απαιτούν ακριβές `deviceId`, `frameRate`, `width`, `height` ή `facingMode` μπορούν μερικές φορές να γίνουν bypass μέσω monkeypatching του `navigator.mediaDevices.getUserMedia` και αντικατάστασης των strict constraints με ευρύτερα ranges.
- **Low-quality generation plus post-processing**: δημιουργήστε το φθηνότερο video που μπορεί να renderάρει αξιόπιστα το model και, στη συνέχεια, χρησιμοποιήστε FFmpeg upscaling ή frame interpolation για να ικανοποιήσετε τις capture requirements.
- **Predictable active challenges**: επαναλαμβανόμενες ακολουθίες head-movement ή light-flash αξίζει να καταγραφούν και να αναπαραχθούν μέσω generative workflow.
- **Weak replay detection**: απλές scene perturbations, όπως crop ή position shifts, αλλαγές σε overlays ή ελαφριά κίνηση, μπορεί να αρκούν όταν η anti-replay λογική ελέγχει μόνο επιφανειακή ομοιότητα frames.

## Mobile vs. Desktop Trust Differences

Τα native mobile apps μπορούν να αυξήσουν το κόστος για τον attacker με:

- **sensor ή Secure Element attestation** για camera buffers;
- **execution-integrity** signals όπως **Play Integrity** ή **App Attest**;
- **motion correlation** μεταξύ video και accelerometer ή gyroscope telemetry.

Τα desktop web flows συνήθως δεν διαθέτουν ισοδύναμο camera chain of trust, επομένως αποτελούν γενικά το path of least resistance.

## Defensive Review Notes

Κατά την αξιολόγηση ενός KYC ή liveness integration, επαληθεύστε αν:

- επιτρέπει **desktop-browser fallback** για ένα workflow που είχε threat-modeled μόνο για mobile capture;
- βασίζεται κυρίως σε **algorithmic liveness** χωρίς ισχυρό human escalation για ύποπτα sessions;
- χρησιμοποιεί **stable ή predictable challenges** που μπορούν να προεγγραφούν και να τροφοδοτηθούν σε generation pipeline;
- εντοπίζει **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry ή missing device attestation.

## References

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
