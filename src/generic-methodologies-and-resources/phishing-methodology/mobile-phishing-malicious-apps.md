# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Αυτή η σελίδα καλύπτει τεχνικές που χρησιμοποιούν οι απειλητικοί παράγοντες για να διανείμουν **κακόβουλα Android APKs** και **προφίλ κινητής διαμόρφωσης iOS** μέσω phishing (SEO, κοινωνική μηχανική, ψεύτικα καταστήματα, εφαρμογές γνωριμιών, κ.λπ.).
> Το υλικό έχει προσαρμοστεί από την καμπάνια SarangTrap που αποκαλύφθηκε από την Zimperium zLabs (2025) και άλλες δημόσιες έρευνες.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Καταχωρήστε δεκάδες τομείς που μοιάζουν (γνωριμίες, κοινή χρήση cloud, υπηρεσία αυτοκινήτων…).
– Χρησιμοποιήστε λέξεις-κλειδιά και emoji στη το `<title>` για να καταταγείτε στο Google.
– Φιλοξενήστε *και τις δύο* οδηγίες εγκατάστασης Android (`.apk`) και iOS στην ίδια σελίδα προορισμού.
2. **First Stage Download**
* Android: άμεσος σύνδεσμος σε ένα *unsigned* ή “κατάστημα τρίτου μέρους” APK.
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
* Η εφαρμογή εμφανίζει αβλαβείς προβολές (θεατής SMS, επιλογέας γκαλερί) που υλοποιούνται τοπικά.
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
3. Εμπιστευτείτε το unsigned προφίλ ➜ ο επιτιθέμενος αποκτά *Επαφές* & *Δικαιώματα Φωτογραφιών* χωρίς έλεγχο από το App Store.
7. **Network Layer**
* Απλό HTTP, συχνά στη θύρα 80 με HOST header όπως `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (χωρίς TLS → εύκολο να εντοπιστεί).

## Defensive Testing / Red-Team Tips

* **Dynamic Analysis Bypass** – Κατά την αξιολόγηση κακόβουλου λογισμικού, αυτοματοποιήστε τη φάση κωδικού πρόσκλησης με Frida/Objection για να φτάσετε στον κακόβουλο κλάδο.
* **Manifest vs. Runtime Diff** – Συγκρίνετε `aapt dump permissions` με runtime `PackageManager#getRequestedPermissions()`; η απουσία επικίνδυνων αδειών είναι κόκκινη σημαία.
* **Network Canary** – Ρυθμίστε `iptables -p tcp --dport 80 -j NFQUEUE` για να ανιχνεύσετε μη σταθερές εκρήξεις POST μετά την είσοδο κωδικού.
* **mobileconfig Inspection** – Χρησιμοποιήστε `security cms -D -i profile.mobileconfig` σε macOS για να καταγράψετε το `PayloadContent` και να εντοπίσετε υπερβολικά δικαιώματα.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** για να πιάσετε ξαφνικές εκρήξεις τομέων πλούσιων σε λέξεις-κλειδιά.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` από πελάτες Dalvik εκτός Google Play.
* **Invite-code Telemetry** – POST 6–8 ψηφίων αριθμητικών κωδικών λίγο μετά την εγκατάσταση APK μπορεί να υποδηλώνει προετοιμασία.
* **MobileConfig Signing** – Εμποδίστε τα unsigned προφίλ διαμόρφωσης μέσω πολιτικής MDM.

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
## Αναφορές

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}
