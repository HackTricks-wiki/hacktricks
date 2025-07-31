# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Αυτές είναι οι κοινές υπηρεσίες macOS για απομακρυσμένη πρόσβαση.\
Μπορείτε να ενεργοποιήσετε/απενεργοποιήσετε αυτές τις υπηρεσίες στις `System Settings` --> `Sharing`

- **VNC**, γνωστό ως “Screen Sharing” (tcp:5900)
- **SSH**, ονομάζεται “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), ή “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, γνωστό ως “Remote Apple Event” (tcp:3031)

Ελέγξτε αν κάποια είναι ενεργοποιημένη εκτελώντας:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\\*.88|\\*.445|\\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) είναι μια ενισχυμένη έκδοση του [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) προσαρμοσμένη για macOS, προσφέροντας επιπλέον δυνατότητες. Μια αξιοσημείωτη ευπάθεια στο ARD είναι η μέθοδος αυθεντικοποίησης για τον κωδικό πρόσβασης της οθόνης ελέγχου, η οποία χρησιμοποιεί μόνο τους πρώτους 8 χαρακτήρες του κωδικού πρόσβασης, καθιστώντας την επιρρεπή σε [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) με εργαλεία όπως το Hydra ή το [GoRedShell](https://github.com/ahhh/GoRedShell/), καθώς δεν υπάρχουν προεπιλεγμένα όρια ρυθμού.

Οι ευάλωτες περιπτώσεις μπορούν να εντοπιστούν χρησιμοποιώντας το σενάριο `vnc-info` του **nmap**. Υπηρεσίες που υποστηρίζουν `VNC Authentication (2)` είναι ιδιαίτερα ευάλωτες σε επιθέσεις brute force λόγω της περικοπής του κωδικού πρόσβασης σε 8 χαρακτήρες.

Για να ενεργοποιήσετε το ARD για διάφορες διοικητικές εργασίες όπως η κλιμάκωση προνομίων, η πρόσβαση μέσω GUI ή η παρακολούθηση χρηστών, χρησιμοποιήστε την παρακάτω εντολή:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD παρέχει ευέλικτα επίπεδα ελέγχου, συμπεριλαμβανομένης της παρακολούθησης, του κοινόχρηστου ελέγχου και του πλήρους ελέγχου, με τις συνεδρίες να παραμένουν ενεργές ακόμη και μετά από αλλαγές κωδικού πρόσβασης χρήστη. Επιτρέπει την αποστολή εντολών Unix απευθείας, εκτελώντας τις ως root για διαχειριστικούς χρήστες. Ο προγραμματισμός εργασιών και η απομακρυσμένη αναζήτηση Spotlight είναι αξιοσημείωτα χαρακτηριστικά, διευκολύνοντας απομακρυσμένες, χαμηλής επιρροής αναζητήσεις ευαίσθητων αρχείων σε πολλές μηχανές.

#### Πρόσφατες ευπάθειες Screen-Sharing / ARD (2023-2025)

| Έτος | CVE | Συστατικό | Επιπτώσεις | Διορθώθηκε σε |
|------|-----|-----------|------------|----------------|
|2023|CVE-2023-42940|Screen Sharing|Η λανθασμένη απόδοση συνεδρίας θα μπορούσε να προκαλέσει τη μετάδοση του *λανθασμένου* επιφάνειας εργασίας ή παραθύρου, με αποτέλεσμα τη διαρροή ευαίσθητων πληροφοριών|macOS Sonoma 14.2.1 (Δεκ 2023) |
|2024|CVE-2024-23296|launchservicesd / login|Παράκαμψη προστασίας μνήμης πυρήνα που μπορεί να αλυσοδεθεί μετά από επιτυχημένη απομακρυσμένη σύνδεση (εκμεταλλεύεται ενεργά στην άγρια φύση)|macOS Ventura 13.6.4 / Sonoma 14.4 (Μάρ 2024) |

**Συμβουλές σκληροποίησης**

* Απενεργοποιήστε το *Screen Sharing*/*Remote Management* όταν δεν απαιτείται αυστηρά.
* Διατηρήστε το macOS πλήρως ενημερωμένο (η Apple γενικά αποστέλλει διορθώσεις ασφαλείας για τις τελευταίες τρεις κύριες εκδόσεις).
* Χρησιμοποιήστε έναν **ισχυρό κωδικό πρόσβασης** *και* επιβάλετε την επιλογή *“VNC viewers may control screen with password”* **απενεργοποιημένη** όταν είναι δυνατόν.
* Τοποθετήστε την υπηρεσία πίσω από ένα VPN αντί να εκθέτετε το TCP 5900/3283 στο Διαδίκτυο.
* Προσθέστε έναν κανόνα Firewall εφαρμογής για να περιορίσετε το `ARDAgent` στο τοπικό υποδίκτυο:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Πρωτόκολλο Bonjour

Το Bonjour, μια τεχνολογία σχεδιασμένη από την Apple, επιτρέπει **στις συσκευές στο ίδιο δίκτυο να ανιχνεύουν τις προσφερόμενες υπηρεσίες η μία της άλλης**. Γνωστό επίσης ως Rendezvous, **Zero Configuration**, ή Zeroconf, επιτρέπει σε μια συσκευή να ενταχθεί σε ένα δίκτυο TCP/IP, **να επιλέξει αυτόματα μια διεύθυνση IP** και να διαφημίσει τις υπηρεσίες της σε άλλες συσκευές δικτύου.

Η Δικτύωση Χωρίς Ρυθμίσεις, που παρέχεται από το Bonjour, διασφαλίζει ότι οι συσκευές μπορούν να:

- **Αποκτούν αυτόματα μια διεύθυνση IP** ακόμη και στην απουσία διακομιστή DHCP.
- Εκτελούν **μετάφραση ονόματος σε διεύθυνση** χωρίς να απαιτείται διακομιστής DNS.
- **Ανακαλύπτουν υπηρεσίες** διαθέσιμες στο δίκτυο.

Οι συσκευές που χρησιμοποιούν το Bonjour θα αναθέσουν μόνες τους μια **διεύθυνση IP από το εύρος 169.254/16** και θα επαληθεύσουν την μοναδικότητά της στο δίκτυο. Οι Macs διατηρούν μια καταχώρηση πίνακα δρομολόγησης για αυτό το υποδίκτυο, επαληθεύσιμη μέσω του `netstat -rn | grep 169`.

Για το DNS, το Bonjour χρησιμοποιεί το **πρωτόκολλο Multicast DNS (mDNS)**. Το mDNS λειτουργεί μέσω **θύρας 5353/UDP**, χρησιμοποιώντας **τυπικά ερωτήματα DNS** αλλά στοχεύοντας τη **διεύθυνση multicast 224.0.0.251**. Αυτή η προσέγγιση διασφαλίζει ότι όλες οι συσκευές που ακούν στο δίκτυο μπορούν να λάβουν και να απαντήσουν στα ερωτήματα, διευκολύνοντας την ενημέρωση των καταχωρήσεών τους.

Κατά την ένταξή τους στο δίκτυο, κάθε συσκευή επιλέγει αυτόματα ένα όνομα, που συνήθως τελειώνει σε **.local**, το οποίο μπορεί να προέρχεται από το όνομα υπολογιστή ή να είναι τυχαία παραγόμενο.

Η ανακάλυψη υπηρεσιών εντός του δικτύου διευκολύνεται από το **DNS Service Discovery (DNS-SD)**. Εκμεταλλευόμενο τη μορφή των καταχωρήσεων DNS SRV, το DNS-SD χρησιμοποιεί **καταχωρήσεις DNS PTR** για να επιτρέψει την καταχώρηση πολλαπλών υπηρεσιών. Ένας πελάτης που αναζητά μια συγκεκριμένη υπηρεσία θα ζητήσει μια καταχώρηση PTR για `<Service>.<Domain>`, λαμβάνοντας σε αντάλλαγμα μια λίστα καταχωρήσεων PTR μορφοποιημένων ως `<Instance>.<Service>.<Domain>` αν η υπηρεσία είναι διαθέσιμη από πολλούς διακομιστές.

Το εργαλείο `dns-sd` μπορεί να χρησιμοποιηθεί για **ανακάλυψη και διαφήμιση δικτυακών υπηρεσιών**. Ακολουθούν μερικά παραδείγματα χρήσης του:

### Αναζητώντας Υπηρεσίες SSH

Για να αναζητήσετε υπηρεσίες SSH στο δίκτυο, χρησιμοποιείται η εξής εντολή:
```bash
dns-sd -B _ssh._tcp
```
Αυτή η εντολή ξεκινά την αναζήτηση για υπηρεσίες \_ssh.\_tcp και εξάγει λεπτομέρειες όπως χρονοσφραγίδα, σημαίες, διεπαφή, τομέα, τύπο υπηρεσίας και όνομα στιγμής.

### Διαφήμιση μιας Υπηρεσίας HTTP

Για να διαφημίσετε μια υπηρεσία HTTP, μπορείτε να χρησιμοποιήσετε:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Αυτή η εντολή καταχωρεί μια υπηρεσία HTTP με το όνομα "Index" στη θύρα 80 με διαδρομή `/index.html`.

Για να αναζητήσετε υπηρεσίες HTTP στο δίκτυο:
```bash
dns-sd -B _http._tcp
```
Όταν μια υπηρεσία ξεκινά, ανακοινώνει τη διαθεσιμότητά της σε όλες τις συσκευές στο υποδίκτυο μέσω multicast της παρουσίας της. Οι συσκευές που ενδιαφέρονται για αυτές τις υπηρεσίες δεν χρειάζεται να στείλουν αιτήματα, αλλά απλώς να ακούν αυτές τις ανακοινώσεις.

Για μια πιο φιλική προς τον χρήστη διεπαφή, η εφαρμογή **Discovery - DNS-SD Browser** που είναι διαθέσιμη στο Apple App Store μπορεί να οπτικοποιήσει τις υπηρεσίες που προσφέρονται στο τοπικό σας δίκτυο.

Εναλλακτικά, μπορούν να γραφούν προσαρμοσμένα σενάρια για να περιηγηθούν και να ανακαλύψουν υπηρεσίες χρησιμοποιώντας τη βιβλιοθήκη `python-zeroconf`. Το [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) σενάριο δείχνει τη δημιουργία ενός περιηγητή υπηρεσιών για τις υπηρεσίες `_http._tcp.local.`, εκτυπώνοντας τις προστιθέμενες ή αφαιρεθείσες υπηρεσίες:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Enumerating Bonjour over the network

* **Nmap NSE** – ανακάλυψη υπηρεσιών που διαφημίζονται από έναν μόνο υπολογιστή:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Το σενάριο `dns-service-discovery` στέλνει ένα ερώτημα `_services._dns-sd._udp.local` και στη συνέχεια απαριθμεί κάθε διαφημισμένο τύπο υπηρεσίας.

* **mdns_recon** – εργαλείο Python που σαρώνει ολόκληρες περιοχές αναζητώντας *κακώς ρυθμισμένους* mDNS responders που απαντούν σε unicast ερωτήματα (χρήσιμο για να βρείτε συσκευές που είναι προσβάσιμες μέσω υποδικτύων/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Αυτό θα επιστρέψει υπολογιστές που εκθέτουν SSH μέσω Bonjour εκτός του τοπικού συνδέσμου.

### Security considerations & recent vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Ένα λογικό σφάλμα στο *mDNSResponder* επέτρεψε σε ένα κακόβουλο πακέτο να προκαλέσει **άρνηση υπηρεσίας**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Σεπ 2024) |
|2025|CVE-2025-31222|High|Ένα ζήτημα ορθότητας στο *mDNSResponder* θα μπορούσε να εκμεταλλευτεί για **τοπική κλιμάκωση προνομίων**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (Μάιος 2025) |

**Mitigation guidance**

1. Περιορίστε το UDP 5353 σε *link-local* πεδίο – αποκλείστε ή περιορίστε την ταχύτητα του σε ασύρματους ελεγκτές, δρομολογητές και τείχη προστασίας βασισμένα σε υπολογιστές.
2. Απενεργοποιήστε εντελώς το Bonjour σε συστήματα που δεν απαιτούν ανακάλυψη υπηρεσιών:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Για περιβάλλοντα όπου το Bonjour απαιτείται εσωτερικά αλλά δεν πρέπει ποτέ να διασχίζει τα δίκτυα, χρησιμοποιήστε περιορισμούς προφίλ *AirPlay Receiver* (MDM) ή έναν mDNS proxy.
4. Ενεργοποιήστε την **Προστασία Ακεραιότητας Συστήματος (SIP)** και κρατήστε το macOS ενημερωμένο – και οι δύο ευπάθειες παραπάνω διορθώθηκαν γρήγορα αλλά εξαρτήθηκαν από την ενεργοποίηση του SIP για πλήρη προστασία.

### Disabling Bonjour

Εάν υπάρχουν ανησυχίες σχετικά με την ασφάλεια ή άλλοι λόγοι για να απενεργοποιήσετε το Bonjour, μπορεί να απενεργοποιηθεί χρησιμοποιώντας την παρακάτω εντολή:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Αναφορές

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)

{{#include ../../banners/hacktricks-training.md}}
