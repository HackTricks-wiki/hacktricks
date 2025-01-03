# macOS Υπηρεσίες Δικτύου & Πρωτόκολλα

{{#include ../../banners/hacktricks-training.md}}

## Υπηρεσίες Απομακρυσμένης Πρόσβασης

Αυτές είναι οι κοινές υπηρεσίες macOS για απομακρυσμένη πρόσβαση.\
Μπορείτε να ενεργοποιήσετε/απενεργοποιήσετε αυτές τις υπηρεσίες στις `Ρυθμίσεις Συστήματος` --> `Κοινή Χρήση`

- **VNC**, γνωστό ως “Κοινή Χρήση Οθόνης” (tcp:5900)
- **SSH**, που ονομάζεται “Απομακρυσμένη Σύνδεση” (tcp:22)
- **Apple Remote Desktop** (ARD), ή “Απομακρυσμένη Διαχείριση” (tcp:3283, tcp:5900)
- **AppleEvent**, γνωστό ως “Απομακρυσμένο Apple Event” (tcp:3031)

Ελέγξτε αν κάποια είναι ενεργοποιημένη εκτελώντας:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) είναι μια ενισχυμένη έκδοση του [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) προσαρμοσμένη για macOS, προσφέροντας επιπλέον δυνατότητες. Μια αξιοσημείωτη ευπάθεια στο ARD είναι η μέθοδος αυθεντικοποίησης για τον κωδικό πρόσβασης της οθόνης ελέγχου, η οποία χρησιμοποιεί μόνο τους πρώτους 8 χαρακτήρες του κωδικού πρόσβασης, καθιστώντας την επιρρεπή σε [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) με εργαλεία όπως το Hydra ή το [GoRedShell](https://github.com/ahhh/GoRedShell/), καθώς δεν υπάρχουν προεπιλεγμένα όρια ρυθμού.

Οι ευάλωτες περιπτώσεις μπορούν να εντοπιστούν χρησιμοποιώντας το σενάριο `vnc-info` του **nmap**. Υπηρεσίες που υποστηρίζουν `VNC Authentication (2)` είναι ιδιαίτερα ευάλωτες σε επιθέσεις brute force λόγω της περικοπής του κωδικού πρόσβασης σε 8 χαρακτήρες.

Για να ενεργοποιήσετε το ARD για διάφορες διοικητικές εργασίες όπως η κλιμάκωση προνομίων, η πρόσβαση GUI ή η παρακολούθηση χρηστών, χρησιμοποιήστε την παρακάτω εντολή:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD παρέχει ευέλικτα επίπεδα ελέγχου, συμπεριλαμβανομένης της παρακολούθησης, του κοινόχρηστου ελέγχου και του πλήρους ελέγχου, με τις συνεδρίες να παραμένουν ενεργές ακόμη και μετά από αλλαγές κωδικών πρόσβασης χρηστών. Επιτρέπει την αποστολή εντολών Unix απευθείας, εκτελώντας τις ως root για διαχειριστικούς χρήστες. Ο προγραμματισμός εργασιών και η απομακρυσμένη αναζήτηση Spotlight είναι αξιοσημείωτα χαρακτηριστικά, διευκολύνοντας απομακρυσμένες, χαμηλής επίπτωσης αναζητήσεις για ευαίσθητα αρχεία σε πολλές μηχανές.

## Πρωτόκολλο Bonjour

Το Bonjour, μια τεχνολογία σχεδιασμένη από την Apple, επιτρέπει **στις συσκευές στο ίδιο δίκτυο να ανιχνεύουν τις προσφερόμενες υπηρεσίες η μία της άλλης**. Γνωστό επίσης ως Rendezvous, **Zero Configuration**, ή Zeroconf, επιτρέπει σε μια συσκευή να ενταχθεί σε ένα δίκτυο TCP/IP, **να επιλέξει αυτόματα μια διεύθυνση IP**, και να εκπέμπει τις υπηρεσίες της σε άλλες συσκευές του δικτύου.

Το Zero Configuration Networking, που παρέχεται από το Bonjour, διασφαλίζει ότι οι συσκευές μπορούν να:

- **Αποκτούν αυτόματα μια διεύθυνση IP** ακόμη και στην απουσία διακομιστή DHCP.
- Εκτελούν **μετάφραση ονόματος σε διεύθυνση** χωρίς να απαιτείται διακομιστής DNS.
- **Ανακαλύπτουν υπηρεσίες** διαθέσιμες στο δίκτυο.

Οι συσκευές που χρησιμοποιούν το Bonjour θα αναθέσουν μόνες τους μια **διεύθυνση IP από το εύρος 169.254/16** και θα επαληθεύσουν την μοναδικότητά της στο δίκτυο. Οι Macs διατηρούν μια καταχώρηση πίνακα δρομολόγησης για αυτό το υποδίκτυο, που μπορεί να επαληθευτεί μέσω `netstat -rn | grep 169`.

Για το DNS, το Bonjour χρησιμοποιεί το **πρωτόκολλο Multicast DNS (mDNS)**. Το mDNS λειτουργεί μέσω **θύρας 5353/UDP**, χρησιμοποιώντας **τυπικά ερωτήματα DNS** αλλά στοχεύοντας τη **διεύθυνση multicast 224.0.0.251**. Αυτή η προσέγγιση διασφαλίζει ότι όλες οι συσκευές που ακούν στο δίκτυο μπορούν να λάβουν και να απαντήσουν στα ερωτήματα, διευκολύνοντας την ενημέρωση των καταχωρήσεών τους.

Κατά την ένταξή τους στο δίκτυο, κάθε συσκευή επιλέγει αυτόματα ένα όνομα, που συνήθως τελειώνει σε **.local**, το οποίο μπορεί να προέρχεται από το όνομα υπολογιστή ή να είναι τυχαία παραγόμενο.

Η ανακάλυψη υπηρεσιών εντός του δικτύου διευκολύνεται από το **DNS Service Discovery (DNS-SD)**. Εκμεταλλευόμενο τη μορφή των καταχωρήσεων DNS SRV, το DNS-SD χρησιμοποιεί **καταχωρήσεις DNS PTR** για να επιτρέψει την καταχώρηση πολλαπλών υπηρεσιών. Ένας πελάτης που αναζητά μια συγκεκριμένη υπηρεσία θα ζητήσει μια καταχώρηση PTR για `<Service>.<Domain>`, λαμβάνοντας ως απάντηση μια λίστα καταχωρήσεων PTR μορφοποιημένων ως `<Instance>.<Service>.<Domain>` αν η υπηρεσία είναι διαθέσιμη από πολλούς διακομιστές.

Το εργαλείο `dns-sd` μπορεί να χρησιμοποιηθεί για **την ανακάλυψη και διαφήμιση δικτυακών υπηρεσιών**. Ακολουθούν μερικά παραδείγματα χρήσης του:

### Αναζητώντας Υπηρεσίες SSH

Για να αναζητήσετε υπηρεσίες SSH στο δίκτυο, χρησιμοποιείται η εξής εντολή:
```bash
dns-sd -B _ssh._tcp
```
Αυτή η εντολή ξεκινά την αναζήτηση για υπηρεσίες \_ssh.\_tcp και εξάγει λεπτομέρειες όπως χρονική σήμανση, σημαίες, διεπαφή, τομέα, τύπο υπηρεσίας και όνομα παρουσίας.

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
Όταν μια υπηρεσία ξεκινά, ανακοινώνει τη διαθεσιμότητά της σε όλες τις συσκευές στο υποδίκτυο μέσω multicast της παρουσίας της. Οι συσκευές που ενδιαφέρονται για αυτές τις υπηρεσίες δεν χρειάζεται να στείλουν αιτήματα, αλλά απλώς να ακούσουν αυτές τις ανακοινώσεις.

Για μια πιο φιλική προς τον χρήστη διεπαφή, η εφαρμογή **Discovery - DNS-SD Browser** που είναι διαθέσιμη στο Apple App Store μπορεί να οπτικοποιήσει τις υπηρεσίες που προσφέρονται στο τοπικό σας δίκτυο.

Εναλλακτικά, μπορούν να γραφούν προσαρμοσμένα σενάρια για να περιηγηθούν και να ανακαλύψουν υπηρεσίες χρησιμοποιώντας τη βιβλιοθήκη `python-zeroconf`. Το [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) σενάριο δείχνει πώς να δημιουργήσετε έναν περιηγητή υπηρεσιών για τις υπηρεσίες `_http._tcp.local.`, εκτυπώνοντας τις προστιθέμενες ή αφαιρεθείσες υπηρεσίες:
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
### Απενεργοποίηση Bonjour

Εάν υπάρχουν ανησυχίες σχετικά με την ασφάλεια ή άλλοι λόγοι για να απενεργοποιηθεί το Bonjour, μπορεί να απενεργοποιηθεί χρησιμοποιώντας την παρακάτω εντολή:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Αναφορές

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}
