# Υπηρεσίες & Πρωτόκολλα Δικτύου macOS

{{#include ../../banners/hacktricks-training.md}}

## Υπηρεσίες Απομακρυσμένης Πρόσβασης

Αυτές είναι οι συνήθεις υπηρεσίες macOS για απομακρυσμένη πρόσβαση.\
Μπορείτε να ενεργοποιήσετε/απενεργοποιήσετε αυτές τις υπηρεσίες στο `System Settings` --> `Sharing`

- **VNC**, γνωστό ως “Screen Sharing” (tcp:5900)
- **SSH**, που ονομάζεται “Remote Login” (tcp:22)
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
### Απαρίθμηση της ρύθμισης κοινής χρήσης τοπικά

Όταν έχεις ήδη τοπική εκτέλεση κώδικα σε Mac, **έλεγξε την διαμορφωμένη κατάσταση**, όχι μόνο τα listening sockets. Τα `systemsetup` και `launchctl` συνήθως δείχνουν αν η υπηρεσία είναι administratively enabled, ενώ τα `kickstart` και `system_profiler` βοηθούν να επιβεβαιώσεις την effective ARD/Sharing configuration:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Το Apple Remote Desktop (ARD) είναι μια βελτιωμένη έκδοση του [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) προσαρμοσμένη για macOS, που προσφέρει επιπλέον λειτουργίες. Μια αξιοσημείωτη ευπάθεια στο ARD είναι η μέθοδος authentication του για το control screen password, η οποία χρησιμοποιεί μόνο τα πρώτα 8 characters του password, καθιστώντας το επιρρεπές σε [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) με εργαλεία όπως το Hydra ή το [GoRedShell](https://github.com/ahhh/GoRedShell/), καθώς δεν υπάρχουν default rate limits.

Τα vulnerable instances μπορούν να εντοπιστούν χρησιμοποιώντας το script `vnc-info` του **nmap**. Τα services που υποστηρίζουν `VNC Authentication (2)` είναι ιδιαίτερα susceptible σε brute force attacks λόγω της αποκοπής του password στα 8 characters.

Για να ενεργοποιήσετε το ARD για διάφορες administrative tasks όπως privilege escalation, GUI access ή user monitoring, χρησιμοποιήστε την ακόλουθη εντολή:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD παρέχει ευέλικτα επίπεδα ελέγχου, όπως observation, shared control και full control, με sessions που παραμένουν ενεργές ακόμη και μετά από αλλαγές στον κωδικό πρόσβασης του user. Επιτρέπει την αποστολή Unix commands απευθείας, εκτελώντας τες ως root για administrative users. Το task scheduling και το Remote Spotlight search είναι αξιοσημείωτα features, διευκολύνοντας απομακρυσμένες, χαμηλού αντίκτυπου αναζητήσεις για sensitive files σε πολλαπλά machines.

Από τη σκοπιά του operator, το **Monterey 12.1+ changed remote-enablement workflows** σε managed fleets. Αν ήδη ελέγχεις το MDM του victim, το `EnableRemoteDesktop` command της Apple είναι συχνά ο πιο καθαρός τρόπος για να ενεργοποιήσεις τη remote desktop functionality σε νεότερα systems. Αν έχεις ήδη foothold στον host, το `kickstart` εξακολουθεί να είναι χρήσιμο για να inspect ή reconfigure τα ARD privileges από το command line.

### Pentesting Remote Apple Events (RAE / EPPC)

Η Apple ονομάζει αυτό το feature **Remote Application Scripting** στα σύγχρονα System Settings. Στο εσωτερικό του, εκθέτει τον **Apple Event Manager** απομακρυσμένα μέσω **EPPC** στο **TCP/3031** μέσω της υπηρεσίας `com.apple.AEServer`. Η Palo Alto Unit 42 το ανέδειξε ξανά ως πρακτικό **macOS lateral movement** primitive, επειδή valid credentials μαζί με ένα ενεργοποιημένο RAE service επιτρέπουν σε έναν operator να ελέγχει scriptable applications σε ένα remote Mac.

Χρήσιμοι έλεγχοι:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Αν ήδη έχεις admin/root στον στόχο και θέλεις να το ενεργοποιήσεις:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Βασικός έλεγχος συνδεσιμότητας από άλλο Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Στην πράξη, η κατάχρηση δεν περιορίζεται στο Finder. Οποιαδήποτε **scriptable application** που δέχεται τα απαιτούμενα Apple events γίνεται απομακρυσμένη attack surface, κάτι που κάνει το RAE ιδιαίτερα ενδιαφέρον μετά από credential theft σε εσωτερικά macOS networks.

#### Recent Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Η λανθασμένη απόδοση session θα μπορούσε να προκαλέσει τη μετάδοση της *λάθος* desktop ή window, με αποτέλεσμα leak ευαίσθητων πληροφοριών|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Ένας user με screen sharing access ενδέχεται να μπορεί να δει την **οθόνη άλλου user** λόγω ενός state-management issue|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Disable *Screen Sharing*/*Remote Management* when not strictly required.
* Keep macOS fully patched (Apple generally ships security fixes for the last three major releases).
* Use a **Strong Password** *and* enforce the *“VNC viewers may control screen with password”* option **disabled** when possible.
* Put the service behind a VPN instead of exposing TCP 5900/3283 to the Internet.
* Add an Application Firewall rule to limit `ARDAgent` to the local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Το Bonjour, μια τεχνολογία σχεδιασμένη από την Apple, επιτρέπει σε **devices στο ίδιο network να ανιχνεύουν τις services που προσφέρουν μεταξύ τους**. Γνωστό επίσης ως Rendezvous, **Zero Configuration**, ή Zeroconf, επιτρέπει σε ένα device να ενταχθεί σε ένα TCP/IP network, **να επιλέξει αυτόματα μια IP address**, και να broadcastάρει τις services του σε άλλα network devices.

Το Zero Configuration Networking, που παρέχεται από το Bonjour, διασφαλίζει ότι τα devices μπορούν να:

- **Αποκτούν αυτόματα ένα IP Address** ακόμη και χωρίς DHCP server.
- Κάνουν **name-to-address translation** χωρίς να απαιτείται DNS server.
- **Ανακαλύπτουν services** διαθέσιμες στο network.

Τα devices που χρησιμοποιούν Bonjour θα αντιστοιχίσουν στον εαυτό τους μια **IP address από το 169.254/16 range** και θα επαληθεύσουν τη μοναδικότητά της στο network. Τα Macs διατηρούν μια routing table entry για αυτό το subnet, κάτι που μπορεί να επαληθευτεί μέσω `netstat -rn | grep 169`.

Για DNS, το Bonjour χρησιμοποιεί το **Multicast DNS (mDNS) protocol**. Το mDNS λειτουργεί μέσω **port 5353/UDP**, χρησιμοποιώντας **standard DNS queries** αλλά στοχεύοντας στη **multicast address 224.0.0.251**. Αυτή η προσέγγιση διασφαλίζει ότι όλα τα listening devices στο network μπορούν να λαμβάνουν και να απαντούν στα queries, διευκολύνοντας την ενημέρωση των records τους.

Με την ένταξη στο network, κάθε device επιλέγει μόνο του ένα name, συνήθως που τελειώνει σε **.local**, το οποίο μπορεί να προέρχεται από το hostname ή να έχει παραχθεί τυχαία.

Η service discovery μέσα στο network διευκολύνεται από το **DNS Service Discovery (DNS-SD)**. Αξιοποιώντας τη μορφή των DNS SRV records, το DNS-SD χρησιμοποιεί **DNS PTR records** για να επιτρέπει την καταγραφή πολλαπλών services. Ένας client που αναζητά μια συγκεκριμένη service θα ζητήσει ένα PTR record για `<Service>.<Domain>`, λαμβάνοντας ως απάντηση μια λίστα από PTR records σε μορφή `<Instance>.<Service>.<Domain>` αν η service είναι διαθέσιμη από πολλαπλά hosts.

Το `dns-sd` utility μπορεί να χρησιμοποιηθεί για **ανακάλυψη και advertising network services**. Ακολουθούν μερικά παραδείγματα χρήσης:

### Searching for SSH Services

Για να αναζητήσετε SSH services στο network, χρησιμοποιείται η ακόλουθη εντολή:
```bash
dns-sd -B _ssh._tcp
```
Αυτή η εντολή ξεκινά την αναζήτηση για υπηρεσίες \_ssh.\_tcp και εμφανίζει λεπτομέρειες όπως timestamp, flags, interface, domain, service type και instance name.

### Advertising an HTTP Service

Για να advertise ένα HTTP Service, μπορείτε να χρησιμοποιήσετε:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Αυτή η εντολή καταχωρεί μια HTTP υπηρεσία με όνομα "Index" στη θύρα 80 με διαδρομή `/index.html`.

Στη συνέχεια, για να αναζητήσετε HTTP υπηρεσίες στο δίκτυο:
```bash
dns-sd -B _http._tcp
```
Όταν μια υπηρεσία ξεκινά, ανακοινώνει τη διαθεσιμότητά της σε όλες τις συσκευές στο subnet κάνοντας multicast την παρουσία της. Οι συσκευές που ενδιαφέρονται για αυτές τις υπηρεσίες δεν χρειάζεται να στέλνουν αιτήματα, αλλά απλώς να ακούν αυτές τις ανακοινώσεις.

Για ένα πιο φιλικό προς τον χρήστη interface, η εφαρμογή **Discovery - DNS-SD Browser** που είναι διαθέσιμη στο Apple App Store μπορεί να οπτικοποιήσει τις υπηρεσίες που προσφέρονται στο τοπικό σου δίκτυο.

Εναλλακτικά, μπορούν να γραφτούν custom scripts για browsing και discovery υπηρεσιών χρησιμοποιώντας τη βιβλιοθήκη `python-zeroconf`. Το [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) script δείχνει τη δημιουργία ενός service browser για υπηρεσίες `_http._tcp.local.`, εκτυπώνοντας services που προστέθηκαν ή αφαιρέθηκαν:
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
### macOS-specific Bonjour hunting

Σε δίκτυα macOS, το Bonjour είναι συχνά ο ευκολότερος τρόπος για να βρεις **remote administration surfaces** χωρίς να αγγίξεις απευθείας τον στόχο. Το Apple Remote Desktop το ίδιο μπορεί να εντοπίσει clients μέσω Bonjour, άρα τα ίδια δεδομένα discovery είναι χρήσιμα και σε έναν attacker.
```bash
# Enumerate every advertised service type first
dns-sd -B _services._dns-sd._udp local

# Then look for common macOS admin surfaces
dns-sd -B _rfb._tcp local      # Screen Sharing / VNC
dns-sd -B _ssh._tcp local      # Remote Login
dns-sd -B _eppc._tcp local     # Remote Apple Events / EPPC

# Resolve a specific instance to hostname, port and TXT data
dns-sd -L "<Instance>" _rfb._tcp local
dns-sd -L "<Instance>" _eppc._tcp local
```
Για ευρύτερες τεχνικές **mDNS spoofing, impersonation, and cross-subnet discovery**, δείτε την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Καταγραφή Bonjour στο δίκτυο

* **Nmap NSE** – ανακαλύπτει services που διαφημίζονται από έναν μεμονωμένο host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Το script `dns-service-discovery` στέλνει ένα `_services._dns-sd._udp.local` query και στη συνέχεια καταγράφει κάθε advertised service type.

* **mdns_recon** – εργαλείο Python που σαρώνει ολόκληρα ranges αναζητώντας *misconfigured* mDNS responders που απαντούν σε unicast queries (χρήσιμο για εύρεση devices προσβάσιμων across subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Αυτό θα επιστρέψει hosts που εκθέτουν SSH μέσω Bonjour εκτός του τοπικού link.

### Ζητήματα ασφάλειας & πρόσφατα vulnerabilities (2024-2025)

| Year | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|A logic error in *mDNSResponder* allowed a crafted packet to trigger a **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|A correctness issue in *mDNSResponder* could be abused for **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Οδηγίες mitigation**

1. Περιορίστε το UDP 5353 σε *link-local* scope – μπλοκάρετέ το ή εφαρμόστε rate-limit σε wireless controllers, routers και host-based firewalls.
2. Απενεργοποιήστε πλήρως το Bonjour σε συστήματα που δεν χρειάζονται service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Για περιβάλλοντα όπου το Bonjour απαιτείται εσωτερικά αλλά δεν πρέπει ποτέ να διασχίζει network boundaries, χρησιμοποιήστε περιορισμούς του προφίλ *AirPlay Receiver* (MDM) ή ένα mDNS proxy.
4. Ενεργοποιήστε το **System Integrity Protection (SIP)** και κρατήστε το macOS ενημερωμένο – και τα δύο vulnerabilities παραπάνω διορθώθηκαν γρήγορα, αλλά βασίζονταν στο ότι το SIP ήταν ενεργοποιημένο για πλήρη προστασία.

### Απενεργοποίηση Bonjour

Αν υπάρχουν concerns για security ή άλλοι λόγοι για να απενεργοποιηθεί το Bonjour, μπορεί να απενεργοποιηθεί με την παρακάτω εντολή:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [**NVD – CVE-2023-42940**](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [**NVD – CVE-2024-44183**](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [**Palo Alto Unit 42 - Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples**](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [**Apple Support - About the security content of macOS Sonoma 14.7.2**](https://support.apple.com/en-us/121840)

{{#include ../../banners/hacktricks-training.md}}
