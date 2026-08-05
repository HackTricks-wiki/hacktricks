# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Υπηρεσίες Απομακρυσμένης Πρόσβασης

Αυτές είναι οι συνηθισμένες υπηρεσίες του macOS για απομακρυσμένη πρόσβαση.\
Μπορείτε να ενεργοποιήσετε/απενεργοποιήσετε αυτές τις υπηρεσίες από τις `System Settings` --> `Sharing`

- **VNC**, γνωστό ως “Screen Sharing” (tcp:5900)
- **SSH**, γνωστό ως “Remote Login” (tcp:22)
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
### Enumerating sharing configuration locally

Όταν έχετε ήδη local code execution σε ένα Mac, **ελέγξτε την configured state**, όχι μόνο τα listening sockets. Τα `systemsetup` και `launchctl` συνήθως δείχνουν αν η υπηρεσία είναι ενεργοποιημένη administratively, ενώ τα `kickstart` και `system_profiler` βοηθούν στην επιβεβαίωση της effective ARD/Sharing configuration:
```bash
system_profiler SPSharingDataType
sudo /usr/sbin/systemsetup -getremotelogin
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status
sudo launchctl print-disabled system | egrep 'com.apple.screensharing|com.apple.AEServer|ssh'
```
### Pentesting ARD

Το Apple Remote Desktop (ARD) είναι μια βελτιωμένη έκδοση του [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing), προσαρμοσμένη για macOS, που προσφέρει επιπλέον δυνατότητες. Μια αξιοσημείωτη ευπάθεια στο ARD αφορά τη μέθοδο authentication για το control screen password, η οποία χρησιμοποιεί μόνο τους πρώτους 8 χαρακτήρες του password, καθιστώντας το ευάλωτο σε [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) με εργαλεία όπως το Hydra ή το [GoRedShell](https://github.com/ahhh/GoRedShell/), καθώς δεν υπάρχουν προεπιλεγμένα rate limits.<sup>[3]</sup>

Τα ευάλωτα instances μπορούν να εντοπιστούν με χρήση του script `vnc-info` του **nmap**. Οι υπηρεσίες που υποστηρίζουν `VNC Authentication (2)` είναι ιδιαίτερα ευάλωτες σε brute force attacks λόγω της περικοπής του password στους 8 χαρακτήρες.

Για να ενεργοποιήσετε το ARD για διάφορες administrative εργασίες, όπως privilege escalation, GUI access ή user monitoring, χρησιμοποιήστε την ακόλουθη εντολή:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
Το ARD παρέχει ευέλικτα επίπεδα ελέγχου, όπως παρακολούθηση, κοινόχρηστο έλεγχο και πλήρη έλεγχο, ενώ οι sessions παραμένουν ενεργές ακόμη και μετά την αλλαγή των passwords των χρηστών. Επιτρέπει την απευθείας αποστολή Unix commands, την εκτέλεσή τους ως root για administrative users, καθώς και τον προγραμματισμό tasks. Η αναζήτηση Remote Spotlight είναι επίσης αξιοσημείωτη δυνατότητα, καθώς διευκολύνει απομακρυσμένες, χαμηλού αντίκτυπου αναζητήσεις για ευαίσθητα αρχεία σε πολλαπλά machines.

Από την οπτική γωνία ενός operator, το **Monterey 12.1+ άλλαξε τα workflows ενεργοποίησης της απομακρυσμένης πρόσβασης** σε managed fleets. Αν ελέγχετε ήδη το MDM του victim, η εντολή `EnableRemoteDesktop` της Apple είναι συχνά ο καθαρότερος τρόπος ενεργοποίησης της λειτουργικότητας remote desktop σε νεότερα systems. Αν έχετε ήδη foothold στο host, το `kickstart` παραμένει χρήσιμο για την επιθεώρηση ή την επαναρύθμιση των ARD privileges από τη command line.

#### Apple Screen Sharing (RFB 003.889 / security type 36) pre-auth file-copy abuse

Πρόσφατη έρευνα για το `screensharingd` έδειξε ότι το Apple Screen Sharing δεν χρησιμοποιεί πάντα μόνο το κλασικό VNC auth: νεότερα builds μιλούν **RFB `003.889`** και διαφημίζουν **security type `36`**, όπου το **SRP** πραγματοποιεί πρώτα το authentication και το **ChaCha20-Poly1305** εγκαθίσταται μόνο αφού επιτύχει το `ccsrp_server_verify_session`. Η δημόσια write-up αναφέρει ότι το bug διορθώθηκε στο **macOS Tahoe 26.6** (**27 Ιουλίου 2026**).<sup>[8][9]</sup>

Ένα χρήσιμο pattern που πρέπει να θυμάστε είναι το **stale-status parser bypass**: μετά από μια επιτυχημένη ανάγνωση length 4 bytes, κάθε branch για oversized/error πρέπει να επιστρέφει νέο error. Σε affected builds, ένα big-endian SRP frame length **`>= 32768`** κάνει το rejection path να επαναχρησιμοποιεί το προηγούμενο success του `NetBufferRead` (`0`), με αποτέλεσμα ο caller να ορίζει τη session ως authenticated, παρότι δεν εκτελέστηκε password proof και δεν εγκαταστάθηκε transport crypto. Επειδή τα bytes που δεν έχουν διαβαστεί παραμένουν στο shared socket buffer, ένας attacker μπορεί να κάνει **pipeline malformed SRP data και post-auth RFB messages στο ίδιο TCP burst** και να τα κάνει parse ως **cleartext authenticated traffic**.<sup>[8]</sup>

Μετά το bypass, το proprietary **file-copy** message της Apple **`0x22`** μετατρέπεται σε **root file read/write primitive**, επειδή το `screensharingd` εκτελείται ως root:<sup>[8]</sup>
```text
[u8 0x22][u8 sub][be32 L]
[be16 ver][be16 kind][be32 sid][be32 arg]
[L-12 bytes payload]
```
- `kind=1` / `StartFileSend`: αυθαίρετη ανάγνωση αρχείων
- `kind=2` / `StartFileReceive`: αυθαίρετη εγγραφή αρχείων
- Διαφορετικές τιμές `sid` επιτρέπουν το pipeline πολλών transactions σε μία σύνδεση
- Στο `kind=101` (`NewItem`), ορίστε το byte `14` / `arg[0]` σε `0x01` για ένα κανονικό αρχείο, το payload offset `+42` σε **μη μηδενικό** big-endian μέγεθος αρχείου και το payload offset `+0x5a` στο επιθυμητό Unix mode (`0600` αν στοχεύετε crontab)

Ενδιαφέροντα post-write pivots σε writable paths περιλαμβάνουν τα **`/etc/sudoers.d/`**, **`/etc/zshenv`**, **`/Library/LaunchDaemons/`** και **`/var/root/.ssh/authorized_keys`**. Το **SIP δεν σταματά το auth bypass ή την ανάγνωση αρχείων ως root**, αλλά αποκλείει ορισμένα write targets, όπως το **`/var/at`**, επομένως η εκτέλεση μέσω cron λειτουργεί μόνο με απενεργοποιημένο SIP. Σε hosts με ενεργοποιημένο το προεπιλεγμένο SIP, σκεφτείτε με όρους **«εγγραφή αρχείων ως root σε privileged auto-consumed files»** αντί για άμεση εκτέλεση κώδικα.<sup>[8]</sup>

Μια ακόμη παγίδα του SRP από την ίδια έρευνα: οι servers πρέπει να επικυρώνουν το **`A mod N != 0`** (σύμφωνα με το RFC 5054), όχι μόνο το `A > 0`. Η αποδοχή του **`A = N`** μπορεί να εξαναγκάσει το shared secret να γίνει μηδέν και να υπονομεύσει την επαλήθευση κωδικού πρόσβασης.<sup>[8][10]</sup>

**Ιδέες για Detection**

- Sessions τύπου Security `36` όπου το μήκος του πρώτου SRP frame είναι **`>= 32768`**
- Sessions που ξεκινούν να επεξεργάζονται cleartext traffic αντιγραφής αρχείων **`0x22`** πριν από οποιοδήποτε επιτυχημένο SRP proof / cipher install
- Επαναλαμβανόμενα retries μικρής διάρκειας προς το **TCP/5900**, μαζί με πολλαπλές τιμές file-copy `sid` σε ένα burst
- Μη αναμενόμενη δημιουργία των **`/etc/zshenv`**, **`/etc/sudoers.d/*`**, **`/Library/LaunchDaemons/*.plist`** ή **`/var/root/.ssh/authorized_keys`** μετά από έκθεση σε Screen Sharing

### Pentesting Remote Apple Events (RAE / EPPC)

Η Apple αποκαλεί αυτή τη δυνατότητα **Remote Application Scripting** στα σύγχρονα System Settings. Στο παρασκήνιο εκθέτει το **Apple Event Manager** απομακρυσμένα μέσω **EPPC** στο **TCP/3031**, μέσω της υπηρεσίας `com.apple.AEServer`. Η Palo Alto Unit 42 την ανέδειξε ξανά ως πρακτικό primitive για **macOS lateral movement**, επειδή έγκυρα credentials μαζί με ενεργοποιημένη υπηρεσία RAE επιτρέπουν σε έναν operator να χειρίζεται scriptable applications σε ένα απομακρυσμένο Mac.<sup>[6]</sup>

Χρήσιμοι έλεγχοι:
```bash
sudo /usr/sbin/systemsetup -getremoteappleevents
sudo launchctl print-disabled system | grep AEServer
lsof -nP -iTCP:3031 -sTCP:LISTEN
```
Αν έχετε ήδη admin/root στο target και θέλετε να το ενεργοποιήσετε:
```bash
sudo /usr/sbin/systemsetup -setremoteappleevents on
```
Βασική δοκιμή συνδεσιμότητας από άλλο Mac:
```bash
osascript -e 'tell application "Finder" of machine "eppc://user:pass@192.0.2.10" to get name of startup disk'
```
Στην πράξη, το abuse case δεν περιορίζεται στο Finder. Οποιαδήποτε **scriptable application** που αποδέχεται τα απαιτούμενα Apple events αποτελεί remote attack surface, γεγονός που καθιστά το RAE ιδιαίτερα ενδιαφέρον μετά από credential theft σε εσωτερικά macOS δίκτυα.

#### Πρόσφατα Screen-Sharing / ARD vulnerabilities (2023-2025)

| Year | CVE | Component | Impact | Fixed in |
|------|-----|-----------|--------|----------|
|2023|CVE-2023-42940|Screen Sharing|Η εσφαλμένη απόδοση της συνεδρίας μπορούσε να προκαλέσει τη μετάδοση του *λάθος* desktop ή window, με αποτέλεσμα τη διαρροή ευαίσθητων πληροφοριών|macOS Sonoma 14.2.1 (Dec 2023) |
|2024|CVE-2024-44248|Screen Sharing Server|Ένας χρήστης με πρόσβαση στο screen sharing ενδέχεται να μπορεί να δει την **οθόνη άλλου χρήστη** λόγω προβλήματος στη διαχείριση κατάστασης|macOS Ventura 13.7.2 / Sonoma 14.7.2 / Sequoia 15.1 (Oct-Dec 2024) |

**Hardening tips**

* Απενεργοποιήστε το *Screen Sharing*/*Remote Management* όταν δεν απαιτείται αυστηρά.
* Διατηρείτε το macOS πλήρως ενημερωμένο (η Apple γενικά παρέχει security fixes για τις τρεις τελευταίες major releases).
* Χρησιμοποιήστε έναν **Strong Password** *και* επιβάλετε η επιλογή *“VNC viewers may control screen with password”* να είναι **απενεργοποιημένη**, όταν αυτό είναι δυνατό.
* Τοποθετήστε το service πίσω από VPN αντί να εκθέτετε τις TCP 5900/3283 στο Internet.
* Προσθέστε έναν κανόνα Application Firewall για να περιορίσετε το `ARDAgent` στο local subnet:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockapp /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent on
```

---

## Bonjour Protocol

Το Bonjour, μια τεχνολογία σχεδιασμένη από την Apple, επιτρέπει σε **συσκευές στο ίδιο network να εντοπίζουν τα services που προσφέρουν μεταξύ τους**. Είναι επίσης γνωστό ως Rendezvous, **Zero Configuration** ή Zeroconf και επιτρέπει σε μια συσκευή να συνδεθεί σε ένα TCP/IP network, να **επιλέξει αυτόματα μια IP address** και να μεταδίδει τα services της σε άλλες network devices.

Το Zero Configuration Networking, που παρέχεται από το Bonjour, διασφαλίζει ότι οι συσκευές μπορούν να:

- **Αποκτούν αυτόματα μια IP Address** ακόμη και χωρίς DHCP server.
- Εκτελούν **name-to-address translation** χωρίς να απαιτείται DNS server.
- **Εντοπίζουν services** που είναι διαθέσιμα στο network.

Οι συσκευές που χρησιμοποιούν Bonjour εκχωρούν στον εαυτό τους μια **IP address από το εύρος 169.254/16** και επαληθεύουν τη μοναδικότητά της στο network. Τα Macs διατηρούν μια καταχώριση στον routing table για αυτό το subnet, η οποία μπορεί να επαληθευτεί μέσω του `netstat -rn | grep 169`.

Για το DNS, το Bonjour χρησιμοποιεί το **Multicast DNS (mDNS protocol)**. Το mDNS λειτουργεί μέσω της **port 5353/UDP**, χρησιμοποιώντας **standard DNS queries**, αλλά στοχεύοντας τη **multicast address 224.0.0.251**. Αυτή η προσέγγιση διασφαλίζει ότι όλες οι συσκευές του network που ακούν μπορούν να λαμβάνουν και να απαντούν στα queries, διευκολύνοντας την ενημέρωση των records τους.

Με την είσοδό της στο network, κάθε συσκευή επιλέγει αυτόματα ένα name, το οποίο συνήθως τελειώνει σε **.local** και μπορεί να προέρχεται από το hostname ή να έχει δημιουργηθεί τυχαία.

Η service discovery μέσα στο network διευκολύνεται από το **DNS Service Discovery (DNS-SD)**. Αξιοποιώντας τη μορφή των DNS SRV records, το DNS-SD χρησιμοποιεί **DNS PTR records** για να επιτρέπει την καταχώριση πολλαπλών services. Ένας client που αναζητά ένα συγκεκριμένο service θα ζητήσει ένα PTR record για το `<Service>.<Domain>` και, αν το service είναι διαθέσιμο από πολλαπλούς hosts, θα λάβει ως απάντηση μια λίστα από PTR records σε μορφή `<Instance>.<Service>.<Domain>`.

Το utility `dns-sd` μπορεί να χρησιμοποιηθεί για **discovering και advertising network services**. Ακολουθούν ορισμένα παραδείγματα χρήσης του:

### Αναζήτηση SSH Services

Για την αναζήτηση SSH services στο network, χρησιμοποιείται η ακόλουθη command:
```bash
dns-sd -B _ssh._tcp
```
Αυτή η εντολή ξεκινά την αναζήτηση υπηρεσιών \_ssh.\_tcp και εμφανίζει λεπτομέρειες όπως timestamp, flags, interface, domain, τύπο υπηρεσίας και όνομα instance.

### Διαφήμιση μιας υπηρεσίας HTTP

Για να διαφημίσετε μια υπηρεσία HTTP, μπορείτε να χρησιμοποιήσετε:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Αυτή η εντολή καταχωρίζει μια HTTP service με το όνομα "Index" στη θύρα 80 και με διαδρομή `/index.html`.

Για να αναζητήσετε HTTP services στο δίκτυο:
```bash
dns-sd -B _http._tcp
```
Όταν ξεκινά μια υπηρεσία, ανακοινώνει τη διαθεσιμότητά της σε όλες τις συσκευές του subnet κάνοντας multicast την παρουσία της. Οι συσκευές που ενδιαφέρονται για αυτές τις υπηρεσίες δεν χρειάζεται να στέλνουν requests, αλλά απλώς να ακούν αυτές τις ανακοινώσεις.

Για ένα πιο φιλικό προς τον χρήστη interface, η εφαρμογή **Discovery - DNS-SD Browser**, που είναι διαθέσιμη στο Apple App Store, μπορεί να οπτικοποιήσει τις υπηρεσίες που προσφέρονται στο τοπικό σας δίκτυο.

Εναλλακτικά, μπορείτε να γράψετε custom scripts για την περιήγηση και την ανακάλυψη υπηρεσιών χρησιμοποιώντας τη library `python-zeroconf`. Το script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) παρουσιάζει τη δημιουργία ενός service browser για υπηρεσίες `_http._tcp.local.`, εκτυπώνοντας τις υπηρεσίες που προστέθηκαν ή αφαιρέθηκαν:
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
### Αναζήτηση Bonjour ειδικά για macOS

Στα δίκτυα macOS, το Bonjour είναι συχνά ο ευκολότερος τρόπος για να εντοπίσετε **επιφάνειες απομακρυσμένης διαχείρισης** χωρίς να αγγίξετε απευθείας τον στόχο. Το Apple Remote Desktop μπορεί να ανακαλύπτει clients μέσω Bonjour, επομένως τα ίδια δεδομένα discovery είναι χρήσιμα και για έναν επιτιθέμενο.
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
Για ευρύτερες τεχνικές **mDNS spoofing, impersonation και cross-subnet discovery**, δείτε την ειδική σελίδα:

{{#ref}}
../../network-services-pentesting/5353-udp-multicast-dns-mdns.md
{{#endref}}

### Enumerating Bonjour μέσω δικτύου

* **Nmap NSE** – εντοπισμός services που διαφημίζονται από έναν host:

```bash
nmap -sU -p 5353 --script=dns-service-discovery <target>
```

Το script `dns-service-discovery` στέλνει ένα query `_services._dns-sd._udp.local` και στη συνέχεια κάνει enumerate κάθε διαφημιζόμενο service type.

* **mdns_recon** – Python tool που σαρώνει ολόκληρα ranges αναζητώντας *misconfigured* mDNS responders που απαντούν σε unicast queries (χρήσιμο για τον εντοπισμό συσκευών που είναι προσβάσιμες μεταξύ subnets/WAN):

```bash
git clone https://github.com/chadillac/mdns_recon && cd mdns_recon
python3 mdns_recon.py -r 192.0.2.0/24 -s _ssh._tcp.local
```

Αυτό θα επιστρέψει hosts που εκθέτουν SSH μέσω Bonjour εκτός του local link.

### Security considerations & πρόσφατα vulnerabilities (2024-2025)

| Έτος | CVE | Severity | Issue | Patched in |
|------|-----|----------|-------|------------|
|2024|CVE-2024-44183|Medium|Ένα logic error στο *mDNSResponder* επέτρεπε σε ένα crafted packet να προκαλέσει **denial-of-service**|macOS Ventura 13.7 / Sonoma 14.7 / Sequoia 15.0 (Sep 2024) |
|2025|CVE-2025-31222|High|Ένα correctness issue στο *mDNSResponder* μπορούσε να γίνει exploit για **local privilege escalation**|macOS Ventura 13.7.6 / Sonoma 14.7.6 / Sequoia 15.5 (May 2025) |

**Mitigation guidance**

1. Περιορίστε το UDP 5353 σε *link-local* scope – κάντε block ή rate-limit την κίνησή του σε wireless controllers, routers και host-based firewalls.
2. Απενεργοποιήστε πλήρως το Bonjour σε συστήματα που δεν χρειάζονται service discovery:

```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
3. Σε περιβάλλοντα όπου απαιτείται εσωτερικά το Bonjour, αλλά δεν πρέπει ποτέ να περνά τα network boundaries, χρησιμοποιήστε περιορισμούς του *AirPlay Receiver* profile (MDM) ή έναν mDNS proxy.
4. Ενεργοποιήστε το **System Integrity Protection (SIP)** και διατηρείτε το macOS ενημερωμένο – και τα δύο vulnerabilities διορθώθηκαν γρήγορα, αλλά βασίζονταν στο ότι το SIP ήταν ενεργοποιημένο για πλήρη προστασία.

### Απενεργοποίηση του Bonjour

Εάν υπάρχουν ανησυχίες για την ασφάλεια ή άλλοι λόγοι για την απενεργοποίηση του Bonjour, μπορεί να απενεργοποιηθεί με την ακόλουθη εντολή:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Αναφορές

- [1] [Το Εγχειρίδιο του Mac Hacker](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [Η Τέχνη του Mac Malware, Τόμος I: Ανάλυση - Patrick Wardle](https://taomm.org/vol1/analysis.html)
- [3] [LockBoxx - macOS Red Teaming 206: ARD (Apple Remote Desktop Protocol)](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)
- [4] [NVD – CVE-2023-42940](https://nvd.nist.gov/vuln/detail/CVE-2023-42940)
- [5] [NVD – CVE-2024-44183](https://nvd.nist.gov/vuln/detail/CVE-2024-44183)
- [6] [Palo Alto Unit 42 - Lateral Movement στο macOS: Μοναδικές και δημοφιλείς τεχνικές και παραδείγματα από τον πραγματικό κόσμο](https://unit42.paloaltonetworks.com/unique-popular-techniques-lateral-movement-macos/)
- [7] [Apple Support - Σχετικά με το περιεχόμενο ασφάλειας του macOS Sonoma 14.7.2](https://support.apple.com/en-us/121840)
- [8] [Apple Screen Sharing Pre-Auth RCE](https://warez.sl0p.foo/apple-screensharing-rce/)
- [9] [Apple Support - Σχετικά με το περιεχόμενο ασφάλειας του macOS Tahoe 26.6](https://support.apple.com/en-us/128067)
- [10] [RFC 5054 - Χρήση του Secure Remote Password (SRP) Protocol για TLS Authentication](https://www.rfc-editor.org/rfc/rfc5054)

{{#include ../../banners/hacktricks-training.md}}
