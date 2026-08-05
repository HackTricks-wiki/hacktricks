# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Σε αντίθεση με τα Kernel Extensions, τα **System Extensions εκτελούνται σε user space** αντί για kernel space, μειώνοντας τον κίνδυνο κατάρρευσης του συστήματος λόγω δυσλειτουργίας του extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Υπάρχουν τρεις τύποι system extensions: **DriverKit** Extensions, **Network** Extensions και **Endpoint Security** Extensions.

### **DriverKit Extensions**

Το DriverKit αποτελεί αντικατάσταση των kernel extensions που **παρέχουν υποστήριξη υλικού**. Επιτρέπει στους device drivers (όπως USB, Serial, NIC και HID drivers) να εκτελούνται σε user space αντί για kernel space. Το framework DriverKit περιλαμβάνει **εκδόσεις συγκεκριμένων κλάσεων του I/O Kit για user space**, ενώ ο kernel προωθεί τα κανονικά συμβάντα I/O Kit στο user space, προσφέροντας ένα ασφαλέστερο περιβάλλον για την εκτέλεση αυτών των drivers.<sup>[2]</sup>

### **Network Extensions**

Τα Network Extensions παρέχουν τη δυνατότητα προσαρμογής των συμπεριφορών του δικτύου. Υπάρχουν αρκετοί τύποι Network Extensions:

- **App Proxy**: Χρησιμοποιείται για τη δημιουργία ενός VPN client που υλοποιεί ένα flow-oriented, custom VPN protocol. Αυτό σημαίνει ότι διαχειρίζεται την κίνηση δικτύου με βάση τις συνδέσεις (ή flows) και όχι με βάση μεμονωμένα packets.
- **Packet Tunnel**: Χρησιμοποιείται για τη δημιουργία ενός VPN client που υλοποιεί ένα packet-oriented, custom VPN protocol. Αυτό σημαίνει ότι διαχειρίζεται την κίνηση δικτύου με βάση μεμονωμένα packets.
- **Filter Data**: Χρησιμοποιείται για το filtering δικτυακών "flows". Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου σε επίπεδο flow.
- **Filter Packet**: Χρησιμοποιείται για το filtering μεμονωμένων network packets. Μπορεί να παρακολουθεί ή να τροποποιεί δεδομένα δικτύου σε επίπεδο packet.
- **DNS Proxy**: Χρησιμοποιείται για τη δημιουργία ενός custom DNS provider. Μπορεί να χρησιμοποιηθεί για την παρακολούθηση ή την τροποποίηση DNS requests και responses.<sup>[2]</sup>

## Endpoint Security Framework

Το Endpoint Security είναι ένα framework που παρέχεται από την Apple στο macOS και προσφέρει ένα σύνολο APIs για την ασφάλεια του συστήματος. Προορίζεται για χρήση από **security vendors και developers, ώστε να δημιουργούν προϊόντα που μπορούν να παρακολουθούν και να ελέγχουν τη δραστηριότητα του συστήματος** για τον εντοπισμό και την προστασία από κακόβουλη δραστηριότητα.

Αυτό το framework παρέχει μια **συλλογή APIs για την παρακολούθηση και τον έλεγχο της δραστηριότητας του συστήματος**, όπως executions διεργασιών, συμβάντα file system, network και kernel events.

Ο πυρήνας αυτού του framework υλοποιείται στον kernel, ως Kernel Extension (KEXT) που βρίσκεται στο **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Αυτό το KEXT αποτελείται από αρκετά βασικά components:

- **EndpointSecurityDriver**: Λειτουργεί ως το "entry point" για το kernel extension. Είναι το κύριο σημείο αλληλεπίδρασης μεταξύ του OS και του Endpoint Security framework.
- **EndpointSecurityEventManager**: Αυτό το component είναι υπεύθυνο για την υλοποίηση kernel hooks. Τα kernel hooks επιτρέπουν στο framework να παρακολουθεί system events, παρεμβάλλοντας system calls.
- **EndpointSecurityClientManager**: Διαχειρίζεται την επικοινωνία με clients στο user space, καταγράφοντας ποιοι clients είναι συνδεδεμένοι και χρειάζεται να λαμβάνουν event notifications.
- **EndpointSecurityMessageManager**: Στέλνει messages και event notifications σε clients στο user space.

Τα events που μπορεί να παρακολουθεί το Endpoint Security framework κατηγοριοποιούνται σε:

- File events
- Process events
- Socket events
- Kernel events (όπως loading/unloading ενός kernel extension ή το άνοιγμα μιας I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Η **επικοινωνία σε user space** με το Endpoint Security framework πραγματοποιείται μέσω της κλάσης IOUserClient. Χρησιμοποιούνται δύο διαφορετικές subclasses, ανάλογα με τον τύπο του caller:

- **EndpointSecurityDriverClient**: Απαιτεί το entitlement `com.apple.private.endpoint-security.manager`, το οποίο διαθέτει μόνο η system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Απαιτεί το entitlement `com.apple.developer.endpoint-security.client`. Συνήθως χρησιμοποιείται από third-party security software που χρειάζεται να αλληλεπιδρά με το Endpoint Security framework.<sup>[1]</sup>

Τα Endpoint Security Extensions:**`libEndpointSecurity.dylib`** είναι η C library που χρησιμοποιούν τα system extensions για να επικοινωνούν με τον kernel. Αυτή η library χρησιμοποιεί το I/O Kit (`IOKit`) για να επικοινωνεί με το Endpoint Security KEXT.<sup>[2]</sup>

Το **`endpointsecurityd`** είναι ένα βασικό system daemon που εμπλέκεται στη διαχείριση και την εκκίνηση των endpoint security system extensions, ιδιαίτερα κατά τη διαδικασία early boot. **Μόνο τα system extensions** που έχουν τη σήμανση **`NSEndpointSecurityEarlyBoot`** στο αρχείο `Info.plist` λαμβάνουν αυτή την επεξεργασία early boot.<sup>[2]</sup>

Ένα άλλο system daemon, το **`sysextd`**, **επικυρώνει τα system extensions** και τα μετακινεί στις κατάλληλες τοποθεσίες του συστήματος. Στη συνέχεια ζητά από το σχετικό daemon να φορτώσει το extension. Το **`SystemExtensions.framework`** είναι υπεύθυνο για την ενεργοποίηση και απενεργοποίηση των system extensions.<sup>[2]</sup>

## Bypassing ESF

Το ESF χρησιμοποιείται από security tools που θα προσπαθήσουν να εντοπίσουν έναν red teamer, επομένως οποιαδήποτε πληροφορία σχετικά με το πώς θα μπορούσε να αποφευχθεί αυτό ακούγεται ενδιαφέρουσα.

### CVE-2021-30965

Το θέμα είναι ότι η εφαρμογή ασφάλειας χρειάζεται να διαθέτει **Full Disk Access permissions**. Επομένως, αν ένας attacker μπορούσε να τις αφαιρέσει, θα μπορούσε να αποτρέψει την εκτέλεση του software:<sup>[3]</sup>
```bash
tccutil reset All
```
Για **περισσότερες πληροφορίες** σχετικά με αυτό το bypass και άλλα συναφή, δείτε την ομιλία [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Τελικά, αυτό διορθώθηκε με την εκχώρηση της νέας permission **`kTCCServiceEndpointSecurityClient`** στην εφαρμογή ασφαλείας που διαχειρίζεται το **`tccd`**, ώστε το `tccutil` να μην εκκαθαρίζει τις permissions της, αποτρέποντας την εκτέλεσή της.<sup>[3]</sup>

## Αναφορές

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
