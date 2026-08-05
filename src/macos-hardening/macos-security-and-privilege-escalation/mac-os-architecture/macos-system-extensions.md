# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Σε αντίθεση με τα Kernel Extensions, τα **System Extensions εκτελούνται σε user space** αντί για kernel space, μειώνοντας τον κίνδυνο κατάρρευσης του συστήματος λόγω δυσλειτουργίας του extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Υπάρχουν τρεις τύποι system extensions: **DriverKit** Extensions, **Network** Extensions και **Endpoint Security** Extensions.

### **DriverKit Extensions**

Το DriverKit αποτελεί αντικατάσταση των kernel extensions που **παρέχουν υποστήριξη hardware**. Επιτρέπει στους device drivers (όπως USB, Serial, NIC και HID drivers) να εκτελούνται σε user space αντί για kernel space. Το DriverKit framework περιλαμβάνει **user space εκδόσεις συγκεκριμένων κλάσεων του I/O Kit**, ενώ ο kernel προωθεί τα κανονικά I/O Kit events στο user space, προσφέροντας ένα ασφαλέστερο περιβάλλον για την εκτέλεση αυτών των drivers.<sup>[[2]](#references)</sup>

### **Network Extensions**

Τα Network Extensions παρέχουν τη δυνατότητα προσαρμογής των network behaviors. Υπάρχουν διάφοροι τύποι Network Extensions:

- **App Proxy**: Χρησιμοποιείται για τη δημιουργία ενός VPN client που υλοποιεί ένα flow-oriented, custom VPN protocol. Αυτό σημαίνει ότι χειρίζεται την κίνηση δικτύου με βάση τις συνδέσεις (ή flows) και όχι τα μεμονωμένα packets.
- **Packet Tunnel**: Χρησιμοποιείται για τη δημιουργία ενός VPN client που υλοποιεί ένα packet-oriented, custom VPN protocol. Αυτό σημαίνει ότι χειρίζεται την κίνηση δικτύου με βάση τα μεμονωμένα packets.
- **Filter Data**: Χρησιμοποιείται για το filtering των network "flows". Μπορεί να παρακολουθεί ή να τροποποιεί network data σε επίπεδο flow.
- **Filter Packet**: Χρησιμοποιείται για το filtering μεμονωμένων network packets. Μπορεί να παρακολουθεί ή να τροποποιεί network data σε επίπεδο packet.
- **DNS Proxy**: Χρησιμοποιείται για τη δημιουργία ενός custom DNS provider. Μπορεί να χρησιμοποιηθεί για την παρακολούθηση ή την τροποποίηση DNS requests και responses.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Το Endpoint Security είναι ένα framework που παρέχεται από την Apple στο macOS και προσφέρει ένα σύνολο από APIs για την ασφάλεια του συστήματος. Προορίζεται για χρήση από **security vendors και developers, ώστε να δημιουργούν προϊόντα που μπορούν να παρακολουθούν και να ελέγχουν τη δραστηριότητα του συστήματος** για τον εντοπισμό και την προστασία από malicious activity.

Αυτό το framework παρέχει μια **συλλογή από APIs για την παρακολούθηση και τον έλεγχο της δραστηριότητας του συστήματος**, όπως process executions, file system events, network events και kernel events.

Ο πυρήνας αυτού του framework υλοποιείται στον kernel, ως Kernel Extension (KEXT) που βρίσκεται στο **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Αυτό το KEXT αποτελείται από αρκετά βασικά components:

- **EndpointSecurityDriver**: Λειτουργεί ως το "entry point" για το kernel extension. Είναι το βασικό σημείο αλληλεπίδρασης μεταξύ του OS και του Endpoint Security framework.
- **EndpointSecurityEventManager**: Αυτό το component είναι υπεύθυνο για την υλοποίηση kernel hooks. Τα kernel hooks επιτρέπουν στο framework να παρακολουθεί system events, κάνοντας interception των system calls.
- **EndpointSecurityClientManager**: Διαχειρίζεται την επικοινωνία με τους user space clients, καταγράφοντας ποιοι clients είναι συνδεδεμένοι και χρειάζεται να λαμβάνουν event notifications.
- **EndpointSecurityMessageManager**: Στέλνει messages και event notifications σε user space clients.

Τα events που μπορεί να παρακολουθεί το Endpoint Security framework κατηγοριοποιούνται ως εξής:

- File events
- Process events
- Socket events
- Kernel events (όπως το loading/unloading ενός kernel extension ή το άνοιγμα μιας I/O Kit συσκευής)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

Η **επικοινωνία σε user space** με το Endpoint Security framework πραγματοποιείται μέσω της κλάσης IOUserClient. Χρησιμοποιούνται δύο διαφορετικές subclasses, ανάλογα με τον τύπο του caller:

- **EndpointSecurityDriverClient**: Απαιτεί το `com.apple.private.endpoint-security.manager` entitlement, το οποίο διαθέτει μόνο το system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Απαιτεί το `com.apple.developer.endpoint-security.client` entitlement. Συνήθως χρησιμοποιείται από third-party security software που χρειάζεται να αλληλεπιδρά με το Endpoint Security framework.<sup>[[1]](#references)</sup>

Τα Endpoint Security Extensions:**`libEndpointSecurity.dylib`** είναι η C library που χρησιμοποιούν τα system extensions για να επικοινωνούν με τον kernel. Αυτή η library χρησιμοποιεί το I/O Kit (`IOKit`) για να επικοινωνεί με το Endpoint Security KEXT.<sup>[[2]](#references)</sup>

Το **`endpointsecurityd`** είναι ένα βασικό system daemon που συμμετέχει στη διαχείριση και την εκκίνηση των endpoint security system extensions, ιδιαίτερα κατά τη διαδικασία του early boot. **Μόνο system extensions** που έχουν σημειωθεί με **`NSEndpointSecurityEarlyBoot`** στο αρχείο `Info.plist` λαμβάνουν αυτή την early boot μεταχείριση.<sup>[[2]](#references)</sup>

Ένα άλλο system daemon, το **`sysextd`**, **επικυρώνει τα system extensions** και τα μετακινεί στις κατάλληλες system locations. Στη συνέχεια ζητά από το σχετικό daemon να φορτώσει το extension. Το **`SystemExtensions.framework`** είναι υπεύθυνο για την ενεργοποίηση και απενεργοποίηση των system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

Το ESF χρησιμοποιείται από security tools που θα προσπαθήσουν να εντοπίσουν έναν red teamer, επομένως κάθε πληροφορία σχετικά με το πώς θα μπορούσε να αποφευχθεί αυτό ακούγεται ενδιαφέρουσα.

### CVE-2021-30965

Το ζήτημα είναι ότι η security application χρειάζεται **Full Disk Access permissions**. Επομένως, αν ένας attacker μπορούσε να τα αφαιρέσει, θα μπορούσε να εμποδίσει τη λειτουργία του software:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Για **περισσότερες πληροφορίες** σχετικά με αυτό το bypass και παρόμοια bypass, δείτε την ομιλία [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Τελικά, αυτό διορθώθηκε δίνοντας τη νέα permission **`kTCCServiceEndpointSecurityClient`** στην security app που διαχειρίζεται το **`tccd`**, ώστε το `tccutil` να μην εκκαθαρίζει τις permissions της, εμποδίζοντάς την να εκτελείται.<sup>[[3]](#references)</sup>

## Αναφορές

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
