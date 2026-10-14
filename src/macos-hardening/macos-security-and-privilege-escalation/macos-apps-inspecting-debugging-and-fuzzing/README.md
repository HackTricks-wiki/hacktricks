# Applications macOS - Inspection, débogage et fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Analyse statique

### otool & objdump & nm

```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```

### Disarm (ancien jtool2)

Vous pouvez [**télécharger disarm ici**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Notez que **`disarm`** peut également fonctionner avec des fichiers IM4P compressés (comme `kernelcache`) et n’extraire que les parties nécessaires, voire analyser la partie requise sans l’extraire.

```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```


### Codesign / ldid

> [!TIP]
> **`Codesign`** se trouve sur **macOS**, tandis que **`ldid`** se trouve sur **iOS**.

```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```

### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) est un outil utile pour inspecter les fichiers **.pkg** (installateurs) et voir leur contenu avant de les installer.\
Ces installateurs contiennent des scripts bash `preinstall` et `postinstall` que les auteurs de malware exploitent généralement pour **assurer la** **persistance** **du** **malware**.

### hdiutil

Cet outil **monte** les fichiers d’image disque Apple (`.dmg`) afin qu’ils puissent être inspectés avant toute exécution :

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Il sera monté dans `/Volumes`

### Binaires packés

- Vérifiez si l’entropie est élevée
- Vérifiez les chaînes de caractères (y a-t-il presque aucune chaîne compréhensible ? Le binaire est alors packé)
- Le packer UPX pour macOS génère une section appelée `__XHDR`.

## Analyse statique d’Objective-C

### Métadonnées

> [!CAUTION]
> Notez que les programmes écrits en Objective-C **conservent** leurs déclarations de classes **lorsqu’ils sont** **compilés** en [binaires Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Ces déclarations de classes **incluent** le nom et le type des éléments suivants :

- Les interfaces définies
- Les méthodes des interfaces
- Les variables d’instance des interfaces
- Les protocoles définis

Notez que ces noms peuvent être obfusqués afin de rendre l’analyse du binaire plus difficile.

### Appel de fonction

Lorsqu’une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé appelle **`objc_msgSend`** au lieu d’appeler directement cette fonction. Cette fonction appellera ensuite la fonction finale :

![Métadonnées - Appel de fonction : Lorsqu’une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé appelle objc msgSend au lieu d’appeler directement cette fonction. Cette fonction appellera ensuite...](<../../../images/image (305).png>)

Les paramètres attendus par cette fonction sont :

- Le premier paramètre (**self**) est « un pointeur qui pointe vers l’**instance de la classe destinée à recevoir le message** ». Plus simplement, c’est l’objet sur lequel la méthode est appelée. Si la méthode est une méthode de classe, il s’agit d’une instance de l’objet classe (dans son ensemble), tandis que pour une méthode d’instance, self pointe vers une instance de la classe instanciée en tant qu’objet.
- Le deuxième paramètre (**op**) est « le sélecteur de la méthode qui traite le message ». Plus simplement, il s’agit du **nom de la méthode**.
- Les paramètres restants sont les **valeurs requises par la méthode** (op).

Consultez cette page pour voir comment **obtenir facilement ces informations avec `lldb` sur ARM64** :


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64 :

| **Argument**       | **Registre**                                                    | **(pour) objc_msgSend**                                      |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------------ |
| **1er argument**  | **rdi**                                                         | **self : objet sur lequel la méthode est appelée**           |
| **2e argument**   | **rsi**                                                         | **op : nom de la méthode**                                   |
| **3e argument**   | **rdx**                                                         | **1er argument de la méthode**                               |
| **4e argument**   | **rcx**                                                         | **2e argument de la méthode**                                |
| **5e argument**   | **r8**                                                          | **3e argument de la méthode**                                |
| **6e argument**   | **r9**                                                          | **4e argument de la méthode**                                |
| **7e argument et +** | <p><strong>rsp+</strong><br><strong>(sur la pile)</strong></p> | **5e argument de la méthode et suivants**                    |

### Extraction des métadonnées Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) est un outil permettant d’effectuer un class-dump de binaires Objective-C. Le dépôt GitHub indique qu’il s’applique aux dylibs, mais il fonctionne également avec les exécutables.

```bash
./dynadump dump /path/to/bin
```

Au moment de la rédaction, c’est **actuellement celui qui fonctionne le mieux**.

#### Outils classiques

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) est l’outil d’origine qui génère des déclarations pour les classes, catégories et protocoles dans du code Objective-C formaté.

Il est ancien et n’est plus maintenu ; il risque donc de ne pas fonctionner correctement.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) est un outil moderne et multiplateforme de class dump Objective-C. Par rapport aux outils existants, iCDump peut fonctionner indépendamment de l’écosystème Apple et expose des bindings Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Analyse statique de Swift

Avec les binaires Swift, grâce à la compatibilité avec Objective-C, il est parfois possible d’extraire les déclarations à l’aide de [class-dump](https://github.com/nygard/class-dump/), mais pas toujours.

Avec les lignes de commande **`jtool -l`** ou **`otool -l`**, il est possible de trouver plusieurs sections commençant par le préfixe **`__swift5`** :

```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
    [...]
    Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
    Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
    Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
    Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
    [...]
```

Vous trouverez plus d’informations sur les [**informations stockées dans ces sections dans cet article de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

De plus, **les binaires Swift peuvent contenir des symboles** (par exemple, les bibliothèques doivent stocker des symboles pour que leurs fonctions puissent être appelées). Les **symboles contiennent généralement le nom de la fonction** et ses attributs, sous une forme peu lisible. Ils sont donc très utiles, et il existe des « **demanglers** » capables de retrouver le nom d’origine :

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Analyse dynamique

> [!WARNING]
> **Ne désactivez pas SIP comme étape de débogage par défaut.** Les builds de développement dotés de `com.apple.security.get-task-allow` peuvent être débogués avec SIP activé. Vérifiez la cible avec `codesign -d --entitlements :- /path/to/binary` avant d’essayer LLDB. Le seul fait de disposer d’un droit de débogueur ne donne pas accès aux cibles protégées par SIP.<sup>[[15]](#references)</sup>
>
> Une application distribuée avec le hardened runtime omet généralement `get-task-allow` et bloque l’attachement. Si possible, utilisez un build de débogage fourni par le développeur ; re-signer une copie jetable peut modifier le comportement testé. Si une cible protégée exige la désactivation de SIP, utilisez une machine de test dédiée ou une VM plutôt qu’une machine dont vous dépendez.<sup>[[16]](#references)</sup>

> [!WARNING]
> Notez que pour **instrumenter des binaires système** (tels que `cloudconfigurationd`) sous macOS, **SIP doit être désactivé** (la simple suppression de la signature ne suffit pas).

### APIs

macOS expose des APIs intéressantes qui fournissent des informations sur les processus :

- `proc_info` : c’est la principale API qui fournit de nombreuses informations sur chaque processus. Vous devez être root pour obtenir des informations sur les autres processus, mais vous n’avez besoin ni de droits spéciaux ni de ports mach.
- `libsysmon.dylib` : expose des informations sur les processus au moyen de fonctions XPC, mais les appelants doivent disposer du droit `com.apple.sysmond.client`.

### Stackshot & microstackshots

Le **stackshotting** est une technique permettant de capturer l’état des processus, y compris les piles d’appels de tous les threads en cours d’exécution. C’est particulièrement utile pour le débogage, l’analyse des performances et la compréhension du comportement du système à un instant donné. Sous iOS et macOS, le stackshotting peut être effectué à l’aide de plusieurs outils et méthodes, notamment les outils **`sample`** et **`spindump`**.

### Sysdiagnose

Cet outil (`/usr/bini/ysdiagnose`) collecte essentiellement de nombreuses informations depuis votre ordinateur en exécutant des dizaines de commandes différentes, telles que `ps`, `zprint`...

Il doit être exécuté en tant que **root** et le daemon `/usr/libexec/sysdiagnosed` possède des droits très intéressants, tels que `com.apple.system-task-ports` et `get-task-allow`.

Son plist se trouve dans `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` et déclare 3 MachServices :

- `com.apple.sysdiagnose.CacheDelete` : supprime les anciennes archives dans /var/rmp
- `com.apple.sysdiagnose.kernel.ipc` : port spécial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc` : interface en mode utilisateur via la classe Obj-C `Libsysdiagnose`. Trois arguments peuvent être transmis dans un dict (`compress`, `display`, `run`)

### Unified Logs

macOS génère de nombreux logs utiles pour analyser le comportement d’une application.

Certains champs des logs contiennent la balise `<private>` afin de masquer les informations permettant d’identifier l’utilisateur ou l’appareil. D’anciennes instructions décrivent parfois l’installation d’un certificat pour révéler ces champs ; les recommandations actuelles de débogage utilisent plutôt un profil de configuration explicitement limité avec `Enable-Private-Data`, ou des `OSLogPreferences` propres à l’application. Le comportement peut varier selon le sous-système et la version de macOS. Les anciennes informations sur les certificats et les profils sont conservées dans les références. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Panneau de gauche

Dans le panneau de gauche de Hopper, il est possible de voir les symboles (**Labels**) du binaire, la liste des procédures et des fonctions (**Proc**) ainsi que les chaînes (**Str**). Il ne s’agit pas de toutes les chaînes, mais de celles définies dans différentes parties du fichier Mach-O (comme _cstring ou_ `objc_methname`).

#### Panneau central

Dans le panneau central, vous pouvez voir le **code désassemblé**. Vous pouvez afficher le désassemblage en **brut**, sous forme de **graphe**, en version **décompilée** ou en **binaire**, en cliquant sur l’icône correspondante :

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

En faisant un clic droit sur un objet de code, vous pouvez voir les **références vers/depuis cet objet** ou même modifier son nom (cela ne fonctionne pas dans le pseudocode décompilé) :

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

De plus, vous pouvez **écrire des commandes Python en bas du panneau central**.

#### Panneau de droite

Dans le panneau de droite, vous pouvez voir des informations intéressantes, telles que l’**historique de navigation** (pour savoir comment vous êtes arrivé à la situation actuelle), le **graphe d’appels** qui indique toutes les **fonctions appelant cette fonction** et toutes les fonctions **appelées par cette fonction**, ainsi que les informations sur les **variables locales**.

### dtrace

Il permet aux utilisateurs d’accéder aux applications à un **niveau extrêmement bas** et leur offre un moyen de **tracer** des **programmes**, voire de modifier leur flux d’exécution. Dtrace utilise des **probes** placées à différents endroits du kernel, notamment au début et à la fin des appels système.

DTrace utilise la fonction **`dtrace_probe_create`** pour créer un probe pour chaque appel système. Ces probes peuvent se déclencher au **point d’entrée et au point de sortie de chaque appel système**. L’interaction avec DTrace se fait via /dev/dtrace, accessible uniquement à l’utilisateur root.<sup>[[1]](#references)</sup>

> [!TIP]
> Pour activer Dtrace sans désactiver complètement la protection SIP, vous pouvez exécuter en mode de récupération : `csrutil enable --without dtrace`
>
> Vous pouvez aussi utiliser **`dtrace`** ou **`dtruss`** sur les binaires que **vous avez compilés**.

Les probes disponibles dans dtrace peuvent être obtenus avec :

```bash
dtrace -l | head
   ID   PROVIDER            MODULE                          FUNCTION NAME
    1     dtrace                                                     BEGIN
    2     dtrace                                                     END
    3     dtrace                                                     ERROR
   43    profile                                                     profile-97
   44    profile                                                     profile-199
```

Le nom du probe se compose de quatre parties : le fournisseur, le module, la fonction et le nom (`fbt:mach_kernel:ptrace:entry`). Si vous ne spécifiez pas une partie du nom, DTrace utilisera un caractère générique à sa place.

Pour configurer DTrace afin d’activer des probes et de spécifier les actions à effectuer lorsqu’ils se déclenchent, nous devons utiliser le langage D.

Vous trouverez une explication plus détaillée et d’autres exemples sur [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemples

Exécutez `man -k dtrace` pour afficher la liste des **scripts DTrace disponibles**. Exemple : `sudo dtruss -n binary`

- En ligne

```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```

- script

```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
    printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
        printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
        ;
}
syscall:::return
{
        printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```

### dtruss

```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```

### kdebug

C'est une fonction de traçage du kernel. Les codes documentés se trouvent dans **`/usr/share/misc/trace.codes`**.

Des outils comme `latency`, `sc_usage`, `fs_usage` et `trace` l'utilisent en interne.

Pour interagir avec `kdebug`, on utilise `sysctl` dans l'espace de noms `kern.kdebug`. Les MIB à utiliser se trouvent dans `sys/sysctl.h`, et les fonctions sont implémentées dans `bsd/kern/kdebug.c`.

Pour interagir avec kdebug à l'aide d'un client personnalisé, les étapes sont généralement les suivantes :

- Supprimer les paramètres existants avec KERN_KDSETREMOVE
- Configurer le trace avec KERN_KDSETBUF et KERN_KDSETUP
- Utiliser KERN_KDGETBUF pour obtenir le nombre d'entrées du buffer
- Récupérer son propre client du trace avec KERN_KDPINDEX
- Activer le tracing avec KERN_KDENABLE
- Lire le buffer en appelant KERN_KDREADTR
- Pour associer chaque thread à son processus, appeler KERN_KDTHRMAP.

Pour obtenir ces informations, il est possible d'utiliser l'outil Apple **`trace`** ou l'outil personnalisé [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Notez que Kdebug n'est disponible que pour un seul client à la fois.** Un seul outil utilisant k-debug peut donc être exécuté à la fois.

### ktrace

Les API `ktrace_*` proviennent de `libktrace.dylib`, qui encapsule celles de `Kdebug`. Un client peut donc simplement appeler `ktrace_session_create` et `ktrace_events_[single/class]` pour définir des callbacks sur des codes spécifiques, puis démarrer le tout avec `ktrace_start`.

Vous pouvez utiliser celui-ci même si **SIP est activé**

Vous pouvez utiliser l'utilitaire `ktrace` comme client :

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

Ou `tailspin`.

### kperf

Cet outil sert à effectuer le profiling au niveau du kernel et est construit à l’aide des callouts `Kdebug`.

En gros, la variable globale `kernel_debug_active` est vérifiée. Si elle est définie, `kperf_kdebug_handler` est appelé avec le code `Kdebug` et l’adresse du frame kernel appelant. Si le code `Kdebug` correspond à l’un des codes sélectionnés, les « actions » configurées sous forme de bitmap sont exécutées (consultez `osfmk/kperf/action.h` pour connaître les options).

Kperf possède également une table MIB sysctl : (en tant que root) `sysctl kperf`. Ce code se trouve dans `osfmk/kperf/kperfbsd.c`.

Par ailleurs, un sous-ensemble des fonctionnalités de Kperf se trouve dans `kpc`, qui fournit des informations sur les compteurs de performance de la machine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) est un outil très utile pour vérifier les actions liées aux processus effectuées par un processus (par exemple, surveiller les nouveaux processus qu’il crée).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) est un outil qui affiche les relations entre les processus.\
Vous devez surveiller votre Mac à l’aide d’une commande comme **`sudo eslogger fork exec rename create > cap.json`** (le terminal qui l’exécute doit disposer de FDA). Vous pouvez ensuite charger le fichier json dans cet outil pour afficher toutes les relations :

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) surveille les événements liés aux fichiers, tels que leur création, leur modification et leur suppression.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) est un outil GUI dont l’apparence et le fonctionnement rappelleront aux utilisateurs de Windows _Procmon_ de Microsoft Sysinternals. Cet outil permet de démarrer et d’arrêter l’enregistrement de différents types d’événements, de filtrer ces événements par catégories telles que les fichiers, les processus, le réseau, etc., et d’enregistrer les événements capturés au format json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fait partie des outils de développement de Xcode. Il sert à surveiller les performances des applications, à détecter les fuites de mémoire et à suivre l’activité du système de fichiers.

![Crescendo - Apple Instruments : Apple Instruments fait partie des outils de développement de Xcode. Il sert à surveiller les performances des applications, à détecter les fuites de mémoire et à suivre l’activité du système de fichiers](<../../../images/image (1138).png>)

### fs_usage

Permet de suivre les actions effectuées par les processus :

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) est utile pour voir les **bibliothèques** utilisées par un binaire, les **fichiers** qu’il utilise et ses connexions **réseau**.\
Il vérifie également les processus binaires avec **VirusTotal** et affiche des informations sur le binaire.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Dans [**cet article de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), vous trouverez un exemple montrant comment **déboguer un daemon en cours d’exécution** qui utilisait **`PT_DENY_ATTACH`** pour empêcher le débogage, même lorsque SIP était désactivé.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` est une requête `ptrace(2)` propre à Darwin, dont la valeur est **31** (`0x1f`) ; les autres arguments sont ignorés. Un processus peut l’appeler directement, sans fork, pour empêcher tout traçage ultérieur par son processus parent.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### État de XNU et ordre des appels

Le résultat dépend de la requête `ptrace` qui atteint XNU en premier :<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB s’attache en premier :** `debugserver` utilise `PT_ATTACHEXC` ; XNU le convertit en `PT_ATTACH`, effectue l’autorisation `KAUTH_PROCESS_CANTRACE` et définit `P_LTRACED` sur la cible. Un `PT_DENY_ATTACH` ultérieur détecte ce flag et termine la cible avec `W_EXITCODE(ENOTSUP, 0)`, généralement affiché par LLDB comme le statut **45** (`0x2d`).
- **La cible refuse en premier :** XNU définit `P_LNOATTACH`. Un attachement ultérieur est rejeté par l’autorisation de traçage des processus ; le chemin d’erreur de l’attachement détecte `P_LNOATTACH` et envoie `SIGSEGV` au processus qui tente de s’attacher, ce qui peut apparaître dans LLDB comme une perte de connexion avec `debugserver`.

Pour distinguer ces chemins, activez la journalisation de `debugserver` avant le lancement ou l’attachement, puis examinez ses requêtes `ptrace` :<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Identification statique ARM64 et contournement

Pour un Mach-O ARM64 non obfusqué, localisez le stub de `_ptrace` importé et examinez les sites d’appel. Le premier argument entier est passé dans `w0` ; cette séquence expose directement la requête anti-debug. L’absence de cet import n’est pas concluante, car le code peut résoudre `ptrace` dynamiquement. Un `_sysctl` importé peut également indiquer la présence de vérifications anti-debug, bien qu’il puisse lui aussi être résolu dynamiquement.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

Dans l’exemple présenté, remplacer la valeur immédiate `0x1f` par `0x0` modifie la requête en `PT_TRACE_ME` et permet au programme de continuer sous LLDB. Il s’agit d’un **contournement spécifique à cet exemple**, et non d’un no-op général : examinez les vérifications de la valeur de retour et le flux de contrôle de l’appelant avant de choisir de modifier la requête, d’ignorer l’appel ou de forcer un retour réussi.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** est l’outil de facto pour le **débogage** des binaires **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Vous pouvez définir la syntaxe Intel lors de l’utilisation de lldb en créant un fichier **`.lldbinit`** dans votre dossier personnel contenant la ligne suivante :

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dans lldb, dump a process avec `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Command</strong></td><td><strong>Description</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Démarre l’exécution, qui continue jusqu’à ce qu’un breakpoint soit atteint ou que le processus se termine.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Démarre l’exécution et s’arrête au point d’entrée.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Reprend l’exécution du processus débogué.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Exécute l’instruction suivante. Cette commande passe les appels de fonction.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Exécute l’instruction suivante. Contrairement à la commande <code>nexti</code>, cette commande entre dans les appels de fonction.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Exécute les instructions restantes de la fonction (frame) actuelle, revient, puis s’arrête.</td></tr>
<tr><td><strong>control + c</strong></td><td>Met l’exécution en pause. Si le processus a été lancé (<code>r</code>) ou repris (<code>c</code>), il s’arrête là où il se trouve.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Toute fonction appelée main</p>
<p><code>b &lt;binname&gt;`main</code> # Fonction principale du binaire</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Fonction principale du binaire indiqué</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Toute méthode NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # S’arrêter dans toutes les fonctions de cette bibliothèque</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Liste des breakpoints</p>
<p><code>br e/dis &lt;num&gt;</code> # Activer/désactiver un breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Obtenir de l’aide sur la commande breakpoint</p>
<p><code>help memory write</code> # Obtenir de l’aide sur l’écriture en mémoire</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Affiche la mémoire sous forme de chaîne terminée par un caractère nul.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Affiche la mémoire sous forme d’instruction d’assembleur.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Affiche la mémoire sous forme d’octet.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Affiche l’objet référencé par le paramètre.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
<p>La plupart des API ou méthodes Objective-C d’Apple renvoient des objets ; il faut donc les afficher avec la commande « print object » (<code>po</code>). Si <code>po</code> ne produit pas de résultat pertinent, utilisez <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Écrire AAAA à cette adresse<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Écrire AAAA à cette adresse
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Désassembler la fonction actuelle</p>
<p><code>dis -n &lt;funcname&gt;</code> # Désassembler une fonction</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Désassembler une fonction<br>
<code>dis -c 6</code> # Désassembler six lignes<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Désassembler de la première adresse à la seconde<br>
<code>dis -p -c 4</code> # Commencer le désassemblage à l’adresse actuelle</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Examiner un tableau de trois éléments dans le registre <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Affiche une carte de la mémoire du processus actuel.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Obtenir l’adresse de chaque symbole de CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Lors de l’appel de la fonction **`objc_sendMsg`**, le registre **rsi** contient le **nom de la méthode** sous forme de chaîne terminée par un caractère nul (« C »). Pour afficher le nom avec lldb :
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Analyse anti-dynamique

#### Détection de VM

- La commande **`sysctl hw.model`** renvoie normalement un identifiant de modèle Mac sur une machine physique et peut renvoyer une valeur différente dans une VM.<sup>[[3]](#references)</sup>
- En modifiant les valeurs de **`hw.logicalcpu`** et **`hw.physicalcpu`**, certains malwares tentent de détecter si le système est une VM.<sup>[[4]](#references)</sup>
- Certains malwares peuvent aussi **détecter** si la machine est basée sur **VMware** à partir de son adresse MAC (00:50:56).
- Il est également possible de savoir **si un processus est en cours de débogage** avec un code simple comme :
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Il peut aussi invoquer l’appel système **`ptrace`** avec le flag **`PT_DENY_ATTACH`**. Consultez la [section PT_DENY_ATTACH](#page-title) pour comprendre son comportement XNU dépendant de l’ordre, les logs de `debugserver` et le processus de patching ARM64.<sup>[[7]](#references)[[12]](#references)</sup>

- Il peut aussi invoquer l’appel système **`ptrace`** avec le flag **`PT_DENY_ATTACH`**. Cela **empêche** un deb**u**gger de s’attacher au processus et de le tracer.
  - Vous pouvez vérifier si la fonction **`sysctl`** ou **`ptrace`** est **importée** (mais le malware peut l’importer dynamiquement).
  - Comme l’indique cet article, « [Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/) » :<sup>[[7]](#references)</sup>\
    « _Le message Process # exited with **status = 45 (0x0000002d)** indique généralement que la cible de débogage utilise **PT_DENY_ATTACH**_ »
#### Transfert du processus `fork()`

Un processus peut échapper à un debugger qui reste attaché au PID d’origine en appelant `fork()` au démarrage, en terminant le processus parent (`fork()` renvoie un PID enfant positif) et en poursuivant la logique protégée uniquement dans le processus enfant (`fork()` renvoie `0`). Résoudre `fork` avec `dlsym(RTLD_DEFAULT, "fork")` supprime également l’appel direct à `_fork`, mais cela ne constitue qu’un obstacle à l’analyse : la chaîne du nom du symbole et le flux de données de résolution dynamique restent visibles dans le binaire Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

Sur arm64, détectez ce motif en suivant le flux de données plutôt que des adresses fixes : les deux premiers arguments de `dlsym` sont passés dans `x0` et `x1`, `RTLD_DEFAULT` peut apparaître sous la forme `-2` (par exemple, `movn x0, #1`), et une paire `adrp`/`add` construit couramment l’adresse de la chaîne `"fork"`. Après le `bl` vers le stub de `dlsym`, suivez le pointeur renvoyé de `x0` à travers sa vérification de nullité et son stockage jusqu’à un `blr` indirect ultérieur. Suivez ensuite le résultat de `fork()` dans `w0` : zéro mène à la continuation du processus enfant, tandis que les valeurs positives et `-1` mènent au chemin du processus parent ou d’erreur.<sup>[[13]](#references)[[14]](#references)</sup>

Un bypass statique consiste à neutraliser l’appel indirect et à forcer la vérification du résultat existante à emprunter le chemin du processus enfant. Par exemple, si le compilateur a généré la séquence illustrée ci-dessous, patchez le `blr` et le stockage du résultat avec `nop`, fournissez un résultat synthétique égal à zéro, et conservez la logique de comparaison et de branchement. L’application continue alors sous le PID d’origine sans créer de processus enfant ; les registres d’instruction et les cibles de branchement doivent être adaptés à la version analysée.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Les core dumps sont créés si :

- le sysctl `kern.coredump` est défini sur 1 (valeur par défaut)
- le processus n'est pas suid/sgid ou si `kern.sugid_coredump` est défini sur 1 (valeur par défaut : 0)
- la limite `AS_CORE` autorise l'opération. Il est possible d'empêcher la création de core dumps en appelant `ulimit -c 0`, puis de la réactiver avec `ulimit -c unlimited`.

Dans ces cas, les core dumps sont générés selon le sysctl `kern.corefile` et enregistrés généralement dans `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyse les processus qui plantent et enregistre un rapport de plantage sur le disque**. Un rapport de plantage contient des informations qui peuvent **aider un développeur à diagnostiquer** la cause d'un plantage.\
Pour les applications et autres processus **exécutés dans le contexte launchd de l'utilisateur**, ReportCrash s'exécute comme un LaunchAgent et enregistre les rapports de plantage dans le répertoire `~/Library/Logs/DiagnosticReports/` de l'utilisateur.\
Pour les daemons, les autres processus **exécutés dans le contexte launchd du système** et les autres processus privilégiés, ReportCrash s'exécute comme un LaunchDaemon et enregistre les rapports de plantage dans `/Library/Logs/DiagnosticReports` du système.

Si vous craignez que les rapports de plantage **soient envoyés à Apple**, vous pouvez désactiver cette fonctionnalité. Sinon, les rapports de plantage peuvent être utiles pour **déterminer pourquoi un serveur a planté**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Mise en veille

Pendant le fuzzing sur macOS, empêchez le Mac de se mettre en veille :

- systemsetup -setsleep Never
- pmset, Préférences Système
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Déconnexion SSH

Si vous effectuez du fuzzing via une connexion SSH, il est important de veiller à ce que la session ne se termine pas. Modifiez donc le fichier sshd_config comme suit :

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Gestionnaires internes

**Consultez la page suivante** pour découvrir comment trouver quelle app est responsable de **la gestion du schéma ou du protocole spécifié :**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Énumération des processus réseau

C’est utile pour trouver les processus qui gèrent les données réseau :

```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```

Ou utilisez `netstat` ou `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```

### Fuzzing stateful de Mach IPC

Les services Mach exposés par des daemons privilégiés sont des cibles de fuzzing utiles lorsqu’un client non privilégié ou en sandbox peut obtenir un droit d’envoi. Partez de l’entrée `MachServices` de launchd du daemon et utilisez le [workflow d’analyse MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) pour associer les identifiants de message aux handlers. Avant de modifier les octets, placez un point d’arrêt sur la routine serveur MIG pendant qu’un client normal utilise le service, puis enregistrez des messages de requête valides comme entrées de départ. Préservez les champs d’en-tête requis, les tailles des messages et la disposition des descripteurs afin que les mutations atteignent le handler au lieu d’échouer immédiatement lors de la répartition.<sup>[[17]](#references)</sup>

De nombreux handlers dépendent d’appels antérieurs. Faites initialiser l’état du service par le harness, puis traitez chaque entrée de fuzzing comme une séquence d’**opérations et d’arguments** : envoyez des requêtes de configuration (par exemple, open ou create), conservez les identifiants renvoyés et réutilisez-les dans les requêtes suivantes. La rétroaction de couverture peut ainsi explorer les transitions d’état au lieu de retomber sans cesse sur une vérification d’objet non initialisé.<sup>[[17]](#references)</sup>

Pour une cible closed-source, un harness in-process qui appelle la routine de répartition MIG peut être instrumenté avec Jackalope/TinyInst. Le [harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) est une implémentation concrète, et non un harness prêt à l’emploi pour d’autres services.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Validez chaque crash par le véritable chemin IPC.** Un harness à répartition directe ignore la validation des messages Mach par le noyau et peut produire des faux positifs, en particulier s’il fournit une mémoire out-of-line (OOL) ou des descripteurs de port invalides. Allouez une mémoire de soutien OOL valide dans le harness, puis rejouez le testcase réduit via `mach_msg` depuis un client disposant des mêmes accès au service et vérifiez que le daemon plante toujours.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Fonctionne avec les outils CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Il « **fonctionne tout simplement** » avec de nombreux outils GUI macOS. Certaines applications ont des exigences supplémentaires, comme des noms de fichiers uniques, une extension particulière ou la lecture de fichiers depuis leur conteneur sandbox (`~/Library/Containers/com.apple.Safari/Data`).

Quelques exemples :

```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```

### Plus d’informations sur le fuzzing macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)



## References

- [1] [Réponse aux incidents sous OS X : scripting et analyse](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz : macOS - AppSec Village de DEF CON 29](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [L’art du malware macOS, volume I : analyse](https://taomm.org/)
- [4] [No Starch Press - L’art du malware macOS : guide d’analyse des logiciels malveillants](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - informations stockées dans ces sections de cet article de blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Déboguer les binaires Apple qui utilisent Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Contourner les techniques anti-débogage : variantes macOS de ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Forums des développeurs Apple - journaux structurés de Xcode et `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Afficher les données privées dans le journal unifié de macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Définitions des requêtes de `ptrace.h` de XNU d’Apple](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Implémentation de `ptrace` de XNU d’Apple dans `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - Internals de ptrace : comment il empêche l’attachement d’un débogueur](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - exemples de fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - Technique anti-débogage utilisant dlsym et fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - Autorisation d’outil de débogage](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Forums des développeurs Apple - Déboguer une application tierce renforcée](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Franchir le mur du son, partie I : fuzzing de CoreAudio avec des messages Mach](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - Harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - Fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
{{#include ../../../banners/hacktricks-training.md}}
