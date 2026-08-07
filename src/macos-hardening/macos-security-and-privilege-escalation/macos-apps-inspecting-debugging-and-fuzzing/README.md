# macOS Apps - Inspection, debugging and Fuzzing

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
### Disarm (old jtool2)

Vous pouvez [**télécharger disarm ici**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Notez que **`disarm`** peut également fonctionner avec des fichiers IM4P compressés (comme `kernelcache`) et extraire uniquement les parties requises, voire analyser la partie requise sans l'extraire.
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
> **`Codesign`** se trouve dans **macOS**, tandis que **`ldid`** se trouve dans **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) est un outil utile pour inspecter les fichiers **.pkg** (programmes d'installation) et voir ce qu'ils contiennent avant de les installer.\
Ces programmes d'installation contiennent des scripts bash `preinstall` et `postinstall` que les auteurs de malware détournent généralement pour **persister** **le** **malware**.

### hdiutil

Cet outil permet de **monter** des fichiers d'image disque Apple (**.dmg**) afin de les inspecter avant d'exécuter quoi que ce soit :
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Il sera monté dans `/Volumes`

### Binaires packés

- Vérifier la haute entropie
- Vérifier les chaînes de caractères (s'il n'y a presque aucune chaîne compréhensible, le binaire est packé)
- Le packer UPX pour MacOS génère une section appelée "\_\_XHDR"

## Analyse statique Objective-C

### Métadonnées

> [!CAUTION]
> Notez que les programmes écrits en Objective-C **conservent** leurs déclarations de classes **lorsqu'ils sont** **compilés** en [binaires Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Ces déclarations de classes **incluent** le nom et le type des éléments suivants :

- Les interfaces définies
- Les méthodes des interfaces
- Les variables d'instance des interfaces
- Les protocoles définis

Notez que ces noms peuvent être obfusqués afin de rendre le reversing du binaire plus difficile.

### Appel de fonctions

Lorsqu'une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé, au lieu d'appeler cette fonction, appelle **`objc_msgSend`**, qui appellera la fonction finale :

![Métadonnées - Appel de fonctions : Lorsqu'une fonction est appelée dans un binaire qui utilise Objective-C, le code compilé, au lieu d'appeler cette fonction, appelle objc msgSend. Ce qui appellera...](<../../../images/image (305).png>)

Les paramètres attendus par cette fonction sont :

- Le premier paramètre (**self**) est « un pointeur qui pointe vers **l'instance de la classe destinée à recevoir le message** ». Plus simplement, il s'agit de l'objet sur lequel la méthode est invoquée. Si la méthode est une méthode de classe, il s'agit d'une instance de l'objet classe (dans son ensemble), tandis que pour une méthode d'instance, self pointe vers une instance instanciée de la classe en tant qu'objet.
- Le deuxième paramètre, (**op**), est « le selector de la méthode qui gère le message ». Plus simplement, il s'agit du **nom de la méthode.**
- Les paramètres restants sont les **valeurs requises par la méthode** (op).

Voir comment **obtenir facilement ces informations avec `lldb` sur ARM64** sur cette page :


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64 :

| **Argument**      | **Registre**                                                    | **(pour) objc_msgSend**                                 |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argument**  | **rdi**                                                         | **self : objet sur lequel la méthode est invoquée** |
| **2e argument**  | **rsi**                                                         | **op : nom de la méthode**                             |
| **3e argument**  | **rdx**                                                         | **1er argument de la méthode**                         |
| **4e argument**  | **rcx**                                                         | **2e argument de la méthode**                         |
| **5e argument**  | **r8**                                                          | **3e argument de la méthode**                         |
| **6e argument**  | **r9**                                                          | **4e argument de la méthode**                         |
| **7e+ argument** | <p><strong>rsp+</strong><br><strong>(sur la pile)</strong></p> | **5e+ argument de la méthode**                        |

### Dump des métadonnées ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) est un outil permettant d'effectuer un class-dump sur des binaires Objective-C. Le github indique des dylibs, mais cela fonctionne également avec les exécutables.
```bash
./dynadump dump /path/to/bin
```
Au moment de la rédaction, c’est **actuellement celle qui fonctionne le mieux**.

#### Outils standard
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) est l'outil original permettant de générer les déclarations des classes, catégories et protocoles dans du code Objective-C formaté.

Il est ancien et n'est plus maintenu, il est donc probable qu'il ne fonctionne pas correctement.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) est un class dump Objective-C moderne et multiplateforme. Comparé aux outils existants, iCDump peut fonctionner indépendamment de l'écosystème Apple et expose des bindings Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Analyse statique de Swift

Avec les binaires Swift, en raison de la compatibilité avec Objective-C, il est parfois possible d'extraire les déclarations à l'aide de [class-dump](https://github.com/nygard/class-dump/), mais pas toujours.

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
Vous pouvez trouver davantage d'informations sur les [**informations stockées dans ces sections dans cet article de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

De plus, les **binaires Swift peuvent contenir des symboles** (par exemple, les bibliothèques doivent stocker des symboles afin que leurs fonctions puissent être appelées). Les **symboles contiennent généralement le nom de la fonction** et ses attributs d'une manière peu lisible ; ils sont donc très utiles, et il existe des "**demanglers"** capables de retrouver le nom d'origine :
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Analyse dynamique

> [!WARNING]
> Notez que pour déboguer des binaires, **SIP doit être désactivé** (`csrutil disable` ou `csrutil enable --without debug`), ou qu'il faut copier les binaires dans un dossier temporaire et **supprimer la signature** avec `codesign --remove-signature <binary-path>`, ou autoriser le débogage du binaire (vous pouvez utiliser [ce script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Notez que pour **instrumenter les binaires système**, (comme `cloudconfigurationd`) sur macOS, **SIP doit être désactivé** (la simple suppression de la signature ne fonctionnera pas).

### APIs

macOS expose certaines APIs intéressantes qui fournissent des informations sur les processus :

- `proc_info` : Il s'agit de la principale API, qui fournit beaucoup d'informations sur chaque processus. Vous devez être root pour obtenir les informations des autres processus, mais vous n'avez pas besoin d'entitlements spéciaux ni de ports mach.
- `libsysmon.dylib` : Elle permet d'obtenir des informations sur les processus via des fonctions exposées par XPC. Cependant, l'entitlement `com.apple.sysmond.client` est requis.

### Stackshot et microstackshots

Le **Stackshotting** est une technique utilisée pour capturer l'état des processus, notamment les call stacks de tous les threads en cours d'exécution. Cela est particulièrement utile pour le débogage, l'analyse des performances et la compréhension du comportement du système à un moment donné. Sur iOS et macOS, le stackshotting peut être effectué à l'aide de plusieurs outils et méthodes, tels que les outils **`sample`** et **`spindump`**.

### Sysdiagnose

Cet outil (`/usr/bini/ysdiagnose`) collecte essentiellement beaucoup d'informations sur votre ordinateur en exécutant des dizaines de commandes différentes, telles que `ps`, `zprint`...

Il doit être exécuté en tant que **root**, et le daemon `/usr/libexec/sysdiagnosed` possède des entitlements très intéressants, tels que `com.apple.system-task-ports` et `get-task-allow`.

Son plist se trouve dans `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, qui déclare 3 MachServices :

- `com.apple.sysdiagnose.CacheDelete` : Supprime les anciennes archives dans /var/rmp
- `com.apple.sysdiagnose.kernel.ipc` : Port spécial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc` : Interface en mode utilisateur via la classe Obj-C `Libsysdiagnose`. Trois arguments dans un dict peuvent être transmis (`compress`, `display`, `run`)

### Unified Logs

MacOS génère beaucoup de logs qui peuvent être très utiles lors de l'exécution d'une application, afin de comprendre **ce qu'elle fait**.

De plus, certains logs contiennent le tag `<private>` pour **masquer** certaines informations **permettant d'identifier l'utilisateur** ou **l'ordinateur**. Cependant, il est possible **d'installer un certificat pour divulguer ces informations**. Suivez les explications [ici](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panneau de gauche

Dans le panneau de gauche de Hopper, il est possible de voir les symboles (**Labels**) du binaire, la liste des procédures et fonctions (**Proc**), ainsi que les chaînes (**Str**). Il ne s'agit pas de toutes les chaînes, mais de celles définies dans plusieurs parties du fichier Mac-O (comme _cstring ou_ `objc_methname`).

#### Panneau central

Dans le panneau central, vous pouvez voir le **code désassemblé**. Vous pouvez l'afficher sous forme de désassemblage **raw**, de **graph**, de code **décompilé** ou de code **binaire**, en cliquant sur l'icône correspondante :

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

En cliquant avec le bouton droit sur un objet de code, vous pouvez voir les **références vers/de cet objet** ou même modifier son nom (cela ne fonctionne pas dans le pseudocode décompilé) :

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

De plus, dans la **partie inférieure du panneau central, vous pouvez écrire des commandes Python**.

#### Panneau de droite

Dans le panneau de droite, vous pouvez voir des informations intéressantes, telles que l'**historique de navigation** (afin de savoir comment vous êtes arrivé à la situation actuelle), le **graphe d'appels**h, où vous pouvez voir toutes les **fonctions qui appellent cette fonction** ainsi que toutes les fonctions **appelées par cette fonction**, et les informations sur les **variables locales**.

### dtrace

Il permet aux utilisateurs d'accéder aux applications à un niveau **très bas** et fournit un moyen de **tracer** les **programmes**, voire de modifier leur flux d'exécution. Dtrace utilise des **probes** qui sont **placées dans tout le kernel**, à des emplacements tels que le début et la fin des appels système.

DTrace utilise la fonction **`dtrace_probe_create`** pour créer une probe pour chaque appel système. Ces probes peuvent être déclenchées au **point d'entrée et de sortie de chaque appel système**. L'interaction avec DTrace se fait via /dev/dtrace, qui est uniquement disponible pour l'utilisateur root.<sup>[[1]](#references)</sup>

> [!TIP]
> Pour activer Dtrace sans désactiver complètement la protection SIP, vous pouvez exécuter la commande suivante en mode recovery : `csrutil enable --without dtrace`
>
> Vous pouvez également utiliser **`dtrace`** ou les binaires **`dtruss`** que **vous avez compilés**.

Les probes disponibles de dtrace peuvent être obtenues avec :
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
Le nom du probe se compose de quatre parties : le provider, le module, la fonction et le nom (`fbt:mach_kernel:ptrace:entry`). Si vous ne spécifiez pas une partie du nom, DTrace l'appliquera comme un wildcard.

Pour configurer DTrace afin d'activer les probes et de spécifier les actions à effectuer lorsqu'ils se déclenchent, nous devons utiliser le langage D.

Une explication plus détaillée et davantage d'exemples sont disponibles dans [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Exemples

Exécutez `man -k dtrace` pour répertorier les **scripts DTrace disponibles**. Exemple : `sudo dtruss -n binary`

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

C'est une fonctionnalité de traçage du kernel. Les codes documentés se trouvent dans **`/usr/share/misc/trace.codes`**.

Des outils comme `latency`, `sc_usage`, `fs_usage` et `trace` l'utilisent en interne.

Pour utiliser `kdebug`, `sysctl` est utilisé via l'espace de noms `kern.kdebug`, et les MIB à utiliser se trouvent dans `sys/sysctl.h`, les fonctions étant implémentées dans `bsd/kern/kdebug.c`.

Pour interagir avec kdebug à l'aide d'un client personnalisé, les étapes sont généralement les suivantes :

- Supprimer les paramètres existants avec KERN_KDSETREMOVE
- Configurer le traçage avec KERN_KDSETBUF et KERN_KDSETUP
- Utiliser KERN_KDGETBUF pour obtenir le nombre d'entrées du buffer
- Exclure son propre client du traçage avec KERN_KDPINDEX
- Activer le traçage avec KERN_KDENABLE
- Lire le buffer en appelant KERN_KDREADTR
- Associer chaque thread à son processus avec KERN_KDTHRMAP.

Pour obtenir ces informations, il est possible d'utiliser l'outil Apple **`trace`** ou l'outil personnalisé [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Notez que Kdebug n'est disponible que pour 1 client à la fois.** Ainsi, un seul outil utilisant k-debug peut être exécuté simultanément.

### ktrace

Les APIs `ktrace_*` proviennent de `libktrace.dylib`, qui encapsule celles de `Kdebug`. Un client peut donc simplement appeler `ktrace_session_create` et `ktrace_events_[single/class]` pour définir des callbacks sur des codes spécifiques, puis démarrer le traçage avec `ktrace_start`.

Vous pouvez également l'utiliser avec **SIP activé**

Vous pouvez utiliser l'utilitaire `ktrace` comme client :
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
Ou `tailspin`.

### kperf

Cet outil sert à effectuer un profiling au niveau du kernel et est construit à l'aide de callouts `Kdebug`.

En bref, la variable globale `kernel_debug_active` est vérifiée et, si elle est définie, elle appelle `kperf_kdebug_handler` avec le code `Kdebug` et l'adresse de la frame du kernel appelante. Si le code `Kdebug` correspond à l'un de ceux sélectionnés, il récupère les « actions » configurées sous forme de bitmap (consultez `osfmk/kperf/action.h` pour connaître les options).

Kperf possède également une table MIB sysctl : (en tant que root) `sysctl kperf`. Ce code se trouve dans `osfmk/kperf/kperfbsd.c`.

De plus, un sous-ensemble des fonctionnalités de Kperf réside dans `kpc`, qui fournit des informations sur les compteurs de performance de la machine.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) est un outil très utile pour vérifier les actions liées aux processus qu'un processus effectue (par exemple, surveiller les nouveaux processus qu'un processus crée).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) est un outil qui affiche les relations entre les processus.\
Vous devez monitorer votre Mac avec une commande telle que **`sudo eslogger fork exec rename create > cap.json`** (le terminal qui exécute cette commande nécessite la FDA). Vous pouvez ensuite charger le json dans cet outil afin d'afficher toutes les relations :

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permet de monitorer les événements liés aux fichiers (comme leur création, leur modification et leur suppression) en fournissant des informations détaillées sur ces événements.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) est un outil GUI dont l'apparence et le fonctionnement peuvent rappeler aux utilisateurs de Windows le _Procmon_ de Microsoft Sysinternal. Cet outil permet de démarrer et d'arrêter l'enregistrement de différents types d'événements, de filtrer ces événements par catégories telles que fichier, processus, réseau, etc., et de sauvegarder les événements enregistrés au format json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) fait partie des outils Developer de Xcode : il est utilisé pour monitorer les performances des applications, identifier les memory leaks et suivre l'activité du filesystem.

![Crescendo - Apple Instruments : Apple Instruments fait partie des outils Developer de Xcode : il est utilisé pour monitorer les performances des applications, identifier les memory leaks et suivre l'activité du filesystem](<../../../images/image (1138).png>)

### fs_usage

Permet de suivre les actions effectuées par les processus :
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) est utile pour voir les **bibliothèques** utilisées par un binaire, les **fichiers** qu'il utilise et les **connexions** réseau.\
Il vérifie également les processus binaires avec **virustotal** et affiche des informations sur le binaire.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

Dans [**cet article de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html), vous trouverez un exemple expliquant comment **déboguer un daemon en cours d'exécution** qui utilisait **`PT_DENY_ATTACH`** pour empêcher le débogage, même si SIP était désactivé.<sup>[[6]](#references)</sup>

### lldb

**lldb** est l'outil de facto pour le **débogage** des binaires **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Vous pouvez définir le format Intel lors de l'utilisation de lldb en créant un fichier appelé **`.lldbinit`** dans votre dossier personnel avec la ligne suivante :
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Dans lldb, sauvegardez un processus avec `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Commande</strong></td><td><strong>Description</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Démarre l’exécution, qui continue sans interruption jusqu’à ce qu’un breakpoint soit atteint ou que le processus se termine.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Démarre l’exécution en s’arrêtant au point d’entrée</td></tr><tr><td><strong>continue (c)</strong></td><td>Continue l’exécution du processus débogué.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Exécute l’instruction suivante. Cette commande ignore les appels de fonction.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Exécute l’instruction suivante. Contrairement à la commande nexti, cette commande entre dans les appels de fonction.</td></tr><tr><td><strong>finish (f)</strong></td><td>Exécute le reste des instructions de la fonction actuelle (« frame »), revient et s’arrête.</td></tr><tr><td><strong>control + c</strong></td><td>Met l’exécution en pause. Si le processus a été lancé (r) ou poursuivi (c), le processus s’arrête ...où qu’il soit en train de s’exécuter.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Affiche la mémoire sous forme de chaîne terminée par un caractère nul.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Affiche la mémoire sous forme d’instruction d’assembly.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Affiche la mémoire sous forme d’octet.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Affiche l’objet référencé par le paramètre</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Notez que la plupart des API ou méthodes Objective-C d’Apple renvoient des objets et doivent donc être affichées avec la commande « print object » (po). Si po ne produit pas de sortie significative, utilisez <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Affiche la carte de la mémoire du processus actuel</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Lors de l’appel de la fonction **`objc_sendMsg`**, le registre **rsi** contient le **nom de la méthode** sous forme de chaîne terminée par un caractère nul (« C »). Pour afficher le nom via lldb, exécutez :
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Analyse anti-dynamique

#### Détection de VM

- La commande **`sysctl hw.model`** renvoie « Mac » lorsque **l’hôte est un MacOS**, mais une valeur différente lorsqu’il s’agit d’une VM.<sup>[[3]](#references)</sup>
- En manipulant les valeurs de **`hw.logicalcpu`** et **`hw.physicalcpu`**, certains malwares tentent de détecter s’il s’agit d’une VM.<sup>[[4]](#references)</sup>
- Certains malwares peuvent également **détecter** si la machine est basée sur **VMware** à partir de l’adresse MAC (00:50:56).
- Il est également possible de déterminer **si un processus est débogué** avec un code simple tel que :
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- Il peut également appeler l’appel système **`ptrace`** avec le flag **`PT_DENY_ATTACH`**. Cela **empêche** un débogueur de s’attacher au processus et de le tracer.
- Vous pouvez vérifier si la fonction **`sysctl`** ou **`ptrace`** est **importée** (mais le malware peut l’importer dynamiquement)
- Comme indiqué dans cet article, « [Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/) » :<sup>[[7]](#references)</sup>\
« _Le message Process # exited with **status = 45 (0x0000002d)** indique généralement que la cible de débogage utilise **PT_DENY_ATTACH**_ »

## Dumps mémoire

Les dumps mémoire sont créés si :

- Le sysctl `kern.coredump` est défini sur 1 (par défaut)
- Si le processus n’était pas suid/sgid ou si `kern.sugid_coredump` vaut 1 (sa valeur par défaut est 0)
- La limite `AS_CORE` autorise l’opération. Il est possible d’empêcher la création de dumps mémoire en appelant `ulimit -c 0`, puis de les réactiver avec `ulimit -c unlimited`.

Dans ces cas, le dump mémoire est généré conformément au sysctl `kern.corefile` et stocké généralement dans `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analyse les processus qui crashent et enregistre un rapport de crash sur le disque**. Un rapport de crash contient des informations pouvant **aider un développeur à diagnostiquer** la cause d’un crash.\
Pour les applications et autres processus **exécutés dans le contexte launchd de l’utilisateur**, ReportCrash s’exécute comme LaunchAgent et enregistre les rapports de crash dans `~/Library/Logs/DiagnosticReports/` de l’utilisateur.\
Pour les daemons, les autres processus **exécutés dans le contexte launchd du système** et les autres processus privilégiés, ReportCrash s’exécute comme LaunchDaemon et enregistre les rapports de crash dans `/Library/Logs/DiagnosticReports` du système.

Si vous craignez que les rapports de crash **soient envoyés à Apple**, vous pouvez les désactiver. Dans le cas contraire, les rapports de crash peuvent être utiles pour **déterminer comment un serveur a crashé**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Veille

Lors du fuzzing sur un MacOS, il est important d'empêcher le Mac de se mettre en veille :

- systemsetup -setsleep Never
- pmset, Préférences Système
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Déconnexion SSH

Si vous effectuez du fuzzing via une connexion SSH, il est important de vous assurer que la session ne va pas se déconnecter. Modifiez donc le fichier sshd_config avec :

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Handlers internes

**Consultez la page suivante** pour découvrir comment trouver quelle app est responsable de la **gestion du schéma ou protocole spécifié :**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Énumération des processus réseau

Cela est intéressant pour trouver les processus qui gèrent les données réseau :
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
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Fonctionne avec les outils CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Cela "**fonctionne tout simplement"** avec les outils GUI macOS. Notez que certaines apps macOS ont des exigences spécifiques, comme des noms de fichiers uniques, la bonne extension, ou la nécessité de lire les fichiers depuis le sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Informations supplémentaires sur le Fuzzing de macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Références

- [1] [Réponse aux incidents sous OS X : scripting et analyse](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz : macOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [L'art des malwares Mac, volume I : analyse](https://taomm.org/vol1/analysis.html)
- [4] [L'art des malwares Mac : guide d'analyse des logiciels malveillants](https://taomm.org/)
- [5] [knight.sc - informations stockées dans cette section de cet article de blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging des binaires Apple utilisant Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Contourner les techniques Anti-Debug : variantes de ptrace sous macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
