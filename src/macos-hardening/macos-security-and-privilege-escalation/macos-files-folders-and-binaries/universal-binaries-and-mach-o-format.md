# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Les binaires Mac OS sont généralement compilés comme des **universal binaries**. Un **universal binary** peut **prendre en charge plusieurs architectures dans le même fichier**.

Ces binaires suivent la **structure Mach-O** qui est essentiellement composée de :

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Cherchez le fichier avec : `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

<pre class="language-c"><code class="lang-c"><strong>#define FAT_MAGIC	0xcafebabe
</strong><strong>#define FAT_CIGAM	0xbebafeca	/* NXSwapLong(FAT_MAGIC) */
</strong>
struct fat_header {
<strong>	uint32_t	magic;		/* FAT_MAGIC or FAT_MAGIC_64 */
</strong><strong>	uint32_t	nfat_arch;	/* number of structs that follow */
</strong>};

struct fat_arch {
cpu_type_t	cputype;	/* cpu specifier (int) */
cpu_subtype_t	cpusubtype;	/* machine specifier (int) */
uint32_t	offset;		/* file offset to this object file */
uint32_t	size;		/* size of this object file */
uint32_t	align;		/* alignment as a power of 2 */
};
</code></pre>

L'en-tête contient les octets **magic** suivis du **nombre** d'**archs** que le fichier **contient** (`nfat_arch`) et chaque arch aura une structure `fat_arch`.

Vérifiez-le avec :

<pre class="language-shell-session"><code class="lang-shell-session">% file /bin/ls
/bin/ls: Mach-O universal binary with 2 architectures: [x86_64:Mach-O 64-bit executable x86_64] [arm64e:Mach-O 64-bit executable arm64e]
/bin/ls (for architecture x86_64):	Mach-O 64-bit executable x86_64
/bin/ls (for architecture arm64e):	Mach-O 64-bit executable arm64e

% otool -f -v /bin/ls
Fat headers
fat_magic FAT_MAGIC
<strong>nfat_arch 2
</strong><strong>architecture x86_64
</strong>    cputype CPU_TYPE_X86_64
cpusubtype CPU_SUBTYPE_X86_64_ALL
capabilities 0x0
<strong>    offset 16384
</strong><strong>    size 72896
</strong>    align 2^14 (16384)
<strong>architecture arm64e
</strong>    cputype CPU_TYPE_ARM64
cpusubtype CPU_SUBTYPE_ARM64E
capabilities PTR_AUTH_VERSION USERSPACE 0
<strong>    offset 98304
</strong><strong>    size 88816
</strong>    align 2^14 (16384)
</code></pre>

ou en utilisant l'outil [Mach-O View](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez le penser, en général un universal binary compilé pour 2 architectures **double la taille** de celui compilé pour une seule arch.

> [!TIP]
> Lors de l'analyse de malware ou d'apps suspectes, ne vous arrêtez pas après que `file` ait indiqué la "meilleure" architecture. Un universal binary peut cacher différents imports, load commands ou métadonnées du compilateur dans chaque slice, alors énumérez d'abord **tous** les slices puis inspectez-les indépendamment :
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Les SDK macOS récents exposent aussi des helpers comme `macho_for_each_slice()` et `macho_best_slice()` dans `<mach-o/utils.h>`. Ce dernier est pratique pour émuler ce que dyld/kernel chargerait, mais les scanners devraient quand même itérer sur chaque slice pour éviter de manquer du contenu spécifique à une arch.

## **Mach-O Header**

Le header contient des informations de base sur le fichier, comme les magic bytes pour l’identifier en tant que fichier Mach-O et des informations sur l’architecture cible. Vous pouvez le trouver dans : `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
```c
#define	MH_MAGIC	0xfeedface	/* the mach magic number */
#define MH_CIGAM	0xcefaedfe	/* NXSwapInt(MH_MAGIC) */
struct mach_header {
uint32_t	magic;		/* mach magic number identifier */
cpu_type_t	cputype;	/* cpu specifier (e.g. I386) */
cpu_subtype_t	cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file (usage and alignment for the file) */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
};

#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */
struct mach_header_64 {
uint32_t	magic;		/* mach magic number identifier */
int32_t		cputype;	/* cpu specifier */
int32_t		cpusubtype;	/* machine specifier */
uint32_t	filetype;	/* type of file */
uint32_t	ncmds;		/* number of load commands */
uint32_t	sizeofcmds;	/* the size of all the load commands */
uint32_t	flags;		/* flags */
uint32_t	reserved;	/* reserved */
};
```
### Types de fichiers Mach-O

Il existe différents types de fichiers, vous pouvez les trouver définis dans le [**code source par exemple ici**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Les plus importants sont :

- `MH_OBJECT`: Fichier objet relocatable (produits intermédiaires de compilation, pas encore exécutables).
- `MH_EXECUTE`: Fichiers exécutables.
- `MH_FVMLIB`: Fichier de bibliothèque VM fixe.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Fichier exécutable préchargé (plus supporté dans XNU)
- `MH_DYLIB`: Bibliothèques dynamiques
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Générés en utilisant -bundle dans gcc et chargés explicitement par `NSBundle` ou `dlopen`.
- `MH_DYSM`: Fichier compagnon `.dSym` (fichier avec les symboles pour le débogage).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou en utilisant [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Mach-O Flags**

Le code source définit également plusieurs flags utiles pour charger des bibliothèques :

- `MH_NOUNDEFS`: Aucune référence indéfinie (entièrement lié)
- `MH_DYLDLINK`: Liaison Dyld
- `MH_PREBOUND`: Références dynamiques pré-liées.
- `MH_SPLIT_SEGS`: Le fichier sépare les segments r/o et r/w.
- `MH_WEAK_DEFINES`: Le binaire a des symboles weak définis
- `MH_BINDS_TO_WEAK`: Le binaire utilise des symboles weak
- `MH_ALLOW_STACK_EXECUTION`: Rendre la stack exécutable
- `MH_NO_REEXPORTED_DYLIBS`: La bibliothèque n'a pas de commandes LC_REEXPORT
- `MH_PIE`: Executable indépendant de la position
- `MH_HAS_TLV_DESCRIPTORS`: Il existe une section avec des variables locales de thread
- `MH_NO_HEAP_EXECUTION`: Aucune exécution pour les pages heap/data
- `MH_HAS_OBJC`: Le binaire a des sections oBject-C
- `MH_SIM_SUPPORT`: Support du simulateur
- `MH_DYLIB_IN_CACHE`: Utilisé sur les dylibs/frameworks dans le cache de bibliothèques partagées.

## **Mach-O Load commands**

La **disposition du fichier en mémoire** est spécifiée ici, en détaillant l'**emplacement de la table des symboles**, le contexte du thread principal au démarrage de l'exécution, et les **bibliothèques partagées** requises. Des instructions sont fournies au chargeur dynamique **(dyld)** sur le processus de chargement du binaire en mémoire.

Le utilise la structure **load_command**, définie dans le **`loader.h`** mentionné :
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Il y a environ **50 types différents de load commands** que le système gère différemment. Les plus courants sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, et `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> En gros, ce type de Load Command définit **comment charger les segments \_\_TEXT** (code exécutable) **et \_\_DATA** (données pour le processus) **selon les offsets indiqués dans la section Data** lorsque le binaire est exécuté.

Ces commandes **définissent des segments** qui sont **mappés** dans l’**espace mémoire virtuel** d’un processus lorsqu’il est exécuté.

Il existe **différents types** de segments, comme le segment **\_\_TEXT**, qui contient le code exécutable d’un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments se trouvent dans la section data** du fichier Mach-O.

**Chaque segment** peut être ensuite **divisé** en plusieurs **sections**. La **structure du load command** contient des **informations** sur **ces sections** dans le segment respectif.

Dans l’en-tête, vous trouvez d’abord le **segment header** :

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* for 64-bit architectures */
uint32_t	cmd;		/* LC_SEGMENT_64 */
uint32_t	cmdsize;	/* includes sizeof section_64 structs */
char		segname[16];	/* segment name */
uint64_t	vmaddr;		/* memory address of this segment */
uint64_t	vmsize;		/* memory size of this segment */
uint64_t	fileoff;	/* file offset of this segment */
uint64_t	filesize;	/* amount to map from the file */
int32_t		maxprot;	/* maximum VM protection */
int32_t		initprot;	/* initial VM protection */
<strong>	uint32_t	nsects;		/* number of sections in segment */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Exemple de segment header :

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Cet en-tête définit le **nombre de sections dont les en-têtes apparaissent après** lui :
```c
struct section_64 { /* for 64-bit architectures */
char		sectname[16];	/* name of this section */
char		segname[16];	/* segment this section goes in */
uint64_t	addr;		/* memory address of this section */
uint64_t	size;		/* size in bytes of this section */
uint32_t	offset;		/* file offset of this section */
uint32_t	align;		/* section alignment (power of 2) */
uint32_t	reloff;		/* file offset of relocation entries */
uint32_t	nreloc;		/* number of relocation entries */
uint32_t	flags;		/* flags (section type and attributes)*/
uint32_t	reserved1;	/* reserved (for offset or index) */
uint32_t	reserved2;	/* reserved (for count or sizeof) */
uint32_t	reserved3;	/* reserved */
};
```
Exemple d’**en-tête de section** :

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Si vous **ajoutez** le **décalage de section** (0x37DC) + le **décalage** où **commence l’arch**, dans ce cas `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Il est aussi possible d’obtenir des **informations d’en-tête** depuis la **ligne de commande** avec :
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Il indique au kernel de **mapper** **l’adresse zéro** afin qu’elle **ne puisse pas être lue, écrite ou exécutée**. Les variables maxprot et minprot dans la structure sont définies à zéro pour indiquer qu’il n’y a **aucun droit read-write-execute sur cette page**.
- Cette allocation est importante pour **mitigate NULL pointer dereference vulnerabilities**. En effet, XNU impose une page zero dure qui garantit que la première page (seulement la première) de mémoire est inaccesible (sauf en i386). Un binaire pourrait satisfaire ces exigences en créant un petit \_\_PAGEZERO (en utilisant `-pagezero_size`) pour couvrir les premiers 4k et en rendant le reste de la mémoire 32bit accessible à la fois en user et kernel mode.
- **`__TEXT`**: Contient du **code exécutable** avec des permissions **read** et **execute** (pas writable)**.** Sections courantes de ce segment :
- `__text`: Code binaire compilé
- `__const`: Données constantes (read only)
- `__[c/u/os_log]string`: Constantes de chaînes C, Unicode ou os logs
- `__stubs` and `__stubs_helper`: Interviennent pendant le processus de chargement des bibliothèques dynamiques
- `__unwind_info`: Données de désassemblage de pile.
- Note that all this content is signed but also marked as executable (creating more options for exploitation of sections that doesn't necessarily need this privilege, like string dedicated sections).
- **`__DATA`**: Contient des données **readable** et **writable** (pas executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Non lazy (bind at load) symbol pointer
- `__la_symbol_ptr`: Lazy (bind on use) symbol pointer
- `__const`: Should be read-only data (not really)
- `__cfstring`: Chaînes CoreFoundation
- `__data`: Variables globales (qui ont été initialisées)
- `__bss`: Variables statiques (qui n'ont pas été initialisées)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informations utilisées par l’Objective-C runtime
- **`__DATA_CONST`**: \_\_DATA.\_\_const n’est pas garanti d’être constant (write permissions), pas plus que les autres pointeurs et la GOT. Cette section rend `__const`, certains initializers et la table GOT (une fois résolue) **read only** en utilisant `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Courant dans les binaires Apple Silicon récents. Ces segments contiennent des pointeurs qui doivent être authentifiés au chargement ou au moment de l’utilisation (par exemple `__auth_got`). Si une technique de rebinding, hook ou import-patching ne vérifie que les sections héritées `__got` / `__la_symbol_ptr`, elle peut manquer les vrais call sites dans les binaires `arm64e` modernes. Pour plus de détails sur ces sections, consultez [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contient les informations pour le linker (dyld) comme les entrées de table des symboles, de chaînes et de relocations. C'est un conteneur générique pour les contenus qui ne sont ni dans `__TEXT` ni dans `__DATA`, et son contenu est décrit dans d’autres load commands.
- dyld information: Rebase, Non-lazy/lazy/weak binding opcodes and export info
- Functions starts: Table of start addresses of functions
- Data In Code: Data islands in \_\_text
- SYmbol Table: Symbols in binary
- Indirect Symbol Table: Pointer/stub symbols
- String Table
- Code Signature
- **`__OBJC`**: Contient des informations utilisées par l’Objective-C runtime. Bien que ces informations puissent aussi se trouver dans le segment \_\_DATA, dans diverses sections \_\_objc\_\*.
- **`__RESTRICT`**: Un segment sans contenu avec une seule section appelée **`__restrict`** (elle aussi vide) qui garantit que lors de l’exécution du binaire, les variables d’environnement DYLD seront ignorées.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contient l’entrypoint dans l’attribut **entryoff**. Au moment du chargement, **dyld** **ajoute** simplement cette valeur à la **base du binaire** (en mémoire), puis **saute** à cette instruction pour démarrer l’exécution du code du binaire.

**`LC_UNIXTHREAD`** contient les valeurs que les registres doivent avoir au démarrage du thread principal. C’est déjà obsolète mais **`dyld`** l’utilise encore. Il est possible de voir les valeurs des registres définies par cela avec :
```bash
otool -l /usr/lib/dyld
[...]
Load command 13
cmd LC_UNIXTHREAD
cmdsize 288
flavor ARM_THREAD_STATE64
count ARM_THREAD_STATE64_COUNT
x0  0x0000000000000000 x1  0x0000000000000000 x2  0x0000000000000000
x3  0x0000000000000000 x4  0x0000000000000000 x5  0x0000000000000000
x6  0x0000000000000000 x7  0x0000000000000000 x8  0x0000000000000000
x9  0x0000000000000000 x10 0x0000000000000000 x11 0x0000000000000000
x12 0x0000000000000000 x13 0x0000000000000000 x14 0x0000000000000000
x15 0x0000000000000000 x16 0x0000000000000000 x17 0x0000000000000000
x18 0x0000000000000000 x19 0x0000000000000000 x20 0x0000000000000000
x21 0x0000000000000000 x22 0x0000000000000000 x23 0x0000000000000000
x24 0x0000000000000000 x25 0x0000000000000000 x26 0x0000000000000000
x27 0x0000000000000000 x28 0x0000000000000000  fp 0x0000000000000000
lr 0x0000000000000000 sp  0x0000000000000000  pc 0x0000000000004b70
cpsr 0x00000000

[...]
```
### **`LC_CODE_SIGNATURE`**

{{#ref}}
../../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/mach-o-entitlements-and-ipsw-indexing.md
{{#endref}}


Contient des informations sur la **signature de code du fichier Macho-O**. Il ne contient qu'un **offset** qui **pointe** vers le **signature blob**. Celui-ci se trouve généralement tout à la fin du fichier.\
Cependant, vous pouvez trouver quelques informations sur cette section dans [**ce billet de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et dans [**ces gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Prise en charge du chiffrement des binaires. Cependant, bien sûr, si un attaquant parvient à compromettre le processus, il pourra dumper la mémoire en clair.

### **`LC_LOAD_DYLINKER`**

Contient le **chemin vers l'exécutable du dynamic linker** qui mappe les bibliothèques partagées dans l'espace d'adressage du processus. La **valeur est toujours définie sur `/usr/lib/dyld`**. Il est important de noter que, sous macOS, le mapping des dylib se fait en **user mode**, et non en kernel mode.

### **`LC_IDENT`**

Obsolète, mais lorsqu'il est configuré pour générer des dumps sur panic, un dump core Mach-O est créé et la version du kernel est définie dans la commande `LC_IDENT`.

### **`LC_UUID`**

UUID aléatoire. Ce n'est pas directement utile pour grand-chose, mais XNU le met en cache avec le reste des infos du processus. Il peut être utilisé dans les crash reports.

### **`LC_BUILD_VERSION`**

Les binaires modernes incluent généralement cette commande pour déclarer la **target platform**, la **minimum OS version**, la **SDK version**, et éventuellement les **tool versions** utilisées pour construire cette slice. D'un point de vue offensif/reversing, c'est très utile pour fingerprint la manière dont un échantillon a été compilé et pour repérer rapidement des universal binaries bizarres où une slice a été compilée avec un SDK ou un deployment target différent. Les binaires plus anciens peuvent encore utiliser `LC_VERSION_MIN_*` à la place.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permet d’indiquer des variables d’environnement à dyld avant que le processus ne soit exécuté. Cela peut être très dangereux, car cela peut permettre d’exécuter du code arbitraire à l’intérieur du processus, donc ce load command n’est utilisé que dans les builds de dyld avec `#define SUPPORT_LC_DYLD_ENVIRONMENT` et restreint davantage le traitement uniquement aux variables de la forme `DYLD_..._PATH` spécifiant des chemins de chargement.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Les toolchains récentes stockent fréquemment les métadonnées export/bind/rebase dans ces commandes au lieu de s’appuyer uniquement sur les anciens opcodes `LC_DYLD_INFO[_ONLY]`. Les deux sont des entrées `linkedit_data_command` qui pointent vers **`__LINKEDIT`** :

- **`LC_DYLD_EXPORTS_TRIE`** : Trie compact avec les symboles exportés par l’image.
- **`LC_DYLD_CHAINED_FIXUPS`** : Chaînes de fixup par segment utilisées par dyld pour appliquer les rebases et les binds. Sur Apple Silicon, c’est aussi là que vous rencontrerez de nombreux fixups modernes de pointeurs authentifiés.

Ces métadonnées sont très utiles pour reconstruire les imports/exports, comprendre pourquoi une dépendance chargée via `@rpath` s’est résolue de cette façon, ou déterminer pourquoi une tentative de hook/rebinding a échoué sur une cible moderne `arm64e`. `dyld_info` peut aussi être utilisé sur des chemins de dylib **cache-only** qui n’existent pas comme fichiers autonomes sur le disque, ce qui est très utile sur les versions modernes de macOS où beaucoup de bibliothèques système résident uniquement dans le shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Cette commande de chargement moderne est surtout pertinente lors de l’inspection de **kernel collections / kernelcache-style filesets**. Au lieu de représenter une seule image autonome, le Mach-O externe agit comme un conteneur et chaque `LC_FILESET_ENTRY` pointe vers un Mach-O intégré avec son propre **entry id** de type chemin, son adresse VM et son offset dans le fichier. Si vous faites du reverse sur des composants kernel macOS/iOS modernes, cette commande est souvent le pont entre le conteneur de niveau supérieur et l’image réelle que vous voulez extraire ou désassembler.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Pour des workflows d’extraction pratiques, consultez [cette autre page sur les extensions de noyau macOS et kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Cette commande de chargement décrit une dépendance de **bibliothèque** **dynamique** qui **informe** le **loader** (dyld) de **charger et lier cette bibliothèque**. Il existe une commande de chargement `LC_LOAD_DYLIB` **pour chaque bibliothèque** dont le binaire Mach-O a besoin.

- Cette commande de chargement est une structure de type **`dylib_command`** (qui contient un struct dylib, décrivant la bibliothèque dynamique dépendante réelle) :
```objectivec
struct dylib_command {
uint32_t        cmd;            /* LC_LOAD_{,WEAK_}DYLIB */
uint32_t        cmdsize;        /* includes pathname string */
struct dylib    dylib;          /* the library identification */
};

struct dylib {
union lc_str  name;                 /* library's path name */
uint32_t timestamp;                 /* library's build time stamp */
uint32_t current_version;           /* library's current version number */
uint32_t compatibility_version;     /* library's compatibility vers number*/
};
```
![LC DYLD ENVIRONMENT - LC LOAD DYLIB: uint32 t compatibility version; / library's compatibility vers number /](<../../../images/image (486).png>)

Vous pouvez aussi obtenir ces informations depuis le cli avec :
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Some potential malware related libraries are:

- **DiskArbitration**: Monitoring USB drives
- **AVFoundation:** Capture audio and video
- **CoreWLAN**: Wifi scans.

> [!TIP]
> A Mach-O binary can contain one or **more** **constructors**, that will be **executed** **before** the address specified in **LC_MAIN**.\
> The offsets of any constructors are held in the **\_\_mod_init_func** section of the **\_\_DATA_CONST** segment.

## **Mach-O Data**

At the core of the file lies the data region, which is composed of several segments as defined in the load-commands region. **A variety of data sections can be housed within each segment**, with each section **holding code or data** specific to a type.

> [!TIP]
> The data is basically the part containing all the **information** that is loaded by the load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

This includes:

- **Function table:** Which holds information about the program functions.
- **Symbol table**: Which contains information about the external function used by the binary
- It could also contain internal function, variable names as well and more.

To check it you could use the [**Mach-O View**](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Or from the cli:
```bash
size -m /bin/ls
```
## Sections courantes Objective-C

Dans le segment `__TEXT` (r-x) :

- `__objc_classname`: Noms de classes (strings)
- `__objc_methname`: Noms de méthodes (strings)
- `__objc_methtype`: Types de méthodes (strings)

Dans le segment `__DATA` (rw-) :

- `__objc_classlist`: Pointeurs vers toutes les classes Objetive-C
- `__objc_nlclslist`: Pointeurs vers les classes Objective-C Non-Lazy
- `__objc_catlist`: Pointeur vers les Categories
- `__objc_nlcatlist`: Pointeur vers les Non-Lazy Categories
- `__objc_protolist`: Liste des Protocols
- `__objc_const`: Données constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
