# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Mac OS binaries usually are compiled as **universal binaries**. A **universal binary** can **support multiple architectures in the same file**.

These binaries follows the **Mach-O structure** which is basically compased of:

- En-tête
- Load Commands
- Données

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

L'en-tête contient les octets **magic** suivis du **nombre** d'**archs** que le fichier **contient** (`nfat_arch`) et chaque arch aura une `fat_arch` struct.

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

or using the [Mach-O View](https://sourceforge.net/projects/machoview/) tool:

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez l'imaginer, un universal binary compilé pour 2 architectures **double généralement la taille** de celui compilé pour une seule arch.

## **Mach-O Header**

L'en-tête contient des informations de base sur le fichier, comme les octets magic permettant de l'identifier en tant que fichier Mach-O et des informations sur l'architecture cible. Vous pouvez le trouver dans : `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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

Il existe différents types de fichiers, vous pouvez les trouver définis dans la [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Les plus importants sont :

- `MH_OBJECT`: Fichier objet relocatable (produits intermédiaires de compilation, pas encore exécutables).
- `MH_EXECUTE`: Fichiers exécutables.
- `MH_FVMLIB`: Fichier de bibliothèque VM fixe.
- `MH_CORE`: Dumps de code
- `MH_PRELOAD`: Fichier exécutable préchargé (n'est plus supporté dans XNU)
- `MH_DYLIB`: Bibliothèques dynamiques
- `MH_DYLINKER`: Linker dynamique
- `MH_BUNDLE`: "Plugin files". Générés en utilisant -bundle dans gcc et chargés explicitement par `NSBundle` ou `dlopen`.
- `MH_DYSM`: Fichier compagnon `.dSym` (fichier contenant des symboles pour le débogage).
- `MH_KEXT_BUNDLE`: Extensions du noyau.
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

Le code source définit également plusieurs flags utiles pour le chargement des bibliothèques :

- `MH_NOUNDEFS`: Pas de références non définies (entièrement lié)
- `MH_DYLDLINK`: Liaison dyld
- `MH_PREBOUND`: Références dynamiques préliées.
- `MH_SPLIT_SEGS`: Sépare les segments r/o et r/w.
- `MH_WEAK_DEFINES`: Le binaire possède des symboles définis faibles
- `MH_BINDS_TO_WEAK`: Le binaire utilise des symboles faibles
- `MH_ALLOW_STACK_EXECUTION`: Rendre la pile exécutable
- `MH_NO_REEXPORTED_DYLIBS`: Bibliothèque sans commandes LC_REEXPORT
- `MH_PIE`: Exécutable indépendant de la position
- `MH_HAS_TLV_DESCRIPTORS`: Il y a une section avec des variables thread-local
- `MH_NO_HEAP_EXECUTION`: Pas d'exécution pour les pages heap/data
- `MH_HAS_OBJC`: Le binaire contient des sections Objective-C
- `MH_SIM_SUPPORT`: Support du simulateur
- `MH_DYLIB_IN_CACHE`: Utilisé pour les dylibs/frameworks dans le cache de librairies partagées.

## **Mach-O Load commands**

La disposition du fichier en mémoire est spécifiée ici, détaillant l'emplacement de la table des symboles, le contexte du thread principal au démarrage de l'exécution, et les bibliothèques partagées requises. Des instructions sont fournies au chargeur dynamique (dyld) sur le processus de chargement du binaire en mémoire.

Il utilise la structure **load_command**, définie dans le fichier **`loader.h`** mentionné :
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Il existe environ **50 types différents de commandes de chargement** que le système gère différemment. Les plus courantes sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, et `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> En gros, ce type de commande de chargement définit **comment charger le \_\_TEXT** (code exécutable) **et le \_\_DATA** (données pour le processus) **segments** selon les **offsets indiqués dans la section Data** lorsque le binaire est exécuté.

Ces commandes **définissent des segments** qui sont **mappés** dans l'**espace mémoire virtuel** d'un processus lorsqu'il est exécuté.

Il existe **différents types** de segments, comme le segment **\_\_TEXT**, qui contient le code exécutable d'un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments se trouvent dans la section de données** du fichier Mach-O.

**Chaque segment** peut être en outre **divisé** en plusieurs **sections**. La **structure de la commande de chargement** contient des **informations** sur **ces sections** au sein du segment concerné.

Dans l'en-tête, on trouve d'abord l'**en-tête de segment** :

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

Exemple d'en-tête de segment :

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
Exemple d'**en-tête de section** :

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Si vous **ajoutez** l'**offset de section** (0x37DC) + l'**offset** où **arch** commence, dans ce cas `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Il est également possible d'obtenir les **informations des headers** depuis la **ligne de commande** avec :
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Il indique au noyau de **mapper** l'**adresse zéro** afin qu'elle **ne puisse pas être lue, écrite ou exécutée**. Les variables maxprot et minprot de la structure sont réglées à zéro pour indiquer qu'il n'y a **aucun droit lecture-écriture-exécution sur cette page**.
- Cette allocation est importante pour **atténuer les vulnérabilités de déréférencement de pointeur NULL**. En effet, XNU applique une page zéro stricte qui garantit que la première page (seule la première) de la mémoire est inaccessible (sauf sur i386). Un binaire peut satisfaire cette exigence en construisant un petit \_\_PAGEZERO (en utilisant le `-pagezero_size`) pour couvrir les premiers 4k et en rendant le reste de la mémoire 32bit accessible en mode utilisateur et noyau.
- **`__TEXT`**: Contient du **code** **exécutable** avec les permissions **lecture** et **exécution** (pas d'écriture)**.** Sections communes de ce segment :
- `__text`: Code binaire compilé
- `__const`: Données constantes (lecture seule)
- `__[c/u/os_log]string`: Constantes de chaînes C, Unicode ou os logs
- `__stubs` et `__stubs_helper`: Impliqués lors du chargement des bibliothèques dynamiques
- `__unwind_info`: Données d'unwind de pile.
- Notez que tout ce contenu est signé mais aussi marqué comme exécutable (offrant davantage d'options pour l'exploitation de sections qui n'ont pas nécessairement besoin de ce privilège, comme les sections dédiées aux chaînes).
- **`__DATA`**: Contient des données **lisibles** et **écrivables** (pas exécutables)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Pointeur de symbole non-lazy (liaison au chargement)
- `__la_symbol_ptr`: Pointeur de symbole lazy (liaison à l'utilisation)
- `__const`: Devrait être des données en lecture seule (pas vraiment)
- `__cfstring`: Chaînes CoreFoundation
- `__data`: Variables globales (initialisées)
- `__bss`: Variables statiques (non initialisées)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informations utilisées par le runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const n'est pas garanti constant (permissions d'écriture), ni le reste des pointeurs et la GOT. Cette section rend `__const`, certains initialisateurs et la table GOT (une fois résolue) **en lecture seule** en utilisant `mprotect`.
- **`__LINKEDIT`**: Contient des informations pour le linker (dyld) telles que les tables de symboles, de chaînes et de relocalisation. C'est un conteneur générique pour le contenu qui n'est ni dans `__TEXT` ni dans `__DATA` et son contenu est décrit dans d'autres load commands.
- dyld information: Rebase, opcodes de liaison Non-lazy/lazy/weak et info d'export
- Functions starts: Table of start addresses of functions
- Data In Code: îlots de données dans \_\_text
- SYmbol Table: Table des symboles dans le binaire
- Indirect Symbol Table: Pointeurs/symboles de stub
- String Table
- Code Signature
- **`__OBJC`**: Contient des informations utilisées par le runtime Objective-C. Bien que ces informations puissent aussi se trouver dans le segment \_\_DATA, au sein des différentes sections \_\_objc\_\*.
- **`__RESTRICT`**: Un segment sans contenu avec une seule section appelée **`__restrict`** (aussi vide) qui assure que, lors de l'exécution du binaire, les variables d'environnement DYLD seront ignorées.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Core only (not used)
- `SG_FVMLIB`: Not used
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contient le point d'entrée dans l'attribut **entryoff.** Au moment du chargement, **dyld** ajoute simplement cette valeur à la base (en mémoire) du binaire, puis **saute** à cette instruction pour démarrer l'exécution du code du binaire.

**`LC_UNIXTHREAD`** contient les valeurs que doivent avoir les registres lors du démarrage du thread principal. Ceci est déjà déprécié mais **`dyld`** l'utilise encore. Il est possible de voir les valeurs des registres définies par ceci avec :
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


Contient des informations sur la **signature de code du fichier Mach-O**. Il contient seulement un **offset** qui **pointe** vers le **blob de signature**. Ceci se trouve typiquement à la toute fin du fichier.\
Cependant, vous pouvez trouver des informations sur cette section dans [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et ce [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Prend en charge le chiffrement binaire. Cependant, bien sûr, si un attaquant parvient à compromettre le processus, il pourra extraire la mémoire en clair.

### **`LC_LOAD_DYLINKER`**

Contient le **chemin vers l'exécutable du dynamic linker** qui mappe les bibliothèques partagées dans l'espace d'adresses du processus. La **valeur est toujours définie sur `/usr/lib/dyld`**. Il est important de noter que sous macOS, le mapping des dylib se fait en **mode utilisateur**, pas en mode noyau.

### **`LC_IDENT`**

Obsolète, mais lorsqu'il est configuré pour générer des dumps lors d'un panic, un core dump Mach-O est créé et la version du kernel est définie dans la commande `LC_IDENT`.

### **`LC_UUID`**

UUID aléatoire. Il n'est pas utile directement pour grand-chose mais XNU le met en cache avec le reste des infos du processus. Il peut être utilisé dans les rapports de crash.

### **`LC_DYLD_ENVIRONMENT`**

Permet d'indiquer des variables d'environnement à dyld avant que le processus ne soit exécuté. Cela peut être très dangereux car cela peut permettre d'exécuter du code arbitraire dans le processus, donc cette load command n'est utilisée que dans les build de dyld avec `#define SUPPORT_LC_DYLD_ENVIRONMENT` et restreint en outre le traitement uniquement aux variables de la forme `DYLD_..._PATH` spécifiant des chemins de chargement.

### **`LC_LOAD_DYLIB`**

Cette load command décrit une dépendance de **bibliothèque dynamique** qui **indique** au **loader** (dyld) de **charger et lier ladite bibliothèque**. Il y a une `LC_LOAD_DYLIB` load command **pour chaque bibliothèque** dont le binaire Mach-O a besoin.

- This load command is a structure of type **`dylib_command`** (which contains a struct dylib, describing the actual dependent dynamic library):
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
![](<../../../images/image (486).png>)

Vous pouvez aussi obtenir ces informations depuis la CLI avec :
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Quelques bibliothèques potentiellement liées aux malwares sont :

- **DiskArbitration**: Surveillance des périphériques USB
- **AVFoundation:** Capture audio et vidéo
- **CoreWLAN**: Analyses Wi‑Fi

> [!TIP]
> Un binaire Mach-O peut contenir un ou **plusieurs** **constructeurs**, qui seront **exécutés** **avant** l'adresse spécifiée dans **LC_MAIN**.\
> Les offsets de ces constructeurs sont stockés dans la section **\_\_mod_init_func** du segment **\_\_DATA_CONST**.

## **Mach-O Data**

Au cœur du fichier se trouve la région de données, qui est composée de plusieurs segments tels que définis dans la région des load-commands. **Une variété de sections de données peut être hébergée dans chaque segment**, chaque section **contenant du code ou des données** spécifiques à un type.

> [!TIP]
> Les données sont essentiellement la partie contenant toutes les **informations** qui sont chargées par les load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Cela inclut :

- **Function table:** Qui contient des informations sur les fonctions du programme.
- **Symbol table**: Qui contient des informations sur les fonctions externes utilisées par le binaire
- Il peut aussi contenir des fonctions internes, des noms de variables et plus encore.

Pour le vérifier, vous pouvez utiliser l'outil [**Mach-O View**](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou depuis le cli:
```bash
size -m /bin/ls
```
## Objetive-C Sections communes

Dans le segment `__TEXT` (r-x) :

- `__objc_classname`: Noms de classes (chaînes)
- `__objc_methname`: Noms de méthodes (chaînes)
- `__objc_methtype`: Types de méthodes (chaînes)

Dans le segment `__DATA` (rw-) :

- `__objc_classlist`: Pointeurs vers toutes les classes Objetive-C
- `__objc_nlclslist`: Pointeurs vers les classes Objective-C Non-Lazy
- `__objc_catlist`: Pointeur vers les catégories
- `__objc_nlcatlist`: Pointeur vers les catégories Non-Lazy
- `__objc_protolist`: Liste des protocoles
- `__objc_const`: Données constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
