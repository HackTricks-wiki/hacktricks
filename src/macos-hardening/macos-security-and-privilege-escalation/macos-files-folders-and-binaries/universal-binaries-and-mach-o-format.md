# Binaires universels macOS et format Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

macOS utilise le format exécutable **Mach-O**. Un binaire **universel**, ou fat, contient plusieurs tranches Mach-O spécifiques à chaque architecture dans un seul fichier. Les en-têtes open source `fat.h` et `loader.h` d’Apple définissent les structures et les constantes décrites sur cette page. <sup>[[5]](#references)</sup>

Une image Mach-O est composée de :

- En-tête
- Commandes de chargement
- Données

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## En-tête fat

Recherchez le fichier avec : `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

L’en-tête contient les octets **magic**, suivis du **nombre** d’**architectures** que le fichier **contient** (`nfat_arch`). Chaque architecture possède une structure `fat_arch`.

Vérifiez avec :

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

ou avec l’outil [Mach-O View](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Comme vous pouvez vous en douter, un binaire universel compilé pour 2 architectures **double généralement de taille** par rapport à un binaire compilé pour une seule architecture.

> [!TIP]
> Lors de l’analyse de malware ou d’applications suspectes, ne vous arrêtez pas lorsque `file` indique l’architecture « la plus adaptée ». Un binaire universel peut dissimuler des imports, des commandes de chargement ou des métadonnées de compilateur différents dans chaque tranche. Commencez donc par énumérer **toutes** les tranches, puis examinez-les séparément :

```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
  lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
  otool -hv "/tmp/$(basename "$BIN").$A"
  otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```

Les SDK macOS récents exposent également des fonctions utilitaires telles que `macho_for_each_slice()` et `macho_best_slice()` dans `<mach-o/utils.h>`. Cette dernière est pratique pour reproduire le comportement de chargement de dyld/kernel, mais les scanners doivent tout de même parcourir chaque slice afin de ne manquer aucun contenu propre à une architecture.<sup>[[1]](#references)</sup>

## **En-tête Mach-O**

L’en-tête contient des informations de base sur le fichier, comme les octets magiques permettant de l’identifier comme un fichier Mach-O et des informations sur l’architecture cible. Vous pouvez le trouver avec : `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`

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

Il existe différents types de fichiers, que vous pouvez trouver définis dans le [**code source, par exemple ici**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Les plus importants sont :

- `MH_OBJECT` : Fichier objet relogeable (produit intermédiaire de la compilation, pas encore un exécutable).
- `MH_EXECUTE` : Fichiers exécutables.
- `MH_FVMLIB` : Fichier de bibliothèque VM fixe.
- `MH_CORE` : Dumps de code.
- `MH_PRELOAD` : Fichier exécutable préchargé (n’est plus pris en charge dans XNU).
- `MH_DYLIB` : Bibliothèques dynamiques.
- `MH_DYLINKER` : Éditeur de liens dynamique.
- `MH_BUNDLE` : « Fichiers de plugin ». Générés avec l’option -bundle de gcc et chargés explicitement par `NSBundle` ou `dlopen`.
- `MH_DYSM` : Fichier `.dSym` associé (fichier contenant les symboles de débogage).
- `MH_KEXT_BUNDLE` : Extensions du noyau.

```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```

Ou en utilisant [Mach-O View](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flags Mach-O**

Le code source définit également plusieurs flags utiles au chargement des bibliothèques :

- `MH_NOUNDEFS` : aucune référence indéfinie (liaison complète)
- `MH_DYLDLINK` : liaison Dyld
- `MH_PREBOUND` : références dynamiques préliées.
- `MH_SPLIT_SEGS` : le fichier sépare les segments r/o et r/w.
- `MH_WEAK_DEFINES` : le binaire contient des symboles définis faibles
- `MH_BINDS_TO_WEAK` : le binaire utilise des symboles faibles
- `MH_ALLOW_STACK_EXECUTION` : rend la pile exécutable
- `MH_NO_REEXPORTED_DYLIBS` : bibliothèque sans commandes LC_REEXPORT
- `MH_PIE` : exécutable indépendant de la position
- `MH_HAS_TLV_DESCRIPTORS` : une section contient des variables locales au thread
- `MH_NO_HEAP_EXECUTION` : pas d'exécution pour les pages du heap/des données
- `MH_HAS_OBJC` : le binaire contient des sections Objective-C
- `MH_SIM_SUPPORT` : prise en charge du simulateur
- `MH_DYLIB_IN_CACHE` : utilisé pour les dylibs/frameworks dans le cache de bibliothèques partagées.

## **Commandes de chargement Mach-O**

La **disposition du fichier en mémoire** est spécifiée ici, avec l'**emplacement de la table des symboles**, le contexte du thread principal au début de l'exécution et les **bibliothèques partagées** requises. Des instructions sont fournies au chargeur dynamique **(dyld)** sur le processus de chargement du binaire en mémoire.

Il utilise la structure **load_command**, définie dans le fichier **`loader.h`** mentionné :

```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```

Il existe environ **50 types différents de load commands**, que le système traite différemment. Les plus courants sont : `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` et `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> En gros, ce type de load command définit **comment charger les segments \_\_TEXT** (code exécutable) **et \_\_DATA** (données du processus), **selon les offsets indiqués dans la section Data** lors de l’exécution du binaire.

Ces commandes **définissent les segments** qui sont **mappés** dans l’**espace mémoire virtuelle** d’un processus lors de son exécution.

Il existe **différents types** de segments, comme le segment **\_\_TEXT**, qui contient le code exécutable d’un programme, et le segment **\_\_DATA**, qui contient les données utilisées par le processus. Ces **segments se trouvent dans la section de données** du fichier Mach-O.

**Chaque segment** peut être **divisé** en plusieurs **sections**. La **structure du load command** contient des **informations** sur **ces sections** au sein du segment correspondant.

Dans l’en-tête, on trouve d’abord l’**en-tête du segment** :

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

Exemple d’en-tête de segment :

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Cet en-tête définit le **nombre de sections dont les en-têtes apparaissent après** celui-ci :

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

Si vous **ajoutez** le **décalage de section** (0x37DC) au **décalage** où l'**architecture commence**, ici `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Il est également possible d'obtenir les **informations d'en-tête** depuis la **ligne de commande** avec :

```bash
otool -lv /bin/ls
```

Segments courants chargés par cette commande :

- **`__PAGEZERO` :** Il indique au kernel de **mapper** l’**adresse zéro** afin qu’elle **ne puisse être ni lue, ni écrite, ni exécutée**. Les variables maxprot et minprot de la structure sont définies à zéro pour indiquer qu’il n’y a **aucun droit de lecture-écriture-exécution sur cette page**.
  - Cette allocation est importante pour **atténuer les vulnérabilités de déréférencement de pointeur NULL**. En effet, XNU applique une page zéro stricte qui garantit que la première page mémoire (et uniquement la première) est inaccessible (sauf sur i386). Un binaire pourrait satisfaire à cette exigence en créant un petit \_\_PAGEZERO (avec `-pagezero_size`) couvrant les premiers 4 Ko et en rendant le reste de la mémoire 32 bits accessible en modes utilisateur et kernel.
- **`__TEXT`** : Contient du **code** **exécutable**, avec les permissions **lecture** et **exécution** (sans écriture)**.** Sections courantes de ce segment :
  - `__text` : Code binaire compilé
  - `__const` : Données constantes (en lecture seule)
  - `__[c/u/os_log]string` : Chaînes constantes C, Unicode ou de journaux os
  - `__stubs` et `__stubs_helper` : Interviennent pendant le chargement des bibliothèques dynamiques
  - `__unwind_info` : Données de déroulement de pile.
  - Notez que tout ce contenu est signé, mais également marqué comme exécutable (ce qui offre davantage de possibilités d’exploitation de sections qui n’ont pas nécessairement besoin de ce privilège, comme les sections dédiées aux chaînes).
- **`__DATA`** : Contient des données **lisibles** et **modifiables** (non exécutables)**.**
  - `__got:` Global Offset Table
  - `__nl_symbol_ptr` : Pointeur de symbole non paresseux (lié au chargement)
  - `__la_symbol_ptr` : Pointeur de symbole paresseux (lié à l’utilisation)
  - `__const` : Devrait contenir des données en lecture seule (ce n’est pas vraiment le cas)
  - `__cfstring` : Chaînes CoreFoundation
  - `__data` : Variables globales (initialisées)
  - `__bss` : Variables statiques (non initialisées)
  - `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc.) : Informations utilisées par le runtime Objective-C
- **`__DATA_CONST`** : \_\_DATA.\_\_const n’est pas garanti d’être constant (permissions d’écriture), pas plus que les autres pointeurs et la GOT. Ce segment rend `__const`, certains initialiseurs et la table GOT (une fois résolue) **accessibles en lecture seule** avec `mprotect`.
- **`__AUTH` / `__AUTH_CONST`** : Courants dans les binaires Apple Silicon récents. Ces segments contiennent des pointeurs qui doivent être authentifiés au chargement ou à l’utilisation (par exemple `__auth_got`). Si une technique de rebinding, de hook ou de modification des imports ne vérifie que les sections historiques `__got` / `__la_symbol_ptr`, elle peut manquer les véritables sites d’appel dans les binaires `arm64e` modernes. Pour plus de détails sur ces sections, consultez [cette page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`** : Contient des informations destinées à l’éditeur de liens (dyld), telles que les entrées des tables de symboles, de chaînes et de relocalisation. C’est un conteneur générique pour les éléments qui ne se trouvent ni dans `__TEXT` ni dans `__DATA`, et son contenu est décrit dans d’autres commandes de chargement.
  - Informations dyld : Rebase, opcodes de liaison non paresseuse/paresseuse/faible et informations d’exportation
  - Débuts des fonctions : Table des adresses de début des fonctions
  - Data In Code : Îlots de données dans \_\_text
  - Table des symboles : Symboles du binaire
  - Table des symboles indirects : Symboles de pointeurs/stubs
  - Table des chaînes
  - Signature du code
- **`__OBJC`** : Contient des informations utilisées par le runtime Objective-C. Ces informations peuvent toutefois aussi se trouver dans le segment \_\_DATA, au sein de diverses sections \_\_objc\_\*.
- **`__RESTRICT`** : Segment sans contenu, avec une seule section appelée **`__restrict`** (également vide), qui garantit qu’à l’exécution du binaire, les variables d’environnement DYLD seront ignorées.

Comme on a pu le voir dans le code, **les segments prennent également en charge des flags** (bien qu’ils ne soient pas très utilisés) :

- `SG_HIGHVM` : Réservé au core (inutilisé)
- `SG_FVMLIB` : Inutilisé
- `SG_NORELOC` : Le segment n’a pas de relocalisation
- `SG_PROTECTED_VERSION_1` : Chiffrement. Utilisé, par exemple, par Finder pour chiffrer le segment texte `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contient le point d’entrée dans l’attribut **entryoff**. Au chargement, **dyld** **ajoute** simplement cette valeur à la **base du binaire** (en mémoire), puis **saute** à cette instruction pour commencer l’exécution du code du binaire.

**`LC_UNIXTHREAD`** contient les valeurs que les registres doivent avoir au démarrage du thread principal. Cette commande est obsolète, mais **`dyld`** l’utilise encore. Il est possible de voir les valeurs définies dans les registres avec :

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


Contient des informations sur la **signature de code du fichier Mach-O**. Il contient uniquement un **offset** qui **pointe** vers le **bloc de signature**. Celui-ci se trouve généralement tout à la fin du fichier.\
Vous trouverez davantage d’informations sur cette section dans [**cet article de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) et [**ce gist**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Prise en charge du chiffrement des binaires. Cependant, bien sûr, si un attaquant parvient à compromettre le processus, il pourra dumper la mémoire en clair.

### **`LC_LOAD_DYLINKER`**

Contient le **chemin vers l’exécutable du linker dynamique**, qui mappe les bibliothèques partagées dans l’espace d’adressage du processus. La **valeur est toujours `/usr/lib/dyld`**. Il est important de noter que, dans macOS, le mappage des dylib se fait en **user mode**, et non en mode kernel.

### **`LC_IDENT`**

Obsolète, mais lorsqu’il est configuré pour générer des dumps en cas de panic, un core dump Mach-O est créé et la version du kernel est définie dans la commande `LC_IDENT`.

### **`LC_UUID`**

UUID aléatoire. Il n’est directement utile à rien, mais XNU le met en cache avec le reste des informations du processus. Il peut être utilisé dans les rapports de crash.

### **`LC_BUILD_VERSION`**

Les binaires modernes contiennent généralement cette commande pour déclarer la **plateforme cible**, la **version minimale de l’OS**, la **version du SDK** et, éventuellement, les **versions des outils** utilisés pour compiler cette tranche. Du point de vue de l’offensive et de la rétro-ingénierie, ces informations sont très utiles pour déterminer comment un échantillon a été compilé et repérer rapidement les binaires universels suspects dont une tranche aurait été compilée avec un SDK ou une cible de déploiement différente. Les binaires plus anciens peuvent encore utiliser `LC_VERSION_MIN_*`.

```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```

### **`LC_DYLD_ENVIRONMENT`**

Permet d’indiquer des variables d’environnement à dyld avant l’exécution du processus. Cela peut être très dangereux, car cela peut permettre d’exécuter du code arbitraire dans le processus. Cette commande de chargement n’est donc utilisée que dans les compilations de dyld avec `#define SUPPORT_LC_DYLD_ENVIRONMENT` et le traitement est en outre limité aux variables de la forme `DYLD_..._PATH` qui spécifient des chemins de chargement.

### **`LC_DYLD_EXPORTS_TRIE` et `LC_DYLD_CHAINED_FIXUPS`**

Les chaînes d’outils récentes stockent souvent les métadonnées d’exportation, de liaison et de rebasage dans ces commandes, au lieu de s’appuyer uniquement sur les anciens opcodes `LC_DYLD_INFO[_ONLY]`. Toutes deux sont des entrées `linkedit_data_command` qui pointent dans **`__LINKEDIT`** :

- **`LC_DYLD_EXPORTS_TRIE`** : trie compact contenant les symboles exportés par l’image.
- **`LC_DYLD_CHAINED_FIXUPS`** : chaînes de correctifs par segment utilisées par dyld pour appliquer les rebasages et les liaisons. Sur Apple Silicon, c’est aussi là que vous trouverez de nombreux correctifs modernes de pointeurs authentifiés.

Ces métadonnées sont très utiles pour reconstituer les imports/exports, comprendre pourquoi une dépendance chargée via `@rpath` a été résolue de cette façon, ou déterminer pourquoi une tentative de hook/rebinding a échoué sur une cible `arm64e` moderne. `dyld_info` peut aussi être utilisé avec des chemins de dylib uniquement présents dans le cache, qui n’existent pas en tant que fichiers autonomes sur le disque. C’est très utile sur les versions récentes de macOS, où de nombreuses bibliothèques système ne se trouvent que dans le cache partagé.<sup>[[2]](#references)</sup>

```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```

### **`LC_FILESET_ENTRY`**

Cette commande de chargement moderne est surtout pertinente lors de l’inspection de **collections du noyau / filesets de type kernelcache**. Au lieu de représenter une image autonome, le Mach-O externe sert de conteneur et chaque `LC_FILESET_ENTRY` pointe vers un Mach-O intégré, avec son propre **identifiant d’entrée** de type chemin, son adresse VM et son décalage dans le fichier. Lors de la rétro-ingénierie des composants modernes du noyau macOS/iOS, cette commande sert souvent de passerelle entre le conteneur de niveau supérieur et l’image que vous souhaitez extraire ou désassembler.

```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```

Pour les workflows d’extraction pratiques, consultez [cette autre page sur les extensions du noyau macOS et le kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Cette commande de chargement décrit une dépendance à une **bibliothèque** **dynamique** qui **indique** au **chargeur** (dyld) de **charger et lier ladite bibliothèque**. Le binaire Mach-O comporte une commande de chargement `LC_LOAD_DYLIB` **pour chaque bibliothèque** dont il a besoin.

- Cette commande de chargement est une structure de type **`dylib_command`** (qui contient une structure dylib décrivant la bibliothèque dynamique dont dépend le binaire) :

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

![LC DYLD ENVIRONMENT - LC LOAD DYLIB : uint32 t version de compatibilité ; / numéro de version de compatibilité de la bibliothèque /](<../../../images/image (486).png>)

Vous pouvez également obtenir ces informations depuis la ligne de commande avec :

```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```

Certaines bibliothèques potentiellement liées aux malwares sont :

- **DiskArbitration** : Surveillance des clés USB
- **AVFoundation:** Capture audio et vidéo
- **CoreWLAN**: Analyses Wi-Fi.

> [!TIP]
> Un binaire Mach-O peut contenir un ou **plusieurs** **constructeurs**, qui seront **exécutés** **avant** l’adresse spécifiée dans **LC_MAIN**.\
> Les offsets des constructeurs se trouvent dans la section **\_\_mod_init_func** du segment **\_\_DATA_CONST**.

## **Données Mach-O**

Au cœur du fichier se trouve la région de données, composée de plusieurs segments définis dans la région des commandes de chargement. **Chaque segment peut contenir différents types de sections de données**, chacune **contenant du code ou des données** propres à un type.

> [!TIP]
> Les données correspondent essentiellement à la partie contenant toutes les **informations** chargées par les commandes de chargement **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Cela comprend :

- **Table des fonctions :** Contient des informations sur les fonctions du programme.
- **Table des symboles** : Contient des informations sur les fonctions externes utilisées par le binaire.
- Elle peut également contenir des fonctions internes, des noms de variables, etc.

Pour l’inspecter, vous pouvez utiliser l’outil [**Mach-O View**](https://sourceforge.net/projects/machoview/) :

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou depuis la CLI :

```bash
size -m /bin/ls
```

### Données ajoutées et overlays analysés à rebours

Un chargeur peut conserver sa configuration dans des données ajoutées à la fin du fichier, plutôt que dans une section Mach-O nommée. Un analyseur à rebours s’ancre alors sur un marqueur de fin, lit une taille stockée juste avant celui-ci et utilise cette valeur pour localiser et déchiffrer le blob précédent. Un chargeur universel observé utilisait cette structure pour une URL de téléchargement chiffrée par XOR :<sup>[[6]](#references)</sup>

```text
[XOR-encrypted URL][8-byte ciphertext length][SONOMAC1]
```

Lors de l’analyse d’un binaire inconnu, examinez les octets autour des marqueurs de fin reconnaissables et suivez chaque calcul de taille effectué en remontant dans le fichier avant de supposer que des chaînes ou une configuration doivent appartenir à une section de commandes de chargement. Le marqueur et la clé XOR dépendent de l’échantillon ; la technique réutilisable consiste à utiliser un trailer auto-descriptif.

## Sections courantes Objective-C

Dans le segment `__TEXT` (r-x) :

- `__objc_classname` : noms des classes (chaînes)
- `__objc_methname` : noms des méthodes (chaînes)
- `__objc_methtype` : types des méthodes (chaînes)

Dans le segment `__DATA` (rw-) :

- `__objc_classlist` : pointeurs vers toutes les classes Objective-C
- `__objc_nlclslist` : pointeurs vers les classes Objective-C Non-Lazy
- `__objc_catlist` : pointeur vers les catégories
- `__objc_nlcatlist` : pointeur vers les catégories Non-Lazy
- `__objc_protolist` : liste des protocoles
- `__objc_const` : données constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Les slices Mach-O ne sont pas aussi simples qu’on pourrait le croire](https://objective-see.org/blog/blog_0x80.html)
- [2] [Page de manuel de dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lire ses propres entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)
- [5] [Apple Open Source - Mach-O `fat.h` et `loader.h`](https://github.com/apple-oss-distributions/xnu/tree/main/EXTERNAL_HEADERS/mach-o)
- [6] [Kaspersky Securelist - Une nouvelle version du stealer macOS MacSync cible les passionnés de crypto et les développeurs](https://securelist.com/macsync-new-version/121383/)
