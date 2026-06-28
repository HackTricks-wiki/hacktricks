# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Binaries do Mac OS geralmente são compilados como **universal binaries**. Um **universal binary** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

Esses binaries seguem a **estrutura Mach-O**, que basicamente é composta por:

- Header
- Load Commands
- Data

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Fat Header

Procure o arquivo com: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

O header tem os bytes **magic** seguidos pelo **número** de **archs** que o arquivo **contém** (`nfat_arch`), e cada arch terá uma struct `fat_arch`.

Confira com:

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

ou usando a ferramenta [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1094).png" alt=""><figcaption></figcaption></figure>

Como você pode estar pensando, normalmente um universal binary compilado para 2 arquiteturas **duplica o tamanho** de um compilado para apenas 1 arch.

> [!TIP]
> Quando estiver triando malware ou apps suspeitos, não pare depois que `file` reportar a "best" architecture. Um universal binary pode esconder imports, load commands ou compiler metadata diferentes em cada slice, então enumere **todos** os slices primeiro e depois inspecione-os independentemente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
SDKs recentes do macOS também expõem helpers como `macho_for_each_slice()` e `macho_best_slice()` em `<mach-o/utils.h>`. A segunda é útil para emular o que o dyld/kernel carregaria, mas os scanners ainda devem iterar por cada slice para evitar perder conteúdo específico da arquitetura.

## **Mach-O Header**

O header contém informações básicas sobre o arquivo, como magic bytes para identificar que ele é um arquivo Mach-O e informações sobre a arquitetura de destino. Você pode encontrá-lo em: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipos de Arquivo Mach-O

Existem diferentes tipos de arquivo, você pode encontrá-los definidos no [**source code por exemplo aqui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Os mais importantes são:

- `MH_OBJECT`: Arquivo objeto relocável (produtos intermediários da compilação, ainda não executáveis).
- `MH_EXECUTE`: Arquivos executáveis.
- `MH_FVMLIB`: Arquivo de biblioteca VM fixa.
- `MH_CORE`: Code Dumps
- `MH_PRELOAD`: Arquivo executável pré-carregado (não mais suportado no XNU)
- `MH_DYLIB`: Dynamic Libraries
- `MH_DYLINKER`: Dynamic Linker
- `MH_BUNDLE`: "Plugin files". Gerados usando -bundle no gcc e carregados explicitamente por `NSBundle` ou `dlopen`.
- `MH_DYSM`: Arquivo `.dSym` acompanhante (arquivo com símbolos para depuração).
- `MH_KEXT_BUNDLE`: Kernel Extensions.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou usando [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flags do Mach-O**

O código-fonte também define várias flags úteis para carregar bibliotecas:

- `MH_NOUNDEFS`: Sem referências indefinidas (totalmente linked)
- `MH_DYLDLINK`: Linking do Dyld
- `MH_PREBOUND`: Referências dinâmicas prebound.
- `MH_SPLIT_SEGS`: O arquivo separa segmentos r/o e r/w.
- `MH_WEAK_DEFINES`: O binary tem símbolos weak definidos
- `MH_BINDS_TO_WEAK`: O binary usa símbolos weak
- `MH_ALLOW_STACK_EXECUTION`: Torna a stack executável
- `MH_NO_REEXPORTED_DYLIBS`: A biblioteca não tem comandos LC_REEXPORT
- `MH_PIE`: Position Independent Executable
- `MH_HAS_TLV_DESCRIPTORS`: Há uma seção com thread local variables
- `MH_NO_HEAP_EXECUTION`: Sem execução para páginas de heap/data
- `MH_HAS_OBJC`: O binary tem seções oBject-C
- `MH_SIM_SUPPORT`: Suporte ao simulador
- `MH_DYLIB_IN_CACHE`: Usado em dylibs/frameworks no shared library cache.

## **Comandos de carga do Mach-O**

O **layout do arquivo na memória** é especificado aqui, detalhando a **localização da symbol table**, o contexto da thread principal no início da execução e as **shared libraries** necessárias. Instruções são fornecidas ao dynamic loader **(dyld)** sobre o processo de carregamento do binary na memória.

Ele usa a estrutura **load_command**, definida no mencionado **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Existem cerca de **50 tipos diferentes de load commands** que o sistema trata de forma diferente. Os mais comuns são: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basicamente, esse tipo de Load Command define **como carregar os segmentos \_\_TEXT** (código executável) **e \_\_DATA** (dados para o processo) **de acordo com os offsets indicados na seção Data** quando o binário é executado.

Esses comandos **definem segmentos** que são **mapeados** no **espaço de memória virtual** de um processo quando ele é executado.

Existem **diferentes tipos** de segmentos, como o segmento **\_\_TEXT**, que contém o código executável de um programa, e o segmento **\_\_DATA**, que contém dados usados pelo processo. Esses **segmentos estão localizados na seção de dados** do arquivo Mach-O.

**Cada segmento** pode ser ainda **dividido** em várias **sections**. A **estrutura do load command** contém **informações** sobre **essas sections** dentro do respectivo segmento.

No header, primeiro você encontra o **segment header**:

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

Exemplo de segment header:

<figure><img src="../../../images/image (1126).png" alt=""><figcaption></figcaption></figure>

Esse header define o **número de sections cujos headers aparecem depois** dele:
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
Exemplo de **section header**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se você **adicionar** o **section offset** (0x37DC) + o **offset** onde o **arch starts**, neste caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Também é possível obter **headers information** pela **command line** com:
```bash
otool -lv /bin/ls
```
Segmentos comuns carregados por este cmd:

- **`__PAGEZERO`:** Ele instrui o kernel a **mapear** o **endereço zero** para que ele **não possa ser lido, escrito ou executado**. As variáveis maxprot e minprot na estrutura são definidas como zero para indicar que **não há direitos de leitura-escrita-execução nesta página**.
- Essa alocação é importante para **mitigar vulnerabilidades de NULL pointer dereference**. Isso ocorre porque o XNU impõe uma hard page zero que garante que a primeira página (apenas a primeira) da memória seja inacessível (exceto em i386). Um binary poderia cumprir esse requisito criando um pequeno \_\_PAGEZERO (usando `-pagezero_size`) para cobrir os primeiros 4k e deixando o restante da memória de 32bit acessível tanto em user quanto em kernel mode.
- **`__TEXT`**: Contém **code** **executável** com permissões de **read** e **execute** (sem writable)**.** Seções comuns deste segmento:
- `__text`: Código binário compilado
- `__const`: Dados constantes (somente leitura)
- `__[c/u/os_log]string`: C, Unicode ou constantes de string de logs do os
- `__stubs` and `__stubs_helper`: Envolvidos durante o processo de carregamento da dynamic library
- `__unwind_info`: Dados de unwind da stack.
- Observe que todo esse conteúdo é assinado, mas também marcado como executável (criando mais opções para exploitation de seções que não necessariamente precisam desse privilégio, como seções dedicadas a strings).
- **`__DATA`**: Contém dados que são **readable** e **writable** (sem executable)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Ponteiro de símbolo non lazy (bind at load)
- `__la_symbol_ptr`: Ponteiro de símbolo lazy (bind on use)
- `__const`: Deve ser dados somente leitura (na verdade, não)
- `__cfstring`: Strings do CoreFoundation
- `__data`: Variáveis globais (que foram inicializadas)
- `__bss`: Variáveis estáticas (que não foram inicializadas)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informações usadas pelo runtime do Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const não é гарантido ser constante (permissões de escrita), nem outros ponteiros e a GOT. Esta seção torna `__const`, alguns initializers e a tabela GOT (uma vez resolvida) **read only** usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comum em binaries recentes de Apple Silicon. Esses segmentos guardam ponteiros que devem ser autenticados no load ou no use time (por exemplo `__auth_got`). Se uma técnica de rebinding, hook ou import-patching verifica apenas as seções legadas `__got` / `__la_symbol_ptr`, ela pode perder os reais call sites em binaries modernos `arm64e`. Para mais detalhes sobre essas seções, confira [this page](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contém informações para o linker (dyld), como entradas de tabela de symbols, strings e relocation. É um contêiner genérico para conteúdos que não estão em `__TEXT` ou `__DATA` e seu conteúdo é descrito em outros load commands.
- informações do dyld: opcodes de Rebase, Non-lazy/lazy/weak binding e export info
- Functions starts: tabela de endereços iniciais de functions
- Data In Code: ilhas de dados em \_\_text
- SYmbol Table: Symbols no binary
- Indirect Symbol Table: symbols de ponteiro/stub
- String Table
- Code Signature
- **`__OBJC`**: Contém informações usadas pelo runtime do Objective-C. Embora essas informações também possam ser encontradas no segmento \_\_DATA, dentro de várias seções \_\_objc\_\*.
- **`__RESTRICT`**: Um segmento sem conteúdo com uma única seção chamada **`__restrict`** (também vazia) que garante que, ao executar o binary, ele ignore variáveis de ambiente DYLD.

Como foi possível ver no code, **segments também suportam flags** (embora elas não sejam muito usadas):

- `SG_HIGHVM`: Apenas core (não usado)
- `SG_FVMLIB`: Não usado
- `SG_NORELOC`: O segmento não tem relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Usado, por exemplo, pelo Finder para encryptar o segmento `__TEXT` de text.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contém o entrypoint no atributo **entryoff.** No momento do load, **dyld** simplesmente **adiciona** esse valor à **base do binary** (na memória) e então **jumpa** para esta instrução para iniciar a execução do code do binary.

**`LC_UNIXTHREAD`** contém os valores que o register deve ter ao iniciar a main thread. Isso já foi deprecated, mas o **dyld** ainda o usa. É possível ver os values dos registers definidos por isso com:
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


Contém informações sobre a **code signature do arquivo Macho-O**. Ela contém apenas um **offset** que **aponta** para o **signature blob**. Isso normalmente fica no final do arquivo.\
No entanto, você pode encontrar algumas informações sobre esta seção neste [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e nestes [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Suporte para binary encryption. No entanto, claro, se um atacante conseguir comprometer o processo, ele conseguirá despejar a memória sem criptografia.

### **`LC_LOAD_DYLINKER`**

Contém o **caminho para o executável dynamic linker** que mapeia shared libraries no espaço de endereçamento do processo. O **valor é sempre definido como `/usr/lib/dyld`**. É importante notar que, no macOS, o mapeamento de dylib acontece em **user mode**, não em kernel mode.

### **`LC_IDENT`**

Obsoleto, mas quando configurado para gerar dumps no panic, um Mach-O core dump é criado e a versão do kernel é definida no comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatório. Não é útil diretamente para nada, mas o XNU o armazena em cache com o restante das informações do processo. Pode ser usado em crash reports.

### **`LC_BUILD_VERSION`**

Binaries modernos normalmente carregam este comando para declarar a **target platform**, a **minimum OS version**, a **SDK version** e, opcionalmente, as **tool versions** usadas para compilar aquele slice. Do ponto de vista ofensivo/reversing, isso é muito útil para identificar como um sample foi compilado e para notar rapidamente universal binaries estranhos em que um slice foi compilado com um SDK ou deployment target diferente. Binários mais antigos ainda podem usar `LC_VERSION_MIN_*` em vez disso.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variáveis de ambiente para o dyld antes de o processo ser executado. Isso pode ser muito perigoso, pois pode permitir executar código arbitrário dentro do processo, então este load command só é usado em builds do dyld com `#define SUPPORT_LC_DYLD_ENVIRONMENT` e ainda restringe o processamento apenas a variáveis no formato `DYLD_..._PATH`, especificando caminhos de carregamento.

### **`LC_DYLD_EXPORTS_TRIE` and `LC_DYLD_CHAINED_FIXUPS`**

Toolchains recentes frequentemente armazenam metadados de export/bind/rebase nestes comandos em vez de depender apenas dos antigos opcodes `LC_DYLD_INFO[_ONLY]`. Ambos são entradas `linkedit_data_command` que apontam para **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: trie compacta com os símbolos exportados pela imagem.
- **`LC_DYLD_CHAINED_FIXUPS`**: cadeias de fixup por segmento usadas pelo dyld para aplicar rebases e binds. No Apple Silicon, é também aqui que você encontrará muitos fixups modernos de authenticated pointer.

Esses metadados são muito úteis ao reconstruir imports/exports, entender por que uma dependência carregada via `@rpath` foi resolvida daquela forma, ou descobrir por que uma tentativa de hook/rebinding falhou em um alvo moderno `arm64e`. `dyld_info` também pode ser usado em caminhos de **cache-only dylib** que não existem como arquivos standalone no disco, o que é muito útil no macOS moderno, onde muitas bibliotecas do sistema vivem apenas no shared cache.
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Este comando de carregamento moderno é mais relevante ao inspecionar **kernel collections / kernelcache-style filesets**. Em vez de representar uma única imagem independente, o Mach-O externo atua como um contêiner e cada `LC_FILESET_ENTRY` aponta para um Mach-O incorporado com seu próprio **entry id** semelhante a um caminho, endereço de VM e offset de arquivo. Se você está fazendo reversing de componentes modernos do kernel do macOS/iOS, este comando costuma ser a ponte entre o contêiner de nível superior e a imagem real que você quer extrair ou disassemblar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Para fluxos práticos de extração, veja [esta outra página sobre macOS kernel extensions e kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Este load command descreve uma dependência de **dynamic** **library** que **instrui** o **loader** (dyld) a **carregar e linkar essa library**. Existe um load command `LC_LOAD_DYLIB` **para cada library** que o binário Mach-O requer.

- Este load command é uma estrutura do tipo **`dylib_command`** (que contém uma struct dylib, descrevendo a actual dependent dynamic library):
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

Você também pode obter essas informações da linha de comando com:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algumas bibliotecas potencialmente relacionadas a malware são:

- **DiskArbitration**: Monitoramento de drives USB
- **AVFoundation:** Captura de áudio e vídeo
- **CoreWLAN**: scans de Wifi.

> [!TIP]
> Um binário Mach-O pode conter um ou **mais** **constructors**, que serão **executados** **antes** do endereço especificado em **LC_MAIN**.\
> Os offsets de quaisquer constructors são mantidos na seção **\_\_mod_init_func** do segmento **\_\_DATA_CONST**.

## **Mach-O Data**

No núcleo do arquivo está a região de dados, que é composta por vários segmentos conforme definidos na região de load-commands. **Uma variedade de seções de dados pode ser abrigada dentro de cada segmento**, com cada seção **contendo código ou dados** específicos de um tipo.

> [!TIP]
> Os dados são basicamente a parte que contém toda a **informação** carregada pelos load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Isso inclui:

- **Function table:** Que contém informações sobre as funções do programa.
- **Symbol table**: Que contém informações sobre a external function usada pelo binário
- Também pode conter internal function, nomes de variáveis e mais.

Para verificar isso, você pode usar a ferramenta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou pela cli:
```bash
size -m /bin/ls
```
## Objetive-C Common Sections

No segmento `__TEXT` (r-x):

- `__objc_classname`: Nomes de classes (strings)
- `__objc_methname`: Nomes de métodos (strings)
- `__objc_methtype`: Tipos de métodos (strings)

No segmento `__DATA` (rw-):

- `__objc_classlist`: Ponteiros para todas as classes Objetive-C
- `__objc_nlclslist`: Ponteiros para classes Objective-C Non-Lazy
- `__objc_catlist`: Ponteiro para Categories
- `__objc_nlcatlist`: Ponteiros para Categories Non-Lazy
- `__objc_protolist`: Lista de protocols
- `__objc_const`: Dados constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`



## References

- [Mach-O slices aren't as straightforward as you might think](https://objective-see.org/blog/blog_0x80.html)
- [dyld_info(1) man page](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
{{#include ../../../banners/hacktricks-training.md}}
