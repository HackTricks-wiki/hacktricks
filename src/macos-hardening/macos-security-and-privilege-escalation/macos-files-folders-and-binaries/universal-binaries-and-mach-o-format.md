# macOS Universal binaries & Mach-O Format

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Binários do macOS geralmente são compilados como **universal binaries**. Um **universal binary** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

Esses binários seguem a **estrutura Mach-O** que basicamente é composta por:

- Cabeçalho
- Comandos de carregamento
- Dados

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

O header tem os bytes **magic** seguidos pelo **número** de **archs** que o arquivo **contém** (`nfat_arch`) e cada arch terá uma struct `fat_arch`.

Verifique com:

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

Como você pode imaginar, geralmente um universal binary compilado para 2 arquiteturas **dobra o tamanho** de um compilado para apenas 1 arch.

## **Mach-O Header**

O header contém informações básicas sobre o arquivo, como bytes magic para identificá-lo como um arquivo Mach-O e informações sobre a arquitetura alvo. Você pode encontrá-lo em: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Mach-O File Types

Existem diferentes tipos de arquivo — você pode encontrá-los definidos no [**source code for example here**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Os mais importantes são:

- `MH_OBJECT`: Arquivo objeto relocável (produtos intermediários da compilação, ainda não executáveis).
- `MH_EXECUTE`: Arquivos executáveis.
- `MH_FVMLIB`: Arquivo de biblioteca de VM fixa.
- `MH_CORE`: Despejos de código
- `MH_PRELOAD`: Arquivo executável pré-carregado (não é mais suportado no XNU)
- `MH_DYLIB`: Bibliotecas dinâmicas
- `MH_DYLINKER`: Ligador dinâmico
- `MH_BUNDLE`: "Plugin files". Gerados usando -bundle no gcc e carregados explicitamente por `NSBundle` ou `dlopen`.
- `MH_DYSM`: Arquivo acompanhante `.dSym` (arquivo com símbolos para depuração).
- `MH_KEXT_BUNDLE`: Extensões do Kernel.
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Or using [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1133).png" alt=""><figcaption></figcaption></figure>

## **Flags do Mach-O**

O código-fonte também define várias flags úteis para carregar bibliotecas:

- `MH_NOUNDEFS`: Sem referências indefinidas (totalmente vinculadas)
- `MH_DYLDLINK`: Ligação pelo dyld
- `MH_PREBOUND`: Referências dinâmicas pré-vinculadas.
- `MH_SPLIT_SEGS`: Arquivo divide segmentos r/o e r/w.
- `MH_WEAK_DEFINES`: Binário possui símbolos definidos fracos
- `MH_BINDS_TO_WEAK`: Binário usa símbolos fracos
- `MH_ALLOW_STACK_EXECUTION`: Tornar a pilha executável
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteca sem comandos LC_REEXPORT
- `MH_PIE`: Executável independente de posição
- `MH_HAS_TLV_DESCRIPTORS`: Há uma seção com variáveis thread-local
- `MH_NO_HEAP_EXECUTION`: Sem execução para páginas de heap/dados
- `MH_HAS_OBJC`: Binário possui seções oBject-C
- `MH_SIM_SUPPORT`: Suporte ao simulador
- `MH_DYLIB_IN_CACHE`: Usado em dylibs/frameworks no cache de bibliotecas compartilhadas.

## **Comandos de carregamento do Mach-O**

A **disposição do arquivo na memória** é especificada aqui, detalhando a **localização da tabela de símbolos**, o contexto da thread principal no início da execução e as **bibliotecas compartilhadas** necessárias. São fornecidas instruções para o loader dinâmico **(dyld)** sobre o processo de carregamento do binário na memória.

Ele usa a estrutura **load_command**, definida no mencionado **`loader.h`**:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Existem cerca de **50 tipos diferentes de comandos de carregamento** que o sistema trata de forma diferente. Os mais comuns são: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB`, and `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basicamente, esse tipo de Comando de carregamento define **como carregar os \_\_TEXT** (código executável) **e \_\_DATA** (dados do processo) **segmentos** de acordo com os **offsets indicados na seção de dados** quando o binário é executado.

Esses comandos **definem segmentos** que são **mapeados** no **espaço de memória virtual** de um processo quando ele é executado.

Existem **diferentes tipos** de segmentos, como o segmento **\_\_TEXT**, que contém o código executável de um programa, e o segmento **\_\_DATA**, que contém dados usados pelo processo. Esses **segmentos estão localizados na seção de dados** do arquivo Mach-O.

**Cada segmento** pode ser ainda **dividido** em múltiplas **seções**. A **estrutura do load command** contém **informações** sobre **essas seções** dentro do respectivo segmento.

No cabeçalho, primeiro você encontra o **segment header**:

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

Esse cabeçalho define o **número de seções cujos cabeçalhos aparecem após** ele:
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

Se você **somar** o **section offset** (0x37DC) + o **offset** onde a **arch** começa, neste caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Também é possível obter **headers information** pela **command line** com:
```bash
otool -lv /bin/ls
```
Common segments loaded by this cmd:

- **`__PAGEZERO`:** Instrui o kernel a **mapear** o **endereço zero** de modo que **não possa ser lido, escrito ou executado**. As variáveis `maxprot` e `minprot` na estrutura são definidas como zero para indicar que **não há permissões de leitura-escrita-execução nesta página**.
- Esta alocação é importante para **mitigar vulnerabilidades de desreferência de ponteiro NULL**. Isso porque XNU aplica uma hard page zero que garante que a primeira página (apenas a primeira) da memória seja inacessível (exceto em i386). Um binário poderia satisfazer esse requisito criando um pequeno \_\_PAGEZERO (usando o `-pagezero_size`) para cobrir os primeiros 4k e deixando o restante da memória 32bit acessível tanto em modo usuário quanto em modo kernel.
- **`__TEXT`**: Contém **código** **executável** com permissões de **leitura** e **execução** (não gravável). Seções comuns deste segmento:
- `__text`: Código binário compilado
- `__const`: Dados constantes (somente leitura)
- `__[c/u/os_log]string`: Constantes de string C, Unicode ou de logs do os
- `__stubs` and `__stubs_helper`: Envolvidas durante o processo de carregamento de bibliotecas dinâmicas
- `__unwind_info`: Dados de unwind da pilha
- Note que todo esse conteúdo é assinado, mas também marcado como executável (criando mais opções para exploração de seções que nem necessariamente precisam desse privilégio, como seções dedicadas a strings).
- **`__DATA`**: Contém dados que são **legíveis** e **graváveis** (não executáveis).
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Ponteiro de símbolo non-lazy (bind at load)
- `__la_symbol_ptr`: Ponteiro de símbolo lazy (bind on use)
- `__const`: Deveria ser dados somente leitura (na prática não é)
- `__cfstring`: Strings do CoreFoundation
- `__data`: Variáveis globais (que foram inicializadas)
- `__bss`: Variáveis estáticas (que não foram inicializadas)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informações usadas pelo runtime Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const não é garantidamente constante (tem permissões de escrita), nem outros ponteiros e o GOT. Esta seção torna `__const`, alguns inicializadores e a tabela GOT (uma vez resolvida) **somente leitura** usando `mprotect`.
- **`__LINKEDIT`**: Contém informações para o linker (dyld) tais como entradas de tabelas de símbolos, strings e relocação. É um contêiner genérico para conteúdos que não estão em `__TEXT` ou `__DATA` e seu conteúdo é descrito em outros load commands.
- Informação do dyld: Rebase, opcodes de binding Non-lazy/lazy/weak e informações de exportação
- Functions starts: Tabela de endereços iniciais das funções
- Data In Code: Ilhas de dados em \_\_text
- Symbol Table: Símbolos no binário
- Indirect Symbol Table: Símbolos de ponteiro/stub
- String Table
- Code Signature
- **`__OBJC`**: Contém informações usadas pelo runtime Objective-C. Embora essas informações também possam ser encontradas no segmento \_\_DATA, dentro de várias seções \_\_objc\_\*.
- **`__RESTRICT`**: Um segmento sem conteúdo com uma única seção chamada **`__restrict`** (também vazia) que assegura que, ao executar o binário, ele irá ignorar as variáveis de ambiente do DYLD.

As it was possible to see in the code, **segments also support flags** (although they aren't used very much):

- `SG_HIGHVM`: Somente core (não usado)
- `SG_FVMLIB`: Não usado
- `SG_NORELOC`: Segment has no relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Used for example by Finder to encrypt text `__TEXT` segment.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contains the entrypoint in the **entryoff attribute.** At load time, **dyld** simply **adds** this value to the (in-memory) **base of the binary**, then **jumps** to this instruction to start execution of the binary’s code.

**`LC_UNIXTHREAD`** contains the values the register must have when starting the main thread. This was already deprecated but **`dyld`** still uses it. It's possible to see the vlaues of the registers set by this with:
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


Contains information about the **code signature of the Macho-O file**. It only contains an **offset** that **points** to the **signature blob**. This is typically at the very end of the file.\
However, you can find some information about this section in [**this blog post**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) and this [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).

### **`LC_ENCRYPTION_INFO[_64]`**

Suporte para criptografia de binários. No entanto, claro, se um atacante conseguir comprometer o processo, ele poderá extrair a memória sem criptografia.

### **`LC_LOAD_DYLINKER`**

Contém o **caminho para o executável do dynamic linker** que mapeia bibliotecas compartilhadas no espaço de endereços do processo. O **valor é sempre definido para `/usr/lib/dyld`**. É importante notar que no macOS, o mapeamento de dylib ocorre em **modo de usuário**, não em modo kernel.

### **`LC_IDENT`**

Obsoleto, mas quando configurado para gerar dumps em panic, um core dump Mach-O é criado e a versão do kernel é definida no comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatório. Não é útil diretamente para muita coisa, mas o XNU o armazena em cache com o resto das informações do processo. Pode ser usado em crash reports.

### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variáveis de ambiente para o dyld antes do processo ser executado. Isso pode ser muito perigoso, pois pode permitir executar código arbitrário dentro do processo, então esse load command é usado apenas em builds do dyld com `#define SUPPORT_LC_DYLD_ENVIRONMENT` e restringe o processamento apenas às variáveis da forma `DYLD_..._PATH` que especificam caminhos de carregamento.

### **`LC_LOAD_DYLIB`**

This load command describes a **dynamic** **library** dependency which **instructs** the **loader** (dyld) to **load and link said library**. There is a `LC_LOAD_DYLIB` load command **for each library** that the Mach-O binary requires.

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

Você também pode obter essa informação pelo cli com:
```bash
otool -L /bin/ls
/bin/ls:
/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algumas bibliotecas potencialmente relacionadas a malware são:

- **DiskArbitration**: Monitoramento de unidades USB
- **AVFoundation:** Captura de áudio e vídeo
- **CoreWLAN**: Varreduras Wifi.

> [!TIP]
> Um binário Mach-O pode conter um ou **mais** **constructors**, que serão **executados** **antes** do endereço especificado em **LC_MAIN**.\
> Os offsets de quaisquer constructors são mantidos na seção **\_\_mod_init_func** do segmento **\_\_DATA_CONST**.

## **Mach-O Data**

No núcleo do arquivo encontra-se a região de dados, que é composta por vários segmentos conforme definidos na região de load-commands. **Uma variedade de seções de dados pode ser alojada em cada segmento**, com cada seção **contendo código ou dados** específicos a um tipo.

> [!TIP]
> Os dados são basicamente a parte que contém todas as **informações** que são carregadas pelos load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Isto inclui:

- **Function table:** Que armazena informações sobre as funções do programa.
- **Symbol table**: Que contém informações sobre as funções externas usadas pelo binário
- Também pode conter nomes de funções internas, variáveis e mais.

Para verificar isso você pode usar a ferramenta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou pelo cli:
```bash
size -m /bin/ls
```
## Seções comuns do Objective-C

No segmento `__TEXT` (r-x):

- `__objc_classname`: Nomes de classes (strings)
- `__objc_methname`: Nomes de métodos (strings)
- `__objc_methtype`: Tipos de método (strings)

No segmento `__DATA` (rw-):

- `__objc_classlist`: Ponteiros para todas as classes Objective-C
- `__objc_nlclslist`: Ponteiros para classes Objective-C Non-Lazy
- `__objc_catlist`: Ponteiro para Categories
- `__objc_nlcatlist`: Ponteiro para Categories Non-Lazy
- `__objc_protolist`: Lista de protocolos
- `__objc_const`: Dados constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

{{#include ../../../banners/hacktricks-training.md}}
