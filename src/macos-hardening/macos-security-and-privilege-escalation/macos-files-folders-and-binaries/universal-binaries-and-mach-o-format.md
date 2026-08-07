# Binários universais do macOS e formato Mach-O

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar múltiplas arquiteturas no mesmo arquivo**.

Esses binários seguem a **estrutura Mach-O**, que é basicamente composta por:

- Cabeçalho
- Load Commands
- Dados

![https://alexdremov.me/content/images/2022/10/6XLCD.gif](<../../../images/image (470).png>)

## Cabeçalho Fat

Pesquise pelo arquivo com: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

O cabeçalho contém os bytes **magic**, seguidos pelo **número** de **arquiteturas** que o arquivo **contém** (`nfat_arch`), e cada arquitetura terá uma struct `fat_arch`.

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

Como você pode estar pensando, normalmente um binário universal compilado para 2 arquiteturas **dobra o tamanho** de um binário compilado para apenas 1 arquitetura.

> [!TIP]
> Ao fazer a triagem de malware ou aplicativos suspeitos, não pare depois que `file` reportar a arquitetura "melhor". Um binário universal pode ocultar imports, load commands ou metadados do compilador diferentes em cada slice; portanto, enumere **todos** os slices primeiro e depois inspecione-os individualmente:
```bash
BIN=/path/to/bin
lipo -archs "$BIN"
for A in $(lipo -archs "$BIN"); do
lipo -thin "$A" "$BIN" -output "/tmp/$(basename "$BIN").$A"
otool -hv "/tmp/$(basename "$BIN").$A"
otool -l "/tmp/$(basename "$BIN").$A" | egrep 'LC_BUILD_VERSION|LC_LOAD_DYLIB|LC_RPATH|LC_DYLD_CHAINED_FIXUPS|LC_CODE_SIGNATURE'
done
```
Os SDKs recentes do macOS também expõem helpers como `macho_for_each_slice()` e `macho_best_slice()` em `<mach-o/utils.h>`. Este último é útil para emular o que o dyld/kernel carregaria, mas os scanners ainda devem iterar por cada slice para evitar perder conteúdo específico de uma arquitetura.<sup>[[1]](#references)</sup>

## **Cabeçalho Mach-O**

O cabeçalho contém informações básicas sobre o arquivo, como magic bytes para identificá-lo como um arquivo Mach-O e informações sobre a arquitetura de destino. Você pode encontrá-lo em: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
### Tipos de arquivo Mach-O

Existem diferentes tipos de arquivo; você pode encontrá-los definidos no [**código-fonte, por exemplo, aqui**](https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h). Os mais importantes são:

- `MH_OBJECT`: Arquivo de objeto relocável (produtos intermediários da compilação, ainda não são executáveis).
- `MH_EXECUTE`: Arquivos executáveis.
- `MH_FVMLIB`: Arquivo de biblioteca VM fixa.
- `MH_CORE`: Dumps de código.
- `MH_PRELOAD`: Arquivo executável pré-carregado (não é mais compatível com XNU).
- `MH_DYLIB`: Bibliotecas dinâmicas.
- `MH_DYLINKER`: Dynamic Linker.
- `MH_BUNDLE`: "Arquivos de Plugin". Gerados usando -bundle no gcc e carregados explicitamente por `NSBundle` ou `dlopen`.
- `MH_DYSM`: Arquivo `.dSym` complementar (arquivo com símbolos para debugging).
- `MH_KEXT_BUNDLE`: Extensões do kernel.
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

- `MH_NOUNDEFS`: Sem referências indefinidas (totalmente vinculário)
- `MH_DYLDLINK`: Linkedição pelo Dyld
- `MH_PREBOUND`: Referências dinâmicas pré-vinculadas.
- `MH_SPLIT_SEGS`: O arquivo divide os segmentos r/o e r/w.
- `MH_WEAK_DEFINES`: O binário possui símbolos definidos como weak
- `MH_BINDS_TO_WEAK`: O binário usa símbolos weak
- `MH_ALLOW_STACK_EXECUTION`: Torna a stack executável
- `MH_NO_REEXPORTED_DYLIBS`: Biblioteca sem comandos LC_REEXPORT
- `MH_PIE`: Executável independente de posição
- `MH_HAS_TLV_DESCRIPTORS`: Há uma seção com variáveis locais de thread
- `MH_NO_HEAP_EXECUTION`: Sem execução para páginas de heap/dados
- `MH_HAS_OBJC`: O binário possui seções Objective-C
- `MH_SIM_SUPPORT`: Suporte a simulador
- `MH_DYLIB_IN_CACHE`: Usado em dylibs/frameworks no cache de bibliotecas compartilhadas.

## **Comandos de carregamento do Mach-O**

O **layout do arquivo na memória** é especificado aqui, detalhando a **localização da tabela de símbolos**, o contexto da thread principal no início da execução e as **bibliotecas compartilhadas** necessárias. São fornecidas instruções ao carregador dinâmico **(dyld)** sobre o processo de carregamento do binário na memória.

Ele usa a estrutura **load_command**, definida no **`loader.h`** mencionado:
```objectivec
struct load_command {
uint32_t cmd;           /* type of load command */
uint32_t cmdsize;       /* total size of command in bytes */
};
```
Há cerca de **50 tipos diferentes de load commands** que o sistema trata de forma diferente. Os mais comuns são: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC_SEGMENT/LC_SEGMENT_64**

> [!TIP]
> Basicamente, esse tipo de Load Command define **como carregar os segmentos \_\_TEXT** (código executável) **e \_\_DATA** (dados do processo) **de acordo com os offsets indicados na seção Data** quando o binary é executado.

Esses comandos **definem segmentos** que são **mapeados** no **espaço de memória virtual** de um processo quando ele é executado.

Existem **diferentes tipos** de segmentos, como o segmento **\_\_TEXT**, que contém o código executável de um programa, e o segmento **\_\_DATA**, que contém dados usados pelo processo. Esses **segmentos estão localizados na seção de dados** do arquivo Mach-O.

**Cada segmento** pode ser ainda **dividido** em várias **seções**. A **estrutura do load command** contém **informações** sobre **essas seções** dentro do respectivo segmento.

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

Esse header define o **número de seções cujos headers aparecem depois dele**:
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
Exemplo de **cabeçalho de seção**:

<figure><img src="../../../images/image (1108).png" alt=""><figcaption></figcaption></figure>

Se você **adicionar** o **deslocamento da seção** (0x37DC) + o **deslocamento** onde a **arquitetura começa**, neste caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../images/image (701).png" alt=""><figcaption></figcaption></figure>

Também é possível obter **informações dos cabeçalhos** pela **linha de comando** com:
```bash
otool -lv /bin/ls
```
Segmentos comuns carregados por este cmd:

- **`__PAGEZERO`:** Instrui o kernel a **mapear** o **endereço zero** para que ele **não possa ser lido, escrito ou executado**. As variáveis maxprot e minprot na estrutura são definidas como zero para indicar que **não há permissões de leitura-escrita-execução nesta página**.
- Essa alocação é importante para **mitigar vulnerabilidades de NULL pointer dereference**. Isso ocorre porque o XNU impõe um page zero rígido que garante que a primeira página (somente a primeira) da memória seja inacessível (exceto em i386). Um binário poderia cumprir esse requisito criando um \_\_PAGEZERO pequeno (usando `-pagezero_size`) para cobrir os primeiros 4k e tendo o restante da memória de 32 bits acessível tanto no modo de usuário quanto no modo kernel.
- **`__TEXT`**: Contém **código** **executável** com permissões de **leitura** e **execução** (sem escrita)**.** Seções comuns deste segmento:
- `__text`: Código binário compilado
- `__const`: Dados constantes (somente leitura)
- `__[c/u/os_log]string`: Constantes de strings C, Unicode ou os logs
- `__stubs` e `__stubs_helper`: Envolvidos durante o processo de carregamento de dynamic libraries
- `__unwind_info`: Dados para unwind da stack.
- Observe que todo esse conteúdo é assinado, mas também marcado como executável (criando mais opções para exploração de seções que não necessariamente precisam desse privilégio, como seções dedicadas a strings).
- **`__DATA`**: Contém dados que são **legíveis** e **graváveis** (não executáveis)**.**
- `__got:` Global Offset Table
- `__nl_symbol_ptr`: Ponteiro de símbolo non-lazy (bind no carregamento)
- `__la_symbol_ptr`: Ponteiro de símbolo lazy (bind no uso)
- `__const`: Deveria conter dados somente leitura (mas não realmente)
- `__cfstring`: Strings do CoreFoundation
- `__data`: Variáveis globais (que foram inicializadas)
- `__bss`: Variáveis estáticas (que não foram inicializadas)
- `__objc_*` (\_\_objc_classlist, \_\_objc_protolist, etc): Informações usadas pelo runtime do Objective-C
- **`__DATA_CONST`**: \_\_DATA.\_\_const não tem garantia de ser constante (possui permissões de escrita), assim como outros ponteiros e a GOT. Esta seção torna `__const`, alguns initializers e a tabela GOT (depois de resolvida) **somente leitura** usando `mprotect`.
- **`__AUTH` / `__AUTH_CONST`**: Comuns em binários recentes do Apple Silicon. Esses segmentos contêm ponteiros que precisam ser autenticados no carregamento ou no momento do uso (por exemplo, `__auth_got`). Se um truque de rebinding, hook ou import-patching verificar apenas as seções legadas `__got` / `__la_symbol_ptr`, ele pode não encontrar os call sites reais em binários `arm64e` modernos. Para mais detalhes sobre essas seções, consulte [esta página](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).
- **`__LINKEDIT`**: Contém informações para o linker (dyld), como entradas de tabelas de símbolos, strings e relocations. É um contêiner genérico para conteúdos que não estão em `__TEXT` ou `__DATA`, e seu conteúdo é descrito em outros load commands.
- Informações do dyld: opcodes de rebase, binding non-lazy/lazy/weak e informações de exportação
- Inícios de funções: Tabela de endereços iniciais das funções
- Data In Code: Ilhas de dados em \_\_text
- Symbol Table: Símbolos no binário
- Indirect Symbol Table: Símbolos de ponteiros/stubs
- String Table
- Code Signature
- **`__OBJC`**: Contém informações usadas pelo runtime do Objective-C. Embora essas informações também possam ser encontradas no segmento \_\_DATA, dentro de várias seções \_\_objc\_\*.
- **`__RESTRICT`**: Um segmento sem conteúdo com uma única seção chamada **`__restrict`** (também vazia), que garante que, ao executar o binário, ele ignore as variáveis de ambiente do DYLD.

Como foi possível observar no código, **os segmentos também suportam flags** (embora não sejam muito usadas):

- `SG_HIGHVM`: Apenas para Core (não usada)
- `SG_FVMLIB`: Não usada
- `SG_NORELOC`: O segmento não possui relocation
- `SG_PROTECTED_VERSION_1`: Encryption. Usada, por exemplo, pelo Finder para criptografar o segmento de texto `__TEXT`.

### **`LC_UNIXTHREAD/LC_MAIN`**

**`LC_MAIN`** contém o entrypoint no **atributo entryoff.** No carregamento, o **dyld** simplesmente **adiciona** esse valor à **base (na memória) do binário** e então **salta** para essa instrução para iniciar a execução do código do binário.

**`LC_UNIXTHREAD`** contém os valores que os registradores devem ter ao iniciar a thread principal. Isso já foi deprecated, mas o **`dyld`** ainda o utiliza. É possível ver os valores dos registradores definidos por ele com:
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


Contém informações sobre a **assinatura de código do arquivo Macho-O**. Ele contém apenas um **offset** que **aponta** para o **bloco da assinatura**. Normalmente, ele fica no final do arquivo.\
No entanto, você pode encontrar algumas informações sobre esta seção nesta [**publicação de blog**](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/) e nestes [**gists**](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4).<sup>[[3]](#references)[[4]](#references)</sup>

### **`LC_ENCRYPTION_INFO[_64]`**

Suporte para criptografia de binários. No entanto, é claro, se um atacante conseguir comprometer o processo, ele poderá fazer o dump da memória sem criptografia.

### **`LC_LOAD_DYLINKER`**

Contém o **caminho para o executável do dynamic linker** que mapeia shared libraries para o espaço de endereçamento do processo. O **valor é sempre definido como `/usr/lib/dyld`**. É importante observar que, no macOS, o mapeamento de dylibs ocorre no **user mode**, não no **kernel mode**.

### **`LC_IDENT`**

Obsoleto, mas quando configurado para gerar dumps em caso de panic, um core dump Mach-O é criado e a versão do kernel é definida no comando `LC_IDENT`.

### **`LC_UUID`**

UUID aleatório. Não é diretamente útil para nada, mas o XNU o armazena em cache junto com o restante das informações do processo. Ele pode ser usado em crash reports.

### **`LC_BUILD_VERSION`**

Os binários modernos normalmente carregam este comando para declarar a **plataforma de destino**, a **versão mínima do OS**, a **versão do SDK** e, opcionalmente, as **versões das ferramentas** usadas para compilar esse slice. De uma perspectiva de offensive/reversing, isso é muito útil para identificar como um sample foi compilado e detectar rapidamente universal binaries estranhos em que um slice foi compilado com um SDK ou deployment target diferente. Binários mais antigos ainda podem usar `LC_VERSION_MIN_*`.
```bash
vtool -show-build /bin/ls
otool -l /bin/ls | grep -A 8 LC_BUILD_VERSION
```
### **`LC_DYLD_ENVIRONMENT`**

Permite indicar variáveis de ambiente para o dyld antes que o processo seja executado. Isso pode ser muito perigoso, pois pode permitir executar código arbitrário dentro do processo, portanto este load command só é usado em builds do dyld com `#define SUPPORT_LC_DYLD_ENVIRONMENT` e restringe ainda mais o processamento apenas a variáveis no formato `DYLD_..._PATH`, especificando paths de carregamento.

### **`LC_DYLD_EXPORTS_TRIE` e `LC_DYLD_CHAINED_FIXUPS`**

Toolchains recentes frequentemente armazenam metadados de export/bind/rebase nesses commands, em vez de depender apenas dos opcodes mais antigos `LC_DYLD_INFO[_ONLY]`. Ambos são entries de `linkedit_data_command` que apontam para **`__LINKEDIT`**:

- **`LC_DYLD_EXPORTS_TRIE`**: Trie compacta com os símbolos exportados pela image.
- **`LC_DYLD_CHAINED_FIXUPS`**: Chains de fixups por segmento usadas pelo dyld para aplicar rebases e binds. No Apple Silicon, também é aqui que você encontrará muitos dos modernos authenticated pointer fixups.

Esses metadados são muito úteis ao reconstruir imports/exports, entender por que uma dependency carregada por `@rpath` foi resolvida dessa forma ou descobrir por que uma tentativa de hook/rebinding falhou em um target `arm64e` moderno. `dyld_info` também pode ser usado contra **cache-only dylib paths** que não existem como arquivos independentes no disco, o que é muito útil no macOS moderno, onde muitas bibliotecas do sistema existem apenas no shared cache.<sup>[[2]](#references)</sup>
```bash
dyld_info -arch arm64e -exports -fixup_chains -fixup_chain_details /bin/ls
```
### **`LC_FILESET_ENTRY`**

Este comando de carregamento moderno é principalmente relevante ao inspecionar **kernel collections / kernelcache-style filesets**. Em vez de representar uma imagem standalone única, o Mach-O externo atua como um contêiner, e cada `LC_FILESET_ENTRY` aponta para um Mach-O incorporado com seu próprio **entry id** semelhante a um caminho, endereço de VM e deslocamento no arquivo. Se você estiver fazendo reverse engineering de componentes modernos do kernel do macOS/iOS, esse comando costuma ser a ponte entre o contêiner de nível superior e a imagem real que deseja extrair ou desmontar.
```bash
otool -l /System/Library/KernelCollections/BootKernelExtensions.kc | grep -A 6 LC_FILESET_ENTRY
```
Para workflows práticos de extração, consulte [esta outra página sobre extensões do kernel do macOS e kernelcache](../mac-os-architecture/macos-kernel-extensions.md).

### **`LC_LOAD_DYLIB`**

Este comando de carregamento descreve uma dependência de **biblioteca** **dinâmica** que instrui o **loader** (dyld) a **carregar e vincular a biblioteca mencionada**. Existe um comando de carregamento `LC_LOAD_DYLIB` **para cada biblioteca** exigida pelo binário Mach-O.

- Este comando de carregamento é uma estrutura do tipo **`dylib_command`** (que contém uma struct dylib, descrevendo a biblioteca dinâmica dependente real):
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

Você também pode obter estas informações pela CLI com:
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
- **CoreWLAN**: Scans de Wi-Fi.

> [!TIP]
> Um binário Mach-O pode conter um ou **mais** **construtores**, que serão **executados** **antes** do endereço especificado em **LC_MAIN**.\
> Os offsets de quaisquer construtores são mantidos na seção **\_\_mod_init_func** do segmento **\_\_DATA_CONST**.

## **Dados do Mach-O**

No núcleo do arquivo está a região de dados, composta por vários segmentos, conforme definido na região de load-commands. **Uma variedade de seções de dados pode ser armazenada em cada segmento**, com cada seção **contendo código ou dados** específicos de um tipo.

> [!TIP]
> Os dados são basicamente a parte que contém todas as **informações** carregadas pelos load commands **LC_SEGMENTS_64**

![https://www.oreilly.com/api/v2/epubs/9781785883378/files/graphics/B05055_02_38.jpg](<../../../images/image (507) (3).png>)

Isso inclui:

- **Tabela de funções:** Contém informações sobre as funções do programa.
- **Tabela de símbolos**: Contém informações sobre a função externa usada pelo binário
- Ela também pode conter nomes de funções internas, variáveis e muito mais.

Para verificá-la, você pode usar a ferramenta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../images/image (1120).png" alt=""><figcaption></figcaption></figure>

Ou a partir da CLI:
```bash
size -m /bin/ls
```
## Seções comuns de Objective-C

No segmento `__TEXT` (r-x):

- `__objc_classname`: Nomes de classes (strings)
- `__objc_methname`: Nomes de métodos (strings)
- `__objc_methtype`: Tipos de métodos (strings)

No segmento `__DATA` (rw-):

- `__objc_classlist`: Ponteiros para todas as classes de Objective-C
- `__objc_nlclslist`: Ponteiros para classes de Objective-C Non-Lazy
- `__objc_catlist`: Ponteiro para Categories
- `__objc_nlcatlist`: Ponteiro para Categories Non-Lazy
- `__objc_protolist`: Lista de Protocols
- `__objc_const`: Dados constantes
- `__objc_imageinfo`, `__objc_selrefs`, `objc__protorefs`...

## Swift

- `_swift_typeref`, `_swift3_capture`, `_swift3_assocty`, `_swift3_types, _swift3_proto`, `_swift3_fieldmd`, `_swift3_builtin`, `_swift3_reflstr`

## Referências

- [1] [Mach-O slices não são tão diretas quanto você pode imaginar](https://objective-see.org/blog/blog_0x80.html)
- [2] [Página de manual do dyld_info(1)](https://keith.github.io/xcode-man-pages/dyld_info.1.html)
- [3] [Lendo seus próprios Entitlements](https://davedelong.com/blog/2018/01/10/reading-your-own-entitlements/)
- [4] [carlospolop/machoreader.py (gist)](https://gist.github.com/carlospolop/ef26f8eb9fafd4bc22e69e1a32b81da4)

{{#include ../../../banners/hacktricks-training.md}}
