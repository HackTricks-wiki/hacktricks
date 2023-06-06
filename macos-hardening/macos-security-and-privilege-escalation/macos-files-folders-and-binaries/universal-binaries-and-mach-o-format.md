# Binários universais e Formato Mach-O

Os binários do Mac OS geralmente são compilados como **binários universais**. Um **binário universal** pode **suportar várias arquiteturas no mesmo arquivo**.

Esses binários seguem a **estrutura Mach-O** que é basicamente composta por:

* Cabeçalho
* Comandos de carga
* Dados

![](<../../../.gitbook/assets/image (559).png>)

## Cabeçalho Fat

Procure pelo arquivo com: `mdfind fat.h | grep -i mach-o | grep -E "fat.h$"`

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

O cabeçalho tem os bytes **magic** seguidos pelo **número** de **arquiteturas** que o arquivo **contém** (`nfat_arch`) e cada arquitetura terá uma estrutura `fat_arch`.

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

<figure><img src="../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

Como você pode estar pensando, geralmente um binário universal compilado para 2 arquiteturas **dobra o tamanho** de um compilado para apenas 1 arquitetura.

## **Cabeçalho Mach-O**

O cabeçalho contém informações básicas sobre o arquivo, como bytes mágicos para identificá-lo como um arquivo Mach-O e informações sobre a arquitetura de destino. Você pode encontrá-lo em: `mdfind loader.h | grep -i mach-o | grep -E "loader.h$"`
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
**Tipos de arquivos**:

* MH\_EXECUTE (0x2): Executável Mach-O padrão
* MH\_DYLIB (0x6): Uma biblioteca dinâmica Mach-O (ou seja, .dylib)
* MH\_BUNDLE (0x8): Um pacote Mach-O (ou seja, .bundle)
```bash
# Checking the mac header of a binary
otool -arch arm64e -hv /bin/ls
Mach header
      magic  cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags
MH_MAGIC_64    ARM64          E USR00     EXECUTE    19       1728   NOUNDEFS DYLDLINK TWOLEVEL PIE
```
Ou usando o [Mach-O View](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (4) (1) (4).png" alt=""><figcaption></figcaption></figure>

## **Comandos de carga Mach-O**

Isso especifica o **layout do arquivo na memória**. Ele contém a **localização da tabela de símbolos**, o contexto da thread principal no início da execução e quais **bibliotecas compartilhadas** são necessárias.\
Os comandos basicamente instruem o carregador dinâmico **(dyld) como carregar o binário na memória.**

Os comandos de carga começam com uma estrutura **load\_command**, definida no **`loader.h`** mencionado anteriormente:
```objectivec
struct load_command {
        uint32_t cmd;           /* type of load command */
        uint32_t cmdsize;       /* total size of command in bytes */
};
```
Existem cerca de **50 tipos diferentes de comandos de carga** que o sistema manipula de forma diferente. Os mais comuns são: `LC_SEGMENT_64`, `LC_LOAD_DYLINKER`, `LC_MAIN`, `LC_LOAD_DYLIB` e `LC_CODE_SIGNATURE`.

### **LC\_SEGMENT/LC\_SEGMENT\_64**

{% hint style="success" %}
Basicamente, este tipo de Comando de Carga define **como carregar as seções** que são armazenadas em DATA quando o binário é executado.
{% endhint %}

Esses comandos **definem segmentos** que são **mapeados** no **espaço de memória virtual** de um processo quando ele é executado.

Existem **diferentes tipos** de segmentos, como o segmento **\_\_TEXT**, que contém o código executável de um programa, e o segmento **\_\_DATA**, que contém dados usados pelo processo. Esses **segmentos estão localizados na seção de dados** do arquivo Mach-O.

**Cada segmento** pode ser ainda **dividido** em várias **seções**. A **estrutura do comando de carga** contém **informações** sobre **essas seções** dentro do respectivo segmento.

No cabeçalho, primeiro você encontra o **cabeçalho do segmento**:

<pre class="language-c"><code class="lang-c">struct segment_command_64 { /* para arquiteturas de 64 bits */
	uint32_t	cmd;		/* LC_SEGMENT_64 */
	uint32_t	cmdsize;	/* inclui o tamanho dos structs section_64 */
	char		segname[16];	/* nome do segmento */
	uint64_t	vmaddr;		/* endereço de memória deste segmento */
	uint64_t	vmsize;		/* tamanho da memória deste segmento */
	uint64_t	fileoff;	/* deslocamento do arquivo deste segmento */
	uint64_t	filesize;	/* quantidade a ser mapeada do arquivo */
	int32_t		maxprot;	/* proteção VM máxima */
	int32_t		initprot;	/* proteção VM inicial */
<strong>	uint32_t	nsects;		/* número de seções no segmento */
</strong>	uint32_t	flags;		/* flags */
};
</code></pre>

Exemplo de cabeçalho do segmento:

<figure><img src="../../../.gitbook/assets/image (2) (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Este cabeçalho define o **número de seções cujos cabeçalhos aparecem depois** dele:
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

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Se você **adicionar** o **deslocamento da seção** (0x37DC) + o **deslocamento** onde o **arquitetura começa**, neste caso `0x18000` --> `0x37DC + 0x18000 = 0x1B7DC`

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Também é possível obter **informações de cabeçalho** a partir da **linha de comando** com:
```bash
otool -lv /bin/ls
```
Segmentos comuns carregados por este comando:

* **`__PAGEZERO`:** Instrui o kernel a **mapear** o **endereço zero** para que ele **não possa ser lido, escrito ou executado**. As variáveis maxprot e minprot na estrutura são definidas como zero para indicar que não há **direitos de leitura-escrita-execução nesta página**.
  * Esta alocação é importante para **mitigar vulnerabilidades de referência de ponteiro nulo**.
* **`__TEXT`**: Contém **código executável** e **dados** que são **somente leitura**. Seções comuns deste segmento:
  * `__text`: Código binário compilado
  * `__const`: Dados constantes
  * `__cstring`: Constantes de string
  * `__stubs` e `__stubs_helper`: Envolvidos durante o processo de carregamento de biblioteca dinâmica
* **`__DATA`**: Contém dados que são **graváveis**.
  * `__data`: Variáveis globais (que foram inicializadas)
  * `__bss`: Variáveis estáticas (que não foram inicializadas)
  * `__objc_*` (\_\_objc\_classlist, \_\_objc\_protolist, etc): Informações usadas pelo tempo de execução do Objective-C
* **`__LINKEDIT`**: Contém informações para o linker (dyld) como, "símbolo, string e entradas de tabela de realocação."
* **`__OBJC`**: Contém informações usadas pelo tempo de execução do Objective-C. Embora essas informações também possam ser encontradas no segmento \_\_DATA, dentro de várias seções \_\_objc\_\*.

### **`LC_MAIN`**

Contém o ponto de entrada no atributo **entryoff.** No momento do carregamento, **dyld** simplesmente **adiciona** esse valor à **base do binário na memória**, então **salta** para esta instrução para iniciar a execução do código binário.

### **LC\_CODE\_SIGNATURE**

Contém informações sobre a **assinatura de código do arquivo Macho-O**. Ele contém apenas um **deslocamento** que **aponta** para o **bloco de assinatura**. Isso geralmente está no final do arquivo.

### **LC\_LOAD\_DYLINKER**

Contém o **caminho para o executável do linker dinâmico** que mapeia bibliotecas compartilhadas no espaço de endereço do processo. O **valor é sempre definido como `/usr/lib/dyld`**. É importante observar que no macOS, o mapeamento de dylib acontece em **modo de usuário**, não em modo de kernel.

### **`LC_LOAD_DYLIB`**

Este comando de carregamento descreve uma **dependência de biblioteca dinâmica** que **instrui** o **carregador** (dyld) a **carregar e vincular a biblioteca**. Há um comando de carregamento LC\_LOAD\_DYLIB **para cada biblioteca** que o binário Mach-O requer.

* Este comando de carregamento é uma estrutura do tipo **`dylib_command`** (que contém uma estrutura dylib, descrevendo a biblioteca dinâmica dependente real):
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
Você também pode obter essas informações a partir da linha de comando com:
```bash
otool -L /bin/ls
/bin/ls:
	/usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
	/usr/lib/libncurses.5.4.dylib (compatibility version 5.4.0, current version 5.4.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1319.0.0)
```
Algumas bibliotecas potencialmente relacionadas a malwares são:

* **DiskArbitration**: Monitoramento de unidades USB
* **AVFoundation:** Captura de áudio e vídeo
* **CoreWLAN**: Escaneamento de Wi-Fi.

{% hint style="info" %}
Um binário Mach-O pode conter um ou **mais** **construtores**, que serão **executados** **antes** do endereço especificado em **LC\_MAIN**.\
Os offsets de quaisquer construtores são mantidos na seção **\_\_mod\_init\_func** do segmento **\_\_DATA\_CONST**.
{% endhint %}

## **Dados Mach-O**

O coração do arquivo é a região final, os dados, que consiste em vários segmentos conforme disposto na região de comandos de carga. **Cada segmento pode conter várias seções de dados**. Cada uma dessas seções **contém código ou dados** de um tipo específico.

{% hint style="success" %}
Os dados são basicamente a parte que contém todas as informações carregadas pelos comandos de carga LC\_SEGMENTS\_64
{% endhint %}

![](<../../../.gitbook/assets/image (507) (3).png>)

Isso inclui:&#x20;

* **Tabela de funções:** Que contém informações sobre as funções do programa.
* **Tabela de símbolos**: Que contém informações sobre as funções externas usadas pelo binário
* Também pode conter nomes de funções internas, variáveis e mais.

Para verificar, você pode usar a ferramenta [**Mach-O View**](https://sourceforge.net/projects/machoview/):

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Ou pelo cli:
```bash
size -m /bin/ls
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
