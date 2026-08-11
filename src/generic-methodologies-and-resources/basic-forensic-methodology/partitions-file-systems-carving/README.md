# Partições/Sistemas de Arquivos/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partições

Um disco rígido ou um **disco SSD pode conter diferentes partições** com o objetivo de separar os dados fisicamente.\
A unidade **mínima** de um disco é o **setor** (normalmente composto por 512B). Portanto, o tamanho de cada partição precisa ser múltiplo desse tamanho.

### MBR (master Boot Record)

Ele é alocado no **primeiro setor do disco, após os 446B do código de boot**. Esse setor é essencial para indicar ao PC qual partição deve ser montada e de onde.\
Ele permite até **4 partições** (no máximo **apenas 1** pode estar ativa/**bootable**). No entanto, se você precisar de mais partições, poderá usar **extended partitions**. O **byte final** desse primeiro setor é a assinatura do registro de boot **0x55AA**. Apenas uma partição pode ser marcada como ativa.\
O MBR permite no máximo **2.2TB**.

![Partições - MBR (master Boot Record): O MBR permite no máximo 2.2TB](<../../../images/image (350).png>)

![Partições - MBR (master Boot Record): O MBR permite no máximo 2.2TB](<../../../images/image (304).png>)

Dos **bytes 440 a 443** do MBR, você pode encontrar a **Windows Disk Signature** (se o Windows estiver sendo usado). A letra da unidade lógica do disco rígido depende da Windows Disk Signature. Alterar essa assinatura pode impedir o boot do Windows (ferramenta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partições - MBR (master Boot Record): Dos bytes 440 a 443 do MBR, você pode encontrar a Windows Disk Signature (se o Windows estiver sendo usado). A letra da unidade lógica do disco rígido...](<../../../images/image (310).png>)

**Formato**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de boot      |
| 446 (0x1BE) | 16 (0x10)  | Primeira partição   |
| 462 (0x1CE) | 16 (0x10)  | Segunda partição    |
| 478 (0x1DE) | 16 (0x10)  | Terceira partição   |
| 494 (0x1EE) | 16 (0x10)  | Quarta partição     |
| 510 (0x1FE) | 2 (0x2)    | Assinatura 0x55 0xAA |

**Formato do registro de partição**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Sinalizador ativo (0x80 = bootable)                    |
| 1 (0x01)  | 1 (0x01) | Cabeça inicial                                        |
| 2 (0x02)  | 1 (0x01) | Setor inicial (bits 0-5); bits superiores do cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | 8 bits inferiores do cilindro inicial                 |
| 4 (0x04)  | 1 (0x01) | Código do tipo de partição (0x83 = Linux)             |
| 5 (0x05)  | 1 (0x01) | Cabeça final                                           |
| 6 (0x06)  | 1 (0x01) | Setor final (bits 0-5); bits superiores do cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01) | 8 bits inferiores do cilindro final                    |
| 8 (0x08)  | 4 (0x04) | Setores anteriores à partição (little endian)          |
| 12 (0x0C) | 4 (0x04) | Setores na partição                                    |

Para montar um MBR no Linux, primeiro você precisa obter o offset inicial (você pode usar `fdisk` e o comando `p`)

![Partições - MBR (master Boot Record): Para montar um MBR no Linux, primeiro você precisa obter o offset inicial (você pode usar fdisk e o comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Em seguida, use o código a seguir
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) é um esquema comum usado para **especificar a localização de blocos** de dados armazenados em dispositivos de armazenamento de computadores, geralmente sistemas de armazenamento secundário, como unidades de disco rígido. LBA é um esquema de endereçamento linear particularmente simples; **os blocos são localizados por um índice inteiro**, sendo o primeiro bloco LBA 0, o segundo LBA 1 e assim por diante.

### GPT (GUID Partition Table)

A GUID Partition Table, conhecida como GPT, é preferida por seus recursos aprimorados em comparação com MBR (Master Boot Record). Caracterizada por seu **identificador globalmente exclusivo** para partições, a GPT se destaca de várias maneiras:

- **Localização e tamanho**: tanto GPT quanto MBR começam no **setor 0**. No entanto, a GPT opera com **64bits**, em contraste com os 32bits do MBR.
- **Limites de partições**: a GPT suporta até **128 partições** em sistemas Windows e acomoda até **9.4ZB** de dados.
- **Nomes de partições**: oferece a possibilidade de nomear partições com até 36 caracteres Unicode.

**Resiliência e recuperação de dados**:

- **Redundância**: diferentemente do MBR, a GPT não confina os dados de particionamento e boot a um único local. Ela replica esses dados por todo o disco, melhorando a integridade e a resiliência dos dados.
- **Cyclic Redundancy Check (CRC)**: a GPT utiliza CRC para garantir a integridade dos dados. Ela monitora ativamente a corrupção de dados e, quando detectada, tenta recuperar os dados corrompidos de outro local do disco.

**Protective MBR (LBA0)**:

- A GPT mantém compatibilidade retroativa por meio de um protective MBR. Esse recurso reside no espaço do MBR legado, mas foi projetado para impedir que utilitários antigos baseados em MBR sobrescrevam discos GPT por engano, protegendo assim a integridade dos dados em discos formatados com GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Em sistemas operacionais que oferecem suporte a **boot baseado em GPT por meio de serviços BIOS**, em vez de EFI, o primeiro setor também pode continuar sendo usado para armazenar o código do primeiro estágio do **bootloader**, mas **modificado** para reconhecer **partições** **GPT**. O bootloader no MBR não deve presumir um tamanho de setor de 512 bytes.

**Partition table header (LBA 1)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

O cabeçalho da tabela de partições define os blocos utilizáveis no disco. Ele também define o número e o tamanho das entradas de partição que compõem a tabela de partições (offsets 80 e 84 na tabela).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Assinatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)em máquinas little-endian) |
| 8 (0x08)  | 4 bytes  | Revisão 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Tamanho do cabeçalho em little endian (em bytes, geralmente 5Ch 00h 00h 00h ou 92 bytes)                                                                                     |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) do cabeçalho (offset +0 até o tamanho do cabeçalho) em little endian, com este campo zerado durante o cálculo                    |
| 20 (0x14) | 4 bytes  | Reservado; deve ser zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | LBA atual (localização desta cópia do cabeçalho)                                                                                                                              |
| 32 (0x20) | 8 bytes  | LBA de backup (localização da outra cópia do cabeçalho)                                                                                                                       |
| 40 (0x28) | 8 bytes  | Primeiro LBA utilizável para partições (último LBA da tabela de partições primária + 1)                                                                                       |
| 48 (0x30) | 8 bytes  | Último LBA utilizável (primeiro LBA da tabela de partições secundária − 1)                                                                                                    |
| 56 (0x38) | 16 bytes | GUID do disco em mixed endian                                                                                                                                                  |
| 72 (0x48) | 8 bytes  | LBA inicial de um array de entradas de partição (sempre 2 na cópia primária)                                                                                                  |
| 80 (0x50) | 4 bytes  | Número de entradas de partição no array                                                                                                                                       |
| 84 (0x54) | 4 bytes  | Tamanho de uma única entrada de partição (geralmente 80h ou 128)                                                                                                              |
| 88 (0x58) | 4 bytes  | CRC32 do array de entradas de partição em little endian                                                                                                                       |
| 92 (0x5C) | \*       | Reservado; deve conter zeros no restante do bloco (420 bytes para um tamanho de setor de 512 bytes; mas pode ser maior com tamanhos de setor maiores)                         |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID do tipo de partição](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | GUID exclusivo da partição (mixed endian)                                                                      |
| 32 (0x20)                   | 8 bytes  | Primeiro LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Último LBA (inclusive, geralmente ímpar)                                                                         |
| 48 (0x30)                   | 8 bytes  | Flags de atributos (por exemplo, o bit 60 indica somente leitura)                                                |
| 56 (0x38)                   | 72 bytes | Nome da partição (36 unidades de código [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                        |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Nome da partição (36 unidades de código UTF-16LE)](<../../../images/image (83).png>)

Mais tipos de partição em [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspecting

Após montar a imagem forense com o [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), você pode inspecionar o primeiro setor usando a ferramenta do Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na imagem a seguir, um **MBR** foi detectado no **setor 0** e interpretado:

![GPT (GUID Partition Table) - Inspeção: após montar a imagem forense com o ArsenalImageMounter, você pode inspecionar o primeiro setor usando a ferramenta do Windows Active Disk Editor. Na...](<../../../images/image (354).png>)

Se fosse uma **tabela GPT em vez de um MBR**, a assinatura _EFI PART_ deveria aparecer no **setor 1** (que está vazio na imagem anterior).

## Sistemas de arquivos

### Lista de sistemas de arquivos do Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

O sistema de arquivos **FAT (File Allocation Table)** é projetado em torno de seu componente principal, a file allocation table, localizada no início do volume. Esse sistema protege os dados mantendo **duas cópias** da tabela, garantindo a integridade dos dados mesmo que uma delas seja corrompida. A tabela, juntamente com a pasta raiz, deve estar em uma **localização fixa**, algo essencial para o processo de inicialização do sistema.

A unidade básica de armazenamento do sistema de arquivos é um **cluster, geralmente de 512B**, composto por vários setores. O FAT evoluiu por meio das seguintes versões:

- **FAT12**, compatível com endereços de cluster de 12 bits e capaz de lidar com até 4078 clusters (4084 com UNIX).
- **FAT16**, expandindo para endereços de 16 bits e acomodando até 65.517 clusters.
- **FAT32**, avançando para endereços de 32 bits e permitindo impressionantes 268.435.456 clusters por volume.

Uma limitação significativa comum a todas as versões do FAT é o **tamanho máximo de arquivo de 4GB**, imposto pelo campo de 32 bits usado para armazenar o tamanho do arquivo.

Os principais componentes do diretório raiz, especialmente no FAT12 e FAT16, incluem:

- **Nome do arquivo/pasta** (até 8 caracteres)
- **Atributos**
- **Datas de criação, modificação e último acesso**
- **Endereço da tabela FAT** (indicando o cluster inicial do arquivo)
- **Tamanho do arquivo**

### EXT

O **Ext2** é o sistema de arquivos mais comum para partições **sem journaling** (**partições que não mudam muito**), como a partição de boot. **Ext3/4** possuem **journaling** e geralmente são usados para as **demais partições**.

## **Metadata**

Alguns arquivos contêm metadata. Essas informações dizem respeito ao conteúdo do arquivo e, às vezes, podem ser interessantes para um analista, pois, dependendo do tipo de arquivo, podem conter informações como:

- Título
- Versão do MS Office utilizada
- Autor
- Datas de criação e da última modificação
- Modelo da câmera
- Coordenadas GPS
- Informações da imagem

Você pode usar ferramentas como [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obter os metadados de um arquivo.

## **Recuperação de arquivos excluídos**

### Arquivos excluídos registrados

Como visto anteriormente, existem vários locais onde o arquivo ainda é salvo depois de ser "excluído". Isso ocorre porque, geralmente, a exclusão de um arquivo de um sistema de arquivos apenas o marca como excluído, mas os dados não são alterados. Assim, é possível inspecionar os registros dos arquivos (como o MFT) e encontrar os arquivos excluídos.<sup>[[2]](#references)</sup>

Além disso, o sistema operacional geralmente salva muitas informações sobre alterações e backups do sistema de arquivos, portanto, é possível tentar usá-las para recuperar o arquivo ou o máximo possível de informações.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** é uma técnica que tenta **encontrar arquivos no conjunto bruto de dados**. Existem 3 maneiras principais pelas quais ferramentas desse tipo funcionam: **com base nos headers e footers dos tipos de arquivo**, com base nas **estruturas** dos tipos de arquivo e com base no próprio **conteúdo**.

Observe que essa técnica **não funciona para recuperar arquivos fragmentados**. Se um arquivo **não estiver armazenado em setores contíguos**, essa técnica não conseguirá encontrá-lo, ou encontrará apenas parte dele.

Existem várias ferramentas que podem ser usadas para File Carving, indicando os tipos de arquivo que você deseja pesquisar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving é semelhante ao File Carving, mas **em vez de procurar arquivos completos, procura fragmentos interessantes** de informações.\
Por exemplo, em vez de procurar um arquivo completo contendo URLs registradas, essa técnica procurará URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Obviamente, existem maneiras de **excluir arquivos e partes dos logs sobre eles de forma "segura"**. Por exemplo, é possível **sobrescrever o conteúdo** de um arquivo com dados aleatórios várias vezes, depois **remover** os **logs** do **$MFT** e do **$LOGFILE** sobre o arquivo e **remover as Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Você pode notar que, mesmo realizando essa ação, pode haver **outras partes onde a existência do arquivo ainda esteja registrada**, e isso é verdade; parte do trabalho do profissional de forensics é encontrá-las.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Como verificar entradas NTFS $I30 (diretório) em busca de evidências de arquivos excluídos](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
