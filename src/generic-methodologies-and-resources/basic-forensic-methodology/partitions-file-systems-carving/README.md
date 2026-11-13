# Partições/Sistemas de arquivos/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partições

Um disco pode conter várias **partições**: intervalos lógicos de blocos, não áreas de armazenamento fisicamente separadas. O início e o tamanho das partições são medidos em **setores lógicos**; não presuma que todas as imagens usam setores de 512 bytes, pois também existem setores lógicos de 4096 bytes.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

O MBR ocupa o primeiro setor lógico (LBA 0); suas quatro entradas de partição de 16 bytes começam no byte 446. A área anterior inclui o código de inicialização e pode incluir uma assinatura de disco.<sup>[[4]](#references)</sup>\
Ele permite até **4 partições** (no máximo **apenas 1** pode estar ativa/**inicializável**). No entanto, se precisar de mais partições, você pode usar **partições estendidas**. Os **dois últimos bytes** do MBR de 512 bytes são a assinatura de inicialização **0x55 0xAA**. Apenas uma partição pode ser marcada como ativa.\
Com setores lógicos de 512 bytes, os campos de setor de 32 bits do MBR limitam o endereçamento a cerca de **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Partições - MBR (master Boot Record): o MBR permite no máximo 2,2 TB](<../../../images/image (350).png>)

![Partições - MBR (master Boot Record): o MBR permite no máximo 2,2 TB](<../../../images/image (304).png>)

Nos **bytes 440 a 443** do MBR, você pode encontrar a **Windows Disk Signature** (se o Windows estiver sendo usado). A letra da unidade lógica do disco rígido depende da Windows Disk Signature. Alterar essa assinatura pode impedir a inicialização do Windows (ferramenta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partições - MBR (master Boot Record): nos bytes 440 a 443 do MBR, você pode encontrar a Windows Disk Signature (se o Windows estiver sendo usado). A letra da unidade lógica do disco rígido...](<../../../images/image (310).png>)

**Formato**

| Deslocamento | Tamanho    | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de inicialização |
| 446 (0x1BE) | 16 (0x10)  | Primeira partição   |
| 462 (0x1CE) | 16 (0x10)  | Segunda partição    |
| 478 (0x1DE) | 16 (0x10)  | Terceira partição   |
| 494 (0x1EE) | 16 (0x10)  | Quarta partição     |
| 510 (0x1FE) | 2 (0x2)    | Assinatura 0x55 0xAA |

**Formato do registro da partição**

| Deslocamento | Tamanho  | Item                                                        |
| --------- | -------- | ----------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Sinalizador ativo (0x80 = inicializável)                    |
| 1 (0x01)  | 1 (0x01) | Cabeçote inicial                                           |
| 2 (0x02)  | 1 (0x01) | Setor inicial (bits 0-5); bits superiores do cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | 8 bits inferiores do cilindro inicial                      |
| 4 (0x04)  | 1 (0x01) | Código do tipo de partição (0x83 = Linux)                   |
| 5 (0x05)  | 1 (0x01) | Cabeçote final                                             |
| 6 (0x06)  | 1 (0x01) | Setor final (bits 0-5); bits superiores do cilindro (6- 7)  |
| 7 (0x07)  | 1 (0x01) | 8 bits inferiores do cilindro final                        |
| 8 (0x08)  | 4 (0x04) | Setores anteriores à partição (little endian)               |
| 12 (0x0C) | 4 (0x04) | Setores na partição                                         |

Para inspecionar uma partição em uma imagem MBR de disco inteiro, primeiro obtenha o LBA inicial e o tamanho do setor lógico. `mount` recebe um **deslocamento em bytes**, não um LBA; o exemplo abaixo só é válido para uma imagem com setores de 512 bytes cuja partição começa no LBA 63. Para imagens não confiáveis ou sistemas de arquivos com journaling, use o fluxo de trabalho isolado e somente leitura em [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partições - MBR (master Boot Record): para montar um MBR no Linux, primeiro você precisa obter o deslocamento inicial (você pode usar fdisk e o comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (endereçamento lógico de blocos)**

**Endereçamento lógico de blocos** (**LBA**) é um esquema comum usado para **especificar a localização de blocos** de dados armazenados em dispositivos de armazenamento de computadores, geralmente sistemas de armazenamento secundário, como discos rígidos. LBA é um esquema de endereçamento linear particularmente simples; **os blocos são localizados por um índice inteiro**, sendo o primeiro bloco LBA 0, o segundo LBA 1 e assim por diante.

### GPT (GUID Partition Table)

A GUID Partition Table (GPT) armazena um GUID exclusivo para cada partição e usa metadados primários e de backup. Seu layout difere do MBR da seguinte forma:<sup>[[4]](#references)</sup>

- **Localização e tamanho**: LBA 0 contém um **MBR protetor**. O cabeçalho GPT primário fica em LBA 1; o array de entradas de partição vem em seguida, e um array e um cabeçalho de backup ficam no final do disco. GPT usa campos LBA de 64 bits, enquanto as entradas de partição MBR usam campos LBA de 32 bits.
- **Limites de partição**: Um array de entradas comum de 16 KiB contém **128 entradas de 128 bytes**, mas a quantidade de entradas é registrada no cabeçalho, em vez de ser fixada pela GPT. O tamanho endereçável também depende do tamanho do setor lógico (cerca de **9,4 ZB** com setores de 512 bytes).<sup>[[4]](#references)</sup>
- **Nomes de partição**: Permite nomear partições com até 36 caracteres Unicode.

**Resiliência e recuperação de dados**:

- **Redundância**: Ao contrário do MBR, GPT não restringe os dados de particionamento e inicialização a um único local. Ela replica esses dados no disco, aumentando a integridade e a resiliência dos dados.
- **Verificação de redundância cíclica (CRC)**: O cabeçalho e o array de entradas de partição têm, cada um, um CRC32. Um CRC detecta inconsistências; ele não monitora continuamente nem repara o disco por conta própria. Se a cópia primária for inválida, valide o backup no último LBA antes de qualquer recuperação em uma cópia de trabalho.<sup>[[4]](#references)</sup>

**MBR protetor (LBA0)**:

- GPT mantém a compatibilidade com versões anteriores por meio de um MBR protetor. Esse recurso fica no espaço do MBR legado, mas foi projetado para impedir que utilitários antigos baseados em MBR sobrescrevam por engano discos GPT, protegendo assim a integridade dos dados em discos formatados com GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**MBR híbrido (LBA 0 + GPT)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Em sistemas operacionais que oferecem suporte à **inicialização baseada em GPT por meio** de serviços **BIOS**, em vez de EFI, o primeiro setor também pode continuar sendo usado para armazenar o código do primeiro estágio do **bootloader**, mas **modificado** para reconhecer **partições** **GPT**. O bootloader no MBR não deve presumir um tamanho de setor de 512 bytes.

**Cabeçalho da tabela de partições (LBA 1)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

O cabeçalho da tabela de partições define os blocos utilizáveis no disco. Ele também define a quantidade e o tamanho das entradas de partição que compõem a tabela de partições (deslocamentos 80 e 84 na tabela).

| Deslocamento | Tamanho  | Conteúdo                                                                                                                                                                    |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Assinatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)em máquinas little-endian) |
| 8 (0x08)  | 4 bytes  | Revisão 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Tamanho do cabeçalho em little-endian (em bytes, geralmente 5Ch 00h 00h 00h ou 92 bytes)                                                                                     |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) do cabeçalho (deslocamento +0 até o tamanho do cabeçalho) em little-endian, com este campo zerado durante o cálculo                |
| 20 (0x14) | 4 bytes  | Reservado; deve ser zero                                                                                                                                                      |
| 24 (0x18) | 8 bytes  | LBA atual (localização desta cópia do cabeçalho)                                                                                                                             |
| 32 (0x20) | 8 bytes  | LBA de backup (localização da outra cópia do cabeçalho)                                                                                                                      |
| 40 (0x28) | 8 bytes  | Primeiro LBA utilizável para partições (último LBA da tabela de partições primária + 1)                                                                                       |
| 48 (0x30) | 8 bytes  | Último LBA utilizável (primeiro LBA da tabela de partições secundária − 1)                                                                                                    |
| 56 (0x38) | 16 bytes | GUID do disco em formato mixed-endian                                                                                                                                        |
| 72 (0x48) | 8 bytes  | LBA inicial de um array de entradas de partição (sempre 2 na cópia primária)                                                                                                 |
| 80 (0x50) | 4 bytes  | Quantidade de entradas de partição no array                                                                                                                                  |
| 84 (0x54) | 4 bytes  | Tamanho de uma única entrada de partição (geralmente 80h ou 128)                                                                                                             |
| 88 (0x58) | 4 bytes  | CRC32 do array de entradas de partição em little-endian                                                                                                                      |
| 92 (0x5C) | \*       | Reservado; deve ser zero no restante do bloco (420 bytes para um tamanho de setor de 512 bytes; pode ser maior com tamanhos de setor maiores)                                |

**Entradas de partição (LBA 2–33)**

| Formato de entrada de partição GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Deslocamento                      | Tamanho   | Conteúdo                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID do tipo de partição](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed-endian) |
| 16 (0x10)                   | 16 bytes | GUID exclusivo da partição (mixed-endian)                                                                      |
| 32 (0x20)                   | 8 bytes  | Primeiro LBA ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Último LBA (inclusivo, geralmente ímpar)                                                                        |
| 48 (0x30)                   | 8 bytes  | Sinalizadores de atributo (por exemplo, o bit 60 indica somente leitura)                                        |
| 56 (0x38)                   | 72 bytes | Nome da partição (36 unidades de código [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                     |

**Tipos de partição**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Nome da partição (36 unidades de código UTF-16LE)](<../../../images/image (83).png>)

Mais tipos de partição em [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspeção

Depois de montar a imagem forense com [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), você pode inspecionar o primeiro setor usando a ferramenta do Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na imagem a seguir, foi detectado um **MBR** no **setor 0** e ele foi interpretado:

![GPT (GUID Partition Table) - Inspeção: depois de montar a imagem forense com ArsenalImageMounter , você pode inspecionar o primeiro setor usando a ferramenta do Windows Active Disk Editor . Na...](<../../../images/image (354).png>)

Para GPT, procure a assinatura _EFI PART_ no cabeçalho primário em **LBA 1**; LBA 0 ainda contém o MBR protetor.<sup>[[4]](#references)</sup>

### Encontrar dados fora das partições listadas

Uma entrada de partição excluída ou um espaço deliberadamente não utilizado pode deixar um sistema de arquivos fora do mapa de partições atual. Em uma **cópia de trabalho bruta verificada**, liste os intervalos não alocados e, em seguida, teste um LBA inicial candidato como sistema de arquivos. `mmls` e `fsstat` usam **deslocamentos de setor**; informe a ambos o tamanho real do setor lógico. Não confunda setores de metadados GPT com um volume oculto.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Se o `fsstat` não conseguir identificar um sistema de arquivos no início do espaço vazio, use **Analyse → Quick Search** do TestDisk e, se necessário, **Deeper Search**. Pressione `P` em uma partição candidata para inspecionar os arquivos; não selecione **Write** nas evidências. Em imagens GPT, `sgdisk --verify disk.img` verifica os CRCs e a concordância entre as tabelas principal e de backup, mas um cabeçalho de backup pode estar desatualizado após o reparticionamento. Portanto, confirme os limites candidatos com estruturas do sistema de arquivos antes da recuperação.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Sistemas de arquivos

### Lista de sistemas de arquivos do Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

O sistema de arquivos **FAT (File Allocation Table)** é organizado em torno de seu componente principal, a tabela de alocação de arquivos, localizada no início do volume. Um volume geralmente tem **duas cópias da FAT**, embora o BPB permita apenas uma. FAT12/16 armazenam o diretório raiz em uma região fixa; FAT32 armazena o diretório raiz na área de dados, no cluster indicado por `BPB_RootClus`.<sup>[[7]](#references)</sup>

A unidade de alocação é um **cluster**: `BPB_BytsPerSec × BPB_SecPerClus`, que não necessariamente corresponde a 512 bytes. O tipo de FAT é determinado pelo número de clusters de dados, não por uma string de versão no setor de inicialização. Os limites de quantidade de clusters são:<sup>[[7]](#references)</sup>

- **FAT12**: menos de 4.085 clusters de dados.
- **FAT16**: de 4.085 a 65.524 clusters de dados.
- **FAT32**: pelo menos 65.525 clusters de dados; apenas 28 bits de cada entrada FAT de 32 bits são usados para o número do cluster.

O campo de tamanho de arquivo de 32 bits limita um arquivo regular a **2³²−1 bytes** (pouco menos de 4 GiB).<sup>[[7]](#references)</sup>

Os principais componentes do diretório raiz, especialmente em FAT12 e FAT16, incluem:

- **Nome do arquivo/pasta** (até 8 caracteres)
- **Atributos**
- **Datas de criação, modificação e último acesso**
- **Endereço da tabela FAT** (indica o cluster inicial do arquivo)
- **Tamanho do arquivo**

### EXT

**Ext2** é o sistema de arquivos mais comum em partições **sem journaling** (**partições que não mudam muito**), como a partição de inicialização. **Ext3/4** têm **journaling** e geralmente são usados nas **demais partições**.

## **Metadados**

Alguns arquivos contêm metadados. Essas informações dizem respeito ao conteúdo do arquivo e, às vezes, podem ser interessantes para um analista, pois, dependendo do tipo de arquivo, podem incluir:

- Título
- Versão do MS Office usada
- Autor
- Datas de criação e da última modificação
- Modelo da câmera
- Coordenadas GPS
- Informações da imagem

Você pode usar ferramentas como [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obter os metadados de um arquivo.

## **Recuperação de arquivos excluídos**

### Arquivos excluídos registrados

Como vimos anteriormente, há vários locais em que o arquivo continua salvo após ser "excluído". Isso acontece porque, geralmente, a exclusão de um arquivo de um sistema de arquivos apenas o marca como excluído, sem tocar nos dados. Assim, é possível inspecionar os registros dos arquivos (como a MFT) e encontrar os arquivos excluídos.<sup>[[2]](#references)</sup>

Além disso, o sistema operacional geralmente salva muitas informações sobre alterações no sistema de arquivos e backups. Portanto, é possível tentar usá-las para recuperar o arquivo ou o máximo possível de informações.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** é uma técnica que tenta **encontrar arquivos em grandes volumes de dados**. Há três maneiras principais de ferramentas desse tipo funcionarem: **com base em cabeçalhos e rodapés de tipos de arquivo**, em **estruturas** de tipos de arquivo e no **próprio conteúdo**.

O carving simples por cabeçalho/rodapé pressupõe blocos contíguos e pode retornar apenas um fragmento quando um arquivo está dividido. Essa limitação não é absoluta: o PhotoRec tem uma opção **Paranoid → bruteforce**, que exige bastante CPU, para alguns JPEGs fragmentados, enquanto a remontagem de fragmentos com reconhecimento de formato pode recuperar outros tipos compatíveis. Consulte [ferramentas de file carving e recuperação](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) para ver um fluxo de trabalho atualizado de remontagem de fragmentos.<sup>[[8]](#references)</sup>

Há várias ferramentas que você pode usar para fazer File Carving, indicando os tipos de arquivo que deseja procurar.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Data Stream Carving**

Data Stream Carving é semelhante a File Carving, mas **em vez de procurar arquivos completos, procura fragmentos de informação interessantes**.\
Por exemplo, em vez de procurar um arquivo completo que contenha URLs registradas, essa técnica procura URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Exclusão segura

Obviamente, há maneiras de **excluir arquivos de forma "segura" e apagar parte dos registros sobre eles**. Por exemplo, é possível **sobrescrever o conteúdo** de um arquivo com dados inúteis várias vezes e, em seguida, **remover** os **registros** do arquivo da **$MFT** e do **$LOGFILE**, além de **remover as Cópias de Sombra de Volume**.<sup>[[3]](#references)</sup>\
Você pode notar que, mesmo realizando essa ação, ainda pode haver **outros locais onde a existência do arquivo continua registrada**. Isso é verdade, e encontrar esses registros faz parte do trabalho de um profissional de perícia forense.



## References

- [1] [Tabela de Partição GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Como verificar entradas $I30 (diretório) do NTFS em busca de evidências de arquivos excluídos](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Serviço de Cópias de Sombra de Volume (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Especificação UEFI: layout de disco GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Manual do mmls do The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Manual do fsstat do The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Especificação FAT da Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Opções de recuperação do PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Recuperação de partições excluídas do TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Manual do sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Manual do mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
