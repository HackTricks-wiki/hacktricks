# Partições/Sistemas de Arquivos/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partições

Um disco rígido ou um **SSD pode conter diferentes partições** com o objetivo de separar dados fisicamente.\
A **unidade mínima** de um disco é o **setor** (normalmente composto por 512B). Portanto, cada tamanho de partição precisa ser múltiplo desse tamanho.

### MBR (master Boot Record)

Ele é alocado no **primeiro setor do disco após os 446B do código de inicialização**. Este setor é essencial para indicar ao PC o que e de onde uma partição deve ser montada.\
Permite até **4 partições** (no máximo **apenas 1** pode ser ativa/**inicializável**). No entanto, se você precisar de mais partições, pode usar **partições estendidas**. O **último byte** deste primeiro setor é a assinatura do registro de inicialização **0x55AA**. Apenas uma partição pode ser marcada como ativa.\
MBR permite **máx 2.2TB**.

![](<../../../images/image (350).png>)

![](<../../../images/image (304).png>)

Dos **bytes 440 a 443** do MBR, você pode encontrar a **Assinatura do Disco do Windows** (se o Windows estiver em uso). A letra da unidade lógica do disco rígido depende da Assinatura do Disco do Windows. Alterar essa assinatura pode impedir o Windows de inicializar (ferramenta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../images/image (310).png>)

**Formato**

| Offset      | Comprimento | Item                |
| ----------- | ----------- | ------------------- |
| 0 (0x00)    | 446(0x1BE)  | Código de inicialização           |
| 446 (0x1BE) | 16 (0x10)   | Primeira Partição     |
| 462 (0x1CE) | 16 (0x10)   | Segunda Partição    |
| 478 (0x1DE) | 16 (0x10)   | Terceira Partição     |
| 494 (0x1EE) | 16 (0x10)   | Quarta Partição    |
| 510 (0x1FE) | 2 (0x2)     | Assinatura 0x55 0xAA |

**Formato do Registro da Partição**

| Offset    | Comprimento | Item                                                   |
| --------- | ----------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01)   | Sinalizador ativo (0x80 = inicializável)                          |
| 1 (0x01)  | 1 (0x01)   | Cabeça de início                                             |
| 2 (0x02)  | 1 (0x01)   | Setor de início (bits 0-5); bits superiores do cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01)   | Cilindro de início, 8 bits mais baixos                           |
| 4 (0x04)  | 1 (0x01)   | Código do tipo de partição (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01)   | Cabeça de fim                                               |
| 6 (0x06)  | 1 (0x01)   | Setor de fim (bits 0-5); bits superiores do cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01)   | Cilindro de fim, 8 bits mais baixos                             |
| 8 (0x08)  | 4 (0x04)   | Setores precedendo a partição (little endian)            |
| 12 (0x0C) | 4 (0x04)   | Setores na partição                                   |

Para montar um MBR no Linux, você primeiro precisa obter o deslocamento de início (você pode usar `fdisk` e o comando `p`)

![](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

E então use o seguinte código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Endereçamento de bloco lógico)**

**Endereçamento de bloco lógico** (**LBA**) é um esquema comum usado para **especificar a localização de blocos** de dados armazenados em dispositivos de armazenamento de computador, geralmente sistemas de armazenamento secundário, como discos rígidos. LBA é um esquema de endereçamento linear particularmente simples; **os blocos são localizados por um índice inteiro**, com o primeiro bloco sendo LBA 0, o segundo LBA 1, e assim por diante.

### GPT (Tabela de Partição GUID)

A Tabela de Partição GUID, conhecida como GPT, é favorecida por suas capacidades aprimoradas em comparação ao MBR (Registro de Inicialização Mestre). Distintiva por seu **identificador único global** para partições, a GPT se destaca de várias maneiras:

- **Localização e Tamanho**: Tanto a GPT quanto a MBR começam no **setor 0**. No entanto, a GPT opera em **64 bits**, contrastando com os 32 bits da MBR.
- **Limites de Partição**: A GPT suporta até **128 partições** em sistemas Windows e acomoda até **9,4ZB** de dados.
- **Nomes de Partição**: Oferece a capacidade de nomear partições com até 36 caracteres Unicode.

**Resiliência e Recuperação de Dados**:

- **Redundância**: Ao contrário da MBR, a GPT não confina os dados de partição e inicialização a um único lugar. Ela replica esses dados em todo o disco, melhorando a integridade e resiliência dos dados.
- **Verificação de Redundância Cíclica (CRC)**: A GPT emprega CRC para garantir a integridade dos dados. Ela monitora ativamente a corrupção de dados e, quando detectada, a GPT tenta recuperar os dados corrompidos de outra localização no disco.

**MBR Protetora (LBA0)**:

- A GPT mantém compatibilidade retroativa através de um MBR protetora. Este recurso reside no espaço MBR legado, mas é projetado para evitar que utilitários mais antigos baseados em MBR sobrescrevam acidentalmente discos GPT, protegendo assim a integridade dos dados em discos formatados em GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**MBR Híbrido (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Em sistemas operacionais que suportam **inicialização baseada em GPT através de serviços BIOS** em vez de EFI, o primeiro setor também pode ser usado para armazenar a primeira etapa do código do **bootloader**, mas **modificado** para reconhecer **partições GPT**. O bootloader na MBR não deve assumir um tamanho de setor de 512 bytes.

**Cabeçalho da tabela de partição (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

O cabeçalho da tabela de partição define os blocos utilizáveis no disco. Ele também define o número e o tamanho das entradas de partição que compõem a tabela de partição (offsets 80 e 84 na tabela).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Assinatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)em máquinas little-endian) |
| 8 (0x08)  | 4 bytes  | Revisão 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Tamanho do cabeçalho em little endian (em bytes, geralmente 5Ch 00h 00h 00h ou 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) do cabeçalho (offset +0 até o tamanho do cabeçalho) em little endian, com este campo zerado durante o cálculo                             |
| 20 (0x14) | 4 bytes  | Reservado; deve ser zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | LBA atual (localização desta cópia do cabeçalho)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | LBA de backup (localização da outra cópia do cabeçalho)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Primeiro LBA utilizável para partições (último LBA da tabela de partição primária + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Último LBA utilizável (primeiro LBA da tabela de partição secundária − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | GUID do disco em endian misto                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | LBA inicial de um array de entradas de partição (sempre 2 na cópia primária)                                                                                                     |
| 80 (0x50) | 4 bytes  | Número de entradas de partição no array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Tamanho de uma única entrada de partição (geralmente 80h ou 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 do array de entradas de partição em little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reservado; deve ser zeros para o restante do bloco (420 bytes para um tamanho de setor de 512 bytes; mas pode ser mais com tamanhos de setor maiores)                                      |

**Entradas de partição (LBA 2–33)**

| Formato de entrada de partição GUID |          |                                                                                                               |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                               | Length   | Contents                                                                                                      |
| 0 (0x00)                             | 16 bytes | [Tipo de partição GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (endian misto) |
| 16 (0x10)                            | 16 bytes | GUID de partição único (endian misto)                                                                          |
| 32 (0x20)                            | 8 bytes  | Primeiro LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                            | 8 bytes  | Último LBA (inclusivo, geralmente ímpar)                                                                             |
| 48 (0x30)                            | 8 bytes  | Flags de atributo (por exemplo, o bit 60 denota somente leitura)                                                               |
| 56 (0x38)                            | 72 bytes | Nome da partição (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE unidades de código)                               |

**Tipos de Partições**

![](<../../../images/image (83).png>)

Mais tipos de partições em [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspecionando

Após montar a imagem forense com [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), você pode inspecionar o primeiro setor usando a ferramenta do Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na imagem a seguir, um **MBR** foi detectado no **setor 0** e interpretado:

![](<../../../images/image (354).png>)

Se fosse uma **tabela GPT em vez de um MBR**, deveria aparecer a assinatura _EFI PART_ no **setor 1** (que na imagem anterior está vazio).

## Sistemas de Arquivos

### Lista de sistemas de arquivos do Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

O sistema de arquivos **FAT (Tabela de Alocação de Arquivos)** é projetado em torno de seu componente central, a tabela de alocação de arquivos, posicionada no início do volume. Este sistema protege os dados mantendo **duas cópias** da tabela, garantindo a integridade dos dados mesmo se uma estiver corrompida. A tabela, juntamente com a pasta raiz, deve estar em uma **localização fixa**, crucial para o processo de inicialização do sistema.

A unidade básica de armazenamento do sistema de arquivos é um **cluster, geralmente 512B**, composto por vários setores. O FAT evoluiu através de versões:

- **FAT12**, suportando endereços de cluster de 12 bits e lidando com até 4078 clusters (4084 com UNIX).
- **FAT16**, aprimorando para endereços de 16 bits, acomodando assim até 65.517 clusters.
- **FAT32**, avançando ainda mais com endereços de 32 bits, permitindo impressionantes 268.435.456 clusters por volume.

Uma limitação significativa em todas as versões do FAT é o **tamanho máximo de arquivo de 4GB**, imposto pelo campo de 32 bits usado para armazenamento do tamanho do arquivo.

Os componentes principais do diretório raiz, particularmente para FAT12 e FAT16, incluem:

- **Nome do Arquivo/Pasta** (até 8 caracteres)
- **Atributos**
- **Datas de Criação, Modificação e Último Acesso**
- **Endereço da Tabela FAT** (indicando o cluster inicial do arquivo)
- **Tamanho do Arquivo**

### EXT

**Ext2** é o sistema de arquivos mais comum para **partições que não fazem journaling** (**partições que não mudam muito**) como a partição de inicialização. **Ext3/4** são **journaling** e são usados geralmente para as **demais partições**.

## **Metadados**

Alguns arquivos contêm metadados. Essas informações são sobre o conteúdo do arquivo que às vezes podem ser interessantes para um analista, pois dependendo do tipo de arquivo, pode conter informações como:

- Título
- Versão do MS Office utilizada
- Autor
- Datas de criação e última modificação
- Modelo da câmera
- Coordenadas GPS
- Informações da imagem

Você pode usar ferramentas como [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) para obter os metadados de um arquivo.

## **Recuperação de Arquivos Excluídos**

### Arquivos Excluídos Registrados

Como foi visto anteriormente, há vários lugares onde o arquivo ainda está salvo após ter sido "excluído". Isso ocorre porque geralmente a exclusão de um arquivo de um sistema de arquivos apenas o marca como excluído, mas os dados não são tocados. Assim, é possível inspecionar os registros dos arquivos (como o MFT) e encontrar os arquivos excluídos.

Além disso, o sistema operacional geralmente salva muitas informações sobre alterações no sistema de arquivos e backups, então é possível tentar usá-las para recuperar o arquivo ou o máximo de informações possível.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** é uma técnica que tenta **encontrar arquivos na massa de dados**. Existem 3 maneiras principais pelas quais ferramentas como essa funcionam: **Baseadas em cabeçalhos e rodapés de tipos de arquivo**, baseadas em **estruturas** de tipos de arquivo e baseadas no **conteúdo** em si.

Observe que essa técnica **não funciona para recuperar arquivos fragmentados**. Se um arquivo **não estiver armazenado em setores contíguos**, então essa técnica não será capaz de encontrá-lo ou pelo menos parte dele.

Existem várias ferramentas que você pode usar para file carving indicando os tipos de arquivo que deseja pesquisar.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Carving de Fluxo de Dados

Carving de Fluxo de Dados é semelhante ao File Carving, mas **em vez de procurar arquivos completos, procura fragmentos interessantes** de informação.\
Por exemplo, em vez de procurar um arquivo completo contendo URLs registradas, essa técnica irá procurar por URLs.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Exclusão Segura

Obviamente, existem maneiras de **"excluir com segurança" arquivos e parte dos logs sobre eles**. Por exemplo, é possível **sobrescrever o conteúdo** de um arquivo com dados aleatórios várias vezes e, em seguida, **remover** os **logs** do **$MFT** e **$LOGFILE** sobre o arquivo, e **remover as Cópias de Sombra do Volume**.\
Você pode notar que mesmo realizando essa ação, pode haver **outras partes onde a existência do arquivo ainda está registrada**, e isso é verdade, e parte do trabalho do profissional de forense é encontrá-las.

## Referências

- [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
- [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- **iHackLabs Certified Digital Forensics Windows**

{{#include ../../../banners/hacktricks-training.md}}
