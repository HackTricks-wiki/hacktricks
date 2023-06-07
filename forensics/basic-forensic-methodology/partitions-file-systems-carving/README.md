## Partições/Sistemas de Arquivos/Carving

Um disco rígido ou um **SSD pode conter diferentes partições** com o objetivo de separar fisicamente os dados.\
A **unidade mínima** de um disco é o **setor** (normalmente composto por 512B). Portanto, o tamanho de cada partição precisa ser múltiplo desse tamanho.

### MBR (Master Boot Record)

Ele é alocado no **primeiro setor do disco após os 446B do código de inicialização**. Este setor é essencial para indicar ao PC o que e de onde uma partição deve ser montada.\
Ele permite até **4 partições** (no máximo **apenas 1** pode ser ativa/inicializável). No entanto, se você precisar de mais partições, pode usar **partições estendidas**. O **último byte** deste primeiro setor é a assinatura do registro de inicialização **0x55AA**. Apenas uma partição pode ser marcada como ativa.\
MBR permite **máximo de 2,2TB**.

![](<../../../.gitbook/assets/image (489).png>)

![](<../../../.gitbook/assets/image (490).png>)

Do **byte 440 ao 443** do MBR, você pode encontrar a **Assinatura do Disco do Windows** (se o Windows for usado). A letra da unidade lógica do disco rígido depende da Assinatura do Disco do Windows. Alterar esta assinatura pode impedir que o Windows seja inicializado (ferramenta: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../.gitbook/assets/image (493).png>)

**Formato**

| Offset      | Comprimento | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Código de inicialização           |
| 446 (0x1BE) | 16 (0x10)  | Primeira Partição     |
| 462 (0x1CE) | 16 (0x10)  | Segunda Partição    |
| 478 (0x1DE) | 16 (0x10)  | Terceira Partição     |
| 494 (0x1EE) | 16 (0x10)  | Quarta Partição    |
| 510 (0x1FE) | 2 (0x2)    | Assinatura 0x55 0xAA |

**Formato do Registro de Partição**

| Offset    | Comprimento   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Flag ativa (0x80 = inicializável)                          |
| 1 (0x01)  | 1 (0x01) | Cabeça de início                                             |
| 2 (0x02)  | 1 (0x01) | Setor de início (bits 0-5); bits superiores do cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01) | Bits mais baixos do cilindro de início                           |
| 4 (0x04)  | 1 (0x01) | Código do tipo de partição (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | Cabeça final                                               |
| 6 (0x06)  | 1 (0x01) | Setor final (bits 0-5); bits superiores do cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Bits mais baixos do cilindro final                             |
| 8 (0x08)  | 4 (0x04) | Setores anteriores à partição (pouco significativo)            |
| 12 (0x0C) | 4 (0x04) | Setores na partição                                   |

Para montar um MBR no Linux, você primeiro precisa obter o deslocamento de início (você pode usar `fdisk` e o comando `p`)

![](<../../../.gitbook/assets/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

E então use o seguinte código
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Endereçamento lógico de blocos)**

O **Endereçamento lógico de blocos** (**LBA**) é um esquema comum usado para **especificar a localização de blocos** de dados armazenados em dispositivos de armazenamento de computador, geralmente sistemas de armazenamento secundário, como unidades de disco rígido. O LBA é um esquema de endereçamento linear particularmente simples; **os blocos são localizados por um índice inteiro**, sendo o primeiro bloco LBA 0, o segundo LBA 1 e assim por diante.

### GPT (Tabela de partição GUID)

É chamado de Tabela de Partição GUID porque cada partição no seu disco tem um **identificador globalmente único**.

Assim como o MBR, ele começa no **setor 0**. O MBR ocupa 32 bits enquanto o **GPT** usa **64 bits**.\
O GPT **permite até 128 partições** no Windows e até **9,4ZB**.\
Além disso, as partições podem ter um nome Unicode de 36 caracteres.

Em um disco MBR, o particionamento e os dados de inicialização são armazenados em um só lugar. Se esses dados forem sobrescritos ou corrompidos, você terá problemas. Em contraste, o **GPT armazena várias cópias desses dados em todo o disco**, portanto, é muito mais robusto e pode se recuperar se os dados estiverem corrompidos.

O GPT também armazena valores de **verificação de redundância cíclica (CRC)** para verificar se seus dados estão intactos. Se os dados estiverem corrompidos, o GPT pode detectar o problema e **tentar recuperar os dados danificados** de outra localização no disco.

**MBR protetor (LBA0)**

Para compatibilidade retroativa limitada, o espaço do MBR legado ainda é reservado na especificação do GPT, mas agora é usado de uma **maneira que impede que utilitários de disco baseados em MBR reconheçam erroneamente e possivelmente sobrescrevam discos GPT**. Isso é referido como um MBR protetor.

![](<../../../.gitbook/assets/image (491).png>)

**MBR híbrido (LBA 0 + GPT)**

Em sistemas operacionais que suportam **inicialização baseada em GPT por meio de serviços BIOS** em vez de EFI, o primeiro setor também pode ser usado para armazenar o primeiro estágio do código do **carregador de inicialização**, mas **modificado** para reconhecer **partições GPT**. O carregador de inicialização no MBR não deve assumir um tamanho de setor de 512 bytes.

**Cabeçalho da tabela de partição (LBA 1)**

O cabeçalho da tabela de partição define os blocos utilizáveis no disco. Ele também define o número e o tamanho das entradas de partição que compõem a tabela de partição (deslocamentos 80 e 84 na tabela).

| Deslocamento | Comprimento | Conteúdo                                                                                                                                                                        |
| ------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)     | 8 bytes     | Assinatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ou 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID\_Partition\_Table#cite\_note-8)em máquinas little-endian) |
| 8 (0x08)     | 4 bytes     | Revisão 1.0 (00h 00h 01h 00h) para UEFI 2.8                                                                                                                                     |
| 12 (0x0C)    | 4 bytes     | Tamanho do cabeçalho em little-endian (em bytes, geralmente 5Ch 00h 00h 00h ou 92 bytes)                                                                                         |
| 16 (0x10)    | 4 bytes     | [CRC32](https://en.wikipedia.org/wiki/CRC32) do cabeçalho (deslocamento +0 até o tamanho do cabeçalho) em little-endian, com este campo zerado durante o cálculo             |
| 20 (0x14)    | 4 bytes     | Reservado; deve ser zero                                                                                                                                                        |
| 24 (0x18)    | 8 bytes     | LBA atual (localização desta cópia do cabeçalho)                                                                                                                                |
| 32 (0x20)    | 8 bytes     | LBA de backup (localização da outra cópia do cabeçalho)                                                                                                                         |
| 40 (0x28)    | 8 bytes     | Primeiro LBA utilizável para partições (último LBA da tabela de partição primária + 1)                                                                                            |
| 48 (0x30)    | 8 bytes     | Último LBA utilizável (primeiro LBA da tabela de partição secundária - 1)                                                                                                        |
| 56 (0x38)    | 16 bytes    | GUID do disco em endian misto                                                                                                                                                   |
| 72 (0x48)    | 8 bytes     | LBA de início de uma matriz de entradas de partição (sempre 2 na cópia primária)                                                                                                 |
| 80 (0x50)    | 4 bytes     | Número de entradas de partição na matriz                                                                                                                                        |
| 84 (0x54)    | 4 bytes     | Tamanho de uma única entrada de partição (geralmente 80h ou 128)                                                                                                                |
| 88 (0x58)    | 4 bytes     | CRC32 da matriz de entradas de partição em little-endian                                                                                                                        |
| 92 (0x5C)    | \*          | Reservado; deve ser zero para o restante do bloco (420 bytes para um tamanho de setor de 512 bytes; mas pode ser mais com tamanhos de setor maiores)                            |

**Entradas de
### **Escultura de Arquivos**

A **escultura de arquivos** é uma técnica que tenta **encontrar arquivos no volume de dados**. Existem três maneiras principais pelas quais ferramentas como essa funcionam: **com base nos cabeçalhos e rodapés dos tipos de arquivo**, com base nas **estruturas** dos tipos de arquivo e com base no **conteúdo** em si.

Observe que essa técnica **não funciona para recuperar arquivos fragmentados**. Se um arquivo **não estiver armazenado em setores contíguos**, essa técnica não poderá encontrá-lo ou pelo menos parte dele.

Existem várias ferramentas que você pode usar para a escultura de arquivos, indicando os tipos de arquivo que deseja pesquisar.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Escultura de Fluxo de Dados

A Escultura de Fluxo de Dados é semelhante à Escultura de Arquivos, mas **em vez de procurar arquivos completos, procura fragmentos interessantes** de informações. Por exemplo, em vez de procurar um arquivo completo contendo URLs registrados, essa técnica procurará URLs.

{% content-ref url="file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](file-data-carving-recovery-tools.md)
{% endcontent-ref %}

### Exclusão Segura

Obviamente, existem maneiras de **"excluir" arquivos com segurança e parte dos logs sobre eles**. Por exemplo, é possível **sobrescrever o conteúdo** de um arquivo com dados inúteis várias vezes e, em seguida, **remover** os **logs** do **$MFT** e **$LOGFILE** sobre o arquivo e **remover as cópias de sombra do volume**. Você pode notar que, mesmo realizando essa ação, pode haver **outras partes em que a existência do arquivo ainda é registrada**, e isso é verdadeiro e parte do trabalho do profissional de forense é encontrá-las.

## Referências

* [https://en.wikipedia.org/wiki/GUID\_Partition\_Table](https://en.wikipedia.org/wiki/GUID\_Partition\_Table)
* [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
* [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
* [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
* **iHackLabs Certified Digital Forensics Windows**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
