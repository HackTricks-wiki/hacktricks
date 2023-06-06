# Ext - Sistema de Arquivos Estendido

O **Ext2** é o sistema de arquivos mais comum para partições **sem journaling** (**partições que não mudam muito**) como a partição de inicialização. O **Ext3/4** são **com journaling** e são usados geralmente para as **outras partições**.

Todos os grupos de blocos no sistema de arquivos têm o mesmo tamanho e são armazenados sequencialmente. Isso permite que o kernel derive facilmente a localização de um grupo de blocos em um disco a partir de seu índice inteiro.

Cada grupo de blocos contém as seguintes informações:

* Uma cópia do superbloco do sistema de arquivos
* Uma cópia dos descritores do grupo de blocos
* Um mapa de bits de bloco de dados que é usado para identificar os blocos livres dentro do grupo
* Um mapa de bits de inode, que é usado para identificar os inodes livres dentro do grupo
* tabela de inode: consiste em uma série de blocos consecutivos, cada um dos quais contém um número predefinido de inodes da Figura 1 do Ext2. Todos os inodes têm o mesmo tamanho: 128 bytes. Um bloco de 1.024 bytes contém 8 inodes, enquanto um bloco de 4.096 bytes contém 32 inodes. Observe que no Ext2, não é necessário armazenar em disco um mapeamento entre um número de inode e o número de bloco correspondente porque o último valor pode ser derivado do número de grupo de blocos e da posição relativa dentro da tabela de inode. Por exemplo, suponha que cada grupo de blocos contenha 4.096 inodes e que desejamos saber o endereço no disco do inode 13.021. Nesse caso, o inode pertence ao terceiro grupo de blocos e seu endereço no disco é armazenado na 733ª entrada da tabela de inode correspondente. Como você pode ver, o número de inode é apenas uma chave usada pelas rotinas do Ext2 para recuperar rapidamente o descritor de inode apropriado no disco
* blocos de dados, contendo arquivos. Qualquer bloco que não contenha nenhuma informação significativa é dito ser livre.

![](<../../../.gitbook/assets/image (406).png>)

## Recursos Opcionais do Ext

Os **recursos afetam onde** os dados estão localizados, **como** os dados são armazenados em inodes e alguns deles podem fornecer **metadados adicionais** para análise, portanto, os recursos são importantes no Ext.

O Ext tem recursos opcionais que seu sistema operacional pode ou não suportar, existem 3 possibilidades:

* Compatível
* Incompatível
* Compatível somente leitura: pode ser montado, mas não para gravação

Se houver **recursos incompatíveis**, você não poderá montar o sistema de arquivos, pois o sistema operacional não saberá como acessar os dados.

{% hint style="info" %}
Um atacante suspeito pode ter extensões não padrão
{% endhint %}

**Qualquer utilitário** que leia o **superbloco** poderá indicar os **recursos** de um **sistema de arquivos Ext**, mas você também pode usar `file -sL /dev/sd*`

## Superbloco

O superbloco é os primeiros 1024 bytes do início e é repetido no primeiro bloco de cada grupo e contém:

* Tamanho do bloco
* Total de blocos
* Blocos por grupo de blocos
* Blocos reservados antes do primeiro grupo de blocos
* Total de inodes
* Inodes por grupo de blocos
* Nome do volume
* Última hora de gravação
* Última hora de montagem
* Caminho onde o sistema de arquivos foi montado pela última vez
* Status do sistema de arquivos (limpo?)

É possível obter essas informações de um arquivo de sistema de arquivos Ext usando:
```bash
fsstat -o <offsetstart> /pat/to/filesystem-file.ext
#You can get the <offsetstart> with the "p" command inside fdisk
```
Você também pode usar a aplicação GUI gratuita: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
Ou você também pode usar **python** para obter informações do superbloco: [https://pypi.org/project/superblock/](https://pypi.org/project/superblock/)

## inodes

Os **inodes** contêm a lista de **blocos** que **contêm** os dados reais de um **arquivo**.\
Se o arquivo for grande, um inode **pode conter ponteiros** para **outros inodes** que apontam para os blocos/mais inodes que contêm os dados do arquivo.

![](<../../../.gitbook/assets/image (416).png>)

Nos sistemas de arquivos **Ext2** e **Ext3**, os inodes têm tamanho de **128B**, o **Ext4** atualmente usa **156B**, mas aloca **256B** no disco para permitir uma expansão futura.

Estrutura do inode:

| Offset | Tamanho | Nome              | Descrição                                       |
| ------ | ------- | ----------------- | ----------------------------------------------- |
| 0x0    | 2       | Modo do arquivo   | Modo e tipo de arquivo                          |
| 0x2    | 2       | UID               | 16 bits inferiores do ID do proprietário         |
| 0x4    | 4       | Tamanho Il        | 32 bits inferiores do tamanho do arquivo         |
| 0x8    | 4       | Atime             | Hora de acesso em segundos desde a época         |
| 0xC    | 4       | Ctime             | Hora de alteração em segundos desde a época      |
| 0x10   | 4       | Mtime             | Hora de modificação em segundos desde a época    |
| 0x14   | 4       | Dtime             | Hora de exclusão em segundos desde a época       |
| 0x18   | 2       | GID               | 16 bits inferiores do ID do grupo                |
| 0x1A   | 2       | Contagem de links | Contagem de links rígidos                        |
| 0xC    | 4       | Blocos Io         | 32 bits inferiores da contagem de blocos         |
| 0x20   | 4       | Flags             | Sinalizadores                                    |
| 0x24   | 4       | União osd1        | Linux: versão I                                  |
| 0x28   | 69      | Bloco\[15]        | 15 pontos para bloco de dados                    |
| 0x64   | 4       | Versão            | Versão do arquivo para NFS                       |
| 0x68   | 4       | Arquivo ACL baixo | 32 bits inferiores de atributos estendidos (ACL, etc.) |
| 0x6C   | 4       | Tamanho do arquivo hi | 32 bits superiores do tamanho do arquivo (somente ext4) |
| 0x70   | 4       | Fragmento obsoleto | Um endereço de fragmento obsoleto                |
| 0x74   | 12      | Osd 2             | Segunda união dependente do sistema operacional  |
| 0x74   | 2       | Blocos hi         | 16 bits superiores da contagem de blocos         |
| 0x76   | 2       | Arquivo ACL hi    | 16 bits superiores de atributos estendidos (ACL, etc.) |
| 0x78   | 2       | UID hi            | 16 bits superiores do ID do proprietário         |
| 0x7A   | 2       | GID hi            | 16 bits superiores do ID do grupo                |
| 0x7C   | 2       | Checksum Io       | 16 bits inferiores do checksum do inode          |

"Modificar" é o carimbo de data/hora da última vez que o _conteúdo_ do arquivo foi modificado. Isso é frequentemente chamado de "_mtime_".\
"Mudança" é o carimbo de data/hora da última vez que o _inode_ do arquivo foi alterado, como ao alterar permissões, propriedade, nome do arquivo e o número de links rígidos. É frequentemente chamado de "_ctime_".

Estrutura do inode estendido (Ext4):

| Offset | Tamanho | Nome         | Descrição                                         |
| ------ | ------- | ------------ | ------------------------------------------------- |
| 0x80   | 2       | Tamanho extra | Quantos bytes além dos 128 padrão são usados      |
| 0x82   | 2       | Checksum hi  | 16 bits superiores do checksum do inode           |
| 0x84   | 4       | Ctime extra  | Bits extras de hora de alteração                  |
| 0x88   | 4       | Mtime extra  | Bits extras de hora de modificação                |
| 0x8C   | 4       | Atime extra  | Bits extras de hora de acesso                     |
| 0x90   | 4       | Crtime       | Hora de criação do arquivo (segundos desde a época) |
| 0x94   | 4       | Crtime extra | Bits extras de hora de criação                    |
| 0x98   | 4       | Versão hi    | 32 bits superiores da versão                      |
| 0x9C   |         | Não utilizado | Espaço reservado para futuras expansões           |

Inodes especiais:

| Inode | Finalidade especial                                  |
| ----- | ---------------------------------------------------- |
| 0     | Nenhum inode, a numeração começa em 1                |
| 1     | Lista de blocos defeituosos                           |
| 2     | Diretório raiz                                       |
| 3     | Cotas de usuário                                     |
| 4     | Cotas de grupo                                       |
| 5     | Carregador de inicialização                          |
| 6     | Diretório de recuperação excluído                     |
| 7     | Descritores de grupo reservados (para redimensionar o sistema de arquivos) |
| 8     | Diário                                               |
| 9     | Excluir inode (para snapshots)                       |
| 10    | Réplica de inode                                     |
| 11    | Primeiro inode não reservado (geralmente lost + found) |

{% hint style="info" %}
Observe que o tempo de criação só aparece no Ext4.
{% endhint %}

Ao saber o número do inode, você pode facilmente encontrar seu índice:

* **Grupo de blocos** onde um inode pertence: (Número do inode - 1) / (Inodes por grupo)
* **Índice dentro do grupo**: (Número do inode - 1) mod (Inodes/grupos)
* **Deslocamento** na **tabela de inodes**: Número do inode \* (Tamanho do inode)
* O "-1" é porque o inode 0 é indefinido (não usado)
```bash
ls -ali /bin | sort -n #Get all inode numbers and sort by them
stat /bin/ls #Get the inode information of a file
istat -o <start offset> /path/to/image.ext 657103 #Get information of that inode inside the given ext file
icat -o <start offset> /path/to/image.ext 657103 #Cat the file
```
Modo de Arquivo

| Número | Descrição                                                                                           |
| ------ | --------------------------------------------------------------------------------------------------- |
| **15** | **Reg/Slink-13/Socket-14**                                                                          |
| **14** | **Diretório/Bit de Bloco 13**                                                                       |
| **13** | **Dispositivo de Caractere/Bit de Bloco 14**                                                       |
| **12** | **FIFO**                                                                                            |
| 11     | Set UID                                                                                             |
| 10     | Set GID                                                                                             |
| 9      | Bit Pegajoso (sem ele, qualquer pessoa com permissões de escrita e execução em um diretório pode excluir e renomear arquivos) |
| 8      | Leitura do Proprietário                                                                             |
| 7      | Escrita do Proprietário                                                                             |
| 6      | Execução do Proprietário                                                                            |
| 5      | Leitura do Grupo                                                                                    |
| 4      | Escrita do Grupo                                                                                    |
| 3      | Execução do Grupo                                                                                   |
| 2      | Leitura de Outros                                                                                    |
| 1      | Escrita de Outros                                                                                    |
| 0      | Execução de Outros                                                                                   |

Os bits em negrito (12, 13, 14, 15) indicam o tipo de arquivo que o arquivo é (um diretório, um socket...) apenas uma das opções em negrito pode existir.

Diretórios

| Offset | Tamanho | Nome      | Descrição                                                                                                                                                  |
| ------ | ------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 4       | Inode     |                                                                                                                                                              |
| 0x4    | 2       | Rec len   | Comprimento do registro                                                                                                                                                |
| 0x6    | 1       | Name len  | Comprimento do nome                                                                                                                                                  |
| 0x7    | 1       | Tipo de Arquivo | <p>0x00 Desconhecido<br>0x01 Regular</p><p>0x02 Diretório</p><p>0x03 Dispositivo de Caractere</p><p>0x04 Dispositivo de Bloco</p><p>0x05 FIFO</p><p>0x06 Socket</p><p>0x07 Link Simbólico</p> |
| 0x8    |         | Nome      | String de nome (até 255 caracteres)                                                                                                                           |

**Para aumentar o desempenho, blocos de diretório de hash raiz podem ser usados.**

**Atributos Estendidos**

Podem ser armazenados em

* Espaço extra entre inodes (256 - tamanho do inode, geralmente = 100)
* Um bloco de dados apontado por file\_acl no inode

Podem ser usados para armazenar qualquer coisa como um atributo do usuário se o nome começar com "user". Dessa forma, os dados podem ser ocultados.

Entradas de Atributos Estendidos

| Offset | Tamanho | Nome         | Descrição                                                                                                                                                                                                        |
| ------ | ------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x0    | 1       | Comprimento do Nome     | Comprimento do nome do atributo                                                                                                                                                                                           |
| 0x1    | 1       | Índice do Nome   | <p>0x0 = sem prefixo</p><p>0x1 = prefixo user.</p><p>0x2 = system.posix_acl_access</p><p>0x3 = system.posix_acl_default</p><p>0x4 = trusted.</p><p>0x6 = security.</p><p>0x7 = system.</p><p>0x8 = system.richacl</p> |
| 0x2    | 2       | Offset do Valor   | Deslocamento do primeiro inode ou início do bloco                                                                                                                                                                    |
| 0x4    | 4       | Blocos de Valor | Bloco de disco onde o valor é armazenado ou zero para este bloco                                                                                                                                                               |
| 0x8    | 4       | Tamanho do Valor   | Comprimento do valor                                                                                                                                                                                                    |
| 0xC    | 4       | Hash         | Hash para atributos no bloco ou zero se no inode                                                                                                                                                                      |
| 0x10   |         | Nome         | Nome do atributo sem NULL no final                                                                                                                                                                                   |
```bash
setfattr -n 'user.secret' -v 'This is a secret' file.txt #Save a secret using extended attributes
getfattr file.txt #Get extended attribute names of a file
getdattr -n 'user.secret' file.txt #Get extended attribute called "user.secret"
```
## Visualização do sistema de arquivos

Para ver o conteúdo do sistema de arquivos, você pode **usar a ferramenta gratuita**: [https://www.disk-editor.org/index.html](https://www.disk-editor.org/index.html)\
Ou você pode montá-lo em seu linux usando o comando `mount`.

[https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=The%20Ext2%20file%20system%20divides,lower%20average%20disk%20seek%20time.](https://piazza.com/class\_profile/get\_resource/il71xfllx3l16f/inz4wsb2m0w2oz#:\~:text=O%20sistema%20de%20arquivos%20Ext2%20divide,o%20tempo%20médio%20de%20busca%20no%20disco.) 


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
