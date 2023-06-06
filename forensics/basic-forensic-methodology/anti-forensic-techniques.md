# Timestamps

Um invasor pode estar interessado em **alterar os carimbos de data/hora dos arquivos** para evitar ser detectado.\
É possível encontrar os carimbos de data/hora dentro do MFT nos atributos `$STANDARD_INFORMATION` __ e __ `$FILE_NAME`.

Ambos os atributos têm 4 carimbos de data/hora: **Modificação**, **acesso**, **criação** e **modificação do registro MFT** (MACE ou MACB).

O **Windows Explorer** e outras ferramentas mostram as informações de **`$STANDARD_INFORMATION`**.

## TimeStomp - Ferramenta Anti-forense

Esta ferramenta **modifica** as informações de carimbo de data/hora dentro de **`$STANDARD_INFORMATION`** **mas não** as informações dentro de **`$FILE_NAME`**. Portanto, é possível **identificar** **atividades suspeitas**.

## Usnjrnl

O **USN Journal** (Update Sequence Number Journal), ou Change Journal, é um recurso do sistema de arquivos Windows NT (NTFS) que **mantém um registro das alterações feitas no volume**.\
É possível usar a ferramenta [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) para procurar modificações neste registro.

![](<../../.gitbook/assets/image (449).png>)

A imagem anterior é a **saída** mostrada pela **ferramenta** onde é possível observar que algumas **alterações foram realizadas** no arquivo.

## $LogFile

Todas as alterações de metadados em um sistema de arquivos são registradas para garantir a recuperação consistente das estruturas críticas do sistema de arquivos após uma falha do sistema. Isso é chamado de [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging).\
Os metadados registrados são armazenados em um arquivo chamado “**$LogFile**”, que é encontrado em um diretório raiz de um sistema de arquivos NTFS.\
É possível usar ferramentas como [LogFileParser](https://github.com/jschicht/LogFileParser) para analisar este arquivo e encontrar alterações.

![](<../../.gitbook/assets/image (450).png>)

Novamente, na saída da ferramenta, é possível ver que **algumas alterações foram realizadas**.

Usando a mesma ferramenta, é possível identificar a **qual momento os carimbos de data/hora foram modificados**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Hora de criação do arquivo
* ATIME: Hora de modificação do arquivo
* MTIME: Hora de modificação do registro MFT do arquivo
* RTIME: Hora de acesso ao arquivo

## Comparação entre `$STANDARD_INFORMATION` e `$FILE_NAME`

Outra maneira de identificar arquivos suspeitos modificados seria comparar o tempo em ambos os atributos procurando por **incompatibilidades**.

## Nanosegundos

Os carimbos de data/hora do **NTFS** têm uma **precisão** de **100 nanossegundos**. Então, encontrar arquivos com carimbos de data/hora como 2010-10-10 10:10:**00.000:0000 é muito suspeito**.

## SetMace - Ferramenta Anti-forense

Esta ferramenta pode modificar ambos os atributos `$STARNDAR_INFORMATION` e `$FILE_NAME`. No entanto, a partir do Windows Vista, é necessário um sistema operacional ativo para modificar essas informações.

# Ocultação de dados

O NFTS usa um cluster e o tamanho mínimo de informação. Isso significa que se um arquivo ocupa um cluster e meio, o **meio restante nunca será usado** até que o arquivo seja excluído. Então, é possível **ocultar dados neste espaço ocioso**.

Existem ferramentas como o slacker que permitem ocultar dados neste espaço "oculto". No entanto, uma análise do `$logfile` e `$usnjrnl` pode mostrar que alguns dados foram adicionados:

![](<../../.gitbook/assets/image
