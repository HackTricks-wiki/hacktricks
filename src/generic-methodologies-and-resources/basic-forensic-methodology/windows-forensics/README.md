# Artefatos do Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos genéricos do Windows

### Notificações do Windows 10

No caminho `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, você pode encontrar o banco de dados `appdb.dat` (antes do Windows Anniversary) ou `wpndatabase.db` (depois do Windows Anniversary).

Dentro desse banco de dados SQLite, você pode encontrar a tabela `Notification` com todas as notificações (no formato XML), que podem conter dados interessantes.

### Timeline

Timeline é um recurso do Windows que fornece o **histórico cronológico de páginas da web visitadas, documentos editados e aplicações executadas**.

O banco de dados está localizado no caminho `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Esse banco de dados pode ser aberto com uma ferramenta SQLite ou com a ferramenta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), **que gera 2 arquivos que podem ser abertos com a ferramenta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Os arquivos baixados podem conter o **ADS Zone.Identifier**, indicando **como** foram **baixados** da intranet, internet etc. Alguns softwares (como navegadores) geralmente adicionam ainda **mais** **informações**, como a **URL** de onde o arquivo foi baixado.

## **Backups de arquivos**

### Lixeira

No Vista/Win7/Win8/Win10, a **Lixeira** pode ser encontrada na pasta **`$Recycle.bin`**, na raiz da unidade (`C:\$Recycle.bin`).\
Quando um arquivo é excluído nessa pasta, 2 arquivos específicos são criados:

- `$I{id}`: Informações do arquivo (data em que foi excluído}
- `$R{id}`: Conteúdo do arquivo

![Backups de arquivos - Lixeira: $R{id}: Conteúdo do arquivo](<../../../images/image (1029).png>)

Com esses arquivos, você pode usar a ferramenta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obter o endereço original dos arquivos excluídos e a data em que foram excluídos (use `rifiuti-vista.exe` para Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Backups de Arquivos - Lixeira: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Cópias de Sombra de Volume

Shadow Copy é uma tecnologia incluída no Microsoft Windows que pode criar **cópias de backup** ou snapshots de arquivos ou volumes do computador, mesmo quando estão em uso.

Esses backups geralmente estão localizados em `\System Volume Information`, na raiz do sistema de arquivos, e o nome é composto por **UIDs**, conforme mostrado na imagem a seguir:

![Lixeira - Cópias de Sombra de Volume: Esses backups geralmente estão localizados em System Volume Information, na raiz do sistema de arquivos, e o nome é composto por UIDs, conforme mostrado na...](<../../../images/image (94).png>)

Montando a imagem forensics com o **ArsenalImageMounter**, a ferramenta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) pode ser usada para inspecionar uma shadow copy e até mesmo **extrair os arquivos** dos backups da shadow copy.

![Lixeira - Cópias de Sombra de Volume: Montando a imagem forensics com o ArsenalImageMounter, a ferramenta ShadowCopyView pode ser usada para inspecionar uma shadow copy e até mesmo extrair os arquivos...](<../../../images/image (576).png>)

A entrada do registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contém os arquivos e as chaves que **não devem ser incluídos no backup**:

![Lixeira - Cópias de Sombra de Volume: A entrada do registro HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contém os arquivos e as chaves que não devem ser incluídos no backup](<../../../images/image (254).png>)

O registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` também contém informações de configuração sobre as `Volume Shadow Copies`.

### Arquivos AutoSaved do Office

Você pode encontrar os arquivos autosaved do Office em: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Itens do Shell

Um shell item é um item que contém informações sobre como acessar outro arquivo.

### Documentos Recentes (LNK)

O Windows **cria** **automaticamente** esses **atalhos** quando o usuário **abre, usa ou cria um arquivo** em:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando uma pasta é criada, também é criado um link para a pasta, para a pasta pai e para a pasta avó.

Esses arquivos de link criados automaticamente **contêm informações sobre a origem**, como se ela é um **arquivo** **ou** uma **pasta**, os **horários** **MAC** desse arquivo, informações do **volume** onde o arquivo está armazenado e a **pasta do arquivo de destino**. Essas informações podem ser úteis para recuperar esses arquivos caso tenham sido removidos.

Além disso, a **data de criação do arquivo de link** é o primeiro **momento** em que o arquivo original foi **usado** pela **primeira** vez, e a **data** de **modificação** do arquivo de link é o último **momento** em que o arquivo de origem foi usado.

Para inspecionar esses arquivos, você pode usar o [**LinkParser**](http://4discovery.com/our-tools/).

Nessa ferramenta, você encontrará **2 conjuntos** de timestamps:

- **Primeiro conjunto:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Segundo conjunto:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

O primeiro conjunto de timestamps faz referência aos **timestamps do próprio arquivo**. O segundo conjunto faz referência aos **timestamps do arquivo vinculado**.

Você pode obter as mesmas informações executando a ferramenta CLI do Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Neste caso, as informações serão salvas em um arquivo CSV.

### Jumplists

Esses são os arquivos recentes indicados por aplicativo. É a lista de **arquivos recentes usados por um aplicativo** que você pode acessar em cada aplicação. Eles podem ser criados **automaticamente ou de forma personalizada**.

As **jumplists** criadas automaticamente são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. As jumplists seguem o formato de nome `{id}.autmaticDestinations-ms`, em que o ID inicial é o ID da aplicação.

As jumplists personalizadas são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e são criadas pela aplicação geralmente porque algo **importante** aconteceu com o arquivo (talvez ele tenha sido marcado como favorito).

O **horário de criação** de qualquer jumplist indica **a primeira vez que o arquivo foi acessado**, e o **horário de modificação indica a última vez**.

Você pode inspecionar as jumplists usando o [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![Documentos recentes (LNK) - Jumplists: Você pode inspecionar as jumplists usando o JumplistExplorer](<../../../images/image (168).png>)

(_Observe que os timestamps fornecidos pelo JumplistExplorer estão relacionados ao próprio arquivo da jumplist_)

### Shellbags

[**Siga este link para saber o que são os shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB no Windows

É possível identificar que um dispositivo USB foi usado graças à criação de:

- Pasta de arquivos recentes do Windows
- Pasta de arquivos recentes do Microsoft Office
- Jumplists

Observe que alguns arquivos LNK, em vez de apontarem para o caminho original, apontam para a pasta WPDNSE:

![Shellbags - Uso de dispositivos USB no Windows: Observe que alguns arquivos LNK, em vez de apontarem para o caminho original, apontam para a pasta WPDNSE](<../../../images/image (218).png>)

Os arquivos na pasta WPDNSE são cópias dos originais; portanto, não sobreviverão a uma reinicialização do PC, e o GUID é obtido de um shellbag.

### Informações do Registry

[Consulte esta página para descobrir](interesting-windows-registry-keys.md#usb-information) quais chaves do Registry contêm informações interessantes sobre dispositivos USB conectados.

### setupapi

Verifique o arquivo `C:\Windows\inf\setupapi.dev.log` para obter os timestamps de quando a conexão USB foi realizada (procure por `Section start`).

![Informações do Registry - setupapi: Verifique o arquivo C: Windows inf setupapi.dev.log para obter os timestamps de quando a conexão USB foi realizada (procure por Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

O [**USBDetective**](https://usbdetective.com) pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem.

![setupapi - USB Detective: O USBDetective pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem](<../../../images/image (452).png>)

### Plug and Play Cleanup

A tarefa agendada conhecida como 'Plug and Play Cleanup' foi projetada principalmente para a remoção de versões desatualizadas de drivers. Ao contrário de sua finalidade especificada de manter a versão mais recente do pacote de drivers, fontes online sugerem que ela também tem como alvo drivers que estão inativos há 30 dias. Consequentemente, drivers de dispositivos removíveis que não foram conectados nos últimos 30 dias podem estar sujeitos à exclusão.<sup>[[1]](#references)</sup>

A tarefa está localizada no seguinte caminho: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Uma captura de tela mostrando o conteúdo da tarefa é fornecida: ![USB Detective - Plug and Play Cleanup: A tarefa está localizada no seguinte caminho: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Principais componentes e configurações da tarefa:**

- **pnpclean.dll**: Esta DLL é responsável pelo processo de limpeza propriamente dito.
- **UseUnifiedSchedulingEngine**: Definido como `TRUE`, indicando o uso do mecanismo genérico de agendamento de tarefas.
- **MaintenanceSettings**:
- **Period ('P1M')**: Instrui o Task Scheduler a iniciar a tarefa de limpeza mensalmente durante a manutenção Automatic regular.
- **Deadline ('P2M')**: Instrui o Task Scheduler, caso a tarefa falhe por dois meses consecutivos, a executá-la durante a manutenção Automatic de emergência.

Essa configuração garante a manutenção e a limpeza regulares dos drivers, com disposições para tentar novamente a tarefa em caso de falhas consecutivas.

**Para obter mais informações, consulte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-mails

Os e-mails contêm **2 partes interessantes: os cabeçalhos e o conteúdo** do e-mail. Nos **cabeçalhos**, você pode encontrar informações como:

- **Quem** enviou os e-mails (endereço de e-mail, IP, mail servers que redirecionaram o e-mail)
- **Quando** o e-mail foi enviado

Além disso, nos cabeçalhos `References` e `In-Reply-To`, você pode encontrar o ID das mensagens:

![Plug and Play Cleanup - E-mails: Quando o e-mail foi enviado](<../../../images/image (593).png>)

### Windows Mail App

Esta aplicação salva os e-mails em HTML ou texto. Você pode encontrar os e-mails dentro de subpastas em `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Os e-mails são salvos com a extensão `.dat`.

Os **metadados** dos e-mails e os **contatos** podem ser encontrados dentro do **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Altere a extensão** do arquivo de `.vol` para `.edb` e você poderá usar a ferramenta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abri-lo. Dentro da tabela `Message`, você pode ver os e-mails.

### Microsoft Outlook

Quando Exchange servers ou clientes Outlook são usados, haverá alguns cabeçalhos MAPI:

- `Mapi-Client-Submit-Time`: Hora do sistema em que o e-mail foi enviado
- `Mapi-Conversation-Index`: Número de mensagens filhas da thread e timestamp de cada mensagem da thread
- `Mapi-Entry-ID`: Identificador da mensagem.
- `Mappi-Message-Flags` e `Pr_last_Verb-Executed`: Informações sobre o cliente MAPI (mensagem lida? não lida? respondida? redirecionada? fora do escritório?)

No cliente Microsoft Outlook, todas as mensagens enviadas/recebidas, os dados de contatos e os dados do calendário são armazenados em um arquivo PST em:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

O caminho do Registry `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indica o arquivo que está sendo usado.

Você pode abrir o arquivo PST usando a ferramenta [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![Windows Mail App - Microsoft Outlook: Você pode abrir o arquivo PST usando a ferramenta Kernel PST Viewer](<../../../images/image (498).png>)

### Arquivos OST do Microsoft Outlook

Um **arquivo OST** é gerado pelo Microsoft Outlook quando ele é configurado com **IMAP** ou um servidor **Exchange**, armazenando informações semelhantes às de um arquivo PST. Esse arquivo é sincronizado com o servidor, mantendo dados dos **últimos 12 meses** até um **tamanho máximo de 50GB**, e está localizado no mesmo diretório que o arquivo PST. Para visualizar um arquivo OST, pode ser utilizado o [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recuperação de anexos

Anexos perdidos podem ser recuperáveis em:

- Para **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Para **IE11 e posteriores**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Arquivos MBOX do Thunderbird

O **Thunderbird** utiliza **arquivos MBOX** para armazenar dados, localizados em `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturas de imagens

- **Windows XP e 8-8.1**: Acessar uma pasta com miniaturas gera um arquivo `thumbs.db` que armazena visualizações das imagens, mesmo após a exclusão.
- **Windows 7/10**: `thumbs.db` é criado quando o acesso ocorre por uma rede via caminho UNC.
- **Windows Vista e versões posteriores**: As visualizações em miniatura são centralizadas em `%userprofile%\AppData\Local\Microsoft\Windows\Explorer`, com arquivos nomeados **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) e [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) são ferramentas para visualizar esses arquivos.

### Informações do Windows Registry

O Windows Registry, que armazena muitos dados de atividade do sistema e dos usuários, está contido em arquivos localizados em:

- `%windir%\System32\Config` para várias subchaves de `HKEY_LOCAL_MACHINE`.
- `%UserProfile%{User}\NTUSER.DAT` para `HKEY_CURRENT_USER`.
- O Windows Vista e versões posteriores fazem backup dos arquivos do Registry de `HKEY_LOCAL_MACHINE` em `%Windir%\System32\Config\RegBack\`.
- Além disso, as informações de execução de programas são armazenadas em `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` a partir do Windows Vista e do Windows 2008 Server.

### Ferramentas

Algumas ferramentas são úteis para analisar os arquivos do Registry:

- **Registry Editor**: Vem instalado no Windows. É uma GUI para navegar pelo Windows Registry da sessão atual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite carregar o arquivo do Registry e navegar por ele usando uma GUI. Também contém Bookmarks que destacam chaves com informações interessantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Novamente, possui uma GUI que permite navegar pelo Registry carregado e também contém plugins que destacam informações interessantes dentro do Registry carregado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Outra aplicação GUI capaz de extrair as informações importantes do Registry carregado.

### Recuperando elementos excluídos

Quando uma chave é excluída, ela é marcada como tal, mas não será removida até que o espaço que ocupa seja necessário. Portanto, usando ferramentas como o **Registry Explorer**, é possível recuperar essas chaves excluídas.

### Last Write Time

Cada Key-Value contém um **timestamp** indicando a última vez em que foi modificado.

### SAM

O arquivo/hive **SAM** contém os hashes das **senhas de usuários, grupos e usuários** do sistema.

Em `SAM\Domains\Account\Users`, você pode obter o nome de usuário, o RID, o último login, a última tentativa de logon malsucedida, o contador de logins, a política de senhas e quando a conta foi criada. Para obter os **hashes**, você também **precisa** do arquivo/hive **SYSTEM**.

### Entradas interessantes no Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas executados

### Processos básicos do Windows

Nesta [publicação](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d), você pode aprender sobre os processos comuns do Windows para detectar comportamentos suspeitos.

### Aplicações recentes do Windows

Dentro do Registry `NTUSER.DAT`, no caminho `Software\Microsoft\Current Version\Search\RecentApps`, você pode encontrar subchaves com informações sobre a **aplicação executada**, a **última vez** em que foi executada e o **número de vezes** que foi iniciada.

### BAM (Background Activity Moderator)

Você pode abrir o arquivo `SYSTEM` com um editor de Registry e, dentro do caminho `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`, encontrar as informações sobre as **aplicações executadas por cada usuário** (observe o `{SID}` no caminho) e **em que horário** foram executadas (o horário está dentro do valor Data do Registry).

### Windows Prefetch

Prefetching é uma técnica que permite que um computador **busque silenciosamente os recursos necessários para exibir conteúdo** que um usuário **pode acessar em um futuro próximo**, para que os recursos possam ser acessados mais rapidamente.

O Windows prefetch consiste na criação de **caches dos programas executados** para poder carregá-los mais rapidamente. Esses caches são criados como arquivos `.pf` dentro do caminho: `C:\Windows\Prefetch`. Há um limite de 128 arquivos no XP/VISTA/WIN7 e de 1024 arquivos no Win8/Win10.

O nome do arquivo é criado como `{program_name}-{hash}.pf` (o hash é baseado no caminho e nos argumentos do executável). No W10, esses arquivos são compactados. Observe que a simples presença do arquivo indica que **o programa foi executado** em algum momento.

O arquivo `C:\Windows\Prefetch\Layout.ini` contém os **nomes das pastas dos arquivos que sofreram prefetch**. Esse arquivo contém **informações sobre o número de execuções**, as **datas** de execução e os **arquivos** **abertos** pelo programa.

Para inspecionar esses arquivos, você pode usar a ferramenta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** tem o mesmo objetivo do prefetch, **carregar programas mais rapidamente**, prevendo o que será carregado em seguida. No entanto, ele não substitui o serviço de prefetch.\
Esse serviço gera arquivos de banco de dados em `C:\Windows\Prefetch\Ag*.db`.

Nesses bancos de dados, você pode encontrar o **nome** do **programa**, o **número de** **execuções**, os **arquivos** **abertos**, o **volume** **acessado**, o **caminho** **completo**, os **períodos** e os **timestamps**.

Você pode acessar essas informações usando a ferramenta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

O **System Resource Usage Monitor** (SRUM) **monitora** os **recursos** **consumidos** **por um processo**. Ele surgiu no W8 e armazena os dados em um banco de dados ESE localizado em `C:\Windows\System32\sru\SRUDB.dat`.

Ele fornece as seguintes informações:

- AppID e Path
- Usuário que executou o processo
- Bytes enviados
- Bytes recebidos
- Interface de rede
- Duração da conexão
- Duração do processo

Essas informações são atualizadas a cada 60 minutos.

Você pode obter a data desse arquivo usando a ferramenta [**srum_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

O **AppCompatCache**, também conhecido como **ShimCache**, faz parte do **Application Compatibility Database**, desenvolvido pela **Microsoft** para solucionar problemas de compatibilidade de aplicações. Este componente do sistema registra diversos dados de metadados dos arquivos, incluindo:

- Caminho completo do arquivo
- Tamanho do arquivo
- Hora da última modificação em **$Standard_Information** (SI)
- Hora da última atualização do ShimCache
- Sinalizador de execução do processo

Esses dados são armazenados no registro em locais específicos, dependendo da versão do sistema operacional:

- No XP, os dados são armazenados em `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`, com capacidade para 96 entradas.
- No Server 2003, bem como nas versões 2008, 2012, 2016, 7, 8 e 10 do Windows, o caminho de armazenamento é `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, acomodando 512 e 1024 entradas, respectivamente.

Para analisar as informações armazenadas, recomenda-se usar a ferramenta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser).

![SRUM - AppCompatCache (ShimCache): Para analisar as informações armazenadas, recomenda-se usar a ferramenta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

O arquivo **Amcache.hve** é essencialmente uma registry hive que registra detalhes sobre as aplicações executadas em um sistema. Ele normalmente está localizado em `C:\Windows\AppCompat\Programas\Amcache.hve`.

Esse arquivo se destaca por armazenar registros de processos executados recentemente, incluindo os caminhos para os arquivos executáveis e seus hashes SHA1. Essas informações são extremamente úteis para rastrear a atividade das aplicações em um sistema.

Para extrair e analisar os dados do **Amcache.hve**, pode-se usar a ferramenta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). O comando a seguir é um exemplo de como usar o AmcacheParser para analisar o conteúdo do arquivo **Amcache.hve** e gerar os resultados no formato CSV:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre os arquivos CSV gerados, o `Amcache_Unassociated file entries` é particularmente digno de nota devido às informações detalhadas que fornece sobre entradas de arquivos não associados.

O arquivo CVS gerado mais interessante é o `Amcache_Unassociated file entries`.

### RecentFileCache

Este artifact só pode ser encontrado no W7 em `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contém informações sobre a execução recente de alguns binários.

Você pode usar a ferramenta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para fazer o parse do arquivo.

### Scheduled tasks

Você pode extraí-las de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` e lê-las como XML.

### Services

Você pode encontrá-los no registry em `SYSTEM\ControlSet001\Services`. É possível ver o que será executado e quando.

### **Windows Store**

Os aplicativos instalados podem ser encontrados em `\ProgramData\Microsoft\Windows\AppRepository`\
Esse repositório possui um **log** com **cada aplicativo instalado** no sistema dentro do database **`StateRepository-Machine.srd`**.

Dentro da tabela Application desse database, é possível encontrar as colunas: "Application ID", "PackageNumber" e "Display Name". Essas colunas contêm informações sobre aplicativos pré-instalados e instalados, e é possível identificar se alguns aplicativos foram desinstalados, pois os IDs dos aplicativos instalados devem ser sequenciais.

Também é possível **encontrar aplicativos instalados** no registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`\
E **aplicativos** **desinstalados** em: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

As informações que aparecem dentro dos Windows events são:

- O que aconteceu
- Timestamp (UTC + 0)
- Usuários envolvidos
- Hosts envolvidos (hostname, IP)
- Assets acessados (arquivos, pastas, impressoras, services)

Os logs estão localizados em `C:\Windows\System32\config` antes do Windows Vista e em `C:\Windows\System32\winevt\Logs` depois do Windows Vista. Antes do Windows Vista, os event logs estavam em formato binário e, depois dele, estão em **formato XML** e usam a extensão **.evtx**.

A localização dos arquivos de eventos pode ser encontrada no registry SYSTEM em **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Eles podem ser visualizados no Windows Event Viewer (**`eventvwr.msc`**) ou com outras ferramentas, como [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

## Entendendo o Windows Security Event Logging

Os eventos de acesso são registrados no arquivo de configuração de segurança localizado em `C:\Windows\System32\winevt\Security.evtx`. O tamanho desse arquivo é ajustável e, quando sua capacidade é atingida, os eventos mais antigos são sobrescritos. Os eventos registrados incluem logins e logoffs de usuários, ações dos usuários e alterações nas configurações de segurança, assim como acesso a arquivos, pastas e assets compartilhados.

### Principais Event IDs para User Authentication:

- **EventID 4624**: Indica que um usuário foi autenticado com sucesso.
- **EventID 4625**: Sinaliza uma falha de autenticação.
- **EventIDs 4634/4647**: Representam eventos de logoff do usuário.
- **EventID 4672**: Denota um login com privilégios administrativos.

#### Sub-types dentro de EventID 4634/4647:

- **Interactive (2)**: Login direto do usuário.
- **Network (3)**: Acesso a pastas compartilhadas.
- **Batch (4)**: Execução de processos em batch.
- **Service (5)**: Inicialização de services.
- **Proxy (6)**: Autenticação de proxy.
- **Unlock (7)**: Tela desbloqueada com uma senha.
- **Network Cleartext (8)**: Transmissão de senha em clear text, geralmente do IIS.
- **New Credentials (9)**: Uso de credenciais diferentes para acesso.
- **Remote Interactive (10)**: Login via remote desktop ou terminal services.
- **Cache Interactive (11)**: Login com credenciais em cache sem contato com o domain controller.
- **Cache Remote Interactive (12)**: Login remoto com credenciais em cache.
- **Cached Unlock (13)**: Desbloqueio com credenciais em cache.

#### Status e Sub Status Codes para EventID 4625:

- **0xC0000064**: O username não existe - Pode indicar um username enumeration attack.
- **0xC000006A**: Username correto, mas senha incorreta - Possível password guessing ou tentativa de brute-force.
- **0xC0000234**: User account bloqueada - Pode ocorrer após um brute-force attack que resulte em vários logins com falha.
- **0xC0000072**: Account desabilitada - Tentativas não autorizadas de acessar accounts desabilitadas.
- **0xC000006F**: Logon fora do horário permitido - Indica tentativas de acesso fora dos horários de login definidos, um possível sinal de acesso não autorizado.
- **0xC0000070**: Violação das restrições da workstation - Pode ser uma tentativa de login a partir de um local não autorizado.
- **0xC0000193**: Expiração da account - Tentativas de acesso com user accounts expiradas.
- **0xC0000071**: Senha expirada - Tentativas de login com senhas desatualizadas.
- **0xC0000133**: Problemas de sincronização de tempo - Grandes discrepâncias de tempo entre client e server podem indicar attacks mais sofisticados, como pass-the-ticket.
- **0xC0000224**: Alteração obrigatória de senha necessária - Alterações obrigatórias frequentes podem sugerir uma tentativa de desestabilizar a segurança da account.
- **0xC0000225**: Indica um bug do sistema, e não um problema de segurança.
- **0xC000015b**: Tipo de logon negado - Tentativa de acesso com um tipo de logon não autorizado, como um usuário tentando executar um service logon.

#### EventID 4616:

- **Time Change**: Modificação do horário do sistema, o que pode ocultar a timeline dos eventos.

#### EventID 6005 e 6006:

- **System Startup and Shutdown**: EventID 6005 indica a inicialização do sistema, enquanto EventID 6006 indica seu desligamento.

#### EventID 1102:

- **Log Deletion**: Logs de segurança sendo apagados, o que geralmente é um red flag de tentativa de encobrir atividades ilícitas.

#### EventIDs para USB Device Tracking:

- **20001 / 20003 / 10000**: Primeira conexão do dispositivo USB.
- **10100**: Atualização do driver USB.
- **EventID 112**: Momento da inserção do dispositivo USB.

Para exemplos práticos de como simular esses tipos de login e oportunidades de credential dumping, consulte o [guia detalhado da Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Os detalhes dos eventos, incluindo os status e sub-status codes, fornecem mais informações sobre as causas dos eventos, especialmente no Event ID 4625.

### Recuperando Windows Events

Para aumentar as chances de recuperar Windows Events apagados, é recomendável desligar o computador suspeito desconectando-o diretamente da energia. O **Bulk_extractor**, uma ferramenta de recuperação que especifica a extensão `.evtx`, é recomendado para tentar recuperar esses eventos.

### Identificando Attacks Comuns por meio de Windows Events

Para obter um guia abrangente sobre como utilizar Windows Event IDs na identificação de cyber attacks comuns, visite o [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute Force Attacks

Identificáveis por vários registros EventID 4625, seguidos por um EventID 4624 se o attack for bem-sucedido.

#### Time Change

Registradas pelo EventID 4616, as alterações no horário do sistema podem complicar a análise forense.

#### USB Device Tracking

EventIDs úteis do sistema para USB device tracking incluem 20001/20003/10000 para o uso inicial, 10100 para atualizações de drivers e o EventID 112 do DeviceSetupManager para os timestamps de inserção.

#### System Power Events

EventID 6005 indica a inicialização do sistema, enquanto EventID 6006 indica o desligamento.

#### Log Deletion

O Security EventID 1102 sinaliza a exclusão de logs, um evento crítico para a análise forense.

## Referências

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
