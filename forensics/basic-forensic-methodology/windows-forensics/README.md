# Artefatos do Windows

## Artefatos do Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Artefatos Genéricos do Windows

### Notificações do Windows 10

No caminho `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`, você pode encontrar o banco de dados `appdb.dat` (antes do Windows Anniversary) ou `wpndatabase.db` (depois do Windows Anniversary).

Dentro deste banco de dados SQLite, você pode encontrar a tabela `Notification` com todas as notificações (em formato XML) que podem conter dados interessantes.

### Linha do Tempo

A Linha do Tempo é uma característica do Windows que fornece um **histórico cronológico** de páginas da web visitadas, documentos editados e aplicativos executados.

O banco de dados reside no caminho `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Este banco de dados pode ser aberto com uma ferramenta SQLite ou com a ferramenta [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **que gera 2 arquivos que podem ser abertos com a ferramenta** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### Fluxos de Dados Alternativos (ADS)

Arquivos baixados podem conter a **Zona de Fluxos de Dados Alternativos (ADS) Identifier** indicando **como** foi **baixado** da intranet, internet, etc. Alguns softwares (como navegadores) geralmente colocam ainda **mais** **informações** como a **URL** de onde o arquivo foi baixado.

## **Backups de Arquivos**

### Lixeira

No Vista/Win7/Win8/Win10, a **Lixeira** pode ser encontrada na pasta **`$Recycle.bin`** na raiz da unidade (`C:\$Recycle.bin`).\
Quando um arquivo é excluído nesta pasta, 2 arquivos específicos são criados:

* `$I{id}`: Informações do arquivo (data em que foi excluído}
* `$R{id}`: Conteúdo do arquivo

![](<../../../.gitbook/assets/image (486).png>)

Tendo esses arquivos, você pode usar a ferramenta [**Rifiuti**](https://github.com/abelcheung/rifiuti2) para obter o endereço original dos arquivos excluídos e a data em que foram excluídos (use `rifiuti-vista.exe` para Vista - Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Cópias de sombra de volume

Shadow Copy é uma tecnologia incluída no Microsoft Windows que pode criar **cópias de backup** ou snapshots de arquivos ou volumes de computador, mesmo quando eles estão em uso.

Esses backups geralmente estão localizados em `\System Volume Information` a partir da raiz do sistema de arquivos e o nome é composto por **UIDs** mostrados na imagem a seguir:

![](<../../../.gitbook/assets/image (520).png>)

Montando a imagem forense com o **ArsenalImageMounter**, a ferramenta [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) pode ser usada para inspecionar uma cópia de sombra e até mesmo **extrair os arquivos** dos backups de cópia de sombra.

![](<../../../.gitbook/assets/image (521).png>)

A entrada do registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contém os arquivos e chaves **para não fazer backup**:

![](<../../../.gitbook/assets/image (522).png>)

O registro `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` também contém informações de configuração sobre as `Cópias de sombra de volume`.

### Arquivos salvos automaticamente do Office

Você pode encontrar os arquivos salvos automaticamente do Office em: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Itens de shell

Um item de shell é um item que contém informações sobre como acessar outro arquivo.

### Documentos recentes (LNK)

O Windows **cria automaticamente** esses **atalhos** quando o usuário **abre, usa ou cria um arquivo** em:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Quando uma pasta é criada, um link para a pasta, para a pasta pai e para a pasta avó também é criado.

Esses arquivos de link criados automaticamente **contêm informações sobre a origem** como se é um **arquivo** **ou** uma **pasta**, **tempos MAC** desse arquivo, **informações de volume** de onde o arquivo está armazenado e **pasta do arquivo de destino**. Essas informações podem ser úteis para recuperar esses arquivos caso eles tenham sido removidos.

Além disso, a **data de criação do arquivo de link** é a primeira **vez** que o arquivo original foi **usado** e a **data modificada** do arquivo de link é a **última vez** que o arquivo de origem foi usado.

Para inspecionar esses arquivos, você pode usar [**LinkParser**](http://4discovery.com/our-tools/).

Nessa ferramenta, você encontrará **2 conjuntos** de carimbos de data/hora:

* **Primeiro conjunto:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
* **Segundo conjunto:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

O primeiro conjunto de carimbos de data/hora refere-se aos **carimbos de data/hora do próprio arquivo**. O segundo conjunto refere-se aos **carimbos de data/hora do arquivo vinculado**.

Você pode obter as mesmas informações executando a ferramenta de linha de comando do Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Neste caso, as informações serão salvas em um arquivo CSV.

### Jumplists

Essas são as listas de arquivos recentes indicados por aplicativo. É a lista de **arquivos recentes usados por um aplicativo** que você pode acessar em cada aplicativo. Eles podem ser criados **automaticamente ou personalizados**.

Os **jumplists** criados automaticamente são armazenados em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. As jumplists são nomeadas seguindo o formato `{id}.autmaticDestinations-ms`, onde o ID inicial é o ID do aplicativo.

As jumplists personalizadas são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` e são criadas pelo aplicativo geralmente porque algo **importante** aconteceu com o arquivo (talvez marcado como favorito).

O **tempo de criação** de qualquer jumplist indica a **primeira vez que o arquivo foi acessado** e o **tempo de modificação a última vez**.

Você pode inspecionar as jumplists usando o [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Observe que os carimbos de data e hora fornecidos pelo JumplistExplorer estão relacionados ao arquivo jumplist em si_)

### Shellbags

[**Siga este link para saber o que são as shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de USBs do Windows

É possível identificar que um dispositivo USB foi usado graças à criação de:

* Pasta Recente do Windows
* Pasta Recente do Microsoft Office
* Jumplists

Observe que alguns arquivos LNK, em vez de apontar para o caminho original, apontam para a pasta WPDNSE:

![](<../../../.gitbook/assets/image (476).png>)

Os arquivos na pasta WPDNSE são uma cópia dos originais, então não sobreviverão a uma reinicialização do PC e o GUID é retirado de uma shellbag.

### Informações do Registro

[Verifique esta página para saber](interesting-windows-registry-keys.md#usb-information) quais chaves do registro contêm informações interessantes sobre dispositivos USB conectados.

### setupapi

Verifique o arquivo `C:\Windows\inf\setupapi.dev.log` para obter os carimbos de data e hora sobre quando a conexão USB foi produzida (procure por `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem.

![](<../../../.gitbook/assets/image (483).png>)

### Limpeza de Plug and Play

A tarefa agendada 'Limpeza de Plug and Play' é responsável por **limpar** as versões legadas dos drivers. Parece (com base em relatos online) que ele também pega **drivers que não foram usados em 30 dias**, apesar de sua descrição indicar que "a versão mais atual de cada pacote de driver será mantida". Como tal, **dispositivos removíveis que não foram conectados por 30 dias podem ter seus drivers removidos**.

A própria tarefa agendada está localizada em ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, e seu conteúdo é exibido abaixo:

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

A tarefa faz referência a 'pnpclean.dll', que é responsável por realizar a atividade de limpeza. Além disso, vemos que o campo ‘UseUnifiedSchedulingEngine’ está definido como ‘TRUE’, o que especifica que o mecanismo genérico de agendamento de tarefas é usado para gerenciar a tarefa. Os valores ‘Period’ e ‘Deadline’ de 'P1M' e 'P2M' dentro
### BAM (Moderador de Atividade em Segundo Plano)

Você pode abrir o arquivo `SYSTEM` com um editor de registro e dentro do caminho `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` você pode encontrar informações sobre os **aplicativos executados por cada usuário** (observe o `{SID}` no caminho) e em **que horário** eles foram executados (o horário está dentro do valor de dados do registro).

### Prefetch do Windows

O prefetching é uma técnica que permite que um computador silenciosamente **busque os recursos necessários para exibir o conteúdo** que um usuário **pode acessar em um futuro próximo** para que os recursos possam ser acessados mais rapidamente.

O prefetch do Windows consiste em criar **caches dos programas executados** para poder carregá-los mais rapidamente. Esses caches são criados como arquivos `.pf` dentro do caminho: `C:\Windows\Prefetch`. Há um limite de 128 arquivos no XP/VISTA/WIN7 e 1024 arquivos no Win8/Win10.

O nome do arquivo é criado como `{nome_do_programa}-{hash}.pf` (o hash é baseado no caminho e nos argumentos do executável). No W10, esses arquivos são compactados. Observe que a simples presença do arquivo indica que **o programa foi executado** em algum momento.

O arquivo `C:\Windows\Prefetch\Layout.ini` contém os **nomes das pastas dos arquivos que são prefetchados**. Este arquivo contém **informações sobre o número de execuções**, **datas** da execução e **arquivos** **abertos** pelo programa.

Para inspecionar esses arquivos, você pode usar a ferramenta [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

O **Superprefetch** tem o mesmo objetivo do prefetch, **carregar programas mais rapidamente** prevendo o que será carregado em seguida. No entanto, ele não substitui o serviço de prefetch.\
Este serviço irá gerar arquivos de banco de dados em `C:\Windows\Prefetch\Ag*.db`.

Nesses bancos de dados, você pode encontrar o **nome** do **programa**, **número** de **execuções**, **arquivos** **abertos**, **volume** **acessado**, **caminho** **completo**, **intervalos de tempo** e **carimbos de data/hora**.

Você pode acessar essas informações usando a ferramenta [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

O **Monitor de Uso de Recursos do Sistema** (SRUM) **monitora** os **recursos** **consumidos** **por um processo**. Ele apareceu no W8 e armazena os dados em um banco de dados ESE localizado em `C:\Windows\System32\sru\SRUDB.dat`.

Ele fornece as seguintes informações:

* ID do aplicativo e caminho
* Usuário que executou o processo
* Bytes enviados
* Bytes recebidos
* Interface de rede
* Duração da conexão
* Duração do processo

Essas informações são atualizadas a cada 60 minutos.

Você pode obter a data deste arquivo usando a ferramenta [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

**Shimcache**, também conhecido como **AppCompatCache**, é um componente do **Banco de Dados de Compatibilidade de Aplicativos**, que foi criado pela **Microsoft** e usado pelo sistema operacional para identificar problemas de compatibilidade de aplicativos.

O cache armazena vários metadados de arquivos dependendo do sistema operacional, como:

* Caminho completo do arquivo
* Tamanho do arquivo
* **$Standard\_Information** (SI) Última hora modificada
* Hora da última atualização do ShimCache
* Sinalizador de execução do processo

Essas informações podem ser encontradas no registro em:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
  * XP (96 entradas)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
  * Server 2003 (512 entradas)
  * 2008/2012/2016 Win7/Win8/Win10 (1024 entradas)

Você pode usar a ferramenta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) para analisar essas informações.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

O arquivo **Amcache.hve** é um arquivo de registro que armazena as informações de aplicativos executados. Ele está localizado em `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** registra os processos recentes que foram executados e lista o caminho dos arquivos que são executados, o que pode ser usado para encontrar o programa executado. Ele também registra o SHA1 do programa.

Você pode analisar essas informações com a ferramenta [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)
```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```
O arquivo CVS mais interessante gerado é o `Amcache_Unassociated file entries`.

### RecentFileCache

Este artefato só pode ser encontrado no W7 em `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` e contém informações sobre a execução recente de alguns binários.

Você pode usar a ferramenta [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) para analisar o arquivo.

### Tarefas agendadas

Você pode extraí-las de `C:\Windows\Tasks` ou `C:\Windows\System32\Tasks` e lê-las como XML.

### Serviços

Você pode encontrá-los no registro em `SYSTEM\ControlSet001\Services`. Você pode ver o que vai ser executado e quando.

### **Windows Store**

Os aplicativos instalados podem ser encontrados em `\ProgramData\Microsoft\Windows\AppRepository\`\
Este repositório tem um **log** com **cada aplicativo instalado** no sistema dentro do banco de dados **`StateRepository-Machine.srd`**.

Dentro da tabela de aplicativos deste banco de dados, é possível encontrar as colunas: "ID do aplicativo", "Número do pacote" e "Nome de exibição". Essas colunas têm informações sobre aplicativos pré-instalados e instalados e pode ser encontrado se alguns aplicativos foram desinstalados porque os IDs dos aplicativos instalados devem ser sequenciais.

Também é possível **encontrar aplicativos instalados** no caminho do registro: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
E **aplicativos desinstalados** em: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Eventos do Windows

As informações que aparecem nos eventos do Windows são:

* O que aconteceu
* Timestamp (UTC + 0)
* Usuários envolvidos
* Hosts envolvidos (nome do host, IP)
* Ativos acessados (arquivos, pastas, impressoras, serviços)

Os logs estão localizados em `C:\Windows\System32\config` antes do Windows Vista e em `C:\Windows\System32\winevt\Logs` após o Windows Vista. Antes do Windows Vista, os logs de eventos estavam em formato binário e depois disso, eles estão em formato **XML** e usam a extensão **.evtx**.

A localização dos arquivos de eventos pode ser encontrada no registro do sistema em **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

Eles podem ser visualizados a partir do Visualizador de Eventos do Windows (**`eventvwr.msc`**) ou com outras ferramentas como [**Event Log Explorer**](https://eventlogxp.com) **ou** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Segurança

Isso registra os eventos de acesso e fornece informações sobre a configuração de segurança que pode ser encontrada em `C:\Windows\System32\winevt\Security.evtx`.

O **tamanho máximo** do arquivo de eventos é configurável e ele começará a sobrescrever eventos antigos quando o tamanho máximo for atingido.

Eventos que são registrados como:

* Login/Logoff
* Ações do usuário
* Acesso a arquivos, pastas e ativos compartilhados
* Modificação da configuração de segurança

Eventos relacionados à autenticação do usuário:

| EventID   | Descrição                    |
| --------- | ---------------------------- |
| 4624      | Autenticação bem-sucedida    |
| 4625      | Erro de autenticação         |
| 4634/4647 | logoff                       |
| 4672      | Login com permissões de administração |

Dentro do EventID 4634/4647, existem subtipos interessantes:

* **2 (interativo)**: O login foi interativo usando o teclado ou software como VNC ou `PSexec -U-`
* **3 (rede)**: Conexão a uma pasta compartilhada
* **4 (lote)**: Processo executado
* **5 (serviço)**: Serviço iniciado pelo Gerenciador de Controle de Serviços
* **6 (proxy):** Login de proxy
* **7 (desbloqueio)**: Tela desbloqueada usando senha
* **8 (texto claro de rede)**: Usuário autenticado enviando senhas em texto claro. Este evento costumava vir do IIS
* **9 (novas credenciais)**: É gerado quando o comando `RunAs` é usado ou o usuário acessa um serviço de rede com credenciais diferentes.
* **10 (interativo remoto)**: Autenticação via Terminal Services ou RDP
* **11 (cache interativo)**: Acesso usando as credenciais em cache porque não foi possível entrar em contato com o controlador de domínio
* **12 (cache interativo remoto)**: Login remotamente com credenciais em cache (uma combinação de 10 e 11).
* **13 (desbloqueio em cache)**: Desbloquear uma máquina bloqueada com credenciais em cache.

Neste post, você pode encontrar como imitar todos esses tipos de login e em quais deles você poderá despejar credenciais da memória: [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

As informações de status e substatus dos eventos podem indicar mais detalhes sobre as causas do evento. Por exemplo, dê uma olhada nos seguintes códigos de status e substatus do Evento ID 4625:

![](<../../../.gitbook/assets/image (455).png>)

### Recuperando Eventos do Windows

É altamente recomendável desligar o PC suspeito **desconectando-o** para maximizar a probabilidade de recuperar os Eventos do Windows. Caso tenham sido excluídos, uma ferramenta que pode ser útil para tentar recuperá-los é o [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) indicando a extensão **evtx**.

## Identificando ataques comuns com Eventos do Windows

### Ataque de força bruta

Um ataque de força bruta pode ser facilmente identificável porque **vários EventIDs 4625 aparecerão**. Se o ataque foi **bem-sucedido**, após os EventIDs 4625, **um EventID 4624 aparecerá**.

### Mudança de horário

Isso é terrível para a equipe de forense, pois todos os horários serão modificados. Este evento é registrado pelo EventID 4616 dentro do log de eventos de segurança.

### Dispositivos USB

Os seguintes EventIDs do sistema são úteis:

* 20001 / 20003 / 10000: Primeira vez que foi usado
* 10100: Atualização do driver

O EventID 112 do DeviceSetupManager contém o timestamp de cada dispositivo USB inserido.

### Desligar / Ligar

O ID 6005 do serviço "Log de eventos" indica que o PC foi ligado. O ID 6006 indica que foi desligado.

### Exclusão de logs

O EventID 1102 de segurança indica que os logs foram excluídos.
