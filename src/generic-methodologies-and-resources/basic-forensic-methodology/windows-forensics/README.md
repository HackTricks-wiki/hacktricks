# Artefatos do Windows

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos genéricos do Windows

### Notificações do Windows 10

O banco de dados de notificações por usuário está em `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (por exemplo, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). As primeiras versões do Windows 10 usavam `appdb.dat`; a Anniversary Update (1607) introduziu `wpndatabase.db`. O banco de dados SQLite inclui uma tabela `Notification` com payloads de notificações e campos de temporização, embora a retenção e os dados disponíveis variem conforme a versão e a política de limpeza.<sup>[[3]](#references)</sup>

### Timeline

O Windows Timeline é um recurso de histórico de atividades que pode conter registros de aplicativos compatíveis, documentos e outras atividades do usuário; sua cobertura depende do aplicativo e da versão do Windows.<sup>[[4]](#references)</sup>

O banco de dados está localizado em `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Ele pode ser aberto com SQLite ou analisado com [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), cuja saída pode ser revisada com o [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Arquivos baixados de fora do limite de confiança local podem conter o **fluxo de dados alternativo `Zone.Identifier`**, que registra informações da zona e pode incluir metadados de origem, como uma URL. Sua presença e seus campos dependem do produtor e da política do sistema.<sup>[[6]](#references)</sup>

## **Backups de arquivos**

### Recycle Bin

No Vista e nas versões posteriores, a **Recycle Bin** pode ser encontrada na pasta **`$Recycle.bin`** na raiz da unidade (por exemplo, `C:\$Recycle.bin`).\
Quando um arquivo é excluído nessa pasta, dois arquivos específicos são criados:

- `$I{id}`: Informações do arquivo, incluindo o horário da exclusão e o caminho original
- `$R{id}`: Conteúdo do arquivo

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Com esses arquivos, você pode usar o [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) para extrair o caminho original e o horário da exclusão (use a versão apropriada para a versão-alvo do Windows).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Cópias de Sombra de Volume

O Volume Shadow Copy Service (VSS) pode criar cópias de sombra pontuais de volumes enquanto os arquivos estão em uso; uma cópia de sombra não substitui uma imagem forense.<sup>[[8]](#references)</sup>

Os metadados da cópia normalmente estão associados a `\System Volume Information` na raiz do volume, com identificadores que variam conforme o sistema:

![Recycle Bin - Volume Shadow Copies: Esses backups geralmente estão localizados em System Volume Information, na raiz do sistema de arquivos, e o nome é composto pelos UIDs mostrados na...](<../../../images/image (94).png>)

Depois de montar uma imagem com um forensic mounter adequado, o [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) pode enumerar os snapshots VSS disponíveis e navegar ou copiar arquivos a partir deles.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Ao montar a imagem forense com o ArsenalImageMounter, a ferramenta ShadowCopyView pode ser usada para inspecionar uma cópia de sombra e até mesmo extrair os arquivos...](<../../../images/image (576).png>)

A configuração do registry writer do VSS inclui `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, que pode especificar arquivos e chaves excluídos do backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: A entrada do registry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contém os arquivos e as chaves que não devem ser incluídos no backup](<../../../images/image (254).png>)

A chave `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` também contém a configuração do serviço VSS.<sup>[[8]](#references)</sup>

### Arquivos Salvos Automaticamente pelo Office

Os locais do AutoRecover variam conforme o aplicativo, a versão e a configuração do Office. Para o Word, a Microsoft documenta `%APPDATA%\Microsoft\Word` como o local padrão; verifique as configurações do aplicativo para obter o caminho ativo.<sup>[[12]](#references)</sup>

## Itens do Shell

Um shell item é um item que contém informações sobre como acessar outro arquivo.

### Documentos Recentes (LNK)

O Windows normalmente cria atalhos para itens recentes quando um usuário abre ou acessa um item de outra forma:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

O acesso a uma pasta também pode criar links para a pasta e para as pastas pai relacionadas.

Esses arquivos de link podem conter o tipo do alvo, os horários MAC do alvo, informações do volume e o caminho do alvo. Esses metadados podem ajudar a identificar um alvo removido, mas o artefato, por si só, não prova que o alvo foi aberto por um usuário específico.<sup>[[13]](#references)[[14]](#references)</sup>

Os timestamps do próprio filesystem do LNK e os timestamps do alvo incorporados nele são distintos. Não interprete a criação do link como o primeiro uso ou a modificação do link como o último uso sem artefatos corroborantes; o formato armazena os timestamps do alvo separadamente dos timestamps do arquivo de link.<sup>[[13]](#references)[[14]](#references)</sup>

O link existente para o [**LinkParser**](http://4discovery.com/our-tools/) é mantido como uma opção histórica, mas sua documentação não estava disponível durante a revisão. Para um parser de linha de comando documentado, use o [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Essas ferramentas normalmente exibem dois conjuntos de timestamps:

- **Timestamps do alvo:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Timestamps do arquivo de link:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

O primeiro conjunto refere-se ao alvo; o segundo conjunto refere-se ao próprio arquivo LNK. Interprete ambos com a documentação do parser e o contexto do filesystem.<sup>[[14]](#references)[[15]](#references)</sup>

Você pode obter as mesmas informações executando a ferramenta CLI do Windows: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
Neste caso, as informações serão salvas em um arquivo CSV.

### Jumplists

As Jump Lists são listas por aplicativo de itens recentes ou específicos de tarefas e podem ser automáticas ou personalizadas.<sup>[[13]](#references)</sup>

As Jump Lists automáticas são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` e usam nomes como `{id}.automaticDestinations-ms`, em que o ID identifica o aplicativo.

As Jump Lists personalizadas são armazenadas em `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; o aplicativo controla quais entradas de tarefas ou itens são criadas.

As datas de criação e modificação do sistema de arquivos descrevem o arquivo da Jump List, não automaticamente o primeiro e o último acesso a cada destino listado. Correlacione as entradas analisadas com os timestamps do arquivo e outros artefatos.<sup>[[13]](#references)</sup>

Você pode inspecionar as Jump Lists usando [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Documentos recentes (LNK) - Jumplists: Você pode inspecionar as jumplists usando o JumplistExplorer](<../../../images/image (168).png>)

(_Observe que os timestamps fornecidos pelo JumplistExplorer estão relacionados ao próprio arquivo da jumplist_)

### Shellbags

[**Siga este link para saber o que são os shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Uso de dispositivos USB no Windows

O uso de USB às vezes pode ser corroborado por artefatos criados quando arquivos são acessados a partir de mídias removíveis, incluindo:

- Pasta Recent do Windows
- Pasta Recent do Microsoft Office
- Jumplists

Ferramentas como [**USBDetective**](https://usbdetective.com) correlacionam esses artefatos com registros de dispositivos USB, mas a disponibilidade dos artefatos depende da versão do Windows e do aplicativo.<sup>[[18]](#references)</sup>

Em testes documentados para fluxos de trabalho MTP no Windows XP e Windows 7, alguns LNKs apontavam para uma pasta `WPDNSE` em vez do caminho original.<sup>[[16]](#references)</sup>

![Shellbags - Uso de dispositivos USB no Windows: Observe que alguns arquivos LNK, em vez de apontarem para o caminho original, apontam para a pasta WPDNSE](<../../../images/image (218).png>)

Esse estudo observou cópias em `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; o conteúdo temporário não persistiu após uma reinicialização nos testes, e o GUID pôde ser correlacionado com dados de shellbag. Considere isso um comportamento dependente do sistema operacional, dispositivo e aplicativo, e não uma regra universal.<sup>[[16]](#references)</sup>

### Informações do Registry

[Consulte esta página para saber](interesting-windows-registry-keys.md#usb-information) quais chaves do Registry contêm informações relevantes sobre dispositivos USB conectados.

### setupapi

No Vista e posteriores, inspecione `C:\Windows\inf\setupapi.dev.log` em busca de atividade de instalação de dispositivos. Os cabeçalhos das seções incluem timestamps de `Section start`; eles documentam o processamento da instalação e devem ser correlacionados com outras evidências de conexão, em vez de serem tratados como o momento exato da inserção física.<sup>[[17]](#references)</sup>

![Informações do Registry - setupapi: Verifique o arquivo C: Windows inf setupapi.dev.log para obter os timestamps de quando a conexão USB ocorreu (procure por Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

O [**USBDetective**](https://usbdetective.com) pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: O USBDetective pode ser usado para obter informações sobre os dispositivos USB que foram conectados a uma imagem](<../../../images/image (452).png>)

### Plug and Play Cleanup

A tarefa agendada conhecida como `Plug and Play Cleanup` remove versões desatualizadas de drivers. Uma definição de tarefa do Windows 10 documentada por Adam Harrison também tem como alvo drivers inativos por 30 dias, portanto evidências de drivers de dispositivos removíveis podem ser apagadas; confirme a definição da tarefa local e o build do Windows antes de generalizar esse comportamento.<sup>[[1]](#references)</sup>

A tarefa está localizada no seguinte caminho: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![Definição XML da tarefa agendada Windows Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Principais componentes e configurações da tarefa:**

- **pnpclean.dll**: Esta DLL é responsável pelo processo de limpeza propriamente dito.
- **UseUnifiedSchedulingEngine**: Definido como `TRUE`, indicando o uso do mecanismo genérico de agendamento de tarefas.
- **MaintenanceSettings**:
- **Period ('P1M')**: Instrui o Task Scheduler a iniciar a tarefa de limpeza mensalmente durante a manutenção Automatic regular.
- **Deadline ('P2M')**: Instrui o Task Scheduler, se a tarefa falhar por dois meses consecutivos, a executar a tarefa durante a manutenção Automatic de emergência.

Essa configuração agenda a manutenção regular e tenta novamente após falhas consecutivas; o XML e o comportamento exatos dependem da versão.<sup>[[1]](#references)</sup>

**Para mais informações, consulte:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-mails

Os e-mails contêm **2 partes interessantes: os cabeçalhos e o conteúdo** do e-mail. Nos **cabeçalhos**, você pode encontrar informações como:

- **Quem** enviou os e-mails (endereço de e-mail, IP, mail servers que redirecionaram o e-mail)
- **Quando** o e-mail foi enviado

Além disso, os cabeçalhos `References` e `In-Reply-To` podem transportar IDs de mensagens usados para associar respostas a uma conversa.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-mails: Quando o e-mail foi enviado](<../../../images/image (593).png>)

### Aplicativo Windows Mail

Esse aplicativo salva o conteúdo dos e-mails em arquivos auxiliares de texto ou HTML em caminhos como `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; a pasta numerada exata e a estrutura dos arquivos podem variar conforme o artefato.<sup>[[75]](#references)</sup>

Os **metadados** dos e-mails e os **contatos** podem ser encontrados no **banco de dados ESE** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` usa o formato Extensible Storage Engine (ESE). Trabalhe em uma cópia e use um parser ESE, como o [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); se uma ferramenta exigir o sufixo `.edb`, renomeie apenas a cópia e verifique o schema das tabelas antes de confiar em uma tabela `Message`.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Ao inspecionar propriedades MAPI do Outlook, as propriedades canônicas incluem:

- `PidTagClientSubmitTime`: o horário UTC em que o cliente enviou a mensagem.
- `PidTagConversationIndex`: a posição relativa da mensagem em um thread de conversa.
- `PidTagEntryId`: um identificador do objeto da mensagem.
- `PidTagMessageFlags`: flags de status, como enviada, lida, não lida ou com anexos.
- `PidTagLastVerbExecuted`: a última operação registrada para a mensagem, como abrir, responder ou encaminhar.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Os locais dos arquivos de dados do Outlook variam conforme a versão e o tipo de conta. A Microsoft documenta estes locais comuns para arquivos PST/OST:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

O caminho do Registry `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` pode identificar o perfil do Outlook e a configuração associada dos arquivos de dados.

Os arquivos PST podem conter mensagens, contatos, dados de calendário e outros itens do Outlook. Você pode inspecionar uma cópia com o [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Aplicativo Windows Mail - Microsoft Outlook: Você pode abrir o arquivo PST usando a ferramenta Kernel PST Viewer](<../../../images/image (498).png>)

### Arquivos OST do Microsoft Outlook

Um **arquivo OST** é um cache local para contas Exchange ou Microsoft 365; o Cached Exchange Mode não se aplica a contas POP ou IMAP. O período offline é configurável e geralmente é de 12 meses por padrão, enquanto os limites de tamanho de PST/OST são configurações separadas e configuráveis. Para visualizar um arquivo OST, o [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) pode ser utilizado.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Recuperação de anexos

Anexos perdidos podem ser recuperáveis a partir de:

- Para configurações antigas do Outlook/IE: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Para configurações mais recentes do Outlook/IE11: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Arquivos MBOX do Thunderbird

O **Thunderbird** armazena os dados do perfil em `%APPDATA%\Thunderbird\Profiles`; as pastas de e-mail normalmente usam arquivos mbox sem extensão nos diretórios `Mail` ou `ImapMail` específicos da conta.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniaturas de imagens

- **Windows XP**: As pré-visualizações de miniaturas eram normalmente armazenadas em arquivos `thumbs.db` específicos de cada pasta.
- **Pastas de rede**: Um arquivo `thumbs.db` ainda pode ser criado para uma pasta UNC quando o comportamento de miniaturas relevante está habilitado; não presuma que toda versão ou política do Windows crie um.
- **Windows Vista e posteriores**: O cache de miniaturas do sistema é centralizado em `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer`, com arquivos como **thumbcache_xxx.db**. O [**Thumbsviewer**](https://thumbsviewer.github.io) pode analisar `Thumbs.db` antigos, enquanto o [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) pode analisar bancos de dados modernos de cache de miniaturas.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informações do Windows Registry

O Windows Registry, que armazena dados de configuração do sistema e do usuário, está contido em arquivos hive localizados em:

- `%WINDIR%\System32\Config` para os hives da máquina que respaldam várias subchaves de `HKEY_LOCAL_MACHINE`.
- `%USERPROFILE%\NTUSER.DAT` para o hive `HKEY_CURRENT_USER` de um usuário.
- Algumas instalações antigas do Windows contêm cópias em `%WINDIR%\System32\Config\RegBack\`; o Windows 10 versão 1803 e posteriores não preenchem automaticamente esse diretório, a menos que o backup periódico esteja habilitado.<sup>[[34]](#references)[[35]](#references)</sup>
- Dados de shell e registro de classes por usuário também são normalmente armazenados em `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` nas versões modernas do Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Ferramentas

Algumas ferramentas são úteis para analisar hives do Registry; confirme os formatos de hive e a versão compatíveis com cada ferramenta antes de confiar em um resultado:

- **Registry Editor**: Ele vem instalado no Windows. É uma GUI para navegar pelo Windows Registry da sessão atual.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Permite carregar o arquivo do Registry e navegar por ele usando uma GUI. Também contém Bookmarks que destacam chaves com informações relevantes.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Novamente, possui uma GUI que permite navegar pelo Registry carregado e também contém plugins que destacam informações relevantes dentro do Registry carregado.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Outro aplicativo GUI capaz de extrair informações de um hive do Registry carregado.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recuperação de elemento excluído

Células excluídas do hive podem permanecer até que seu espaço seja reutilizado, mas a recuperação depende do estado do hive e do parser; trate as chaves excluídas recuperadas como evidências que exigem validação, e não como registros garantidos.

### Last Write Time

As chaves do Registry possuem um timestamp de última gravação; o Windows o expõe para a chave ou qualquer uma de suas entradas de valor, portanto um valor não necessariamente possui seu próprio timestamp independente de modificação.<sup>[[69]](#references)</sup>

### SAM

O hive **SAM** contém dados de contas de usuários e grupos locais, incluindo hashes de senha protegidos pelo material de boot-key do sistema.<sup>[[38]](#references)[[39]](#references)</sup>

Em `SAM\Domains\Account\Users`, você pode obter identificadores de conta e alguns campos de logon e políticas. A extração offline de hashes também exige o hive `SYSTEM` para recuperar o material de boot-key relevante.<sup>[[38]](#references)[[39]](#references)</sup>

### Entradas relevantes no Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programas executados

### Processos básicos do Windows

Um [post sobre processos comuns do Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) existente é mantido como leitura adicional; corrobore quaisquer afirmações sobre o comportamento dos processos com a documentação atual do Windows e evidências locais.<sup>[[2]](#references)</sup>

### Aplicativos recentes do Windows

Nas versões do Windows 10 que o exibem, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contém subchaves por aplicativo com campos como horário do último uso e contagem de inicializações; o artefato foi removido de versões posteriores, portanto valide o build de destino.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Nos sistemas que expõem o Background Activity Moderator, inspecione o caminho `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` ou o caminho mais recente `...\bam\State\UserSettings\{SID}`. Os valores são indexados pelo SID do usuário e podem conter caminhos de executáveis rastreados e dados de execução semelhantes a FILETIME; o artefato depende da versão e deve ser corroborado com outras evidências.<sup>[[63]](#references)</sup>

### Windows Prefetch

O Prefetch armazena em cache recursos e metadados de inicialização para que os programas possam iniciar mais rapidamente.

Os arquivos Prefetch são armazenados como arquivos `.pf` em `C:\Windows\Prefetch`; o formato, a retenção e os limites de quantidade de arquivos variam conforme a versão do Windows. A Microsoft documenta a retenção dos oito últimos horários de execução e de até 1024 arquivos no Windows 8 e posteriores, portanto resumos antigos com limites fixos não devem ser generalizados.<sup>[[13]](#references)</sup>

O nome do arquivo normalmente usa o formato `{program_name}-{hash}.pf`, com o hash derivado do contexto de execução, como caminho e argumentos; o Windows 10 e posteriores podem compactar o arquivo. A presença é uma evidência útil de execução, mas por si só não prova a execução por um usuário e deve ser correlacionada com outros artefatos.<sup>[[13]](#references)</sup>

Para inspecionar esses arquivos, você pode usar o [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), que documenta a análise de diretórios, a saída em CSV/HTML e o suporte à descompactação de arquivos Prefetch aplicáveis do Windows 10.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** complementa o Prefetch usando padrões históricos de uso para melhorar o carregamento. Em sistemas que os geram, seus arquivos de banco de dados geralmente são encontrados em `C:\Windows\Prefetch\Ag*.db`; o formato e a presença dependem da versão.<sup>[[41]](#references)</sup>

Esses bancos de dados podem conter nomes de aplicativos, contagens de uso, arquivos ou volumes acessados, caminhos e intervalos de tempo, mas não devem ser tratados como um registro exato de execução.<sup>[[41]](#references)</sup>

O link existente para [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) é mantido como um possível parser; verifique sua disponibilidade atual e o formato de saída compatível na documentação da ferramenta antes de usá-la.

### SRUM

O **System Resource Usage Monitor** (SRUM) registra o uso de recursos por aplicativos e usuários. Ele foi introduzido no Windows 8 e armazena dados no banco de dados ESE `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Ele fornece as seguintes informações:

- AppID e caminho
- Usuário/SID associado ao registro
- Bytes enviados
- Bytes recebidos
- Interface de rede
- Duração da conexão
- Duração do processo

A cadência de coleta e a retenção dependem da implementação; não presuma que cada registro represente um intervalo exato de execução de 60 minutos.<sup>[[13]](#references)</sup>

Você pode extrair e revisar os dados com [**srum_dump**](https://github.com/MarkBaggett/srum-dump), usando as opções documentadas pela versão atual da ferramenta.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

O **AppCompatCache**, também conhecido como **ShimCache**, faz parte da infraestrutura de compatibilidade de aplicações do Windows e registra metadados de arquivos para decisões de compatibilidade. O caminho do hive, o formato dos registros, a capacidade retida e os campos variam conforme a versão do Windows; em versões modernas do Windows, o ShimCache, por si só, não pode comprovar que um usuário executou um arquivo. Analise o hive `SYSTEM` relevante com a ferramenta [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) e corrobore sua saída com artefatos de execução.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Para analisar as informações armazenadas, recomenda-se usar a ferramenta AppCompatCacheParser](<../../../images/image (75).png>)

### Amcache

O arquivo **Amcache.hve** é um hive do registro que inventaria aplicações e arquivos observados pelo Windows. Ele normalmente está localizado em `C:\Windows\AppCompat\Programs\Amcache.hve`.

Ele pode conter entradas de arquivos associados e não associados, caminhos e valores SHA1, mas sua presença é uma evidência de inventário e, por si só, não comprova que um processo foi executado.<sup>[[13]](#references)[[44]](#references)</sup>

Para extrair e analisar o **Amcache.hve**, use a ferramenta [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Esse comando analisa o hive e grava a saída em CSV.<sup>[[44]](#references)</sup>

Por exemplo:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Entre os arquivos CSV gerados, `Amcache_Unassociated file entries` pode ser útil ao investigar arquivos que não estão associados a um programa reconhecido.<sup>[[44]](#references)</sup>

### RecentFileCache

Em sistemas Windows 7, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` pode conter informações sobre binários observados recentemente; a disponibilidade e a semântica dependem da versão.

Você pode usar [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) para analisar o arquivo.<sup>[[45]](#references)</sup>

### Tarefas agendadas

Evidências de tarefas agendadas podem ser encontradas em `C:\Windows\System32\Tasks` para tarefas modernas e em `C:\Windows\Tasks` com arquivos `.job` para tarefas legadas; inspecione o formato de definição de tarefa apropriado para o sistema operacional.<sup>[[73]](#references)[[74]](#references)</sup>

### Serviços

O banco de dados do Service Control Manager está em `SYSTEM\CurrentControlSet\Services` (para um hive SYSTEM offline, inspecione a chave de control-set correspondente); ele contém configurações de serviços e drivers, como caminhos de executáveis e tipos de inicialização.<sup>[[72]](#references)</sup>

### **Windows Store**

Aplicativos Windows Store instalados podem ser representados em `\ProgramData\Microsoft\Windows\AppRepository\`, incluindo o banco de dados **`StateRepository-Machine.srd`**. O schema e os caminhos variam conforme a versão do Windows.<sup>[[71]](#references)</sup>

O banco de dados pode conter identificadores de aplicativos, números de pacotes e nomes de exibição. Lacunas nos identificadores não são, por si só, prova de que um aplicativo foi desinstalado; confirme com o estado dos pacotes e do registry.

Registros de pacotes também podem aparecer em `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. A Microsoft documenta uma subchave `Deprovisioned` específica da versão para aplicativos provisionados removidos; não presuma que uma subchave `Deleted` exista em todas as builds.<sup>[[70]](#references)</sup>

## Eventos do Windows

Dependendo do provider, os eventos do Windows podem conter:

- O que aconteceu
- Um timestamp `TimeCreated` que deve ser interpretado com o schema do evento e o contexto de horário do host
- Usuários envolvidos
- Hosts envolvidos (hostname, IP)
- Ativos acessados (arquivos, pastas, impressoras ou serviços).<sup>[[49]](#references)</sup>

Antes do Windows Vista, os event logs geralmente usavam o formato binário legado em `C:\Windows\System32\config`; o Vista e versões posteriores usam o formato Windows Event Log, normalmente em `C:\Windows\System32\winevt\Logs`, com arquivos `.evtx` contendo dados de eventos renderizados em XML.<sup>[[46]](#references)[[47]](#references)</sup>

O registry SYSTEM armazena a configuração dos canais em **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, incluindo o caminho configurado do arquivo e as configurações de retenção.<sup>[[47]](#references)</sup>

Eles podem ser visualizados com o Windows Event Viewer (**`eventvwr.msc`**) ou com ferramentas como [**Event Log Explorer**](https://eventlogxp.com) e [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Compreendendo o registro de eventos de segurança do Windows

No Vista e versões posteriores, o canal Security é normalmente armazenado em `C:\Windows\System32\winevt\Logs\Security.evtx`. Seu tamanho máximo e sua política de retenção são configuráveis; com o registro circular, registros antigos podem ser sobrescritos quando o arquivo atinge seu limite. O canal pode registrar eventos de autenticação, logoff, privilégios, política de auditoria e acesso a objetos quando a auditoria relevante está habilitada.<sup>[[46]](#references)[[47]](#references)</sup>

### Principais IDs de evento para autenticação de usuários:

- **Event ID 4624**: Um logon de conta bem-sucedido.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Um logon de conta malsucedido.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Uma sessão de logon foi encerrada.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Um usuário iniciou um logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Privilégios especiais foram atribuídos a um novo logon; isso é comum em contas de sistema e de administrador, portanto não é, por si só, prova de atividade maliciosa.<sup>[[54]](#references)</sup>

#### Tipos de logon comumente registrados em 4624, 4625, 4634 e 4647:

- **Interactive (2)**: Um logon local interativo.
- **Network (3)**: Acesso a um recurso compartilhado.
- **Batch (4)**: Um logon de processo em lote.
- **Service (5)**: Um logon de serviço.
- **Unlock (7)**: Desbloqueio de uma workstation.
- **NetworkCleartext (8)**: Um logon de rede que fornece credenciais em texto claro ao authentication package.
- **NewCredentials (9)**: Um logon que usa credenciais alternativas fornecidas para conexões de saída.
- **RemoteInteractive (10)**: Logon via Remote Desktop ou Terminal Services.
- **CachedInteractive (11)**: Um logon interativo usando credenciais de domínio em cache.
- **CachedRemoteInteractive (12)**: Um logon remoto interativo em cache.
- **CachedUnlock (13)**: Um desbloqueio usando credenciais em cache.<sup>[[50]](#references)[[51]](#references)</sup>

#### Códigos de status e substatus para o EventID 4625:

- **0xC0000064**: Usuário inexistente.
- **0xC000006A**: Nome de usuário correto, mas senha incorreta.
- **0xC0000234**: Conta bloqueada.
- **0xC0000072**: Conta desabilitada.
- **0xC000006F**: Logon fora do horário permitido.
- **0xC0000070**: Violação da restrição de workstation.
- **0xC0000193**: Conta expirada.
- **0xC0000071**: Senha expirada.
- **0xC0000133**: A diferença de horário entre o cliente e o servidor é muito grande.
- **0xC0000224**: A conta deve alterar sua senha.
- **0xC0000225**: `STATUS_NOT_FOUND`; o código, isoladamente, não identifica um bug do sistema nem um ataque.
- **0xC000015B**: O tipo de logon solicitado não é concedido à conta.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: O horário do sistema foi alterado. Muitos eventos refletem correções rotineiras do time service; portanto, correlacione o autor e a fonte de horário antes de tratá-lo como adulteração.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 e 6009:

- **Contexto de energia e serviço**: O evento 12 registra a inicialização do sistema operacional, o 13 registra o desligamento do sistema operacional, o 1074 registra um desligamento ou reinicialização planejada, o 6008 indica um desligamento inesperado e o 6009 registra a versão do Windows durante a inicialização. Os eventos 6005 e 6006 indicam, respectivamente, que o serviço Event Log foi iniciado e parado; eles não são, por si mesmos, prova da inicialização e do desligamento do sistema operacional.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Exclusão de logs**: O evento 1102 registra que o Security audit log foi limpo; investigue o autor e os eventos adjacentes em vez de presumir a intenção com base apenas nesse evento.<sup>[[62]](#references)</sup>

#### EventIDs para rastreamento de dispositivos USB:

- **20001 / 20003**: Eventos de instalação de dispositivos do `UserPnp` que podem ajudar a estabelecer o primeiro uso ou a atividade de instalação.
- **10000 / 10100**: Eventos do `DriverFrameworks-UserMode` que podem acompanhar a atividade do dispositivo.
- **Event ID 112**: Atividade do `DeviceSetupManager/Admin` que pode fornecer timestamps relacionados à inserção.
- O provider, o canal e a semântica dos eventos variam conforme a versão do Windows; inspecione o nome do provider e o payload do evento antes de atribuir significado.<sup>[[59]](#references)</sup>

Para exemplos práticos sobre tipos de logon e o material de credenciais associado, consulte o [guia detalhado da Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Os detalhes do evento, incluindo o tipo de logon, o status, o substatus, o endereço de origem e os campos do processo, fornecem contexto para o Event ID 4625; um código de status ou um padrão de falhas repetidas é uma pista investigativa, não uma conclusão.<sup>[[51]](#references)[[55]](#references)</sup>

### Recuperando eventos do Windows

Como os event logs são normalmente circulares, os registros sobrescritos pelo logger podem ser irrecuperáveis. Preserve uma imagem forense ou uma cópia de trabalho antes de interagir com um sistema ativo; use um parser ou carver validado, como **Bulk_extractor**, somente após confirmar que a versão da ferramenta oferece suporte aos dados `.evtx` de destino, e não desconecte um sistema em execução apenas para tentar recuperar eventos.<sup>[[46]](#references)</sup>

### Identificando ataques comuns por meio de eventos do Windows

Para uma referência prática de event IDs, consulte o link existente do [Red Team Recipe](https://redteamrecipe.com/event-codes/) e valide seus exemplos com a documentação dos providers acima.

#### Ataques de força bruta

Correlacione falhas repetidas do Event ID 4625 com um sucesso posterior do 4624, o tipo de logon, o status, a origem e o contexto da conta; a sequência é um indicador para investigação, não uma prova de ataque.<sup>[[50]](#references)[[51]](#references)</sup>

#### Alteração de horário

O Event ID 4616 registra alterações no horário do sistema, o que pode complicar a análise da timeline; compare-o com evidências do time service e do host.<sup>[[56]](#references)</sup>

#### Rastreamento de dispositivos USB

Os event IDs de USB são específicos do provider; correlacione `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 e `DeviceSetupManager/Admin` 112 com artefatos do SetupAPI e do registry.<sup>[[17]](#references)[[59]](#references)</sup>

#### Eventos de energia do sistema

Use 12/13/1074/6008/6009 para o contexto de inicialização, desligamento, reinicialização e perda inesperada de energia do sistema operacional; 6005/6006 marcam o início e a parada do serviço Event Log.<sup>[[57]](#references)[[58]](#references)</sup>

#### Exclusão de logs

O Security Event ID 1102 registra que o Security audit log foi limpo e deve ser correlacionado com a conta e o processo responsáveis.<sup>[[62]](#references)</sup>

## References

- [1] [Limpeza do Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigando processos comuns do Windows](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Uma visão forense digital das notificações do Windows 10](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Ferramentas forenses de Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier e Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Operações de backup e restauração do registry no VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Chaves do registry para backup e restauração](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Problema de desempenho do Word no local do AutoRecover](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Guia de resposta a incidentes](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: formato de arquivo binário Shell Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [Forense de USB MTP: identificando artefatos de exfiltração de dados](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Entradas do log de instalação de dispositivos SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID e tipos relacionados](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Localizar e transferir arquivos de dados do Outlook](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Ativar o Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Somente um subconjunto de itens é sincronizado](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configurar limites de tamanho para arquivos de dados do Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Onde o Thunderbird armazena os dados do usuário](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Configurações de conta do Thunderbird e diretórios mbox](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [Interface IThumbnailCache](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Hives do registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Registry SYSTEM não é copiado para o RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Editar o registry remotamente](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Visão geral técnica de senhas](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Evidências do Superfetch](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Formato de arquivo do Event Log](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Chave do registry Eventlog](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [Propriedade de evento TimeCreated](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: valores NTSTATUS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Solucionar reinicializações inesperadas usando event logs do sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Solucionar o desligamento em andamento](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forense de dispositivos de armazenamento USB para Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderador de atividade em segundo plano](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [A Impressão rápida para de imprimir anexos PDF no Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Arquivos do Windows Registry](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Impedir que aplicativos removidos retornem durante uma atualização](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: resultados dos testes do FTK e do Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Banco de dados de serviços instalados](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tarefas](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Tarefas agendadas falham com o erro Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navegando pelo banco de dados do Windows Mail](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: formato de mensagens da Internet](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
