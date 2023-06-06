## smss.exe

**Gerenciador de sessão**.\
A sessão 0 inicia o **csrss.exe** e o **wininit.exe** (**serviços** do **SO**) enquanto a sessão 1 inicia o **csrss.exe** e o **winlogon.exe** (**sessão** do **usuário**). No entanto, você deve ver **apenas um processo** dessa **binário** sem filhos na árvore de processos.

Além disso, sessões diferentes de 0 e 1 podem significar que as sessões RDP estão ocorrendo.


## csrss.exe

**Processo do Subsistema de Execução Cliente/Servidor**.\
Gerencia **processos** e **threads**, disponibiliza a **API do Windows** para outros processos e também **mapeia letras de unidade**, cria **arquivos temporários** e manipula o **processo de desligamento**.

Há um **executando na Sessão 0 e outro na Sessão 1** (portanto, **2 processos** na árvore de processos). Outro é criado **por nova sessão**.


## winlogon.exe

**Processo de Logon do Windows**.\
É responsável pelos **logons**/**logoffs** do usuário. Ele inicia o **logonui.exe** para solicitar nome de usuário e senha e, em seguida, chama o **lsass.exe** para verificá-los.

Em seguida, ele inicia o **userinit.exe**, que é especificado em **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** com a chave **Userinit**.

Além disso, o registro anterior deve ter o **explorer.exe** na chave **Shell** ou pode ser abusado como um **método de persistência de malware**.


## wininit.exe

**Processo de Inicialização do Windows**.\
Inicia **services.exe**, **lsass.exe** e **lsm.exe** na Sessão 0. Deve haver apenas 1 processo.


## userinit.exe

**Aplicativo de Logon do Userinit**.\
Carrega o **ntduser.dat em HKCU** e inicializa o **ambiente do usuário** e executa **scripts de logon** e **GPO**.

Ele inicia o **explorer.exe**.


## lsm.exe

**Gerenciador de Sessão Local**.\
Trabalha com smss.exe para manipular sessões de usuário: logon/logoff, início de shell, bloqueio/desbloqueio de desktop, etc.

Depois do W7, lsm.exe foi transformado em um serviço (lsm.dll).

Deve haver apenas 1 processo no W7 e a partir deles um serviço executando a DLL.


## services.exe

**Gerenciador de Controle de Serviço**.\
Carrega **serviços** configurados como **início automático** e **drivers**.

É o processo pai de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** e muitos outros.

Os serviços são definidos em `HKLM\SYSTEM\CurrentControlSet\Services` e este processo mantém um banco de dados em memória das informações do serviço que podem ser consultadas por sc.exe.

Observe como **alguns** **serviços** serão executados em um **processo próprio** e outros serão **compartilhados em um processo svchost.exe**.

Deve haver apenas 1 processo.


## lsass.exe

**Subsistema de Autoridade de Segurança Local**.\
É responsável pela **autenticação do usuário** e criação dos **tokens de segurança**. Ele usa pacotes de autenticação localizados em `HKLM\System\CurrentControlSet\Control\Lsa`.

Ele escreve no **log de eventos de segurança** e deve haver apenas 1 processo.

Lembre-se de que esse processo é altamente atacado para extrair senhas.


## svchost.exe

**Processo de Hospedagem de Serviço Genérico**.\
Hospeda vários serviços DLL em um processo compartilhado.

Normalmente, você encontrará que o **svchost.exe** é iniciado com a flag `-k`. Isso iniciará uma consulta ao registro **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** onde haverá uma chave com o argumento mencionado em -k que conterá os serviços a serem iniciados no mesmo processo.

Por exemplo: `-k UnistackSvcGroup` iniciará: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Se a **flag `-s`** também for usada com um argumento, o svchost será solicitado a **iniciar apenas o serviço especificado** neste argumento.

Haverá vários processos de `svchost.exe`. Se algum deles **não estiver usando a flag `-k`**, isso é muito suspeito. Se você descobrir que o **services.exe não é o pai**, isso também é muito suspeito.


## taskhost.exe

Este processo atua como um host para processos em execução a partir de DLLs. Ele também carrega os serviços que estão sendo executados a partir de DLLs.

No W8, isso é chamado de taskhostex.exe e no W10 de taskhostw.exe.


## explorer.exe

Este é o processo responsável pela **área de trabalho do usuário** e pelo lançamento de arquivos via extensões de arquivo.

Deve ser gerado **apenas 1** processo **por usuário logado**.

Isso é executado a partir do **userinit.exe**, que deve ser encerrado, portanto, **nenhum pai** deve aparecer para este processo.


# Capturando Processos Maliciosos

* Está sendo executado no caminho esperado? (Nenhum binário do Windows é executado a partir de um local temporário)
* Está se comunicando com IPs estranhos?
* Verifique as assinaturas digitais (os artefatos da Microsoft devem estar assinados)
* Está escrito corretamente?
* Está sendo executado sob o SID esperado?
* O processo pai é o esperado (se houver)?
* Os processos filhos são os esperados? (sem cmd.exe, wscript.exe, powershell.exe..?)
