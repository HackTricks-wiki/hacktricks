# Checklist - Escalação de Privilégios Local no Windows

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informações do Sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obter [**Informações do sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Procurar por **explorações de kernel** [**usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para pesquisar** por **explorações de kernel**
- [ ] Usar **searchsploit para pesquisar** por **explorações de kernel**
- [ ] Informações interessantes em [**variáveis de ambiente**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Senhas no [**histórico do PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informações interessantes em [**configurações da Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploração do WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeração de Logs/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verificar as configurações de [**Auditoria**](windows-local-privilege-escalation/index.html#audit-settings) e [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificar se [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) está ativo
- [ ] [**Proteção LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenciais em Cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verificar se há algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Política do AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilégios do Usuário**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Verificar [**privilégios do usuário atual**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Você é [**membro de algum grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificar se você tem [algum desses tokens habilitados](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
- [ ] [**Sessões de Usuários**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verificar [**pastas pessoais dos usuários**](windows-local-privilege-escalation/index.html#home-folders) (acesso?)
- [ ] Verificar [**Política de Senhas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] O que está [**dentro da Área de Transferência**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Verificar **informações de rede** [**atuais**](windows-local-privilege-escalation/index.html#network)
- [ ] Verificar **serviços locais ocultos** restritos ao exterior

### [Processos em Execução](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissões de [**arquivos e pastas de binários de processos**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Mineração de Senhas na Memória**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicativos GUI Inseguros**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Roubar credenciais com **processos interessantes** via `ProcDump.exe`? (firefox, chrome, etc ...)

### [Serviços](windows-local-privilege-escalation/index.html#services)

- [ ] [Você pode **modificar algum serviço**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Você pode **modificar** o **binário** que é **executado** por algum **serviço**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Você pode **modificar** o **registro** de algum **serviço**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Você pode tirar proveito de algum **caminho de binário de serviço não citado**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Aplicações**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permissões de escrita** [**em aplicações instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicações de Inicialização**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Drivers Vulneráveis** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Você pode **escrever em alguma pasta dentro do PATH**?
- [ ] Existe algum binário de serviço conhecido que **tente carregar alguma DLL inexistente**?
- [ ] Você pode **escrever** em alguma **pasta de binários**?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar a rede (compartilhamentos, interfaces, rotas, vizinhos, ...)
- [ ] Prestar atenção especial aos serviços de rede escutando em localhost (127.0.0.1)

### [Credenciais do Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciais do [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenciais do [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que você poderia usar?
- [ ] Informações interessantes sobre [**credenciais DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Senhas de [**redes Wifi salvas**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Informações interessantes em [**Conexões RDP salvas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Senhas em [**comandos executados recentemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Senhas do [**Gerenciador de Credenciais do Desktop Remoto**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenciais?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? Carregamento lateral de DLL?

### [Arquivos e Registro (Credenciais)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciais**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chaves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chaves SSH no registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Senhas em [**arquivos não supervisionados**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Algum backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Credenciais em Nuvem**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Senha GPP em Cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Senha no [**arquivo de configuração do IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informações interessantes em [**logs da web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Você quer [**pedir credenciais**](windows-local-privilege-escalation/index.html#ask-for-credentials) ao usuário?
- [ ] Informações interessantes em [**arquivos dentro da Lixeira**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Outros [**registros contendo credenciais**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro dos [**dados do Navegador**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, histórico, favoritos, ...)?
- [ ] [**Busca genérica de senhas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) em arquivos e registro
- [ ] [**Ferramentas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar senhas automaticamente

### [Manipuladores Vazados](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Você tem acesso a algum manipulador de um processo executado por administrador?

### [Impersonação de Cliente de Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verifique se você pode abusar disso

{{#include ../banners/hacktricks-training.md}}
