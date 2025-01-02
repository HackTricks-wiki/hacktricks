# Checklist - Escalação de Privilégios Local no Windows

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informações do Sistema](windows-local-privilege-escalation/#system-info)

- [ ] Obter [**Informações do sistema**](windows-local-privilege-escalation/#system-info)
- [ ] Procurar por **explorações de kernel** [**usando scripts**](windows-local-privilege-escalation/#version-exploits)
- [ ] Usar **Google para pesquisar** por **explorações de kernel**
- [ ] Usar **searchsploit para pesquisar** por **explorações de kernel**
- [ ] Informações interessantes em [**variáveis de ambiente**](windows-local-privilege-escalation/#environment)?
- [ ] Senhas no [**histórico do PowerShell**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Informações interessantes em [**configurações da Internet**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Unidades**](windows-local-privilege-escalation/#drives)?
- [ ] [**Exploração do WSUS**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeração de Logs/AV](windows-local-privilege-escalation/#enumeration)

- [ ] Verificar as configurações de [**Auditoria**](windows-local-privilege-escalation/#audit-settings) e [**WEF**](windows-local-privilege-escalation/#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Verificar se [**WDigest**](windows-local-privilege-escalation/#wdigest) está ativo
- [ ] [**Proteção LSA**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Credenciais em Cache**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Verificar se há algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Política do AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilégios do Usuário**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Verificar [**privilégios do usuário atual**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Você é [**membro de algum grupo privilegiado**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Verificar se você tem [algum desses tokens habilitados](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**?
- [ ] [**Sessões de Usuários**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Verificar [**pastas pessoais dos usuários**](windows-local-privilege-escalation/#home-folders) (acesso?)
- [ ] Verificar [**Política de Senhas**](windows-local-privilege-escalation/#password-policy)
- [ ] O que está [**dentro da Área de Transferência**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Rede](windows-local-privilege-escalation/#network)

- [ ] Verificar **informações de rede** [**atuais**](windows-local-privilege-escalation/#network)
- [ ] Verificar **serviços locais ocultos** restritos ao exterior

### [Processos em Execução](windows-local-privilege-escalation/#running-processes)

- [ ] Permissões de [**arquivos e pastas de binários de processos**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Mineração de Senhas na Memória**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Aplicativos GUI Inseguros**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Roubar credenciais com **processos interessantes** via `ProcDump.exe`? (firefox, chrome, etc ...)

### [Serviços](windows-local-privilege-escalation/#services)

- [ ] [Você pode **modificar algum serviço**?](windows-local-privilege-escalation/#permissions)
- [ ] [Você pode **modificar** o **binário** que é **executado** por algum **serviço**?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Você pode **modificar** o **registro** de algum **serviço**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Você pode tirar proveito de algum **caminho de binário de serviço não citado**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplicações**](windows-local-privilege-escalation/#applications)

- [ ] **Permissões de escrita** [**em aplicações instaladas**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Aplicações de Inicialização**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Drivers Vulneráveis** [**Drivers**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Você pode **escrever em alguma pasta dentro do PATH**?
- [ ] Existe algum binário de serviço conhecido que **tente carregar alguma DLL inexistente**?
- [ ] Você pode **escrever** em alguma **pasta de binários**?

### [Rede](windows-local-privilege-escalation/#network)

- [ ] Enumerar a rede (compartilhamentos, interfaces, rotas, vizinhos, ...)
- [ ] Prestar atenção especial aos serviços de rede escutando em localhost (127.0.0.1)

### [Credenciais do Windows](windows-local-privilege-escalation/#windows-credentials)

- [ ] Credenciais do [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
- [ ] Credenciais do [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que você poderia usar?
- [ ] Credenciais [**DPAPI**](windows-local-privilege-escalation/#dpapi) interessantes?
- [ ] Senhas de redes [**Wifi salvas**](windows-local-privilege-escalation/#wifi)?
- [ ] Informações interessantes em [**Conexões RDP salvas**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Senhas em [**comandos executados recentemente**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] Senhas do [**Gerenciador de Credenciais do Desktop Remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/#appcmd-exe)? Credenciais?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Carregamento lateral de DLL?

### [Arquivos e Registro (Credenciais)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciais**](windows-local-privilege-escalation/#putty-creds) **e** [**chaves de host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**Chaves SSH no registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Senhas em [**arquivos não atendidos**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Algum backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
- [ ] [**Credenciais em Nuvem**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] Arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
- [ ] [**Senha GPP em Cache**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Senha no [**arquivo de configuração do IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Informações interessantes em [**logs da web**](windows-local-privilege-escalation/#logs)?
- [ ] Você quer [**pedir credenciais**](windows-local-privilege-escalation/#ask-for-credentials) ao usuário?
- [ ] Arquivos interessantes [**dentro da Lixeira**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Outros [**registros contendo credenciais**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] Dentro dos [**dados do Navegador**](windows-local-privilege-escalation/#browsers-history) (dbs, histórico, favoritos, ...)?
- [ ] [**Busca genérica de senhas**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) em arquivos e registro
- [ ] [**Ferramentas**](windows-local-privilege-escalation/#tools-that-search-for-passwords) para buscar senhas automaticamente

### [Manipuladores Vazados](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Você tem acesso a algum manipulador de um processo executado por administrador?

### [Impersonação de Cliente de Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Verifique se você pode abusar disso

{{#include ../banners/hacktricks-training.md}}
