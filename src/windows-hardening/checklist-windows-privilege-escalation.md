# Checklist - Escalação de Privilégios Local no Windows

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalação de privilégios locais no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informações do sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obter [**informações do sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Procurar por [**exploits de kernel usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar o **Google para procurar** por **exploits de kernel**
- [ ] Usar o **searchsploit para procurar** por **exploits de kernel**
- [ ] Há informações interessantes nas [**variáveis de ambiente**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Há senhas no [**histórico do PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Há informações interessantes nas [**configurações da Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit do WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-updaters de agentes de terceiros / abuso de IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeração de logs/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verificar as configurações de [**Auditoria** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Verificar o [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificar se o [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está ativo
- [ ] [**Proteção da LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenciais em cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verificar se há algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Política do AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Proteção de administrador / elevação silenciosa via UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagação do registro de acessibilidade da Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilégios de usuário**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Verificar os [**privilégios**](windows-local-privilege-escalation/index.html#users-and-groups) do usuário **atual**
- [ ] Você é [**membro de algum grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificar se algum [destes tokens está habilitado](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Verificar se você possui [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) para ler volumes brutos e ignorar ACLs de arquivos
- [ ] [**Sessões de usuários**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verificar as [**pastas pessoais dos usuários**](windows-local-privilege-escalation/index.html#home-folders) (acesso?)
- [ ] Verificar a [**política de senhas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] O que há [**dentro da área de transferência**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Verificar as **informações de rede** [**atuais**](windows-local-privilege-escalation/index.html#network)
- [ ] Verificar **serviços locais ocultos** restritos ao exterior

### [Processos em execução](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permissões de arquivos e pastas**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dos binários dos processos
- [ ] [**Password mining da memória**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicativos GUI inseguros**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Roubar credenciais de **processos interessantes** via `ProcDump.exe` ? (firefox, chrome etc. ...)

### [Serviços](windows-local-privilege-escalation/index.html#services)

- [ ] [Você pode **modificar algum serviço**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Você pode **modificar** o **binário** que é **executado** por algum **serviço**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Você pode **modificar** o **registro** de algum **serviço**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Você pode tirar proveito de algum **caminho** de **binário de serviço** **sem aspas**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerar e acionar serviços privilegiados](windows-local-privilege-escalation/service-triggers.md)

### [**Aplicativos**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permissões de escrita** em [**aplicativos instalados**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicativos de inicialização**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulneráveis**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Você pode **escrever em alguma pasta dentro do PATH**?
- [ ] Existe algum binário de serviço conhecido que **tenta carregar alguma DLL inexistente**?
- [ ] Você pode **escrever** em alguma **pasta de binários**?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar a rede (compartilhamentos, interfaces, rotas, vizinhos, ...)
- [ ] Dar atenção especial aos serviços de rede escutando no localhost (127.0.0.1)

### [Credenciais do Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciais do [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Há credenciais do [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que você poderia usar?
- [ ] Há [**credenciais DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interessantes?
- [ ] Senhas de [**redes Wifi**](windows-local-privilege-escalation/index.html#wifi) salvas?
- [ ] Há informações interessantes nas [**conexões RDP salvas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Há senhas em [**comandos executados recentemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Senhas do [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe existe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenciais?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Arquivos e registro (credenciais)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chaves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chaves SSH no registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Há senhas em [**arquivos unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Há algum backup do [**SAM e SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) estiver presente, tentar leituras de volumes brutos para obter `SAM`, `SYSTEM`, material DPAPI e `MachineKeys`
- [ ] [**Credenciais de Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Senha GPP em cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Senha no [**arquivo de configuração web do IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Há informações interessantes nos [**logs** da **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Você quer [**pedir credenciais**](windows-local-privilege-escalation/index.html#ask-for-credentials) ao usuário?
- [ ] Há [**arquivos interessantes dentro da Lixeira**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Outros [**registros contendo credenciais**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro dos [**dados do navegador**](windows-local-privilege-escalation/index.html#browsers-history) (bancos de dados, histórico, favoritos, ...)?
- [ ] [**Busca genérica por senhas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) em arquivos e no registro
- [ ] [**Ferramentas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para procurar senhas automaticamente

### [Handlers com leak](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Você tem acesso a algum handler de um processo executado por um administrador?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verificar se você pode abusar disso

## References

- [1] [Project Zero - Ignorando a proteção de administrador por meio do abuso de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
