# Checklist - Escalada de privilégios local no Windows

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalada de privilégios local no Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informações do sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenha [**informações do sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Procure por **exploits de kernel usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Use o **Google para procurar** **exploits** de kernel
- [ ] Use o **searchsploit para procurar** **exploits** de kernel
- [ ] Há informações interessantes nas [**variáveis de ambiente**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Há senhas no [**histórico do PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Há informações interessantes nas [**configurações da Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploit do WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Agentes de terceiros com atualização automática / abuso de IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeração de logs/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verifique as configurações de [**Auditoria** ](windows-local-privilege-escalation/index.html#audit-settings)e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Verifique o [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verifique se o [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está ativo
- [ ] [**Proteção LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Credenciais em cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verifique se há algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Política do AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Proteção de Administrador / elevação silenciosa de UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] [**Propagação de registro de acessibilidade na Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilégios de usuário**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Verifique os [**privilégios**](windows-local-privilege-escalation/index.html#users-and-groups) do usuário **atual**
- [ ] Você é [**membro de algum grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verifique se estes [privilégios estão presentes no token atual](windows-local-privilege-escalation/access-tokens.md), mesmo que apareçam como **Disabled**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Um privilégio desativado só pode ser ativado se já estiver no token.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Verifique se há [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), um direito de manutenção de volume. Por si só, ele não concede acesso de leitura ao volume bruto; abrir um disco ou volume também exige permissões de acesso específicas.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] [**Sessões de usuários**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verifique os[ **diretórios pessoais dos usuários**](windows-local-privilege-escalation/index.html#home-folders) (acesso?)
- [ ] Verifique a [**política de senhas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] O que há[ **na área de transferência**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Verifique as [**informações** **atuais** da **rede**](windows-local-privilege-escalation/index.html#network)
- [ ] Verifique se há **serviços locais ocultos** restritos a conexões externas

### [Processos em execução](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissões de [**arquivos e pastas**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dos binários dos processos
- [ ] [**Extração de senhas da memória**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicativos GUI inseguros**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Roube credenciais de **processos interessantes** usando `ProcDump.exe`? (firefox, chrome, etc ...)

### [Serviços](windows-local-privilege-escalation/index.html#services)

- [ ] [Você pode **modificar algum serviço**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Você pode **modificar** o **binário** **executado** por algum **serviço**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Você pode **modificar** o **registro** de algum **serviço**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Você pode explorar algum **caminho** de binário de **serviço sem aspas**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Gatilhos de serviço: enumere e acione serviços privilegiados](windows-local-privilege-escalation/service-triggers.md)

### [**Aplicativos**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permissões de gravação** em [**aplicativos instalados**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicativos de inicialização**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulneráveis**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Você pode **gravar em alguma pasta dentro de PATH**?
- [ ] Há algum binário de serviço conhecido que **tenta carregar uma DLL inexistente**?
- [ ] Você pode **gravar** em alguma **pasta de binários**?

### [Rede](windows-local-privilege-escalation/index.html#network)

- [ ] Enumere a rede (compartilhamentos, interfaces, rotas, vizinhos, ...)
- [ ] Examine com atenção os serviços de rede que estão escutando em localhost (127.0.0.1)

### [Credenciais do Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciais do [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Há credenciais no [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que você possa usar?
- [ ] Há [**credenciais DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interessantes?
- [ ] Senhas de [**redes Wi-Fi**](windows-local-privilege-escalation/index.html#wifi) salvas?
- [ ] Há informações interessantes nas [**conexões RDP salvas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Há senhas em [**comandos executados recentemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Senhas no [**Gerenciador de Credenciais da Área de Trabalho Remota**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe existe**](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenciais?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Arquivos e registro (credenciais)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciais**](windows-local-privilege-escalation/index.html#putty-creds) **e** [**chaves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Chaves SSH no registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Há senhas em [**arquivos unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Há algum backup de [**SAM e SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se o acesso de leitura a um identificador de volume bruto for permitido independentemente, avalie a possível exposição de `SAM`, `SYSTEM`, material DPAPI e `MachineKeys`; não presuma que esse acesso é concedido apenas por **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] [**Credenciais de cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Senha GPP em cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Há senha no [**arquivo de configuração web do IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Há informações interessantes nos [**logs** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Você quer [**solicitar credenciais**](windows-local-privilege-escalation/index.html#ask-for-credentials) ao usuário?
- [ ] Há [**arquivos interessantes na Lixeira**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Há outro [**registro contendo credenciais**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Há algo nos [**dados do navegador**](windows-local-privilege-escalation/index.html#browsers-history) (bancos de dados, histórico, favoritos, ...)?
- [ ] [**Busca genérica por senhas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) em arquivos e no registro
- [ ] [**Ferramentas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para procurar senhas automaticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Você tem acesso a algum handler de um processo executado por um administrador?

### [Impersonation de cliente de named pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verifique se você pode abusar disso



## References

- [1] [Project Zero - Burlando a proteção de administrador por meio do abuso de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privilégios](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Alterando privilégios em um token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile para discos físicos e volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Gerenciando privilégios em um sistema de arquivos](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
