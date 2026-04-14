# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de local Windows privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obter [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Procurar por [**exploits de kernel usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar o **Google para procurar** por **exploits** de kernel
- [ ] Usar **searchsploit para procurar** por **exploits** de kernel
- [ ] Informação interessante em [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Senhas no [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informação interessante em [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verificar as configurações de [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificar se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está ativo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verificar se existe algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Verificar os [**current** privilégios do **user**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Você é [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificar se você tem algum destes tokens habilitados [**SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**] ?
- [ ] Verificar se você tem [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) para ler raw volumes e contornar file ACLs
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verificar [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (access?)
- [ ] Verificar [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] O que há [**dentro da Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Verificar as [**network information**](windows-local-privilege-escalation/index.html#network) **current**
- [ ] Verificar serviços locais ocultos restritos ao exterior

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissões de [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) dos binários dos processos
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Roubar credenciais de **interesting processes** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Você pode **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Você pode **modify** o **binary** que é **executed** por algum **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Você pode **modify** o **registry** de algum **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Você pode aproveitar algum **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Você pode **write in any folder inside PATH**?
- [ ] Há algum binário de serviço conhecido que **tries to load any non-existant DLL**?
- [ ] Você pode **write** em alguma pasta de **binaries**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar a network (shares, interfaces, routes, neighbours, ...)
- [ ] Dar uma atenção especial aos serviços de rede escutando em localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] credentials do [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que você possa usar?
- [ ] [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) interessantes?
- [ ] Senhas de redes [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) salvas?
- [ ] Informação interessante em [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Senhas em [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Senhas do [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credenciais?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Senhas em [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Algum backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Se [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) estiver presente, tente leituras de raw-volume de `SAM`, `SYSTEM`, material DPAPI e `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] arquivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Senha no arquivo de configuração web [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informação interessante em [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Você quer [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) ao usuário?
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) interessantes?
- [ ] Outros [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro de [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) em arquivos e registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para procurar senhas automaticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Você tem acesso a algum handler de um processo executado por administrador?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verificar se você consegue abusar disso



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
