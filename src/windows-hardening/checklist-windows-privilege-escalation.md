# Checklist - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de local Windows privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obter [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Procurar por **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para procurar** por exploits de kernel
- [ ] Usar **searchsploit para procurar** por exploits de kernel
- [ ] Informações interessantes em [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Senhas no [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informações interessantes em [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verificar configurações de [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings) e [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificar se [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest) está ativo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verificar se há algum [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Verificar [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Você é [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificar se você tem [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verificar[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (acesso?)
- [ ] Verificar [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] O que há [ **inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Verificar **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Verificar **hidden local services** restritos ao exterior

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissões de arquivos das binaries dos processos [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Roubar credenciais com **interesting processes** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Can you **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Can you **modify** the **binary** that is **executed** by any **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Can you **modify** the **registry** of any **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Can you take advantage of any **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Você pode **write in any folder inside PATH**?
- [ ] Existe algum serviço conhecido cuja binary **tries to load any non-existant DLL**?
- [ ] Você pode **write** em alguma **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar a rede (shares, interfaces, routes, neighbours, ...)
- [ ] Preste atenção especial a serviços de rede ouvindo em localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials) credentials
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) credentials que você poderia usar?
- [ ] Informações interessantes em [**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Senhas de [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Informações interessantes em [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Senhas em [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager) senhas?
- [ ] [**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? Credentials?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Senhas em [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Algum backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml) file?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Senha no [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informações interessantes em [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Deseja [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) ao usuário?
- [ ] Arquivos interessantes dentro da [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Outras [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] Dentro de [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) em arquivos e registro
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar senhas automaticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Você tem acesso a algum handler de um processo executado por administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verificar se você pode abusar disso

{{#include ../banners/hacktricks-training.md}}
