# Checklist - Escalada local de privilegios en Windows

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **kernel** [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google to search** para buscar **kernel exploits**
- [ ] Usar **searchsploit to search** para buscar **kernel exploits**
- [ ] ¿Información interesante en [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Contraseñas en [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Información interesante en [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Comprobar [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)y [**WEF** ](windows-local-privilege-escalation/index.html#wef)settings
- [ ] Comprobar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Comprobar si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está activo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Comprobar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Comprobar [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] ¿Eres [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Comprobar si tienes [alguno de estos tokens habilitados](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Comprobar[ **users homes**](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Comprobar [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Comprobar **current** [**network** **information**](windows-local-privilege-escalation/index.html#network)
- [ ] Comprobar **hidden local services** restringidos al exterior

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permisos de binarios de procesos [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales con **interesting processes** vía `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] ¿Puedes **modify any service**? (¿modificar algún servicio?)
- [ ] ¿Puedes **modify** el **binary** que es **executed** por algún **service**? (¿modificar el binario ejecutado por algún servicio?)
- [ ] ¿Puedes **modify** el **registry** de algún **service**? (¿modificar el registro de algún servicio?)
- [ ] ¿Puedes aprovechar cualquier **unquoted service** binary **path**?
- [ ] Service Triggers: enumerate and trigger privileged services

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Vulnerable** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **write in any folder inside PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **tries to load any non-existant DLL**?
- [ ] ¿Puedes **write** en alguna **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (shares, interfaces, routes, neighbours, ...)
- [ ] Presta especial atención a los servicios de red escuchando en localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)credentials
- [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que puedas usar?
- [ ] ¿Credenciales interesantes de [**DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] ¿Contraseñas de redes [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] ¿Información interesante en [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Contraseñas en [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿[**AppCmd.exe** exists](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Credenciales?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **and** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Algún backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Contraseña en [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Información interesante en [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿Archivos interesantes dentro de la Papelera ([**Recycle Bin**)](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Otras [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Dentro de [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y registro
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar automáticamente contraseñas

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por administrador?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Comprobar si puedes abusarlo

{{#include ../banners/hacktricks-training.md}}
