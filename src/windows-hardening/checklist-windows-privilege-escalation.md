# Checklist - Escalada de privilegios local en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar [**exploits using scripts**](windows-local-privilege-escalation/index.html#version-exploits) de **kernel**
- [ ] Usar **Google to search** para buscar **exploits** de kernel
- [ ] Usar **searchsploit to search** para buscar **exploits** de kernel
- [ ] ¿Información interesante en las [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Contraseñas en el [**PowerShell history**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Información interesante en los [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Revisar la configuración de [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)y [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Revisar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Revisar si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está activo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Revisar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Admin Protection / UIAccess silent elevation**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?
- [ ] [**Secure Desktop accessibility registry propagation (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?
- [ ] [**User Privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Revisar los [**current** user **privileges**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] ¿Eres [**member of any privileged group**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Revisar si tienes habilitados [any of these tokens enabled](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Revisar si tienes [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) para leer volúmenes raw y saltarte las ACL de archivos
- [ ] [**Users Sessions**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Revisar [**users homes**](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Revisar la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**inside the Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Revisar la [**network** **information**](windows-local-privilege-escalation/index.html#network) **current**
- [ ] Revisar los servicios locales ocultos restringidos al exterior

### [Running Processes](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permisos de [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) de los binarios de procesos
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Robar credenciales con **interesting processes** usando `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [¿Puedes **modify any service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [¿Puedes **modify** el **binary** que se **executed** por cualquier **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [¿Puedes **modify** el **registry** de cualquier **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [¿Puedes aprovechar algún **unquoted service** binary **path**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerate and trigger privileged services](windows-local-privilege-escalation/service-triggers.md)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Write** [**permissions on installed applications**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **Vulnerable**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **write in any folder inside PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **tries to load any non-existant DLL**?
- [ ] ¿Puedes **write** en alguna **binaries folder**?

### [Network](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (shares, interfaces, routes, neighbours, ...)
- [ ] Presta especial atención a los servicios de red que escuchen en localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] Credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que puedas usar?
- [ ] ¿[**DPAPI credentials**](windows-local-privilege-escalation/index.html#dpapi) interesantes?
- [ ] ¿Contraseñas de redes [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) guardadas?
- [ ] ¿Información interesante en [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Contraseñas del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Credenciales?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Algún backup de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Si está presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), intenta lecturas de raw-volume para `SAM`, `SYSTEM`, material DPAPI y `MachineKeys`
- [ ] [**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Contraseña en el archivo de configuración web de [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Información interesante en los [**web** **logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**ask for credentials**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] [**files inside the Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin) interesantes?
- [ ] ¿Otros [**registry containing credentials**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Dentro de los [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Generic password search**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y registry
- [ ] [**Tools**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por administrator?

### [Pipe Client Impersonation](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Comprueba si puedes abusar de ello



## References

- [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)


{{#include ../banners/hacktricks-training.md}}
