# Lista de verificación - Local Windows Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**System information**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **exploits** de **kernel** [**usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google** para buscar **exploits** de kernel
- [ ] Usar **searchsploit** para buscar **exploits** de kernel
- [ ] ¿Información interesante en [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Contraseñas en el [**historial de PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Información interesante en los [**Internet settings**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] ¿[**Drives**](windows-local-privilege-escalation/index.html#drives)?
- [ ] ¿[**WSUS exploit**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Third-party agent auto-updaters / IPC abuse**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeración de Logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Revisar la configuración de [**Audit**](windows-local-privilege-escalation/index.html#audit-settings) y [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Comprobar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Comprobar si [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) está activo
- [ ] [**LSA Protection**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Cached Credentials**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Comprobar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**AppLocker Policy**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Comprobar [**privilegios** del **usuario actual**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Comprobar si tienes habilitados algunos de estos tokens: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sesiones de usuarios**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Comprobar [**carpetas home** de los usuarios](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Comprobar la [**Password Policy**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**dentro del Portapapeles**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Comprobar la [**información de red actual**](windows-local-privilege-escalation/index.html#network)
- [ ] Comprobar servicios locales ocultos restringidos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Comprobar permisos de archivos y carpetas de los binarios de procesos [**file and folders permissions**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Memory Password mining**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Insecure GUI apps**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales con **procesos interesantes** vía `ProcDump.exe`? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] ¿Puedes **modificar algún servicio**? (windows-local-privilege-escalation/index.html#permissions)
- [ ] ¿Puedes **modificar** el **binario** que es **ejecutado** por algún **servicio**? (windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] ¿Puedes **modificar** el **registro** de algún **servicio**? (windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] ¿Puedes aprovechar alguna ruta de binario de servicio **sin comillas**? (windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permisos de escritura** en las [**aplicaciones instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Startup Applications**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulnerables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **intente cargar alguna DLL inexistente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (shares, interfaces, rutas, vecinos, ...)
- [ ] Poner especial atención a los servicios de red escuchando en localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] ¿Credenciales del [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que podrías usar?
- [ ] ¿Credenciales interesantes de [**DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] ¿Contraseñas de [**Wifi networks**](windows-local-privilege-escalation/index.html#wifi) guardadas?
- [ ] ¿Información interesante en [**saved RDP Connections**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**recently run commands**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Contraseñas del [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿[**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe) existe? ¿Credenciales?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**SSH host keys**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] ¿[**SSH keys in registry**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**unattended files**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Alguna copia de seguridad de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] ¿[**Cloud credentials**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] ¿[**Cached GPP Password**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Contraseña en el [**IIS Web config file**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Información interesante en los [**web logs**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**pedir credenciales**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿Archivos interesantes dentro de la Papelera [**Recycle Bin**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Otras [**ramas del registro que contienen credenciales**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Dentro de los [**Browser data**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, history, bookmarks, ...)?
- [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por administrador?

### [Impersonación de cliente de Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Comprobar si puedes abusarlo

{{#include ../banners/hacktricks-training.md}}
