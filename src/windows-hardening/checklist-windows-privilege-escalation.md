# Checklist - Escalada de privilegios local en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**información del sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **exploits** de **kernel** [**usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para buscar** **exploits** de kernel
- [ ] Usar **searchsploit para buscar** **exploits** de kernel
- [ ] ¿Hay información interesante en las [**variables de entorno**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Hay contraseñas en el [**historial de PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Hay información interesante en la [**configuración de Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] ¿Hay [**unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] ¿Hay un [**exploit de WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Auto-updaters de agentes de terceros / abuso de IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] ¿Está habilitado [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeración de logging/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Comprobar la configuración de [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)y [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Comprobar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Comprobar si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está activo
- [ ] ¿Está activa la [**protección LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] ¿Está activo [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] ¿Hay [**credenciales en caché**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Comprobar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] ¿Existe una [**política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] ¿Existe [**protección del administrador / elevación silenciosa mediante UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] ¿Existe [**propagación del registro de accesibilidad del Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Comprobar los [**privilegios**](windows-local-privilege-escalation/index.html#users-and-groups) del usuario **actual**
- [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Comprobar si tienes [alguno de estos tokens habilitado](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Comprobar si tienes [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) para leer volúmenes sin procesar y omitir las ACL de archivos
- [ ] ¿Hay [**sesiones de usuarios**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Comprobar[ **los directorios personales de los usuarios**](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Comprobar la [**política de contraseñas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay[ **dentro del Clipboard**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Comprobar la **información** de [**red** **actual**](windows-local-privilege-escalation/index.html#network)
- [ ] Comprobar los **servicios locales ocultos** restringidos desde el exterior

### [Procesos en ejecución](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permisos de archivos y carpetas**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) de los binarios de los procesos
- [ ] [**Extracción de contraseñas de la memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales con **procesos interesantes** mediante `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/index.html#services)

- [ ] [¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [¿Puedes **modificar** el **binario** que **ejecuta** algún **servicio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [¿Puedes aprovechar alguna **ruta** de binario de **servicio sin comillas**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Service Triggers: enumerar y activar servicios privilegiados](windows-local-privilege-escalation/service-triggers.md)

### [**Aplicaciones**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permisos de escritura** en [**aplicaciones instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicaciones de inicio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers** vulnerables](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Existe algún binario de servicio conocido que **intente cargar alguna DLL inexistente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (shares, interfaces, rutas, vecinos, ...)
- [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] ¿Hay credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que puedas usar?
- [ ] ¿Hay [**credenciales DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interesantes?
- [ ] ¿Hay contraseñas de [**redes Wifi** guardadas](windows-local-privilege-escalation/index.html#wifi)?
- [ ] ¿Hay información interesante en las [**conexiones RDP guardadas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Hay contraseñas en los [**comandos ejecutados recientemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Hay contraseñas en el [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Credenciales?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Archivos y registro (credenciales)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] ¿Hay [**claves SSH en el registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Hay contraseñas en [**archivos desatendidos**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Hay alguna copia de seguridad de [**SAM y SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Si está presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), intentar leer volúmenes sin procesar en busca de `SAM`, `SYSTEM`, material DPAPI y `MachineKeys`
- [ ] ¿Hay [**credenciales de Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Existe el archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] ¿Existe una [**contraseña GPP en caché**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Hay alguna contraseña en el [**archivo de configuración web de IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Hay información interesante en los [**logs** de **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**solicitar credenciales**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿Hay [**archivos interesantes dentro de la Papelera de reciclaje**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] ¿Hay otro [**registro que contenga credenciales**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Hay datos de [**Browser**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historial, marcadores, ...)?
- [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Handlers con leak](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por un administrador?

### [Suplantación de clientes de Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Comprobar si puedes abusar de ello

## Referencias

- [1] [Project Zero - Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)

{{#include ../banners/hacktricks-training.md}}
