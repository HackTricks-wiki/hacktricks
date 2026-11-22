# Lista de verificación - Escalada local de privilegios en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada local de privilegios en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**información del sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **exploits del kernel** [**con scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para buscar** **exploits** del kernel
- [ ] Usar **searchsploit para buscar** **exploits** del kernel
- [ ] ¿Hay información interesante en las [**variables de entorno**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Hay contraseñas en el [**historial de PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Hay información interesante en la [**configuración de Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] ¿[**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] ¿[**Exploit de WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Actualizadores automáticos de agentes de terceros / abuso de IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeración de registros/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Revisar la configuración de [**Auditoría** ](windows-local-privilege-escalation/index.html#audit-settings)y [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Revisar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Comprobar si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está activo
- [ ] ¿[**Protección de LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] ¿[**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] ¿[**Credenciales almacenadas en caché**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Comprobar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] ¿[**Política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] ¿[**Protección de administrador / elevación silenciosa de UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] ¿[**Propagación del registro de accesibilidad de Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Revisar los [**privilegios**](windows-local-privilege-escalation/index.html#users-and-groups) del usuario **actual**
- [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Comprobar si estos [privilegios están presentes en el token actual](windows-local-privilege-escalation/access-tokens.md), aunque aparezcan como **Deshabilitados**: **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege**. Un privilegio deshabilitado solo se puede habilitar si ya está en el token.<sup>[[3]](#references)[[4]](#references)</sup>
- [ ] Comprobar si existe [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), un derecho de mantenimiento de volúmenes. Por sí solo, no otorga acceso de lectura al volumen sin procesar; abrir un disco o volumen también requiere permisos de acceso independientes.<sup>[[5]](#references)[[6]](#references)</sup>
- [ ] ¿[**Sesiones de usuario**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Revisar los [**directorios personales de los usuarios**](windows-local-privilege-escalation/index.html#home-folders) (¿hay acceso?)
- [ ] Revisar la [**política de contraseñas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**dentro del portapapeles**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Revisar la [**información** **de red**](windows-local-privilege-escalation/index.html#network) **actual**
- [ ] Revisar los **servicios locales ocultos** restringidos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permisos de archivos y carpetas**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) de los binarios de los procesos
- [ ] [**Búsqueda de contraseñas en memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales de **procesos interesantes** mediante `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/index.html#services)

- [ ] [¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [¿Puedes **modificar** el **binario** que **ejecuta** algún **servicio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [¿Puedes aprovechar la **ruta** de un binario de **servicio sin comillas**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Activadores de servicios: enumerar y activar servicios privilegiados](windows-local-privilege-escalation/service-triggers.md)

### [**Aplicaciones**](windows-local-privilege-escalation/index.html#applications)

- [ ] [**Permisos de escritura sobre las aplicaciones instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicaciones de inicio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulnerables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **intente cargar una DLL inexistente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (shares, interfaces, rutas, vecinos, ...)
- [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] ¿Hay credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que puedas usar?
- [ ] ¿Hay [**credenciales DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interesantes?
- [ ] ¿Hay contraseñas de [**redes Wifi**](windows-local-privilege-escalation/index.html#wifi) guardadas?
- [ ] ¿Hay información interesante en las [**conexiones RDP guardadas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Hay contraseñas en los [**comandos ejecutados recientemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Hay contraseñas en [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿[**Existe AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Hay credenciales?
- [ ] ¿[**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Archivos y registro (credenciales)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] ¿Hay [**claves SSH en el registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Hay contraseñas en [**archivos desatendidos**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Hay alguna copia de seguridad de [**SAM y SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Si se permite de forma independiente el acceso de lectura a un identificador de volumen sin procesar, evalúa la posible exposición de `SAM`, `SYSTEM`, material DPAPI y `MachineKeys`; no deduzcas que existe este acceso solo por **SeManageVolumePrivilege**.<sup>[[5]](#references)</sup>
- [ ] ¿Hay [**credenciales de cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Existe el archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] ¿Hay [**contraseñas GPP almacenadas en caché**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Hay contraseñas en el [**archivo de configuración web de IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Hay información interesante en los [**registros** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**pedirle credenciales**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿Hay [**archivos interesantes en la papelera de reciclaje**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] ¿Hay otros [**elementos del registro que contengan credenciales**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Hay datos del [**navegador**](windows-local-privilege-escalation/index.html#browsers-history) (bases de datos, historial, marcadores, ...)?
- [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y el registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por un administrador?

### [Suplantación de clientes de Named Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Comprobar si puedes abusar de ello



## References

- [1] [Project Zero - Eludir la protección de administrador mediante el abuso de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [3] [Microsoft - Privilegios](https://learn.microsoft.com/en-us/windows/win32/secauthz/privileges)
- [4] [Microsoft - Cambiar privilegios en un token](https://learn.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token)
- [5] [Microsoft - CreateFile: discos físicos y volúmenes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [6] [Microsoft - Administración de privilegios en un sistema de archivos](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)
{{#include ../banners/hacktricks-training.md}}
