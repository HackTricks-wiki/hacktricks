# Checklist - Escalada de privilegios local en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalada de privilegios local en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**información del sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **exploits del kernel** [**mediante scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para buscar** **exploits** del kernel
- [ ] Usar **searchsploit para buscar** **exploits** del kernel
- [ ] ¿Hay información interesante en las [**variables de entorno**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Hay contraseñas en el [**historial de PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Hay información interesante en la [**configuración de Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] ¿[**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] ¿[**Exploit de WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**Actualizadores automáticos de agentes de terceros / abuso de IPC**](windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md)
- [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeración de logs/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Revisar la configuración de [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)y [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Revisar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Revisar si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)está activo
- [ ] ¿[**Protección de LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] ¿[**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] ¿[**Credenciales almacenadas en caché**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Revisar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] ¿[**Política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] ¿[**Protección del administrador / elevación silenciosa de UIAccess**](windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md)?<sup>[[1]](#references)</sup>
- [ ] ¿[**Propagación del registro de accesibilidad de Secure Desktop (RegPwn)**](windows-local-privilege-escalation/secure-desktop-accessibility-registry-propagation-regpwn.md)?<sup>[[2]](#references)</sup>
- [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Revisar los [**privilegios**](windows-local-privilege-escalation/index.html#users-and-groups) del usuario **actual**
- [ ] ¿Eres [**miembro de algún grupo con privilegios**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Revisar si tienes [alguno de estos tokens habilitados](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] Revisar si tienes [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md) para leer volúmenes sin procesar y omitir las ACL de archivos
- [ ] ¿[**Sesiones de usuarios**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Revisar las [**carpetas personales de los usuarios**](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Revisar la [**política de contraseñas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**dentro del portapapeles**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Revisar la [**información** **de red**](windows-local-privilege-escalation/index.html#network) **actual**
- [ ] Revisar los **servicios locales ocultos** que no están expuestos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/index.html#running-processes)

- [ ] [**Permisos de archivos y carpetas**](windows-local-privilege-escalation/index.html#file-and-folder-permissions) de los binarios de procesos
- [ ] [**Búsqueda de contraseñas en memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales con **procesos interesantes** mediante `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/index.html#services)

- [ ] [¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [¿Puedes **modificar** el **binario** que **ejecuta** algún **servicio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [¿Puedes aprovechar alguna **ruta** de **binario** de **servicio sin comillas**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)
- [ ] [Activadores de servicios: enumerar y activar servicios con privilegios](windows-local-privilege-escalation/service-triggers.md)

### [**Aplicaciones**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Permisos de escritura** en [**aplicaciones instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicaciones de inicio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] [**Drivers**](windows-local-privilege-escalation/index.html#drivers) **vulnerables**

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **intente cargar una DLL inexistente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (recursos compartidos, interfaces, rutas, vecinos, ...)
- [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que puedas usar?
- [ ] ¿[**Credenciales DPAPI**](windows-local-privilege-escalation/index.html#dpapi) interesantes?
- [ ] ¿Contraseñas de [**redes Wifi**](windows-local-privilege-escalation/index.html#wifi) guardadas?
- [ ] ¿Información interesante en [**conexiones RDP guardadas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**comandos ejecutados recientemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Contraseñas en [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Credenciales?
- [ ] ¿[**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿DLL Side Loading?

### [Archivos y registro (credenciales)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] ¿[**Claves SSH en el registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**archivos unattended**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Alguna copia de seguridad de [**SAM y SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] Si está presente [**SeManageVolumePrivilege**](windows-local-privilege-escalation/semanagevolume-perform-volume-maintenance-tasks.md), probar a leer volúmenes sin procesar para obtener `SAM`, `SYSTEM`, material DPAPI y `MachineKeys`
- [ ] ¿[**Credenciales de Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] ¿[**Contraseña GPP almacenada en caché**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Contraseña en el [**archivo de configuración web de IIS**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Información interesante en los [**logs** **web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**solicitar credenciales**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿[**Archivos interesantes en la Papelera de reciclaje**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] ¿Otros [**elementos del registro que contienen credenciales**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿[**Datos del navegador**](windows-local-privilege-escalation/index.html#browsers-history) (bases de datos, historial, marcadores, ...)?
- [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y el registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Leaked Handlers](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún handler de un proceso ejecutado por un administrador?

### [Suplantación de cliente de Named Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Revisar si puedes abusar de ello

## References

- [1] [Project Zero - Cómo eludir la protección del administrador abusando de UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [MDSec - RIP RegPwn](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
{{#include ../banners/hacktricks-training.md}}
