# Lista de verificación - Escalación de privilegios local en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalación de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtener [**Información del sistema**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Buscar **exploits de kernel** [**usando scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Usar **Google para buscar** **exploits de kernel**
- [ ] Usar **searchsploit para buscar** **exploits de kernel**
- [ ] ¿Información interesante en [**variables de entorno**](windows-local-privilege-escalation/index.html#environment)?
- [ ] ¿Contraseñas en [**historial de PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] ¿Información interesante en [**configuraciones de Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] ¿[**Unidades**](windows-local-privilege-escalation/index.html#drives)?
- [ ] ¿[**Explotación de WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Enumeración de registros/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Verificar [**configuraciones de auditoría**](windows-local-privilege-escalation/index.html#audit-settings) y [**WEF**](windows-local-privilege-escalation/index.html#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Verificar si [**WDigest**](windows-local-privilege-escalation/index.html#wdigest) está activo
- [ ] ¿[**Protección de LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] ¿[**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] ¿[**Credenciales en caché**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Verificar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] ¿[**Política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] ¿[**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)?
- [ ] ¿[**Privilegios de usuario**](windows-local-privilege-escalation/index.html#users-and-groups)?
- [ ] Verificar [**privilegios del usuario actual**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Verificar si tienes [cualquiera de estos tokens habilitados](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] ¿[**Sesiones de usuarios**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Verificar [**carpetas de usuarios**](windows-local-privilege-escalation/index.html#home-folders) (¿acceso?)
- [ ] Verificar [**Política de Contraseñas**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] ¿Qué hay [**dentro del portapapeles**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Verificar **información de red** [**actual**](windows-local-privilege-escalation/index.html#network)
- [ ] Verificar **servicios locales ocultos** restringidos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permisos de [**archivos y carpetas de procesos**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Minería de contraseñas en memoria**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] ¿Robar credenciales con **procesos interesantes** a través de `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/index.html#services)

- [ ] ¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] ¿Puedes **modificar** el **binario** que es **ejecutado** por algún **servicio**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] ¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] ¿Puedes aprovechar cualquier **ruta de binario de servicio no citada**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Aplicaciones**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Escribir** [**permisos en aplicaciones instaladas**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Aplicaciones de inicio**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Controladores** [**vulnerables**](windows-local-privilege-escalation/index.html#drivers)

### [Secuestro de DLL](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **intente cargar alguna DLL no existente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/index.html#network)

- [ ] Enumerar la red (comparticiones, interfaces, rutas, vecinos, ...)
- [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] Credenciales de [**Winlogon**](windows-local-privilege-escalation/index.html#winlogon-credentials)
- [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) que podrías usar?
- [ ] ¿Interesantes [**credenciales DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] ¿Contraseñas de [**redes Wifi guardadas**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] ¿Información interesante en [**Conexiones RDP guardadas**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**comandos ejecutados recientemente**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] ¿Contraseñas de [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/index.html#appcmd-exe)? ¿Credenciales?
- [ ] ¿[**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? ¿Carga lateral de DLL?

### [Archivos y Registro (Credenciales)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/index.html#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] ¿[**Claves SSH en el registro**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**archivos desatendidos**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] ¿Alguna copia de seguridad de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] ¿[**Credenciales en la nube**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] ¿Archivo de [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] ¿[**Contraseña GPP en caché**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] ¿Contraseña en [**archivo de configuración de IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] ¿Información interesante en [**registros web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] ¿Quieres [**pedir credenciales**](windows-local-privilege-escalation/index.html#ask-for-credentials) al usuario?
- [ ] ¿Interesantes [**archivos dentro de la Papelera de reciclaje**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] ¿Otros [**registros que contienen credenciales**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] ¿Dentro de [**datos del navegador**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historial, marcadores, ...)?
- [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) en archivos y registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Manejadores filtrados](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] ¿Tienes acceso a algún manejador de un proceso ejecutado por el administrador?

### [Suplantación de cliente de Pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Verificar si puedes abusar de ello

{{#include ../banners/hacktricks-training.md}}
