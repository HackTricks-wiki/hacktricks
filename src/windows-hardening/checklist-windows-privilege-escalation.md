# Lista de verificación - Escalación de privilegios local en Windows

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalación de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/#system-info)

- [ ] Obtener [**Información del sistema**](windows-local-privilege-escalation/#system-info)
- [ ] Buscar **exploits de kernel** [**usando scripts**](windows-local-privilege-escalation/#version-exploits)
- [ ] Usar **Google para buscar** **exploits de kernel**
- [ ] Usar **searchsploit para buscar** **exploits de kernel**
- [ ] ¿Información interesante en [**variables de entorno**](windows-local-privilege-escalation/#environment)?
- [ ] ¿Contraseñas en [**historial de PowerShell**](windows-local-privilege-escalation/#powershell-history)?
- [ ] ¿Información interesante en [**configuraciones de Internet**](windows-local-privilege-escalation/#internet-settings)?
- [ ] ¿[**Unidades**](windows-local-privilege-escalation/#drives)?
- [ ] ¿[**Explotación de WSUS**](windows-local-privilege-escalation/#wsus)?
- [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeración de registros/AV](windows-local-privilege-escalation/#enumeration)

- [ ] Verificar [**configuraciones de auditoría**](windows-local-privilege-escalation/#audit-settings) y [**WEF**](windows-local-privilege-escalation/#wef)
- [ ] Verificar [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Verificar si [**WDigest**](windows-local-privilege-escalation/#wdigest) está activo
- [ ] ¿[**Protección de LSA**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] ¿[**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] ¿[**Credenciales en caché**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Verificar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] ¿[**Política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Verificar [**privilegios del usuario actual**](windows-local-privilege-escalation/#users-and-groups)
- [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Verificar si tienes [cualquiera de estos tokens habilitados](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] ¿[**Sesiones de usuarios**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Verificar [**carpetas de usuarios**](windows-local-privilege-escalation/#home-folders) (¿acceso?)
- [ ] Verificar [**Política de contraseñas**](windows-local-privilege-escalation/#password-policy)
- [ ] ¿Qué hay [**dentro del portapapeles**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/#network)

- [ ] Verificar **información de red** [**actual**](windows-local-privilege-escalation/#network)
- [ ] Verificar **servicios locales ocultos** restringidos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/#running-processes)

- [ ] Permisos de [**archivos y carpetas de procesos**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Minería de contraseñas en memoria**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] ¿Robar credenciales con **procesos interesantes** a través de `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/#services)

- [ ] ¿Puedes **modificar algún servicio**?
- [ ] ¿Puedes **modificar** el **binario** que es **ejecutado** por algún **servicio**?
- [ ] ¿Puedes **modificar** el **registro** de algún **servicio**?
- [ ] ¿Puedes aprovechar algún **camino de binario de servicio no citado**?

### [**Aplicaciones**](windows-local-privilege-escalation/#applications)

- [ ] **Escribir** [**permisos en aplicaciones instaladas**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Aplicaciones de inicio**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Controladores** [**vulnerables**](windows-local-privilege-escalation/#drivers)

### [Secuestro de DLL](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
- [ ] ¿Hay algún binario de servicio conocido que **intente cargar alguna DLL no existente**?
- [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/#network)

- [ ] Enumerar la red (comparticiones, interfaces, rutas, vecinos, ...)
- [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/#windows-credentials)

- [ ] Credenciales de [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
- [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que podrías usar?
- [ ] ¿Credenciales [**DPAPI**](windows-local-privilege-escalation/#dpapi) interesantes?
- [ ] ¿Contraseñas de redes [**Wifi guardadas**](windows-local-privilege-escalation/#wifi)?
- [ ] ¿Información interesante en [**Conexiones RDP guardadas**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] ¿Contraseñas en [**comandos ejecutados recientemente**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] ¿Contraseñas del [**Administrador de credenciales de Escritorio Remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
- [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? ¿Credenciales?
- [ ] ¿[**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? ¿Carga lateral de DLL?

### [Archivos y Registro (Credenciales)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] ¿[**Claves SSH en el registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] ¿Contraseñas en [**archivos desatendidos**](windows-local-privilege-escalation/#unattended-files)?
- [ ] ¿Alguna copia de seguridad de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
- [ ] ¿[**Credenciales en la nube**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] ¿Archivo de [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
- [ ] ¿[**Contraseña GPP en caché**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] ¿Contraseña en [**archivo de configuración de IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] ¿Información interesante en [**registros web**](windows-local-privilege-escalation/#logs)?
- [ ] ¿Quieres [**pedir credenciales**](windows-local-privilege-escalation/#ask-for-credentials) al usuario?
- [ ] ¿Archivos interesantes dentro de la [**Papelera de reciclaje**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] ¿Otros [**registros que contienen credenciales**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] ¿Dentro de [**datos del navegador**](windows-local-privilege-escalation/#browsers-history) (dbs, historial, marcadores, ...)?
- [ ] [**Búsqueda de contraseñas genéricas**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) en archivos y registro
- [ ] [**Herramientas**](windows-local-privilege-escalation/#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Manejadores filtrados](windows-local-privilege-escalation/#leaked-handlers)

- [ ] ¿Tienes acceso a algún manejador de un proceso ejecutado por el administrador?

### [Suplantación de cliente de Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Verifica si puedes abusar de ello

{{#include ../banners/hacktricks-training.md}}
