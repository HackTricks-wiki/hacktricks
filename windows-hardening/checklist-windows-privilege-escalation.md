# Checklist - Local Windows Privilege Escalation

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del sistema](windows-local-privilege-escalation/#system-info)

* [ ] Obtener [**información del sistema**](windows-local-privilege-escalation/#system-info)
* [ ] Buscar **exploits de kernel** [**utilizando scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Usar **Google para buscar** exploits de kernel
* [ ] Usar **searchsploit para buscar** exploits de kernel
* [ ] ¿Información interesante en las [**variables de entorno**](windows-local-privilege-escalation/#environment)?
* [ ] Contraseñas en el [**historial de PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Información interesante en la [**configuración de Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Unidades**](windows-local-privilege-escalation/#drives)?
* [ ] [**Explotación de WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeración de registro/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Verificar la configuración de [**Auditoría**](windows-local-privilege-escalation/#audit-settings) y [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Verificar [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Verificar si está activo [**WDigest**](windows-local-privilege-escalation/#wdigest)
* [ ] [**Protección de LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guardia de Credenciales**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Credenciales en caché**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Verificar si hay algún [**AV**](https://github.com/carlospolop/hacktricks/blob/es/windows-hardening/windows-av-bypass/README.md)
* [ ] [**Política de AppLocker**](https://github.com/carlospolop/hacktricks/blob/es/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/es/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Privilegios de usuario**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Verificar los [**privilegios actuales** del usuario](windows-local-privilege-escalation/#users-and-groups)
* [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Verificar si tienes habilitados [algunos de estos tokens](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Sesiones de usuarios**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Verificar los [**directorios de inicio de usuarios**](windows-local-privilege-escalation/#home-folders) (¿acceso?)
* [ ] Verificar la [**política de contraseñas**](windows-local-privilege-escalation/#password-policy)
* [ ] ¿Qué hay [**dentro del Portapapeles**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/#network)

* Verificar la [**información de red actual**](windows-local-privilege-escalation/#network)
* Verificar los **servicios locales ocultos** restringidos al exterior

### [Procesos en ejecución](windows-local-privilege-escalation/#running-processes)

* Permisos de [**archivos y carpetas de los binarios de procesos**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Extracción de contraseñas de memoria**](windows-local-privilege-escalation/#memory-password-mining)
* [**Aplicaciones GUI inseguras**](windows-local-privilege-escalation/#insecure-gui-apps)
* ¿Robar credenciales con **procesos interesantes** a través de `ProcDump.exe`? (firefox, chrome, etc ...)

### [Servicios](windows-local-privilege-escalation/#services)

* [¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation/#permissions)
* [¿Puedes **modificar** el **binario** que es **ejecutado** por algún **servicio**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* ¿Puedes aprovecharte de alguna **ruta de binario de servicio sin comillas**? (windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplicaciones**](windows-local-privilege-escalation/#applications)

* **Permisos de escritura en aplicaciones instaladas**]\(windows-local-privilege-escalation/#write-permissions)
* [**Aplicaciones de inicio**](windows-local-privilege-escalation/#run-at-startup)
* **Controladores** [**Vulnerables**](windows-local-privilege-escalation/#drivers)

### [Secuestro de DLL](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] ¿Puedes **escribir en cualquier carpeta dentro de PATH**?
* [ ] ¿Hay algún binario de servicio conocido que **intente cargar alguna DLL inexistente**?
* [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/#network)

* [ ] Enumera la red (compartidos, interfaces, rutas, vecinos, ...)
* [ ] Presta especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Credenciales de [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que podrías usar?
* [ ] ¿Credenciales de [**DPAPI**](windows-local-privilege-escalation/#dpapi) interesantes?
* [ ] Contraseñas de redes Wifi guardadas
* [ ] Información interesante en [**conexiones RDP guardadas**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Contraseñas en [**comandos ejecutados recientemente**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Contraseñas del [**Administrador de credenciales de Escritorio remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? ¿Credenciales?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? ¿Carga lateral de DLL?

### [Archivos y Registro (Credenciales)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] ¿Claves SSH en el registro?
* [ ] Contraseñas en [**archivos sin supervisión**](windows-local-privilege-escalation/#unattended-files)?
* [ ] ¿Algún respaldo de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] ¿Credenciales de [**nube**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] Contraseña [**GPP en caché**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Contraseña en el archivo de configuración web de [**IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Información interesante en [**logs web**](windows-local-privilege-escalation/#logs)?
* [ ] ¿Quieres [**solicitar credenciales**](windows-local-privilege-escalation/#ask-for-credentials) al usuario?
* [ ] Archivos interesantes dentro de la [**Papelera de reciclaje**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Otro [**registro que contiene credenciales**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Dentro de los [**datos del navegador**](windows-local-privilege-escalation/#browsers-history) (bases de datos, historial, marcadores, ...)?
* [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) en archivos y registro
* [ ] [**Herramientas**](windows-local-privilege-escalation/#tools-that-search-for-passwords) para buscar contraseñas automáticamente

### [Manejadores Filtrados](windows-local-privilege-escalation/#leaked-handlers)

* [ ] ¿Tienes acceso a algún manejador de un proceso ejecutado por el administrador?

### [Impersonación de Cliente de Tubería](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Verifica si puedes abusar de ello

**Grupo de Seguridad Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
