# Lista de Verificación - Escalada de Privilegios Local en Windows

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### **Mejor herramienta para buscar vectores de escalada de privilegios locales en Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Información del Sistema](windows-local-privilege-escalation/#system-info)

* [ ] Obtener [**Información del sistema**](windows-local-privilege-escalation/#system-info)
* [ ] Buscar **exploits de kernel** [**usando scripts**](windows-local-privilege-escalation/#version-exploits)
* [ ] Usar **Google para buscar** exploits de **kernel**
* [ ] Usar **searchsploit para buscar** exploits de **kernel**
* [ ] ¿Información interesante en [**variables de entorno**](windows-local-privilege-escalation/#environment)?
* [ ] ¿Contraseñas en [**historial de PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] ¿Información interesante en [**configuraciones de Internet**](windows-local-privilege-escalation/#internet-settings)?
* [ ] ¿[**Unidades de disco**](windows-local-privilege-escalation/#drives)?
* [ ] ¿[**Explotación de WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] ¿[**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Enumeración de Logging/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Verificar configuraciones de [**Auditoría**](windows-local-privilege-escalation/#audit-settings) y [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Verificar [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Verificar si [**WDigest**](windows-local-privilege-escalation/#wdigest) está activo
* [ ] ¿[**Protección LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] ¿[**Guarda de Credenciales**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] ¿[**Credenciales en Caché**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Verificar si hay algún [**AV**](windows-av-bypass)
* [ ] ¿[**Política de AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Privilegios de Usuario**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Verificar [**privilegios del usuario actual**](windows-local-privilege-escalation/#users-and-groups)
* [ ] ¿Eres [**miembro de algún grupo privilegiado**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Verificar si tienes [alguno de estos tokens habilitados](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] ¿[**Sesiones de Usuarios**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Verificar [**hogares de usuarios**](windows-local-privilege-escalation/#home-folders) (¿acceso?)
* [ ] Verificar [**Política de Contraseñas**](windows-local-privilege-escalation/#password-policy)
* [ ] ¿Qué hay [**dentro del Portapapeles**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Red](windows-local-privilege-escalation/#network)

* [ ] Verificar [**información actual de red**](windows-local-privilege-escalation/#network)
* [ ] Verificar **servicios locales ocultos** restringidos al exterior

### [Procesos en Ejecución](windows-local-privilege-escalation/#running-processes)

* [ ] Permisos de [**archivos y carpetas de procesos**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Minería de Contraseñas en Memoria**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Aplicaciones GUI Inseguras**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Servicios](windows-local-privilege-escalation/#services)

* [ ] [¿Puedes **modificar algún servicio**?](windows-local-privilege-escalation#permissions)
* [ ] [¿Puedes **modificar** el **binario** que es **ejecutado** por algún **servicio**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [¿Puedes **modificar** el **registro** de algún **servicio**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [¿Puedes aprovechar algún **camino de binario de servicio sin comillas**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplicaciones**](windows-local-privilege-escalation/#applications)

* [ ] **Permisos de escritura en aplicaciones instaladas**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Aplicaciones de Inicio**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Drivers** [**Vulnerables**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] ¿Puedes **escribir en alguna carpeta dentro de PATH**?
* [ ] ¿Hay algún servicio conocido que **intente cargar alguna DLL inexistente**?
* [ ] ¿Puedes **escribir** en alguna **carpeta de binarios**?

### [Red](windows-local-privilege-escalation/#network)

* [ ] Enumerar la red (comparticiones, interfaces, rutas, vecinos, ...)
* [ ] Prestar especial atención a los servicios de red que escuchan en localhost (127.0.0.1)

### [Credenciales de Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] Credenciales de [**Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
* [ ] ¿Credenciales de [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que podrías usar?
* [ ] ¿Información interesante en [**credenciales DPAPI**](windows-local-privilege-escalation/#dpapi)?
* [ ] ¿Contraseñas de [**redes Wifi guardadas**](windows-local-privilege-escalation/#wifi)?
* [ ] ¿Información interesante en [**conexiones RDP guardadas**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] ¿Contraseñas en [**comandos recientemente ejecutados**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] ¿Contraseñas en [**Administrador de Credenciales de Escritorio Remoto**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] ¿Existe [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? ¿Credenciales?
* [ ] ¿[**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? ¿Carga lateral de DLL?

### [Archivos y Registro (Credenciales)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Credenciales**](windows-local-privilege-escalation/#putty-creds) **y** [**claves de host SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] ¿[**Claves SSH en el registro**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] ¿Contraseñas en [**archivos desatendidos**](windows-local-privilege-escalation/#unattended-files)?
* [ ] ¿Algún [**respaldo de SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] ¿[**Credenciales en la nube**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] ¿Archivo [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] ¿[**Contraseña GPP en caché**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] ¿Contraseña en [**archivo de configuración web de IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] ¿Información interesante en [**registros web**](windows-local-privilege-escalation/#logs)?
* [ ] ¿Quieres [**pedir credenciales**](windows-local-privilege-escalation/#ask-for-credentials) al usuario?
* [ ] ¿Archivos interesantes [**dentro de la Papelera de Reciclaje**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] ¿Otros [**registros que contienen credenciales**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] ¿Dentro de [**datos del navegador**](windows-local-privilege-escalation/#browsers-history) (dbs, historial, marcadores, ...)?
* [ ] [**Búsqueda genérica de contraseñas**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) en archivos y registro
* [ ] [**Herramientas**](windows-local-privilege-escalation/#tools-that-search-for-passwords) para buscar automáticamente contraseñas

### [Manejadores Filtrados](windows-local-privilege-escalation/#leaked-handlers)

* [ ] ¿Tienes acceso a algún manejador de un proceso ejecutado por el administrador?

### [Impersonación de Cliente de Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Verifica si puedes abusar de ello

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
