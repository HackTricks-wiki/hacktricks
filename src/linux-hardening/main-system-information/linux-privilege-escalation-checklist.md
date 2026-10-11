# Lista de comprobación de escalada de privilegios en Linux

{{#include ../../banners/hacktricks-training.md}}

# Lista de comprobación - Escalada de privilegios en Linux



### **Mejor herramienta para buscar vectores de escalada de privilegios local en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtener **información del SO**
- [ ] Comprobar [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), ¿hay alguna **carpeta con permisos de escritura**?
- [ ] Comprobar las [**variables de entorno**](../linux-basics/linux-privilege-escalation/index.html#env-info), ¿hay algún dato sensible?
- [ ] Buscar [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (¿DirtyCow?)
- [ ] Antes de ejecutar un PoC del kernel, verifica sus **requisitos reales**, no solo `uname -r`: arquitectura, opciones/módulos `CONFIG_*` necesarios, creación de namespaces y mitigaciones activas. Por ejemplo, prueba si se pueden crear user/network namespaces con `unshare -Urn true`; los exploits modernos de netfilter pueden requerir `CONFIG_USER_NS`, user namespaces sin privilegios y `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Comprobar** si la [**versión de sudo** es vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Falló la verificación de la firma de Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar [**errores de configuración de módulos del kernel y su carga**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, aplicación de firmas y `modules_disabled`.
- [ ] Comprobar [**vías de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) si se puede modificar o activar la ruta del helper.
- [ ] Comprobar [**rutas con permisos de escritura en /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluidos archivos `.ko*` y metadatos `modules.*` con permisos de escritura.
- [ ] Más enumeración del sistema ([fecha, estadísticas del sistema, información de CPU, impresoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar más defensas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unidades](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Listar las unidades montadas**
- [ ] **¿Hay alguna unidad sin montar?**
- [ ] **¿Hay credenciales en fstab?**

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Comprobar si hay**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Comprobar si hay** [**software vulnerable**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**
- [ ] En Debian/Ubuntu, comprobar si está instalado/habilitado el **escaneo de intérpretes de needrestart**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Las versiones vulnerables cruzaban el límite de privilegios al reutilizar `PYTHONPATH`/`RUBYLIB` controlados por el atacante, competir por `/proc/<pid>/exe` o escanear rutas de Perl controladas por el atacante cuando APT o `unattended-upgrades` invocaban needrestart como root.<sup>[[4]](#references)</sup>

### [Procesos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] ¿Se está ejecutando algún **software desconocido**?
- [ ] ¿Se está ejecutando algún software con **más privilegios de los que debería tener**?
- [ ] Buscar **exploits para los procesos en ejecución** (especialmente para la versión que se está ejecutando).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorizar los procesos** y comprobar si algún proceso interesante se ejecuta con frecuencia.
- [ ] ¿Puedes **leer** la **memoria de algún proceso** interesante (donde podrían guardarse contraseñas)?

### [¿Tareas programadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] ¿Algún cron está modificando [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)y puedes **escribir** en él?
- [ ] ¿Hay algún [**comodín** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)en una tarea cron?
- [ ] ¿Se está **ejecutando** algún [**script modificable** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)o está dentro de una **carpeta modificable**?
- [ ] ¿Has detectado algún **script** que pueda estar o esté siendo [**ejecutado** con mucha **frecuencia**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] ¿Hay algún archivo **.service con permisos de escritura**?
- [ ] ¿Hay algún **binario con permisos de escritura** que ejecute un **servicio**?
- [ ] ¿Hay algún **helper, archivo de configuración o de entorno con permisos de escritura referenciado por una unidad root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspecciona la unidad combinada con `systemctl cat <unit>` y revisa el [abuso de archivos de servicio/socket](../interesting-files-permissions/write-to-root.md).
- [ ] ¿Un flujo de trabajo privilegiado bajo demanda ejecuta un helper en un directorio con permisos de escritura para un usuario con menos privilegios? Comprueba tanto el helper como su directorio padre para detectar [ejecución por root de rutas modificables por el usuario](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); los helpers de corta duración podrían aparecer solo mientras se ejecuta el flujo de trabajo.
- [ ] ¿Hay alguna **carpeta con permisos de escritura en el PATH de systemd**?
- [ ] ¿Hay algún **drop-in de unidad de systemd con permisos de escritura** en `/etc/systemd/system/<unit>.d/*.conf` que pueda sobrescribir `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] ¿Hay algún **timer con permisos de escritura**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] ¿Hay algún archivo **.socket con permisos de escritura**?
- [ ] ¿Puedes **comunicarte con algún socket**?
- [ ] ¿Hay **sockets HTTP** con información interesante?
- [ ] ¿Puedes acceder a una [**API de container-runtime o node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) como `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` o un endpoint de kubelet? Prueba la API HTTP/gRPC directamente aunque no esté disponible su CLI habitual.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerar la red para saber dónde estás
- [ ] ¿Hay **puertos abiertos a los que no podías acceder antes** de obtener una shell en la máquina?
- [ ] ¿Puedes **capturar tráfico** usando `tcpdump`?

### [Usuarios](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeración** general de usuarios/grupos
- [ ] ¿Tienes un **UID muy alto**? ¿Es la **máquina** **vulnerable**?
- [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](../user-information/interesting-groups-linux-pe/index.html) al que perteneces?
- [ ] ¿Hay datos del **portapapeles**?
- [ ] ¿Política de contraseñas?
- [ ] Intenta **usar** todas las **contraseñas conocidas** que hayas descubierto previamente para iniciar sesión **con cada** **usuario** posible. Intenta iniciar sesión también sin contraseña.

### [PATH con permisos de escritura](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Si tienes **permisos de escritura en alguna carpeta de PATH**, podrías escalar privilegios

### [Comandos SUDO y SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] ¿Puedes ejecutar **algún comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` permite `sudoedit`, comprueba la **inyección de argumentos de sudoedit** (CVE-2023-22809) mediante `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar archivos arbitrarios en versiones vulnerables (`sudo -V` < 1.9.12p2). Ejemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Los comandos de [**sudo** están **limitados** por la **ruta**? ¿Puedes **eludir** las restricciones](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Comando sudo/binario SUID sin ruta indicada**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID con ruta especificada**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Eludir la restricción
- [ ] [**Vulnerabilidad de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] ¿Falta una [**biblioteca .so en un binario SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) dentro de una carpeta con permisos de escritura?
- [ ] ¿Hay [**RPATH/RUNPATH SUID o una ruta de biblioteca con permisos de escritura**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] ¿Hay [**tokens SUDO disponibles**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**¿Puedes crear un token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] ¿Puedes [**leer o modificar archivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] ¿Tiene algún binario alguna **capability inesperada**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] ¿Tiene algún archivo alguna **ACL inesperada**?

### [Sesiones de shell abiertas](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuración interesantes de SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Archivos interesantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Comprobar carpetas que suelen ser interesantes** en busca de datos sensibles
- [ ] **Archivos en ubicaciones/rutas extrañas o con propietario inusual;** podrías tener acceso a archivos ejecutables o poder modificarlos
- [ ] **Modificados** en los últimos minutos
- [ ] **Archivos de bases de datos Sqlite**
- [ ] **Archivos ocultos**
- [ ] **Scripts/binarios en PATH**
- [ ] **Archivos web** (¿contraseñas?)
- [ ] ¿**Copias de seguridad**?
- [ ] **Archivos conocidos que contienen contraseñas**: usa **Linpeas** y **LaZagne**
- [ ] **Búsqueda general**

### [**Archivos con permisos de escritura**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] ¿Modificar una **biblioteca de Python** para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modificar archivos de registro**? Exploit **Logtotten**
- [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Exploit para Centos/Redhat
- [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escapar de una shell restrictiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Aviso de Sudo: edición arbitraria de archivos con sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentación de Oracle Linux: configuración drop-in de systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisitos e investigación del exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Aviso de seguridad de Qualys: LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
