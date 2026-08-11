# Checklist de escalada de privilegios en Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalada de privilegios en Linux



### **Mejor herramienta para buscar vectores de escalada de privilegios local en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtener **información del sistema operativo**
- [ ] Comprobar el [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), ¿hay alguna **carpeta escribible**?
- [ ] Comprobar las [**variables de entorno**](../linux-basics/linux-privilege-escalation/index.html#env-info), ¿hay algún detalle sensible?
- [ ] Buscar [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (¿DirtyCow?)
- [ ] Antes de ejecutar un PoC del kernel, verificar sus **prerrequisitos reales**, no solo `uname -r`: arquitectura, opciones/módulos `CONFIG_*` necesarios, creación de namespaces y mitigaciones activas. Por ejemplo, probar la disponibilidad de user/network namespaces con `unshare -Urn true`; los exploits modernos de netfilter pueden requerir `CONFIG_USER_NS`, user namespaces sin privilegios y `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Comprobar** si la [**versión de sudo** es vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Falló la verificación de la firma de Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar las [**configuraciones incorrectas de kernel modules y de carga de módulos**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, imposición de firmas y `modules_disabled`.
- [ ] Comprobar las [**rutas de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) si la ruta del helper puede modificarse o activarse.
- [ ] Comprobar las [**rutas escribibles de /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluidos los archivos `.ko*` y los metadatos `modules.*` escribibles.
- [ ] Más enumeración del sistema ([fecha, estadísticas del sistema, información de la CPU, impresoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar más defensas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unidades](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Listar** las unidades montadas
- [ ] **¿Hay alguna unidad desmontada?**
- [ ] **¿Hay credenciales en fstab?**

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Comprobar si hay**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Comprobar si hay** [**software vulnerable**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**
- [ ] En Debian/Ubuntu, comprobar si **needrestart interpreter scanning** está instalado/activado: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Las compilaciones vulnerables cruzaban el límite de privilegios reutilizando `PYTHONPATH`/`RUBYLIB` controlados por el atacante, provocando una carrera con `/proc/<pid>/exe` o analizando rutas de Perl controladas por el atacante cuando APT o `unattended-upgrades` invocaban needrestart como root.<sup>[[4]](#references)</sup>

### [Procesos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] ¿Se está ejecutando algún **software desconocido**?
- [ ] ¿Hay algún software ejecutándose con **más privilegios de los que debería tener**?
- [ ] Buscar **exploits de procesos en ejecución** (especialmente de la versión en ejecución).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorizar los procesos** y comprobar si algún proceso interesante se ejecuta con frecuencia.
- [ ] ¿Puedes **leer** la **memoria de algún proceso** interesante (donde podrían guardarse contraseñas)?

### [¿Tareas programadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] ¿Está siendo modificado el [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)por algún cron y puedes **escribir** en él?
- [ ] ¿Hay algún [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)en un cron job?
- [ ] ¿Se está **ejecutando** algún [**script modificable** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) o está dentro de una **carpeta modificable**?
- [ ] ¿Has detectado que algún **script** podría estar o está siendo [**ejecutado** con mucha **frecuencia**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] ¿Hay algún archivo **.service escribible**?
- [ ] ¿Hay algún **binario escribible** ejecutado por un **servicio**?
- [ ] ¿Hay algún **helper, archivo de configuración o archivo de entorno** escribible referenciado por una unit de root (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspeccionar la unit combinada con `systemctl cat <unit>` y revisar el [abuso de archivos de service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] ¿Hay alguna **carpeta escribible en el PATH de systemd**?
- [ ] ¿Hay algún **drop-in de unit de systemd escribible** en `/etc/systemd/system/<unit>.d/*.conf` que pueda sobrescribir `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] ¿Hay algún **timer escribible**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] ¿Hay algún archivo **.socket escribible**?
- [ ] ¿Puedes **comunicarte con algún socket**?
- [ ] ¿Hay **sockets HTTP** con información interesante?
- [ ] ¿Puedes acceder a una [**API de container-runtime o node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) como `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` o un endpoint de kubelet? Probar la API HTTP/gRPC sin procesar incluso cuando su CLI habitual no esté disponible.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerar la red para saber dónde estás
- [ ] ¿Hay **puertos abiertos a los que antes no podías acceder** tras obtener una shell dentro de la máquina?
- [ ] ¿Puedes **sniffear tráfico** usando `tcpdump`?

### [Usuarios](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeración** genérica de usuarios/grupos
- [ ] ¿Tienes un **UID muy grande**? ¿La **máquina** es **vulnerable**?
- [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](../user-information/interesting-groups-linux-pe/index.html) al que perteneces?
- [ ] ¿Hay datos del **portapapeles**?
- [ ] ¿Cuál es la política de contraseñas?
- [ ] Intentar **usar** todas las **contraseñas conocidas** que hayas descubierto previamente para iniciar sesión **con cada** **usuario** posible. Intentar iniciar sesión también sin contraseña.

### [PATH escribible](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Si tienes **permisos de escritura sobre alguna carpeta del PATH**, es posible que puedas escalar privilegios

### [Comandos SUDO y SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] ¿Puedes ejecutar **cualquier comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR cualquier cosa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` permite `sudoedit`, comprobar la **inyección de argumentos de sudoedit** (CVE-2023-22809) mediante `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar archivos arbitrarios en versiones vulnerables (`sudo -V` < 1.9.12p2). Ejemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Los comandos de [**sudo** están **limitados** por la **ruta**? ¿Puedes **evitar** las restricciones](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binario Sudo/SUID sin ruta indicada**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**¿Binario SUID especificando una ruta**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Evitarlo
- [ ] [**Vulnerabilidad de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Falta una librería .so en el binario SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) desde una carpeta escribible?
- [ ] [**SUID RPATH/RUNPATH o ruta de librería escribible**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens disponibles**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**¿Puedes crear un SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
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

- [ ] **Archivos de Profile** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Comprobar carpetas comúnmente interesantes** en busca de datos sensibles
- [ ] **Archivos en ubicaciones/propiedad extrañas**, puedes tener acceso a archivos ejecutables o alterarlos
- [ ] **Modificados** en los últimos minutos
- [ ] **Archivos de bases de datos Sqlite**
- [ ] **Archivos ocultos**
- [ ] **Scripts/binarios en el PATH**
- [ ] **Archivos web** (¿contraseñas?)
- [ ] ¿Hay **backups**?
- [ ] **Archivos conocidos que contienen contraseñas**: usar **Linpeas** y **LaZagne**
- [ ] **Búsqueda genérica**

### [**Archivos escribibles**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] ¿Puedes **modificar una librería de Python** para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modificar archivos de log**? Exploit **Logtotten**
- [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Exploit de Centos/Redhat
- [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escapar de una shell restrictiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Aviso de Sudo: edición arbitraria de archivos con sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentación de Oracle Linux: configuración de drop-in de systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisitos e investigación del exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Aviso de seguridad de Qualys: LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
