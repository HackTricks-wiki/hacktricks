# Lista de comprobación de escalada de privilegios en Linux

{{#include ../../banners/hacktricks-training.md}}

# Lista de comprobación - Escalada de privilegios en Linux



### **Mejor herramienta para buscar vectores de escalada de privilegios local en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtener **información del SO**
- [ ] Comprobar el [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), ¿hay alguna **carpeta escribible**?
- [ ] Comprobar las [**variables de entorno**](../linux-basics/linux-privilege-escalation/index.html#env-info), ¿hay algún detalle sensible?
- [ ] Buscar [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (¿DirtyCow?)
- [ ] **Comprobar** si la [**versión de sudo** es vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Fallo de verificación de firma de [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar las [**configuraciones incorrectas de kernel modules y module-loading**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, aplicación de firmas y `modules_disabled`.
- [ ] Comprobar las [**rutas de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) si la ruta del helper puede modificarse o activarse.
- [ ] Comprobar las [**rutas escribibles de /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluidos los archivos `.ko*` y los metadatos `modules.*` escribibles.
- [ ] Más enum del sistema ([fecha, estadísticas del sistema, información de la CPU, impresoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar más defensas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unidades](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Listar** las unidades montadas
- [ ] **¿Hay alguna unidad sin montar?**
- [ ] **¿Hay credenciales en fstab?**

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Comprobar si hay**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Comprobar si hay** [**software vulnerable**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Procesos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] ¿Se está ejecutando algún **software desconocido**?
- [ ] ¿Se está ejecutando algún software con **más privilegios de los que debería tener**?
- [ ] Buscar **exploits de procesos en ejecución** (especialmente de la versión en ejecución).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorizar los procesos** y comprobar si algún proceso interesante se ejecuta con frecuencia.
- [ ] ¿Puedes **leer** la **memoria de algún proceso** interesante (donde podrían guardarse contraseñas)?

### [¿Tareas programadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] ¿Se está modificando el [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)mediante algún cron y puedes **escribir** en él?
- [ ] ¿Hay algún [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)en un cron job?
- [ ] ¿Se está **ejecutando** algún [**script modificable** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)o está dentro de una **carpeta modificable**?
- [ ] ¿Has detectado que algún **script** podría o está siendo [**ejecutado** con mucha **frecuencia**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] ¿Hay algún archivo **.service escribible**?
- [ ] ¿Hay algún **binario escribible** ejecutado por un **servicio**?
- [ ] ¿Hay alguna **carpeta escribible en el PATH de systemd**?
- [ ] ¿Hay algún **systemd unit drop-in escribible** en `/etc/systemd/system/<unit>.d/*.conf` que pueda sobrescribir `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] ¿Hay algún **timer escribible**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] ¿Hay algún archivo **.socket escribible**?
- [ ] ¿Puedes **comunicarte con algún socket**?
- [ ] ¿Hay **sockets HTTP** con información interesante?

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
- [ ] ¿Política de contraseñas?
- [ ] Intenta **usar** cada **contraseña conocida** que hayas descubierto anteriormente para iniciar sesión **con cada** **usuario** posible. Intenta iniciar sesión también sin contraseña.

### [PATH escribible](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Si tienes **permisos de escritura sobre alguna carpeta del PATH**, podrías ser capaz de escalar privilegios

### [Comandos SUDO y SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] ¿Puedes ejecutar **algún comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR cualquier cosa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` permite `sudoedit`, comprueba la **inyección de argumentos de sudoedit** (CVE-2023-22809) mediante `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar archivos arbitrarios en versiones vulnerables (`sudo -V` < 1.9.12p2). Ejemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Los comandos de [**sudo** están **limitados** por la **ruta**? ¿Puedes **evitar** las restricciones](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] ¿[**Binario Sudo/SUID sin ruta indicada**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] ¿[**Binario SUID especificando una ruta**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vulnerabilidad de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] ¿Falta alguna [**biblioteca .so en un binario SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) en una carpeta escribible?
- [ ] ¿[**SUID RPATH/RUNPATH o ruta de biblioteca escribible**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] ¿Hay [**tokens de SUDO disponibles**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? ¿[**Puedes crear un token de SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] ¿Puedes [**leer o modificar los archivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
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

- [ ] **Debian** [**PRNG predecible de OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuración interesantes de SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Archivos interesantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Comprobar las carpetas habitualmente interesantes** en busca de datos sensibles
- [ ] **Archivos en ubicaciones extrañas o propiedad de usuarios,** podrías tener acceso a archivos ejecutables o poder alterarlos
- [ ] **Modificados** en los últimos minutos
- [ ] **Archivos de bases de datos Sqlite**
- [ ] **Archivos ocultos**
- [ ] **Scripts/Binaries en el PATH**
- [ ] **Archivos web** (¿contraseñas?)
- [ ] ¿**Backups**?
- [ ] **Archivos conocidos que contienen contraseñas**: Usar **Linpeas** y **LaZagne**
- [ ] **Búsqueda genérica**

### [**Archivos escribibles**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] ¿**Modificar una biblioteca de Python** para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modificar archivos de log**? Exploit **Logtotten**
- [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Exploit de Centos/Redhat
- [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escapar de una shell restrictiva**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?

## Referencias

- [1] [Aviso de Sudo: edición de archivos arbitrarios mediante sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentación de Oracle Linux: configuración de systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
