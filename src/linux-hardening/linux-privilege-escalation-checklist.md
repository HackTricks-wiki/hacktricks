# Lista de verificación - Escalación de privilegios en Linux

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de escalación de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del sistema](privilege-escalation/#system-information)

- [ ] Obtener **información del SO**
- [ ] Verificar el [**PATH**](privilege-escalation/#path), ¿hay alguna **carpeta escribible**?
- [ ] Verificar [**variables de entorno**](privilege-escalation/#env-info), ¿hay algún detalle sensible?
- [ ] Buscar [**exploits del kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (¿DirtyCow?)
- [ ] **Verificar** si la [**versión de sudo** es vulnerable](privilege-escalation/#sudo-version)
- [ ] [**Dmesg** verificación de firma fallida](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Más enumeración del sistema ([fecha, estadísticas del sistema, información de CPU, impresoras](privilege-escalation/#more-system-enumeration))
- [ ] [**Enumerar más defensas**](privilege-escalation/#enumerate-possible-defenses)

### [Unidades](privilege-escalation/#drives)

- [ ] **Listar unidades** montadas
- [ ] **¿Alguna unidad no montada?**
- [ ] **¿Alguna credencial en fstab?**

### [**Software instalado**](privilege-escalation/#installed-software)

- [ ] **Verificar** [**software útil**](privilege-escalation/#useful-software) **instalado**
- [ ] **Verificar** [**software vulnerable**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Procesos](privilege-escalation/#processes)

- [ ] ¿Hay algún **software desconocido en ejecución**?
- [ ] ¿Hay algún software en ejecución con **más privilegios de los que debería tener**?
- [ ] Buscar **exploits de procesos en ejecución** (especialmente la versión en ejecución).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorear procesos** y verificar si algún proceso interesante se está ejecutando con frecuencia.
- [ ] ¿Puedes **leer** alguna **memoria de proceso** interesante (donde podrían estar guardadas las contraseñas)?

### [¿Tareas programadas/Cron?](privilege-escalation/#scheduled-jobs)

- [ ] ¿Se está modificando el [**PATH**](privilege-escalation/#cron-path) por algún cron y puedes **escribir** en él?
- [ ] ¿Algún [**comodín**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) en un trabajo cron?
- [ ] ¿Algún [**script modificable**](privilege-escalation/#cron-script-overwriting-and-symlink) está siendo **ejecutado** o está dentro de una **carpeta modificable**?
- [ ] ¿Has detectado que algún **script** podría estar o está siendo [**ejecutado** muy **frecuentemente**](privilege-escalation/#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](privilege-escalation/#services)

- [ ] ¿Algún archivo **.service** **escribible**?
- [ ] ¿Algún **binario escribible** ejecutado por un **servicio**?
- [ ] ¿Alguna **carpeta escribible en el PATH de systemd**?

### [Temporizadores](privilege-escalation/#timers)

- [ ] ¿Algún **temporizador escribible**?

### [Sockets](privilege-escalation/#sockets)

- [ ] ¿Algún archivo **.socket** **escribible**?
- [ ] ¿Puedes **comunicarte con algún socket**?
- [ ] ¿**Sockets HTTP** con información interesante?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](privilege-escalation/#network)

- [ ] Enumerar la red para saber dónde estás
- [ ] **¿Puertos abiertos a los que no pudiste acceder antes** de obtener un shell dentro de la máquina?
- [ ] ¿Puedes **capturar tráfico** usando `tcpdump`?

### [Usuarios](privilege-escalation/#users)

- [ ] Enumeración de usuarios/grupos **genéricos**
- [ ] ¿Tienes un **UID muy grande**? ¿Es la **máquina** **vulnerable**?
- [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](privilege-escalation/interesting-groups-linux-pe/) al que perteneces?
- [ ] ¿Datos del **portapapeles**?
- [ ] ¿Política de contraseñas?
- [ ] Intenta **usar** cada **contraseña conocida** que hayas descubierto previamente para iniciar sesión **con cada** posible **usuario**. Intenta iniciar sesión también sin una contraseña.

### [PATH escribible](privilege-escalation/#writable-path-abuses)

- [ ] Si tienes **privilegios de escritura sobre alguna carpeta en PATH**, podrías ser capaz de escalar privilegios

### [Comandos SUDO y SUID](privilege-escalation/#sudo-and-suid)

- [ ] ¿Puedes ejecutar **cualquier comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Los [**comandos sudo** están **limitados** por **path**? ¿Puedes **eludir** las restricciones](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Binario Sudo/SUID sin path indicado**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binario SUID especificando path**](privilege-escalation/#suid-binary-with-command-path)? Eludir
- [ ] [**Vuln de LD_PRELOAD**](privilege-escalation/#ld_preload)
- [ ] [**Falta de .so en binario SUID**](privilege-escalation/#suid-binary-so-injection) desde una carpeta escribible?
- [ ] [**Tokens SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens)? [**¿Puedes crear un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] ¿Puedes [**leer o modificar archivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**Comando OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacidades](privilege-escalation/#capabilities)

- [ ] ¿Algún binario tiene alguna **capacidad inesperada**?

### [ACLs](privilege-escalation/#acls)

- [ ] ¿Algún archivo tiene alguna **ACL inesperada**?

### [Sesiones de Shell abiertas](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL PRNG predecible - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuración interesantes de SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Archivos interesantes](privilege-escalation/#interesting-files)

- [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Verificar carpetas comúnmente interesantes** en busca de datos sensibles
- [ ] **Ubicación extraña/Archivos propiedad,** a los que podrías tener acceso o alterar archivos ejecutables
- [ ] **Modificados** en los últimos minutos
- [ ] **Archivos de base de datos Sqlite**
- [ ] **Archivos ocultos**
- [ ] **Scripts/Binarios en PATH**
- [ ] **Archivos web** (¿contraseñas?)
- [ ] **¿Copias de seguridad?**
- [ ] **Archivos conocidos que contienen contraseñas**: Usa **Linpeas** y **LaZagne**
- [ ] **Búsqueda genérica**

### [**Archivos escribibles**](privilege-escalation/#writable-files)

- [ ] **Modificar biblioteca de python** para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modificar archivos de registro**? **Explotación Logtotten**
- [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Explotación Centos/Redhat
- [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](privilege-escalation/#other-tricks)

- [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escapar de un shell restrictivo**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
