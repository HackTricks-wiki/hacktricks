# Checklist - Linux Privilege Esccalation

{{#include ../banners/hacktricks-training.md}}

### **Mejor herramienta para buscar vectores de Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Obtener **información del OS**
- [ ] Comprobar el [**PATH**](privilege-escalation/index.html#path), ¿alguna **carpeta escribible**?
- [ ] Comprobar las [**env variables**](privilege-escalation/index.html#env-info), ¿algún detalle sensible?
- [ ] Buscar [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Comprobar** si la [**sudo version**](privilege-escalation/index.html#sudo-version) es vulnerable
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Más enum de sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] ¿**Alguna unidad no montada**?
- [ ] ¿**Alguna credencial en fstab**?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Comprobar** si hay [**useful software**](privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Comprobar** si hay [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processes](privilege-escalation/index.html#processes)

- [ ] ¿Hay algún **software desconocido en ejecución**?
- [ ] ¿Algún software corre con **más privilegios de los que debería**?
- [ ] Buscar **exploits de procesos en ejecución** (especialmente la versión que corre).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorizar procesos** y comprobar si algún proceso interesante se ejecuta con frecuencia.
- [ ] ¿Puedes **leer** parte de la **memoria de procesos** interesante (donde podrían estar guardadas contraseñas)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] ¿El [**PATH** ](privilege-escalation/index.html#cron-path) está siendo modificado por algún cron y puedes **escribir** en él?
- [ ] ¿Algún [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) en un cron job?
- [ ] ¿Algún [**script modificable** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) está siendo **ejecutado** o está dentro de una **carpeta modificable**?
- [ ] ¿Has detectado que algún **script** podría estar siendo [**ejecutado** muy **frecuentemente**](privilege-escalation/index.html#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Services](privilege-escalation/index.html#services)

- [ ] ¿Algún **archivo .service escribible**?
- [ ] ¿Algún **binario escribible** ejecutado por un **service**?
- [ ] ¿Alguna **carpeta escribible en systemd PATH**?
- [ ] ¿Algún **systemd unit drop-in escribible** en `/etc/systemd/system/<unit>.d/*.conf` que pueda sobrescribir `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] ¿Algún **timer escribible**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] ¿Algún **archivo .socket escribible**?
- [ ] ¿Puedes **comunicarte con algún socket**?
- [ ] ¿**HTTP sockets** con información interesante?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumerar la red para saber dónde estás
- [ ] ¿Puertos abiertos a los que no podías acceder antes de obtener shell dentro de la máquina?
- [ ] ¿Puedes **sniffear tráfico** usando `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Enumeración genérica de usuarios/grupos
- [ ] ¿Tienes un **UID muy grande**? ¿La **máquina** es **vulnerable**?
- [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](privilege-escalation/interesting-groups-linux-pe/index.html) al que perteneces?
- [ ] ¿Datos del **Clipboard**?
- [ ] ¿Política de contraseñas?
- [ ] Intenta **usar** todas las **contraseñas conocidas** que hayas descubierto previamente para iniciar sesión **con cada** posible **usuario**. Intenta iniciar sesión también sin contraseña.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Si tienes **privilegios de escritura sobre alguna carpeta en PATH** podrías ser capaz de escalar privilegios

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] ¿Puedes ejecutar **algún comando con sudo**? ¿Puedes usarlo para READ, WRITE o EXECUTE cualquier cosa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` permite `sudoedit`, comprobar **sudoedit argument injection** (CVE-2023-22809) vía `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar ficheros arbitrarios en versiones vulnerables (`sudo -V` < 1.9.12p2). Ejemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] ¿Algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] ¿Están los [**comandos sudo limitados por path**? puedes **burlar** las restricciones](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) desde una carpeta escribible?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] ¿Puedes [**leer o modificar archivos sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] ¿Algún binario tiene alguna **capabilidad inesperada**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] ¿Algún archivo tiene alguna **ACL inesperada**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **passwd/shadow files** - ¿Leer datos sensibles? ¿Escribir para privesc?
- [ ] **Comprobar carpetas comúnmente interesantes** en busca de datos sensibles
- [ ] **Ubicaciones raras/archivos owned,** podrías tener acceso o alterar archivos ejecutables
- [ ] **Modificados** en los últimos minutos
- [ ] **Sqlite DB files**
- [ ] **Archivos ocultos**
- [ ] **Script/Binaries en PATH**
- [ ] **Archivos web** (¿contraseñas?)
- [ ] **Backups**?
- [ ] **Ficheros conocidos que contienen contraseñas**: Usa **Linpeas** y **LaZagne**
- [ ] **Búsqueda genérica**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] ¿Modificar librería de python para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modificar archivos de logs**? exploit Logtotten
- [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? exploit Centos/Redhat
- [ ] ¿Puedes [**escribir en ini, init.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escapar de un shell restrictivo**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referencias

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
