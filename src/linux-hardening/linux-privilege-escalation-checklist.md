# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Obtener **información del OS**
- [ ] Comprobar el [**PATH**](privilege-escalation/index.html#path), ¿alguna **carpeta escribible**?
- [ ] Comprobar [**env variables**](privilege-escalation/index.html#env-info), ¿algún detalle sensible?
- [ ] Buscar [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Comprobar** si la [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Más enumeración del sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] ¿**Any unmounted drive**?
- [ ] ¿**Creds in fstab**?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Comprobar** si hay[ **useful software**](privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Comprobar** si hay [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processes](privilege-escalation/index.html#processes)

- [ ] ¿Hay algún **software desconocido en ejecución**?
- [ ] ¿Algún software se está ejecutando con **más privilegios de los que debería**?
- [ ] Buscar **exploits** de procesos en ejecución (especialmente la versión que se está ejecutando).
- [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
- [ ] **Monitorizar procesos** y comprobar si algún proceso interesante se ejecuta frecuentemente.
- [ ] ¿Puedes **leer** algo de **memoria de proceso** interesante (donde podrían estar guardadas contraseñas)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] ¿El [**PATH**](privilege-escalation/index.html#cron-path) está siendo modificado por algún cron y puedes **write** en él?
- [ ] ¿Algún [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) en un cron job?
- [ ] ¿Algún [**modifiable script**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) está siendo **executed** o está dentro de una **modifiable folder**?
- [ ] ¿Has detectado que algún **script** podría estar o está siendo [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Services](privilege-escalation/index.html#services)

- [ ] ¿Algún archivo **.service** escribible?
- [ ] ¿Algún **writable binary** ejecutado por un **servicio**?
- [ ] ¿Alguna **carpeta escribible en systemd PATH**?
- [ ] ¿Algún drop-in de unidad systemd escribible en `/etc/systemd/system/<unit>.d/*.conf` que pueda sobrescribir `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] ¿Algún **writable timer**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] ¿Algún **writable .socket** file?
- [ ] ¿Puedes **communicate with any socket**?
- [ ] ¿**HTTP sockets** con información interesante?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] ¿Puedes **communicate with any D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumerar la red para saber dónde estás
- [ ] ¿**Open ports you couldn't access before** getting a shell inside the machine?
- [ ] ¿Puedes **sniff traffic** usando `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Enumeración genérica de usuarios/grupos
- [ ] ¿Tienes un **UID muy grande**? ¿La **máquina** es **vulnerable**?
- [ ] ¿Puedes [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) al que perteneces?
- [ ] ¿Datos del **Clipboard**?
- [ ] ¿Política de contraseñas?
- [ ] Intenta **usar** cada **known password** que hayas descubierto previamente para iniciar sesión **con cada** posible **user**. Intenta iniciar sesión también sin contraseña.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Si tienes **write privileges over some folder in PATH** podrías escalar privilegios

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] ¿Puedes ejecutar **any command with sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR cualquier cosa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Si `sudo -l` permite `sudoedit`, verifica **sudoedit argument injection** (CVE-2023-22809) vía `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar archivos arbitrarios en versiones vulnerables (`sudo -V` < 1.9.12p2). Ejemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] ¿Existe algún **exploitable SUID binary**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) desde una carpeta escribible?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] ¿Puedes [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] ¿Puedes [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] ¿Algún binario tiene alguna **unexpected capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] ¿Algún archivo tiene algún **unexpected ACL**?

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
- [ ] **Weird Location/Owned files,** podrías tener acceso o alterar archivos ejecutables
- [ ] **Modificados** en los últimos minutos
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (¿contraseñas?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] ¿**Modificar python library** para ejecutar comandos arbitrarios?
- [ ] ¿Puedes **modify log files**? **Logtotten** exploit
- [ ] ¿Puedes **modify /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] ¿Puedes [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] ¿Puedes [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] ¿Necesitas [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referencias

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
