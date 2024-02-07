# Lista de verificación - Escalada de privilegios en Linux

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red de HackTricks en AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**Discord de HackenProof**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Información sobre Hacking**\
Involúcrate con contenido que explora la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado sobre los nuevos programas de recompensas por errores y actualizaciones importantes de plataformas.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy.

### **Mejor herramienta para buscar vectores de escalada de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del Sistema](privilege-escalation/#system-information)

* [ ] Obtener **información del SO**
* [ ] Verificar la [**RUTA**](privilege-escalation/#path), ¿alguna **carpeta escribible**?
* [ ] Verificar las [**variables de entorno**](privilege-escalation/#env-info), ¿algún detalle sensible?
* [ ] Buscar [**exploits de kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (DirtyCow?)
* [ ] **Verificar** si la [**versión de sudo es vulnerable**](privilege-escalation/#sudo-version)
* [ ] [**Fallo de verificación de firma de Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Más enumeración del sistema ([fecha, estadísticas del sistema, información de la CPU, impresoras](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerar más defensas](privilege-escalation/#enumerate-possible-defenses)

### [Unidades](privilege-escalation/#drives)

* [ ] Listar las unidades montadas
* [ ] ¿Algún unidad no montada?
* [ ] ¿Algún credencial en fstab?

### [**Software Instalado**](privilege-escalation/#installed-software)

* [ ] Verificar si hay [**software útil**](privilege-escalation/#useful-software) **instalado**
* [ ] Verificar si hay [**software vulnerable**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Procesos](privilege-escalation/#processes)

* [ ] ¿Hay algún **software desconocido en ejecución**?
* [ ] ¿Hay algún software en ejecución con **más privilegios de los que debería tener**?
* [ ] Buscar **exploits de procesos en ejecución** (especialmente la versión en ejecución).
* [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
* [ ] **Monitorear procesos** y verificar si algún proceso interesante se ejecuta con frecuencia.
* [ ] ¿Puedes **leer** alguna **memoria de proceso** interesante (donde podrían estar guardadas contraseñas)?

### [¿Trabajos programados/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] ¿Se está modificando la [**RUTA** ](privilege-escalation/#cron-path)por algún cron y puedes **escribir** en ella?
* [ ] ¿Algún [**comodín** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)en un trabajo cron?
* [ ] ¿Algún [**script modificable** ](privilege-escalation/#cron-script-overwriting-and-symlink)se está **ejecutando** o está dentro de una **carpeta modificable**?
* [ ] ¿Has detectado que algún **script** podría estar siendo [**ejecutado** muy **frecuentemente**](privilege-escalation/#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](privilege-escalation/#services)

* [ ] ¿Algún archivo **.service escribible**?
* [ ] ¿Algún binario **ejecutado por un servicio** escribible?
* [ ] ¿Alguna **carpeta escribible en la RUTA de systemd**?

### [Temporizadores](privilege-escalation/#timers)

* [ ] ¿Algún **temporizador escribible**?

### [Sockets](privilege-escalation/#sockets)

* [ ] ¿Algún archivo **.socket escribible**?
* [ ] ¿Puedes **comunicarte con algún socket**?
* [ ] ¿**Sockets HTTP** con información interesante?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](privilege-escalation/#network)

* [ ] Enumerar la red para saber dónde te encuentras
* [ ] ¿Puertos abiertos a los que no podías acceder antes de obtener una shell dentro de la máquina?
* [ ] ¿Puedes **espiar el tráfico** usando `tcpdump`?

### [Usuarios](privilege-escalation/#users)

* [ ] Enumeración de usuarios/grupos **genéricos**
* [ ] ¿Tienes un **UID muy grande**? ¿Es **vulnerable** la **máquina**?
* [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](privilege-escalation/interesting-groups-linux-pe/) al que perteneces?
* [ ] ¿Datos del **portapapeles**?
* [ ] ¿Política de contraseñas?
* [ ] Intenta **usar** todas las **contraseñas conocidas** que hayas descubierto previamente para iniciar sesión **con cada** usuario **posible**. Intenta iniciar sesión también sin contraseña.

### [RUTA Escribible](privilege-escalation/#writable-path-abuses)

* [ ] Si tienes **privilegios de escritura sobre alguna carpeta en la RUTA**, es posible que puedas escalar privilegios

### [Comandos SUDO y SUID](privilege-escalation/#sudo-and-suid)

* [ ] ¿Puedes ejecutar **cualquier comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Los [**comandos sudo** están **limitados** por **ruta**? ¿puedes **burlar** las restricciones](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binario Sudo/SUID sin ruta indicada**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binario SUID especificando ruta**](privilege-escalation/#suid-binary-with-command-path)? Burlar
* [ ] [**Vulnerabilidad LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Falta de biblioteca .so en binario SUID**](privilege-escalation/#suid-binary-so-injection) desde una carpeta escribible?
* [ ] ¿Hay [**tokens de SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens)? [**Puedes crear un token de SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] ¿Puedes [**leer o modificar archivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] Comando [**OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacidades](privilege-escalation/#capabilities)

* [ ] ¿Algún binario tiene alguna **capacidad inesperada**?

### [ACLs](privilege-escalation/#acls)

* [ ] ¿Algún archivo tiene algún **ACL inesperado**?

### [Sesiones de Shell abiertas](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valores de configuración de SSH interesantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Archivos Interesantes](privilege-escalation/#interesting-files)

* [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para escalada de privilegios?
* [ ] Archivos **passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para escalada de privilegios?
* [ ] Verificar carpetas comúnmente interesantes en busca de datos sensibles
* [ ] **Ubicación/archivos de propiedad extraña**, a los que puedes acceder o alterar archivos ejecutables
* [ ] **Modificado** en los últimos minutos
* [ ] Archivos de **base de datos Sqlite**
* [ ] **Archivos ocultos**
* [ ] **Scripts/Binarios en la RUTA**
* [ ] **Archivos web** (¿contraseñas?)
* [ ] **Copias de seguridad**?
* [ ] **Archivos conocidos que contienen contraseñas**: Usa **Linpeas** y **LaZagne**
* [ ] **Búsqueda genérica**

### [**Archivos Escribibles**](privilege-escalation/#writable-files)

* [ ] ¿Modificar biblioteca de Python para ejecutar comandos arbitrarios?
* [ ] ¿Puedes **modificar archivos de registro**? Exploit de **Logtotten**
* [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Exploit de Centos/Redhat
* [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](privilege-escalation/#other-tricks)

* [ ] ¿Puedes **abusar de NFS para escalar privilegios**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] ¿Necesitas **escapar de una shell restrictiva**](privilege-escalation/#escaping-from-restricted-shells)?
