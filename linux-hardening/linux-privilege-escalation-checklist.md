# Lista de verificación - Escalada de Privilegios en Linux

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking de ritmo rápido a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado con los lanzamientos de las más recientes recompensas por errores y actualizaciones críticas de la plataforma.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo.

### **Mejor herramienta para buscar vectores de escalada de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del Sistema](privilege-escalation/#system-information)

* [ ] Obtén **información del SO**
* [ ] Verifica el [**PATH**](privilege-escalation/#path), ¿alguna **carpeta con permisos de escritura**?
* [ ] Revisa las [**variables de entorno**](privilege-escalation/#env-info), ¿algún detalle sensible?
* [ ] Busca [**exploits de kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (¿DirtyCow?)
* [ ] **Verifica** si la [**versión de sudo** es vulnerable](privilege-escalation/#sudo-version)
* [ ] [**Fallo en la verificación de firma de Dmesg**](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Más enumeración del sistema ([fecha, estadísticas del sistema, información de la CPU, impresoras](privilege-escalation/#more-system-enumeration))
* [ ] [Enumera más defensas](privilege-escalation/#enumerate-possible-defenses)

### [Unidades](privilege-escalation/#drives)

* [ ] **Lista unidades montadas**
* [ ] **¿Alguna unidad sin montar?**
* [ ] **¿Algún credencial en fstab?**

### [**Software Instalado**](privilege-escalation/#installed-software)

* [ ] **Verifica si hay** [**software útil**](privilege-escalation/#useful-software) **instalado**
* [ ] **Verifica si hay** [**software vulnerable**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Procesos](privilege-escalation/#processes)

* [ ] ¿Hay algún **software desconocido en ejecución**?
* [ ] ¿Hay algún software en ejecución con **más privilegios de los que debería tener**?
* [ ] Busca **exploits de procesos en ejecución** (especialmente la versión en ejecución).
* [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
* [ ] **Monitorea procesos** y verifica si algún proceso interesante se ejecuta con frecuencia.
* [ ] ¿Puedes **leer** alguna **memoria de proceso interesante** (donde podrían guardarse contraseñas)?

### [¿Trabajos Programados/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] ¿El [**PATH**](privilege-escalation/#cron-path) está siendo modificado por algún cron y puedes **escribir** en él?
* [ ] ¿Algún [**comodín**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) en un trabajo cron?
* [ ] ¿Algún [**script modificable**](privilege-escalation/#cron-script-overwriting-and-symlink) está siendo **ejecutado** o está dentro de una **carpeta modificable**?
* [ ] ¿Has detectado que algún **script** podría estar siendo [**ejecutado muy frecuentemente**](privilege-escalation/#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](privilege-escalation/#services)

* [ ] ¿Algún archivo .service **con permisos de escritura**?
* [ ] ¿Algún **binario con permisos de escritura** ejecutado por un **servicio**?
* [ ] ¿Algún **directorio con permisos de escritura en el PATH de systemd**?

### [Temporizadores](privilege-escalation/#timers)

* [ ] ¿Algún **temporizador con permisos de escritura**?

### [Sockets](privilege-escalation/#sockets)

* [ ] ¿Algún archivo .socket **con permisos de escritura**?
* [ ] ¿Puedes **comunicarte con algún socket**?
* [ ] **Sockets HTTP** con información interesante?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](privilege-escalation/#network)

* [ ] Enumera la red para saber dónde estás
* [ ] ¿**Puertos abiertos a los que no podías acceder antes** de obtener una shell dentro de la máquina?
* [ ] ¿Puedes **capturar tráfico** usando `tcpdump`?

### [Usuarios](privilege-escalation/#users)

* [ ] Enumeración genérica de usuarios/grupos
* [ ] ¿Tienes un **UID muy grande**? ¿La **máquina** es **vulnerable**?
* [ ] ¿Puedes [**escalar privilegios gracias a un grupo**](privilege-escalation/interesting-groups-linux-pe/) al que perteneces?
* [ ] ¿Datos del **portapapeles**?
* [ ] ¿Política de contraseñas?
* [ ] Intenta **usar** cada **contraseña conocida** que hayas descubierto previamente para iniciar sesión **con cada** posible **usuario**. Intenta también iniciar sesión sin contraseña.

### [PATH con permisos de escritura](privilege-escalation/#writable-path-abuses)

* [ ] Si tienes **privilegios de escritura sobre alguna carpeta en PATH**, podrías ser capaz de escalar privilegios

### [Comandos SUDO y SUID](privilege-escalation/#sudo-and-suid)

* [ ] ¿Puedes ejecutar **algún comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Los comandos de [**sudo** están **limitados** por **ruta**? ¿puedes **burlar** las restricciones](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binario Sudo/SUID sin ruta indicada**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binario SUID especificando ruta**](privilege-escalation/#suid-binary-with-command-path)? Burla
* [ ] [**Vulnerabilidad LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Falta de biblioteca .so en binario SUID**](privilege-escalation/#suid-binary-so-injection) desde una carpeta con permisos de escritura?
* [ ] [**Tokens de SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens)? [**¿Puedes crear un token de SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] ¿Puedes [**leer o modificar archivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**Comando OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacidades](privilege-escalation/#capabilities)

* [ ] ¿Tiene algún binario alguna **capacidad inesperada**?

### [ACLs](privilege-escalation/#acls)

* [ ] ¿Tiene algún archivo alguna **ACL inesperada**?

### [Sesiones de Shell abiertas](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**PRNG Predecible de OpenSSL - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valores de configuración de SSH interesantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Archivos Interesantes](privilege-escalation/#interesting-files)

* [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para escalar privilegios?
* [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para escalar privilegios?
* [ ] **Revisa carpetas comúnmente interesantes** en busca de datos sensibles
* [ ] **Archivos en Ubicación/Raros,** podrías tener acceso o alterar archivos ejecutables
* [ ] **Modificados** en los últimos minutos
* [ ] **Archivos de base de datos SQLite**
* [ ] **Archivos ocultos**
* [ ] **Scripts/Binarios en PATH**
* [ ] **Archivos web** (¿contraseñas?)
* [ ] **¿Copias de seguridad**?
* [ ] **Archivos conocidos que contienen contraseñas**: Usa **Linpeas** y **LaZagne**
* [ ] **Búsqueda genérica**

### [**Archivos con permisos de escritura**](privilege-escalation/#writable-files)

* [ ] ¿**Modificar biblioteca de python** para ejecutar comandos arbitrarios?
* [ ] ¿Puedes **modificar archivos de registro**? Explotación de **Logtotten**
* [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Explotación de Centos/Redhat
* [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Otros trucos**](privilege-escalation/#other-tricks)

* [ ] ¿Puedes [**abusar de NFS para escalar privilegios**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] ¿Necesitas [**escapar de una shell restringida**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Únete al servidor de [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para comunicarte con hackers experimentados y cazadores de recompensas por errores.

**Perspectivas de Hacking**\
Interactúa con contenido que profundiza en la emoción y los desafíos del hacking.

**Noticias de Hacking en Tiempo Real**\
Mantente actualizado con el mundo del hacking de ritmo rápido a través de noticias e información en tiempo real.

**Últimos Anuncios**\
Mantente informado con los lanzamientos de las más recientes recompensas por errores y actualizaciones críticas de la plataforma.

**Únete a nosotros en** [**Discord**](https://discord.com/invite/N3FrSbmwdy) y comienza a colaborar con los mejores hackers hoy mismo.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
