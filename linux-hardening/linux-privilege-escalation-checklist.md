# Lista de verificación - Escalada de privilegios en Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).​

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof es el hogar de todas las recompensas por errores de criptografía.**

**Obtén recompensas sin demoras**\
Las recompensas de HackenProof se lanzan solo cuando sus clientes depositan el presupuesto de recompensa. Obtendrás la recompensa después de que se verifique el error.

**Obtén experiencia en pentesting web3**\
¡Los protocolos blockchain y los contratos inteligentes son el nuevo Internet! Domina la seguridad web3 en sus días de crecimiento.

**Conviértete en la leyenda del hacker web3**\
Gana puntos de reputación con cada error verificado y conquista la cima de la clasificación semanal.

[**Regístrate en HackenProof**](https://hackenproof.com/register) ¡comienza a ganar con tus hacks!

{% embed url="https://hackenproof.com/register" %}

### **La mejor herramienta para buscar vectores de escalada de privilegios locales en Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Información del sistema](privilege-escalation/#system-information)

* [ ] Obtener información del **sistema operativo**
* [ ] Verificar la [**ruta**](privilege-escalation/#path), ¿alguna carpeta **escribible**?
* [ ] Verificar las [**variables de entorno**](privilege-escalation/#env-info), ¿algún detalle sensible?
* [ ] Buscar [**exploits del kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (DirtyCow?)
* [ ] Verificar si la versión de **sudo es vulnerable**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** verificación de firma fallida](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Enumeración adicional del sistema ([fecha, estadísticas del sistema, información de la CPU, impresoras](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerar más defensas](privilege-escalation/#enumerate-possible-defenses)

### [Unidades](privilege-escalation/#drives)

* [ ] Listar las unidades **montadas**
* [ ] ¿Algún unidad **desmontada**?
* [ ] ¿Algún credencial en fstab?

### [**Software instalado**](privilege-escalation/#installed-software)

* [ ] Verificar si hay [**software útil**](privilege-escalation/#useful-software) **instalado**
* [ ] Verificar si hay [**software vulnerable**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Procesos](privilege-escalation/#processes)

* [ ] ¿Hay algún software **desconocido en ejecución**?
* [ ] ¿Hay algún software en ejecución con **más privilegios de los que debería tener**?
* [ ] Buscar **exploits de procesos en ejecución** (especialmente la versión en ejecución).
* [ ] ¿Puedes **modificar el binario** de algún proceso en ejecución?
* [ ] **Monitorizar los procesos** y verificar si se ejecuta frecuentemente algún proceso interesante.
* [ ] ¿Puedes **leer** la **memoria de algún proceso** interesante (donde podrían estar guardadas las contraseñas)?

### [¿Tareas programadas/Cron jobs?](privilege-escalation/#scheduled-jobs)

* [ ] ¿Se está modificando la [**ruta**](privilege-escalation/#cron-path) por algún cron y puedes **escribir** en ella?
* [ ] ¿Algún [**comodín**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) en un trabajo cron?
* [ ] ¿Algún [**script modificable**](privilege-escalation/#cron-script-overwriting-and-symlink) se está **ejecutando** o está dentro de una **carpeta modificable**?
* [ ] ¿Has detectado que algún **script** podría estar o se está **ejecutando con mucha frecuencia**](privilege-escalation/#frequent-cron-jobs)? (cada 1, 2 o 5 minutos)

### [Servicios](privilege-escalation/#services)

* [ ] ¿Algún archivo **.service escribible**?
* [ ] ¿Algún **binario escribible** ejecutado por un **servicio**?
* [ ] ¿Alguna **carpeta escribible en la ruta de systemd**?
### [Temporizadores](privilege-escalation/#timers)

* [ ] ¿Algún temporizador **editable**?

### [Sockets](privilege-escalation/#sockets)

* [ ] ¿Algún archivo **.socket** editable?
* [ ] ¿Puedes **comunicarte con algún socket**?
* [ ] ¿Hay sockets **HTTP** con información interesante?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] ¿Puedes **comunicarte con algún D-Bus**?

### [Red](privilege-escalation/#network)

* [ ] Enumera la red para saber dónde estás
* [ ] ¿Hay puertos abiertos a los que no podías acceder antes de obtener una shell dentro de la máquina?
* [ ] ¿Puedes **espiar el tráfico** usando `tcpdump`?

### [Usuarios](privilege-escalation/#users)

* [ ] Enumeración de usuarios/grupos genéricos
* [ ] ¿Tienes un **UID muy grande**? ¿La **máquina** es **vulnerable**?
* [ ] ¿Puedes [**elevar privilegios gracias a un grupo**](privilege-escalation/interesting-groups-linux-pe/) al que perteneces?
* [ ] ¿Datos del **portapapeles**?
* [ ] ¿Política de contraseñas?
* [ ] Intenta **usar** todas las **contraseñas conocidas** que hayas descubierto previamente para iniciar sesión **con cada** usuario **posible**. Intenta iniciar sesión también sin contraseña.

### [Ruta editable](privilege-escalation/#writable-path-abuses)

* [ ] Si tienes **permisos de escritura en alguna carpeta de la ruta**, es posible que puedas elevar privilegios

### [Comandos SUDO y SUID](privilege-escalation/#sudo-and-suid)

* [ ] ¿Puedes ejecutar **cualquier comando con sudo**? ¿Puedes usarlo para LEER, ESCRIBIR o EJECUTAR cualquier cosa como root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Hay algún **binario SUID explotable**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] ¿Los comandos [**sudo** están **limitados** por **ruta**? ¿Puedes **burlar** las restricciones](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binario Sudo/SUID sin ruta indicada**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binario SUID especificando ruta**](privilege-escalation/#suid-binary-with-command-path)? Burla
* [ ] [**Vulnerabilidad LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Falta de biblioteca .so en el binario SUID**](privilege-escalation/#suid-binary-so-injection) desde una carpeta editable?
* [ ] [**Tokens SUDO disponibles**](privilege-escalation/#reusing-sudo-tokens)? [**¿Puedes crear un token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] ¿Puedes [**leer o modificar archivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] ¿Puedes [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) command

### [Capacidades](privilege-escalation/#capabilities)

* [ ] ¿Algún binario tiene alguna **capacidad inesperada**?

### [ACLs](privilege-escalation/#acls)

* [ ] ¿Algún archivo tiene algún **ACL inesperado**?

### [Sesiones de shell abiertas](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valores de configuración interesantes de SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Archivos interesantes](privilege-escalation/#interesting-files)

* [ ] **Archivos de perfil** - ¿Leer datos sensibles? ¿Escribir para escalada de privilegios?
* [ ] **Archivos passwd/shadow** - ¿Leer datos sensibles? ¿Escribir para escalada de privilegios?
* [ ] **Comprobar carpetas comúnmente interesantes** en busca de datos sensibles
* [ ] **Ubicación/archivos de propiedad extraña**, a los que puedes acceder o alterar archivos ejecutables
* [ ] **Modificado** en los últimos minutos
* [ ] **Archivos de base de datos Sqlite**
* [ ] **Archivos ocultos**
* [ ] **Scripts/Binarios en la ruta**
* [ ] **Archivos web** (¿contraseñas?)
* [ ] **Copias de seguridad**?
* [ ] **Archivos conocidos que contienen contraseñas**: Usa **Linpeas** y **LaZagne**
* [ ] **Búsqueda genérica**

### [Archivos editables](privilege-escalation/#writable-files)

* [ ] ¿Modificar biblioteca de Python para ejecutar comandos arbitrarios?
* [ ] ¿Puedes **modificar archivos de registro**? Explotar Logtotten
* [ ] ¿Puedes **modificar /etc/sysconfig/network-scripts/**? Explotar Centos/Redhat
* [ ] ¿Puedes [**escribir en archivos ini, int.d, systemd o rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [Otros trucos](privilege-escalation/#other-tricks)

* [ ] ¿Puedes [**abusar de NFS para elevar privilegios**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] ¿Necesitas [**escapar de una shell restrictiva**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof es el hogar de todas las recompensas por errores de cifrado.**

**Obtén recompensas sin demoras**\
Las recompensas de HackenProof se lanzan solo cuando los clientes depositan el presupuesto de recompensa. Recibirás la recompensa después de que se verifique el error.

**Obtén experiencia en pentesting web3**\
¡Los protocolos blockchain y los contratos inteligentes son el nuevo Internet! Domina la seguridad web3 en sus días de crecimiento.

**Conviértete en la leyenda del hacker web3**\
Gana puntos de reputación con cada error verificado y conquista la cima de la clasificación semanal.

[**Regístrate en HackenProof**](https://hackenproof.com/register) ¡comienza a ganar con tus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
