# AppArmor

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

**AppArmor** es una mejora del kernel para confinar **programas** a un conjunto **limitado** de **recursos** con **perfiles por programa**. Los perfiles pueden **permitir** **capacidades** como acceso a la red, acceso a sockets en bruto y el permiso para leer, escribir o ejecutar archivos en rutas coincidentes.

Es un Control de Acceso Obligatorio o **MAC** que vincula **atributos de control de acceso** **a programas en lugar de a usuarios**.\
El confinamiento de AppArmor se proporciona a través de **perfiles cargados en el kernel**, típicamente al arrancar.\
Los perfiles de AppArmor pueden estar en uno de **dos modos**:

* **Enforcement**: Los perfiles cargados en modo de enforcement resultarán en la **aplicación de la política** definida en el perfil **así como en la notificación** de intentos de violación de la política (ya sea a través de syslog o auditd).
* **Complain**: Los perfiles en modo de complain **no aplicarán la política** sino que **notificarán** intentos de **violación** de la política.

AppArmor se diferencia de algunos otros sistemas MAC en Linux: es **basado en rutas**, permite la mezcla de perfiles en modos de enforcement y complain, utiliza archivos de inclusión para facilitar el desarrollo y tiene una barrera de entrada mucho más baja que otros sistemas MAC populares.

### Componentes de AppArmor

* **Módulo del kernel**: Realiza el trabajo real
* **Políticas**: Define el comportamiento y el confinamiento
* **Analizador**: Carga las políticas en el kernel
* **Utilidades**: Programas en modo usuario para interactuar con apparmor

### Ruta de los perfiles

Los perfiles de apparmor suelen guardarse en _**/etc/apparmor.d/**_\
Con `sudo aa-status` podrás listar los binarios que están restringidos por algún perfil. Si cambias el carácter "/" por un punto en la ruta de cada binario listado, obtendrás el nombre del perfil de apparmor dentro de la carpeta mencionada.

Por ejemplo, un perfil de **apparmor** para _/usr/bin/man_ estará ubicado en _/etc/apparmor.d/usr.bin.man_

### Comandos
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Creando un perfil

* Para indicar el ejecutable afectado, se permiten **rutas absolutas y comodines** (para la búsqueda de archivos) para especificar archivos.
* Para indicar el acceso que tendrá el binario sobre **archivos**, se pueden usar los siguientes **controles de acceso**:
* **r** (lectura)
* **w** (escritura)
* **m** (mapear en memoria como ejecutable)
* **k** (bloqueo de archivos)
* **l** (creación de enlaces duros)
* **ix** (para ejecutar otro programa con la nueva política heredada)
* **Px** (ejecutar bajo otro perfil, después de limpiar el entorno)
* **Cx** (ejecutar bajo un perfil hijo, después de limpiar el entorno)
* **Ux** (ejecutar sin restricciones, después de limpiar el entorno)
* Se pueden definir **Variables** en los perfiles y se pueden manipular desde fuera del perfil. Por ejemplo: @{PROC} y @{HOME} (añadir #include \<tunables/global> al archivo de perfil)
* **Se admiten reglas de denegación para anular reglas de permiso**.

### aa-genprof

Para empezar a crear un perfil fácilmente, apparmor puede ayudarte. Es posible hacer que **apparmor inspeccione las acciones realizadas por un binario y luego te permita decidir qué acciones quieres permitir o denegar**.\
Solo necesitas ejecutar:
```bash
sudo aa-genprof /path/to/binary
```
Luego, en una consola diferente, realiza todas las acciones que el binario normalmente llevaría a cabo:
```bash
/path/to/binary -a dosomething
```
Luego, en la primera consola presiona "**s**" y luego en las acciones grabadas indica si quieres ignorar, permitir o lo que sea. Cuando hayas terminado presiona "**f**" y el nuevo perfil se creará en _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Usando las teclas de flecha puedes seleccionar lo que deseas permitir/denegar/lo que sea
{% endhint %}

### aa-easyprof

También puedes crear una plantilla de un perfil de apparmor de un binario con:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Tenga en cuenta que, por defecto, en un perfil creado no se permite nada, por lo que todo está denegado. Necesitará agregar líneas como `/etc/passwd r,` para permitir que el binario lea `/etc/passwd` por ejemplo.
{% endhint %}

Luego puede **hacer cumplir** el nuevo perfil con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificación de un perfil a partir de registros

La siguiente herramienta leerá los registros y preguntará al usuario si desea permitir algunas de las acciones prohibidas detectadas:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Usando las teclas de flecha puedes seleccionar lo que deseas permitir/denegar/cualquier otra acción
{% endhint %}

### Administrando un Perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Registros

Ejemplo de registros **AUDIT** y **DENIED** del archivo _/var/log/audit/audit.log_ del ejecutable **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
También puedes obtener esta información utilizando:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor en Docker

Observe cómo el perfil **docker-profile** de docker se carga por defecto:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Por defecto, se genera el **perfil Apparmor docker-default** desde [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Resumen del perfil docker-default**:

* **Acceso** a toda la **red**
* **No se define ninguna capacidad** (Sin embargo, algunas capacidades provendrán de incluir reglas básicas base, por ejemplo, #include \<abstractions/base>)
* **No está permitido escribir** en ningún archivo de **/proc**
* Otros **subdirectorios**/**archivos** de /**proc** y /**sys** tienen **denegado** el acceso de lectura/escritura/bloqueo/enlace/ejecución
* **No está permitido montar**
* **Ptrace** solo se puede ejecutar en un proceso que esté confinado por el **mismo perfil de apparmor**

Una vez que **ejecutes un contenedor docker**, deberías ver la siguiente salida:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Tenga en cuenta que **apparmor bloqueará incluso los privilegios de capacidades** otorgados al contenedor por defecto. Por ejemplo, podrá **bloquear el permiso para escribir dentro de /proc incluso si se otorga la capacidad SYS\_ADMIN** porque por defecto el perfil de apparmor de docker niega este acceso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Necesitas **deshabilitar apparmor** para eludir sus restricciones:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Tenga en cuenta que, por defecto, **AppArmor** también **prohibirá que el contenedor monte** carpetas desde el interior, incluso con la capacidad de SYS\_ADMIN.

Tenga en cuenta que puede **añadir/eliminar** **capacidades** al contenedor de docker (esto seguirá estando restringido por métodos de protección como **AppArmor** y **Seccomp**):

* `--cap-add=SYS_ADMIN` otorga la capacidad `SYS_ADMIN`
* `--cap-add=ALL` otorga todas las capacidades
* `--cap-drop=ALL --cap-add=SYS_PTRACE` elimina todas las capacidades y solo otorga `SYS_PTRACE`

{% hint style="info" %}
Normalmente, cuando **descubre** que tiene una **capacidad privilegiada** disponible **dentro** de un contenedor de **docker** **pero** alguna parte del **exploit no está funcionando**, esto se deberá a que AppArmor de docker **estará previniéndolo**.
{% endhint %}

### Ejemplo

(Ejemplo de [**aquí**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Para ilustrar la funcionalidad de AppArmor, creé un nuevo perfil de Docker "mydocker" con la siguiente línea añadida:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Para activar el perfil, necesitamos hacer lo siguiente:
```
sudo apparmor_parser -r -W mydocker
```
Para listar los perfiles, podemos hacer el siguiente comando. El comando a continuación está listando mi nuevo perfil de AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Como se muestra a continuación, obtenemos un error al intentar cambiar “/etc/” ya que el perfil de AppArmor está previniendo el acceso de escritura a “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Evasión de AppArmor en Docker1

Puedes encontrar **qué perfil de apparmor está ejecutando un contenedor** utilizando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Entonces, puedes ejecutar la siguiente línea para **encontrar el perfil exacto que se está utilizando**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
En el caso extraño de que puedas **modificar el perfil de apparmor de docker y recargarlo**, podrías eliminar las restricciones y "evitarlas".

### AppArmor Docker Bypass2

**AppArmor se basa en rutas**, esto significa que incluso si podría estar **protegiendo** archivos dentro de un directorio como **`/proc`**, si puedes **configurar cómo se va a ejecutar el contenedor**, podrías **montar** el directorio proc del host dentro de **`/host/proc`** y **ya no estará protegido por AppArmor**.

### AppArmor Shebang Bypass

En [**este error**](https://bugs.launchpad.net/apparmor/+bug/1911431) puedes ver un ejemplo de cómo **incluso si estás previniendo que perl se ejecute con ciertos recursos**, si solo creas un script de shell **especificando** en la primera línea **`#!/usr/bin/perl`** y **ejecutas el archivo directamente**, podrás ejecutar lo que quieras. Por ejemplo:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
