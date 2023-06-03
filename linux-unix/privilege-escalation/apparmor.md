# Información Básica

**AppArmor** es una mejora del kernel para confinar **programas** a un **conjunto limitado de recursos** con **perfiles por programa**. Los perfiles pueden **permitir capacidades** como acceso a la red, acceso a sockets en bruto y permisos para leer, escribir o ejecutar archivos en rutas coincidentes.

Es un Control de Acceso Obligatorio o **MAC** que vincula los atributos de **control de acceso a programas en lugar de a usuarios**.\
El confinamiento de AppArmor se proporciona mediante **perfiles cargados en el kernel**, normalmente en el arranque.\
Los perfiles de AppArmor pueden estar en uno de **dos modos**:

* **Ejecución**: Los perfiles cargados en modo de ejecución darán lugar a la **ejecución de la política** definida en el perfil **así como a la notificación** de intentos de violación de la política (ya sea a través de syslog o auditd).
* **Queja**: Los perfiles en modo de queja **no harán cumplir la política** sino que en su lugar **notificarán** los intentos de **violación de la política**.

AppArmor difiere de algunos otros sistemas MAC en Linux: es **basado en rutas**, permite la mezcla de perfiles de modo de ejecución y de queja, utiliza archivos de inclusión para facilitar el desarrollo y tiene una barrera de entrada mucho más baja que otros sistemas MAC populares.

## Partes de AppArmor

* **Módulo del kernel**: Realiza el trabajo real
* **Políticas**: Define el comportamiento y la contención
* **Analizador**: Carga las políticas en el kernel
* **Utilidades**: Programas de modo de usuario para interactuar con apparmor

## Ruta de los perfiles

Los perfiles de Apparmor suelen guardarse en _**/etc/apparmor.d/**_\
Con `sudo aa-status` podrás listar los binarios que están restringidos por algún perfil. Si puedes cambiar el carácter "/" por un punto de la ruta de cada binario listado, obtendrás el nombre del perfil de apparmor dentro de la carpeta mencionada.

Por ejemplo, un perfil de **apparmor** para _/usr/bin/man_ se encontrará en _/etc/apparmor.d/usr.bin.man_

## Comandos
```bash
aa-status     #check the current status 
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
# Creando un perfil

* Para indicar el ejecutable afectado, se permiten **rutas absolutas y comodines** (para la expansión de archivos) para especificar archivos.
* Para indicar el acceso que el binario tendrá sobre **archivos**, se pueden utilizar los siguientes **controles de acceso**:
  * **r** (lectura)
  * **w** (escritura)
  * **m** (mapeo de memoria como ejecutable)
  * **k** (bloqueo de archivos)
  * **l** (creación de enlaces duros)
  * **ix** (para ejecutar otro programa con la nueva política heredada)
  * **Px** (ejecutar bajo otro perfil, después de limpiar el entorno)
  * **Cx** (ejecutar bajo un perfil hijo, después de limpiar el entorno)
  * **Ux** (ejecutar sin restricciones, después de limpiar el entorno)
* Se pueden definir **variables** en los perfiles y se pueden manipular desde fuera del perfil. Por ejemplo: @{PROC} y @{HOME} (agregue #include \<tunables/global> al archivo de perfil)
* Se admiten **reglas de denegación para anular las reglas de permiso**.

## aa-genprof

Para comenzar a crear un perfil fácilmente, apparmor puede ayudarlo. Es posible hacer que **apparmor inspeccione las acciones realizadas por un binario y luego permitirle decidir qué acciones desea permitir o denegar**.\
Solo necesita ejecutar:
```bash
sudo aa-genprof /path/to/binary
```
Entonces, en una consola diferente realiza todas las acciones que el binario normalmente realiza:
```bash
/path/to/binary -a dosomething
```
Entonces, en la primera consola presiona "**s**" y luego en las acciones grabadas indica si quieres ignorar, permitir o lo que sea. Cuando hayas terminado, presiona "**f**" y el nuevo perfil se creará en _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Usando las teclas de flecha puedes seleccionar lo que quieres permitir/denegar/lo que sea.
{% endhint %}

## aa-easyprof

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
Ten en cuenta que por defecto en un perfil creado nada está permitido, por lo que todo está denegado. Necesitarás agregar líneas como `/etc/passwd r,` para permitir la lectura del binario `/etc/passwd`, por ejemplo.
{% endhint %}

Luego puedes **aplicar** el nuevo perfil con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## Modificando un perfil a partir de registros

La siguiente herramienta leerá los registros y preguntará al usuario si desea permitir algunas de las acciones prohibidas detectadas:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Usando las teclas de flecha puedes seleccionar lo que quieres permitir/denegar/lo que sea.
{% endhint %}

## Administrando un perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# Registros

Ejemplo de registros **AUDIT** y **DENIED** del ejecutable **`service_bin`** en _/var/log/audit/audit.log_:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
También puedes obtener esta información usando:
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
# Apparmor en Docker

Observe cómo el perfil **docker-profile** de Docker se carga por defecto:
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
Por defecto, el perfil de Apparmor docker-default se genera a partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor).

Resumen del perfil docker-default:

* **Acceso** a toda la **red**
* No se define ninguna **capacidad** (sin embargo, algunas capacidades vendrán incluidas en las reglas básicas base, es decir, #include \<abstractions/base>)
* **No se permite** escribir en ningún archivo de **/proc**
* Otros **subdirectorios**/**archivos** de /**proc** y /**sys** tienen **denegado** el acceso de lectura/escritura/bloqueo/enlace/ejecución
* **No se permite** el **montaje**
* **Ptrace** solo se puede ejecutar en un proceso que esté confinado por el **mismo perfil de apparmor**

Una vez que **ejecutas un contenedor de Docker**, deberías ver la siguiente salida:
```bash
1 processes are in enforce mode.
   docker-default (825)
```
Tenga en cuenta que **apparmor incluso bloqueará los privilegios de capacidades** otorgados al contenedor por defecto. Por ejemplo, será capaz de **bloquear el permiso de escritura dentro de /proc incluso si se otorga la capacidad SYS_ADMIN** porque por defecto el perfil de apparmor de docker deniega este acceso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Necesitas **desactivar apparmor** para evitar sus restricciones:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Tenga en cuenta que por defecto, **AppArmor** también **prohibirá que el contenedor monte** carpetas desde el interior, incluso con la capacidad SYS_ADMIN.

Tenga en cuenta que puede **añadir/eliminar** **capacidades** al contenedor de Docker (esto seguirá estando restringido por métodos de protección como **AppArmor** y **Seccomp**):

* `--cap-add=SYS_ADMIN`_ _dar_ _la capacidad_ `SYS_ADMIN`
* `--cap-add=ALL`_ _dar_ _todas las capacidades
* `--cap-drop=ALL --cap-add=SYS_PTRACE` eliminar todas las capacidades y sólo dar `SYS_PTRACE`

{% hint style="info" %}
Por lo general, cuando **descubra** que tiene una **capacidad privilegiada** disponible **dentro** de un **contenedor docker**, pero alguna parte del **exploit no funciona**, esto se debe a que **apparmor de docker lo está impidiendo**.
{% endhint %}

## Fuga de AppArmor en Docker

Puede encontrar qué **perfil de apparmor está ejecutando un contenedor** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
        "AppArmorProfile": "lowpriv",
                "apparmor=lowpriv"
```
Entonces, puedes ejecutar la siguiente línea para **encontrar el perfil exacto que se está utilizando**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
En el extraño caso de que puedas **modificar el perfil de docker de apparmor y recargarlo**, podrías eliminar las restricciones y "burlarlas".
