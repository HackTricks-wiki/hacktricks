# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Información Básica

AppArmor es una **mejora del kernel diseñada para restringir los recursos disponibles para los programas a través de perfiles por programa**, implementando efectivamente el Control de Acceso Obligatorio (MAC) al vincular los atributos de control de acceso directamente a los programas en lugar de a los usuarios. Este sistema opera **cargando perfiles en el kernel**, generalmente durante el arranque, y estos perfiles dictan qué recursos puede acceder un programa, como conexiones de red, acceso a sockets en bruto y permisos de archivos.

Hay dos modos operativos para los perfiles de AppArmor:

- **Modo de Aplicación**: Este modo aplica activamente las políticas definidas dentro del perfil, bloqueando acciones que violan estas políticas y registrando cualquier intento de infringirlas a través de sistemas como syslog o auditd.
- **Modo de Queja**: A diferencia del modo de aplicación, el modo de queja no bloquea acciones que van en contra de las políticas del perfil. En su lugar, registra estos intentos como violaciones de políticas sin imponer restricciones.

### Componentes de AppArmor

- **Módulo del Kernel**: Responsable de la aplicación de políticas.
- **Políticas**: Especifican las reglas y restricciones para el comportamiento del programa y el acceso a recursos.
- **Parser**: Carga políticas en el kernel para su aplicación o reporte.
- **Utilidades**: Estos son programas en modo usuario que proporcionan una interfaz para interactuar y gestionar AppArmor.

### Ruta de Perfiles

Los perfiles de AppArmor generalmente se guardan en _**/etc/apparmor.d/**_\
Con `sudo aa-status` podrás listar los binarios que están restringidos por algún perfil. Si puedes cambiar el carácter "/" por un punto en la ruta de cada binario listado, obtendrás el nombre del perfil de AppArmor dentro de la carpeta mencionada.

Por ejemplo, un **perfil de apparmor** para _/usr/bin/man_ se ubicará en _/etc/apparmor.d/usr.bin.man_

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

- Para indicar el ejecutable afectado, se permiten **rutas absolutas y comodines** para especificar archivos.
- Para indicar el acceso que tendrá el binario sobre **archivos**, se pueden utilizar los siguientes **controles de acceso**:
- **r** (leer)
- **w** (escribir)
- **m** (mapa de memoria como ejecutable)
- **k** (bloqueo de archivos)
- **l** (creación de enlaces duros)
- **ix** (para ejecutar otro programa con la nueva política heredada)
- **Px** (ejecutar bajo otro perfil, después de limpiar el entorno)
- **Cx** (ejecutar bajo un perfil hijo, después de limpiar el entorno)
- **Ux** (ejecutar sin restricciones, después de limpiar el entorno)
- **Variables** pueden ser definidas en los perfiles y pueden ser manipuladas desde fuera del perfil. Por ejemplo: @{PROC} y @{HOME} (agregar #include \<tunables/global> al archivo del perfil)
- **Se admiten reglas de denegación para anular reglas de permiso**.

### aa-genprof

Para comenzar a crear un perfil fácilmente, apparmor puede ayudarte. Es posible hacer que **apparmor inspeccione las acciones realizadas por un binario y luego te deje decidir qué acciones deseas permitir o denegar**.\
Solo necesitas ejecutar:
```bash
sudo aa-genprof /path/to/binary
```
Luego, en una consola diferente, realiza todas las acciones que el binario normalmente realizará:
```bash
/path/to/binary -a dosomething
```
Luego, en la primera consola presiona "**s**" y luego en las acciones grabadas indica si deseas ignorar, permitir o lo que sea. Cuando hayas terminado presiona "**f**" y el nuevo perfil se creará en _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Usando las teclas de flecha puedes seleccionar lo que deseas permitir/denegar/o lo que sea

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
> [!NOTE]
> Tenga en cuenta que, por defecto, en un perfil creado no se permite nada, por lo que todo está denegado. Necesitará agregar líneas como `/etc/passwd r,` para permitir que el binario lea `/etc/passwd`, por ejemplo.

Luego puede **imponer** el nuevo perfil con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificando un perfil a partir de registros

La siguiente herramienta leerá los registros y preguntará al usuario si desea permitir algunas de las acciones prohibidas detectadas:
```bash
sudo aa-logprof
```
> [!NOTE]
> Usando las teclas de flecha puedes seleccionar lo que deseas permitir/negar/o lo que sea

### Gestionando un Perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Ejemplo de registros **AUDIT** y **DENIED** de _/var/log/audit/audit.log_ del ejecutable **`service_bin`**:
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

Nota cómo el perfil **docker-profile** de docker se carga por defecto:
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
Por defecto, el **perfil docker-default de Apparmor** se genera a partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Resumen del perfil docker-default**:

- **Acceso** a toda la **red**
- **No se define ninguna capacidad** (Sin embargo, algunas capacidades provendrán de incluir reglas base básicas es decir, #include \<abstractions/base>)
- **Escribir** en cualquier archivo de **/proc** **no está permitido**
- Otros **subdirectorios**/**archivos** de /**proc** y /**sys** tienen acceso de lectura/escritura/bloqueo/enlace/ejecución **denegado**
- **Montar** **no está permitido**
- **Ptrace** solo se puede ejecutar en un proceso que está confinado por el **mismo perfil de apparmor**

Una vez que **ejecutes un contenedor docker**, deberías ver la siguiente salida:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Tenga en cuenta que **apparmor incluso bloqueará los privilegios de capacidades** otorgados al contenedor por defecto. Por ejemplo, podrá **bloquear el permiso para escribir dentro de /proc incluso si se otorga la capacidad SYS_ADMIN** porque, por defecto, el perfil de apparmor de docker niega este acceso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Necesitas **deshabilitar apparmor** para eludir sus restricciones:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Tenga en cuenta que por defecto **AppArmor** también **prohibirá que el contenedor monte** carpetas desde adentro, incluso con la capacidad SYS_ADMIN.

Tenga en cuenta que puede **agregar/eliminar** **capacidades** al contenedor de docker (esto seguirá estando restringido por métodos de protección como **AppArmor** y **Seccomp**):

- `--cap-add=SYS_ADMIN` otorga la capacidad `SYS_ADMIN`
- `--cap-add=ALL` otorga todas las capacidades
- `--cap-drop=ALL --cap-add=SYS_PTRACE` elimina todas las capacidades y solo otorga `SYS_PTRACE`

> [!NOTE]
> Generalmente, cuando **encuentra** que tiene una **capacidad privilegiada** disponible **dentro** de un contenedor **docker** **pero** alguna parte de la **explotación no está funcionando**, esto será porque **apparmor de docker estará impidiendo** que funcione.

### Ejemplo

(Ejemplo de [**aquí**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Para ilustrar la funcionalidad de AppArmor, creé un nuevo perfil de Docker “mydocker” con la siguiente línea añadida:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Para activar el perfil, necesitamos hacer lo siguiente:
```
sudo apparmor_parser -r -W mydocker
```
Para listar los perfiles, podemos ejecutar el siguiente comando. El comando a continuación está listando mi nuevo perfil de AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Como se muestra a continuación, obtenemos un error al intentar cambiar “/etc/” ya que el perfil de AppArmor está impidiendo el acceso de escritura a “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Puedes encontrar qué **perfil de apparmor está ejecutando un contenedor** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Luego, puedes ejecutar la siguiente línea para **encontrar el perfil exacto que se está utilizando**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
En el extraño caso de que puedas **modificar el perfil de docker de apparmor y recargarlo.** Podrías eliminar las restricciones y "eludirlas".

### Bypass de AppArmor Docker2

**AppArmor se basa en rutas**, esto significa que incluso si podría estar **protegiendo** archivos dentro de un directorio como **`/proc`**, si puedes **configurar cómo se va a ejecutar el contenedor**, podrías **montar** el directorio proc del host dentro de **`/host/proc`** y **ya no estará protegido por AppArmor**.

### Bypass de Shebang de AppArmor

En [**este bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) puedes ver un ejemplo de cómo **incluso si estás impidiendo que perl se ejecute con ciertos recursos**, si simplemente creas un script de shell **especificando** en la primera línea **`#!/usr/bin/perl`** y **ejecutas el archivo directamente**, podrás ejecutar lo que quieras. Por ejemplo:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
