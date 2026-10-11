# Evaluación y hardening

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Una buena evaluación de contenedores debe responder dos preguntas paralelas. Primero, ¿qué puede hacer un atacante desde la carga de trabajo actual? Segundo, ¿qué decisiones del operador lo hicieron posible? Las herramientas de enumeración ayudan con la primera pregunta, y las guías de hardening ayudan con la segunda. Mantener ambas en una sola página hace que esta sección sea más útil como referencia de campo, en lugar de ser solo un catálogo de técnicas de escape.

Una actualización práctica para los entornos modernos es que muchos writeups antiguos sobre contenedores dan por sentado, sin decirlo, un **runtime rootful**, **sin aislamiento de user namespace** y, a menudo, **cgroup v1**. Esas suposiciones ya no son seguras. Antes de dedicar tiempo a primitivas de escape antiguas, confirma primero si la carga de trabajo es rootless o tiene userns-remapped, si el host usa cgroup v2 y si Kubernetes o el runtime están aplicando ahora perfiles predeterminados de seccomp y AppArmor. Estos detalles suelen determinar si una técnica de breakout conocida sigue siendo aplicable.

## Herramientas de enumeración

Varias herramientas siguen siendo útiles para caracterizar rápidamente un entorno de contenedores:

- `linpeas` puede identificar muchos indicadores de contenedores, sockets montados, conjuntos de capacidades, sistemas de archivos peligrosos e indicios de breakout.
- `CDK` se centra específicamente en entornos de contenedores e incluye enumeración, además de algunas comprobaciones automatizadas de escape.
- `amicontained` es ligera y útil para identificar restricciones de contenedores, capacidades, exposición de namespaces y posibles clases de breakout.
- `deepce` es otra herramienta de enumeración centrada en contenedores, con comprobaciones orientadas al breakout.
- `grype` es útil cuando la evaluación incluye el análisis de vulnerabilidades de paquetes de imágenes, en lugar de limitarse al análisis de escapes en runtime.
- `Tracee` es útil cuando necesitas **evidencia en runtime**, y no solo una evaluación estática de la postura, especialmente para detectar ejecuciones de procesos sospechosas, accesos a archivos y recopilar eventos con contexto de contenedores.
- `Inspektor Gadget` es útil en investigaciones de Kubernetes y de hosts Linux cuando necesitas visibilidad respaldada por eBPF y vinculada a pods, contenedores, namespaces y otros conceptos de nivel superior.

El valor de estas herramientas está en su rapidez y cobertura, no en la certeza. Ayudan a revelar rápidamente la postura general, pero los hallazgos relevantes aún requieren interpretación manual teniendo en cuenta el runtime, los namespaces, las capacidades y el modelo de montaje reales.

## Prioridades de hardening

Los principios de hardening más importantes son conceptualmente sencillos, aunque su implementación varía según la plataforma. Evita los contenedores privilegiados. Evita montar sockets del runtime. No des a los contenedores rutas del host con permisos de escritura, salvo que haya una razón muy específica. Usa user namespaces o ejecución rootless cuando sea viable. Elimina todas las capacidades y vuelve a añadir solo las que la carga de trabajo realmente necesita. Mantén seccomp, AppArmor y SELinux habilitados, en lugar de desactivarlos para resolver problemas de compatibilidad de aplicaciones. Limita los recursos para que un contenedor comprometido no pueda causar fácilmente una denegación de servicio al host.

La higiene de las imágenes y del proceso de build importa tanto como la postura en runtime. Usa imágenes mínimas, reconstrúyelas con frecuencia, analízalas, exige procedencia cuando sea práctico y evita incluir secretos en las capas. Un contenedor que se ejecuta como non-root, con una imagen pequeña y una superficie reducida de syscalls y capacidades, es mucho más fácil de defender que una imagen grande y conveniente que se ejecuta como root con privilegios equivalentes a los del host y con herramientas de depuración preinstaladas.

En Kubernetes, las líneas base de hardening actuales son más estrictas de lo que muchos operadores todavía creen. Los **Pod Security Standards** integrados consideran `restricted` el perfil de "mejores prácticas actuales": `allowPrivilegeEscalation` debería ser `false`, las cargas de trabajo deberían ejecutarse como non-root, seccomp debería establecerse explícitamente en `RuntimeDefault` o `Localhost`, y los conjuntos de capacidades deberían reducirse de forma agresiva. Durante una evaluación, esto importa porque un clúster que solo usa etiquetas `warn` o `audit` puede parecer endurecido sobre el papel y, aun así, admitir pods riesgosos en la práctica.<sup>[[1]](#references)</sup>

Cuando un Pod tiene montado un token de service account, evalúa sus permisos **en cada namespace de destino**. Una regla que enumera Pods en un namespace no establece permisos en otro; un token montado en otro Pod puede tener derechos diferentes. Usa `kubectl auth can-i list pods -n <target-namespace>` y `kubectl auth can-i list secrets -n <target-namespace>` con la identidad que se está evaluando. Que se permita listar Secrets es un indicio importante, porque la respuesta de una operación de listado puede incluir el contenido de los Secrets, pero no demuestra que haya un token con privilegios. El acceso al host requiere además un permiso utilizable para crear cargas de trabajo, que se admita el montaje `hostPath` propuesto y que el contexto de seguridad del nodo/pod permita la operación prevista sobre los archivos. Consulta la [documentación de Kubernetes sobre comprobaciones de autorización](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) y la [guía de RBAC sobre escalada de privilegios](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Preguntas de triage moderno

Antes de profundizar en páginas específicas sobre escapes, responde estas preguntas rápidas:

1. ¿La carga de trabajo es **rootful**, **rootless** o **userns-remapped**?
2. ¿El nodo usa **cgroup v1** o **cgroup v2**?
3. ¿Están **seccomp** y **AppArmor/SELinux** configurados explícitamente o solo se heredan cuando están disponibles?
4. En Kubernetes, ¿el namespace realmente **enforcea** `baseline` o `restricted`, o solo genera advertencias o auditorías?

Comprobaciones útiles:

```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```

Qué resulta interesante aquí:

- Si `/proc/self/uid_map` muestra que el root del container está asignado a un **rango alto de UID del host**, muchos writeups antiguos sobre root en el host pierden relevancia, porque el root del container ya no equivale al root del host.
- Si `/sys/fs/cgroup` es `cgroup2fs`, los writeups antiguos específicos de **cgroup v1**, como el abuso de `release_agent`, ya no deberían ser tu primera opción.
- Si seccomp y AppArmor solo se heredan de forma implícita, la portabilidad puede ser menor de lo que esperan los defensores. En Kubernetes, establecer explícitamente `RuntimeDefault` suele ser más seguro que depender silenciosamente de los valores predeterminados del nodo.
- Si `supplementalGroupsPolicy` está establecido en `Strict`, el pod debería evitar heredar silenciosamente membresías de grupos adicionales de `/etc/group` dentro de la imagen, lo que hace más predecible el comportamiento de acceso a volúmenes y archivos basado en grupos.
- Vale la pena comprobar directamente las etiquetas de namespace, como `pod-security.kubernetes.io/enforce=restricted`. `warn` y `audit` son útiles, pero no impiden que se cree un pod riesgoso.

## Triaje de la línea base en tiempo de ejecución

Una línea base en tiempo de ejecución es una comprobación rápida que permite determinar si un container parece una carga de trabajo aislada normal o un punto de apoyo en el plano de control con impacto en el host. Debería recopilar suficientes datos para priorizar qué revisar después: abuso de sockets del runtime, montajes del host, namespaces, cgroups, capabilities o revisión de secretos de la imagen.

Comprobaciones útiles desde dentro de una carga de trabajo:

```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Interpretación:

- La ausencia de límites o los valores ilimitados en `memory.max` / `pids.max` indican controles débiles del radio de impacto, incluso sin una vía de escape clara.
- Un shell de root con `NoNewPrivs: 0`, capacidades amplias y seccomp permisivo es mucho más interesante que una carga de trabajo limitada y sin privilegios de root.
- Los sockets del runtime y los montajes del host con permisos de escritura suelen tener prioridad sobre los exploits del kernel, porque ya exponen una vía de control de la administración o del sistema de archivos.
- Los namespaces compartidos de PID, red, IPC o cgroups no siempre constituyen por sí solos escapes completos, pero facilitan encontrar el siguiente paso.

## Ejemplos de agotamiento de recursos

Los controles de recursos no son llamativos, pero forman parte de la seguridad de contenedores porque limitan el radio de impacto de un compromiso. Sin límites de memoria, CPU o PID, un simple shell puede bastar para degradar el host o las cargas de trabajo vecinas.

Ejemplos de pruebas que afectan al host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Estos ejemplos son útiles porque muestran que no todos los resultados peligrosos en contenedores implican una «escape» limpia. Los límites débiles de cgroup aún pueden convertir la ejecución de código en un impacto operativo real.

En entornos respaldados por Kubernetes, comprueba también si existen controles de recursos antes de considerar teórico un DoS:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Herramientas de hardening

En entornos centrados en Docker, `docker-bench-security` sigue siendo una referencia útil para las auditorías del host, ya que comprueba problemas de configuración comunes con respecto a directrices de referencia ampliamente reconocidas. Los avisos sobre el runtime deben revisarse por separado, ya que una evaluación de configuración no puede detectar si el runtime instalado está afectado por una vulnerabilidad recién divulgada. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

La herramienta no sustituye al threat modeling, pero sigue siendo útil para detectar valores predeterminados descuidados en daemons, montajes, redes y entornos de ejecución que se acumulan con el tiempo.

En entornos de Kubernetes y con mucho uso de entornos de ejecución, combina las comprobaciones estáticas con la visibilidad en tiempo de ejecución:

- `Tracee` es útil para la detección en tiempo de ejecución con conocimiento de contenedores y para realizar análisis forenses rápidos cuando necesitas confirmar qué elementos tocó realmente una carga de trabajo comprometida.
- `Inspektor Gadget` es útil cuando la evaluación requiere telemetría a nivel de kernel asociada a pods, contenedores, actividad DNS, ejecución de archivos o comportamiento de red.

## Comprobaciones

Usa estos comandos como primera comprobación rápida durante la evaluación:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Qué resulta interesante aquí:

- Un proceso root con amplias capabilities y `Seccomp: 0` merece atención inmediata.
- Un proceso root que también tiene un **mapa de UID 1:1** es mucho más interesante que «root» dentro de un user namespace correctamente aislado.
- `cgroup2fs` suele significar que muchas cadenas de escape antiguas de **cgroup v1** no son el mejor punto de partida, mientras que la ausencia de `memory.max` o `pids.max` sigue apuntando a controles débiles del radio de impacto.
- Los mounts sospechosos y los sockets del runtime suelen ofrecer una vía más rápida para lograr impacto que cualquier exploit del kernel.
- La combinación de una postura débil del runtime y límites de recursos débiles suele indicar un entorno de contenedores generalmente permisivo, en lugar de un único error aislado.

## References

- [1] [Estándares de seguridad de pods de Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Aviso de seguridad de Docker: múltiples vulnerabilidades en runc, BuildKit y Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
