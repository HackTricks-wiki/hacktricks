# Evaluación y hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Una buena evaluación de un contenedor debería responder a dos preguntas en paralelo. Primero, ¿qué puede hacer un atacante desde la carga de trabajo actual? Segundo, ¿qué decisiones del operador lo hicieron posible? Las herramientas de enumeración ayudan con la primera pregunta, y las guías de hardening ayudan con la segunda. Mantener ambas en una misma página hace que la sección sea más útil como referencia de campo, en lugar de ser solo un catálogo de técnicas de escape.

Una actualización práctica para los entornos modernos es que muchos writeups antiguos sobre contenedores asumen implícitamente un **runtime rootful**, **sin aislamiento de user namespace** y, a menudo, **cgroup v1**. Esas suposiciones ya no son seguras. Antes de dedicar tiempo a primitivas de escape antiguas, confirma primero si la carga de trabajo es rootless o usa userns-remapped, si el host utiliza cgroup v2 y si Kubernetes o el runtime están aplicando perfiles predeterminados de seccomp y AppArmor. Estos detalles suelen determinar si un breakout conocido todavía es aplicable.

## Enumeration Tools

Varias herramientas siguen siendo útiles para caracterizar rápidamente un entorno de contenedores:

- `linpeas` puede identificar muchos indicadores de contenedores, sockets montados, conjuntos de capabilities, filesystems peligrosos e indicios de breakout.
- `CDK` se centra específicamente en entornos de contenedores e incluye enumeración y algunas comprobaciones automatizadas de escape.
- `amicontained` es ligera y útil para identificar restricciones del contenedor, capabilities, exposición de namespaces y posibles clases de breakout.
- `deepce` es otra herramienta de enumeración centrada en contenedores, con comprobaciones orientadas a breakout.
- `grype` es útil cuando la evaluación incluye una revisión de vulnerabilidades de paquetes de la imagen, en lugar de limitarse al análisis de escape en runtime.
- `Tracee` es útil cuando necesitas **evidencia en runtime** en lugar de únicamente la postura estática, especialmente para ejecuciones de procesos sospechosas, acceso a archivos y recopilación de eventos con conocimiento de contenedores.
- `Inspektor Gadget` es útil en investigaciones de Kubernetes y de hosts Linux cuando necesitas visibilidad basada en eBPF vinculada a pods, contenedores, namespaces y otros conceptos de nivel superior.

El valor de estas herramientas está en la velocidad y la cobertura, no en la certeza. Ayudan a revelar rápidamente la postura general, pero los hallazgos interesantes aún necesitan interpretación manual según el runtime, el namespace, las capabilities y el modelo de mounts reales.

## Hardening Priorities

Los principios más importantes de hardening son conceptualmente sencillos, aunque su implementación varía según la plataforma. Evita los contenedores privileged. Evita montar sockets del runtime. No proporciones a los contenedores rutas del host con permisos de escritura, salvo que exista una razón muy específica. Usa user namespaces o ejecución rootless cuando sea viable. Elimina todas las capabilities y vuelve a añadir únicamente las que la carga de trabajo necesite realmente. Mantén seccomp, AppArmor y SELinux habilitados en lugar de desactivarlos para resolver problemas de compatibilidad de la aplicación. Limita los recursos para que un contenedor comprometido no pueda provocar fácilmente una denegación de servicio en el host.

La higiene de las imágenes y del proceso de build es tan importante como la postura del runtime. Usa imágenes minimalistas, recompílalas con frecuencia, escanéalas, exige provenance cuando sea práctico y mantén los secrets fuera de las layers. Un contenedor que se ejecuta como non-root, con una imagen pequeña y una superficie reducida de syscalls y capabilities, es mucho más fácil de defender que una imagen grande y conveniente que se ejecuta como root equivalente al host, con herramientas de debugging preinstaladas.

En Kubernetes, los baselines actuales de hardening son más estrictos de lo que muchos operadores todavía asumen. Los **Pod Security Standards** integrados consideran `restricted` como el perfil de "mejor práctica actual": `allowPrivilegeEscalation` debería ser `false`, las cargas de trabajo deberían ejecutarse como non-root, seccomp debería establecerse explícitamente en `RuntimeDefault` o `Localhost`, y los conjuntos de capabilities deberían eliminarse de forma agresiva. Durante una evaluación, esto es importante porque un cluster que solo utiliza labels `warn` o `audit` puede parecer hardened sobre el papel, mientras que en la práctica sigue admitiendo pods de riesgo.

## Modern Triage Questions

Antes de entrar en páginas específicas sobre escapes, responde a estas preguntas rápidas:

1. ¿La carga de trabajo es **rootful**, **rootless** o **userns-remapped**?
2. ¿El nodo utiliza **cgroup v1** o **cgroup v2**?
3. ¿Están **seccomp** y **AppArmor/SELinux** configurados explícitamente, o simplemente se heredan cuando están disponibles?
4. En Kubernetes, ¿el namespace está realmente **enforcing** `baseline` o `restricted`, o solo está generando warnings/auditing?

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
Qué es interesante aquí:

- Si `/proc/self/uid_map` muestra que el root del contenedor está asignado a un **rango de UID altos del host**, muchas writeups antiguas sobre escritura como root en el host son menos relevantes, porque el root dentro del contenedor ya no equivale al root del host.
- Si `/sys/fs/cgroup` es `cgroup2fs`, las writeups antiguas específicas de **cgroup v1**, como el abuso de `release_agent`, ya no deberían ser tu primera hipótesis.
- Si seccomp y AppArmor solo se heredan implícitamente, la portabilidad puede ser menor de lo que esperan los defensores. En Kubernetes, establecer explícitamente `RuntimeDefault` suele ser más seguro que depender silenciosamente de los valores predeterminados del nodo.
- Si `supplementalGroupsPolicy` está establecido en `Strict`, el pod debería evitar heredar silenciosamente membresías de grupos adicionales desde `/etc/group` dentro de la imagen, lo que hace más predecible el comportamiento del acceso basado en grupos a volúmenes y archivos.
- Conviene comprobar directamente etiquetas de namespace como `pod-security.kubernetes.io/enforce=restricted`. `warn` y `audit` son útiles, pero no impiden que se cree un pod de riesgo.

## Triaje de la línea base del runtime

Una línea base del runtime es la comprobación rápida que indica si un contenedor parece una carga de trabajo aislada normal o un punto de apoyo en el plano de control con impacto en el host. Debe recopilar suficientes datos para priorizar la siguiente área que revisar: abuso del socket del runtime, montajes del host, namespaces, cgroups, capabilities o revisión de secretos de la imagen.

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

- Un `memory.max` / `pids.max` ausente o ilimitado apunta a controles débiles del radio de impacto, incluso sin un escape limpio.
- Un shell root con `NoNewPrivs: 0`, capabilities amplias y seccomp permisivo es mucho más interesante que un workload no root y restringido.
- Los runtime sockets y los host mounts escribibles normalmente tienen prioridad sobre los kernel exploits, porque ya exponen una ruta de control de gestión o del filesystem.
- Los namespaces de PID, red, IPC o cgroup compartidos no siempre son escapes completos por sí mismos, pero facilitan encontrar el siguiente paso.

## Ejemplos de agotamiento de recursos

Los controles de recursos no son glamurosos, pero forman parte de la seguridad de los containers porque limitan el radio de impacto de un compromiso. Sin límites de memoria, CPU o PID, un simple shell puede bastar para degradar el host o los workloads vecinos.

Ejemplos de pruebas con impacto en el host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todos los resultados peligrosos en un contenedor constituyen un «escape» limpio. Unos límites de cgroup débiles aún pueden convertir la ejecución de código en un impacto operativo real.

En entornos respaldados por Kubernetes, comprueba también si existen controles de recursos antes de considerar el DoS como algo teórico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Herramientas de hardening

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una referencia útil para la auditoría del host, ya que comprueba problemas de configuración comunes conforme a directrices de referencia ampliamente reconocidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no sustituye al threat modeling, pero sigue siendo valiosa para encontrar configuraciones predeterminadas descuidadas de daemons, montajes, red y runtime que se acumulan con el tiempo.

Para Kubernetes y entornos con un uso intensivo del runtime, combina las comprobaciones estáticas con visibilidad del runtime:

- `Tracee` resulta útil para la detección en runtime con conocimiento de los containers y para realizar forensics rápidos cuando necesitas confirmar qué elementos tocó realmente un workload comprometido.
- `Inspektor Gadget` resulta útil cuando la evaluación necesita telemetría a nivel del kernel asociada de vuelta a pods, containers, actividad DNS, ejecución de archivos o comportamiento de red.

## Comprobaciones

Úsalas como comandos iniciales rápidos durante la evaluación:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Qué es interesante aquí:

- Un proceso root con capacidades amplias y `Seccomp: 0` merece atención inmediata.
- Un proceso root que también tiene un **1:1 UID map** es mucho más interesante que el usuario "root" dentro de un user namespace correctamente aislado.
- `cgroup2fs` normalmente significa que muchas cadenas de escape antiguas de **cgroup v1** no son el mejor punto de partida, mientras que la ausencia de `memory.max` o `pids.max` sigue apuntando a controles débiles del radio de impacto.
- Los mounts sospechosos y los runtime sockets suelen proporcionar un camino más rápido hacia el impacto que cualquier exploit del kernel.
- La combinación de una postura débil del runtime y límites de recursos débiles suele indicar un entorno de contenedores generalmente permisivo, en lugar de un único error aislado.

## Referencias

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
