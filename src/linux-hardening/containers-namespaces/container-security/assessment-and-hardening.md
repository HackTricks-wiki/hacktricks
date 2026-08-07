# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Un buen assessment de un container debería responder a dos preguntas paralelas. Primero, ¿qué puede hacer un atacante desde el workload actual? Segundo, ¿qué decisiones del operador lo hicieron posible? Las herramientas de enumeración ayudan con la primera pregunta, y las guías de hardening con la segunda. Mantener ambas en la misma página hace que esta sección sea más útil como referencia de campo, en lugar de ser solo un catálogo de técnicas de escape.

Una actualización práctica para los entornos modernos es que muchos writeups antiguos sobre containers asumen implícitamente un **rootful runtime**, **sin aislamiento de user namespace** y, a menudo, **cgroup v1**. Esas suposiciones ya no son seguras. Antes de dedicar tiempo a antiguos escape primitives, confirma primero si el workload es rootless o usa userns-remapped, si el host utiliza cgroup v2 y si Kubernetes o el runtime están aplicando actualmente perfiles predeterminados de seccomp y AppArmor. Estos detalles suelen determinar si un breakout conocido sigue siendo aplicable.

## Enumeration Tools

Varias herramientas siguen siendo útiles para caracterizar rápidamente un entorno de container:

- `linpeas` puede identificar muchos indicadores de container, sockets montados, conjuntos de capabilities, filesystems peligrosos e indicios de breakout.
- `CDK` se centra específicamente en entornos de container e incluye enumeración y algunas comprobaciones automatizadas de escape.
- `amicontained` es ligera y útil para identificar restricciones del container, capabilities, exposición de namespaces y posibles clases de breakout.
- `deepce` es otra herramienta de enumeración centrada en containers, con comprobaciones orientadas a breakout.
- `grype` es útil cuando el assessment incluye la revisión de vulnerabilidades de paquetes de la image, en lugar de limitarse al análisis de escape en runtime.
- `Tracee` es útil cuando necesitas **evidencia en runtime** y no solo una evaluación estática de la postura, especialmente para la ejecución de procesos sospechosos, el acceso a archivos y la recopilación de eventos con conocimiento de containers.
- `Inspektor Gadget` es útil en investigaciones de Kubernetes y hosts Linux cuando necesitas visibilidad respaldada por eBPF y vinculada a pods, containers, namespaces y otros conceptos de mayor nivel.

El valor de estas herramientas reside en la velocidad y la cobertura, no en la certeza. Ayudan a revelar rápidamente la postura general, pero los hallazgos relevantes aún requieren interpretación manual según el runtime real y el modelo de namespaces, capabilities y mounts.

## Hardening Priorities

Los principios más importantes de hardening son conceptualmente simples, aunque su implementación varía según la plataforma. Evita los containers privilegiados. Evita montar sockets del runtime. No proporciones a los containers paths del host con permisos de escritura, salvo que exista un motivo muy concreto. Usa user namespaces o ejecución rootless cuando sea viable. Elimina todas las capabilities y añade únicamente las que el workload necesite realmente. Mantén seccomp, AppArmor y SELinux habilitados, en lugar de desactivarlos para solucionar problemas de compatibilidad de la aplicación. Limita los recursos para que un container comprometido no pueda provocar fácilmente una denegación de servicio en el host.

La higiene de las images y del proceso de build es tan importante como la postura del runtime. Usa images mínimas, reconstruye con frecuencia, escanéalas, exige provenance cuando sea práctico y mantén los secrets fuera de las layers. Un container que se ejecuta como non-root, con una image pequeña y una superficie reducida de syscalls y capabilities, es mucho más fácil de defender que una image grande y cómoda que se ejecuta con root equivalente al host y con herramientas de debugging preinstaladas.

En Kubernetes, los baselines actuales de hardening son más estrictos de lo que muchos operadores todavía asumen. Los **Pod Security Standards** integrados consideran `restricted` como el perfil de "mejor práctica actual": `allowPrivilegeEscalation` debería ser `false`, los workloads deberían ejecutarse como non-root, seccomp debería configurarse explícitamente como `RuntimeDefault` o `Localhost`, y los conjuntos de capabilities deberían eliminarse de forma agresiva. Durante el assessment, esto es importante porque un cluster que solo utiliza labels `warn` o `audit` puede parecer hardened sobre el papel y, aun así, seguir admitiendo pods riesgosos en la práctica.<sup>[[1]](#references)</sup>

## Modern Triage Questions

Antes de entrar en páginas específicas sobre escape, responde estas preguntas rápidas:

1. ¿El workload es **rootful**, **rootless** o **userns-remapped**?
2. ¿El node utiliza **cgroup v1** o **cgroup v2**?
3. ¿**seccomp** y **AppArmor/SELinux** están configurados explícitamente o simplemente se heredan cuando están disponibles?
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

- Si `/proc/self/uid_map` muestra que el root del contenedor está mapeado a un **rango de UID alto del host**, muchos writeups antiguos sobre escritura como root en el host son menos relevantes, porque el root dentro del contenedor ya no es equivalente al root del host.
- Si `/sys/fs/cgroup` es `cgroup2fs`, los writeups antiguos específicos de **cgroup v1**, como el abuso de `release_agent`, ya no deberían ser tu primera opción.
- Si seccomp y AppArmor solo se heredan implícitamente, la portabilidad puede ser menor de lo que los defensores esperan. En Kubernetes, establecer explícitamente `RuntimeDefault` suele ser más seguro que depender silenciosamente de los valores predeterminados del nodo.
- Si `supplementalGroupsPolicy` está establecido en `Strict`, el pod debería evitar heredar silenciosamente membresías de grupos adicionales desde `/etc/group` dentro de la imagen, lo que hace más predecible el comportamiento de acceso a volúmenes y archivos basado en grupos.
- Conviene comprobar directamente etiquetas del namespace como `pod-security.kubernetes.io/enforce=restricted`. `warn` y `audit` son útiles, pero no impiden que se cree un pod arriesgado.

## Triage de la línea base del Runtime

Una línea base del Runtime es la comprobación rápida que indica si un contenedor parece una carga de trabajo aislada normal o un punto de apoyo del plano de control con impacto en el host. Debe recopilar suficientes datos para priorizar la siguiente sección que leer: abuso del socket del Runtime, montajes del host, namespaces, cgroups, capabilities o revisión de secretos de la imagen.

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

- La ausencia de límites o los valores ilimitados en `memory.max` / `pids.max` apuntan a controles débiles del radio de impacto incluso sin una escape limpia.
- Un shell root con `NoNewPrivs: 0`, capabilities amplias y seccomp permisivo es mucho más interesante que una workload non-root restringida.
- Los runtime sockets y los mounts del host con permisos de escritura suelen tener prioridad sobre los kernel exploits, porque ya exponen una vía de control de gestión o del filesystem.
- Los namespaces PID, de red, IPC o cgroup compartidos no siempre constituyen escapes completos por sí mismos, pero facilitan encontrar el siguiente paso.

## Ejemplos de agotamiento de recursos

Los controles de recursos no son atractivos, pero forman parte de la seguridad de los containers porque limitan el radio de impacto de una compromise. Sin límites de memoria, CPU o PID, un simple shell puede bastar para degradar el host o las workloads vecinas.

Ejemplos de tests con impacto en el host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todo resultado peligroso en un container es un «escape» limpio. Unos límites de cgroup débiles aún pueden convertir la ejecución de código en un impacto operativo real.

En entornos respaldados por Kubernetes, comprueba también si existen controles de recursos antes de considerar el DoS como algo teórico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Herramientas de hardening

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una referencia útil para la auditoría en el host, ya que comprueba problemas de configuración comunes conforme a directrices de benchmarks ampliamente reconocidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no sustituye al threat modeling, pero sigue siendo útil para detectar valores predeterminados descuidados en daemons, montajes, redes y runtimes que se acumulan con el tiempo.

Para Kubernetes y entornos con un uso intensivo de runtimes, combina las comprobaciones estáticas con visibilidad en runtime:

- `Tracee` es útil para la detección en runtime con conocimiento de contenedores y para realizar forensics rápidamente cuando necesitas confirmar qué elementos tocó realmente un workload comprometido.
- `Inspektor Gadget` es útil cuando el assessment necesita telemetría a nivel del kernel asociada de vuelta a pods, contenedores, actividad DNS, ejecución de archivos o comportamiento de red.

## Comprobaciones

Usa estos comandos como primera comprobación rápida durante el assessment:
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

- Un proceso root con capacidades amplias y `Seccomp: 0` merece atención inmediata.
- Un proceso root que también tiene un **mapeo de UID 1:1** es mucho más interesante que el usuario "root" dentro de un user namespace correctamente aislado.
- `cgroup2fs` normalmente significa que muchas cadenas de escape antiguas de **cgroup v1** no son el mejor punto de partida, mientras que la ausencia de `memory.max` o `pids.max` sigue apuntando a controles débiles del blast radius.
- Los mounts sospechosos y los runtime sockets suelen proporcionar una vía más rápida para lograr impacto que cualquier exploit del kernel.
- La combinación de una postura débil del runtime y límites de recursos débiles suele indicar un entorno de contenedores generalmente permisivo, en lugar de un único error aislado.

## Referencias

- [1] [Estándares de seguridad de Kubernetes para Pods](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Aviso de seguridad de Docker: múltiples vulnerabilidades en runc, BuildKit y Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
