# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Una buena evaluación de containers debería responder dos preguntas en paralelo. Primero, ¿qué puede hacer un atacante desde la carga de trabajo actual? Segundo, ¿qué decisiones del operador hicieron eso posible? Las herramientas de enumeración ayudan con la primera pregunta, y las guías de hardening ayudan con la segunda. Mantener ambas en una sola página hace que la sección sea más útil como referencia de campo en lugar de solo un catálogo de técnicas de escape.

Una actualización práctica para entornos modernos es que muchos writeups antiguos de containers asumen silenciosamente un **rootful runtime**, **sin aislamiento de user namespace**, y a menudo **cgroup v1**. Esas suposiciones ya no son seguras. Antes de invertir tiempo en primitivas antiguas de escape, primero confirma si la carga de trabajo es rootless o userns-remapped, si el host está usando cgroup v2, y si Kubernetes o el runtime están aplicando ahora perfiles predeterminados de seccomp y AppArmor. Estos detalles suelen decidir si un breakout famoso sigue aplicando.

## Enumeration Tools

Una serie de herramientas siguen siendo útiles para caracterizar rápidamente un entorno de containers:

- `linpeas` puede identificar muchos indicadores de containers, sockets montados, conjuntos de capabilities, filesystems peligrosos y pistas de breakout.
- `CDK` se centra específicamente en entornos de containers e incluye enumeración además de algunas comprobaciones automáticas de escape.
- `amicontained` es ligera y útil para identificar restricciones de containers, capabilities, exposición de namespaces y clases probables de breakout.
- `deepce` es otro enumerador enfocado en containers con comprobaciones orientadas a breakout.
- `grype` es útil cuando la evaluación incluye revisión de vulnerabilidades de paquetes de la imagen en lugar de solo análisis de escape en runtime.
- `Tracee` es útil cuando necesitas **runtime evidence** en lugar de solo postura estática, especialmente para ejecución sospechosa de procesos, acceso a archivos y recolección de eventos aware de containers.
- `Inspektor Gadget` es útil en Kubernetes e investigaciones de hosts Linux cuando necesitas visibilidad respaldada por eBPF vinculada a pods, containers, namespaces y otros conceptos de nivel superior.

El valor de estas herramientas es la velocidad y la cobertura, no la certeza. Ayudan a revelar rápidamente la postura general, pero los hallazgos interesantes siguen necesitando interpretación manual frente al modelo real de runtime, namespace, capabilities y mounts.

## Hardening Priorities

Los principios más importantes de hardening son conceptualmente simples aunque su implementación varíe según la plataforma. Evita containers privilegiados. Evita sockets de runtime montados. No des a los containers paths del host con escritura salvo que haya una razón muy específica. Usa user namespaces o ejecución rootless donde sea posible. Elimina todas las capabilities y añade solo las que la carga de trabajo realmente necesita. Mantén seccomp, AppArmor y SELinux habilitados en lugar de desactivarlos para resolver problemas de compatibilidad de aplicaciones. Limita los recursos para que un container comprometido no pueda denegar servicio al host de forma trivial.

La higiene de imágenes y builds importa tanto como la postura en runtime. Usa imágenes mínimas, reconstruye con frecuencia, escanéelas, exige provenance donde sea práctico y mantén los secrets fuera de las layers. Un container que se ejecuta como non-root con una imagen pequeña y una superficie reducida de syscalls y capabilities es mucho más fácil de defender que una imagen grande de conveniencia ejecutándose como root equivalente al host con herramientas de debugging preinstaladas.

Para Kubernetes, las bases modernas de hardening son más opinadas de lo que muchos operadores todavía suponen. Los **Pod Security Standards** integrados tratan `restricted` como el perfil de "current best practice": `allowPrivilegeEscalation` debería ser `false`, las cargas de trabajo deberían ejecutarse como non-root, seccomp debería configurarse explícitamente como `RuntimeDefault` o `Localhost`, y los conjuntos de capabilities deberían eliminarse de forma agresiva. Durante la evaluación, esto importa porque un cluster que solo usa etiquetas `warn` o `audit` puede parecer endurecido sobre el papel mientras sigue admitiendo pods riesgosos en la práctica.

## Modern Triage Questions

Antes de entrar en páginas específicas de escape, responde estas preguntas rápidas:

1. ¿La carga de trabajo es **rootful**, **rootless** o **userns-remapped**?
2. ¿El nodo usa **cgroup v1** o **cgroup v2**?
3. ¿**seccomp** y **AppArmor/SELinux** están configurados explícitamente, o simplemente se heredan cuando están disponibles?
4. En Kubernetes, ¿el namespace realmente está **enforcing** `baseline` o `restricted`, o solo está advirtiendo/auditing?

Useful checks:
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
Lo interesante aquí:

- Si `/proc/self/uid_map` muestra que root del container está mapeado a un **rango alto de UID de host**, muchos writeups antiguos de host-root dejan de ser tan relevantes porque root dentro del container ya no es equivalente a host-root.
- Si `/sys/fs/cgroup` es `cgroup2fs`, los writeups antiguos específicos de **cgroup v1** como el abuso de `release_agent` ya no deberían ser tu primera suposición.
- Si seccomp y AppArmor solo se heredan implícitamente, la portabilidad puede ser más débil de lo que esperan los defenders. En Kubernetes, establecer explícitamente `RuntimeDefault` suele ser más fuerte que confiar silenciosamente en los defaults del node.
- Si `supplementalGroupsPolicy` está configurado como `Strict`, el pod debería evitar heredar silenciosamente membresías extra de grupos desde `/etc/group` dentro de la image, lo que hace que el comportamiento de acceso a volumes y files basado en grupos sea más predecible.
- Las labels de namespace como `pod-security.kubernetes.io/enforce=restricted` vale la pena verificarlas directamente. `warn` y `audit` son útiles, pero no detienen que se cree un pod riesgoso.

## Resource-Exhaustion Examples

Los controles de recursos no son glamorosos, pero forman parte de la seguridad de containers porque limitan el blast radius de una compromise. Sin límites de memory, CPU o PID, un simple shell puede ser suficiente para degradar el host o los workloads vecinos.

Ejemplo de tests que impactan al host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todos los resultados peligrosos de un container son un "escape" limpio. Los límites débiles de cgroup aún pueden convertir la ejecución de código en un impacto operativo real.

En entornos respaldados por Kubernetes, también verifica si existen controles de recursos en absoluto antes de tratar DoS como algo teórico:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una línea base útil de auditoría en el lado del host porque comprueba problemas de configuración comunes frente a una guía de benchmark ampliamente reconocida:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no es un sustituto de threat modeling, pero sigue siendo valiosa para encontrar defaults descuidados de daemon, mount, network y runtime que se acumulan con el tiempo.

Para Kubernetes y entornos con mucho runtime, combina comprobaciones estáticas con visibilidad en runtime:

- `Tracee` es útil para detección en runtime consciente de contenedores y forensics rápidas cuando necesitas confirmar qué tocó realmente un workload comprometido.
- `Inspektor Gadget` es útil cuando la assessment necesita telemetría a nivel de kernel mapeada de vuelta a pods, containers, actividad DNS, ejecución de archivos o comportamiento de network.

## Checks

Usa estos como comandos rápidos de primera pasada durante la assessment:
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

- Un proceso root con amplias capabilities y `Seccomp: 0` merece atención inmediata.
- Un proceso root que además tiene un **mapeo UID 1:1** es mucho más interesante que "root" dentro de un user namespace correctamente aislado.
- `cgroup2fs` normalmente significa que muchas cadenas de escape más antiguas de **cgroup v1** no son tu mejor punto de partida, mientras que la ausencia de `memory.max` o `pids.max` aún apunta a controles débiles de blast-radius.
- Mounts sospechosos y runtime sockets a menudo ofrecen una vía más rápida para impactar que cualquier kernel exploit.
- La combinación de una postura de runtime débil y límites de recursos débiles suele indicar un entorno de container generalmente permisivo en lugar de un único error aislado.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
