# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en container security es que varios componentes completamente distintos suelen agruparse bajo la misma palabra. "Docker" puede referirse a un formato de imagen, una CLI, un daemon, un sistema de build, un runtime stack o simplemente a la idea de los containers en general. Para el trabajo de security, esa ambigüedad es un problema, porque las distintas capas son responsables de diferentes protecciones. Un breakout causado por un bind mount incorrecto no es lo mismo que un breakout causado por un bug en el runtime de bajo nivel, y tampoco es lo mismo que un error de policy del cluster en Kubernetes.

Esta página separa el ecosistema por función para que el resto de la sección pueda explicar con precisión dónde se encuentra realmente una protección o una debilidad.

## OCI As The Common Language

Los stacks modernos de containers en Linux suelen interoperar porque hablan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las layers. La **OCI Runtime Specification** describe cómo el runtime debe lanzar el proceso, incluyendo namespaces, mounts, cgroups y security settings. La **OCI Distribution Specification** estandariza cómo los registries exponen el contenido.

Esto es importante porque explica por qué una container image creada con una herramienta a menudo puede ejecutarse con otra, y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de security puede parecer similar entre distintos productos: muchos de ellos construyen la misma configuración del runtime OCI y se la entregan al mismo conjunto reducido de runtimes.

## Low-Level OCI Runtimes

El runtime de bajo nivel es el componente más cercano al límite con el kernel. Es la parte que realmente crea namespaces, escribe la configuración de los cgroups, aplica capabilities y filtros seccomp y, finalmente, ejecuta `execve()` sobre el proceso del container. Cuando se habla de "container isolation" a nivel mecánico, normalmente se está hablando de esta capa, aunque no se diga explícitamente.

### `runc`

`runc` es el runtime OCI de referencia y sigue siendo la implementación más conocida. Se utiliza ampliamente bajo Docker, containerd y muchos deployments de Kubernetes. Gran parte del material público de research y exploitation se dirige a entornos de tipo `runc`, simplemente porque son comunes y porque `runc` define la baseline que muchas personas imaginan cuando piensan en un container Linux. Por tanto, comprender `runc` proporciona al lector un modelo mental sólido sobre el container isolation clásico.

### `crun`

`crun` es otro runtime OCI, escrito en C y ampliamente utilizado en entornos modernos de Podman. A menudo se valora por su buen soporte de cgroup v2, sus buenas capacidades rootless y su menor overhead. Desde una perspectiva de security, lo importante no es que esté escrito en un lenguaje diferente, sino que sigue desempeñando el mismo papel: es el componente que convierte la configuración OCI en un process tree en ejecución bajo el kernel. Un workflow rootless de Podman suele parecer más seguro no porque `crun` solucione mágicamente todo, sino porque el stack general que lo rodea tiende a apoyarse más en user namespaces y least privilege.

### `runsc` From gVisor

`runsc` es el runtime utilizado por gVisor. Aquí el límite cambia de forma significativa. En lugar de pasar la mayoría de los syscalls directamente al host kernel de la forma habitual, gVisor introduce una capa de userspace kernel que emula o media grandes partes de la interfaz de Linux. El resultado no es un container `runc` normal con algunos flags adicionales; es un diseño de sandbox diferente cuyo objetivo es reducir la attack surface del host kernel. Los tradeoffs de compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que utilizan `runsc` deben documentarse de forma diferente a los entornos normales con OCI runtime.

### `kata-runtime`

Kata Containers llevan el límite aún más lejos al lanzar el workload dentro de una lightweight virtual machine. Administrativamente, esto todavía puede parecer un deployment de containers y las orchestration layers pueden seguir tratándolo como tal, pero el isolation boundary subyacente está más cerca de la virtualization que de un container clásico que comparte el host kernel. Esto hace que Kata sea útil cuando se desea un tenant isolation más fuerte sin abandonar los workflows centrados en containers.

## Engines And Container Managers

Si el runtime de bajo nivel es el componente que se comunica directamente con el kernel, el engine o manager es el componente con el que normalmente interactúan los usuarios y operadores. Gestiona image pulls, metadata, logs, networks, volumes, lifecycle operations y la exposición de APIs. Esta capa es extremadamente importante porque muchos compromisos del mundo real ocurren aquí: el acceso a un runtime socket o a la API de un daemon puede equivaler a un compromiso del host aunque el runtime de bajo nivel esté perfectamente sano.

### Docker Engine

Docker Engine es la container platform más reconocible para los developers y una de las razones por las que el vocabulario de containers adquirió una forma tan orientada a Docker. El flujo típico va de la CLI `docker` a `dockerd`, que a su vez coordina componentes de más bajo nivel como `containerd` y un OCI runtime. Históricamente, los deployments de Docker suelen haber sido **rootful**, por lo que el acceso al Docker socket ha sido un primitive muy poderoso. Por eso gran parte del material práctico sobre privilege escalation se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un privileged container, monte paths del host o se una a host namespaces, quizá no necesite un kernel exploit en absoluto.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Operativamente, esto ayuda a reforzar la idea de que los containers son simplemente procesos gestionados mediante mecanismos estándar de Linux, en lugar de hacerlo a través de un único daemon privilegiado de larga duración. Podman también ofrece una historia **rootless** mucho más sólida que los deployments clásicos de Docker con los que muchas personas aprendieron inicialmente. Esto no hace que Podman sea automáticamente seguro, pero cambia significativamente el risk profile por defecto, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de runtime management en muchos stacks modernos. Se utiliza bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona images y snapshots, y delega la creación final del proceso a un runtime de bajo nivel. Las conversaciones sobre security en containerd deben destacar que el acceso al socket de containerd o a la funcionalidad de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, aunque la interfaz y el workflow parezcan menos "developer friendly".

### CRI-O

CRI-O está más centrado que Docker Engine. En lugar de ser una developer platform de propósito general, está diseñado para implementar de forma limpia la Kubernetes Container Runtime Interface. Esto hace que sea especialmente común en distribuciones de Kubernetes y ecosistemas con un uso intensivo de SELinux, como OpenShift. Desde una perspectiva de security, este scope más reducido resulta útil porque disminuye el desorden conceptual: CRI-O forma claramente parte de la capa de "ejecutar containers para Kubernetes", en lugar de ser una plataforma para todo.

### Incus, LXD, And LXC

Los sistemas Incus/LXD/LXC merecen separarse de los application containers de estilo Docker porque a menudo se utilizan como **system containers**. Normalmente se espera que un system container se parezca más a una lightweight machine, con un userspace más completo, servicios de larga duración, una exposición más amplia de devices y una integración más extensa con el host. Los mecanismos de isolation siguen siendo primitives del kernel, pero las expectativas operativas son diferentes. Como resultado, las misconfigurations aquí suelen parecerse menos a "bad app-container defaults" y más a errores de lightweight virtualization o de host delegation.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es systemd-native y muy útil para testing, debugging y la ejecución de entornos similares a un OS. No es el runtime de producción dominante en entornos cloud-native, pero aparece con suficiente frecuencia en labs y entornos orientados a distros como para merecer una mención. Para el análisis de security, es otro recordatorio de que el concepto de "container" abarca múltiples ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de research y HPC. Sus trust assumptions, user workflow y execution model difieren de forma importante de los stacks centrados en Docker/Kubernetes. En particular, estos entornos suelen preocuparse mucho por permitir que los usuarios ejecuten workloads empaquetados sin otorgarles amplios poderes privilegiados de container management. Si un reviewer asume que todo container environment es básicamente "Docker en un server", entenderá muy mal estos deployments.

## Build-Time Tooling

Muchas conversaciones sobre security solo hablan del runtime, pero las build-time tools también importan porque determinan el contenido de las images, la exposición de build secrets y cuánto trusted context queda incorporado en el artifact final.

**BuildKit** y `docker buildx` son backends modernos de build que soportan funcionalidades como caching, secret mounting, SSH forwarding y multi-platform builds. Son features útiles, pero desde una perspectiva de security también crean lugares donde los secrets pueden hacer leak en las image layers o donde un build context demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** desempeña un papel similar en ecosistemas OCI-native, especialmente alrededor de Podman, mientras que **Kaniko** suele utilizarse en entornos de CI que no quieren conceder un Docker daemon privilegiado al build pipeline.

La lección clave es que la creación de images y la ejecución de images son fases diferentes, pero un build pipeline débil puede crear una runtime posture débil mucho antes de que se lance el container.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes no debe equipararse mentalmente con el runtime. Kubernetes es el orchestrator. Programa Pods, almacena el desired state y expresa security policy mediante la configuración de los workloads. Después, el kubelet se comunica con una implementación de CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación es importante porque muchas personas atribuyen erróneamente una protección a "Kubernetes" cuando en realidad la aplica el node runtime, o culpan a los "containerd defaults" de un comportamiento que procede de un Pod spec. En la práctica, la security posture final es una composición: el orchestrator solicita algo, el runtime stack lo traduce y el kernel finalmente lo aplica.

## Why Runtime Identification Matters During Assessment

Si identificas pronto el engine y el runtime, muchas observaciones posteriores resultan más fáciles de interpretar. Un container rootless de Podman sugiere que los user namespaces probablemente forman parte de la situación. Un Docker socket montado en un workload sugiere que la privilege escalation basada en APIs es un path realista. Un node de CRI-O/OpenShift debería hacerte pensar inmediatamente en SELinux labels y restricted workload policy. Un entorno gVisor o Kata debería hacerte ser más cauteloso al asumir que un breakout PoC clásico de `runc` se comportará de la misma forma.

Por eso, uno de los primeros pasos en un container assessment siempre debería ser responder a dos preguntas sencillas: **qué componente gestiona el container** y **qué runtime lanzó realmente el proceso**. Una vez claras esas respuestas, normalmente resulta mucho más fácil razonar sobre el resto del entorno.

## Runtime Vulnerabilities

No todos los container escapes proceden de una operator misconfiguration. A veces, el propio runtime es el componente vulnerable. Esto importa porque un workload puede estar ejecutándose con una configuración aparentemente cuidadosa y, aun así, estar expuesto a través de una low-level runtime flaw.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un malicious container podía sobrescribir el binario `runc` del host y esperar a que una invocación posterior de `docker exec` o similar activara código controlado por el attacker. El exploit path es muy diferente de un simple error de bind-mount o capabilities, porque abusa de la forma en que el runtime vuelve a entrar en el espacio de procesos del container durante el procesamiento de exec.

Un workflow de reproducción mínimo desde la perspectiva de un red-team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación exacta del exploit histórico, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinario dentro del contenedor puede ser suficiente para comprometer el host, incluso cuando la configuración visible del contenedor no parece evidentemente débil.

Los CVE recientes del runtime, como `CVE-2024-21626` en `runc`, las condiciones de carrera de montajes de BuildKit y los errores de análisis de containerd, refuerzan el mismo punto. La versión y el nivel de parches del runtime forman parte de la frontera de seguridad, no son simples detalles de mantenimiento.
{{#include ../../../banners/hacktricks-training.md}}
