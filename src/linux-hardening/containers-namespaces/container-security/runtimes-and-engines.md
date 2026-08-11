# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de los containers es que varios componentes completamente diferentes suelen agruparse bajo la misma palabra. "Docker" puede referirse a un formato de imagen, una CLI, un daemon, un sistema de build, una runtime stack o simplemente a la idea general de los containers. Para el trabajo de seguridad, esta ambigüedad es un problema, porque las distintas capas son responsables de diferentes protecciones. Un breakout causado por un bind mount incorrecto no es lo mismo que un breakout causado por un bug en el runtime de bajo nivel, y ninguno de los dos es lo mismo que un error de política del cluster en Kubernetes.

Esta página separa el ecosistema por función para que el resto de la sección pueda explicar con precisión dónde reside realmente una protección o una debilidad.

## OCI As The Common Language

Las container stacks modernas de Linux suelen interoperar porque hablan un conjunto de especificaciones de OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe iniciar el proceso, incluidos los namespaces, mounts, cgroups y security settings. La **OCI Distribution Specification** estandariza cómo los registries exponen el contenido.

Esto es importante porque explica por qué una container image creada con una herramienta a menudo puede ejecutarse con otra, y por qué varios engines pueden compartir el mismo low-level runtime. También explica por qué el comportamiento de seguridad puede parecer similar entre distintos productos: muchos de ellos construyen la misma configuración de OCI runtime y se la entregan al mismo pequeño conjunto de runtimes.

## Low-Level OCI Runtimes

El low-level runtime es el componente más cercano al límite con el kernel. Es la parte que realmente crea namespaces, escribe la configuración de los cgroups, aplica capabilities y filtros de seccomp y, finalmente, ejecuta `execve()` sobre el proceso del container. Cuando se habla de "container isolation" a nivel mecánico, normalmente se está hablando de esta capa, aunque no se diga explícitamente.

### `runc`

`runc` es el OCI runtime de referencia y sigue siendo la implementación más conocida. Se utiliza ampliamente bajo Docker, containerd y muchos deployments de Kubernetes. Gran parte de la investigación pública y del material de exploitation se dirige a entornos basados en `runc` simplemente porque son comunes y porque `runc` define la base que muchas personas imaginan cuando piensan en un Linux container. Por ello, comprender `runc` proporciona al lector un modelo mental sólido de la container isolation clásica.

### `crun`

`crun` es otro OCI runtime, escrito en C y ampliamente utilizado en entornos modernos de Podman. A menudo se valora por su buen soporte de cgroup v2, su sólida rootless ergonomics y su menor overhead. Desde una perspectiva de seguridad, lo importante no es que esté escrito en otro lenguaje, sino que sigue desempeñando la misma función: es el componente que convierte la configuración de OCI en un process tree en ejecución bajo el kernel. Un workflow rootless de Podman suele terminar pareciendo más seguro, no porque `crun` solucione mágicamente todo, sino porque la stack general que lo rodea tiende a apoyarse más en user namespaces y least privilege.

### `runsc` From gVisor

`runsc` es el runtime utilizado por gVisor. Aquí el límite cambia de forma significativa. En lugar de pasar la mayoría de los syscalls directamente al host kernel de la forma habitual, gVisor inserta una userspace kernel layer que emula o media gran parte de la interfaz de Linux. El resultado no es un container normal de `runc` con unos cuantos flags adicionales; es un diseño de sandbox diferente cuyo objetivo es reducir la attack surface del host kernel. Los compromisos de compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que utilizan `runsc` deben documentarse de forma diferente a los entornos normales basados en OCI runtime.

### `kata-runtime`

Kata Containers llevan el límite aún más lejos al ejecutar el workload dentro de una lightweight virtual machine. Desde el punto de vista administrativo, esto puede seguir pareciendo un container deployment, y las orchestration layers pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente se acerca más a la virtualización que a un container clásico que comparte el host kernel. Esto hace que Kata sea útil cuando se desea un tenant isolation más fuerte sin abandonar los workflows centrados en containers.

## Engines And Container Managers

Si el low-level runtime es el componente que se comunica directamente con el kernel, el engine o manager es el componente con el que normalmente interactúan los usuarios y operadores. Gestiona image pulls, metadata, logs, networks, volumes, lifecycle operations y API exposure. Esta capa es extremadamente importante porque muchos compromisos reales ocurren aquí: el acceso a un runtime socket o daemon API puede equivaler al compromiso del host incluso si el low-level runtime funciona perfectamente.

### Docker Engine

Docker Engine es la container platform más reconocible para los developers y una de las razones por las que el vocabulario de los containers adquirió una forma tan orientada a Docker. El recorrido típico es `docker` CLI hacia `dockerd`, que a su vez coordina componentes de nivel inferior como `containerd` y un OCI runtime. Históricamente, los deployments de Docker a menudo han sido **rootful**, por lo que el acceso al Docker socket ha constituido un primitive muy potente. Por eso gran parte del material práctico sobre privilege escalation se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un privileged container, monte host paths o se una a host namespaces, quizá no necesite ningún kernel exploit.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Desde el punto de vista operativo, esto ayuda a reforzar la idea de que los containers son simplemente procesos gestionados mediante mecanismos estándar de Linux, en lugar de hacerlo a través de un privileged daemon de larga duración. Podman también ofrece una historia **rootless** mucho más sólida que los deployments clásicos de Docker con los que muchas personas aprendieron inicialmente. Esto no hace que Podman sea automáticamente seguro, pero cambia significativamente el risk profile predeterminado, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de runtime management en muchas stacks modernas. Se utiliza bajo Docker y también es uno de los backends de runtime dominantes de Kubernetes. Expone APIs potentes, gestiona images y snapshots y delega la creación final del proceso a un low-level runtime. Las conversaciones sobre la seguridad de containerd deben enfatizar que el acceso al containerd socket o a la funcionalidad de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, aunque la interfaz y el workflow parezcan menos "developer friendly".

### CRI-O

CRI-O está más enfocado que Docker Engine. En lugar de ser una developer platform de propósito general, está diseñado para implementar de forma limpia la Kubernetes Container Runtime Interface. Esto hace que sea especialmente común en Kubernetes distributions y ecosistemas con mucho uso de SELinux, como OpenShift. Desde una perspectiva de seguridad, este alcance más limitado resulta útil porque reduce el desorden conceptual: CRI-O forma claramente parte de la capa de "ejecutar containers para Kubernetes", en lugar de ser una plataforma que lo abarca todo.

### Incus, LXD, And LXC

Los sistemas Incus/LXD/LXC deben separarse de los application containers de estilo Docker porque suelen utilizarse como **system containers**. Normalmente se espera que un system container se parezca más a una máquina ligera, con un userspace más completo, servicios de larga duración, una exposición más amplia de dispositivos y una integración más extensa con el host. Los mecanismos de aislamiento siguen siendo primitives del kernel, pero las expectativas operativas son diferentes. Como resultado, las misconfigurations aquí suelen parecerse menos a "bad app-container defaults" y más a errores de lightweight virtualization o de host delegation.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y muy útil para testing, debugging y la ejecución de entornos parecidos a un sistema operativo. No es el production runtime dominante en cloud-native, pero aparece con suficiente frecuencia en labs y entornos orientados a distros como para merecer una mención. Para el análisis de seguridad, es otro recordatorio de que el concepto de "container" abarca múltiples ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de investigación y HPC. Sus trust assumptions, user workflow y execution model difieren de forma importante de las stacks centradas en Docker/Kubernetes. En particular, estos entornos suelen preocuparse mucho por permitir que los usuarios ejecuten workloads empaquetados sin otorgarles amplios privilegios de container management. Si un reviewer asume que todo entorno de containers es básicamente "Docker en un server", comprenderá muy mal estos deployments.

## Build-Time Tooling

Muchas conversaciones sobre seguridad solo hablan del runtime, pero el build-time tooling también importa porque determina el contenido de las imágenes, la exposición de build secrets y cuánto contexto confiable queda integrado en el artifact final.

**BuildKit** y `docker buildx` son modern build backends que admiten funcionalidades como caching, secret mounting, SSH forwarding y multi-platform builds. Son funcionalidades útiles, pero desde una perspectiva de seguridad también crean lugares donde los secrets pueden hacer leak en las image layers o donde un build context demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** desempeña una función similar en los ecosistemas nativos de OCI, especialmente alrededor de Podman, mientras que **Kaniko** se utiliza a menudo en entornos de CI que no quieren conceder un privileged Docker daemon al build pipeline.

La lección clave es que la creación de imágenes y la ejecución de imágenes son fases diferentes, pero un build pipeline débil puede crear una postura de runtime débil mucho antes de que se inicie el container.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes no debe equipararse mentalmente con el runtime. Kubernetes es el orchestrator. Programa Pods, almacena el estado deseado y expresa la security policy mediante la workload configuration. El kubelet se comunica entonces con una implementación de CRI como containerd o CRI-O, que a su vez invoca un low-level runtime como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación es importante porque muchas personas atribuyen erróneamente una protección a "Kubernetes" cuando en realidad la aplica el node runtime, o culpan a los "containerd defaults" por un comportamiento que procede de un Pod spec. En la práctica, la postura de seguridad final es una composición: el orchestrator solicita algo, la runtime stack lo traduce y el kernel finalmente lo aplica.

## Why Runtime Identification Matters During Assessment

Si identificas el engine y el runtime al principio, muchas observaciones posteriores resultan más fáciles de interpretar. Un rootless Podman container sugiere que los user namespaces probablemente forman parte de la situación. Un Docker socket montado dentro de un workload sugiere que la privilege escalation basada en API es un camino realista. Un nodo de CRI-O/OpenShift debería hacerte pensar inmediatamente en SELinux labels y restricted workload policy. Un entorno de gVisor o Kata debería hacerte ser más cauteloso al asumir que un classic `runc` breakout PoC se comportará de la misma forma.

Por eso, uno de los primeros pasos en el container assessment siempre debería ser responder a dos preguntas sencillas: **qué componente gestiona el container** y **qué runtime inició realmente el proceso**. Una vez claras esas respuestas, normalmente resulta mucho más fácil razonar sobre el resto del entorno.

## Runtime Vulnerabilities

No todos los container escapes proceden de una operator misconfiguration. A veces el propio runtime es el componente vulnerable. Esto importa porque un workload puede ejecutarse con una configuración aparentemente cuidadosa y, aun así, estar expuesto a través de un low-level runtime flaw.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un malicious container podía sobrescribir el binario `runc` del host y esperar después a que una invocación posterior de `docker exec` o de un runtime similar activara código controlado por el atacante. La ruta de exploitation es muy diferente de un simple error de bind-mount o de capabilities, porque abusa de la forma en que el runtime vuelve a entrar en el espacio de procesos del container durante el manejo de exec.<sup>[[1]](#references)</sup>

Un flujo de reproducción mínimo desde la perspectiva de un red-team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación exacta del exploit histórico, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinaria dentro del contenedor puede ser suficiente para comprometer el host, incluso cuando la configuración visible del contenedor no parece evidentemente débil.

Los CVE recientes de runtimes, como `CVE-2024-21626` en `runc`, las condiciones de carrera de montaje de BuildKit y los errores de análisis de containerd, refuerzan el mismo punto. La versión y el nivel de parches del runtime forman parte del límite de seguridad, no son simplemente detalles de mantenimiento.

## References

- [1] [Escapando de Docker mediante runC: explicación de CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
