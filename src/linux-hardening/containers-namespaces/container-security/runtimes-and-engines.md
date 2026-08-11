# Runtimes, Engines, Builders Y Sandboxes De Contenedores

Una de las mayores fuentes de confusión en container security es que varios componentes completamente diferentes suelen agruparse bajo la misma palabra. "Docker" puede referirse a un formato de imagen, una CLI, un daemon, un sistema de build, un runtime stack o simplemente a la idea general de los contenedores. Para el trabajo de seguridad, esa ambigüedad es un problema, porque las distintas capas son responsables de diferentes protecciones. Un breakout causado por un bind mount incorrecto no es lo mismo que un breakout causado por un bug del runtime de bajo nivel, y ninguno de los dos es igual que un error de política del cluster en Kubernetes.

Esta página separa el ecosistema por función para que el resto de la sección pueda indicar con precisión dónde reside realmente una protección o una debilidad.

## OCI Como Lenguaje Común

Los container stacks modernos de Linux suelen interoperar porque hablan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe iniciar el proceso, incluidos namespaces, mounts, cgroups y security settings. La **OCI Distribution Specification** estandariza cómo los registries exponen el contenido.

Esto es importante porque explica por qué una container image creada con una herramienta a menudo puede ejecutarse con otra y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar entre distintos productos: muchos de ellos construyen la misma configuración de runtime de OCI y se la entregan al mismo pequeño conjunto de runtimes.

## Runtimes OCI De Bajo Nivel

El runtime de bajo nivel es el componente más cercano al límite con el kernel. Es la parte que realmente crea namespaces, escribe la configuración de los cgroups, aplica capabilities y filtros seccomp y finalmente ejecuta `execve()` sobre el proceso del contenedor. Cuando se habla de "container isolation" a nivel mecánico, normalmente se hace referencia a esta capa, aunque no se diga explícitamente.

### `runc`

`runc` es el runtime OCI de referencia y sigue siendo la implementación más conocida. Se utiliza ampliamente bajo Docker, containerd y muchas implementaciones de Kubernetes. Gran parte del material público de research y exploitation está dirigido a entornos tipo `runc`, simplemente porque son comunes y porque `runc` define la base que muchas personas imaginan cuando piensan en un contenedor Linux. Por ello, comprender `runc` proporciona un sólido modelo mental de la container isolation clásica.

### `crun`

`crun` es otro runtime OCI, escrito en C y ampliamente utilizado en entornos modernos de Podman. A menudo se valora por su buen soporte de cgroup v2, una buena ergonomía rootless y un menor overhead. Desde la perspectiva de seguridad, lo importante no es que esté escrito en otro lenguaje, sino que desempeña el mismo papel: es el componente que convierte la configuración OCI en un árbol de procesos en ejecución bajo el kernel. Un flujo de trabajo rootless de Podman suele parecer más seguro, no porque `crun` solucione mágicamente todos los problemas, sino porque el stack general que lo rodea suele apoyarse más en user namespaces y least privilege.

### `runsc` De gVisor

`runsc` es el runtime utilizado por gVisor. Aquí el límite cambia de manera significativa. En lugar de pasar la mayoría de las syscalls directamente al kernel del host de la forma habitual, gVisor inserta una capa de kernel en userspace que emula o media gran parte de la interfaz de Linux. El resultado no es un contenedor `runc` normal con algunos flags adicionales; es un diseño de sandbox diferente cuyo objetivo es reducir la attack surface del kernel del host. Los compromisos de compatibilidad y rendimiento forman parte de este diseño, por lo que los entornos que usan `runsc` deben documentarse de forma diferente a los entornos normales de runtime OCI.

### `kata-runtime`

Kata Containers llevan el límite un paso más allá al ejecutar el workload dentro de una lightweight virtual machine. Administrativamente, esto puede seguir pareciendo un deployment de contenedores, y las capas de orchestration pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente está más cerca de la virtualización que de un contenedor clásico que comparte el kernel del host. Esto hace que Kata sea útil cuando se desea un aislamiento más fuerte entre tenants sin abandonar los workflows centrados en contenedores.

## Engines Y Container Managers

Si el runtime de bajo nivel es el componente que se comunica directamente con el kernel, el engine o manager es el componente con el que normalmente interactúan los usuarios y operadores. Gestiona image pulls, metadata, logs, networks, volumes, operaciones de lifecycle y exposición de APIs. Esta capa es extremadamente importante porque muchos compromisos reales ocurren aquí: el acceso a un runtime socket o a la daemon API puede equivaler al compromiso del host aunque el runtime de bajo nivel esté perfectamente sano.

### Docker Engine

Docker Engine es la container platform más reconocible para los developers y una de las razones por las que el vocabulario de los contenedores adquirió una forma tan marcada por Docker. El flujo típico es la CLI `docker` hacia `dockerd`, que a su vez coordina componentes de bajo nivel como `containerd` y un runtime OCI. Históricamente, los deployments de Docker a menudo han sido **rootful**, por lo que el acceso al Docker socket se ha convertido en una primitive muy poderosa. Por eso gran parte del material práctico de privilege escalation se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un contenedor privilegiado, monte paths del host o se una a los namespaces del host, quizá no necesite ningún kernel exploit.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Operativamente, esto ayuda a reforzar la idea de que los contenedores son simplemente procesos gestionados mediante mecanismos estándar de Linux, en lugar de hacerlo a través de un daemon privilegiado de larga duración. Podman también ofrece una historia **rootless** mucho más sólida que los deployments clásicos de Docker con los que muchas personas comenzaron. Esto no hace que Podman sea automáticamente seguro, pero cambia significativamente el perfil de riesgo predeterminado, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de gestión de runtimes en muchos stacks modernos. Se utiliza bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona images y snapshots y delega la creación final del proceso a un runtime de bajo nivel. Las conversaciones sobre seguridad en containerd deben destacar que el acceso al socket de containerd o a las funcionalidades de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, aunque la interfaz y el workflow parezcan menos "developer friendly".

### CRI-O

CRI-O tiene un enfoque más específico que Docker Engine. En lugar de ser una plataforma de propósito general para developers, está diseñado para implementar de forma limpia la Container Runtime Interface de Kubernetes. Esto lo hace especialmente común en distribuciones de Kubernetes y ecosistemas con un uso intensivo de SELinux, como OpenShift. Desde la perspectiva de seguridad, ese alcance más reducido resulta útil porque disminuye la confusión conceptual: CRI-O forma claramente parte de la capa de "ejecutar contenedores para Kubernetes", en lugar de ser una plataforma para todo.

### Incus, LXD Y LXC

Los sistemas Incus/LXD/LXC merecen separarse de los application containers al estilo Docker porque a menudo se utilizan como **system containers**. Normalmente se espera que un system container se parezca más a una máquina ligera, con un userspace más completo, servicios de larga duración, una exposición más amplia de dispositivos y una integración más extensa con el host. Los mecanismos de aislamiento siguen siendo primitives del kernel, pero las expectativas operativas son diferentes. Por ello, las misconfigurations aquí suelen parecerse menos a "bad app-container defaults" y más a errores de lightweight virtualization o de delegación al host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y resulta muy útil para testing, debugging y la ejecución de entornos similares a un sistema operativo. No es el runtime dominante en producción cloud-native, pero aparece con suficiente frecuencia en labs y entornos orientados a distribuciones como para merecer una mención. Para el análisis de seguridad, es otro recordatorio de que el concepto de "container" abarca múltiples ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de research y HPC. Sus trust assumptions, user workflow y execution model difieren de forma importante de los stacks centrados en Docker/Kubernetes. En particular, estos entornos suelen preocuparse mucho por permitir que los usuarios ejecuten workloads empaquetados sin otorgarles amplios privilegios de gestión de contenedores. Si un reviewer asume que todo entorno de contenedores es básicamente "Docker en un servidor", entenderá muy mal estos deployments.

## Build-Time Tooling

Muchas conversaciones sobre seguridad solo hablan del runtime, pero el build-time tooling también importa porque determina el contenido de las imágenes, la exposición de build secrets y cuánto contexto de confianza se incorpora al artefacto final.

**BuildKit** y `docker buildx` son backends de build modernos que admiten funciones como caching, secret mounting, SSH forwarding y builds multi-platform. Son funciones útiles, pero desde la perspectiva de seguridad también crean lugares donde los secrets pueden filtrarse a las image layers o donde un build context demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** desempeña un papel similar en los ecosistemas nativos de OCI, especialmente alrededor de Podman, mientras que **Kaniko** se utiliza a menudo en entornos de CI que no quieren conceder un Docker daemon privilegiado al build pipeline.

La lección clave es que la creación y la ejecución de imágenes son fases diferentes, pero un build pipeline débil puede crear una postura de runtime débil mucho antes de que se inicie el contenedor.

## La Orchestration Es Otra Capa, No El Runtime

Kubernetes no debe equipararse mentalmente con el runtime. Kubernetes es el orchestrator. Programa Pods, almacena el estado deseado y expresa la security policy mediante la configuración de los workloads. A continuación, el kubelet se comunica con una implementación de CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación es importante porque muchas personas atribuyen erróneamente una protección a "Kubernetes" cuando en realidad la aplica el runtime del nodo, o culpan a los "containerd defaults" de un comportamiento que procede de un Pod spec. En la práctica, la postura de seguridad final es una composición: el orchestrator solicita algo, el runtime stack lo traduce y finalmente el kernel lo aplica.

## Por Qué Importa Identificar El Runtime Durante Un Assessment

Si identificas pronto el engine y el runtime, muchas observaciones posteriores resultan más fáciles de interpretar. Un contenedor rootless de Podman sugiere que los user namespaces probablemente forman parte de la situación. Un Docker socket montado en un workload sugiere que la privilege escalation basada en API es un path realista. Un nodo CRI-O/OpenShift debería hacerte pensar inmediatamente en los labels de SELinux y en la restricted workload policy. Un entorno gVisor o Kata debería hacerte ser más cauteloso al asumir que una classic `runc` breakout PoC se comportará de la misma manera.

Por eso, uno de los primeros pasos en un container assessment siempre debería ser responder a dos preguntas simples: **qué componente gestiona el contenedor** y **qué runtime inició realmente el proceso**. Una vez claras esas respuestas, el resto del entorno suele ser mucho más fácil de analizar.

## Runtime Vulnerabilities

No todos los container escapes proceden de una misconfiguration del operador. A veces, el propio runtime es el componente vulnerable. Esto importa porque un workload puede estar ejecutándose con una configuración aparentemente cuidadosa y aun así estar expuesto debido a un fallo del runtime de bajo nivel.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un contenedor malicioso podía sobrescribir el binario `runc` del host y esperar a que una invocación posterior de `docker exec` o de un runtime similar activara código controlado por el atacante. El exploit path es muy diferente de un simple error de bind mount o capabilities, porque abusa de la forma en que el runtime vuelve a entrar en el espacio de procesos del contenedor durante el procesamiento de exec.<sup>[[1]](#references)</sup>

Un workflow de reproducción mínima desde la perspectiva de un red team es:
```bash
go build main.go
./main
```
A continuación, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación exacta del exploit histórico, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinaria dentro del contenedor puede bastar para comprometer el host, incluso cuando la configuración visible del contenedor no parece evidentemente débil.

Los CVE recientes del runtime, como `CVE-2024-21626` en `runc`, las condiciones de carrera de montajes de BuildKit y los errores de análisis de containerd, refuerzan el mismo punto. La versión del runtime y el nivel de parches forman parte del límite de seguridad, no son simples detalles de mantenimiento.

## References

- [1] [Salir de Docker mediante runC – Explicación de CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
