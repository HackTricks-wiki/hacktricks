# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de contenedores es que varios componentes completamente distintos a menudo se agrupan bajo la misma palabra. "Docker" puede referirse a un formato de imagen, un CLI, un daemon, un sistema de build, una pila de runtime, o simplemente a la idea de contenedores en general. Para trabajo de seguridad, esa ambigüedad es un problema, porque distintas capas son responsables de distintas protecciones. Un breakout causado por un bind mount mal configurado no es lo mismo que un breakout causado por un bug de bajo nivel en el runtime, y ninguno de los dos es lo mismo que un error de política de clúster en Kubernetes.

Esta página separa el ecosistema por rol para que el resto de la sección pueda hablar con precisión sobre dónde vive realmente una protección o una debilidad.

## OCI As The Common Language

Los stacks modernos de contenedores en Linux a menudo interoperan porque hablan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe lanzar el proceso, incluyendo namespaces, mounts, cgroups y configuraciones de seguridad. La **OCI Distribution Specification** estandariza cómo los registries exponen contenido.

Esto importa porque explica por qué una imagen construida con una herramienta a menudo puede ejecutarse con otra, y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar entre distintos productos: muchos de ellos están construyendo la misma configuración de runtime OCI y se la entregan al mismo pequeño conjunto de runtimes.

## Low-Level OCI Runtimes

El runtime de bajo nivel es el componente más cercano al límite con el kernel. Es la parte que realmente crea namespaces, escribe configuraciones de cgroup, aplica capabilities y seccomp filters, y finalmente `execve()` el proceso del contenedor. Cuando la gente discute sobre "aislamiento de contenedores" a nivel mecánico, esta es la capa de la que suelen hablar, aunque no lo digan explícitamente.

### `runc`

`runc` es el runtime de referencia OCI y sigue siendo la implementación más conocida. Se usa ampliamente bajo Docker, containerd y muchas implementaciones de Kubernetes. Mucho material público de investigación y explotación apunta a entornos estilo `runc` simplemente porque son comunes y porque `runc` define la línea base que mucha gente tiene en mente cuando imagina un contenedor Linux. Entender `runc` da por tanto al lector un modelo mental sólido para el aislamiento clásico de contenedores.

### `crun`

`crun` es otro runtime OCI, escrito en C y muy usado en entornos modernos de Podman. A menudo se le elogia por su buen soporte de cgroup v2, fuertes ergonomías rootless y menor overhead. Desde una perspectiva de seguridad, lo importante no es que esté escrito en un lenguaje diferente, sino que sigue desempeñando el mismo rol: es el componente que convierte la configuración OCI en un árbol de procesos en ejecución bajo el kernel. Un flujo rootless de Podman con frecuencia se siente más seguro no porque `crun` arregle todo mágicamente, sino porque la pila alrededor tiende a apoyarse más en user namespaces y el principio de menor privilegio.

### `runsc` From gVisor

`runsc` es el runtime usado por gVisor. Aquí el límite cambia de forma significativa. En lugar de pasar la mayoría de las syscalls directamente al kernel host de la manera habitual, gVisor inserta una capa de kernel en espacio de usuario que emula o media grandes partes de la interfaz de Linux. El resultado no es un contenedor `runc` normal con algunos flags extra; es un diseño de sandbox distinto cuyo propósito es reducir la superficie de ataque del kernel host. Las compensaciones en compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que usan `runsc` deben documentarse de forma diferente a los entornos normales de runtime OCI.

### `kata-runtime`

Kata Containers lleva el límite más allá al lanzar la carga de trabajo dentro de una máquina virtual ligera. Administrativamente, esto puede seguir pareciendo un despliegue de contenedores, y las capas de orquestación pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente está más cerca de la virtualización que de un contenedor clásico que comparte kernel con el host. Esto hace a Kata útil cuando se desea un aislamiento más fuerte entre tenants sin abandonar los flujos de trabajo centrados en contenedores.

## Engines And Container Managers

Si el runtime de bajo nivel es el componente que habla directamente con el kernel, el engine o manager es el componente con el que los usuarios y operadores suelen interactuar. Maneja pulls de imágenes, metadata, logs, redes, volúmenes, operaciones de lifecycle y exposición de APIs. Esta capa importa enormemente porque muchas compromisos del mundo real ocurren aquí: el acceso a un socket de runtime o a una API de daemon puede equivaler a un compromiso del host aunque el runtime de bajo nivel esté perfectamente sano.

### Docker Engine

Docker Engine es la plataforma de contenedores más reconocible para desarrolladores y una de las razones por las que el vocabulario de contenedores tomó tanta forma Docker. La ruta típica es el CLI `docker` hacia `dockerd`, que a su vez coordina componentes de más bajo nivel como `containerd` y un runtime OCI. Históricamente, los despliegues de Docker han sido a menudo **rootful**, y el acceso al Docker socket ha sido por tanto una primitiva muy poderosa. Por eso tanto material práctico de escalada de privilegios se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` crear un contenedor privilegiado, montar rutas del host o unirse a namespaces del host, puede que ni siquiera necesite un exploit de kernel.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Operativamente, esto ayuda a reforzar la idea de que los contenedores son solo procesos gestionados mediante mecanismos estándar de Linux en lugar de mediante un daemon privilegiado de larga vida. Podman también tiene una historia **rootless** mucho más fuerte que los despliegues clásicos de Docker que mucha gente aprendió primero. Eso no hace a Podman automáticamente seguro, pero cambia el perfil de riesgo por defecto de manera significativa, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de gestión de runtime en muchas stacks modernas. Se usa bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona imágenes y snapshots, y delega la creación final del proceso a un runtime de bajo nivel. Las discusiones de seguridad alrededor de containerd deben enfatizar que el acceso al socket de containerd o a la funcionalidad de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, incluso si la interfaz y el flujo de trabajo parecen menos "amigables para desarrolladores".

### CRI-O

CRI-O está más enfocado que Docker Engine. En lugar de ser una plataforma de propósito general para desarrolladores, está construido alrededor de implementar la Container Runtime Interface de Kubernetes de forma limpia. Esto lo hace especialmente común en distribuciones de Kubernetes y ecosistemas con fuerte uso de SELinux como OpenShift. Desde una perspectiva de seguridad, ese alcance más estrecho es útil porque reduce el desorden conceptual: CRI-O es muy parte de la capa "ejecutar contenedores para Kubernetes" en lugar de una plataforma para todo.

### Incus, LXD, And LXC

Los sistemas Incus/LXD/LXC merecen separarse de los contenedores estilo Docker porque a menudo se usan como **system containers**. Un system container suele esperarse que se parezca más a una máquina ligera con un userspace más completo, servicios de larga duración, exposición de dispositivos más rica e integración con el host más extensa. Los mecanismos de aislamiento siguen siendo primitivos del kernel, pero las expectativas operativas son diferentes. Como resultado, las malas configuraciones aquí a menudo se parecen menos a "malos defaults de app-container" y más a errores en virtualización ligera o delegación de host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y muy útil para testing, debugging y ejecutar entornos tipo OS. No es el runtime dominante en producción cloud-native, pero aparece con suficiente frecuencia en labs y entornos orientados a distribuciones como para merecer mención. Para análisis de seguridad, es otro recordatorio de que el concepto "contenedor" abarca múltiples ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (antes Singularity) es común en entornos de investigación y HPC. Sus supuestos de confianza, flujo de trabajo de usuario y modelo de ejecución difieren en formas importantes de las stacks centradas en Docker/Kubernetes. En particular, estos entornos a menudo se preocupan mucho por permitir que los usuarios ejecuten cargas empaquetadas sin darles amplios poderes de gestión privilegiada de contenedores. Si un revisor asume que todo entorno de contenedores es básicamente "Docker en un servidor", va a malinterpretar gravemente estos despliegues.

## Build-Time Tooling

Muchas discusiones de seguridad solo hablan sobre el tiempo de ejecución, pero el tooling de build también importa porque determina el contenido de la imagen, la exposición de build secrets y cuánto contexto confiable se incrusta en el artefacto final.

**BuildKit** y `docker buildx` son backends de build modernos que soportan características como caching, secret mounting, SSH forwarding y builds multi-plataforma. Esas son características útiles, pero desde una perspectiva de seguridad también crean lugares donde secrets pueden leak en capas de imagen o donde un contexto de build demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** juega un papel similar en ecosistemas OCI-native, especialmente alrededor de Podman, mientras que **Kaniko** se usa a menudo en CI que no quiere dar un daemon Docker privilegiado al pipeline de build.

La lección clave es que la creación de imágenes y la ejecución de imágenes son fases diferentes, pero una pipeline de build débil puede crear una postura de runtime débil mucho antes de que el contenedor se lance.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes no debe equipararse mentalmente con el runtime en sí. Kubernetes es el orquestador. Programa Pods, almacena el estado deseado y expresa políticas de seguridad mediante la configuración de workload. El kubelet luego habla con una implementación CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación importa porque mucha gente atribuye erróneamente una protección a "Kubernetes" cuando en realidad la aplica el runtime del nodo, o culpan a "containerd defaults" por un comportamiento que vino de un spec de Pod. En la práctica, la postura final de seguridad es una composición: el orquestador pide algo, la pila de runtime lo traduce y el kernel finalmente lo hace cumplir.

## Why Runtime Identification Matters During Assessment

Si identificas el engine y el runtime temprano, muchas observaciones posteriores son más fáciles de interpretar. Un contenedor Podman rootless sugiere que user namespaces probablemente forman parte de la historia. Un socket de Docker montado dentro de una workload sugiere que la escalada de privilegios vía API es una vía realista. Un nodo CRI-O/OpenShift debería inmediatamente hacerte pensar en SELinux labels y políticas de workload restringidas. Un entorno gVisor o Kata debería hacerte más cauteloso al asumir que un PoC clásico de breakout de `runc` se comportará igual.

Por eso uno de los primeros pasos en una evaluación de contenedores siempre debe ser responder dos preguntas simples: **qué componente está gestionando el contenedor** y **qué runtime lanzó realmente el proceso**. Una vez que esas respuestas están claras, el resto del entorno suele ser mucho más fácil de razonar.

## Runtime Vulnerabilities

No todos los escapes de contenedor provienen de una mala configuración del operador. A veces el runtime en sí es el componente vulnerable. Esto importa porque una workload puede estar corriendo con una configuración que parece cuidadosa y aun así exponerse a través de un fallo de runtime de bajo nivel.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un contenedor malicioso podía sobrescribir el binario `runc` del host y luego esperar a una posterior invocación `docker exec` o similar para desencadenar código controlado por el atacante. La ruta de explotación es muy diferente de un simple bind-mount o un error de capabilities porque abusa de cómo el runtime reingresa al espacio de procesos del contenedor durante el manejo de exec.

Un workflow de reproducción mínimo desde la perspectiva de un red-team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación exacta del exploit histórico, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución ordinaria de código dentro del contenedor puede ser suficiente para comprometer el host incluso cuando la configuración visible del contenedor no parezca abiertamente débil.

CVE recientes del runtime como `CVE-2024-21626` en `runc`, BuildKit mount races y containerd parsing bugs refuerzan el mismo punto. La versión del runtime y el nivel de parches son parte del perímetro de seguridad, no simplemente detalles de mantenimiento.
