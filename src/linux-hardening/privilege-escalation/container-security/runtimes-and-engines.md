# Runtimes, Engines, Builders, And Sandboxes para contenedores

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de contenedores es que varios componentes completamente diferentes suelen colapsarse bajo la misma palabra. "Docker" puede referirse a un formato de imagen, una CLI, un daemon, un sistema de build, una pila de runtime, o simplemente a la idea de contenedores en general. Para el trabajo de seguridad, esa ambigüedad es un problema, porque diferentes capas son responsables de diferentes protecciones. Un breakout causado por un bind mount mal configurado no es lo mismo que un breakout causado por un bug del runtime de bajo nivel, y ninguno es lo mismo que un error de política de clúster en Kubernetes.

Esta página separa el ecosistema por rol para que el resto de la sección pueda hablar con precisión sobre dónde vive realmente una protección o una debilidad.

## OCI como el lenguaje común

Los stacks modernos de contenedores en Linux suelen interoperar porque hablan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe arrancar el proceso, incluyendo namespaces, mounts, cgroups y ajustes de seguridad. La **OCI Distribution Specification** estandariza cómo los registries exponen contenido.

Esto importa porque explica por qué una imagen de contenedor construida con una herramienta a menudo puede ser ejecutada con otra, y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar entre distintos productos: muchos de ellos están construyendo la misma configuración de runtime OCI y la entregan al mismo pequeño conjunto de runtimes.

## Runtimes OCI de bajo nivel

El runtime de bajo nivel es el componente que está más cercano al límite del kernel. Es la parte que realmente crea namespaces, escribe ajustes de cgroup, aplica capabilities y filtros seccomp, y finalmente hace `execve()` del proceso del contenedor. Cuando la gente discute sobre "aislamiento de contenedores" a nivel mecánico, esta es la capa de la que normalmente hablan, aunque no lo expresen explícitamente.

### `runc`

`runc` es el runtime OCI de referencia y sigue siendo la implementación más conocida. Se usa ampliamente bajo Docker, containerd y muchas implementaciones de Kubernetes. Mucho material público de investigación y explotación se dirige a entornos estilo `runc` simplemente porque son comunes y porque `runc` define la línea base que muchas personas imaginan cuando piensan en un contenedor Linux. Entender `runc` da por tanto al lector un modelo mental sólido para el aislamiento clásico de contenedores.

### `crun`

`crun` es otro runtime OCI, escrito en C y ampliamente usado en entornos modernos de Podman. A menudo se le elogia por su buen soporte de cgroup v2, fuerte ergonomía rootless y menor overhead. Desde la perspectiva de seguridad, lo importante no es que esté escrito en otro lenguaje, sino que sigue desempeñando el mismo papel: es el componente que convierte la configuración OCI en un árbol de procesos en ejecución bajo el kernel. Un flujo rootless de Podman frecuentemente acaba sintiéndose más seguro no porque `crun` arregle mágicamente todo, sino porque la pila alrededor tiende a inclinarse más hacia user namespaces y mínimo privilegio.

### `runsc` de gVisor

`runsc` es el runtime usado por gVisor. Aquí el límite cambia de forma significativa. En lugar de pasar la mayoría de las syscalls directamente al kernel host de la manera habitual, gVisor inserta una capa de kernel en userspace que emula o media gran parte de la interfaz de Linux. El resultado no es un contenedor `runc` normal con algunas banderas extra; es un diseño de sandbox diferente cuyo propósito es reducir la superficie de ataque del kernel host. Las compensaciones en compatibilidad y rendimiento son parte de ese diseño, por lo que los entornos que usan `runsc` deberían documentarse de forma distinta a los entornos normales de runtime OCI.

### `kata-runtime`

Kata Containers empujan el límite más lejos lanzando la carga de trabajo dentro de una máquina virtual ligera. Administrativamente, esto puede seguir pareciendo un despliegue de contenedores, y las capas de orquestación pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente está más cerca de la virtualización que de un contenedor clásico que comparte kernel con el host. Esto hace que Kata sea útil cuando se desea un aislamiento de tenant más fuerte sin abandonar los flujos de trabajo centrados en contenedores.

## Engines y gestores de contenedores

Si el runtime de bajo nivel es el componente que habla directamente con el kernel, el engine o manager es el componente con el que los usuarios y operadores suelen interactuar. Maneja pulls de imágenes, metadata, logs, redes, volúmenes, operaciones de ciclo de vida y exposición de API. Esta capa importa enormemente porque muchas compromisos del mundo real ocurren aquí: el acceso a un runtime socket o a una API de daemon puede ser equivalente a la compromisión del host incluso si el runtime de bajo nivel en sí está perfectamente sano.

### Docker Engine

Docker Engine es la plataforma de contenedores más reconocible para desarrolladores y una de las razones por las que el vocabulario de contenedores se volvió tan “Docker-shaped”. La ruta típica es la CLI `docker` hacia `dockerd`, que a su vez coordina componentes de más bajo nivel como `containerd` y un runtime OCI. Históricamente, los despliegues de Docker han sido a menudo **rootful**, y el acceso al socket de Docker ha sido por lo tanto una primitiva muy poderosa. Por eso tanto material práctico de escalada de privilegios se centra en `docker.sock`: si un proceso puede pedir a `dockerd` que cree un contenedor privilegiado, monte rutas del host o se una a namespaces del host, puede no necesitar un exploit del kernel en absoluto.

### Podman

Podman fue diseñado en torno a un modelo más sin daemon. Operativamente, esto ayuda a reforzar la idea de que los contenedores son simplemente procesos gestionados mediante mecanismos estándar de Linux en lugar de a través de un daemon privilegiado de larga vida. Podman también tiene una historia mucho más fuerte de **rootless** que los despliegues clásicos de Docker que mucha gente aprendió primero. Eso no hace a Podman automáticamente seguro, pero cambia significativamente el perfil de riesgo por defecto, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de gestión de runtimes en muchas stacks modernas. Se usa bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona imágenes y snapshots, y delega la creación final del proceso a un runtime de bajo nivel. Las discusiones de seguridad alrededor de containerd deberían enfatizar que el acceso al socket de containerd o a la funcionalidad de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, incluso si la interfaz y el flujo de trabajo parecen menos “amistosos para desarrolladores”.

### CRI-O

CRI-O está más enfocado que Docker Engine. En lugar de ser una plataforma de propósito general para desarrolladores, está construido alrededor de implementar de forma limpia la Kubernetes Container Runtime Interface. Esto lo hace especialmente común en distribuciones de Kubernetes y ecosistemas con fuerte uso de SELinux como OpenShift. Desde la perspectiva de seguridad, ese alcance más estrecho es útil porque reduce el desorden conceptual: CRI-O forma muy claramente parte de la capa “ejecutar contenedores para Kubernetes” en lugar de una plataforma que lo hace todo.

### Incus, LXD y LXC

Los sistemas Incus/LXD/LXC merecen separarse de los contenedores estilo Docker porque a menudo se usan como **system containers**. Un system container suele esperarse que se parezca más a una máquina ligera con un userspace más completo, servicios de larga ejecución, mayor exposición de dispositivos y una integración con el host más amplia. Los mecanismos de aislamiento siguen siendo primitivas del kernel, pero las expectativas operacionales son diferentes. Como resultado, las malas configuraciones aquí a menudo se parecen menos a “ajustes por defecto malos de app-containers” y más a errores en virtualización ligera o delegación del host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y muy útil para testing, debugging y ejecutar entornos tipo OS. No es el runtime dominante en producción cloud-native, pero aparece con suficiente frecuencia en laboratorios y entornos orientados a distribuciones como para merecer mención. Para el análisis de seguridad, es otro recordatorio de que el concepto “contenedor” abarca múltiples ecosistemas y estilos operacionales.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de investigación y HPC. Sus supuestos de confianza, flujo de trabajo de usuario y modelo de ejecución difieren de maneras importantes de las pilas centradas en Docker/Kubernetes. En particular, estos entornos a menudo se preocupan profundamente por permitir a los usuarios ejecutar workloads empaquetados sin darles amplios poderes de gestión de contenedores privilegiados. Si un revisor asume que todo entorno de contenedores es básicamente “Docker en un servidor”, entenderá mal gravemente estos despliegues.

## Herramientas en tiempo de build

Muchas discusiones de seguridad solo hablan sobre el tiempo de ejecución, pero las herramientas de build también importan porque determinan el contenido de la imagen, la exposición de secretos y cuánto contexto de confianza se incrusta en el artefacto final.

**BuildKit** y `docker buildx` son backends de build modernos que soportan características como caching, montaje de secretos, forwarding SSH y builds multi-plataforma. Esas son características útiles, pero desde la perspectiva de seguridad también crean lugares donde los secretos pueden leak en las capas de la imagen o donde un contexto de build demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** juega un papel similar en ecosistemas nativos OCI, especialmente alrededor de Podman, mientras que **Kaniko** se usa a menudo en CI que no quiere otorgar un daemon Docker privilegiado al pipeline de build.

La lección clave es que la creación de imágenes y la ejecución de imágenes son fases diferentes, pero una pipeline de build débil puede crear una postura de runtime débil mucho antes de que el contenedor sea lanzado.

## Orquestación es otra capa, no el runtime

Kubernetes no debe equipararse mentalmente con el runtime en sí. Kubernetes es el orquestador. Programa Pods, almacena estado deseado y expresa políticas de seguridad a través de la configuración de workloads. El kubelet luego habla con una implementación CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación importa porque mucha gente atribuye erróneamente una protección a "Kubernetes" cuando en realidad la aplica el runtime del nodo, o culpan a los "defaults de containerd" por un comportamiento que vino de una spec de Pod. En la práctica, la postura final de seguridad es una composición: el orquestador pide algo, la pila de runtime lo traduce y el kernel finalmente lo hace cumplir.

## Por qué identificar el runtime importa durante una evaluación

Si identificas el engine y el runtime temprano, muchas observaciones posteriores se vuelven más fáciles de interpretar. Un contenedor Podman rootless sugiere que user namespaces probablemente forman parte de la historia. Un socket de Docker montado dentro de una carga de trabajo sugiere que la escalada de privilegios basada en API es un camino realista. Un nodo CRI-O/OpenShift debería hacerte pensar inmediatamente en etiquetas SELinux y en políticas de workloads restringidas. Un entorno gVisor o Kata debería hacerte ser más cauteloso al asumir que un PoC clásico de breakout de `runc` se comportará igual.

Por eso uno de los primeros pasos en la evaluación de contenedores siempre debería ser responder dos preguntas sencillas: **qué componente está gestionando el contenedor** y **qué runtime lanzó realmente el proceso**. Una vez que esas respuestas estén claras, el resto del entorno suele volverse mucho más fácil de razonar.

## Vulnerabilidades en runtimes

No todo escape de contenedor proviene de una mala configuración del operador. A veces el propio runtime es el componente vulnerable. Esto importa porque una carga de trabajo puede estar ejecutándose con una configuración que parece cuidadosa y aun así estar expuesta por una falla de bajo nivel en el runtime.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un contenedor malicioso podía sobrescribir el binario `runc` del host y luego esperar a una posterior invocación de `docker exec` u otro manejo de exec del runtime para desencadenar código controlado por el atacante. La ruta de explotación es muy diferente a un simple error de bind-mount o de capabilities porque abusa de cómo el runtime reingresa en el espacio de proceso del contenedor durante el manejo de exec.

Un flujo mínimo de reproducción desde la perspectiva de red-team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación histórica exacta del exploit, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinaria in-container puede ser suficiente para comprometer el host incluso cuando la configuración visible del container no parezca abiertamente débil.

Recientes CVEs de runtime como `CVE-2024-21626` en `runc`, BuildKit mount races y containerd parsing bugs refuerzan el mismo punto. La versión del runtime y el nivel de parche son parte del límite de seguridad, no mera trivia de mantenimiento.
{{#include ../../../banners/hacktricks-training.md}}
