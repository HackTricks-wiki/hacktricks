# Runtimes, Engines, Builders, And Sandboxes de Contenedores

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de contenedores es que varios componentes completamente diferentes a menudo se colapsan en la misma palabra. "Docker" puede referirse a un formato de imagen, un CLI, un daemon, un sistema de build, una pila de runtime, o simplemente a la idea de contenedores en general. Para trabajo de seguridad, esa ambigüedad es un problema, porque capas distintas son responsables de protecciones diferentes. Un breakout causado por un mal bind mount no es lo mismo que un breakout causado por un bug de runtime de bajo nivel, y ninguno es lo mismo que un error de política de cluster en Kubernetes.

Esta página separa el ecosistema por rol para que el resto de la sección pueda hablar con precisión sobre dónde vive realmente una protección o una debilidad.

## OCI como lenguaje común

Los stacks modernos de contenedores en Linux a menudo interoperan porque hablan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe lanzar el proceso, incluyendo namespaces, mounts, cgroups y configuraciones de seguridad. La **OCI Distribution Specification** estandariza cómo los registries exponen contenido.

Esto importa porque explica por qué una imagen de contenedor construida con una herramienta puede a menudo ejecutarse con otra, y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar entre productos diferentes: muchos de ellos están construyendo la misma configuración de runtime OCI y entregándola al mismo pequeño conjunto de runtimes.

## Runtimes OCI de bajo nivel

El runtime de bajo nivel es el componente que está más cercano al límite del kernel. Es la parte que realmente crea namespaces, escribe configuraciones de cgroup, aplica capabilities y filtros seccomp, y finalmente `execve()` el proceso del contenedor. Cuando la gente discute "aislamiento de contenedores" a nivel mecánico, esta es la capa de la que suelen hablar, incluso si no lo dicen explícitamente.

### `runc`

`runc` es el runtime referencia de OCI y sigue siendo la implementación más conocida. Se usa ampliamente bajo Docker, containerd y muchas implementaciones de Kubernetes. Mucho material público de investigación y explotación apunta a entornos del estilo `runc` simplemente porque son comunes y porque `runc` define la línea base que mucha gente imagina cuando piensa en un contenedor Linux. Entender `runc` por lo tanto da al lector un modelo mental sólido para el aislamiento clásico de contenedores.

### `crun`

`crun` es otro runtime OCI, escrito en C y ampliamente usado en entornos modernos de Podman. A menudo se le alaba por buen soporte de cgroup v2, fuerte ergonomía rootless y menor overhead. Desde una perspectiva de seguridad, lo importante no es que esté escrito en un lenguaje diferente, sino que sigue desempeñando el mismo rol: es el componente que convierte la configuración OCI en un árbol de procesos en ejecución bajo el kernel. Un flujo de trabajo rootless de Podman frecuentemente acaba sintiéndose más seguro no porque `crun` arregle mágicamente todo, sino porque la pila alrededor tiende a inclinarse más hacia user namespaces y least privilege.

### `runsc` de gVisor

`runsc` es el runtime usado por gVisor. Aquí el límite cambia de forma significativa. En lugar de pasar la mayoría de las syscalls directamente al kernel del host de la manera habitual, gVisor inserta una capa de kernel en espacio de usuario que emula o media gran parte de la interfaz de Linux. El resultado no es un contenedor `runc` normal con algunas flags extra; es un diseño de sandbox diferente cuyo propósito es reducir la superficie de ataque del kernel del host. Las compensaciones en compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que usan `runsc` deberían documentarse de forma distinta a los entornos normales de runtime OCI.

### `kata-runtime`

Kata Containers empujan el límite más lejos lanzando la carga de trabajo dentro de una máquina virtual ligera. Administrativamente, esto puede seguir pareciendo un despliegue de contenedores, y las capas de orquestación pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente está más cerca de la virtualización que de un contenedor clásico que comparte kernel con el host. Esto hace a Kata útil cuando se desea un aislamiento de tenants más fuerte sin abandonar los flujos de trabajo centrados en contenedores.

## Engines y gestores de contenedores

Si el runtime de bajo nivel es el componente que habla directamente con el kernel, el engine o manager es el componente con el que normalmente interactúan usuarios y operadores. Maneja pulls de imágenes, metadata, logs, redes, volúmenes, operaciones de ciclo de vida y exposición de APIs. Esta capa importa enormemente porque muchas compromisos del mundo real ocurren aquí: el acceso a un socket del runtime o a una API de daemon puede ser equivalente a una compromisión del host incluso si el runtime de bajo nivel en sí está perfectamente sano.

### Docker Engine

Docker Engine es la plataforma de contenedores más reconocible para desarrolladores y una de las razones por las que el vocabulario de contenedores se volvió tan moldeado por Docker. La ruta típica es el CLI `docker` hacia `dockerd`, que a su vez coordina componentes de menor nivel como `containerd` y un runtime OCI. Históricamente, los despliegues de Docker han sido a menudo **rootful**, y el acceso al Docker socket por lo tanto ha sido un primitivo muy poderoso. Por eso tanto material práctico de escalada de privilegios se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un contenedor privilegiado, monte rutas del host o se una a namespaces del host, puede que no necesite un exploit de kernel en absoluto.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Operacionalmente, esto ayuda a reforzar la idea de que los contenedores son solo procesos gestionados mediante mecanismos estándar de Linux en lugar de a través de un daemon privilegiado de larga vida. Podman también tiene una historia **rootless** mucho más fuerte que los despliegues clásicos de Docker que mucha gente aprendió primero. Eso no hace a Podman automáticamente seguro, pero cambia significativamente el perfil de riesgo por defecto, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de gestión de runtime en muchas stacks modernas. Se usa bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona imágenes y snapshots, y delega la creación final de procesos a un runtime de bajo nivel. Las discusiones de seguridad alrededor de containerd deben enfatizar que el acceso al socket de containerd o a la funcionalidad de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, incluso si la interfaz y el flujo de trabajo se sienten menos "amigables para desarrolladores".

### CRI-O

CRI-O está más enfocado que Docker Engine. En lugar de ser una plataforma de propósito general para desarrolladores, está construido alrededor de implementar el Container Runtime Interface de Kubernetes limpiamente. Esto lo hace especialmente común en distribuciones de Kubernetes y ecosistemas con fuerte presencia de SELinux como OpenShift. Desde una perspectiva de seguridad, ese alcance más estrecho es útil porque reduce el desorden conceptual: CRI-O es parte de la capa "ejecutar contenedores para Kubernetes" más que una plataforma todo-en-uno.

### Incus, LXD y LXC

Los sistemas Incus/LXD/LXC valen la pena separarlos de los contenedores estilo Docker porque a menudo se usan como **system containers**. Un system container suele esperarse que se parezca más a una máquina ligera con un userspace más completo, servicios de larga duración, exposición de dispositivos más rica e integración con el host más extensa. Los mecanismos de aislamiento siguen siendo primitivas del kernel, pero las expectativas operacionales son diferentes. Como resultado, las malas configuraciones aquí suelen parecer menos "defaults malos de app-containers" y más errores en virtualización ligera o delegación del host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y muy útil para testing, debugging y ejecutar entornos tipo OS. No es el runtime dominante en producción cloud-native, pero aparece lo suficientemente a menudo en labs y entornos orientados a distribuciones como para merecer mención. Para el análisis de seguridad, es otro recordatorio de que el concepto "contenedor" abarca múltiples ecosistemas y estilos operacionales.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de investigación y HPC. Sus asunciones de confianza, workflow de usuario y modelo de ejecución difieren en formas importantes de los stacks centrados en Docker/Kubernetes. En particular, estos entornos a menudo se preocupan mucho por permitir a los usuarios ejecutar cargas empaquetadas sin darles amplios poderes de gestión de contenedores privilegiados. Si un revisor asume que cada entorno de contenedores es básicamente "Docker en un servidor", malinterpretará gravemente estos despliegues.

## Herramientas en tiempo de construcción

Muchas discusiones de seguridad solo hablan sobre runtime, pero las herramientas en tiempo de construcción también importan porque determinan el contenido de las imágenes, la exposición de build secrets y cuánto contexto de confianza se incrusta en el artefacto final.

**BuildKit** y `docker buildx` son backends modernos de build que soportan características como caching, secret mounting, SSH forwarding y builds multi-plataforma. Esas son características útiles, pero desde una perspectiva de seguridad también crean lugares donde secrets pueden leak into image layers o donde un contexto de build excesivamente amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** desempeña un rol similar en ecosistemas OCI-nativos, especialmente alrededor de Podman, mientras que **Kaniko** se usa a menudo en entornos CI que no quieren conceder un daemon Docker privilegiado al pipeline de build.

La lección clave es que la creación de la imagen y la ejecución de la imagen son fases diferentes, pero una pipeline de build débil puede crear una postura de runtime débil mucho antes de que el contenedor sea lanzado.

## Orquestación es otra capa, no el runtime

Kubernetes no debe equipararse mentalmente con el runtime en sí. Kubernetes es el orquestador. Programa Pods, almacena el estado deseado y expresa la política de seguridad a través de la configuración de workload. El kubelet entonces habla con una implementación CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación importa porque mucha gente atribuye erróneamente una protección a "Kubernetes" cuando en realidad la impone el runtime del nodo, o culpan "defaults de containerd" por un comportamiento que vino de un Pod spec. En la práctica, la postura final de seguridad es una composición: el orquestador pide algo, la pila de runtime lo traduce y el kernel finalmente lo hace cumplir.

## Por qué la identificación del runtime importa durante la evaluación

Si identificas el engine y el runtime temprano, muchas observaciones posteriores se vuelven más fáciles de interpretar. Un contenedor Podman rootless sugiere que los user namespaces probablemente forman parte de la historia. Un socket de Docker montado en una workload sugiere que la escalada de privilegios basada en API es un camino realista. Un nodo CRI-O/OpenShift debería hacerte pensar inmediatamente en etiquetas SELinux y política de workloads restringidas. Un entorno gVisor o Kata debería hacerte más cauteloso al asumir que un PoC clásico de breakout de `runc` se comportará igual.

Por eso uno de los primeros pasos en la evaluación de contenedores siempre debe ser responder dos preguntas simples: **¿qué componente está gestionando el contenedor?** y **¿qué runtime lanzó realmente el proceso?** Una vez que esas respuestas están claras, el resto del entorno normalmente se vuelve mucho más fácil de razonar.

## Vulnerabilidades de runtime

No todas las escapes de contenedor vienen de una mala configuración del operador. A veces el runtime en sí es el componente vulnerable. Esto importa porque una workload puede estar ejecutándose con lo que parece una configuración cuidadosa y aun así estar expuesta mediante un fallo de runtime de bajo nivel.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un contenedor malicioso podía sobreescribir el binario `runc` del host y luego esperar a una posterior invocación de `docker exec` o similar para disparar código controlado por el atacante. La ruta de explotación es muy diferente de un simple bind-mount o error de capabilities porque abusa de cómo el runtime reingresa en el espacio de proceso del contenedor durante el manejo de exec.

Un flujo mínimo de reproducción desde una perspectiva de red-team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación histórica exacta del exploit, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinaria in-container puede ser suficiente para comprometer el host incluso cuando la configuración visible del container no parezca claramente débil.

CVEs recientes del runtime, como `CVE-2024-21626` en `runc`, BuildKit mount races y parsing bugs de containerd refuerzan el mismo punto. La versión del runtime y el nivel de parches forman parte del límite de seguridad, no son meras trivialidades de mantenimiento.
{{#include ../../../banners/hacktricks-training.md}}
