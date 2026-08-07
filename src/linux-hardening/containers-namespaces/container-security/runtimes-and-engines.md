# Runtimes, Engines, Builders Y Sandboxes De Contenedores

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de contenedores es que varios componentes completamente diferentes suelen agruparse bajo la misma palabra. "Docker" puede referirse a un formato de imagen, una CLI, un daemon, un sistema de build, una pila de runtime o simplemente a la idea general de los contenedores. En trabajos de seguridad, esa ambigüedad es un problema, porque distintas capas son responsables de diferentes protecciones. Un breakout causado por un bind mount incorrecto no es lo mismo que uno causado por un bug en un runtime de bajo nivel, y ninguno de los dos es lo mismo que un error de política del clúster en Kubernetes.

Esta página separa el ecosistema por función para que el resto de la sección pueda describir con precisión dónde se encuentra realmente una protección o debilidad.

## OCI Como Lenguaje Común

Las pilas modernas de contenedores Linux suelen interoperar porque utilizan un conjunto de especificaciones OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo el runtime debe iniciar el proceso, incluidos los namespaces, mounts, cgroups y la configuración de seguridad. La **OCI Distribution Specification** estandariza cómo los registries exponen el contenido.

Esto es importante porque explica por qué una imagen de contenedor creada con una herramienta a menudo puede ejecutarse con otra, y por qué varios engines pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar en distintos productos: muchos de ellos construyen la misma configuración de runtime OCI y se la entregan al mismo pequeño conjunto de runtimes.

## Runtimes OCI De Bajo Nivel

El runtime de bajo nivel es el componente más cercano al límite con el kernel. Es la parte que realmente crea namespaces, escribe la configuración de los cgroups, aplica capabilities y filtros de seccomp y, finalmente, ejecuta `execve()` sobre el proceso del contenedor. Cuando se habla de "aislamiento de contenedores" a nivel mecánico, normalmente se está hablando de esta capa, aunque no se diga explícitamente.

### `runc`

`runc` es el runtime OCI de referencia y sigue siendo la implementación más conocida. Se utiliza ampliamente bajo Docker, containerd y muchas implementaciones de Kubernetes. Gran parte de la investigación pública y del material de exploitation se dirige a entornos de tipo `runc`, simplemente porque son comunes y porque `runc` define la base que muchas personas imaginan cuando piensan en un contenedor Linux. Por tanto, entender `runc` proporciona al lector un modelo mental sólido del aislamiento clásico de contenedores.

### `crun`

`crun` es otro runtime OCI, escrito en C y ampliamente utilizado en entornos modernos de Podman. A menudo se valora por su buen soporte para cgroup v2, su sólida ergonomía rootless y su menor overhead. Desde una perspectiva de seguridad, lo importante no es que esté escrito en un lenguaje diferente, sino que sigue desempeñando el mismo papel: es el componente que convierte la configuración OCI en un árbol de procesos en ejecución bajo el kernel. Un workflow rootless de Podman a menudo termina pareciendo más seguro, no porque `crun` solucione mágicamente todo, sino porque la pila general que lo rodea tiende a apoyarse más en user namespaces y least privilege.

### `runsc` De gVisor

`runsc` es el runtime utilizado por gVisor. En este caso, el límite cambia de forma significativa. En lugar de pasar la mayoría de las syscalls directamente al kernel del host de la forma habitual, gVisor inserta una capa de kernel en userspace que emula o media grandes partes de la interfaz de Linux. El resultado no es un contenedor `runc` normal con algunos flags adicionales; es un diseño de sandbox diferente cuyo objetivo es reducir la attack surface del kernel del host. Los compromisos entre compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que utilizan `runsc` deben documentarse de forma diferente a los entornos normales de runtime OCI.

### `kata-runtime`

Kata Containers llevan el límite aún más lejos al iniciar el workload dentro de una máquina virtual ligera. Desde el punto de vista administrativo, esto puede seguir pareciendo un deployment de contenedores y las capas de orchestration pueden seguir tratándolo como tal, pero el límite de aislamiento subyacente se acerca más a la virtualización que a un contenedor clásico que comparte el kernel del host. Esto hace que Kata sea útil cuando se desea un aislamiento más fuerte entre tenants sin abandonar los workflows centrados en contenedores.

## Engines Y Container Managers

Si el runtime de bajo nivel es el componente que se comunica directamente con el kernel, el engine o manager es el componente con el que normalmente interactúan los usuarios y operadores. Gestiona pulls de imágenes, metadata, logs, redes, volúmenes, operaciones del ciclo de vida y exposición de APIs. Esta capa es muy importante porque muchos compromisos reales ocurren aquí: el acceso a un runtime socket o a la API de un daemon puede equivaler al compromiso del host, incluso si el runtime de bajo nivel funciona perfectamente.

### Docker Engine

Docker Engine es la plataforma de contenedores más reconocible para los desarrolladores y una de las razones por las que el vocabulario de contenedores adquirió una forma tan asociada a Docker. El flujo típico es de la CLI `docker` a `dockerd`, que a su vez coordina componentes de bajo nivel como `containerd` y un runtime OCI. Históricamente, los deployments de Docker han sido a menudo **rootful**, por lo que el acceso al socket de Docker se ha convertido en una primitiva muy potente. Por eso gran parte del material práctico sobre privilege escalation se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un contenedor privilegiado, monte rutas del host o se una a namespaces del host, quizá no necesite ningún kernel exploit.

### Podman

Podman fue diseñado alrededor de un modelo más daemonless. Operativamente, esto ayuda a reforzar la idea de que los contenedores son simplemente procesos gestionados mediante mecanismos estándar de Linux, en lugar de hacerlo a través de un daemon privilegiado de larga duración. Podman también ofrece una historia **rootless** mucho más sólida que los deployments clásicos de Docker con los que muchas personas comenzaron a trabajar. Esto no hace que Podman sea automáticamente seguro, pero cambia significativamente el perfil de riesgo predeterminado, especialmente cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central de gestión de runtimes en muchas pilas modernas. Se utiliza bajo Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone APIs potentes, gestiona imágenes y snapshots y delega la creación final del proceso a un runtime de bajo nivel. Las conversaciones sobre seguridad de containerd deben destacar que el acceso al socket de containerd o a las funcionalidades de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, aunque la interfaz y el workflow parezcan menos "developer friendly".

### CRI-O

CRI-O tiene un enfoque más limitado que Docker Engine. En lugar de ser una plataforma de propósito general para desarrolladores, está diseñado para implementar correctamente la Kubernetes Container Runtime Interface. Esto lo hace especialmente común en distribuciones de Kubernetes y ecosistemas centrados en SELinux, como OpenShift. Desde una perspectiva de seguridad, ese alcance más reducido es útil porque disminuye el desorden conceptual: CRI-O forma claramente parte de la capa de "ejecutar contenedores para Kubernetes", en lugar de ser una plataforma para todo.

### Incus, LXD Y LXC

Los sistemas Incus/LXD/LXC deben separarse de los application containers de estilo Docker porque a menudo se utilizan como **system containers**. Normalmente se espera que un system container se parezca más a una máquina ligera con un userspace más completo, servicios de larga duración, una exposición más amplia de dispositivos y una integración más extensa con el host. Los mecanismos de aislamiento siguen siendo primitivas del kernel, pero las expectativas operativas son diferentes. Como resultado, las misconfigurations aquí suelen parecerse menos a "defaults incorrectos de app-containers" y más a errores de lightweight virtualization o de delegación del host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque es nativo de systemd y resulta muy útil para testing, debugging y ejecución de entornos similares a un sistema operativo. No es el runtime de producción dominante en cloud-native, pero aparece con suficiente frecuencia en labs y entornos orientados a distribuciones como para merecer una mención. Para el análisis de seguridad, es otro recordatorio de que el concepto de "contenedor" abarca múltiples ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) es común en entornos de investigación y HPC. Sus trust assumptions, workflow de usuario y modelo de ejecución difieren de forma importante de las pilas centradas en Docker/Kubernetes. En particular, estos entornos suelen preocuparse mucho por permitir que los usuarios ejecuten workloads empaquetados sin concederles amplios privilegios de gestión de contenedores. Si un reviewer asume que todo entorno de contenedores es básicamente "Docker en un servidor", interpretará muy mal estos deployments.

## Build-Time Tooling

Muchas conversaciones sobre seguridad solo hablan del runtime, pero el build-time tooling también importa porque determina el contenido de las imágenes, la exposición de build secrets y cuánto contexto de confianza queda incorporado en el artifact final.

**BuildKit** y `docker buildx` son backends de build modernos que admiten funciones como caching, secret mounting, SSH forwarding y builds multiplataforma. Son funciones útiles, pero desde una perspectiva de seguridad también crean lugares donde los secrets pueden hacer leak hacia las image layers o donde un build context demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** desempeña un papel similar en los ecosistemas nativos de OCI, especialmente junto a Podman, mientras que **Kaniko** se utiliza a menudo en entornos de CI que no quieren conceder un Docker daemon privilegiado al build pipeline.

La lección clave es que la creación de imágenes y la ejecución de imágenes son fases diferentes, pero un build pipeline débil puede crear una postura de runtime débil mucho antes de que se inicie el contenedor.

## La Orchestration Es Otra Capa, No El Runtime

Kubernetes no debe equipararse mentalmente con el runtime. Kubernetes es el orchestrator. Programa Pods, almacena el estado deseado y expresa la política de seguridad mediante la configuración de los workloads. Después, el kubelet se comunica con una implementación de CRI, como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación es importante porque muchas personas atribuyen erróneamente una protección a "Kubernetes" cuando en realidad la aplica el runtime del nodo, o culpan a los "defaults de containerd" por un comportamiento que procede de un Pod spec. En la práctica, la postura de seguridad final es una composición: el orchestrator solicita algo, la pila de runtime lo traduce y el kernel finalmente lo aplica.

## Por Qué Importa Identificar El Runtime Durante Un Assessment

Si identificas pronto el engine y el runtime, muchas observaciones posteriores resultan más fáciles de interpretar. Un contenedor rootless de Podman sugiere que los user namespaces probablemente forman parte de la situación. Un Docker socket montado en un workload sugiere que la privilege escalation mediante API es una ruta realista. Un nodo de CRI-O/OpenShift debería hacerte pensar inmediatamente en los labels de SELinux y en la restricted workload policy. Un entorno gVisor o Kata debería hacerte ser más prudente al asumir que un breakout PoC clásico de `runc` se comportará de la misma forma.

Por eso, uno de los primeros pasos de un container assessment siempre debería ser responder a dos preguntas sencillas: **qué componente gestiona el contenedor** y **qué runtime inició realmente el proceso**. Una vez claras esas respuestas, el resto del entorno normalmente resulta mucho más fácil de analizar.

## Vulnerabilidades Del Runtime

No todos los container escapes se deben a una misconfiguration del operador. En ocasiones, el propio runtime es el componente vulnerable. Esto importa porque un workload puede estar ejecutándose con una configuración aparentemente cuidadosa y aun así estar expuesto a través de un fallo en un runtime de bajo nivel.

El ejemplo clásico es **CVE-2019-5736** en `runc`, mediante el cual un contenedor malicioso podía sobrescribir el binario `runc` del host y esperar a que una invocación posterior de `docker exec` o similar activara código controlado por el atacante. La ruta de exploitation es muy diferente de un simple error de bind mount o de capabilities, porque abusa de la forma en que el runtime vuelve a entrar en el process space del contenedor durante la gestión de exec.<sup>[[1]](#references)</sup>

Un workflow de reproducción mínimo desde la perspectiva de un red team es:
```bash
go build main.go
./main
```
Luego, desde el host:
```bash
docker exec -it <container-name> /bin/sh
```
La lección clave no es la implementación exacta del exploit histórico, sino la implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código ordinaria dentro del contenedor puede ser suficiente para comprometer el host, incluso cuando la configuración visible del contenedor no parece manifiestamente débil.

Las CVE recientes de runtimes, como `CVE-2024-21626` en `runc`, las condiciones de carrera de montajes de BuildKit y los errores de análisis de containerd refuerzan el mismo punto. La versión del runtime y su nivel de parcheado forman parte del límite de seguridad, no son simplemente detalles de mantenimiento.

## Referencias

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
