# Runtimes, motores, herramientas de compilación y sandboxes de contenedores

{{#include ../../../banners/hacktricks-training.md}}

Una de las mayores fuentes de confusión en la seguridad de contenedores es que varios componentes completamente distintos suelen agruparse bajo una misma palabra. «Docker» puede referirse a un formato de imagen, una CLI, un daemon, un sistema de compilación, una pila de runtime o, simplemente, a la idea general de los contenedores. En el trabajo de seguridad, esa ambigüedad es un problema, porque las distintas capas son responsables de distintas protecciones. Un breakout causado por un bind mount mal configurado no es lo mismo que uno causado por un bug en el runtime de bajo nivel, y ninguno de los dos es lo mismo que un error en las políticas de clúster de Kubernetes.

Esta página separa el ecosistema por función para que el resto de la sección pueda describir con precisión dónde se encuentra realmente una protección o una debilidad.

## OCI como lenguaje común

Las pilas modernas de contenedores Linux suelen interoperar porque utilizan un conjunto de especificaciones de OCI. La **OCI Image Specification** describe cómo se representan las imágenes y las capas. La **OCI Runtime Specification** describe cómo debe iniciar el proceso el runtime, incluidos los namespaces, los mounts, los cgroups y la configuración de seguridad. La **OCI Distribution Specification** estandariza cómo los registries exponen el contenido.

Esto importa porque explica por qué a menudo se puede ejecutar con una herramienta una imagen de contenedor creada con otra, y por qué varios motores pueden compartir el mismo runtime de bajo nivel. También explica por qué el comportamiento de seguridad puede parecer similar en distintos productos: muchos construyen la misma configuración de runtime de OCI y se la entregan al mismo pequeño conjunto de runtimes.

## Runtimes de OCI de bajo nivel

El runtime de bajo nivel es el componente más cercano al límite del kernel. Es la parte que realmente crea namespaces, escribe la configuración de cgroups, aplica capabilities y filtros seccomp y, finalmente, ejecuta `execve()` para iniciar el proceso del contenedor. Cuando se habla de «aislamiento de contenedores» en términos mecánicos, normalmente se hace referencia a esta capa, aunque no se diga explícitamente.

### `runc`

`runc` es el runtime de referencia de OCI y sigue siendo la implementación más conocida. Se usa ampliamente con Docker, containerd y muchas implementaciones de Kubernetes. Gran parte de la investigación pública y del material sobre explotación apunta a entornos tipo `runc` simplemente porque son comunes y porque `runc` define el modelo de referencia que mucha gente imagina al pensar en un contenedor Linux. Por eso, entender `runc` proporciona al lector un sólido modelo mental del aislamiento clásico de contenedores.

### `crun`

`crun` es otro runtime de OCI, escrito en C y ampliamente utilizado en entornos modernos de Podman. Suele destacarse por su buen soporte de cgroups v2, su facilidad de uso en modo rootless y su menor sobrecarga. Desde una perspectiva de seguridad, lo importante no es que esté escrito en otro lenguaje, sino que cumple la misma función: convierte la configuración de OCI en un árbol de procesos en ejecución bajo el kernel. Un flujo de trabajo rootless de Podman suele parecer más seguro, no porque `crun` lo solucione todo mágicamente, sino porque la pila que lo rodea tiende a apoyarse más en user namespaces y en el principio de mínimo privilegio.

### `runsc` de gVisor

`runsc` es el runtime que utiliza gVisor. En este caso, el límite cambia de forma significativa. En lugar de pasar la mayoría de las llamadas al sistema directamente al kernel host de la forma habitual, gVisor introduce una capa de kernel en espacio de usuario que emula o media gran parte de la interfaz de Linux. El resultado no es un contenedor `runc` normal con unas cuantas flags adicionales, sino un diseño de sandbox distinto cuyo objetivo es reducir la superficie de ataque del kernel host. Las compensaciones entre compatibilidad y rendimiento forman parte de ese diseño, por lo que los entornos que utilizan `runsc` deben documentarse de manera distinta a los entornos con runtimes de OCI normales.

### `kata-runtime`

Kata Containers llevan el límite más lejos al ejecutar la carga de trabajo dentro de una máquina virtual ligera. Desde el punto de vista administrativo, puede seguir pareciendo una implementación de contenedores y las capas de orquestación pueden seguir tratándola como tal, pero el límite de aislamiento subyacente se acerca más a la virtualización que a un contenedor clásico que comparte el kernel host. Esto hace que Kata sea útil cuando se busca un aislamiento más fuerte entre tenants sin abandonar los flujos de trabajo centrados en contenedores.

## Motores y gestores de contenedores

Si el runtime de bajo nivel es el componente que se comunica directamente con el kernel, el motor o gestor es el componente con el que suelen interactuar los usuarios y operadores. Gestiona la descarga de imágenes, los metadatos, los logs, las redes, los volúmenes, las operaciones del ciclo de vida y la exposición de API. Esta capa es muy importante porque muchos compromisos reales ocurren aquí: acceder al socket de un runtime o a la API de un daemon puede equivaler a comprometer el host, aunque el runtime de bajo nivel funcione perfectamente.

### Docker Engine

Docker Engine es la plataforma de contenedores más reconocible para los desarrolladores y una de las razones por las que el vocabulario de contenedores adquirió una forma tan ligada a Docker. El flujo típico va de la CLI `docker` a `dockerd`, que a su vez coordina componentes de nivel inferior como `containerd` y un runtime de OCI. Históricamente, las implementaciones de Docker suelen haber sido **rootful**, por lo que el acceso al socket de Docker ha sido una primitiva muy poderosa. Por eso, gran parte del material práctico sobre escalada de privilegios se centra en `docker.sock`: si un proceso puede pedirle a `dockerd` que cree un contenedor privilegiado, monte rutas del host o se una a namespaces del host, quizá no necesite ningún exploit del kernel.

Compara los números de versión por sus componentes mayor, menor y de parche, en lugar de eliminar los puntos: `18.09.1` es anterior tanto a `18.09.2` como a `18.09.4`, a pesar de que el componente menor tenga un cero inicial. Las [notas de la versión 18.09 de Docker](https://docs.docker.com/engine/release-notes/18.09/) registran la corrección de `runc` incluida en 18.09.2 para CVE-2019-5736 y la corrección de build-reference para CVE-2019-13139 en 18.09.4. Estas versiones son pistas, no una prueba de que un exploit sea alcanzable. Las mismas notas de la versión advierten que el daemon, el cliente y el runtime se empaquetan por separado, así que comprueba el runtime instalado y los backports del proveedor junto con la versión del daemon; para explotar un problema de build-reference también se necesita acceso al flujo de trabajo de compilación afectado y una entrada controlada por el atacante.

### Podman

Podman se diseñó en torno a un modelo más libre de daemons. En la práctica, esto ayuda a reforzar la idea de que los contenedores son simplemente procesos gestionados mediante mecanismos estándar de Linux, en lugar de hacerlo a través de un único daemon privilegiado de larga duración. Podman también ofrece un soporte **rootless** mucho más sólido que las implementaciones clásicas de Docker que aprendieron a utilizar muchos usuarios. Esto no hace que Podman sea seguro automáticamente, pero cambia considerablemente el perfil de riesgo predeterminado, sobre todo cuando se combina con user namespaces, SELinux y `crun`.

### containerd

containerd es un componente central para la gestión de runtimes en muchas pilas modernas. Se utiliza con Docker y también es uno de los backends de runtime dominantes en Kubernetes. Expone API potentes, gestiona imágenes y snapshots, y delega la creación final de procesos a un runtime de bajo nivel. En los análisis de seguridad sobre containerd conviene destacar que el acceso al socket de containerd o a las funciones de `ctr`/`nerdctl` puede ser tan peligroso como el acceso a la API de Docker, aunque la interfaz y el flujo de trabajo parezcan menos «amigables para desarrolladores».

### CRI-O

CRI-O tiene un alcance más limitado que Docker Engine. En lugar de ser una plataforma de uso general para desarrolladores, está diseñado para implementar correctamente la Kubernetes Container Runtime Interface. Por eso es especialmente común en distribuciones de Kubernetes y ecosistemas que utilizan mucho SELinux, como OpenShift. Desde una perspectiva de seguridad, ese alcance más reducido resulta útil porque reduce la complejidad conceptual: CRI-O forma parte claramente de la capa que «ejecuta contenedores para Kubernetes», en lugar de ser una plataforma que lo hace todo.

Cuando un nodo de Kubernetes usa CRI-O, comprueba la **versión activa de CRI-O en el nodo** y si la identidad actual puede crear Pods en un namespace que se programa en ese nodo. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) permitía que valores sysctl de Pod manipulados cambiaran un parámetro del kernel host y condujeran a la ejecución como root en el host en las versiones afectadas. El aviso upstream enumera las versiones corregidas y las medidas de mitigación. Un `crio --version` local puede no detectar un runtime anidado dentro de Minikube u otro contenedor de nodo; un log de inicio de Minikube que se pueda leer puede dar una pista sobre la versión, pero es evidencia histórica, no una prueba del runtime activo ni de su estado de parcheado. Confirma el runtime real del nodo, la autorización para crear Pods, las reglas de admisión y los límites pertinentes de seccomp y user namespaces antes de considerar que esta escalada es alcanzable.

También existe una vía directa de revisión local de `pinns`: los [investigadores señalan que no se necesita Kubernetes para invocar el helper defectuoso](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Comprueba si la cuenta actual puede ejecutar un `pinns` propiedad de root y con setuid, si NoNewPrivs o un mount `nosuid` impiden esa transición y si la **compilación del helper** instalada carece de la corrección. El [aviso upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) enumera las versiones corregidas, pero la versión que muestra un daemon por sí sola no demuestra qué binario helper está instalado, y los backports de las distribuciones pueden cambiar la exposición. Un archivo setuid solo es un candidato; valida la procedencia del helper, la configuración y el comportamiento de los sysctl del host sin ejecutarlo durante el reconocimiento rutinario.

### Incus, LXD y LXC

Conviene distinguir los sistemas Incus/LXD/LXC de los contenedores de aplicaciones al estilo Docker porque suelen utilizarse como **contenedores de sistema**. Normalmente se espera que un contenedor de sistema se parezca más a una máquina ligera, con un userspace más completo, servicios de larga duración, una exposición más amplia de dispositivos y una integración más extensa con el host. Los mecanismos de aislamiento siguen siendo primitivas del kernel, pero las expectativas operativas son distintas. Por ello, las configuraciones incorrectas suelen parecerse menos a «valores predeterminados inadecuados para contenedores de aplicaciones» y más a errores de virtualización ligera o delegación del host.

### systemd-nspawn

systemd-nspawn ocupa un lugar interesante porque forma parte de systemd y resulta muy útil para probar, depurar y ejecutar entornos similares a sistemas operativos. No es el runtime de producción dominante en entornos cloud-native, pero aparece con suficiente frecuencia en laboratorios y entornos centrados en distribuciones como para mencionarlo. Para el análisis de seguridad, es otro recordatorio de que el concepto de «contenedor» abarca varios ecosistemas y estilos operativos.

### Apptainer / Singularity

Apptainer (antes Singularity) es común en entornos de investigación y HPC. Sus supuestos de confianza, flujos de trabajo de usuario y modelo de ejecución difieren de forma importante de las pilas centradas en Docker/Kubernetes. En particular, estos entornos suelen dar mucha importancia a permitir que los usuarios ejecuten cargas de trabajo empaquetadas sin concederles amplios privilegios de gestión de contenedores. Si un revisor da por hecho que todos los entornos de contenedores son básicamente «Docker en un servidor», entenderá muy mal estas implementaciones.

## Herramientas de compilación

Muchos análisis de seguridad solo hablan del runtime, pero las herramientas de compilación también importan porque determinan el contenido de las imágenes, la exposición de secretos durante la compilación y cuánto contexto de confianza se incorpora al artefacto final.

**BuildKit** y `docker buildx` son backends de compilación modernos que admiten funciones como el caching, el montaje de secretos, el reenvío de SSH y las compilaciones multiplataforma. Son funciones útiles, pero desde una perspectiva de seguridad también crean situaciones en las que los secretos pueden filtrarse a las capas de la imagen o en las que un contexto de compilación demasiado amplio puede exponer archivos que nunca deberían haberse incluido. **Buildah** cumple una función similar en los ecosistemas nativos de OCI, especialmente con Podman, mientras que **Kaniko** suele utilizarse en entornos de CI que no quieren conceder un daemon de Docker privilegiado al pipeline de compilación.

La lección clave es que la creación y la ejecución de imágenes son fases distintas, pero un pipeline de compilación débil puede generar una postura de seguridad de runtime débil mucho antes de que se inicie el contenedor.

## La orquestación es otra capa, no el runtime

No debe equipararse mentalmente Kubernetes con el runtime. Kubernetes es el orquestador. Programa Pods, almacena el estado deseado y define políticas de seguridad mediante la configuración de las cargas de trabajo. A continuación, kubelet se comunica con una implementación de CRI como containerd o CRI-O, que a su vez invoca un runtime de bajo nivel como `runc`, `crun`, `runsc` o `kata-runtime`.

Esta separación importa porque muchas personas atribuyen erróneamente una protección a «Kubernetes» cuando en realidad la aplica el runtime del nodo, o culpan a los «valores predeterminados de containerd» de un comportamiento que proviene de una especificación de Pod. En la práctica, la postura de seguridad final es el resultado de una composición: el orquestador solicita algo, la pila de runtime lo traduce y, finalmente, el kernel lo aplica.

## Por qué importa identificar el runtime durante una evaluación

Si identificas pronto el motor y el runtime, será más fácil interpretar muchas observaciones posteriores. Un contenedor rootless de Podman sugiere que probablemente intervengan user namespaces. Un socket de Docker montado en una carga de trabajo sugiere que la escalada de privilegios mediante API es una vía realista. Un nodo CRI-O/OpenShift debería hacerte pensar de inmediato en las etiquetas de SELinux y las políticas de cargas de trabajo restringidas. Un entorno con gVisor o Kata debería hacerte ser más prudente al suponer que un PoC clásico de breakout de `runc` se comportará igual.

Por eso, uno de los primeros pasos en una evaluación de contenedores debería ser responder siempre a dos preguntas sencillas: **qué componente gestiona el contenedor** y **qué runtime inició realmente el proceso**. Una vez que tengas claras las respuestas, normalmente será mucho más fácil razonar sobre el resto del entorno.

## Vulnerabilidades de runtime

No todos los escapes de contenedores se deben a una mala configuración del operador. A veces, el componente vulnerable es el propio runtime. Esto importa porque una carga de trabajo puede ejecutarse con lo que parece una configuración cuidadosa y aun así estar expuesta por un fallo en un runtime de bajo nivel.

El ejemplo clásico es **CVE-2019-5736** en `runc`, donde un contenedor malicioso podía sobrescribir el binario `runc` del host y esperar a que una invocación posterior de `docker exec` u otra operación similar del runtime ejecutara código controlado por el atacante. La vía de explotación es muy distinta de un simple error de bind mount o de capabilities, porque aprovecha la forma en que el runtime vuelve a entrar en el espacio de procesos del contenedor al gestionar la ejecución.<sup>[[1]](#references)</sup>

Un flujo de trabajo mínimo de reproducción desde la perspectiva de un red team es:

```bash
go build main.go
./main
```

Luego, desde el host:

```bash
docker exec -it <container-name> /bin/sh
```

La lección clave no es la implementación exacta del exploit histórico, sino su implicación para la evaluación: si la versión del runtime es vulnerable, la ejecución de código corriente dentro del contenedor puede bastar para comprometer el host, incluso cuando la configuración visible del contenedor no parece claramente débil.

CVE recientes de runtimes, como `CVE-2024-21626` en `runc`, las carreras en los montajes de BuildKit y los errores de análisis de containerd refuerzan el mismo punto. La versión y el nivel de parches del runtime forman parte del límite de seguridad; no son meros detalles de mantenimiento.

## References

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
