# Seguridad de Contenedores

{{#include ../../../banners/hacktricks-training.md}}

## Qué Es Realmente Un Contenedor

Una forma práctica de definir un contenedor es la siguiente: un contenedor es un **árbol de procesos Linux normal** que se ha iniciado bajo una configuración específica de estilo OCI para que vea un sistema de archivos controlado, un conjunto controlado de recursos del kernel y un modelo de privilegios restringido. El proceso puede creer que es el PID 1, puede creer que tiene su propia pila de red, puede creer que controla su propio hostname y sus propios recursos IPC, e incluso puede ejecutarse como root dentro de su propio user namespace. Pero, internamente, sigue siendo un proceso del host que el kernel programa como cualquier otro.

Por eso, la seguridad de contenedores consiste realmente en estudiar cómo se construye esa ilusión y cómo falla. Si el mount namespace es débil, el proceso puede ver el sistema de archivos del host. Si el user namespace está ausente o deshabilitado, root dentro del contenedor puede mapearse demasiado directamente con root en el host. Si seccomp está unconfined y el conjunto de capabilities es demasiado amplio, el proceso puede acceder a syscalls y funciones privilegiadas del kernel que deberían haber quedado fuera de su alcance. Si el runtime socket está montado dentro del contenedor, puede que el contenedor ni siquiera necesite un kernel breakout, porque simplemente puede pedir al runtime que lance otro contenedor hermano con más privilegios o montar directamente el sistema de archivos raíz del host.

## En Qué Se Diferencian Los Contenedores De Las Máquinas Virtuales

Una VM normalmente incluye su propio kernel y una frontera de abstracción de hardware. Esto significa que el kernel guest puede fallar, entrar en panic o ser explotado sin que ello implique automáticamente el control directo del kernel del host. En los contenedores, el workload no obtiene un kernel separado. En su lugar, obtiene una vista cuidadosamente filtrada y aislada mediante namespaces del mismo kernel que utiliza el host. Como resultado, los contenedores suelen ser más ligeros, arrancan más rápido, permiten empaquetar más workloads en una máquina y son más adecuados para el despliegue de aplicaciones de corta duración. El precio es que la frontera de aislamiento depende mucho más directamente de una configuración correcta del host y del runtime.

Esto no significa que los contenedores sean "insecure" y las VM sean "secure". Significa que el modelo de seguridad es diferente. Un stack de contenedores bien configurado, con ejecución rootless, user namespaces, seccomp por defecto, un conjunto estricto de capabilities, sin compartir namespaces del host y con una aplicación estricta de SELinux o AppArmor puede ser muy robusto. Por el contrario, un contenedor iniciado con `--privileged`, compartiendo el PID/network del host, con el Docker socket montado dentro y con un bind mount escribible de `/` se acerca funcionalmente mucho más al acceso como root del host que a un application sandbox aislado de forma segura. La diferencia proviene de las capas que se habilitaron o deshabilitaron.

También existe un punto intermedio que los lectores deberían entender, porque aparece cada vez más en entornos reales. Los **sandboxed container runtimes**, como **gVisor** y **Kata Containers**, refuerzan intencionadamente la frontera más allá de un contenedor clásico de `runc`. gVisor coloca una capa de kernel en userspace entre el workload y muchas interfaces del kernel del host, mientras que Kata lanza el workload dentro de una máquina virtual ligera. Estos runtimes siguen utilizándose mediante ecosistemas de contenedores y workflows de orquestación, pero sus propiedades de seguridad difieren de las de los runtimes OCI normales y no deberían agruparse mentalmente con los "normal Docker containers" como si todo funcionara de la misma forma.

## El Stack De Contenedores: Varias Capas, No Una Sola

Cuando alguien dice "this container is insecure", la pregunta útil que debe hacerse a continuación es: **¿qué capa lo hizo insecure?** Un workload en un contenedor suele ser el resultado de varios componentes que trabajan conjuntamente.

En la parte superior suele haber una **capa de build de imágenes**, como BuildKit, Buildah o Kaniko, que crea la imagen OCI y sus metadatos. Por encima del runtime de bajo nivel puede existir un **engine o manager**, como Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. En entornos de cluster también puede haber un **orchestrator**, como Kubernetes, que decide la postura de seguridad solicitada mediante la configuración del workload. Finalmente, el **kernel** es el que realmente aplica namespaces, cgroups, seccomp y la política MAC.

Este modelo por capas es importante para entender los valores por defecto. Kubernetes puede solicitar una restricción, que luego se traduce mediante CRI a través de containerd o CRI-O, se convierte en una especificación OCI mediante el runtime wrapper y finalmente es aplicada por `runc`, `crun`, `runsc` u otro runtime contra el kernel. Cuando los valores por defecto difieren entre entornos, a menudo se debe a que una de estas capas cambió la configuración final. Por tanto, el mismo mecanismo puede aparecer en Docker o Podman como un flag de la CLI, en Kubernetes como un campo de Pod o `securityContext`, y en stacks de runtime de nivel inferior como una configuración OCI generada para el workload. Por esta razón, los ejemplos de CLI de esta sección deben interpretarse como **sintaxis específica del runtime para un concepto general de contenedor**, no como flags universales compatibles con todas las herramientas.

## La Verdadera Frontera De Seguridad De Los Contenedores

En la práctica, la seguridad de los contenedores proviene de **controles superpuestos**, no de un único control perfecto. Los namespaces aíslan la visibilidad. Los cgroups gobiernan y limitan el uso de recursos. Las capabilities reducen lo que un proceso aparentemente privilegiado puede hacer realmente. seccomp bloquea syscalls peligrosas antes de que lleguen al kernel. AppArmor y SELinux añaden Mandatory Access Control sobre las comprobaciones DAC normales. `no_new_privs`, las rutas de procfs masked y las rutas del sistema de solo lectura dificultan las cadenas habituales de abuso de privilegios y de proc/sys. El propio runtime también es importante, porque decide cómo se crean los mounts, sockets, labels y uniones a namespaces.

Por eso gran parte de la documentación sobre seguridad de contenedores parece repetitiva. La misma cadena de escape suele depender de varios mecanismos a la vez. Por ejemplo, un bind mount escribible del host es peligroso, pero se vuelve mucho peor si el contenedor también se ejecuta como root real en el host, tiene `CAP_SYS_ADMIN`, está unconfined por seccomp y no está restringido por SELinux o AppArmor. Del mismo modo, compartir el PID del host supone una exposición grave, pero resulta mucho más útil para un atacante cuando se combina con `CAP_SYS_PTRACE`, protecciones débiles de procfs o herramientas de entrada en namespaces como `nsenter`. Por tanto, la forma correcta de documentar el tema no consiste en repetir el mismo ataque en cada página, sino en explicar qué aporta cada capa a la frontera final.

## Cómo Leer Esta Sección

La sección está organizada desde los conceptos más generales hasta los más específicos.

Empieza con la visión general del runtime y del ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Después revisa los planos de control y las superficies de la supply chain que con frecuencia determinan si un atacante necesita siquiera un kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Después pasa al modelo de protección:

{{#ref}}
protections/
{{#endref}}

Las páginas sobre namespaces explican individualmente las primitivas de aislamiento del kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Las páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths y rutas del sistema de solo lectura explican los mecanismos que normalmente se superponen a los namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Una Buena Mentalidad Inicial Para La Enumeración

Al evaluar un target en contenedor, es mucho más útil formular un pequeño conjunto de preguntas técnicas precisas que saltar inmediatamente a PoCs famosas de escape. Primero, identifica el **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer o algo más especializado. Después identifica el **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` u otra implementación compatible con OCI. A continuación, comprueba si el entorno es **rootful o rootless**, si los **user namespaces** están activos, si se comparte algún **host namespace**, qué **capabilities** permanecen, si **seccomp** está habilitado, si una **política MAC** está realmente aplicándose, si existen **mounts o sockets peligrosos** y si el proceso puede interactuar con la API del container runtime.

Estas respuestas proporcionan mucha más información sobre la postura de seguridad real que el nombre de la base image. En muchas evaluaciones, puedes predecir la familia probable de breakout antes de leer un solo archivo de la aplicación, simplemente entendiendo la configuración final del contenedor.

## Cobertura

Esta sección cubre el material antiguo centrado en Docker, reorganizado en torno a contenedores: exposición del runtime y del daemon, authorization plugins, confianza en imágenes y build secrets, mounts sensibles del host, workloads distroless, privileged containers y las protecciones del kernel que normalmente se superponen a la ejecución de contenedores.
{{#include ../../../banners/hacktricks-training.md}}
