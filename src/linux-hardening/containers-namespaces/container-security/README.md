# Seguridad de Contenedores

{{#include ../../../banners/hacktricks-training.md}}

## Qué Es Realmente Un Contenedor

Una forma práctica de definir un contenedor es la siguiente: un contenedor es un **árbol de procesos Linux normal** que se ha iniciado bajo una configuración específica de estilo OCI para que vea un sistema de archivos controlado, un conjunto controlado de recursos del kernel y un modelo de privilegios restringido. El proceso puede creer que es el PID 1, puede creer que tiene su propia pila de red, puede creer que posee su propio hostname y sus propios recursos IPC, e incluso puede ejecutarse como root dentro de su propio user namespace. Pero, internamente, sigue siendo un proceso del host que el kernel planifica como cualquier otro.

Por eso, la seguridad de los contenedores consiste realmente en estudiar cómo se construye esa ilusión y cómo falla. Si el mount namespace es débil, el proceso puede ver el sistema de archivos del host. Si el user namespace está ausente o deshabilitado, root dentro del contenedor puede corresponderse demasiado directamente con root en el host. Si seccomp está sin restricciones y el conjunto de capabilities es demasiado amplio, el proceso puede acceder a syscalls y funciones privilegiadas del kernel que deberían haber permanecido fuera de su alcance. Si el runtime socket está montado dentro del contenedor, puede que el contenedor ni siquiera necesite un kernel breakout, porque simplemente puede pedirle al runtime que lance otro contenedor sibling más potente o que monte directamente el sistema de archivos raíz del host.

## En Qué Se Diferencian Los Contenedores De Las Máquinas Virtuales

Una VM normalmente incluye su propio kernel y una frontera de abstracción de hardware. Esto significa que el kernel guest puede bloquearse, entrar en pánico o ser explotado sin implicar automáticamente un control directo del kernel del host. En los contenedores, el workload no obtiene un kernel separado. En su lugar, obtiene una vista cuidadosamente filtrada y aislada mediante namespaces del mismo kernel que utiliza el host. Como resultado, los contenedores suelen ser más ligeros, iniciar más rápido, ser más fáciles de empaquetar densamente en una máquina y adaptarse mejor al despliegue de aplicaciones de corta duración. El precio es que la frontera de aislamiento depende mucho más directamente de una configuración correcta del host y del runtime.

Esto no significa que los contenedores sean "inseguros" y las VMs sean "seguras". Significa que el modelo de seguridad es diferente. Un stack de contenedores bien configurado, con ejecución rootless, user namespaces, seccomp predeterminado, un conjunto estricto de capabilities, sin compartir namespaces del host y con una aplicación sólida de SELinux o AppArmor, puede ser muy robusto. Por el contrario, un contenedor iniciado con `--privileged`, compartiendo los namespaces PID y de red del host, con el Docker socket montado dentro y con un bind mount escribible de `/`, está funcionalmente mucho más cerca del acceso root al host que de un sandbox de aplicación aislado de forma segura. La diferencia proviene de las capas que se habilitaron o deshabilitaron.

También existe un punto intermedio que los lectores deberían entender, porque aparece cada vez más en entornos reales. Los **sandboxed container runtimes**, como **gVisor** y **Kata Containers**, refuerzan intencionadamente la frontera más allá de un contenedor clásico de `runc`. gVisor coloca una capa de kernel en userspace entre el workload y muchas interfaces del kernel del host, mientras que Kata lanza el workload dentro de una máquina virtual ligera. Estos runtimes siguen utilizándose mediante ecosistemas de contenedores y workflows de orquestación, pero sus propiedades de seguridad difieren de las de los runtimes OCI normales y no deberían agruparse mentalmente con los "contenedores Docker normales" como si todo funcionara igual.

## El Stack De Contenedores: Varias Capas, No Una Sola

Cuando alguien dice "este contenedor es inseguro", la pregunta de seguimiento útil es: **¿qué capa lo hizo inseguro?** Un workload contenerizado suele ser el resultado de varios componentes que trabajan conjuntamente.

En la parte superior suele haber una **capa de build de imágenes**, como BuildKit, Buildah o Kaniko, que crea la imagen OCI y sus metadatos. Sobre el runtime de bajo nivel puede existir un **engine o manager**, como Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. En entornos de cluster también puede haber un **orchestrator**, como Kubernetes, que decide la postura de seguridad solicitada mediante la configuración del workload. Finalmente, el **kernel** es quien aplica realmente los namespaces, cgroups, seccomp y la política MAC.

Este modelo por capas es importante para entender los valores predeterminados. Una restricción puede ser solicitada por Kubernetes, traducida mediante CRI por containerd o CRI-O, convertida en una especificación OCI por el wrapper del runtime y aplicada finalmente por `runc`, `crun`, `runsc` u otro runtime contra el kernel. Cuando los valores predeterminados difieren entre entornos, a menudo se debe a que una de estas capas cambió la configuración final. Por tanto, el mismo mecanismo puede aparecer en Docker o Podman como un flag de CLI, en Kubernetes como un campo de Pod o `securityContext`, y en los stacks de runtime de bajo nivel como una configuración OCI generada para el workload. Por ese motivo, los ejemplos de CLI de esta sección deben interpretarse como **sintaxis específica del runtime para un concepto general de contenedores**, no como flags universales compatibles con todas las herramientas.

## La Verdadera Frontera De Seguridad De Los Contenedores

En la práctica, la seguridad de los contenedores proviene de **controles superpuestos**, no de un único control perfecto. Los namespaces aíslan la visibilidad. Los cgroups regulan y limitan el uso de recursos. Las capabilities reducen lo que un proceso aparentemente privilegiado puede hacer realmente. seccomp bloquea syscalls peligrosas antes de que lleguen al kernel. AppArmor y SELinux añaden Mandatory Access Control sobre las comprobaciones DAC normales. `no_new_privs`, las rutas de procfs enmascaradas y las rutas del sistema de solo lectura dificultan las cadenas habituales de abuso de privilegios y de proc/sys. El propio runtime también es importante, porque decide cómo se crean los mounts, sockets, labels y uniones a namespaces.

Por eso, gran parte de la documentación sobre seguridad de contenedores parece repetitiva. La misma cadena de escape suele depender de varios mecanismos a la vez. Por ejemplo, un bind mount escribible del host es peligroso, pero se vuelve mucho peor si el contenedor también se ejecuta como root real en el host, tiene `CAP_SYS_ADMIN`, no está restringido por seccomp y no está limitado por SELinux o AppArmor. Del mismo modo, compartir el PID del host supone una exposición grave, pero resulta mucho más útil para un atacante cuando se combina con `CAP_SYS_PTRACE`, protecciones débiles de procfs o herramientas de entrada en namespaces como `nsenter`. Por tanto, la forma correcta de documentar el tema no es repetir el mismo ataque en cada página, sino explicar qué aporta cada capa a la frontera final.

## Cómo Leer Esta Sección

La sección está organizada desde los conceptos más generales hasta los más específicos.

Comienza con la visión general del runtime y del ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Después, revisa los planos de control y las superficies de supply chain que suelen determinar si un atacante necesita siquiera un kernel escape:

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

Después, pasa al modelo de protección:

{{#ref}}
protections/
{{#endref}}

Las páginas sobre namespaces explican individualmente las primitivas de aislamiento del kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Las páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, rutas enmascaradas y rutas del sistema de solo lectura explican los mecanismos que normalmente se superponen a los namespaces:

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

Al evaluar un target contenerizado, es mucho más útil plantear un pequeño conjunto de preguntas técnicas precisas que saltar inmediatamente a PoCs famosas de escape. Primero, identifica el **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer u otro más especializado. Después, identifica el **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` u otra implementación compatible con OCI. A continuación, comprueba si el entorno es **rootful o rootless**, si los **user namespaces** están activos, si se comparte algún **namespace del host**, qué **capabilities** permanecen, si **seccomp** está habilitado, si una **política MAC** está aplicándose realmente, si existen **mounts o sockets peligrosos** y si el proceso puede interactuar con la API del runtime de contenedores.

Estas respuestas te dicen mucho más sobre la postura de seguridad real que el nombre de la imagen base. En muchas evaluaciones, puedes predecir la familia probable de breakout antes de leer un solo archivo de la aplicación, simplemente entendiendo la configuración final del contenedor.

## Cobertura

Esta sección cubre el material antiguo centrado en Docker bajo una organización orientada a contenedores: exposición del runtime y del daemon, authorization plugins, confianza en imágenes y build secrets, mounts sensibles del host, workloads distroless, contenedores privilegiados y las protecciones del kernel que normalmente se superponen a la ejecución de contenedores.

{{#include ../../../banners/hacktricks-training.md}}
