# Seguridad de Contenedores

{{#include ../../../banners/hacktricks-training.md}}

## Qué es realmente un contenedor

Una forma práctica de definir un contenedor es esta: un contenedor es un **árbol de procesos de Linux regular** que ha sido iniciado bajo una configuración de estilo OCI específica de modo que vea un sistema de archivos controlado, un conjunto controlado de recursos del kernel y un modelo de privilegios restringido. El proceso puede creer que es PID 1, puede creer que tiene su propia pila de red, puede creer que posee su propio hostname y recursos IPC, e incluso puede ejecutarse como root dentro de su propio user namespace. Pero bajo el capó sigue siendo un proceso del host que el kernel programa como cualquier otro.

Por eso la seguridad de contenedores es realmente el estudio de cómo se construye esa ilusión y cómo falla. Si el mount namespace es débil, el proceso puede ver el filesystem del host. Si el user namespace está ausente o desactivado, root dentro del contenedor puede mapearse demasiado cerca de root en el host. Si seccomp no está confinado y el conjunto de capabilities es demasiado amplio, el proceso puede alcanzar syscalls y funcionalidades privilegiadas del kernel que deberían haber permanecido fuera de alcance. Si el runtime socket está montado dentro del contenedor, el contenedor quizá no necesite un kernel breakout en absoluto porque simplemente puede pedirle al runtime que lance un contenedor hermano más poderoso o monte directamente el filesystem root del host.

## Cómo difieren los contenedores de las máquinas virtuales

Una VM normalmente lleva su propio kernel y límite de abstracción de hardware. Eso significa que el kernel invitado puede crasharse, entrar en panic o ser explotado sin implicar automáticamente control directo del kernel del host. En los contenedores, la carga de trabajo no obtiene un kernel separado. En su lugar, obtiene una vista cuidadosamente filtrada y con namespaces del mismo kernel que usa el host. Como resultado, los contenedores suelen ser más ligeros, arrancan más rápido, son más fáciles de empaquetar densamente en una máquina y están mejor adaptados a despliegues de aplicaciones de corta duración. El precio es que el límite de aislamiento depende mucho más directamente de la configuración correcta del host y del runtime.

Esto no significa que los contenedores sean "inseguros" y las VMs "seguras". Significa que el modelo de seguridad es diferente. Una pila de contenedores bien configurada con rootless execution, user namespaces, seccomp por defecto, un conjunto estricto de capabilities, sin compartición de namespaces del host y con un refuerzo fuerte de SELinux o AppArmor puede ser muy robusta. Por el contrario, un contenedor iniciado con `--privileged`, con compartición de PID/red del host, el Docker socket montado dentro y un bind mount escribible de `/` está funcionalmente mucho más cerca del acceso root del host que de un sandbox de aplicación aislado. La diferencia viene de las capas que se habilitaron o deshabilitaron.

También existe un punto intermedio que los lectores deberían entender porque aparece cada vez más en entornos reales. **Sandboxed container runtimes** como **gVisor** y **Kata Containers** endurecen intencionalmente el límite más allá de un contenedor clásico `runc`. gVisor coloca una capa de kernel en espacio de usuario entre la carga de trabajo y muchas interfaces del kernel del host, mientras que Kata lanza la carga de trabajo dentro de una máquina virtual ligera. Estos siguen usándose a través de ecosistemas de contenedores y flujos de orquestación, pero sus propiedades de seguridad difieren de los runtimes OCI simples y no deberían agruparse mentalmente con "contenedores Docker normales" como si todo se comportara igual.

## La pila de contenedores: varias capas, no una sola

Cuando alguien dice "este contenedor es inseguro", la pregunta útil de seguimiento es: ¿qué capa lo hizo inseguro? Una carga de trabajo containerizada suele ser el resultado de varios componentes que trabajan juntos.

En la parte superior, suele haber una **capa de build de imágenes** como BuildKit, Buildah o Kaniko, que crea la imagen OCI y los metadatos. Por encima del runtime de bajo nivel, puede haber un **engine o manager** como Docker Engine, Podman, containerd, CRI-O, Incus o systemd-nspawn. En entornos de clúster, también puede haber un **orquestador** como Kubernetes que decide la postura de seguridad solicitada mediante la configuración de la carga de trabajo. Finalmente, el **kernel** es lo que realmente aplica namespaces, cgroups, seccomp y las políticas MAC.

Este modelo en capas es importante para entender los valores por defecto. Una restricción puede ser solicitada por Kubernetes, traducida a través de CRI por containerd o CRI-O, convertida en una spec OCI por el wrapper del runtime y solo entonces aplicada por `runc`, `crun`, `runsc` u otro runtime contra el kernel. Cuando los valores por defecto difieren entre entornos, a menudo es porque una de estas capas cambió la configuración final. El mismo mecanismo puede por tanto aparecer en Docker o Podman como una flag de CLI, en Kubernetes como un campo de Pod o `securityContext`, y en pilas de runtime de bajo nivel como configuración OCI generada para la carga de trabajo. Por esa razón, los ejemplos de CLI en esta sección deben leerse como sintaxis específica del runtime para un concepto general de contenedor, no como flags universales soportadas por todas las herramientas.

## El verdadero límite de seguridad del contenedor

En la práctica, la seguridad de contenedores proviene de **controles superpuestos**, no de un único control perfecto. Los namespaces aíslan la visibilidad. Los cgroups gobiernan y limitan el uso de recursos. Las capabilities reducen lo que un proceso con apariencia privilegiada puede realmente hacer. seccomp bloquea syscalls peligrosos antes de que lleguen al kernel. AppArmor y SELinux añaden Mandatory Access Control sobre los chequeos DAC normales. `no_new_privs`, rutas de procfs enmascaradas y rutas del sistema en modo solo-lectura hacen que las cadenas comunes de abuso de privilegios y de proc/sys sean más difíciles. El runtime en sí también importa porque decide cómo se crean mounts, sockets, labels y uniones de namespaces.

Por eso mucha documentación de seguridad de contenedores parece repetitiva. La misma cadena de escape a menudo depende de múltiples mecanismos a la vez. Por ejemplo, un bind mount escribible del host es malo, pero se vuelve mucho peor si el contenedor también se ejecuta como root real en el host, tiene `CAP_SYS_ADMIN`, no está confinado por seccomp y no está restringido por SELinux o AppArmor. De igual forma, la compartición de PID del host es una exposición seria, pero se vuelve dramáticamente más útil para un atacante cuando se combina con `CAP_SYS_PTRACE`, protecciones débiles de procfs o herramientas de entrada a namespaces como `nsenter`. La forma correcta de documentar el tema no es repetir el mismo ataque en cada página, sino explicar qué aporta cada capa al límite final.

## Cómo leer esta sección

La sección está organizada desde los conceptos más generales hasta los más específicos.

Comience con la visión general del runtime y del ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Luego revise los planos de control y las superficies de la supply-chain que con frecuencia deciden si un atacante siquiera necesita un kernel escape:

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

Luego pase al modelo de protección:

{{#ref}}
protections/
{{#endref}}

Las páginas de namespaces explican de forma individual los primitivos de aislamiento del kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Las páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths y read-only system paths explican los mecanismos que normalmente se apilan sobre los namespaces:

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

## Un buen enfoque inicial para la enumeración

Al evaluar un objetivo containerizado, es mucho más útil plantear un pequeño conjunto de preguntas técnicas precisas que saltar inmediatamente a PoCs famosos de escape. Primero, identifique la **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer u otra cosa más especializada. Luego identifique el **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` u otra implementación compatible con OCI. Después de eso, compruebe si el entorno es **rootful or rootless**, si los **user namespaces** están activos, si se comparten **host namespaces**, qué **capabilities** permanecen, si **seccomp** está habilitado, si una **MAC policy** realmente está haciendo cumplir, si hay **dangerous mounts or sockets** presentes y si el proceso puede interactuar con la API del container runtime.

Esas respuestas le dicen mucho más sobre la postura real de seguridad que el nombre de la imagen base. En muchas evaluaciones, puede predecir la familia de breakout probable antes de leer un solo archivo de la aplicación únicamente entendiendo la configuración final del contenedor.

## Cobertura

Esta sección cubre el material antiguo enfocado en Docker bajo una organización orientada a contenedores: runtime y exposición del daemon, authorization plugins, trust de imágenes y build secrets, sensitive host mounts, distroless workloads, privileged containers y las protecciones del kernel que normalmente se apilan alrededor de la ejecución de contenedores.
{{#include ../../../banners/hacktricks-training.md}}
