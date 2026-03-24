# Seguridad de Contenedores

{{#include ../../../banners/hacktricks-training.md}}

## Qué es realmente un contenedor

Una forma práctica de definir un contenedor es esta: un contenedor es un **árbol de procesos Linux regular** que se ha iniciado bajo una configuración estilo OCI de modo que ve un sistema de archivos controlado, un conjunto controlado de recursos del kernel y un modelo de privilegios restringido. El proceso puede creer que es PID 1, puede creer que tiene su propia network stack, puede creer que posee su propio hostname e IPC, e incluso puede ejecutarse como root dentro de su propio user namespace. Pero bajo el capó sigue siendo un proceso del host que el kernel agenda como cualquier otro.

Por eso la seguridad de contenedores es realmente el estudio de cómo se construye esa ilusión y cómo falla. Si el mount namespace es débil, el proceso puede ver el filesystem del host. Si el user namespace está ausente o deshabilitado, root dentro del contenedor puede mapearse demasiado cerca de root en el host. Si seccomp no está confinado y el capability set es demasiado amplio, el proceso puede alcanzar syscalls y funciones privilegiadas del kernel que deberían permanecer fuera de su alcance. Si el runtime socket está montado dentro del contenedor, el contenedor puede no necesitar ningún kernel breakout porque simplemente puede pedir al runtime que lance un contenedor hermano más potente o monte directamente el host root filesystem.

## Cómo difieren los contenedores de las máquinas virtuales

Una VM normalmente lleva su propio kernel y límite de abstracción de hardware. Eso significa que el kernel invitado puede fallar, panic, o ser explotado sin implicar automáticamente control directo sobre el kernel del host. En los contenedores, la carga de trabajo no obtiene un kernel separado. En su lugar, obtiene una vista cuidadosamente filtrada y namespaced del mismo kernel que usa el host. Como resultado, los contenedores suelen ser más ligeros, arrancan más rápido, son más fáciles de empaquetar densamente en una máquina y están mejor adaptados para despliegues de aplicaciones de corta duración. El precio es que el límite de aislamiento depende mucho más directamente de la configuración correcta del host y del runtime.

Esto no significa que los contenedores sean "inseguros" y las VMs "seguras". Significa que el modelo de seguridad es distinto. Un stack de contenedores bien configurado con rootless execution, user namespaces, seccomp por defecto, un capability set estricto, sin host namespace sharing y con una fuerte aplicación de SELinux o AppArmor puede ser muy robusto. A la inversa, un contenedor iniciado con `--privileged`, host PID/network sharing, el Docker socket montado dentro, y un bind mount escribible de `/` es funcionalmente mucho más cercano al acceso root del host que a un sandbox de aplicación aislado de forma segura. La diferencia viene de las capas que se habilitaron o deshabilitaron.

También existe un punto intermedio que los lectores deben entender porque aparece cada vez más en entornos reales. Los runtimes de contenedores sandboxed como gVisor y Kata Containers endurecen intencionalmente el límite más allá de un contenedor clásico `runc`. gVisor coloca una capa de kernel en espacio de usuario entre la carga de trabajo y muchas interfaces del kernel del host, mientras que Kata lanza la carga de trabajo dentro de una máquina virtual ligera. Estos todavía se usan dentro de ecosistemas de contenedores y flujos de orquestación, pero sus propiedades de seguridad difieren de los runtimes OCI simples y no deberían agruparse mentalmente con "contenedores Docker normales" como si todo se comportara igual.

## El stack de contenedores: varias capas, no una sola

Cuando alguien dice "este contenedor es inseguro", la pregunta útil de seguimiento es: ¿**qué capa lo hizo inseguro**? Una carga de trabajo en contenedor suele ser el resultado de varios componentes que trabajan juntos.

En la parte superior, suele haber una **capa de build de imagen** como BuildKit, Buildah, o Kaniko, que crea la imagen OCI y los metadatos. Por debajo del runtime de bajo nivel, puede haber un **engine o manager** como Docker Engine, Podman, containerd, CRI-O, Incus, o systemd-nspawn. En entornos de clúster, también puede haber un **orquestador** como Kubernetes que decide la postura de seguridad solicitada mediante la configuración de la carga de trabajo. Finalmente, el **kernel** es lo que realmente aplica namespaces, cgroups, seccomp y la política MAC.

Este modelo en capas es importante para entender los defaults. Una restricción puede ser solicitada por Kubernetes, traducida a través de CRI por containerd o CRI-O, convertida en una spec OCI por el wrapper del runtime y solo entonces aplicada por `runc`, `crun`, `runsc` u otro runtime contra el kernel. Cuando los defaults difieren entre entornos, a menudo es porque una de estas capas cambió la configuración final. El mismo mecanismo puede por tanto aparecer en Docker o Podman como una flag de CLI, en Kubernetes como un Pod o campo `securityContext`, y en stacks de runtime de bajo nivel como configuración OCI generada para la carga de trabajo. Por esa razón, los ejemplos de CLI en esta sección deben leerse como **sintaxis específica del runtime para un concepto general de contenedor**, no como flags universales soportados por todas las herramientas.

## El verdadero límite de seguridad del contenedor

En la práctica, la seguridad de contenedores proviene de **controles superpuestos**, no de un único control perfecto. namespaces aíslan la visibilidad. cgroups gobiernan y limitan el uso de recursos. Capabilities reducen lo que un proceso con apariencia privilegiada realmente puede hacer. seccomp bloquea syscalls peligrosos antes de que lleguen al kernel. AppArmor y SELinux añaden Mandatory Access Control encima de los chequeos DAC normales. `no_new_privs`, rutas de procfs enmascaradas y rutas del sistema en solo-lectura hacen que las cadenas comunes de abuso de privilegios y proc/sys sean más difíciles. El runtime en sí también importa porque decide cómo se crean mounts, sockets, labels y joins de namespace.

Por eso mucha documentación de seguridad de contenedores parece repetitiva. La misma cadena de escape a menudo depende de múltiples mecanismos a la vez. Por ejemplo, un bind mount del host escribible es malo, pero se vuelve mucho peor si el contenedor también se ejecuta como root real en el host, tiene `CAP_SYS_ADMIN`, no está confinado por seccomp y no está restringido por SELinux o AppArmor. De igual forma, el host PID sharing es una exposición seria, pero se vuelve dramáticamente más útil para un atacante cuando se combina con `CAP_SYS_PTRACE`, protecciones débiles de procfs o herramientas de entrada a namespaces como `nsenter`. La manera correcta de documentar el tema no es repetir el mismo ataque en cada página, sino explicar qué aporta cada capa al límite final.

## Cómo leer esta sección

La sección está organizada desde los conceptos más generales hasta los más específicos.

Empieza con la visión general del runtime y el ecosistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Luego revisa los planos de control y las superficies de supply-chain que con frecuencia deciden si un atacante siquiera necesita un kernel escape:

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

Luego pasa al modelo de protección:

{{#ref}}
protections/
{{#endref}}

Las páginas de namespaces explican los primitivos de aislamiento del kernel individualmente:

{{#ref}}
protections/namespaces/
{{#endref}}

Las páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths y read-only system paths explican los mecanismos que suelen apilarse encima de namespaces:

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

## Una buena mentalidad inicial para enumeración

Al evaluar un objetivo en contenedor, es mucho más útil hacer un pequeño conjunto de preguntas técnicas precisas que saltar inmediatamente a PoCs famosos de escape. Primero, identifica el **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, o algo más especializado. Luego identifica el **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, u otra implementación compatible con OCI. Después de eso, comprueba si el entorno es **rootful o rootless**, si los **user namespaces** están activos, si se comparten **host namespaces**, qué **capabilities** quedan, si **seccomp** está habilitado, si una **MAC policy** está realmente aplicando, si hay **mounts o sockets peligrosos**, y si el proceso puede interactuar con la runtime API del contenedor.

Esas respuestas te dicen mucho más sobre la postura real de seguridad que el nombre de la imagen base. En muchas evaluaciones, puedes predecir la familia de breakout probable antes de leer un solo archivo de la aplicación simplemente entendiendo la configuración final del contenedor.

## Cobertura

Esta sección cubre el material antiguo enfocado en Docker bajo una organización orientada a contenedores: runtime y exposición del daemon, authorization plugins, confianza de imagen y build secrets, mounts sensibles del host, workloads distroless, contenedores privilegiados y las protecciones del kernel que normalmente se apilan alrededor de la ejecución de contenedores.
{{#include ../../../banners/hacktricks-training.md}}
