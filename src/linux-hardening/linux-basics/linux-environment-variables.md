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
## Listar las variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
El contenido de `/proc/*/environ` está **separado por bytes NUL**, por lo que estas variantes suelen ser más fáciles de leer:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si buscas **credentials** o una **interesting service configuration** dentro de entornos heredados, consulta también [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – la pantalla utilizada por **X**. Esta variable normalmente se establece en **:0.0**, lo que significa la primera pantalla del equipo actual.
- **EDITOR** – el editor de texto preferido por el usuario.
- **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
- **HISTSIZE** – número de líneas añadidas al archivo de historial cuando el usuario finaliza su sesión.
- **HOME** – tu directorio de inicio.
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

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza las variables que modifican las **search paths**, los **startup files**, el **dynamic linker behavior** o la **audit/logging**.

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, de modo que cuando **finalices tu sesión**, el **archivo de historial** (\~/.bash_history) se **trunque a 0 líneas**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que los comandos **no se guarden en el historial en memoria** ni se escriban en el **archivo de historial** (\~/.bash_history).
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

Apunta el **archivo de historial** a **`/dev/null`** o desconfigúralo por completo. Esto suele ser más fiable que cambiar únicamente el tamaño del historial.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Los procesos utilizarán el **proxy** declarado aquí para conectarse a Internet mediante **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy y no_proxy

- `all_proxy`: proxy predeterminado para las herramientas/protocolos que lo admiten.
- `no_proxy`: lista de exclusión (hosts/dominios/CIDR) que deben conectarse directamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Pueden utilizarse variantes en minúsculas y mayúsculas según la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto resulta útil para hacer que herramientas como **`curl`**, **`git`**, clientes HTTP de Python o gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para que un proxy de interception parezca legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilegiado ejecuta comandos **sin rutas absolutas**, el **primer directorio controlado por el atacante** en `PATH` es el que prevalece. Este es el primitivo en el que se basan muchos **PATH hijacks** en `sudo`, trabajos de cron, wrappers de shell y helpers SUID personalizados. Busca `env_keep+=PATH`, un `secure_path` débil o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.
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
Para consultar cadenas completas de escalada de privilegios que abusan de `PATH`, revisa [Escalada de privilegios en Linux](linux-privilege-escalation/README.md).

### **HOME y XDG_CONFIG_HOME**

`HOME` no es solo una referencia a un directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo privilegiado conserva estos valores, la **inyección de configuración** puede resultar más sencilla que el secuestro de binarios.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Los objetivos interesantes incluyen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` y archivos específicos de herramientas como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Estas variables influyen en el **dynamic linker**:

- `LD_PRELOAD`: fuerza la carga previa de objetos compartidos adicionales.
- `LD_LIBRARY_PATH`: antepone directorios de búsqueda de bibliotecas.
- `LD_AUDIT`: carga bibliotecas auditoras que observan la carga de bibliotecas y la resolución de símbolos.

Son extremadamente valiosas para **hooking**, **instrumentation** y **privilege escalation** si un comando privilegiado las conserva. En el modo **secure-execution** (`AT_SECURE`, por ejemplo, setuid/setgid/capabilities), el loader elimina o restringe muchas de estas variables. Sin embargo, los parser bugs en esa fase temprana del loader siguen teniendo un gran impacto porque se ejecutan **antes** que el programa objetivo.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia el comportamiento temprano de glibc (por ejemplo, los parámetros ajustables del allocator) y resulta muy útil en exploit labs. También es relevante desde el punto de vista de la seguridad porque el **cargador dinámico lo analiza muy pronto**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una sola variable de entorno analizada por el cargador puede convertirse en una **primitive de escalada local de privilegios** contra programas SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** se inicia **de forma no interactiva**, comprueba `BASH_ENV` y hace source de ese archivo antes de ejecutar el script objetivo. Cuando Bash se invoca como `sh`, o en modo interactivo de estilo POSIX, también puede consultar `ENV`. Esta es una forma clásica de convertir un wrapper de shell en **code execution** si el entorno está controlado por el atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash deshabilita estos archivos de inicio cuando los **IDs reales/efectivos difieren**, a menos que se use `-p`, por lo que el comportamiento exacto depende de cómo el wrapper invoque el shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP y PYTHONINSPECT**

Estas variables cambian cómo se inicia Python:

- `PYTHONPATH`: antepone rutas de búsqueda de importación.
- `PYTHONHOME`: reubica el árbol de la biblioteca estándar.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo después de que finaliza un script.

Son útiles contra scripts de mantenimiento, depuradores, shells y wrappers que invocan Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
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
La misma idea aparece en otros runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): siempre que un intérprete sea iniciado por un wrapper privilegiado, busca variables de entorno que modifiquen la **carga de módulos** o el **comportamiento de inicio**.

Desde una perspectiva de post-exploitation, recuerda también que los entornos heredados suelen contener **credenciales**, **configuraciones de proxy**, **tokens de servicio** o **claves cloud**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) para buscar `/proc/<PID>/environ` y `Environment=` de `systemd`.

### PS1

Cambia el aspecto de tu prompt.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este es un ejemplo](<../images/image (897).png>)

Usuario normal:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos ejecutándose en segundo plano](<../images/image (740).png>)

Uno, dos y tres trabajos ejecutándose en segundo plano:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos ejecutándose en segundo plano](<../images/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente:

![PERL5OPT & PERL5LIB - PS1: Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente](<../images/image (715).png>)

## Referencias

- [Manual de GNU Bash - Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
