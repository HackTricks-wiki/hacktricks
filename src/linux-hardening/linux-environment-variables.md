# Variables de entorno de Linux

{{#include ../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por los **procesos hijos**.

Puedes crear una variable global para tu sesión actual haciendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variable será accesible por tus sesiones actuales y sus procesos hijos.

Puedes **eliminar** una variable haciendo:
```bash
unset MYGLOBAL
```
## Variables locales

Las **variables locales** solo pueden ser **accedidas** por la **shell/script actual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista de variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
El contenido de `/proc/*/environ` está **separado por NUL**, así que estas variantes suelen ser más fáciles de leer:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si estás buscando **credentials** o **interesting service configuration** dentro de entornos heredados, revisa también [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – la pantalla usada por **X**. Esta variable suele establecerse en **:0.0**, lo que significa la primera pantalla en el equipo actual.
- **EDITOR** – el editor de texto preferido del usuario.
- **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de historial.
- **HISTSIZE** – número de líneas añadidas al archivo de historial cuando el usuario termina su sesión
- **HOME** – tu directorio home.
- **HOSTNAME** – el hostname del equipo.
- **LANG** – tu idioma actual.
- **MAIL** – la ubicación del spool de correo del usuario. Normalmente **/var/spool/mail/USER**.
- **MANPATH** – la lista de directorios donde buscar páginas de manual.
- **OSTYPE** – el tipo de sistema operativo.
- **PS1** – el prompt predeterminado en bash.
- **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que quieres ejecutar solo especificando el nombre del archivo y no la ruta relativa o absoluta.
- **PWD** – el directorio de trabajo actual.
- **SHELL** – la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
- **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ** – tu zona horaria.
- **USER** – tu nombre de usuario actual.

## Interesting variables for hacking

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza variables que cambian **search paths**, **startup files**, **dynamic linker behavior**, o **audit/logging**.

### **HISTFILESIZE**

Cambia el **value of this variable to 0**, así cuando **termines tu sesión** el **history file** (\~/.bash_history) será **truncated to 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que los comandos **no se guarden en el historial en memoria** y no se escriban de vuelta al **archivo de historial** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Si el **valor de esta variable se establece en `ignorespace` o `ignoreboth`**, cualquier comando antepuesto con un espacio extra no se guardará en el historial.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Apunta el **history file** a **`/dev/null`** o desactívalo por completo. Esto suele ser más fiable que solo cambiar el tamaño del history.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Los procesos usarán el **proxy** declarado aquí para conectarse a internet a través de **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy predeterminado para herramientas/protocolos que lo respetan.
- `no_proxy`: lista de omisión (hosts/dominios/CIDRs) que deben conectarse directamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Tanto las variantes en minúsculas como en mayúsculas pueden usarse según la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto es útil para hacer que herramientas como **`curl`**, **`git`**, clientes HTTP de Python o gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para hacer que un proxy de interceptación parezca legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script con privilegios ejecuta comandos **sin rutas absolutas**, el **primer directorio controlado por el atacante** en `PATH` gana. Este es el primitivo detrás de muchos **PATH hijacks** en `sudo`, trabajos de cron, shell wrappers y helpers SUID personalizados. Busca `env_keep+=PATH`, `secure_path` débil, o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.
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
Para cadenas completas de escalada de privilegios abusando de `PATH`, consulta [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` no es solo una referencia a un directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo con privilegios preserva estos valores, la **inyección de configuración** puede ser más fácil que el secuestro de binarios.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Targets interesantes incluyen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, y archivos específicos de herramientas como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Estas variables influyen en el **dynamic linker**:

- `LD_PRELOAD`: fuerza a que se carguen primero objetos compartidos extra.
- `LD_LIBRARY_PATH`: antepone directorios de búsqueda de librerías.
- `LD_AUDIT`: carga librerías auditoras que observan la carga de librerías y la resolución de símbolos.

Son extremadamente valiosas para **hooking**, **instrumentation** y **privilege escalation** si un comando privilegiado las conserva. En modo **secure-execution** (`AT_SECURE`, por ejemplo setuid/setgid/capabilities), el loader elimina o restringe muchas de estas variables. Sin embargo, los bugs de parser en esa fase temprana del loader siguen siendo de alto impacto porque se ejecutan **before** el target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia el comportamiento temprano de glibc (por ejemplo, los tunables del allocator) y es muy útil en exploit labs. También importa desde una perspectiva de seguridad porque el **dynamic loader lo analiza muy temprano**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una sola variable de entorno analizada en el loader puede convertirse en un **primitive de local privilege-escalation** contra programas SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** se inicia de forma **no interactiva**, comprueba `BASH_ENV` y carga ese archivo antes de ejecutar el script objetivo. Cuando Bash se invoca como `sh`, o en modo interactivo estilo POSIX, también puede consultarse `ENV`. Esta es una forma clásica de convertir un wrapper de shell en ejecución de código si el entorno está controlado por el atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash mismo deshabilita estos archivos de inicio cuando los **IDs reales/efectivos difieren** a menos que se use `-p`, así que el comportamiento exacto depende de cómo el wrapper invoque la shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Estas variables cambian cómo inicia Python:

- `PYTHONPATH`: antepone rutas de búsqueda de importación.
- `PYTHONHOME`: reubica el árbol de la biblioteca estándar.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo después de que termina un script.

Son útiles contra scripts de mantenimiento, debuggers, shells y wrappers que llaman a Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl tiene variables de inicio igualmente útiles:

- `PERL5LIB`: antepone directorios de librerías.
- `PERL5OPT`: inyecta switches como si estuvieran en cada línea de comando de `perl`.

Esto puede forzar la **carga automática de módulos** o cambiar el comportamiento del intérprete antes de que el script objetivo haga algo interesante. Perl ignora estas variables en contextos de **taint / setuid / setgid**, pero siguen siendo muy importantes para wrappers normales ejecutados como root, trabajos de CI, instaladores y reglas personalizadas de sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
La misma idea aparece en otros runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): siempre que un intérprete se lance mediante un wrapper privilegiado, busca variables de entorno que modifiquen **module loading** o el **startup behavior**.

Desde una perspectiva de post-exploitation, recuerda también que los entornos heredados a menudo contienen **credentials**, **proxy settings**, **service tokens** o **cloud keys**. Revisa [Linux Post Exploitation](linux-post-exploitation/README.md) para la búsqueda de `/proc/<PID>/environ` y `systemd` `Environment=`.

### PS1

Cambia cómo se ve tu prompt.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Usuario normal:

![](<../images/image (740).png>)

Uno, dos y tres jobs en background:

![](<../images/image (145).png>)

Un job en background, uno detenido y el último comando no terminó correctamente:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
