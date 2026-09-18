# Inyección en aplicaciones Shell de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Cuando Bash se inicia de forma no interactiva para ejecutar un script o un comando `-c`, expande el valor de `BASH_ENV` y obtiene el archivo resultante antes de ejecutar el comando solicitado. Bash no utiliza `PATH` para encontrar este archivo. Por lo tanto, un proceso que inicia Bash no interactivo con variables de entorno controladas por un atacante puede hacer que ejecute primero un payload de shell legible.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
El hook se ejecuta únicamente cuando el objetivo inicia realmente Bash; `/bin/sh` en otra plataforma o un programa que ejecuta un comando sin un shell no necesariamente lo respetará. Bash en modo privilegiado ignora `BASH_ENV`. Cuando los ID de usuario o grupo efectivos y reales difieren, Bash también omite los startup files y restablece los ID efectivos, a menos que se proporcione `-p`; con `-p`, el modo privilegiado permanece habilitado y `BASH_ENV` continúa ignorándose.<sup>[[1]](#references)[[2]](#references)</sup>

En macOS, los jobs de `launchd` pueden definir variables de entorno heredadas o específicas del job, por lo que se deben inspeccionar los plists y los contextos de lanzamiento que alimentan los scripts privilegiados. No dependas únicamente de SIP para sanitizar las variables del intérprete: usa un entorno mínimo (`env -i`), desestablece explícitamente `BASH_ENV`, invoca el intérprete previsto mediante una ruta absoluta y evita los startup files modificables.

## zsh `ZDOTDIR`

zsh lee `$ZDOTDIR/.zshenv` para cada shell normal, incluidos los shells no interactivos; si `ZDOTDIR` no está definido, utiliza `HOME`. Redirigir `ZDOTDIR` a un directorio modificable ejecuta, por tanto, su `.zshenv` antes de un comando o script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` desactiva la opción `RCS` y omite este archivo de inicio del usuario. El archivo global `/etc/zshenv` todavía se lee, por lo que debe seguir siendo confiable y mínimo.

## fish `XDG_CONFIG_HOME`

fish lee `$XDG_CONFIG_HOME/fish/conf.d/*.fish` y `$XDG_CONFIG_HOME/fish/config.fish` al iniciar cada shell, no solo los shells interactivos o de inicio de sesión. También ejecuta `fish/vendor_conf.d/*.fish` debajo de las entradas de `XDG_DATA_DIRS`. Por lo tanto, un atacante que controle una de estas variables y un directorio legible puede ejecutar código antes de un script de fish o de un comando `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Usa `fish --no-config` para una invocación de confianza y elimina las variables de ruta XDG no confiables.

## bash `PS4` + xtrace (`SHELLOPTS`)

Cuando Bash se ejecuta con la opción **xtrace**, antes de cada comando rastreado expande `PS4` y lo imprime. `PS4` se expande como cualquier prompt, por lo que una **sustitución de comandos** dentro de este se ejecuta. Tanto el valor de `PS4` **como** la forma en que se habilita xtrace pueden provenir únicamente del entorno: exportar `SHELLOPTS=xtrace` activa xtrace para un `bash script.sh` normal (sin necesidad de la opción `-x`). Esto convierte cualquier script de Bash que ejecute la víctima en una ejecución de código.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` por sí solo no hace nada hasta que se habilita xtrace (mediante `SHELLOPTS=xtrace`, `set -x` o `bash -x`). Bash ignora `SHELLOPTS` en **modo privilegiado** (cuando los ID reales y efectivos difieren sin gestionar `-p`), por lo que se aplican las mismas salvedades de setuid que con `BASH_ENV`.

## POSIX `ENV`

Los shells de estilo POSIX (`/bin/sh`, `dash`, `ksh`) leen la variable `ENV`, la expanden y ejecutan el archivo resultante cuando inician un shell **interactivo**. Es la contraparte POSIX de `BASH_ENV` (que se activa para Bash *no interactivo*), por lo que controlar `ENV` permite ejecutar código cada vez que una víctima inicia un `sh`/`dash` interactivo.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocación de Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Archivos de inicio/cierre de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Archivos de configuración de fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Variables de Bash — `PS4` y el builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
