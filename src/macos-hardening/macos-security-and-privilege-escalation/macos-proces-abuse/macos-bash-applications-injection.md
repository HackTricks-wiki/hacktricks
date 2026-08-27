# Inyección en aplicaciones de Shell de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Cuando Bash se inicia de forma no interactiva para ejecutar un script o un comando `-c`, expande el valor de `BASH_ENV` y obtiene el contenido del archivo resultante antes de ejecutar el comando solicitado. Bash no utiliza `PATH` para buscar este archivo. Por lo tanto, un proceso que inicia Bash no interactivo con variables de entorno controladas por el atacante puede hacer que se ejecute primero un payload de shell legible.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
El hook solo se ejecuta cuando el objetivo realmente inicia Bash; `/bin/sh` en otra plataforma o un programa que ejecuta un comando sin un shell no necesariamente lo respetará. Bash en modo privilegiado ignora `BASH_ENV`. Cuando los ID de usuario/grupo efectivos y reales difieren, Bash también omite los archivos de inicio y restablece los ID efectivos, a menos que se proporcione `-p`; con `-p`, el modo privilegiado permanece habilitado y `BASH_ENV` sigue ignorándose.<sup>[[1]](#references)[[2]](#references)</sup>

En macOS, los jobs de `launchd` pueden definir variables de entorno heredadas o específicas de cada job, así que inspecciona los plists y los contextos de lanzamiento que alimentan scripts privilegiados. No dependas únicamente de SIP para sanear las variables del intérprete: utiliza un entorno mínimo (`env -i`), desestablece explícitamente `BASH_ENV`, invoca el intérprete previsto mediante su ruta absoluta y evita los archivos de inicio modificables.

## zsh `ZDOTDIR`

zsh lee `$ZDOTDIR/.zshenv` para cada shell normal, incluidos los shells no interactivos; si `ZDOTDIR` no está definido, utiliza `HOME`. Redirigir `ZDOTDIR` a un directorio modificable ejecuta, por tanto, su `.zshenv` antes de un comando o script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` desactiva la opción `RCS` y omite este archivo de inicio del usuario. El archivo global `/etc/zshenv` todavía se lee, por lo que debe seguir siendo confiable y mínimo.

## fish `XDG_CONFIG_HOME`

fish lee `$XDG_CONFIG_HOME/fish/conf.d/*.fish` y `$XDG_CONFIG_HOME/fish/config.fish` al iniciar cada shell, no solo los shells interactivos o de login. También ejecuta `fish/vendor_conf.d/*.fish` debajo de las entradas de `XDG_DATA_DIRS`. Por lo tanto, un atacante que controle una de estas variables y un directorio legible puede ejecutar código antes que un script de fish o un comando `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Usa `fish --no-config` para una invocación confiable y borra las variables de ruta XDG no confiables.

## References

- [1] [Archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocación de Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Archivos de inicio y apagado de zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Archivos de configuración de fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
