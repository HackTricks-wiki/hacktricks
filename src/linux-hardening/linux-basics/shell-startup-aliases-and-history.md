# Inicio de Shell, alias e historial

{{#include ../../banners/hacktricks-training.md}}

Un comando de shell puede comportarse de manera diferente al ejecutable con el mismo nombre si un alias, una función, un archivo de inicio o una variable de entorno cambia su ejecución. Comprueba estos elementos antes de confiar en la salida de un comando o asumir que un script usa el mismo PATH que una sesión interactiva.

## Inspeccionar la shell actual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` y `command -V` revelan si un nombre corresponde a un alias, una función, un builtin o un archivo. Es posible que `command -v` y `which` no indiquen lo mismo para alias y funciones. El historial del shell puede revelar comandos o credenciales, pero podría estar incompleto, desactivado o mantenerse en memoria hasta que se cierre la sesión.

Un `.bashrc` modificado puede definir un alias de `sudo` que imite una solicitud de contraseña, registre la respuesta y se la pase al comando real. Esto puede ocultar la interceptación de credenciales sin modificar el ejecutable `sudo` ni `PATH`.<sup>[[5]](#references)</sup> El shell debe leer el archivo de inicio modificado y expandir el alias.<sup>[[7]](#references)</sup> De forma predeterminada, Bash no interactivo no expande alias a menos que `expand_aliases` esté habilitado.<sup>[[6]](#references)</sup>

## Revisar archivos de inicio e historial

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un archivo de inicio modificable por un usuario puede ejecutar comandos cuando se inicie un shell en el futuro. Un archivo de inicio de todo el sistema o el archivo de inicio de un usuario con privilegios es más sensible si una cuenta con menos privilegios puede modificarlo. Bash no interactivo también puede leer el archivo indicado por `BASH_ENV`; la página de [variables de entorno](linux-environment-variables.md#bash_env--env) explica ese comportamiento y otros hooks de intérprete. Verifica qué archivos lee el shell real durante sesiones de inicio de sesión, interactivas y no interactivas antes de afirmar que existe una vía de persistencia.

Inspecciona también los archivos a los que hace `source` un archivo de inicio global. Por ejemplo, un `source /opt/app/venv/bin/activate` literal en `/etc/bash.bashrc` ejecuta el archivo de activación como código de shell cuando un shell realmente lee ese archivo de inicio. Revisa el archivo de activación, los permisos del enlace simbólico y de los directorios padre, y las ACL; un usuario con menos privilegios solo puede afectar a un shell privilegiado si ese shell o una tarea privilegiada hace `source` de ese archivo más adelante. Si el acceso de escritura depende de `sudoedit`, verifica primero la regla exacta de sudoers y el paquete de sudo instalado con los parches del proveedor; la cadena de versión upstream por sí sola no demuestra la [exposición a inyección de argumentos de sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Comprueba el historial, los dotfiles y las copias de seguridad en busca de secretos, como se describe en [usuarios y sesiones](../user-information/user-and-session-triage.md). Si un script privilegiado resuelve comandos por nombre, combina esta revisión con la [guía sobre secuestro de PATH](linux-environment-variables.md#path).

## Redirección del inicio de Zsh y archivos compilados

Con la configuración predeterminada de `RCS`, zsh lee `$ZDOTDIR/.zshenv` antes de las invocaciones normales, incluidas `zsh -c` y los scripts; si `ZDOTDIR` no está definido, usa `$HOME`. Cuando un ejecutor de comandos acepta un mapa de entorno, comprueba si reenvía cualquiera de estas variables a un proceso zsh privilegiado. En ese caso, un `.zshenv` modificable puede ejecutarse **antes** del cuerpo del comando que el ejecutor comprueba o permite mediante una lista de permitidos. Esto requiere que el proceso privilegiado herede el directorio redirigido; `zsh -f` omite los archivos de inicio del usuario, pero no el `zshenv` global (a menudo `/etc/zshenv`, aunque las rutas varían según la distribución). La [página sobre inyección de zsh en macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) incluye un ejemplo mínimo de `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Se ejecuta un `.zshenv.zwc` o `.zshrc.zwc` válido y más reciente en lugar de su archivo de inicio en texto plano. Si puedes escribir en el directorio de inicio, compilar un archivo modificado y luego restaurar un archivo de texto aparentemente inofensivo puede dejar código ejecutable en la copia compilada. Esto es ocultación, no cifrado. La prueba desechable que aparece abajo muestra por qué no basta con inspeccionar solo el archivo de texto; no afecta a ningún directorio de inicio real.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Para un objetivo real, determina su `ZDOTDIR`/`HOME` efectivo, inspecciona tanto los archivos de texto como los archivos `.zwc` y comprueba las marcas de tiempo, la propiedad y los directorios padre con permisos de escritura. Un archivo `.zwc` debe coincidir con el archivo de origen y ser más reciente para tener prioridad.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Archivos de inicio y cierre de Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Aviso sobre la inyección en el entorno de inicio del shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Comandos integrados de Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [El archivo .zshrc.zwc que olvidaste comprobar](https://dfir.ch/posts/compiled_zsh/)
- [5] [Campaña de espionaje con IA apunta a infraestructura gubernamental Linux](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Manual de Bash: alias](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Manual de Bash: archivos de inicio de Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
