# Inicio de shell, aliases e historial

{{#include ../../banners/hacktricks-training.md}}

Un comando de shell puede comportarse de forma distinta al ejecutable con el mismo nombre si un alias, una función, un archivo de inicio o una variable de entorno modifica su ejecución. Comprueba estos elementos antes de confiar en la salida de un comando o asumir que un script usa el mismo PATH que una sesión interactiva.

## Inspeccionar el shell actual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` y `command -V` revelan si un nombre corresponde a un alias, una función, un builtin o un archivo. `command -v` y `which` pueden no mostrar lo mismo para los alias y las funciones. El historial del shell puede exponer comandos o credenciales, pero puede estar incompleto, desactivado o permanecer en memoria hasta que termine la sesión.

## Revisar los archivos de inicio y del historial

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un archivo de inicio modificable por un usuario puede ejecutar comandos cuando se inicie un shell en el futuro. Un archivo de inicio para todo el sistema o el archivo de inicio de un usuario privilegiado es más sensible si una cuenta con menos privilegios puede modificarlo. Bash no interactivo también puede leer el archivo indicado por `BASH_ENV`; la página sobre [variables de entorno](linux-environment-variables.md#bash_env--env) explica ese comportamiento y otros hooks de intérprete. Antes de afirmar que existe una vía de persistencia, verifica qué archivos lee el shell en uso durante las sesiones de inicio de sesión, interactivas y no interactivas.

Inspecciona también los archivos cargados por un archivo de inicio global. Por ejemplo, un `source /opt/app/venv/bin/activate` literal en `/etc/bash.bashrc` ejecuta el archivo de activación como código shell cuando un shell realmente lee ese archivo de inicio. Revisa el archivo de activación, los permisos del symlink y de los directorios padre, y las ACL; un usuario con menos privilegios solo puede afectar a un shell privilegiado si ese shell o una tarea privilegiada carga después el archivo. Si el acceso de escritura depende de `sudoedit`, verifica primero la regla exacta de sudoers y el paquete de sudo instalado con parches del proveedor; una cadena de versión upstream por sí sola no demuestra la [exposición a inyección de argumentos de sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Revisa el historial, los dotfiles y las copias de seguridad en busca de secretos, como se describe en [usuarios y sesiones](../user-information/user-and-session-triage.md). Si un script privilegiado resuelve comandos por nombre, combina esta revisión con las [indicaciones sobre secuestro de PATH](linux-environment-variables.md#path).

## Redirección de inicio de Zsh y archivos compilados

Con la configuración predeterminada de `RCS`, zsh lee `$ZDOTDIR/.zshenv` antes de las invocaciones normales, incluidas `zsh -c` y las ejecuciones de scripts; si `ZDOTDIR` no está definido, usa `$HOME`. Cuando un ejecutor de comandos acepta un mapa de entorno, comprueba si pasa cualquiera de esas variables a un proceso zsh privilegiado. En ese caso, un `.zshenv` modificable puede ejecutarse **antes** del cuerpo del comando que el ejecutor verifica o incluye en la lista de permitidos. Esto requiere que el proceso privilegiado herede el directorio redirigido; `zsh -f` omite los archivos de inicio del usuario, pero no el `zshenv` global (a menudo `/etc/zshenv`, aunque las rutas varían según la distribución). La [página sobre inyección de zsh en macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) contiene un ejemplo mínimo de `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Un `.zshenv.zwc` o `.zshrc.zwc` válido y más reciente se ejecuta en lugar de su archivo de inicio en texto plano. Si puedes escribir en el directorio de inicio, compilar un archivo modificado y luego restaurar un archivo de texto plano aparentemente inofensivo puede dejar código ejecutable en la copia compilada. Esto es ocultación, no cifrado. La prueba desechable de abajo muestra por qué no basta con inspeccionar solo el archivo de texto; no afecta a ningún directorio de inicio real.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Para un objetivo real, determina su `ZDOTDIR`/`HOME` efectivo, inspecciona tanto los archivos de texto como los `.zwc` y comprueba las marcas de tiempo, la propiedad y los permisos de escritura de los directorios padre. Para que un archivo `.zwc` tenga prioridad, debe corresponder al archivo de origen y ser más reciente.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Archivos de inicio y cierre de Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Aviso sobre inyección del entorno durante el inicio del shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Builtins del shell Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [El archivo .zshrc.zwc que olvidaste revisar](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
