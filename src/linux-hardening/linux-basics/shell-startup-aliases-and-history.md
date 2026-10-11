# Inicio de shell, alias e historial

{{#include ../../banners/hacktricks-training.md}}

Un comando del shell puede comportarse de forma distinta al ejecutable con el mismo nombre si un alias, una función, un archivo de inicio o una variable de entorno modifica su ejecución. Comprueba estos elementos antes de confiar en la salida de un comando o de asumir que un script usa el mismo PATH que una sesión interactiva.

## Inspeccionar el shell actual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` y `command -V` revelan si un nombre corresponde a un alias, una función, un builtin o un archivo. `command -v` y `which` pueden no mostrar lo mismo para los alias y las funciones. El historial de shell puede revelar comandos o credenciales, pero puede estar incompleto, desactivado o permanecer en memoria hasta que se cierre la sesión.

## Revisar los archivos de inicio y el historial

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un archivo de inicio modificable por un usuario puede ejecutar comandos cuando se inicie un shell en el futuro. Un archivo de inicio de todo el sistema o de un usuario privilegiado es más sensible si una cuenta con menos privilegios puede modificarlo. Bash no interactivo también puede leer el archivo indicado por `BASH_ENV`; la página de [variables de entorno](linux-environment-variables.md#bash_env--env) explica ese comportamiento y otros hooks de intérprete. Verifica qué archivos lee el shell real en sesiones de inicio de sesión, interactivas y no interactivas antes de afirmar que existe una vía de persistencia.

Inspecciona también los archivos incluidos por un archivo de inicio global. Por ejemplo, un `source /opt/app/venv/bin/activate` literal en `/etc/bash.bashrc` ejecuta el archivo de activación como código de shell cuando un shell realmente lee ese archivo de inicio. Revisa el archivo de activación, los permisos del enlace simbólico y de los directorios padre, y las ACL; un usuario con menos privilegios solo puede afectar a un shell privilegiado si ese shell o una tarea privilegiada lo incluye más adelante. Si el acceso de escritura depende de `sudoedit`, verifica primero la regla exacta de sudoers y el paquete de sudo instalado y parcheado por el proveedor; una cadena de versión upstream por sí sola no demuestra [exposición a la inyección de argumentos de sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Revisa el historial, los dotfiles y las copias de seguridad en busca de secretos, como se describe en [usuarios y sesiones](../user-information/user-and-session-triage.md). Si un script privilegiado resuelve comandos por nombre, combina esta revisión con la [guía sobre secuestro de PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
