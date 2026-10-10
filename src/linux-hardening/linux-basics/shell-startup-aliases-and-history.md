# Inicio de shell, alias e historial

{{#include ../../banners/hacktricks-training.md}}

Un comando de shell puede comportarse de forma distinta al ejecutable con el mismo nombre si un alias, una función, un archivo de inicio o una variable de entorno modifica cómo se ejecuta. Comprueba estos elementos antes de confiar en la salida de un comando o de asumir que un script usa el mismo PATH que una sesión interactiva.

## Inspeccionar el shell actual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` y `command -V` revelan si un nombre se resuelve como alias, función, builtin o archivo. `command -v` y `which` pueden no mostrar lo mismo para alias y funciones. El historial del shell puede exponer comandos o credenciales, pero podría estar incompleto, desactivado o mantenerse en memoria hasta que se cierre la sesión.

## Revisar archivos de inicio e historial

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un archivo de inicio en el que un usuario puede escribir puede ejecutar comandos en un futuro inicio del shell. Un archivo de inicio de todo el sistema o el archivo de inicio de un usuario con privilegios es más sensible si una cuenta con menos privilegios puede modificarlo. Bash no interactivo también puede leer el archivo indicado por `BASH_ENV`; la página de [variables de entorno](linux-environment-variables.md#bash_env--env) explica ese comportamiento y otros hooks de intérprete. Verifica qué archivos lee el shell en uso durante sesiones de inicio de sesión, interactivas y no interactivas antes de afirmar que existe una vía de persistencia.

Inspecciona también los archivos cargados por un archivo de inicio global. Por ejemplo, un `source /opt/app/venv/bin/activate` literal en `/etc/bash.bashrc` ejecuta el archivo de activación como código de shell cuando el shell realmente lee ese archivo de inicio. Revisa el archivo de activación, los permisos del enlace simbólico y del directorio padre, y las ACL; un usuario con menos privilegios solo puede afectar a un shell con privilegios si ese shell o una tarea con privilegios lo carga posteriormente. Si el acceso de escritura depende de `sudoedit`, verifica primero la regla exacta de sudoers y el paquete de sudo instalado con los parches del proveedor; una cadena de versión upstream por sí sola no demuestra la [exposición a la inyección de argumentos de sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Revisa el historial, los dotfiles y las copias de seguridad en busca de secretos, tal como se describe en [usuarios y sesiones](../user-information/user-and-session-triage.md). Si un script con privilegios resuelve los comandos por nombre, combina esta revisión con las [indicaciones sobre secuestro de PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
