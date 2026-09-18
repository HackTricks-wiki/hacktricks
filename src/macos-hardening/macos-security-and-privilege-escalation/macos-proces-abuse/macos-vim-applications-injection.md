# Inyección de aplicaciones de Vim/Neovim en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

El propio lenguaje de scripting de Vim (Vimscript) puede ejecutar **comandos Ex y comandos de shell arbitrarios al inicio** desde variables de entorno. Si un proceso con más privilegios (un flujo de mantenimiento/root, un `sudo vim …`, un editor iniciado por otra herramienta, `crontab -e`, `visudo`, `git`/`less` invocando un editor, …) inicia Vim/Neovim con un entorno controlado por el atacante, este obtiene ejecución de código en ese contexto.

## `VIMINIT`

Durante la inicialización, Vim lee y ejecuta los comandos Ex de **`VIMINIT`**. Los comandos Ex incluyen `:!cmd` (ejecutar un comando de shell) y `:call system(...)`, por lo que una sola variable permite la ejecución arbitraria antes de editar cualquier archivo.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
El `:qa!` introducido mediante stdin simplemente cierra el editor después de que el payload ya se haya ejecutado; en un escenario real, la víctima simplemente abre Vim con normalidad.

## `EXINIT`

Si `VIMINIT` no está establecido, Vim (y los binarios de compatibilidad `vi`/`ex`) recurre a **`EXINIT`**, que se ejecuta de la misma manera. Es la variante clásica de la era de vi de la misma primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notas y advertencias

- **Neovim** también respeta `VIMINIT` (se comprueba antes del `init.vim`/`init.lua` del usuario).
- El modo Batch/Ex (`vim -es` / `vim -Es`) **no** carga `VIMINIT`/`EXINIT`; las variables se ejecutan durante un inicio normal (interactivo), que es el escenario habitual de la víctima.
- Los vectores relacionados basados en archivos son las funciones `exrc`/`.nvimrc` "modeline"/local-rc por directorio y `-u <vimrc>`; la ruta mediante variables de entorno indicada anteriormente no necesita ningún archivo modificable.

## Hardening

- Sanitiza el entorno (elimina `VIMINIT`/`EXINIT`) antes de iniciar editores desde contextos privilegiados o automatizados, y prefiere wrappers `sudo -i`/`env -i` que restablezcan el entorno.
- Establece `EDITOR`/`VISUAL` en rutas absolutas de confianza y evita ejecutar editores como root con un entorno de usuario heredado.
- Trata el control sobre el entorno de un objetivo como equivalente a la ejecución de código para cualquier Vim/Neovim que inicie.

## References

- [1] [Documentación de Vim — `starting.txt` (inicialización, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
