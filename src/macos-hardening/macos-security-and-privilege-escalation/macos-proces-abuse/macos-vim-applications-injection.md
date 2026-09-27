# Inyección de aplicaciones de Vim/Neovim en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

El propio lenguaje de scripting de Vim (Vimscript) puede ejecutar **comandos Ex y comandos de shell arbitrarios al iniciarse** desde variables de entorno. Si un proceso con más privilegios (un flujo de mantenimiento/root, un `sudo vim …`, un editor iniciado por otra herramienta, `crontab -e`, `visudo`, `git`/`less` invocando un editor, …) inicia Vim/Neovim con un entorno controlado por un atacante, este obtiene ejecución de código en ese contexto.

## `VIMINIT`

Durante la inicialización, Vim lee y ejecuta los comandos Ex de **`VIMINIT`**. Los comandos Ex incluyen `:!cmd` (ejecutar un comando de shell) y `:call system(...)`, por lo que una sola variable permite la ejecución arbitraria antes de editar cualquier archivo.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
El `:qa!` introducido por stdin en el primer ejemplo solo cierra el editor después de que se haya ejecutado el payload; en un escenario real, la víctima puede abrir Vim normalmente.

`VIMINIT` se analiza como **una sola línea de comandos Ex**. Separa una cadena con `|` (o un salto de línea literal). Tiene prioridad sobre el vimrc del usuario y `EXINIT`, por lo que un payload no necesita un archivo de configuración malicioso y se ejecuta antes de la configuración normal del usuario.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Si `VIMINIT` no está configurado, Vim (y los binarios de compatibilidad `vi`/`ex`) recurre a **`EXINIT`**, que se ejecuta de la misma manera. Es la variante clásica de la era de vi de la misma primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Supresión del inicio y explotabilidad

Esta primitiva depende de un **inicio normal**. `vim -u NONE` / `nvim -u NONE` omiten la inicialización del entorno/usuario (y los plugins), mientras que `-u <file>` utiliza ese archivo en su lugar. Vim `-es`/`-Es` y Neovim `-es`, `-Es` o `-l` también omiten estos pasos de inicialización. No confundas `--headless` con un modo seguro: un inicio normal de Neovim en modo headless aún procesa `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

En consecuencia, valida la cadena de lanzamiento completa: la variable debe sobrevivir al wrapper, a la política de `sudo`, al job runner y a la selección del editor, y el comando final no debe forzar `-u NONE`/`NORC` ni el modo batch. Un payload fiable puede terminar por sí mismo con `|qall!`, lo que también facilita probar wrappers que no proporcionan un TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking de módulos Lua del directorio actual de Neovim

Una primitiva de injection independiente de Neovim afecta a las builds cuyo `package.path`/`package.cpath` de Lua todavía contiene plantillas del directorio actual, como `./?.lua` o `./?.so`. Iniciar Neovim por sí solo no es suficiente: una configuración o un plugin debe llamar a `require("name")`, y ningún loader anterior debe resolver ese nombre. Un trigger común es una **comprobación de dependencia opcional**, como `pcall(require, "optional_dep")`; colocar `optional_dep.lua` en un directorio controlado por el atacante hace que se ejecute sin habilitar la feature independiente de configuración local `'exrc'`. Los módulos principales `vim.*` y los módulos que ya se encuentran en `'runtimepath'` generalmente no pueden ser shadowed, por lo que debes enumerar las llamadas `require()` faltantes u opcionales reales en lugar de adivinar nombres.<sup>[[3]](#references)</sup>

Lo siguiente reproduce la primitiva del loader con un marcador inofensivo:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Comprueba la build en ejecución en lugar de confiar únicamente en una cadena de versión:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream realiza un seguimiento de la eliminación del fallback del directorio actual durante el inicio normal del editor, manteniendo al mismo tiempo el comportamiento de los scripts de Lua (`nvim -l`). Hasta que la build instalada deje de exponerlo, coloca esto al **inicio** de `init.lua` (elimina intencionadamente las plantillas relativas de módulos Lua/C del directorio actual, por lo que no debes aplicarlo a workflows que las requieran):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Notas y advertencias

- **Neovim** respeta tanto `VIMINIT` como el fallback `EXINIT`, pero su configuración de usuario normal es `init.vim` o `init.lua`.<sup>[[2]](#references)</sup>
- La ruta mediante variables de entorno no necesita ningún archivo escribible. El hijacking de rc local y de módulos del directorio actual son primitives independientes respaldadas por archivos.<sup>[[1]](#references)[[3]](#references)</sup>
- La configuración local del proyecto es una superficie distinta de los modelines. Con `'exrc'` habilitado en Vim, un vimrc/exrc local propiedad de otro usuario se ejecuta con las restricciones de `'secure'`; sin embargo, al extraer un archivo normalmente el archivo plantado pasa a ser propiedad de la víctima, anulando esta protección basada en la propiedad. Neovim también busca `.nvim.lua`, `.nvimrc` o `.exrc` cuando `'exrc'` está habilitado; no confundas este mecanismo opt-in con el fallback de `require()` al directorio actual mencionado anteriormente.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Las variables de selección del editor solo eligen qué programa se inicia; no garantizan que `VIMINIT` llegue al proceso final. Inspecciona el entorno y los argumentos exactos en el límite de exec de Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Elimina explícitamente las variables antes de iniciar editores privilegiados o automatizados: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` es importante cuando el caller debe ignorar todas las fuentes de inicio del usuario.<sup>[[1]](#references)[[2]](#references)</sup>
- Establece `EDITOR`/`VISUAL` en rutas absolutas de confianza, evita ejecutar editores interactivos como root con un entorno de usuario heredado y asegúrate de que los wrappers no puedan restaurar `VIMINIT`/`EXINIT` después de la sanitización.<sup>[[1]](#references)[[2]](#references)</sup>
- Para Neovim, actualiza a una build que elimine las plantillas de búsqueda Lua/C del directorio actual durante el modo editor, o elimínalas antes de cargar plugins. Audita el código de los plugins en busca de llamadas opcionales `pcall(require, ...)` al abrir repositorios no confiables.<sup>[[3]](#references)</sup>
- Trata el control sobre el entorno del editor, el directorio de trabajo o la configuración de inicio de un target como una posible primitive de ejecución de código dentro del security context del editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentación de Vim — `starting.txt` (inicialización, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentación de Neovim — inicio e inicialización](https://neovim.io/doc/user/starting/)
- [3] [Issue #38966 de Neovim — fallback del directorio actual en `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
