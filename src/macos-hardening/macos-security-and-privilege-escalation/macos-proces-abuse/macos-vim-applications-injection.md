# Inyección en aplicaciones de macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

El propio lenguaje de scripting de Vim (Vimscript) puede ejecutar **comandos Ex y comandos de shell arbitrarios al inicio** desde variables de entorno. Si un proceso con más privilegios (un flujo de mantenimiento/root, un `sudo vim …`, un editor iniciado por otra herramienta, `crontab -e`, `visudo`, `git`/`less` que invoquen un editor, …) inicia Vim/Neovim con un entorno controlado por el atacante, este obtiene ejecución de código en ese contexto.

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

`VIMINIT` se interpreta como **una sola línea de comando Ex**. Separa una cadena con `|` (o un salto de línea literal). Tiene precedencia sobre el vimrc del usuario y `EXINIT`, así que un payload no necesita un archivo de configuración malicioso y se ejecuta antes de la configuración normal del usuario.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Si `VIMINIT` no está definido, Vim (y los binarios de compatibilidad `vi`/`ex`) recurre a **`EXINIT`**, que se ejecuta del mismo modo. Es la variante clásica de la era de vi de la misma primitiva.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## rc local del proyecto con Vim `exrc`

Esta es una alternativa a `VIMINIT` basada en archivos. Si la víctima ha habilitado `set exrc` en su configuración de usuario, Vim también carga `.vimrc` (luego `_vimrc` o `.exrc`) desde su **directorio de trabajo**, no solo desde el directorio del archivo que se está editando. Coloca un `.vimrc` local del proyecto y haz que la víctima inicie Vim desde ese proyecto. En Unix, Vim aplica restricciones `secure` a un rc local propiedad de otra persona, pero un archivo comprimido que la víctima extrae normalmente asigna al archivo colocado la propiedad de la víctima y evita esa comprobación.<sup>[[1]](#references)</sup>

Este marcador aislado muestra el activador de inicio sin modificar la configuración real del usuario:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim es diferente: las versiones actuales requieren que se confíe en los archivos locales del proyecto `.nvim.lua`, `.nvimrc` o `.exrc` antes de ejecutarlos. La confianza se basa en el hash del contenido del archivo, así que cambiar un archivo en el que ya se confía requiere otra decisión de confianza. Un atacante que solo pueda colocar un archivo en un repositorio no puede dar por sentado que se ejecutará silenciosamente mediante `exrc`; distingue esta vía opcional, sujeta a confianza, de la vía `require()` de Lua desde el directorio actual que se describe más abajo.<sup>[[4]](#references)[[5]](#references)</sup>

Para un vimrc de **usuario** modificable, en lugar de uno local al proyecto, consulta [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Supresión del inicio y explotabilidad

Esta primitiva depende de un **inicio normal**. `vim -u NONE` / `nvim -u NONE` omiten la inicialización del entorno y del usuario (y los plugins), mientras que `-u <file>` usa ese archivo en su lugar. Vim `-es`/`-Es` y Neovim `-es`, `-Es` o `-l` también omiten estos pasos de inicialización. No confundas `--headless` con un modo seguro: un inicio normal de Neovim en modo headless todavía procesa `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Por consiguiente, valida toda la cadena de inicio: la variable debe sobrevivir al wrapper, a la política de `sudo`, al ejecutor de tareas y a la selección del editor, y el comando final no debe forzar `-u NONE`/`NORC` ni el modo por lotes. Una carga útil fiable puede terminar por sí sola con `|qall!`, lo que también facilita probar wrappers que no proporcionan un TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Secuestro de módulos Lua de Neovim desde el directorio actual

Una primitiva de inyección distinta de Neovim afecta a las versiones cuya `package.path`/`package.cpath` de Lua todavía contienen plantillas del directorio actual, como `./?.lua` o `./?.so`. Iniciar Neovim por sí solo no basta: una configuración o un plugin debe llamar a `require("name")`, y ningún cargador anterior debe resolver ese nombre. Un desencadenante habitual es una **comprobación de dependencia opcional**, como `pcall(require, "optional_dep")`; colocar `optional_dep.lua` en un directorio de trabajo controlado por el atacante hace que se ejecute sin habilitar la función independiente de configuración local `'exrc'`. Por lo general, los módulos principales `vim.*` y los módulos encontrados en `'runtimepath'` no se pueden suplantar, así que enumera las llamadas reales a `require()` de módulos ausentes u opcionales en vez de adivinar nombres.<sup>[[3]](#references)</sup>

Lo siguiente reproduce la primitiva del cargador con un marcador inofensivo:<sup>[[3]](#references)</sup>

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

Comprueba la compilación en ejecución en lugar de basarte únicamente en una cadena de versión:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream sigue la eliminación del mecanismo alternativo del directorio actual durante el inicio normal del editor, conservando el comportamiento de los scripts Lua (`nvim -l`). Hasta que la versión instalada deje de ofrecerlo, coloca esto al **inicio** de `init.lua` (elimina intencionalmente las plantillas relativas de módulos Lua/C del directorio actual, así que no lo apliques a flujos de trabajo que las requieran):<sup>[[3]](#references)</sup>

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

- **Neovim** respeta tanto `VIMINIT` como la alternativa `EXINIT`, pero su configuración de usuario habitual es `init.vim` o `init.lua`.<sup>[[2]](#references)</sup>
- La ruta mediante variables de entorno no requiere un archivo modificable. El rc local y el secuestro de módulos del directorio actual son primitivas distintas que requieren archivos.<sup>[[1]](#references)[[3]](#references)</sup>
- Los archivos rc locales del proyecto son distintos de los modelines y de la alternativa de `require()` basada en el directorio actual descrita arriba. Vim y Neovim tienen comprobaciones diferentes para ellos; consulta el flujo de trabajo `exrc` local del proyecto descrito arriba.<sup>[[1]](#references)[[4]](#references)</sup>
- Las variables de selección del editor solo determinan qué programa se inicia; no garantizan que `VIMINIT` llegue al proceso final. Inspecciona el entorno y los argumentos exactos en el límite de `exec` de Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Mitigación

- Elimina explícitamente las variables antes de iniciar un editor con privilegios o automatizado: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` es importante cuando quien lo inicia debe ignorar todas las fuentes de inicio del usuario.<sup>[[1]](#references)[[2]](#references)</sup>
- Configura `EDITOR`/`VISUAL` con rutas absolutas de confianza, evita ejecutar editores interactivos como root con un entorno de usuario heredado y asegúrate de que los wrappers no puedan restaurar `VIMINIT`/`EXINIT` después de la sanitización.<sup>[[1]](#references)[[2]](#references)</sup>
- Para Neovim, actualiza a una compilación que elimine las plantillas de búsqueda Lua/C del directorio actual durante el modo editor, o quítalas antes de cargar plugins. Audita el código de los plugins para detectar llamadas opcionales a `pcall(require, ...)` al abrir repositorios que no sean de confianza.<sup>[[3]](#references)</sup>
- Considera que controlar el entorno del editor, el directorio de trabajo o la configuración de inicio de un objetivo puede constituir una primitiva de ejecución de código dentro del contexto de seguridad del editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentación de Vim — `starting.txt` (inicialización, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentación de Neovim — inicio e inicialización](https://neovim.io/doc/user/starting/)
- [3] [Incidencia #38966 de Neovim — alternativa de `require()` basada en el directorio actual](https://github.com/neovim/neovim/issues/38966)
- [4] [Opciones de Neovim — `exrc` local del proyecto y requisito de confianza](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Edición en Neovim — archivos de confianza y `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
