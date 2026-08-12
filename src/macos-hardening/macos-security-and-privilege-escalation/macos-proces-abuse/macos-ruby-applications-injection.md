# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby, bir scripti çalıştırmadan önce desteklenen command-line switch'leri `RUBYOPT` environment variable'ından ayrıştırır. Ruby, `RUBYOPT` içinde `-e` aracılığıyla code execution yapılmasını reddeder; ancak `-I` bir library-search directory'sini öne ekleyebilir ve `-r` bir library'yi require edebilir. Bu nedenle Ruby'yi attacker-controlled environment variables ile başlatan bir process, attacker-controlled Ruby code yüklemeye zorlanabilir.<sup>[[1]](#references)</sup>

`/tmp/inject.rb` oluşturun:
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
Bu davranışı devre dışı bırakmak için `--disable=rubyopt` (veya `--disable-rubyopt`) seçeneğini script adından **önce** belirtin:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` sonrasında yazılan bir seçenek, `ARGV` içinde script'e aktarılır; Ruby'nin `RUBYOPT` için daha önce gerçekleştirdiği işlemeyi devre dışı bırakmaz.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
