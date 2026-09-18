# Injection do aplikacji Ruby w macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby parsuje obsługiwane przełączniki wiersza poleceń ze zmiennej środowiskowej `RUBYOPT` przed uruchomieniem skryptu. Ruby odrzuca wykonywanie kodu przez `-e` w `RUBYOPT`, ale `-I` może dodać katalog wyszukiwania bibliotek, a `-r` może załadować bibliotekę. Proces uruchamiający Ruby ze zmiennymi środowiskowymi kontrolowanymi przez atakującego może zatem zostać zmuszony do załadowania kontrolowanego przez atakującego kodu Ruby.<sup>[[1]](#references)</sup>

Utwórz `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Utwórz nieszkodliwy skrypt Ruby, taki jak `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Uruchom go z kontrolowaną wartością `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Aby wyłączyć to zachowanie, przekaż `--disable=rubyopt` (lub `--disable-rubyopt`) **przed** nazwą skryptu:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Opcja zapisana po `hello.rb` jest przekazywana do skryptu w `ARGV`; nie wyłącza wcześniejszego przetwarzania `RUBYOPT` przez Ruby.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Zamiast dodawać katalog ładowania za pomocą `-I` wewnątrz `RUBYOPT`, oddzielna zmienna środowiskowa `RUBYLIB` dodaje katalogi do zmiennej Ruby `$LOAD_PATH`. W połączeniu z `RUBYOPT=-r<module>` ładuje kod atakującego bez konieczności używania `-I` w `RUBYOPT`:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Dokumentacja Ruby - opcje wiersza poleceń Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
