# Injeção em Aplicações Erlang e Elixir do macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` e `ERL_ZFLAGS`

O launcher `erl` adiciona `ERL_AFLAGS` ao início da linha de comando e `ERL_FLAGS` / `ERL_ZFLAGS` ao final. Como `-eval` avalia uma expressão Erlang durante a inicialização da VM, essas variáveis podem fornecer execução de código sem arquivos antes da carga de trabalho pretendida.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix e muitos releases do Elixir acabam iniciando a Erlang VM e podem herdar essas flags. Confirme o wrapper exato do release: ele pode reconstruir ou sanitizar os argumentos da VM, enquanto algumas ferramentas oferecem suporte explícito a `ERL_AFLAGS`, `ERL_ZFLAGS` ou `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Ao contrário da maioria das técnicas baseadas em arquivos, o payload de `-eval` não precisa de nenhum arquivo controlado pelo atacante. Um wrapper confiável deve limpar todas as três variáveis de flags do Erlang (e `ELIXIR_ERL_OPTIONS` para Elixir) antes de iniciar o runtime; não tente permitir individualmente as flags da VM, a menos que o parser e a ordenação sejam totalmente compreendidos.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Releases do Elixir e opções de ambiente da VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
