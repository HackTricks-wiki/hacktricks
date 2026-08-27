# Inyección en aplicaciones Erlang y Elixir de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` y `ERL_ZFLAGS`

El launcher `erl` añade `ERL_AFLAGS` al principio de su línea de comandos y `ERL_FLAGS` / `ERL_ZFLAGS` al final. Dado que `-eval` evalúa una expresión de Erlang durante la inicialización de la VM, estas variables pueden proporcionar ejecución de código sin archivos antes de la carga de trabajo prevista.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix y muchas releases de Elixir finalmente inician la Erlang VM y pueden heredar estos flags. Confirma el wrapper exacto de la release: puede reconstruir o sanear los argumentos de la VM, mientras que algunas herramientas admiten explícitamente `ERL_AFLAGS`, `ERL_ZFLAGS` o `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

A diferencia de la mayoría de las técnicas basadas en archivos, el payload de `-eval` no necesita ningún archivo controlado por el atacante. Un wrapper de confianza debería borrar las tres variables de flags de Erlang (y `ELIXIR_ERL_OPTIONS` para Elixir) antes de iniciar el runtime; no intentes aplicar una allowlist de flags individuales de la VM a menos que el parser y el orden de procesamiento se comprendan completamente.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases and VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
