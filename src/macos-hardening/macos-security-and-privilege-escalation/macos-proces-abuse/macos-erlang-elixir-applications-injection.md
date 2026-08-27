# Uingizaji wa Applications za Erlang na Elixir

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS`, na `ERL_ZFLAGS`

Kianzishaji cha `erl` huongeza `ERL_AFLAGS` mwanzoni mwa command line yake na `ERL_FLAGS` / `ERL_ZFLAGS` mwishoni. Kwa kuwa `-eval` hutathmini expression ya Erlang wakati wa uanzishaji wa VM, variables hizi zinaweza kutoa fileless code execution kabla ya workload iliyokusudiwa.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix na releases nyingi za Elixir hatimaye huanzisha Erlang VM na huenda zikarithi flags hizi. Thibitisha wrapper halisi ya release: inaweza kuunda upya au kusafisha VM arguments, huku baadhi ya tooling ikiunga mkono waziwazi `ERL_AFLAGS`, `ERL_ZFLAGS`, au `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Tofauti na mbinu nyingi zinazotegemea faili, payload ya `-eval` haihitaji faili inayodhibitiwa na attacker. Wrapper inayoaminika inapaswa kufuta variables zote tatu za Erlang flag (pamoja na `ELIXIR_ERL_OPTIONS` kwa Elixir) kabla ya kuanzisha runtime; usijaribu kuruhusu VM flags mahususi pekee isipokuwa parser na mpangilio wake vimeeleweka kikamilifu.

## References

- [1] [`erl` command na environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases na VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
