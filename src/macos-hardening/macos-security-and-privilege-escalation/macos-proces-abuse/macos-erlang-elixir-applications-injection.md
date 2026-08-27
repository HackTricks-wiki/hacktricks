# Injection u macOS Erlang i Elixir Applications

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` i `ERL_ZFLAGS`

`erl` launcher dodaje `ERL_AFLAGS` na početak svoje komandne linije, a `ERL_FLAGS` / `ERL_ZFLAGS` na kraj. Pošto `-eval` evaluira Erlang izraz tokom inicijalizacije VM-a, ove promenljive mogu omogućiti izvršavanje koda bez datoteke pre pokretanja predviđenog workload-a.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix i mnoga Elixir izdanja na kraju pokreću Erlang VM i mogu naslediti ove flagove. Potvrdite tačan release wrapper: može ponovo izgraditi ili sanitizovati VM argumente, dok neki alati eksplicitno podržavaju `ERL_AFLAGS`, `ERL_ZFLAGS` ili `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Za razliku od većine tehnika zasnovanih na fajlovima, `-eval` payload-u nije potreban fajl pod kontrolom napadača. Pouzdani wrapper treba da obriše sve tri Erlang promenljive za flagove (i `ELIXIR_ERL_OPTIONS` za Elixir) pre pokretanja runtime-a; nemojte pokušavati da napravite allowlist pojedinačnih VM flagova osim ako su parser i redosled u potpunosti shvaćeni.

## References

- [1] [`erl` komanda i promenljive okruženja](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir izdanja i VM opcije okruženja](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
