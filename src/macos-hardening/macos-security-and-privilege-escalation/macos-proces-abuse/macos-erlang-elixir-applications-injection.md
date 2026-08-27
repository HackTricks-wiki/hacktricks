# macOS Erlang and Elixir Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS`, and `ERL_ZFLAGS`

The `erl` launcher adds `ERL_AFLAGS` to the beginning of its command line and `ERL_FLAGS` / `ERL_ZFLAGS` to the end. Because `-eval` evaluates an Erlang expression during VM initialization, these variables can provide fileless code execution before the intended workload.<sup>[[1]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix and many Elixir releases ultimately start the Erlang VM and may inherit these flags. Confirm the exact release wrapper: it may rebuild or sanitize VM arguments, while some tooling explicitly supports `ERL_AFLAGS`, `ERL_ZFLAGS`, or `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Unlike most file-backed techniques, the `-eval` payload needs no attacker-controlled file. A trusted wrapper should clear all three Erlang flag variables (and `ELIXIR_ERL_OPTIONS` for Elixir) before starting the runtime; do not try to allowlist individual VM flags unless the parser and ordering are fully understood.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases and VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)

{{#include ../../../banners/hacktricks-training.md}}
