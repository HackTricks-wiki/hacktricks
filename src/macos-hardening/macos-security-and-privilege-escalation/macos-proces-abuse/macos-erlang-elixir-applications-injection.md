# macOS Erlang および Elixir Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`、`ERL_FLAGS`、および `ERL_ZFLAGS`

`erl` launcher は `ERL_AFLAGS` をコマンドラインの先頭に、`ERL_FLAGS` / `ERL_ZFLAGS` を末尾に追加します。`-eval` は VM の初期化中に Erlang expression を評価するため、これらの変数によって、意図された workload の前に fileless code execution を実行できます。<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir、Mix、Phoenix、および多くの Elixir releases は最終的に Erlang VM を起動するため、これらの flags を継承する可能性があります。正確な release wrapper を確認してください。VM arguments を再構築または sanitize する場合がある一方、一部の tooling は `ERL_AFLAGS`、`ERL_ZFLAGS`、または `ELIXIR_ERL_OPTIONS` を明示的にサポートしています。<sup>[[2]](#references)</sup>

ほとんどの file-backed techniques とは異なり、`-eval` payload には attacker-controlled file が必要ありません。trusted wrapper は runtime の起動前に、3 つすべての Erlang flag variables（Elixir の場合は `ELIXIR_ERL_OPTIONS` も）をクリアする必要があります。parser と ordering を完全に理解していない限り、個々の VM flags を allowlist しようとしないでください。

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases and VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
