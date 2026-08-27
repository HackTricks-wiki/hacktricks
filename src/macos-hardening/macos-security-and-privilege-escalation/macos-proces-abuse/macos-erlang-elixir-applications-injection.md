# macOS Erlang 和 Elixir Applications 注入

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`、`ERL_FLAGS` 和 `ERL_ZFLAGS`

`erl` launcher 会将 `ERL_AFLAGS` 添加到其命令行的开头，并将 `ERL_FLAGS` / `ERL_ZFLAGS` 添加到末尾。由于 `-eval` 会在 VM 初始化期间计算 Erlang 表达式，这些变量可以在预期 workload 执行之前提供 fileless code execution。<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir、Mix、Phoenix 以及许多 Elixir releases 最终都会启动 Erlang VM，并可能继承这些 flags。确认确切的 release wrapper：它可能会重新构建或清理 VM arguments，而某些 tooling 会显式支持 `ERL_AFLAGS`、`ERL_ZFLAGS` 或 `ELIXIR_ERL_OPTIONS`。<sup>[[2]](#references)</sup>

与大多数基于文件的技术不同，`-eval` payload 不需要攻击者控制的文件。受信任的 wrapper 应在启动 runtime 前清除全部三个 Erlang flag 变量（对于 Elixir，还应清除 `ELIXIR_ERL_OPTIONS`）；除非完全理解 parser 和 ordering，否则不要尝试对单个 VM flags 进行 allowlist。

## References

- [1] [`erl` 命令和环境变量](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases 和 VM 环境选项](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
