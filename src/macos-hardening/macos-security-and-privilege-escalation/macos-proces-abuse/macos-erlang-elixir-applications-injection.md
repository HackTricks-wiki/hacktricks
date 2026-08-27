# macOS Erlang 및 Elixir Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS`, 및 `ERL_ZFLAGS`

`erl` launcher는 `ERL_AFLAGS`를 command line의 시작 부분에 추가하고 `ERL_FLAGS` / `ERL_ZFLAGS`를 끝에 추가합니다. `-eval`은 VM initialization 중에 Erlang expression을 평가하므로, 이러한 변수는 의도된 workload가 실행되기 전에 fileless code execution을 제공할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix 및 많은 Elixir release는 궁극적으로 Erlang VM을 시작하며 이러한 flag를 상속할 수 있습니다. 정확한 release wrapper를 확인하세요. wrapper가 VM arguments를 다시 빌드하거나 정리할 수 있으며, 일부 tooling은 `ERL_AFLAGS`, `ERL_ZFLAGS` 또는 `ELIXIR_ERL_OPTIONS`를 명시적으로 지원합니다.<sup>[[2]](#references)</sup>

대부분의 file-backed technique와 달리 `-eval` payload에는 attacker-controlled file이 필요하지 않습니다. 신뢰할 수 있는 wrapper는 runtime을 시작하기 전에 세 가지 Erlang flag variable 모두를 삭제해야 하며(Elixir의 경우 `ELIXIR_ERL_OPTIONS`도 포함), parser와 ordering을 완전히 이해하지 못한 상태에서 개별 VM flag를 allowlist에 추가하려고 하지 마세요.

## References

- [1] [`erl` command 및 environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases 및 VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
