# macOS Erlang और Elixir Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS`, और `ERL_ZFLAGS`

`erl` launcher अपनी command line की शुरुआत में `ERL_AFLAGS` और अंत में `ERL_FLAGS` / `ERL_ZFLAGS` जोड़ता है। क्योंकि `-eval` VM initialization के दौरान Erlang expression का evaluation करता है, ये variables intended workload से पहले fileless code execution प्रदान कर सकते हैं।<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix और कई Elixir releases अंततः Erlang VM शुरू करते हैं और इन flags को inherit कर सकते हैं। Exact release wrapper की पुष्टि करें: यह VM arguments को फिर से बना या sanitize कर सकता है, जबकि कुछ tooling स्पष्ट रूप से `ERL_AFLAGS`, `ERL_ZFLAGS` या `ELIXIR_ERL_OPTIONS` को support करती है।<sup>[[2]](#references)</sup>

अधिकांश file-backed techniques के विपरीत, `-eval` payload को attacker-controlled file की आवश्यकता नहीं होती। एक trusted wrapper को runtime शुरू करने से पहले सभी तीन Erlang flag variables (और Elixir के लिए `ELIXIR_ERL_OPTIONS`) clear कर देने चाहिए; individual VM flags को allowlist करने का प्रयास न करें, जब तक parser और ordering पूरी तरह समझ में न हों।

## References

- [1] [`erl` command और environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases और VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
