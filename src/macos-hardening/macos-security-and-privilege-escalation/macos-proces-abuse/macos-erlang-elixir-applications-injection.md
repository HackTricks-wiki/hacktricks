# Injection in macOS-Erlang- und Elixir-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` und `ERL_ZFLAGS`

Der `erl`-Launcher fügt `ERL_AFLAGS` am Anfang seiner Befehlszeile und `ERL_FLAGS` / `ERL_ZFLAGS` am Ende ein. Da `-eval` während der VM-Initialisierung einen Erlang-Ausdruck auswertet, können diese Variablen eine dateilose Codeausführung vor der vorgesehenen Verarbeitung ermöglichen.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix und viele Elixir-Releases starten letztlich die Erlang VM und übernehmen möglicherweise diese Flags. Bestätige den genauen Release-Wrapper: Er kann VM-Argumente neu erstellen oder bereinigen, während einige Tools `ERL_AFLAGS`, `ERL_ZFLAGS` oder `ELIXIR_ERL_OPTIONS` ausdrücklich unterstützen.<sup>[[2]](#references)</sup>

Im Gegensatz zu den meisten dateibasierten Techniken benötigt die `-eval`-Payload keine vom Angreifer kontrollierte Datei. Ein vertrauenswürdiger Wrapper sollte alle drei Erlang-Flag-Variablen (und bei Elixir `ELIXIR_ERL_OPTIONS`) löschen, bevor die Runtime gestartet wird. Versuche nicht, einzelne VM-Flags allowzulisten, sofern Parser und Reihenfolge nicht vollständig verstanden wurden.

## References

- [1] [`erl`-Befehl und Umgebungsvariablen](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir-Releases und VM-Umgebungsoptionen](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
