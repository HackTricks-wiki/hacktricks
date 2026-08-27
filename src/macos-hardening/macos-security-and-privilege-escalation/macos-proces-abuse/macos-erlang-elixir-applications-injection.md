# Iniezione nelle applicazioni Erlang ed Elixir su macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` e `ERL_ZFLAGS`

Il launcher `erl` aggiunge `ERL_AFLAGS` all'inizio della riga di comando e `ERL_FLAGS` / `ERL_ZFLAGS` alla fine. Poiché `-eval` valuta un'espressione Erlang durante l'inizializzazione della VM, queste variabili possono consentire l'esecuzione di codice fileless prima del carico di lavoro previsto.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix e molte release di Elixir avviano infine la Erlang VM e possono ereditare questi flag. Confermare l'esatto release wrapper: potrebbe ricostruire o sanificare gli argomenti della VM, mentre alcuni strumenti supportano esplicitamente `ERL_AFLAGS`, `ERL_ZFLAGS` o `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

A differenza della maggior parte delle tecniche basate su file, il payload `-eval` non richiede alcun file controllato dall'attaccante. Un wrapper fidato dovrebbe cancellare tutte e tre le variabili dei flag Erlang (e `ELIXIR_ERL_OPTIONS` per Elixir) prima di avviare il runtime; non cercare di creare un'allowlist dei singoli flag della VM, a meno che il parser e l'ordinamento non siano completamente compresi.

## References

- [1] [`erl` command e variabili d'ambiente](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Release di Elixir e opzioni dell'ambiente della VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
