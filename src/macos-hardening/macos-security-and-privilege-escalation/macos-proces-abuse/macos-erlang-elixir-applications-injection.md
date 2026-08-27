# macOS Erlang- en Elixir-toepassingsinspuiting

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` en `ERL_ZFLAGS`

Die `erl`-lanseerder voeg `ERL_AFLAGS` aan die begin van sy opdragreël en `ERL_FLAGS` / `ERL_ZFLAGS` aan die einde by. Omdat `-eval` 'n Erlang-uitdrukking tydens VM-inisialisering evalueer, kan hierdie veranderlikes lêerlose kode-uitvoering verskaf voordat die beoogde werklading begin.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix en baie Elixir releases begin uiteindelik die Erlang VM en kan hierdie flags erf. Bevestig die presiese release wrapper: dit kan VM-argumente herbou of sanitiseer, terwyl sommige tooling uitdruklik `ERL_AFLAGS`, `ERL_ZFLAGS` of `ELIXIR_ERL_OPTIONS` ondersteun.<sup>[[2]](#references)</sup>

Anders as die meeste file-backed techniques, benodig die `-eval` payload geen attacker-controlled file nie. ’n Trusted wrapper behoort al drie Erlang flag variables (en `ELIXIR_ERL_OPTIONS` vir Elixir) skoon te maak voordat die runtime begin word; moenie probeer om individuele VM flags te allowlist tensy die parser en ordering volledig verstaan word nie.

## References

- [1] [`erl`-command en environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases en VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
