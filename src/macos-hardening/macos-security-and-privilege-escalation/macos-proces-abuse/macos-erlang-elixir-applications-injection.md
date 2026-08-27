# Iniekcja do aplikacji macOS Erlang i Elixir

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` i `ERL_ZFLAGS`

Launcher `erl` dodaje `ERL_AFLAGS` na początku swojego wiersza poleceń, a `ERL_FLAGS` / `ERL_ZFLAGS` na jego końcu. Ponieważ `-eval` ocenia wyrażenie Erlang podczas inicjalizacji VM, zmienne te mogą zapewnić bezplikowe wykonanie kodu przed uruchomieniem docelowego workloadu.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix i wiele wydań Elixir ostatecznie uruchamia Erlang VM i może dziedziczyć te flagi. Potwierdź dokładny release wrapper: może on ponownie budować lub sanitizować argumenty VM, podczas gdy niektóre narzędzia jawnie obsługują `ERL_AFLAGS`, `ERL_ZFLAGS` lub `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

W przeciwieństwie do większości technik opartych na plikach payload `-eval` nie wymaga pliku kontrolowanego przez atakującego. Zaufany wrapper powinien wyczyścić wszystkie trzy zmienne flag Erlang (a w przypadku Elixir także `ELIXIR_ERL_OPTIONS`) przed uruchomieniem runtime; nie próbuj stosować allowlisty pojedynczych flag VM, chyba że parser i kolejność są w pełni zrozumiałe.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Wydania Elixir i opcje środowiskowe VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
