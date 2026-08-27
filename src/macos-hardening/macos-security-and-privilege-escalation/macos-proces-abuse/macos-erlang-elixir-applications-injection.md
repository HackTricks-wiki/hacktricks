# Injection в застосунки Erlang та Elixir у macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` та `ERL_ZFLAGS`

Launcher `erl` додає `ERL_AFLAGS` на початок командного рядка, а `ERL_FLAGS` / `ERL_ZFLAGS` — у його кінець. Оскільки `-eval` оцінює Erlang-вираз під час ініціалізації VM, ці змінні можуть забезпечити fileless code execution до запуску призначеного workload.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Elixir, Mix, Phoenix і багато релізів Elixir зрештою запускають Erlang VM і можуть успадковувати ці flags. Підтвердьте точну обгортку релізу: вона може перебудовувати або очищати аргументи VM, тоді як деякі інструменти явно підтримують `ERL_AFLAGS`, `ERL_ZFLAGS` або `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

На відміну від більшості технік із файлами, payload `-eval` не потребує файлу під контролем зловмисника. Довірена обгортка повинна очистити всі три змінні flags Erlang (і `ELIXIR_ERL_OPTIONS` для Elixir) перед запуском runtime; не намагайтеся дозволяти окремі flags VM, якщо ви повністю не розумієте parser і порядок їх обробки.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Релізи Elixir та параметри середовища VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
