# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Beim Start lädt R Site- und Benutzerprofildateien, die R-Code enthalten. `R_PROFILE` legt das Site-Profil fest und `R_PROFILE_USER` das Benutzerprofil. Dadurch kann eine geerbte Umgebung die jeweilige Suche auf eine für den Angreifer lesbare Datei umleiten.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` überspringt das Benutzerprofil, `--no-site-file` überspringt das Site-Profil und `--vanilla` aktiviert beide Schutzmaßnahmen. R verarbeitet zunächst die durch `R_ENVIRON` und `R_ENVIRON_USER` ausgewählten Umgebungsdateien, aber diese Dateien setzen nur Variablen; die Profilvariablen sind das direkte Primitive für die Ausführung beliebigen Codes.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` und Library-Pfade

R hängt die durch Kommas getrennten Packages in `R_DEFAULT_PACKAGES` während des Starts an. `Rscript` gibt `R_SCRIPT_DEFAULT_PACKAGES` den Vorrang. Die Kombination einer dieser Variablen mit `R_LIBS`, `R_LIBS_USER` oder `R_LIBS_SITE` kann dazu führen, dass R ein vom Angreifer kontrolliertes installiertes Package findet und lädt; dessen `.onLoad`- oder `.onAttach`-Hook wird automatisch ausgeführt.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Dies erfordert ein strukturell gültiges installiertes R-Paket, nicht lediglich eine lose `.R`-Datei. `--vanilla` löscht direkt geerbte Variablen nicht; daher muss ein vertrauenswürdiger Wrapper die Variablen für Standardpakete und Bibliothekspfade ebenfalls aufheben oder ersetzen und zugleich Profildateien deaktivieren.

## References

- [1] [Initialisierung beim Start einer R-Sitzung](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R-Installation und -Administration: Zusatzpakete](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
