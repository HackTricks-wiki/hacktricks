# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

All'avvio, R carica i file di profilo di sistema e utente contenenti codice R. `R_PROFILE` seleziona il profilo di sistema e `R_PROFILE_USER` seleziona il profilo utente, consentendo a un ambiente ereditato di reindirizzare una delle due ricerche verso un file leggibile dall'attaccante.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` salta il profilo utente, `--no-site-file` salta il profilo del sito e `--vanilla` include entrambe le protezioni. R elabora prima i file di environment selezionati da `R_ENVIRON` e `R_ENVIRON_USER`, ma questi file impostano solo variabili; le variabili del profilo sono la primitiva per l'esecuzione diretta di codice arbitrario.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` e i library path

R collega i package separati da virgole presenti in `R_DEFAULT_PACKAGES` durante l'avvio. `Rscript` dà precedenza a `R_SCRIPT_DEFAULT_PACKAGES`. La combinazione di una delle due variabili con `R_LIBS`, `R_LIBS_USER` o `R_LIBS_SITE` può fare in modo che R trovi e carichi un package installato controllato dall'attacker; il relativo hook `.onLoad` o `.onAttach` viene eseguito automaticamente.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Questo richiede un pacchetto R installato strutturalmente valido, non semplicemente un file `.R` isolato. `--vanilla` non cancella le variabili ereditate direttamente, quindi un wrapper trusted deve rimuovere o sostituire anche le variabili relative al pacchetto predefinito e al percorso delle librerie, oltre a disabilitare i file di profilo.

## References

- [1] [Inizializzazione all'avvio di una sessione R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Installazione e amministrazione di R: pacchetti aggiuntivi](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
