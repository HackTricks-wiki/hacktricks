# Filesystem, Inodes na Urejeshaji

{{#include ../../banners/hacktricks-training.md}}

Abuse ya Filesystem mara nyingi huhusu kuchanganya uhusiano kati ya path inayoonekana na object iliyo nyuma yake.

Disk images zinaweza kuficha filesystem nyingine.<sup>[[1]](#references)</sup> Mounts zinazoweza kuandikwa zinaweza kutumiwa na kazi zenye privileges.

Hardlinks zinaweza kufichua inode ileile kupitia jina tofauti.<sup>[[3]](#references)</sup> Files zilizofutwa bado zinaweza kusomeka kupitia file descriptor iliyo wazi.<sup>[[5]](#references)[[6]](#references)</sup>

Ukurasa huu unalenga technique yenyewe, si lab au target maalum.

## Disk Images na Loop Mounts

File ya kawaida inaweza kuwa na filesystem kamili, hivyo disk image inaweza kufichua mti wa pili wa filesystem inapowekwa kama mount.<sup>[[1]](#references)</sup>

Backup images, vifaa vya block vilivyonakiliwa, VM artifacts, au blobs zilizopewa majina mapya kwa hiyo zinaweza kuwa na credentials, scripts, SSH keys, configuration files, au flags hata kama hazionekani kuwa na manufaa kwa nje.

Tambua images zinazowezekana kwa kutumia `file` ili kuainisha candidate, `blkid` ili kuchunguza metadata inayotambuliwa ya filesystem, na `strings -a` ili kuchanganua file lote kwa mfuatano unaoweza kuchapishwa.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Wakati mounting inaruhusiwa, tumia loop mount yenye `ro` ili image iambatishwe kwa hali ya kusoma pekee; amri ya `find` hapa chini inaweka kikomo cha kina cha ukaguzi na aina ya faili.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ikiwa mounting haipatikani na image ni ext2/ext3/ext4, kagua metadata yake moja kwa moja kwa kutumia `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Mbinu hii ni muhimu kwa sababu hugeuza faili inayoonekana ya kawaida kuwa mti wa pili wa filesystem.<sup>[[1]](#references)</sup> Ichukulie kama njia ya kurejesha data iliyofichwa, si kama privilege escalation yenyewe.

## Writable Mount Abuse

Writable mount huwa hatari wakati context yenye privileges zaidi baadaye inaamini kitu kilicho ndani yake. Swali muhimu si tu "naweza kuandika hapa?", bali "ni nani baadaye huisoma, hui-execute, hui-import, au huipakia kutoka hapa?".

Tumia `findmnt` kukagua filesystems zilizowekwa na options zake.<sup>[[9]](#references)</sup>

Tafuta mounts zinazoweza kuandikwa na consumers wanaotiliwa shaka kwa kutumia predicates za `find` zilizorekodiwa za permission, type, na mipaka ya filesystem, kisha tumia `grep` ya recursive kutafuta usanidi wa consumers wanaowezekana.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Mifumo ya kawaida ya matumizi mabaya:

- Kazi ya cron au service ya systemd huendesha script inayoweza kuandikwa kutoka kwenye mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Service yenye privileges nyingi hupakia plugins, config, templates, au helper binaries kutoka kwenye mount.
- Mount ina files za SUID na inaruhusu kurekebishwa, kubadilishwa, au kudhibitiwa kwa path.
- Container au chroot hufichua path inayotegemea host na inaweza kuandikwa kutoka kwenye mazingira yenye vikwazo. Mount namespaces hutoa mount hierarchies tofauti, huku `chroot()` ikibadilisha tu utatuzi wa pathname na si sandbox kamili.<sup>[[15]](#references)[[16]](#references)</sup>

Muundo wa jumla wa uthibitishaji unaotumia predicates zilezile za `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wakati wa kuthibitisha impact katika labu iliyoidhinishwa, weka payload iweze kuonekana na iwe ndogo, kwa mfano kwa kuandika matokeo ya `id` kwenye faili ya muda.<sup>[[23]](#references)</sup> Mbinu kuu ni utekelezaji uliocheleweshwa kupitia eneo linaloaminika na linaloweza kuandikwa.

## Inodes na Mkanganyiko wa Njia

Inode ni object ya filesystem; path ni jina tu linaloelekeza kwake. Metadata ya device na inode hukuwezesha kutofautisha objects katika filesystems mbalimbali, huku link counts zikifichua hard links nyingi.<sup>[[3]](#references)</sup> Pathname iliyofutwa haimaanishi kila mara kwamba data imeondoka ikiwa process bado imefungua file hiyo.<sup>[[5]](#references)</sup>

Predicates za `find` zilizo hapa chini hulinganisha utambulisho wa inode, link counts, mipaka ya device, na timestamps.<sup>[[4]](#references)</sup>

Linganisha files kwa kutumia inode na device kupitia `ls -i` na miundo ya metadata ya `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Tafuta kila pathname inayoonekana ya inode hiyo hiyo kwa kutumia `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Tafuta moja kwa moja kwa kutumia nambari ya inode kwa `find -inum` wakati una metadata pekee.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Mbinu hii ni muhimu wakati faili inaonekana kwa jina lisilotarajiwa, wakati application inathibitisha path moja lakini inatumia nyingine, au wakati wrapper yenye privileges inashughulikia inode ambayo pia inaweza kufikiwa mahali pengine.

## Hardlink Abuse

Hardlinks huunda majina mengi kwa inode moja. Hazielekezi kwenye target path kama symlinks; ni majina yanayolingana ya file object hiyo hiyo.<sup>[[3]](#references)</sup>

Tafuta faili za SUID zilizo na hardlinks nyingi kwa kutumia predicates za permissions na link-count za `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua faili moja linalotiliwa shaka kwa kutumia `stat` na `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Kwa nini ni muhimu:

- Faili nyeti inaweza kufikiwa kupitia path isiyo dhahiri.
- SUID wrapper inaweza kufichwa nyuma ya jina lisiloonekana kuwa na privileged access.
- Usafishaji unaoondoa pathname moja unaweza kuacha hardlink nyingine ikiwa hai.

Linux `fs.protected_hardlinks` sysctl inaweza kuzuia uundaji wa hardlink katika mipaka ya privileges.<sup>[[7]](#references)</sup> Hardlink zilizopo bado zinapaswa kuchunguzwa.

## Urejeshaji wa Faili Zilizofutwa Kupitia Open FDs

Mchakato unapoweka faili ikiwa wazi, kuondoa pathname yake ya mwisho huiweka faili hai hadi descriptor ya mwisho ifungwe; Linux huonyesha descriptors hizo chini ya `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Tafuta faili zilizofutwa lakini bado zikiwa wazi kwa kuorodhesha descriptors za `/proc` na kuchuja matokeo ya faili zilizo wazi.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Ku-recover kupitia links hizi kunategemea permissions, kwa sababu ku-dereference `/proc/<pid>/fd` kunakabiliwa na ukaguzi wa access wa ptrace na permissions za faili.<sup>[[6]](#references)</sup>

Inaporuhusiwa, `readlink` huonyesha target ya descriptor na `cp` hunakili yaliyomo.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Hii ni mbinu ya kivitendo ya kurejesha logs zilizofutwa, siri za muda, binaries zilizoondolewa, faili zilizozungushwa, au scripts zilizoondolewa baada ya kutekelezwa.

## Urejeshaji wa ext Kwa debugfs

Kwenye filesystems za ext2/ext3/ext4, `debugfs` inaweza kukagua metadata ya inode na kutoa yaliyomo kwenye inode kutoka kwenye block device au image; bila `-w`, hufungua filesystem katika hali ya kusoma-tu.<sup>[[2]](#references)</sup> Fanyia kazi nakala au image ya kusoma-tu inapowezekana.

Orodhesha entries na kagua inodes kwa kutumia requests za `debugfs` za kuorodhesha directory, kuonyesha hali ya inode, na kukagua uhusiano wa inode na path.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump inode inayojulikana kwa amri ya `debugfs dump`, kisha ainisha matokeo yaliyorejeshwa kwa kutumia `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Hii si recovery iliyohakikishwa. Inategemea hali ya filesystem, ikiwa blocks zilitumika tena, na ikiwa metadata bado ipo. Kwa ext3/ext4, mwongozo wa `debugfs` unaeleza kwamba recovery ya inode zilizofutwa inaweza kushindikana kwa sababu data blocks za inode zilizotolewa hazipatikani tena.<sup>[[2]](#references)</sup> Mbinu hii bado ni muhimu kwa sababu hukuwezesha kukagua hali ya kiwango cha inode bila kutegemea path traversal ya kawaida.

## Inode Exhaustion and Ordering

Inode exhaustion hutokea filesystem inapoishiwa file nodes hata kama nafasi ya diski iliyo huru bado ipo.<sup>[[8]](#references)[[17]](#references)</sup> Kwa kawaida husababisha hitilafu za reliability, lakini inaweza pia kueleza tabia zisizo za kawaida wakati wa incident response au lab triage.

Tumia `df -i` kuripoti taarifa za inode badala ya matumizi ya blocks.<sup>[[8]](#references)</sup>

Kagua inode pressure kwa kutumia `df` na hesabu ya `find` ya directory parents.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Nambari za inode na mihuri ya muda pia zinaweza kusaidia kujenga upya shughuli katika mazingira rahisi ya maabara.

Maelekezo ya umbizo la `find` hapa chini yanaonyesha sehemu hizo.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Chukulia mpangilio kama kidokezo, si uthibitisho. Operesheni za kunakili, uchanganuzi wa archive, aina ya filesystem, urejeshaji, na uandishi wa wakati mmoja zinaweza kubadilisha mifumo ya ugawaji.

## Maelezo ya Kihalifu

- Weka images zisizojulikana kwenye hali ya read-only wakati wa uchanganuzi.<sup>[[1]](#references)</sup>
- Weka scripts zenye privileged access, service units, plugins, na njia za helper nje ya mounts zinazoweza kuandikwa na users.
- Tumia `nosuid`, `nodev`, na `noexec` pale inapofaa kiutendaji; chaguo hizi huzima utekelezaji wa set-ID/capability, tafsiri ya vifaa, au utekelezaji wa binary za moja kwa moja kwenye mount.<sup>[[1]](#references)</sup> Usizichukulie kama boundary kamili.
- Zuia access kwa `/proc/<pid>/fd`; kufuatilia links hizo kunadhibitiwa na ptrace access checks na file permissions.<sup>[[6]](#references)</sup> Zuia metadata pana zaidi za process na ukaguzi wa processes za users wengine inapowezekana.
- Fuatilia mount points zinazoweza kuandikwa, hardlinks zisizotarajiwa zinazoelekeza kwenye files zenye privileged access, na files nyeti zilizofutwa lakini bado ziko wazi.

## References

- [1] [mount(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentation for /proc/sys/fs/ — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
