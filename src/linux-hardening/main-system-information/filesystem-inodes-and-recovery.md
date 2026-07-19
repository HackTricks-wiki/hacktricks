# Filesystem, Inodes na Recovery

{{#include ../../banners/hacktricks-training.md}}

Abuse ya Filesystem mara nyingi huhusu kuchanganya uhusiano kati ya path inayoonekana na object iliyo nyuma yake. Disk images zinaweza kuficha filesystem nyingine, mounts zinazoweza kuandikwa zinaweza kutumiwa na kazi zenye privileges, hardlinks zinaweza kufichua inode ileile kupitia jina tofauti, na files zilizofutwa zinaweza bado kusomeka kupitia open file descriptor.

Ukurasa huu unalenga technique yenyewe, si lab au target maalum.

## Disk Images na Loop Mounts

File ya kawaida inaweza kuwa na filesystem kamili. Hivyo, backup images, block devices zilizonakiliwa, VM artifacts, au blobs zilizopewa majina mengine zinaweza kuwa na credentials, scripts, SSH keys, configuration files, au flags hata kama hazionekani kuwa na manufaa kwa nje.

Tambua images zinazowezekana:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ikiwa mounting inaruhusiwa, mount images zisizojulikana katika hali ya read-only kwanza:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ikiwa mounting haipatikani, kagua metadata ya mfumo wa faili moja kwa moja:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Mbinu hii ni muhimu kwa sababu hubadilisha faili inayoonekana kuwa ya kawaida kuwa mti wa pili wa filesystem. Ichukulie kama njia ya kurejesha data iliyofichwa, si kama privilege escalation yenyewe.

## Writable Mount Abuse

Mount inayoweza kuandikwa huwa hatari wakati context yenye privileges zaidi baadaye inapoamini kitu kilicho ndani yake. Swali muhimu si tu "naweza kuandika hapa?", bali "ni nani baadaye atasoma, kutekeleza, ku-import, au kupakia kutoka hapa?".

Tafuta mounts zinazoweza kuandikwa na watumiaji wanaotiliwa shaka:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Mifumo ya kawaida ya matumizi mabaya:

- Cron au systemd unit yenye mapendeleo huendesha script inayoweza kuandikwa kutoka kwenye mount.
- Huduma yenye mapendeleo hupakia plugins, config, templates, au helper binaries kutoka kwenye mount.
- Mount ina faili za SUID na inaruhusu kurekebishwa, kubadilishwa, au kufanyiwa path manipulation.
- Container au chroot hufichua path inayoungwa mkono na host na inayoweza kuandikwa kutoka kwenye mazingira yenye vizuizi.

Muundo wa jumla wa validation:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Unapothibitisha athari katika labu iliyoidhinishwa, fanya payload ionekane na iwe ndogo, kwa mfano kwa kuandika matokeo ya `id` kwenye faili la muda. Mbinu kuu ni utekelezaji uliocheleweshwa kupitia eneo linaloaminika na linaloweza kuandikwa.

## Inode na Mkanganyiko wa Njia

Inode ni object ya filesystem; path ni jina linaloielekeza tu. Hili ni muhimu kwa sababu paths mbili tofauti zinaweza kuelekeza kwenye inode ileile, na pathname iliyofutwa haimaanishi kila mara kwamba data imeondoka.

Linganisha files kwa kutumia inode na device:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Tafuta kila pathname inayoonekana ya inode ileile:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Tafuta moja kwa moja kwa nambari ya inode unapokuwa na metadata pekee:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Mbinu hii ni muhimu wakati faili inaonekana chini ya jina lisilotarajiwa, wakati application inathibitisha path moja lakini inatumia nyingine, au wakati wrapper yenye privileged inashirikiana na inode ambayo pia inaweza kufikiwa mahali pengine.

## Hardlink Abuse

Hardlinks huunda majina mengi kwa inode moja. Hazielekezi kwenye target path kama symlinks; ni majina yaliyo sawa ya file object hiyo hiyo.

Tafuta faili za SUID zilizo na hardlinks nyingi:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Chunguza faili moja linalotiliwa shaka:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Kwa nini ni muhimu:

- Faili nyeti inaweza kufikiwa kupitia njia isiyo dhahiri.
- SUID wrapper inaweza kufichwa nyuma ya jina lisiloonekana kuwa na ruhusa za juu.
- Usafishaji unaoondoa pathname moja unaweza kuacha hardlink nyingine ikiwa hai.

Kernels za kisasa na mount options zinaweza kuzuia uundaji wa hardlink ili kupunguza aina hii ya matumizi mabaya, lakini hardlink zilizopo bado zinafaa kuchunguzwa.

## Recovery ya Faili Zilizofutwa Kupitia Open FDs

Mchakato unapoweka faili ikiwa imefunguliwa, data ya faili inaweza kuendelea kupatikana hata baada ya pathname kufutwa. Linux huonyesha descriptors hizo zilizo wazi chini ya `/proc/<pid>/fd/`.

Tafuta faili zilizofutwa zilizo wazi:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Rejesha data wakati ruhusa zinaruhusu:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Hii ni mbinu ya kiutendaji ya kurejesha logs zilizofutwa, secrets za muda, binaries zilizoachwa, files zilizozungushwa, au scripts zilizoondolewa baada ya kutekelezwa.

## Urejeshaji wa ext Kwa kutumia debugfs

Kwenye filesystems za ext, `debugfs` inaweza kukagua metadata ya inode na wakati mwingine kutoa maudhui ya file kutoka kwenye filesystem image. Fanya kazi kwenye copy au image ya kusomeka pekee inapowezekana.

Orodhesha entries na kagua inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump inode inayojulikana:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Hii si ahadi ya kurejesha data. Inategemea hali ya filesystem, ikiwa blocks zilitumiwa tena, na ikiwa metadata bado ipo. Mbinu hii bado ni muhimu kwa sababu hukuwezesha kukagua hali ya kiwango cha inode bila kutegemea path traversal ya kawaida.

## Kuishiwa kwa Inode na Mpangilio

Kuishiwa kwa inode hutokea filesystem inapoishiwa na file objects hata kama bado kuna nafasi ya kutosha kwenye diski. Kwa kawaida husababisha hitilafu za reliability, lakini pia kunaweza kueleza tabia zisizo za kawaida wakati wa incident response au lab triage.

Kagua shinikizo la inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Nambari za inode na mihuri ya muda zinaweza pia kusaidia kuunda upya shughuli katika mazingira rahisi ya maabara:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Chukulia mpangilio kama kidokezo, si uthibitisho. Operesheni za kunakili, uchimbaji wa archive, aina ya mfumo wa faili, urejeshaji, na uandishi wa wakati mmoja vinaweza kubadilisha mifumo ya ugawaji.

## Vidokezo vya Ulinzi

- Fanya mount ya images zisizojulikana katika hali ya kusoma pekee wakati wa uchanganuzi.
- Weka scripts zenye privileged access, service units, plugins, na njia za wasaidizi nje ya mounts zinazoweza kuandikwa na watumiaji.
- Tumia `nosuid`, `nodev`, na `noexec` pale inapofaa kiutendaji, lakini usizichukulie kama mpaka kamili.
- Zuia ufikiaji wa `/proc/<pid>/fd`, metadata ya michakato, na ukaguzi wa michakato ya watumiaji wengine inapowezekana.
- Fuatilia mount points zinazoweza kuandikwa, hardlinks zisizotarajiwa zinazoelekeza kwenye faili za privileged, na faili nyeti zilizofutwa lakini bado ziko wazi.
{{#include ../../banners/hacktricks-training.md}}
