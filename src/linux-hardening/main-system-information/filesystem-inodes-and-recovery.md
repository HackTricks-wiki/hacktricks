# Mfumo wa Faili, Inode na Urejeshaji

{{#include ../../banners/hacktricks-training.md}}

Matumizi mabaya ya mfumo wa faili mara nyingi yanahusu kuchanganya uhusiano kati ya path inayoonekana na object iliyo nyuma yake. Disk images zinaweza kuficha mfumo mwingine wa faili, mounts zinazoweza kuandikwa zinaweza kutumiwa na kazi zenye privileged access, hardlinks zinaweza kufichua inode ileile kupitia jina tofauti, na files zilizofutwa zinaweza bado kusomeka kupitia file descriptor iliyo wazi.

Ukurasa huu unalenga technique, si lab au target mahususi.

## Disk Images na Loop Mounts

File ya kawaida inaweza kuwa na mfumo kamili wa faili. Kwa hiyo, backup images, block devices zilizonakiliwa, VM artifacts, au blobs zilizopewa majina mapya zinaweza kuwa na credentials, scripts, SSH keys, configuration files, au flags hata kama hazionekani kuwa na manufaa kwa nje.

Tambua images zinazowezekana:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ikiwa mounting inaruhusiwa, mount images zisizojulikana katika hali ya kusoma-tu kwanza:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Ikiwa mounting haipatikani, kagua metadata ya filesystem moja kwa moja:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Mbinu hii ni muhimu kwa sababu hubadilisha faili inayoonekana kuwa ya kawaida kuwa mti wa pili wa filesystem. Ichukulie kama njia ya kurejesha data iliyofichwa, si kama privilege escalation yenyewe.

## Writable Mount Abuse

Mount inayoweza kuandikwa huwa hatari wakati context yenye privileges zaidi inapokuja kuamini kitu kilicho ndani yake. Swali muhimu si tu "naweza kuandika hapa?", bali pia "ni nani atakayesoma, kutekeleza, ku-import, au kupakia kutoka hapa baadaye?".

Tafuta mounts zinazoweza kuandikwa na watumiaji wa kutiliwa shaka:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Mifumo ya kawaida ya matumizi mabaya:

- cron au systemd unit yenye privileges huendesha script inayoweza kuandikwa kutoka kwenye mount.
- Service yenye privileges hupakia plugins, config, templates, au helper binaries kutoka kwenye mount.
- Mount ina files za SUID na inaruhusu kurekebishwa, kubadilishwa, au path manipulation.
- Container au chroot hufichua path inayoungwa mkono na host na inayoweza kuandikwa kutoka kwenye restricted environment.

Muundo wa jumla wa validation:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Unapothibitisha impact katika lab iliyoidhinishwa, weka payload ikiwa observable na minimal, kwa mfano kwa kuandika output ya `id` kwenye faili la muda. Mbinu kuu ni delayed execution kupitia eneo linaloaminika na linaloweza kuandikwa.

## Inodes na Kuchanganyikiwa kwa Path

Inode ni filesystem object; path ni jina tu linaloielekeza. Hili ni muhimu kwa sababu paths mbili tofauti zinaweza kuelekeza kwenye inode moja, na pathname iliyofutwa haimaanishi kila wakati kwamba data imeondoka.

Linganisha files kwa kutumia inode na device:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Tafuta kila pathname inayoonekana ya inode ileile:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Tafuta moja kwa moja kwa kutumia nambari ya inode unapokuwa na metadata pekee:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Mbinu hii ni muhimu wakati faili inaonekana chini ya jina lisilotarajiwa, wakati application inathibitisha path moja lakini inatumia nyingine, au wakati wrapper yenye privileged inashughulikia inode ambayo pia inaweza kufikiwa kutoka sehemu nyingine.

## Hardlink Abuse

Hardlinks huunda majina mengi ya inode moja. Hazielekezi kwenye target path kama symlinks; ni majina yanayolingana ya file object hiyo hiyo.

Tafuta faili za SUID zilizo na hardlinks nyingi:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua faili moja linalotiliwa shaka:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Kwa nini ni muhimu:

- Faili nyeti inaweza kufikiwa kupitia njia isiyo dhahiri.
- SUID wrapper inaweza kufichwa nyuma ya jina lisiloonekana kuwa la privileged.
- Usafishaji unaoondoa pathname moja unaweza kuacha hardlink nyingine ikiwa hai.

Kernels za kisasa na mount options zinaweza kuzuia uundaji wa hardlink ili kupunguza aina hii ya matumizi mabaya, lakini hardlink zilizopo bado zinafaa kukaguliwa.

## Urejeshaji wa Faili Zilizofutwa Kupitia Open FDs

Mchakato unapoweka faili ikiwa wazi, data ya faili inaweza kubaki inapatikana hata baada ya pathname kufutwa. Linux huonyesha descriptors hizo zilizo wazi chini ya `/proc/<pid>/fd/`.

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
Hii ni mbinu ya vitendo ya kurejesha logs zilizofutwa, secrets za muda, binaries zilizoangushwa, files zilizozungushwa, au scripts zilizoondolewa baada ya kutekelezwa.

## Urejeshaji wa ext Kwa kutumia debugfs

Kwenye filesystems za ext, `debugfs` inaweza kukagua metadata ya inode na wakati mwingine kutoa maudhui ya file kutoka kwenye filesystem image. Fanyia kazi nakala au image ya kusomeka tu inapowezekana.

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
Hii si recovery iliyohakikishwa. Inategemea hali ya filesystem, iwapo blocks zilitumika tena, na iwapo metadata bado ipo. Mbinu hii bado ni muhimu kwa sababu hukuruhusu kukagua hali ya kiwango cha inode bila kutegemea path traversal ya kawaida.

## Kuisha kwa Inode na Mpangilio

Kuisha kwa inode hutokea wakati filesystem inaishiwa na file objects hata kama bado kuna nafasi ya diski iliyo wazi. Kwa kawaida husababisha hitilafu za reliability, lakini pia inaweza kueleza tabia isiyo ya kawaida wakati wa incident response au lab triage.

Kagua inode pressure:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Nambari za inode na timestamps pia zinaweza kusaidia kuunda upya shughuli katika mazingira rahisi ya maabara:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Chukulia mpangilio kama kidokezo, si uthibitisho. Operesheni za kunakili, uchimbuaji wa archive, aina ya filesystem, kurejesha data, na uandishi wa wakati mmoja zinaweza kubadilisha mifumo ya ugawaji.

## Maelezo ya Kiusalama

- Mount images zisizojulikana katika hali ya read-only wakati wa uchanganuzi.
- Weka scripts zenye privileged access, service units, plugins, na njia za wasaidizi nje ya mounts zinazoweza kuandikwa na watumiaji.
- Tumia `nosuid`, `nodev`, na `noexec` pale inapofaa kiutendaji, lakini usizichukulie kama boundary kamili.
- Zuia ufikiaji wa `/proc/<pid>/fd`, metadata ya process, na ukaguzi wa processes za watumiaji wengine inapowezekana.
- Fuatilia mount points zinazoweza kuandikwa, hardlinks zisizotarajiwa zinazoelekeza kwenye faili za privileged, na faili nyeti zilizofutwa lakini bado ziko wazi.
