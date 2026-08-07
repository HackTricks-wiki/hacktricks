# Mfumo wa Faili, Inodes na Urejeshaji

{{#include ../../banners/hacktricks-training.md}}

Abuse ya mfumo wa faili mara nyingi huhusu kuchanganya uhusiano kati ya path inayoonekana na object iliyo nyuma yake. Disk images zinaweza kuficha filesystem nyingine, mounts zinazoweza kuandikwa zinaweza kutumiwa na kazi zenye privileged, hardlinks zinaweza kufichua inode ileile kupitia jina tofauti, na files zilizofutwa bado zinaweza kusomeka kupitia file descriptor iliyo wazi.

Ukurasa huu unalenga technique yenyewe, si lab au target maalum.

## Disk Images na Loop Mounts

File ya kawaida inaweza kuwa na filesystem kamili. Kwa hiyo, backup images, block devices zilizonakiliwa, VM artifacts, au blobs zilizopewa majina mapya zinaweza kuwa na credentials, scripts, SSH keys, configuration files, au flags hata kama hazionekani kuwa na manufaa kwa nje.

Tambua images zinazowezekana:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Ikiwa mounting inaruhusiwa, mount images zisizojulikana kwa read-only kwanza:
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
The technique ni muhimu kwa sababu hugeuza file inayoonekana ya kawaida kuwa filesystem tree ya pili. Ichukulie kama njia ya kurecover data iliyofichwa, si kama privilege escalation yenyewe.

## Writable Mount Abuse

Writable mount huwa hatari wakati context yenye privileges zaidi baadaye inaamini kitu kilicho ndani yake. Swali muhimu si tu "naweza kuandika hapa?", bali "ni nani baadaye anayesoma, ana-execute, ana-import, au ana-load kutoka hapa?".

Tafuta writable mounts na consumers wanaotiliwa shaka:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Mifumo ya kawaida ya matumizi mabaya:

- cron au systemd unit yenye privileged huendesha script inayoweza kuandikwa kutoka kwenye mount.
- service yenye privileged hupakia plugins, config, templates, au helper binaries kutoka kwenye mount.
- mount ina faili za SUID na inaruhusu kubadilishwa, kubadilishwa na nyingine, au kufanyiwa path manipulation.
- container au chroot hufichua path inayoungwa mkono na host ambayo inaweza kuandikwa kutoka kwenye restricted environment.

Muundo wa jumla wa validation:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Unapothibitisha athari katika maabara iliyoidhinishwa, weka payload ionekane na iwe ndogo, kwa mfano kwa kuandika matokeo ya `id` kwenye faili la muda. Mbinu kuu ni utekelezaji uliocheleweshwa kupitia eneo linaloaminika na linaloweza kuandikwa.

## Inode na Mkanganyiko wa Njia

Inode ni object ya filesystem; path ni jina linaloielekeza tu. Hili ni muhimu kwa sababu paths mbili tofauti zinaweza kuelekeza kwenye inode moja, na pathname iliyofutwa haimaanishi kila mara kwamba data imeondoka.

Linganisha files kwa kutumia inode na device:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Tafuta kila pathname inayoonekana ya inode hiyo hiyo:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Tafuta moja kwa moja kwa nambari ya inode ukiwa na metadata pekee:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Mbinu hii ni muhimu wakati faili inaonekana chini ya jina lisilotarajiwa, wakati application inathibitisha path moja lakini inatumia nyingine, au wakati wrapper yenye privileges inaingiliana na inode ambayo pia inaweza kufikiwa kutoka mahali pengine.

## Hardlink Abuse

Hardlinks huunda majina mengi kwa inode moja. Hazielekezi kwenye target path kama symlinks; ni majina yanayolingana ya file object hiyo hiyo.

Tafuta faili za SUID zilizo na hardlinks nyingi:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Kagua faili moja lenye shaka:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Kwa nini ni muhimu:

- Faili nyeti inaweza kufikiwa kupitia njia isiyo dhahiri.
- SUID wrapper inaweza kufichwa nyuma ya jina lisiloonekana kuwa na privileges.
- Usafishaji unaoondoa pathname moja unaweza kuacha hardlink nyingine ikiwa hai.

Kernel za kisasa na mount options zinaweza kuzuia uundaji wa hardlink ili kupunguza aina hii ya abuse, lakini hardlink zilizopo bado zinafaa kukaguliwa.

## Deleted File Recovery Through Open FDs

Mchakato unapoweka faili ikiwa wazi, data ya faili inaweza kuendelea kupatikana hata baada ya pathname kufutwa. Linux huweka descriptors hizo zilizo wazi chini ya `/proc/<pid>/fd/`.

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
Hii ni technique ya vitendo ya kurejesha logs zilizofutwa, secrets za muda, binaries zilizowekwa, files zilizozungushwa, au scripts zilizoondolewa baada ya kutekelezwa.

## Urejeshaji wa ext Kwa debugfs

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
Hii si recovery iliyohakikishwa. Inategemea hali ya filesystem, ikiwa blocks zilitumika tena, na ikiwa metadata bado ipo. Technique hii bado ina thamani kwa sababu inakuruhusu kukagua hali ya kiwango cha inode bila kutegemea path traversal ya kawaida.

## Kuishiwa Inode na Mpangilio

Kuishiwa inode hutokea wakati filesystem inaishiwa na file objects hata kama nafasi ya diski bado ipo. Kwa kawaida husababisha kushindwa kwa reliability, lakini pia inaweza kueleza tabia zisizo za kawaida wakati wa incident response au lab triage.

Kagua shinikizo la inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Nambari za inode na mihuri ya muda pia zinaweza kusaidia kujenga upya shughuli katika mazingira rahisi ya maabara:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Chukulia mpangilio kama kidokezo, si uthibitisho. Operesheni za kunakili, uchanganuzi wa archive, aina ya filesystem, urejeshaji, na writes zinazoendelea kwa wakati mmoja zinaweza kubadilisha mifumo ya ugawaji.

## Maelezo ya Kihimili

- Mount images zisizojulikana kwa hali ya read-only wakati wa analysis.
- Weka scripts zenye privileged access, service units, plugins, na helper paths nje ya mounts zinazoandikika na users.
- Tumia `nosuid`, `nodev`, na `noexec` inapofaa kiutendaji, lakini usizichukulie kama boundary kamili.
- Zuia access kwa `/proc/<pid>/fd`, process metadata, na ukaguzi wa processes za users wengine inapowezekana.
- Fuatilia mount points zinazoandikika, hardlinks zisizotarajiwa zinazoelekeza kwenye privileged files, na sensitive files zilizofutwa lakini bado zikiwa wazi.

{{#include ../../banners/hacktricks-training.md}}
