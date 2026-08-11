# Lêerstelsel, Inodes en Herstel

{{#include ../../banners/hacktricks-training.md}}

Lêerstelselmisbruik gaan dikwels daaroor om die verhouding tussen ’n sigbare pad en die objek daaragter te verwar.

Skyfbeelde kan ’n ander lêerstelsel versteek.<sup>[[1]](#references)</sup> Skryfbare mounts kan deur bevoorregte take gebruik word.

Hardlinks kan dieselfde inode deur ’n ander naam blootstel.<sup>[[3]](#references)</sup> Geskrapte lêers kan steeds deur ’n oop lêerbeskrywer gelees word.<sup>[[5]](#references)[[6]](#references)</sup>

Hierdie bladsy fokus op die tegniek, nie op een spesifieke lab of teiken nie.

## Skyfbeelde en Loop Mounts

’n Gewone lêer kan ’n volledige lêerstelsel bevat, dus kan ’n skyfbeeld ’n tweede lêerstelselboom blootstel wanneer dit gemount word.<sup>[[1]](#references)</sup>

Rugsteunbeelde, gekopieerde bloktoestelle, VM-artefakte of hernoemde blobs kan dus geloofsbriewe, scripts, SSH-sleutels, konfigurasielêers of flags bevat, selfs wanneer hulle van buite af nie nuttig lyk nie.

Identifiseer waarskynlike beelde met `file` om ’n kandidaat te klassifiseer, `blkid` om erkende lêerstelselmetadata te ondersoek, en `strings -a` om die hele lêer vir drukbare rye te skandeer.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Wanneer montering toegelaat word, gebruik ’n loop mount met `ro` sodat die image read-only aangeheg word; die `find`-opdrag hieronder beperk die inspeksiediepte en lêertipe.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
As mounting nie beskikbaar is nie en die image ext2/ext3/ext4 is, inspekteer sy metadata direk met `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die tegniek is nuttig omdat dit 'n normaal lykende lêer in 'n tweede lêerstelselboom verander.<sup>[[1]](#references)</sup> Behandel dit as 'n manier om versteekte data te herstel, nie as 'n privilege escalation op sigself nie.

## Writable Mount Abuse

'n Skryfbare mount word gevaarlik wanneer 'n meer bevoorregte konteks later iets daarin vertrou. Die belangrike vraag is nie net "kan ek hier skryf nie?", maar "wie lees, voer uit, importeer of laai later hiervandaan?".

Gebruik `findmnt` om gemounte lêerstelsels en hul opsies te inspekteer.<sup>[[9]](#references)</sup>

Vind skryfbare mounts en verdagte verbruikers met die gedokumenteerde `find`-toestemming-, tipe- en lêerstelselgrens-predikate, en gebruik dan rekursiewe `grep` om waarskynlike verbruikerkonfigurasie te soek.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Algemene misbruikpatrone:

- ’n cron job of systemd-diens voer ’n skryfbare script vanaf die mount uit.<sup>[[13]](#references)[[14]](#references)</sup>
- ’n Bevoorregte diens laai plugins, konfigurasie, templates of helper-binaries vanaf die mount.
- ’n Mount bevat SUID-lêers en laat wysiging, vervanging of path-manipulasie toe.
- ’n Container of chroot stel ’n host-gesteunde path bloot wat vanuit die beperkte omgewing skryfbaar is. Mount namespaces verskaf afsonderlike mounthiërargieë, terwyl `chroot()` slegs pathname-resolusie verander en nie ’n volledige sandbox is nie.<sup>[[15]](#references)[[16]](#references)</sup>

Generiese validasiepatroon wat dieselfde `find`-predikate gebruik.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wanneer jy impak in ’n gemagtigde laboratorium bewys, hou die payload waarneembaar en minimaal, byvoorbeeld deur die uitvoer van `id` na ’n tydelike lêer te skryf.<sup>[[23]](#references)</sup> Die kerntegniek is vertraagde uitvoering deur ’n vertroude skryfbare ligging.

## Inodes en Padverwarring

’n Inode is die lêerstelselobjek; ’n pad is slegs ’n naam wat daarna wys. Toestel- en inode-metadata laat jou toe om objekte oor lêerstelsels heen te onderskei, terwyl skakeltellings veelvuldige hard links blootlê.<sup>[[3]](#references)</sup> ’n Uitgevee padnaam beteken nie altyd dat die data weg is terwyl ’n proses steeds die lêer oop het nie.<sup>[[5]](#references)</sup>

Die `find`-predikate hieronder vergelyk inode-identiteit, skakeltellings, toestelgrense en tydstempels.<sup>[[4]](#references)</sup>

Vergelyk lêers volgens inode en toestel met `ls -i` en `stat`-metadataformate.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Vind elke sigbare padnaam vir dieselfde inode met `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Soek direk volgens inode-nommer met `find -inum` wanneer jy slegs metadata het.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Hierdie tegniek is nuttig wanneer ’n lêer onder ’n onverwagte naam verskyn, wanneer ’n toepassing een pad valideer maar ’n ander gebruik, of wanneer ’n bevoorregte wrapper met ’n inode werk wat ook êrens anders bereikbaar is.

## Hardlink Abuse

Hardlinks skep veelvuldige name vir dieselfde inode. Hulle wys nie na ’n teikenpad soos symlinks nie; hulle is gelyke name vir dieselfde lêerobjek.<sup>[[3]](#references)</sup>

Vind SUID-lêers met veelvuldige hardlinks deur `find` se toestemmings- en skakeltelling-predikate te gebruik.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspekteer een verdagte lêer met `stat` en `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Waarom dit saak maak:

- ’n Sensitiewe lêer kan deur ’n minder ooglopende pad bereikbaar wees.
- ’n SUID-wrapper kan versteek wees agter ’n naam wat nie bevoorreg lyk nie.
- Opruiming wat een padnaam verwyder, kan nog ’n hardlink laat voortbestaan.

Linux se `fs.protected_hardlinks` sysctl kan die skepping van hardlinks oor privilege-grense heen beperk.<sup>[[7]](#references)</sup> Bestaande hardlinks verdien steeds hersiening.

## Herstel van verwyderde lêers deur oop FD's

Wanneer ’n proses ’n lêer oop hou, laat die verwydering van sy laaste padnaam die lêer voortbestaan totdat die laaste descriptor sluit; Linux stel hierdie descriptors beskikbaar onder `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Vind verwyderde oop lêers deur `/proc`-descriptors te lys en die uitvoer van oop lêers te filtreer.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Herwinning via hierdie skakels is afhanklik van toestemmings, omdat die dereferensiëring van `/proc/<pid>/fd` onderhewig is aan `ptrace`-toegangscontroles en lêertoestemmings.<sup>[[6]](#references)</sup>

Wanneer dit toegelaat word, wys `readlink` die teiken van die descriptor, en `cp` kopieer die inhoud daarvan.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Dit is ’n praktiese tegniek om geskrapte logs, tydelike secrets, verwyderde binaries, geroteerde lêers of scripts wat ná uitvoering verwyder is, te herwin.

## ext-herwinning met debugfs

Op ext2/ext3/ext4-lêerstelsels kan `debugfs` inode-metadata inspekteer en inode-inhoud vanaf ’n bloktoestel of image dump; sonder `-w` maak dit die lêerstelsel slegs-leesbaar oop.<sup>[[2]](#references)</sup> Werk waar moontlik op ’n kopie of ’n slegs-leesbare image.

Lys entries en inspekteer inodes met `debugfs`-requests vir gidslyste, inode-status en inode-na-pad-kontroles.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump ’n bekende inode met die `debugfs dump`-opdrag, en klassifiseer dan die herstelde uitvoer met `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dit is nie gewaarborgde herstel nie. Dit hang af van die lêerstelseltoestand, of blokke hergebruik is, en of die metadata steeds bestaan. Vir ext3/ext4 merk die `debugfs`-handleiding op dat herstel van geskrapte inodes kan misluk omdat vrygestelde inode-datablokke nie meer beskikbaar is nie.<sup>[[2]](#references)</sup> Die tegniek is steeds waardevol omdat dit jou toelaat om inode-vlaktoestand te inspekteer sonder om op normale path traversal staat te maak.

## Inode-uitputting en -ordening

Inode-uitputting gebeur wanneer ’n lêerstelsel sonder lêernodusse te staan kom, selfs al is daar steeds vrye skyfspasie.<sup>[[8]](#references)[[17]](#references)</sup> Dit veroorsaak gewoonlik betroubaarheidsfoute, maar dit kan ook vreemde gedrag tydens incident response of lab-triage verklaar.

Gebruik `df -i` om inode-inligting in plaas van blokgebruik te rapporteer.<sup>[[8]](#references)</sup>

Kontroleer inode-druk met `df` en ’n `find`-telling van gidsouers.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode-nommers en tydstempels kan ook help om aktiwiteit in eenvoudige laboratoriumomgewings te rekonstrueer.

Die `find`-formaat-aanwysings hieronder stel daardie velde bloot.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Behandel ordening as 'n leidraad, nie as bewys nie. Kopieerbewerkings, argief-ekstraksie, lêerstelseltipe, herstelbewerkings en gelyktydige skrywings kan almal allokasiepatrone verander.

## Verdedigingsnotas

- Mount onbekende beelde in read-only-modus tydens ontleding.<sup>[[1]](#references)</sup>
- Hou bevoorregte scripts, diens-eenhede, plugins en helper-paaie buite gebruiker-skryfbare mounts.
- Gebruik `nosuid`, `nodev` en `noexec` waar dit operasioneel gepas is; hierdie opsies deaktiveer set-ID/capability-uitvoering, toesteltolking of direkte binêre uitvoering op die mount.<sup>[[1]](#references)</sup> Moet dit nie as 'n volledige grens beskou nie.
- Beperk toegang tot `/proc/<pid>/fd`; dereferensiëring van hierdie skakels word deur ptrace-toegangskontroles en lêertoestemmings beheer.<sup>[[6]](#references)</sup> Beperk breër prosesmetadata en inspeksie oor gebruikers heen waar moontlik.
- Monitor skryfbare mount-punte, onverwagte hardlinks na bevoorregte lêers en sensitiewe lêers wat geskrap is maar steeds oop is.

## References

- [1] [mount(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Dokumentasie vir /proc/sys/fs/ — Die Linux-kern se dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
