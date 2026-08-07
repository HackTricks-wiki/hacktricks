# Lêerstelsel, Inodes en Herstel

{{#include ../../banners/hacktricks-training.md}}

Misbruik van lêerstelsels gaan dikwels daaroor om die verhouding tussen ’n sigbare pad en die objek daaragter te verwar. Disk images kan ’n ander lêerstelsel versteek, skryfbare mounts kan deur bevoorregte take gebruik word, hardlinks kan dieselfde inode deur ’n ander naam blootstel, en verwyderde lêers kan steeds deur ’n oop file descriptor gelees word.

Hierdie bladsy fokus op die tegniek, nie op een spesifieke lab of target nie.

## Disk Images en Loop Mounts

’n Gewone lêer kan ’n volledige lêerstelsel bevat. Backup images, gekopieerde block devices, VM artifacts of hernoemde blobs kan dus credentials, scripts, SSH keys, configuration files of flags bevat, selfs wanneer hulle van buite af nie nuttig lyk nie.

Identifiseer waarskynlike images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Indien mounting toegelaat word, mount onbekende images eers as read-only:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Indien montering nie beskikbaar is nie, inspekteer die lêerstelselmetadata direk:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die tegniek is nuttig omdat dit ’n lêer wat normaal lyk in ’n tweede filesystem-boom verander. Beskou dit as ’n manier om versteekte data te herstel, nie as ’n privilege escalation op sy eie nie.

## Writable Mount Abuse

’n Writable mount word gevaarlik wanneer ’n meer bevoorregte konteks later iets daarin vertrou. Die belangrike vraag is nie slegs "kan ek hier skryf nie?", maar "wie lees, voer uit, importeer of laai later hiervandaan?".

Vind writable mounts en verdagte verbruikers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Algemene misbruikpatrone:

- ’n Bevoorregte cron- of systemd-eenheid voer ’n skrip vanaf die mount uit waaraan geskryf kan word.
- ’n Bevoorregte diens laai plugins, konfigurasie, templates of helper-binaries vanaf die mount.
- ’n Mount bevat SUID-lêers en laat wysiging, vervanging of padmanipulasie toe.
- ’n Container of chroot stel ’n gasheergebaseerde pad bloot waaraan vanuit die beperkte omgewing geskryf kan word.

Generiese validasiepatroon:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wanneer impak in ’n gemagtigde laboratorium bewys word, hou die payload waarneembaar en minimaal, byvoorbeeld deur die uitvoer van `id` na ’n tydelike lêer te skryf. Die kerntegniek is uitgestelde uitvoering deur ’n vertroude skryfbare ligging.

## Inodes en Padverwarring

’n Inode is die lêerstelselobjek; ’n pad is slegs ’n naam wat daarna verwys. Dit is belangrik omdat twee verskillende paaie na dieselfde inode kan verwys, en omdat ’n geskrapte padnaam nie altyd beteken dat die data weg is nie.

Vergelyk lêers volgens inode en toestel:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Vind elke sigbare padnaam vir dieselfde inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Soek direk volgens inodenommer wanneer jy slegs metadata het:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
This technique is useful when a file appears under an unexpected name, when an application validates one path but uses another, or when a privileged wrapper interacts with an inode that is also reachable somewhere else.

## Hardlink Abuse

Hardlinks create multiple names for the same inode. They do not point to a target path like symlinks do; they are equal names for the same file object.

Find SUID files with multiple hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspekteer een verdagte lêer:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Waarom dit saak maak:

- 'n Sensitiewe lêer kan deur 'n minder ooglopende pad bereikbaar wees.
- 'n SUID-wrapper kan versteek wees agter 'n naam wat nie bevoorreg lyk nie.
- Opruiming wat een padnaam verwyder, kan 'n ander hardlink steeds aktief laat.

Moderne kernels en mount-opsies kan die skep van hardlinks beperk om hierdie soort misbruik te verminder, maar bestaande hardlinks is steeds die moeite werd om te hersien.

## Herstel van verwyderde lêers deur oop FD's

Wanneer 'n proses 'n lêer oop hou, kan die lêerdata steeds beskikbaar bly selfs nadat die padnaam verwyder is. Linux stel hierdie oop lêerbeskrywers bloot onder `/proc/<pid>/fd/`.

Vind verwyderde oop lêers:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Herwin die data wanneer toestemmings dit toelaat:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Dit is ’n praktiese tegniek vir die herstel van verwyderde logs, tydelike secrets, neergelêde binaries, geroteerde lêers of scripts wat ná uitvoering verwyder is.

## ext-herwinning met debugfs

Op ext-lêerstelsels kan `debugfs` inode-metadata inspekteer en soms lêerinhoud vanaf ’n lêerstelselbeeld dump. Werk waar moontlik op ’n kopie of ’n leesalleen-beeld.

Lys inskrywings en inspekteer inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump ’n bekende inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dit is nie gewaarborgde recovery nie. Dit hang af van die lêerstelsel se toestand, of blokke hergebruik is, en of die metadata steeds bestaan. Die tegniek bly waardevol omdat dit jou toelaat om inode-vlaktoestand te inspekteer sonder om op normale path traversal staat te maak.

## Inode-uitputting en -ordening

Inode-uitputting gebeur wanneer ’n lêerstelsel sonder file objects raak, selfs al is daar steeds vrye skyfspasie. Dit veroorsaak gewoonlik betroubaarheidsfoute, maar dit kan ook vreemde gedrag tydens incident response of lab triage verklaar.

Kontroleer inode-druk:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode-nommers en tydstempels kan ook help om aktiwiteit in eenvoudige laboratoriumomgewings te rekonstrueer:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Behandel volgorde as 'n leidraad, nie as bewys nie. Kopieerbewerkings, argiefonttrekking, lêerstelseltipe, herstelbewerkings en gelyktydige skryfbewerkings kan almal toewysingspatrone verander.

## Verdedigingsnotas

- Mount onbekende images as read-only tydens ontleding.
- Hou bevoorregte scripts, diens-eenhede, plugins en helper-paaie buite mounts wat deur gebruikers geskryf kan word.
- Gebruik `nosuid`, `nodev` en `noexec` waar dit operasioneel toepaslik is, maar moenie dit as 'n volledige grens beskou nie.
- Beperk waar moontlik toegang tot `/proc/<pid>/fd`, prosesmetadata en prosesinspeksie oor gebruikers heen.
- Monitor mounts wat geskryf kan word, onverwagte hardlinks na bevoorregte lêers en sensitiewe lêers wat uitgevee-maar-oop is.

{{#include ../../banners/hacktricks-training.md}}
