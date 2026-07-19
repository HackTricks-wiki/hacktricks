# Lêerstelsel, Inodes en Herstel

{{#include ../../banners/hacktricks-training.md}}

Lêerstelselmisbruik gaan dikwels daaroor om die verhouding tussen ’n sigbare pad en die objek daaragter te verwar. Skyfbeelde kan ’n ander lêerstelsel verberg, skryfbare mounts kan deur bevoorregte take gebruik word, hardlinks kan dieselfde inode deur ’n ander naam blootstel, en geskrapte lêers kan steeds deur ’n oop lêerbeskrywer gelees word.

Hierdie bladsy fokus op die tegniek, nie op een spesifieke lab of teiken nie.

## Skyfbeelde en Loop Mounts

’n Gewone lêer kan ’n volledige lêerstelsel bevat. Backup-beelde, gekopieerde bloktoestelle, VM-artefakte of hernoemde blobs kan dus credentials, scripts, SSH-sleutels, konfigurasielêers of flags bevat, selfs wanneer dit van buite af nie nuttig lyk nie.

Identifiseer waarskynlike beelde:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Indien mounting toegelaat word, mount onbekende images eers read-only:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Indien montering nie beskikbaar is nie, inspekteer die lêerstelsel se metadata direk:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Die tegniek is nuttig omdat dit ’n normaal lykende lêer in ’n tweede lêerstelselboom verander. Beskou dit as ’n manier om versteekte data te herwin, nie as ’n privilege escalation op sigself nie.

## Misbruik van skryfbare mounts

’n Skryfbare mount word gevaarlik wanneer ’n meer bevoorregte konteks later iets daarin vertrou. Die belangrike vraag is nie net "kan ek hier skryf nie?", maar "wie lees, voer uit, importeer of laai later hiervandaan?".

Vind skryfbare mounts en verdagte verbruikers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Algemene misbruikpatrone:

- ’n Bevoorregte cron- of systemd-eenheid voer ’n skryfbare skrip vanaf die mount uit.
- ’n Bevoorregte diens laai plugins, config, templates of helper binaries vanaf die mount.
- ’n Mount bevat SUID-lêers en laat wysiging, vervanging of path manipulation toe.
- ’n Container of chroot stel ’n host-backed path bloot wat vanuit die beperkte omgewing skryfbaar is.

Generiese validasiepatroon:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Wanneer impak in ’n gemagtigde lab bewys word, hou die payload waarneembaar en minimaal, byvoorbeeld deur `id`-uitset na ’n tydelike lêer te skryf. Die kerntegniek is vertraagde uitvoering deur ’n trusted writable location.

## Inodes en Path Confusion

’n Inode is die filesystem-object; ’n path is slegs ’n naam wat daarna verwys. Dit is belangrik omdat twee verskillende paths na dieselfde inode kan verwys, en ’n deleted pathname beteken nie altyd dat die data weg is nie.

Vergelyk lêers volgens inode en device:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Vind elke sigbare padnaam vir dieselfde inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Soek direk volgens inode-nommer wanneer jy slegs metadata het:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Hierdie tegniek is nuttig wanneer ’n lêer onder ’n onverwagte naam verskyn, wanneer ’n toepassing een pad valideer maar ’n ander een gebruik, of wanneer ’n bevoorregte wrapper met ’n inode werk wat ook êrens anders bereikbaar is.

## Hardlink Abuse

Hardlinks skep veelvuldige name vir dieselfde inode. Hulle wys nie soos symlinks na ’n teikenpad nie; hulle is gelyke name vir dieselfde lêerobjek.

Vind SUID-lêers met veelvuldige hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ondersoek een verdagte lêer:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Waarom dit saak maak:

- ’n Sensitiewe lêer kan deur ’n minder ooglopende pad bereikbaar wees.
- ’n SUID-wrapper kan versteek wees agter ’n naam wat nie bevoorreg lyk nie.
- Opruiming wat een padnaam verwyder, kan ’n ander hardlink steeds aktief laat.

Moderne kernels en mount-opsies kan die skepping van hardlinks beperk om hierdie soort misbruik te verminder, maar bestaande hardlinks is steeds die moeite werd om te hersien.

## Herstel van verwyderde lêers deur oop FD’s

Wanneer ’n proses ’n lêer oop hou, kan die lêerdata steeds beskikbaar bly selfs nadat die padnaam verwyder is. Linux stel hierdie oop descriptors beskikbaar onder `/proc/<pid>/fd/`.

Vind verwyderde oop lêers:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Herstel die data wanneer toestemmings dit toelaat:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Dit is ’n praktiese tegniek om geskrapte logs, tydelike secrets, dropped binaries, geroteerde lêers of scripts wat ná uitvoering verwyder is, te herwin.

## ext-herstel met debugfs

Op ext-filesystems kan `debugfs` inode-metadata inspekteer en soms lêerinhoud uit ’n filesystem image dump. Werk waar moontlik op ’n kopie of ’n read-only image.

Lys inskrywings en inspekteer inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump 'n bekende inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Dit is nie gewaarborgde herstel nie. Dit hang af van die lêerstelsel se toestand, of blokke hergebruik is, en of die metadata steeds bestaan. Die tegniek is steeds waardevol omdat dit jou toelaat om inode-vlaktoestand te inspekteer sonder om op normale padtraversering staat te maak.

## Inode-uitputting en ordening

Inode-uitputting vind plaas wanneer ’n lêerstelsel se lêerobjekte opraak, selfs al is daar steeds vrye skyfspasie. Dit veroorsaak gewoonlik betroubaarheidsfoute, maar dit kan ook vreemde gedrag tydens voorvalreaksie of laboratoriumtriage verklaar.

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
Behandel volgorde as ’n leidraad, nie as bewys nie. Kopieerbewerkings, argiefonttrekking, lêerstelseltipes, herstelbewerkings en gelyktydige skryfbewerkings kan almal allokasiepatrone verander.

## Verdedigingsnotas

- Mount onbekende images read-only tydens analise.
- Hou bevoorregte scripts, service units, plugins en helper paths buite mounts wat deur gebruikers geskryf kan word.
- Gebruik `nosuid`, `nodev` en `noexec` waar dit operasioneel toepaslik is, maar moenie dit as ’n volledige grens beskou nie.
- Beperk waar moontlik toegang tot `/proc/<pid>/fd`, prosesmetadata en inspeksie van prosesse tussen gebruikers.
- Monitor mounts waarop geskryf kan word, onverwagte hardlinks na bevoorregte lêers en sensitiewe lêers wat verwyder is maar steeds oop is.
{{#include ../../banners/hacktricks-training.md}}
