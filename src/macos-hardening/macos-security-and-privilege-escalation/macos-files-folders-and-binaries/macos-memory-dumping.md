# macOS Geheue Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Geheue Artefakte

### Swap Lêers

Swap lêers, soos `/private/var/vm/swapfile0`, dien as **kas wanneer die fisiese geheue vol is**. Wanneer daar nie meer plek in fisiese geheue is nie, word die data na 'n swap lêer oorgedra en dan weer na fisiese geheue gebring soos nodig. Meerdere swap lêers mag teenwoordig wees, met name soos swapfile0, swapfile1, en so aan.

### Hiberneer Beeld

Die lêer geleë by `/private/var/vm/sleepimage` is van kardinale belang tydens **hibernasie modus**. **Data van geheue word in hierdie lêer gestoor wanneer OS X hiberneer**. By die wakkermaak van die rekenaar, haal die stelsel geheue data uit hierdie lêer, wat die gebruiker toelaat om voort te gaan waar hulle opgehou het.

Dit is die moeite werd om te noem dat op moderne MacOS stelsels, hierdie lêer tipies versleuteld is vir sekuriteitsredes, wat herstel moeilik maak.

- Om te kontroleer of versleuteling geaktiveer is vir die sleepimage, kan die opdrag `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer versleuteld is.

### Geheue Druk Logs

Nog 'n belangrike geheue-verwante lêer in MacOS stelsels is die **geheue druk log**. Hierdie logs is geleë in `/var/log` en bevat gedetailleerde inligting oor die stelsel se geheue gebruik en druk gebeurtenisse. Hulle kan veral nuttig wees om geheue-verwante probleme te diagnoseer of te verstaan hoe die stelsel geheue oor tyd bestuur.

## Dumping geheue met osxpmem

Om die geheue in 'n MacOS masjien te dump, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Let wel**: Die volgende instruksies sal slegs werk vir Macs met Intel argitektuur. Hierdie hulpmiddel is nou geargiveer en die laaste vrystelling was in 2017. Die binêre wat afgelaai is met die instruksies hieronder, teiken Intel skyfies aangesien Apple Silicon nie in 2017 beskikbaar was nie. Dit mag moontlik wees om die binêre vir arm64 argitektuur te compileer, maar jy sal self moet probeer.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
As jy hierdie fout vind: `osxpmem.app/MacPmem.kext kon nie laai nie - (libkern/kext) verifikasiefout (lêer eienaarskap/toestemmings); kyk na die stelsel/kernel logs vir foute of probeer kextutil(8)` kan jy dit regmaak deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan reggestel word deur **die laai van die kext toe te laat** in "Sekuriteit & Privaatheid --> Algemeen", net **laat** dit toe.

Jy kan ook hierdie **oneliner** gebruik om die toepassing af te laai, die kext te laai en die geheue te dump:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
