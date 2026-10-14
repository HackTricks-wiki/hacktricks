# Osnovna forenzička metodologija

{{#include ../../banners/hacktricks-training.md}}

## Kreiranje i montiranje slike


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza malvera

Ovo **nije nužno prvi korak koji treba preduzeti nakon što dobijete sliku**. Ove tehnike analize malvera možete koristiti i nezavisno, ako imate datoteku, sliku sistema datoteka, sliku memorije, pcap... zato je dobro **imati ove postupke na umu**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Pregled slike

ako dobijete **forenzičku sliku** uređaja, možete početi da **analizirate particije i sistem datoteka** koji se koriste i da **oporavljate** potencijalno **zanimljive datoteke** (čak i obrisane). Saznajte kako na stranici:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

U zavisnosti od korišćenog OS-a, pa čak i platforme, treba tražiti različite zanimljive artefakte:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

Za zaključan Android uređaj, načine pribavljanja podataka i kreiranje slike memorije pogledajte [Android forensics](android-forensics.md).

## Detaljan pregled određenih tipova datoteka i softvera

Ako imate veoma **sumnjivu** **datoteku**, u zavisnosti od **tipa datoteke i softvera** kojim je napravljena, može biti korisno nekoliko **trikova**.\
Pročitajte sledeću stranicu da biste saznali neke zanimljive trikove:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim posebno da istaknem stranicu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Pregled dump-a memorije


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pregled pcap-a


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-forenzičke tehnike**

Imajte na umu da su možda korišćene anti-forenzičke tehnike:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Lov na pretnje


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
