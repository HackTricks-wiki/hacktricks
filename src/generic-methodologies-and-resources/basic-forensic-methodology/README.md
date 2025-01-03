# Osnovna Forenzička Metodologija

{{#include ../../banners/hacktricks-training.md}}

## Kreiranje i Montiranje Slike

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza Malvera

Ovo **nije nužno prvi korak koji treba preduzeti kada imate sliku**. Ali možete koristiti ove tehnike analize malvera nezavisno ako imate datoteku, sliku datotečnog sistema, sliku memorije, pcap... tako da je dobro **imati ove akcije na umu**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Istraživanje Slike

Ako dobijete **forenzičku sliku** uređaja, možete početi **analizirati particije, datotečni sistem** koji se koristi i **oporaviti** potencijalno **zanimljive datoteke** (čak i obrisane). Saznajte kako u:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

U zavisnosti od korišćenih OS-ova i čak platformi, različiti zanimljivi artefakti treba da se pretražuju:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Dubinska Inspekcija Specifičnih Tipova Datoteka i Softvera

Ako imate vrlo **sumnjivu** **datoteku**, onda **u zavisnosti od tipa datoteke i softvera** koji je kreirao, nekoliko **trikova** može biti korisno.\
Pročitajte sledeću stranicu da biste saznali neke zanimljive trikove:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim da posebno pomenem stranicu:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspekcija Dump-a Memorije

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspekcija Pcap-a

{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forenzičke Tehnike**

Imajte na umu moguću upotrebu anti-forenzičkih tehnika:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Lov na Pretnje

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
