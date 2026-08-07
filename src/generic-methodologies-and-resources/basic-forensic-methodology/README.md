# Osnovna forenzička metodologija

{{#include ../../banners/hacktricks-training.md}}

## Kreiranje i montiranje image-a


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware analiza

Ovo **nije nužno prvi korak koji treba izvršiti nakon dobijanja image-a**. Međutim, ove tehnike malware analize možete koristiti nezavisno ako imate datoteku, image file-systema, memory image, pcap... zato je dobro **imati ove radnje na umu**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Analiza image-a

ako vam je dat **forenzički image** uređaja, možete početi sa **analizom particija i korišćenog file-systema**, kao i **oporavkom** potencijalno **zanimljivih datoteka** (čak i obrisanih). Saznajte kako:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

U zavisnosti od korišćenih OS-ova, pa čak i platforme, treba potražiti različite zanimljive artefakte:


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

## Detaljna analiza specifičnih tipova datoteka i Software-a

Ako imate veoma **sumnjivu** **datoteku**, onda, **u zavisnosti od tipa datoteke i software-a** koji ju je kreirao, nekoliko **trikova** može biti korisno.\
Pročitajte sledeću stranicu da biste naučili neke zanimljive trikove:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim posebno da pomenem stranicu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Analiza Memory Dump-a


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap analiza


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic tehnike**

Imajte na umu moguću upotrebu anti-forensic tehnika:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
