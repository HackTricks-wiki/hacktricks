# Osnovna forenzička metodologija

{{#include ../../banners/hacktricks-training.md}}

## Kreiranje i montiranje image-a


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analiza malware-a

Ovo **nije nužno prvi korak koji treba preduzeti nakon što dobijete image**. Međutim, ove tehnike analize malware-a možete koristiti nezavisno ako imate fajl, image sistema datoteka, memory image, pcap... zato je dobro **imati ove radnje na umu**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Pregled image-a

ako vam je dat **forenzički image** uređaja, možete početi sa **analizom particija i sistema datoteka** koji se koristi, kao i **oporavkom** potencijalno **zanimljivih fajlova** (čak i obrisanih). Saznajte kako:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

U zavisnosti od korišćenih OS-ova, pa čak i platforme, treba pretražiti različite zanimljive artefakte:


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

## Detaljan pregled određenih tipova fajlova i Software-a

Ako imate veoma **sumnjiv** **fajl**, onda, **u zavisnosti od tipa fajla i Software-a** koji ga je kreirao, različiti **trikovi** mogu biti korisni.\
Pročitajte sledeću stranicu da biste saznali neke zanimljive trikove:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim posebno da pomenem stranicu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Pregled memory dump-a


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pregled pcap-a


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Imajte na umu moguću upotrebu anti-forensic techniques:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
