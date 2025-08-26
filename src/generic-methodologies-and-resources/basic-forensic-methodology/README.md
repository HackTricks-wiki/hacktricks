# Osnovna forenzička metodologija

{{#include ../../banners/hacktricks-training.md}}

## Kreiranje i montiranje image-a


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware analiza

Ovo **nije nužno prvi korak koji treba uraditi nakon što imate image**. Ali ove Malware analysis tehnike možete koristiti nezavisno ako imate file, file-system image, memory image, pcap... zato je dobro **imati ove radnje na umu**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekcija image-a

Ako vam je dat **forensic image** uređaja, možete početi **analizu particija, file-system** koji je korišćen i **oporavak** potencijalno **interesantnih file-ova** (čak i obrisanih). Saznajte kako u:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Osnovna forenzička metodologija



## Kreiranje i montiranje image-a


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware analiza

Ovo **nije nužno prvi korak koji treba uraditi nakon što imate image**. Ali ove Malware analysis tehnike možete koristiti nezavisno ako imate file, file-system image, memory image, pcap... zato je dobro **imati ove radnje na umu**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekcija image-a

Ako vam je dat **forensic image** uređaja, možete početi **analizu particija, file-system** koji je korišćen i **oporavak** potencijalno **interesantnih file-ova** (čak i obrisanih). Saznajte kako u:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

U zavisnosti od korišćenih OSs pa čak i platforme, treba tražiti različite interesantne artefakte:


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

## Dubinska inspekcija specifičnih tipova file-ova i softvera

Ako imate veoma **sumnjiv** **file**, onda **u zavisnosti od file-type i softvera** koji ga je kreirao, nekoliko **trikova** može biti korisno.\
Pročitajte sledeću stranicu da naučite neke interesantne trikove:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim posebno pomenuti stranicu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspekcija Memory Dump-a


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspekcija pcap-a


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Imajte na umu mogućnost upotrebe anti-forensic tehnika:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Dubinska inspekcija specifičnih tipova file-ova i softvera

Ako imate veoma **sumnjiv** **file**, onda **u zavisnosti od file-type i softvera** koji ga je kreirao, nekoliko **trikova** može biti korisno.\
Pročitajte sledeću stranicu da naučite neke interesantne trikove:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Želim posebno pomenuti stranicu:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspekcija Memory Dump-a


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspekcija pcap-a


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Imajte na umu mogućnost upotrebe anti-forensic tehnika:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
