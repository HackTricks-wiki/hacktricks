# Basiese Forensiese Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Skep en Monteer van 'n Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-analise

Dit **is nie noodwendig die eerste stap om uit te voer sodra jy die image het nie**. Maar jy kan hierdie malware-analisetegnieke onafhanklik gebruik as jy 'n lêer, 'n lêerstelsel-image, memory image, pcap... het, dus is dit goed om **hierdie aksies in gedagte te hou**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspeksie van 'n Image

As jy 'n **forensiese image** van 'n toestel ontvang, kan jy begin om die gebruikte **partisies en lêerstelsel** te **ontleed** en moontlik **interessante lêers te herstel** (selfs geskrapte lêers). Leer hoe by:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Afhangend van die gebruikte OS'e en selfs platform, moet verskillende interessante artefakte gesoek word:


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

## Diepgaande inspeksie van spesifieke lêertipes en Software

As jy 'n baie **verdagte** **lêer** het, kan verskeie **truuks**, **afhangend van die lêertipe en Software** wat dit geskep het, nuttig wees.\
Lees die volgende bladsy om van die interessante truuks te leer:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ek wil spesiale melding maak van die bladsy:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspeksie van Memory Dumps


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-inspeksie


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-forensiese tegnieke**

Hou die moontlike gebruik van anti-forensiese tegnieke in gedagte:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
