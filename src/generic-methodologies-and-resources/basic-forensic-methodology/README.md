# Basiese Forensiese Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Skep en Monteer van 'n Beeld


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-analise

Dit **is nie noodwendig die eerste stap om uit te voer sodra jy die beeld het nie**. Maar jy kan hierdie malware-analise-tegnieke onafhanklik gebruik indien jy 'n lêer, 'n lêerstelselbeeld, geheuebeeld, pcap... het, dus is dit goed om **hierdie aksies in gedagte te hou**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspeksie van 'n Beeld

indien jy 'n **forensiese beeld** van 'n toestel ontvang, kan jy begin om die gebruikte **partisies en lêerstelsel** te **analiseer** en potensieel **interessante lêers** te **herwin** (selfs geskrapte lêers). Leer hoe by:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Afhangende van die gebruikte OS'e en selfs platform, moet daar na verskillende interessante artefakte gesoek word:


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

## Diep inspeksie van spesifieke lêertipes en Software

Indien jy 'n baie **verdagte** **lêer** het, kan verskeie **tricks**, **afhangende van die lêertipe en die software** wat dit geskep het, nuttig wees.\
Lees die volgende bladsy om van die interessante tricks te leer:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ek wil spesiale vermelding maak van die bladsy:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspeksie van 'n Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-inspeksie


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensiese Tegnieke**

Hou die moontlike gebruik van anti-forensiese tegnieke in gedagte:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
