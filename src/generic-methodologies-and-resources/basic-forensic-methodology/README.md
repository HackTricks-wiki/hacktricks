# Basiese Forensiese Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Skep en Monteer ’n Beeld


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware-ontleding

Dit is **nie noodwendig die eerste stap wat jy moet uitvoer nadat jy die beeld gekry het nie**. Maar jy kan hierdie malware-ontledingstegnieke onafhanklik gebruik as jy ’n lêer, ’n lêerstelselbeeld, ’n geheuebeeld, ’n pcap... het, dus is dit goed om **hierdie stappe in gedagte te hou**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ondersoek ’n Beeld

As jy ’n **forensiese beeld** van ’n toestel kry, kan jy begin om die gebruikte **partisies en lêerstelsel te ontleed** en moontlik **interessante lêers te herwin** (selfs geskrapte lêers). Leer hoe op:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Afhangend van die gebruikte OS'e en selfs platform, moet daar na verskillende interessante artefakte gesoek word:


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

Sien [Android-forensika](android-forensics.md) vir ’n geslote Android-toestel, verkrygingsroetes en geheuebeelding.

## Diep Ondersoek van Spesifieke Lêertipes en Sagteware

As jy ’n baie **verdagte** **lêer** het, kan verskeie **truuks** nuttig wees, **afhangend van die lêertipe en die sagteware** wat dit geskep het.\
Lees die volgende bladsy om van die interessante truuks te leer:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ek wil spesiale melding maak van die bladsy:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Ondersoek van Geheuestortings


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap-ondersoek


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensiese Tegnieke**

Hou die moontlike gebruik van anti-forensiese tegnieke in gedagte:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Bedreigingsjag


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
