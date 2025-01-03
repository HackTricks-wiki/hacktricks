# Basiese Forensiese Metodologie

{{#include ../../banners/hacktricks-training.md}}

## Skep en Monteer 'n Beeld

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analise

Dit **is nie noodsaaklik die eerste stap om uit te voer sodra jy die beeld het nie**. Maar jy kan hierdie malware analise tegnieke onafhanklik gebruik as jy 'n lêer, 'n lêer-stelsel beeld, geheue beeld, pcap... het, so dit is goed om **hierdie aksies in gedagte te hou**:

{{#ref}}
malware-analysis.md
{{#endref}}

## Inspekteer 'n Beeld

As jy 'n **forensiese beeld** van 'n toestel ontvang, kan jy begin **analiseer die partisies, lêer-stelsel** wat gebruik word en **herstel** potensieel **interessante lêers** (selfs verwyderde). Leer hoe in:

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Afhangende van die gebruikte OS's en selfs platform, moet verskillende interessante artefakte gesoek word:

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Diep inspeksie van spesifieke lêer-tipes en Sagteware

As jy 'n baie **verdagte** **lêer** het, dan **afhangende van die lêer-tipe en sagteware** wat dit geskep het, kan verskeie **tricks** nuttig wees.\
Lees die volgende bladsy om 'n paar interessante truuks te leer:

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Ek wil 'n spesiale vermelding maak van die bladsy:

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Geheue Dump Inspekteer

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspekteer

{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensiese Tegnieke**

Hou in gedagte die moontlike gebruik van anti-forensiese tegnieke:

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Bedreiging Jag

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
