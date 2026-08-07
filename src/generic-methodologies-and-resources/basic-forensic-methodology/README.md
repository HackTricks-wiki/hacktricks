# Méthodologie de base de l'analyse forensique

{{#include ../../banners/hacktricks-training.md}}

## Création et montage d'une image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de malware

Ce **n'est pas nécessairement la première étape à effectuer une fois que vous disposez de l'image**. Mais vous pouvez utiliser ces techniques d'analyse de malware indépendamment si vous avez un fichier, une image de système de fichiers, une image mémoire, un pcap... Il est donc utile de **garder ces actions à l'esprit** :


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d'une image

Si une **image forensique** d'un appareil vous est fournie, vous pouvez commencer à **analyser les partitions et le système de fichiers** utilisés, ainsi qu'à **récupérer** des **fichiers potentiellement intéressants** (y compris ceux qui ont été supprimés). Découvrez comment faire ici :


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

En fonction des OS utilisés et même de la plateforme, différents artefacts intéressants doivent être recherchés :


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

## Inspection approfondie de types de fichiers et de logiciels spécifiques

Si vous disposez d'un **fichier** très **suspect**, alors **selon le type de fichier et le logiciel** qui l'a créé, plusieurs **astuces** peuvent être utiles.\
Lisez la page suivante pour découvrir quelques astuces intéressantes :


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je souhaite attirer particulièrement votre attention sur la page suivante :


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection d'un dump mémoire


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection d'un pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniques anti-forensiques**

Gardez à l'esprit l'utilisation possible de techniques anti-forensiques :


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
