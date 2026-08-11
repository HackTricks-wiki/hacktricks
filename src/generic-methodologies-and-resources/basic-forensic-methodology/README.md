# Méthodologie forensique de base

{{#include ../../banners/hacktricks-training.md}}

## Création et montage d'une image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de Malware

Ce **n'est pas nécessairement la première étape à effectuer une fois que vous disposez de l'image**. Mais vous pouvez utiliser ces techniques d'analyse de Malware indépendamment si vous avez un fichier, une image de système de fichiers, une image mémoire, un pcap... Il est donc utile de **garder ces actions à l'esprit** :


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d'une image

Si une **image forensique** d'un appareil vous est fournie, vous pouvez commencer à **analyser les partitions et le système de fichiers** utilisés et à **récupérer** des **fichiers potentiellement intéressants** (y compris ceux qui ont été supprimés). Découvrez comment procéder ici :


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

Si vous avez un **fichier** très **suspect**, alors **en fonction du type de fichier et du logiciel** qui l'a créé, plusieurs **astuces** peuvent être utiles.\
Lisez la page suivante pour découvrir quelques astuces intéressantes :


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je souhaite mentionner tout particulièrement la page suivante :


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection d'un dump mémoire


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection d'un Pcap


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

## References

{{#include ../../banners/hacktricks-training.md}}
