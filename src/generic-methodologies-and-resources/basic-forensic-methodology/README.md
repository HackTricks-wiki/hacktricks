# Méthodologie forensique de base

{{#include ../../banners/hacktricks-training.md}}

## Création et montage d'une image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de Malware

Ce **n'est pas nécessairement la première étape à effectuer une fois que vous avez l'image**. Mais vous pouvez utiliser ces techniques d'analyse de malware de manière indépendante si vous disposez d'un fichier, d'une image du système de fichiers, d'une image mémoire, d'un pcap... il est donc bon de **garder ces actions à l'esprit** :


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d'une image

Si l'on vous remet une **image forensique** d'un appareil, vous pouvez commencer à **analyser les partitions, le système de fichiers** utilisé et **récupérer** potentiellement des **fichiers intéressants** (même supprimés). Apprenez comment dans :


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Méthodologie forensique de base



## Création et montage d'une image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de Malware

Ce **n'est pas nécessairement la première étape à effectuer une fois que vous avez l'image**. Mais vous pouvez utiliser ces techniques d'analyse de malware de manière indépendante si vous disposez d'un fichier, d'une image du système de fichiers, d'une image mémoire, d'un pcap... il est donc bon de **garder ces actions à l'esprit** :


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d'une image

Si l'on vous remet une **image forensique** d'un appareil, vous pouvez commencer à **analyser les partitions, le système de fichiers** utilisé et **récupérer** potentiellement des **fichiers intéressants** (même supprimés). Apprenez comment dans :


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Selon les OS utilisés et même la plateforme, différents artefacts intéressants doivent être recherchés :


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

Si vous avez un fichier très **suspect**, alors **selon le type de fichier et le logiciel** qui l'a créé, plusieurs **astuces** peuvent être utiles.\
Lisez la page suivante pour apprendre quelques astuces intéressantes :


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je tiens à mentionner tout particulièrement la page :


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection du dump mémoire


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection de pcap


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



## Inspection approfondie de types de fichiers et de logiciels spécifiques

Si vous avez un fichier très **suspect**, alors **selon le type de fichier et le logiciel** qui l'a créé, plusieurs **astuces** peuvent être utiles.\
Lisez la page suivante pour apprendre quelques astuces intéressantes :


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je tiens à mentionner tout particulièrement la page :


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection du dump mémoire


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection de pcap


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
