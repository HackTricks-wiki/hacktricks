# Méthodologie de base en criminalistique

{{#include ../../banners/hacktricks-training.md}}

## Création et montage d'une image

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de logiciels malveillants

Ce **n'est pas nécessairement la première étape à réaliser une fois que vous avez l'image**. Mais vous pouvez utiliser ces techniques d'analyse de logiciels malveillants de manière indépendante si vous avez un fichier, une image de système de fichiers, une image mémoire, pcap... donc il est bon de **garder ces actions à l'esprit** :

{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d'une image

Si vous recevez une **image judiciaire** d'un appareil, vous pouvez commencer **à analyser les partitions, le système de fichiers** utilisé et **à récupérer** potentiellement des **fichiers intéressants** (même ceux supprimés). Apprenez comment dans :

{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Selon les systèmes d'exploitation utilisés et même la plateforme, différents artefacts intéressants devraient être recherchés :

{{#ref}}
windows-forensics/
{{#endref}}

{{#ref}}
linux-forensics.md
{{#endref}}

{{#ref}}
docker-forensics.md
{{#endref}}

## Inspection approfondie de types de fichiers spécifiques et de logiciels

Si vous avez un **fichier très suspect**, alors **selon le type de fichier et le logiciel** qui l'a créé, plusieurs **astuces** peuvent être utiles.\
Lisez la page suivante pour apprendre quelques astuces intéressantes :

{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je tiens à faire une mention spéciale à la page :

{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection de dump mémoire

{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection de Pcap

{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniques anti-criminalistiques**

Gardez à l'esprit l'utilisation possible de techniques anti-criminalistiques :

{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Chasse aux menaces

{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
