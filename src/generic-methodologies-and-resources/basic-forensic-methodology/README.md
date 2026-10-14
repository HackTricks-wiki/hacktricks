# Méthodologie de base en analyse forensique

{{#include ../../banners/hacktricks-training.md}}

## Création et montage d’une image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Analyse de malware

Ce n’est **pas nécessairement la première étape à effectuer une fois l’image obtenue**. Mais vous pouvez utiliser ces techniques d’analyse de malware indépendamment, que vous disposiez d’un fichier, d’une image de système de fichiers, d’une image mémoire, d’un pcap... Il est donc utile de **garder ces actions à l’esprit** :


{{#ref}}
malware-analysis.md
{{#endref}}

## Inspection d’une image

si vous disposez d’une **image forensique** d’un appareil, vous pouvez commencer à **analyser les partitions et le système de fichiers** utilisés, et à **récupérer** des **fichiers potentiellement intéressants** (même ceux qui ont été supprimés). Découvrez comment ici :


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Selon les systèmes d’exploitation et même les plateformes utilisés, il peut être intéressant de rechercher différents artefacts :


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

Pour un appareil Android verrouillé, les méthodes d’acquisition et l’imagerie mémoire, consultez [Android forensics](android-forensics.md).

## Inspection approfondie de types de fichiers et de logiciels spécifiques

Si vous disposez d’un **fichier** très **suspect**, plusieurs **astuces** peuvent être utiles **selon le type de fichier et le logiciel** qui l’a créé.\
Consultez la page suivante pour découvrir quelques astuces intéressantes :


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Je tiens à mentionner en particulier la page :


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Inspection d’un dump mémoire


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Inspection d’un pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Techniques anti-forensiques**

Gardez à l’esprit que des techniques anti-forensiques peuvent avoir été utilisées :


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Recherche de menaces


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
