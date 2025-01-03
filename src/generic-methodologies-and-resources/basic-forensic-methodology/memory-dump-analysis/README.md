# Analyse de dump mémoire

{{#include ../../../banners/hacktricks-training.md}}

## Début

Commencez à **chercher** des **malwares** à l'intérieur du pcap. Utilisez les **outils** mentionnés dans [**Analyse de Malware**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility est le principal cadre open-source pour l'analyse de dump mémoire**. Cet outil Python analyse les dumps provenant de sources externes ou de VMs VMware, identifiant des données telles que les processus et les mots de passe en fonction du profil OS du dump. Il est extensible avec des plugins, ce qui le rend très polyvalent pour les enquêtes judiciaires.

[**Trouvez ici une feuille de triche**](volatility-cheatsheet.md)

## Rapport de crash mini dump

Lorsque le dump est petit (juste quelques Ko, peut-être quelques Mo), alors c'est probablement un rapport de crash mini dump et non un dump mémoire.

![](<../../../images/image (532).png>)

Si vous avez Visual Studio installé, vous pouvez ouvrir ce fichier et lier quelques informations de base comme le nom du processus, l'architecture, les informations d'exception et les modules en cours d'exécution :

![](<../../../images/image (263).png>)

Vous pouvez également charger l'exception et voir les instructions décompilées

![](<../../../images/image (142).png>)

![](<../../../images/image (610).png>)

Quoi qu'il en soit, Visual Studio n'est pas le meilleur outil pour effectuer une analyse en profondeur du dump.

Vous devriez **l'ouvrir** en utilisant **IDA** ou **Radare** pour l'inspecter en **profondeur**.

​

{{#include ../../../banners/hacktricks-training.md}}
