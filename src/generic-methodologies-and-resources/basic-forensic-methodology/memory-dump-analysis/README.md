# Analyse des memory dumps

{{#include ../../../banners/hacktricks-training.md}}

## Début

Commencez par **rechercher** du **malware** dans le pcap. Utilisez les **tools** mentionnés dans [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility est le principal framework open source pour l'analyse des memory dumps**. Cet outil Python analyse les dumps provenant de sources externes ou de VMs VMware, en identifiant des données telles que les processus et les mots de passe à partir du profil de l'OS contenu dans le dump. Il est extensible grâce à des plugins, ce qui le rend très polyvalent pour les investigations forensic.

[**Trouvez ici un cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash report

Lorsque le dump est petit (seulement quelques Ko, voire quelques Mo), il s'agit probablement d'un mini dump crash report et non d'un memory dump.

![Volatility - Mini dump crash report : Lorsque le dump est petit (seulement quelques Ko, voire quelques Mo), il s'agit probablement d'un mini dump crash report et non d'un memory dump](<../../../images/image (532).png>)

Si Visual Studio est installé, vous pouvez ouvrir ce fichier et récupérer certaines informations de base comme le nom du processus, l'architecture, les informations sur l'exception et les modules en cours d'exécution :

![Volatility - Mini dump crash report : Si Visual Studio est installé, vous pouvez ouvrir ce fichier et récupérer certaines informations de base comme le nom du processus, l'architecture, les informations sur l'exception et...](<../../../images/image (263).png>)

Vous pouvez également charger l'exception et voir les instructions décompilées.

![Volatility - Mini dump crash report : Vous pouvez également charger l'exception et voir les instructions décompilées](<../../../images/image (142).png>)

![Volatility - Mini dump crash report : Vous pouvez également charger l'exception et voir les instructions décompilées](<../../../images/image (610).png>)

Quoi qu'il en soit, Visual Studio n'est pas le meilleur outil pour effectuer une analyse approfondie du dump.

Vous devriez l'**ouvrir** avec **IDA** ou **Radare** afin de l'inspecter en **profondeur**.

{{#include ../../../banners/hacktricks-training.md}}
