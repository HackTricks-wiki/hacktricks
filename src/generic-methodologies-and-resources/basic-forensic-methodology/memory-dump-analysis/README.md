# Analyse d'un dump mémoire

## Début

Commencez par **rechercher** des **malwares** dans le pcap. Utilisez les **outils** mentionnés dans [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility est un framework open source d'analyse de dumps mémoire**. Cet outil Python analyse les dumps provenant de sources externes ou de machines virtuelles VMware, en identifiant des données telles que les processus et les mots de passe en fonction du profil de l'OS du dump. Il est extensible grâce à des plugins, ce qui le rend très polyvalent pour les investigations forensics.<sup>[[1]](#references)[[2]](#references)</sup>

[**Trouvez ici une cheatsheet**](volatility-cheatsheet.md)

## Rapport de crash mini dump

Lorsque le dump est petit (seulement quelques Ko, voire quelques Mo), il peut s'agir d'un rapport de crash mini dump plutôt que d'un dump mémoire complet.<sup>[[3]](#references)</sup>

![Volatility - Rapport de crash mini dump : petit fichier dump identifié comme rapport de crash Mini DuMP](<../../../images/image (532).png>)

Si Visual Studio est installé, vous pouvez ouvrir ce fichier pour afficher des informations de base telles que le nom du processus, l'architecture, les détails de l'exception et les modules chargés :<sup>[[4]](#references)</sup>

![Volatility - Rapport de crash mini dump : si Visual Studio est installé, vous pouvez ouvrir ce fichier et obtenir des informations de base comme le nom du processus, l'architecture, les informations sur l'exception et...](<../../../images/image (263).png>)

Vous pouvez également examiner l'exception et afficher le désassemblage du module.<sup>[[4]](#references)</sup>

![Panneau Actions de Visual Studio pour le minidump, avec des options pour déboguer nativement et définir les chemins des symboles](<../../../images/image (142).png>)

![Désassemblage Visual Studio des instructions provenant de l'exception du minidump](<../../../images/image (610).png>)

Quoi qu'il en soit, Visual Studio n'est pas le meilleur outil pour effectuer une analyse approfondie du dump.

Vous devriez **l'ouvrir** avec **IDA** ou **Radare** afin de l'inspecter en **profondeur**.

## References

- [1] [Framework Volatility](https://github.com/volatilityfoundation/volatility)
- [2] [Utilisation de Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Fichiers Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Utiliser des fichiers dump dans le débogueur Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}
