# Attaques par injection de fautes

{{#include ../../banners/hacktricks-training.md}}

L'injection de fautes, souvent appelée **glitching** dans le domaine de la sécurité matérielle, consiste à perturber délibérément un appareil pendant son fonctionnement afin de lui faire exécuter un calcul incorrect. Une faute utile peut ignorer une instruction, corrompre des données, contourner un contrôle de sécurité ou produire une sortie cryptographique erronée permettant de déduire des informations secrètes.<sup>[[1]](#references)</sup>

Les techniques courantes manipulent la tension d'alimentation ou l'horloge, injectent des interférences électromagnétiques ou utilisent une stimulation optique ou laser.<sup>[[1]](#references)</sup> Leur précision et leur invasivité diffèrent, mais les tests réussis nécessitent généralement un déclencheur répétable ainsi que des balayages systématiques du timing, de la largeur d'impulsion et de l'intensité. Commencez par établir une base stable, enregistrez séparément les réinitialisations et les sorties malformées, puis ne modifiez qu'un seul paramètre à la fois.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Méthode d'injection de fautes sans déclencheur et non invasive fondée sur des interférences électromagnétiques intentionnelles](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentation de ChipWhisperer - Présentation et comparaison du matériel de capture](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
