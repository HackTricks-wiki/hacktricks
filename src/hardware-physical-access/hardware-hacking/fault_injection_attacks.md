# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

La fault injection — souvent appelée **glitching** dans le domaine de la sécurité matérielle — consiste à perturber délibérément un appareil pendant son fonctionnement afin qu’il effectue un calcul incorrect. Une faute utile peut entraîner l’omission d’une instruction, corrompre des données, contourner un contrôle de sécurité ou produire une sortie cryptographique erronée permettant de déduire des informations secrètes.<sup>[[1]](#references)</sup>

Les techniques courantes modifient la tension d’alimentation ou l’horloge, injectent des interférences électromagnétiques ou utilisent une stimulation optique ou laser.<sup>[[1]](#references)</sup> Leur précision et leur caractère invasif varient, mais les tests réussis nécessitent généralement un déclencheur reproductible et des balayages systématiques des paramètres de synchronisation, de largeur d’impulsion et d’intensité. Commencez par établir une référence stable, consignez séparément les réinitialisations et les sorties malformées, et ne modifiez qu’un seul paramètre à la fois.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Méthode non invasive d’injection de fautes sans déclencheur, fondée sur des interférences électromagnétiques intentionnelles](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentation ChipWhisperer - Présentation et comparaison du matériel de capture](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
