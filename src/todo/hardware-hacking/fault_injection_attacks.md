# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

La fault injection perturbe délibérément un appareil pendant son fonctionnement afin qu’il effectue un calcul incorrect. Une faute utile peut ignorer une instruction, corrompre des données, contourner un contrôle de sécurité ou produire une sortie cryptographique erronée à partir de laquelle des informations secrètes peuvent être dérivées.<sup>[[1]](#references)</sup>

Les techniques courantes manipulent la tension d’alimentation ou l’horloge, injectent des interférences électromagnétiques ou utilisent une stimulation optique ou laser.<sup>[[1]](#references)</sup> Leur précision et leur invasivité diffèrent, mais les tests réussis nécessitent généralement un trigger reproductible et des balayages systématiques de la temporisation, de la largeur d’impulsion et de l’intensité. Commencez par une baseline stable, consignez séparément les réinitialisations et les sorties malformées, et ne modifiez qu’un seul paramètre à la fois.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Méthode de Fault Injection non invasive et sans trigger basée sur des interférences électromagnétiques intentionnelles](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentation ChipWhisperer - Vue d’ensemble et comparaison du matériel de capture](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
