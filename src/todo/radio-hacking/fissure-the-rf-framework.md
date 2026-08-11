# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Compréhension et reverse engineering des signaux basés sur la SDR et indépendants de la fréquence**

FISSURE est un framework open source de RF et de reverse engineering conçu pour tous les niveaux, avec des points d'intégration pour la détection et la classification des signaux, la découverte de protocoles, l'exécution d'attaques, la manipulation IQ, l'analyse des vulnérabilités, l'automatisation et l'IA/ML. Le framework a été conçu pour favoriser l'intégration rapide de modules logiciels, de radios, de protocoles, de données de signaux, de scripts, de graphes de flux, de documents de référence et d'outils tiers. FISSURE facilite les workflows en conservant les logiciels au même endroit et en permettant aux équipes de se mettre rapidement à niveau tout en partageant la même configuration de référence éprouvée pour des distributions Linux spécifiques.<sup>[[1]](#references)[[2]](#references)</sup>

Le framework et les outils inclus avec FISSURE sont conçus pour détecter l'énergie RF, caractériser les signaux, collecter et analyser des échantillons, développer des techniques de transmission ou d'injection et élaborer des payloads ou messages personnalisés. FISSURE fournit également des informations sur les protocoles et les signaux pour l'identification, la création de paquets et le fuzzing, ainsi que des archives et des playlists pour la simulation et les tests de trafic.<sup>[[1]](#references)[[2]](#references)</sup>

La base de code Python et l'interface graphique aident les débutants à apprendre les outils de RF et de reverse engineering. Les formateurs peuvent utiliser les leçons intégrées, tandis que les développeurs et les chercheurs peuvent intégrer leurs propres modules et workflows. Les versions actuelles prennent également en charge les nœuds de capteurs distribués, l'intégration TAK, les workflows de géolocalisation et les déploiements Apptainer spécifiques aux rôles.<sup>[[1]](#references)[[3]](#references)</sup>

**Informations supplémentaires**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Pris en charge**

La version actuelle de FISSURE utilise la branche **`Python3`** pour le développement actif, avec PyQt5 et GNU Radio 3.8 ou 3.10. La branche obsolète **`Python2_maint-3.7`** reste disponible pour les anciens systèmes d'exploitation et les outils tiers nécessitant GNU Radio 3.7. Les anciens noms de branches `Python3_maint-3.8` et `Python3_maint-3.10` sont historiques ; la sélection de la version de maintenance de GNU Radio est désormais gérée depuis la branche `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Système d'exploitation | Branche FISSURE | Branche GNU Radio par défaut |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | utiliser une version Linux prise en charge | utiliser la version correspondante |

**En cours (beta)**

Ces systèmes d'exploitation sont toujours en version beta. Ils sont en cours de développement et plusieurs fonctionnalités sont connues pour être absentes. Les éléments de l'installateur peuvent entrer en conflit avec des programmes existants ou ne pas s'installer tant que ce statut n'est pas supprimé.

| Système d'exploitation | Branche FISSURE | Branche GNU Radio par défaut |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Certains outils tiers ne fonctionnent pas sur tous les systèmes d'exploitation. Consultez la documentation actuelle [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) avant l'installation.<sup>[[3]](#references)</sup>

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
L'étape du submodule télécharge les modules GNU Radio out-of-tree utilisés par FISSURE et est requise lors de l'installation de ces modules. L'installer installera également les dépendances PyQt manquantes nécessaires au lancement de ses interfaces graphiques d'installation.<sup>[[3]](#references)</sup>

Ensuite, sélectionnez l'option qui correspond le mieux à votre système d'exploitation (elle devrait être détectée automatiquement si votre système d'exploitation correspond à une option).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Il est recommandé d'installer FISSURE sur un système d'exploitation propre afin d'éviter les conflits existants. Sélectionnez toutes les cases recommandées (bouton Default) afin d'éviter les erreurs lors de l'utilisation des différents outils de FISSURE. Plusieurs invites s'afficheront au cours de l'installation, demandant principalement des permissions élevées et des noms d'utilisateur. Si un élément contient une section « Verify » à la fin, l'installer exécutera la commande qui suit et surlignera la case de l'élément en vert ou en rouge selon que la commande génère ou non des erreurs. Les éléments cochés sans section « Verify » resteront noirs après l'installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilisation**

Ouvrez un terminal et saisissez :
```
fissure
```
Consultez le menu Help de FISSURE pour plus de détails sur l'utilisation.

## Détails

**Composants**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capacités**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Détecteur de signaux**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulation IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Recherche de signaux**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconnaissance de motifs**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attaques**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlists de signaux**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerie d'images**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Création de paquets**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Intégration de Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculateur CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Journalisation**_            |

**Matériel**

Le matériel suivant présente différents niveaux d'intégration dans FISSURE :<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Adaptateurs 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Leçons

FISSURE est fourni avec plusieurs guides utiles pour se familiariser avec différentes technologies et techniques. Beaucoup d'entre eux incluent des étapes d'utilisation de divers outils intégrés à FISSURE.

* [Leçon 1 : OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Leçon 2 : Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Leçon 3 : Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Leçon 4 : cartes ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Leçon 5 : suivi de radiosondes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Leçon 6 : RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Leçon 7 : types de données](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Leçon 8 : blocs GNU Radio personnalisés](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Leçon 9 : TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Leçon 10 : examens de radioamateur](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Leçon 11 : outils Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Leçon 12 : création de clés USB bootables](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Leçon 13 : Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Leçon 14 : ventilateurs de plafond](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Feuille de route

* [ ] Ajouter davantage de types de matériel, de protocoles RF, de paramètres de signaux et d'outils d'analyse
* [ ] Prendre en charge davantage de systèmes d'exploitation
* [ ] Développer des supports de cours autour de FISSURE (attaques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Créer un conditionneur de signaux, un extracteur de caractéristiques et un classificateur de signaux avec des techniques d'IA/ML sélectionnables
* [ ] Implémenter des mécanismes de démodulation récursive pour produire un flux de bits à partir de signaux inconnus
* [ ] Faire migrer les principaux composants de FISSURE vers un schéma générique de déploiement de nœuds capteurs

## Contribution

Les suggestions visant à améliorer FISSURE sont vivement encouragées. Laissez un commentaire sur la page [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou sur le serveur Discord si vous avez des idées concernant les points suivants :

* Suggestions de nouvelles fonctionnalités et changements de conception
* Outils logiciels avec leurs étapes d'installation
* Nouvelles leçons ou contenu supplémentaire pour les leçons existantes
* Protocoles RF présentant un intérêt
* Davantage de types de matériel et de SDR à intégrer
* Scripts d'analyse IQ en Python
* Corrections et améliorations de l'installation

Les contributions visant à améliorer FISSURE sont essentielles pour accélérer son développement. Toute contribution est grandement appréciée. Si vous souhaitez contribuer au développement du code, veuillez fork le repo et créer une pull request :

1. Forker le projet
2. Créer votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Valider vos modifications (`git commit -m 'Add some AmazingFeature'`)
4. Pousser vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une pull request

La création d'[Issues](https://github.com/ainfosec/FISSURE/issues) pour signaler des bugs est également la bienvenue.

## Collaboration

Contactez le service Business Development d'Assured Information Security, Inc. (AIS) pour proposer et formaliser toute opportunité de collaboration avec FISSURE, que ce soit en consacrant du temps à l'intégration de votre logiciel, en demandant aux personnes talentueuses d'AIS de développer des solutions à vos défis techniques, ou en intégrant FISSURE à d'autres plateformes/applications.

## Licence

GPL-3.0

Pour les détails de la licence, consultez le fichier LICENSE.

## Contact

Rejoignez le serveur Discord : [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Suivez-nous sur Twitter : [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Crédits

Nous remercions ces développeurs et leur sommes reconnaissants :

[Crédits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Remerciements

Remerciements particuliers au Dr Samuel Mantravadi et à Joseph Reith pour leurs contributions à ce projet.

## References

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
