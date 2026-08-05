# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Compréhension et reverse engineering des signaux basés sur un SDR indépendant de la fréquence**

FISSURE est un framework open source RF et de reverse engineering conçu pour tous les niveaux de compétence, avec des hooks pour la détection et la classification des signaux, la découverte de protocoles, l'exécution d'attaques, la manipulation IQ, l'analyse des vulnérabilités, l'automatisation et l'IA/ML. Le framework a été conçu pour favoriser l'intégration rapide de modules logiciels, de radios, de protocoles, de données de signaux, de scripts, de flow graphs, de documents de référence et d'outils tiers. FISSURE facilite les workflows en conservant les logiciels au même endroit et en permettant aux équipes de se familiariser rapidement tout en partageant la même configuration de référence éprouvée pour des distributions Linux spécifiques.<sup>[[1]](#references)[[2]](#references)</sup>

Le framework et les outils inclus avec FISSURE sont conçus pour détecter la présence d'énergie RF, comprendre les caractéristiques d'un signal, collecter et analyser des échantillons, développer des techniques de transmission et/ou d'injection, et élaborer des payloads ou messages personnalisés. FISSURE contient une bibliothèque croissante d'informations sur les protocoles et les signaux afin de faciliter leur identification, la création de paquets et le fuzzing. Des fonctionnalités d'archivage en ligne permettent de télécharger des fichiers de signaux et de créer des playlists pour simuler du trafic et tester des systèmes.

La base de code Python et l'interface utilisateur conviviales permettent aux débutants de découvrir rapidement les outils et techniques populaires liés à la RF et au reverse engineering. Les formateurs en cybersécurité et en ingénierie peuvent tirer parti des ressources intégrées ou utiliser le framework pour présenter leurs propres applications concrètes. Les développeurs et les chercheurs peuvent utiliser FISSURE dans leurs tâches quotidiennes ou présenter leurs solutions de pointe à un public plus large. À mesure que la connaissance et l'utilisation de FISSURE progresseront dans la communauté, ses capacités ainsi que l'étendue des technologies couvertes continueront de s'accroître.

**Informations supplémentaires**

* [Page AIS](https://www.ainfosec.com/technologies/fissure/)
* [Diapositives GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Article GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Vidéo GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcription du Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Premiers pas

**Pris en charge**

FISSURE comporte trois branches afin de faciliter la navigation dans les fichiers et de réduire la redondance du code. La branche Python2\_maint-3.7 contient une base de code construite autour de Python2, PyQt4 et GNU Radio 3.7 ; la branche Python3\_maint-3.8 est construite autour de Python3, PyQt5 et GNU Radio 3.8 ; et la branche Python3\_maint-3.10 est construite autour de Python3, PyQt5 et GNU Radio 3.10.

|   Système d'exploitation   |   Branche FISSURE   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**En cours (bêta)**

Ces systèmes d'exploitation sont toujours en version bêta. Ils sont en cours de développement et plusieurs fonctionnalités sont connues pour être manquantes. Certains éléments de l'installateur peuvent entrer en conflit avec des programmes existants ou ne pas s'installer tant que ce statut n'aura pas été retiré.

|     Système d'exploitation     |    Branche FISSURE   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Remarque : certains outils logiciels ne fonctionnent pas avec tous les systèmes d'exploitation. Consultez [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Cela installera les dépendances logicielles PyQt requises pour lancer les interfaces graphiques d'installation si elles sont introuvables.

Ensuite, sélectionnez l'option qui correspond le mieux à votre système d'exploitation (elle devrait être détectée automatiquement si votre système d'exploitation correspond à l'une des options).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Il est recommandé d'installer FISSURE sur un système d'exploitation propre afin d'éviter les conflits existants. Sélectionnez toutes les cases recommandées (bouton Default) afin d'éviter les erreurs lors de l'utilisation des différents outils dans FISSURE. Plusieurs demandes s'afficheront au cours de l'installation, demandant principalement des autorisations élevées et des noms d'utilisateur. Si un élément contient une section « Verify » à la fin, l'installateur exécutera la commande qui suit et indiquera l'élément de la case en vert ou en rouge selon que la commande a généré des erreurs ou non. Les éléments cochés sans section « Verify » resteront noirs après l'installation.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Utilisation**

Ouvrez un terminal et saisissez :
```
fissure
```
Consultez le menu **Help** de FISSURE pour plus de détails sur son utilisation.

## Détails

**Composants**

* Dashboard
* Central Hub (HIPRFISR)
* Identification des signaux cibles (TSI)
* Découverte des protocoles (PD)
* Exécuteur de graphes de flux et de scripts (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Fonctionnalités**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Détecteur de signaux**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulation IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Recherche de signaux**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Reconnaissance de motifs**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attaques**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Playlists de signaux**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Galerie d’images**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Création de paquets**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Intégration de Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Calculateur CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Journalisation**_            |

**Matériel**

Voici une liste du matériel « pris en charge », avec différents niveaux d’intégration :

* USRP : X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* Adaptateurs 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Cours

FISSURE propose plusieurs guides utiles pour se familiariser avec différentes technologies et techniques. Beaucoup d’entre eux incluent des étapes pour utiliser divers outils intégrés à FISSURE.

* [Cours 1 : OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Cours 2 : Dissecteurs Lua](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Cours 3 : Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Cours 4 : Cartes ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Cours 5 : Suivi de radiosondes](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Cours 6 : RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Cours 7 : Types de données](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Cours 8 : Blocs GNU Radio personnalisés](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Cours 9 : TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Cours 10 : Examens de radioamateur](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Cours 11 : Outils Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Feuille de route

* [ ] Ajouter davantage de types de matériel, de protocoles RF, de paramètres de signaux et d’outils d’analyse
* [ ] Prendre en charge davantage de systèmes d’exploitation
* [ ] Développer du matériel pédagogique autour de FISSURE (attaques RF, Wi-Fi, GNU Radio, PyQt, etc.)
* [ ] Créer un conditionneur de signal, un extracteur de caractéristiques et un classificateur de signaux avec des techniques AI/ML sélectionnables
* [ ] Implémenter des mécanismes de démodulation récursive pour produire un flux de bits à partir de signaux inconnus
* [ ] Faire évoluer les principaux composants de FISSURE vers un schéma générique de déploiement de nœuds capteurs

## Contributions

Les suggestions visant à améliorer FISSURE sont vivement encouragées. Laissez un commentaire sur la page [Discussions](https://github.com/ainfosec/FISSURE/discussions) ou sur le serveur Discord si vous avez des idées concernant les points suivants :

* Suggestions de nouvelles fonctionnalités et modifications de conception
* Outils logiciels avec leurs étapes d’installation
* Nouveaux cours ou matériel supplémentaire pour les cours existants
* Protocoles RF présentant un intérêt
* Davantage de matériel et de types de SDR à intégrer
* Scripts d’analyse IQ en Python
* Corrections et améliorations de l’installation

Les contributions visant à améliorer FISSURE sont essentielles pour accélérer son développement. Toutes vos contributions sont grandement appréciées. Si vous souhaitez contribuer au développement du code, fork le repo et créez une pull request :

1. Forkez le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. Commitez vos modifications (`git commit -m 'Add some AmazingFeature'`)
4. Pushez vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une pull request

La création d’[Issues](https://github.com/ainfosec/FISSURE/issues) pour signaler des bugs est également bienvenue.

## Collaboration

Contactez le service Business Development d’Assured Information Security, Inc. (AIS) pour proposer et formaliser toute opportunité de collaboration autour de FISSURE, qu’il s’agisse de consacrer du temps à l’intégration de votre logiciel, de faire développer par les personnes talentueuses d’AIS des solutions répondant à vos défis techniques, ou d’intégrer FISSURE à d’autres plateformes et applications.

## Licence

GPL-3.0

Pour plus de détails sur la licence, consultez le fichier LICENSE.

## Contact

Rejoignez le serveur Discord : [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Suivez-nous sur Twitter : [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Crédits

Nous remercions ces développeurs et leur sommes reconnaissants :

[Crédits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Remerciements

Nous remercions tout particulièrement le Dr Samuel Mantravadi et Joseph Reith pour leurs contributions à ce projet.

## Références

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
